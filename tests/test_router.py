"""IPv4 路由解析核心逻辑的单元测试。"""
import random

import pytest
from ipaddress import IPv4Network, collapse_addresses, ip_network

from app.analyzer import V4_SPACE, merge_intervals, parse_cidr_v4
from app.router import (
    FAILED_NEXT_HOPS_MAX,
    METRIC_MAX,
    ROUTES_MAX,
    TARGETS_MAX,
    DuplicateNextHopsError,
    DuplicateTargetsError,
    InvalidIPv4AddressError,
    InvalidMetricError,
    audit_routes,
    failover_routes,
    normalize_metric,
    parse_address_v4,
    resolve_routes,
)


# ---------- 地址解析 ----------

def test_parse_basic_address():
    value, text = parse_address_v4("8.8.8.8")
    assert value == (8 << 24) + (8 << 16) + (8 << 8) + 8
    assert text == "8.8.8.8"


def test_parse_address_trims_outer_whitespace():
    assert parse_address_v4("  0.0.0.0 ")[1] == "0.0.0.0"
    assert parse_address_v4("255.255.255.255")[0] == (1 << 32) - 1


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "   ",
        "8.8.8.8/32",   # 禁止 CIDR 写法
        "10.0.0",       # 段数不足
        "999.0.0.1",    # 段越界
        "010.0.0.1",    # 前导零
        "10.0.0. ",     # 段内空白
        "2001:db8::1",  # IPv6
        "::1",
    ],
)
def test_parse_address_rejects_invalid_and_ipv6(bad):
    with pytest.raises(InvalidIPv4AddressError):
        parse_address_v4(bad)


def test_parse_address_rejects_non_string():
    with pytest.raises(InvalidIPv4AddressError):
        parse_address_v4(0x08080808)


# ---------- metric 校验 ----------

@pytest.mark.parametrize("metric", [0, 1, 100, 65535])
def test_normalize_metric_accepts_range(metric):
    assert normalize_metric(metric) == metric


@pytest.mark.parametrize("metric", [-1, 65536, 100_000])
def test_normalize_metric_rejects_out_of_range(metric):
    with pytest.raises(InvalidMetricError):
        normalize_metric(metric)


@pytest.mark.parametrize("metric", [True, False, 1.0, "10", None])
def test_normalize_metric_rejects_non_int(metric):
    with pytest.raises(InvalidMetricError):
        normalize_metric(metric)


# ---------- 解析主流程 ----------

def test_lpm_beats_shorter_prefix_even_with_worse_metric():
    # /8 默认路由 metric 很小，但 /16 前缀更长必须胜出
    result = resolve_routes(
        [
            ("0.0.0.0/0", "1.1.1.1", 0),
            ("10.0.0.0/8", "10.0.0.1", 200),
            ("10.1.0.0/16", "10.1.0.1", 500),
        ],
        ["10.1.9.9"],
    )
    item = result["results"][0]
    assert item["status"] == "reachable"
    assert item["matched_cidr"] == "10.1.0.0/16"
    assert item["metric"] == 500
    assert item["next_hops"] == ["10.1.0.1"]


def test_lowest_metric_kept_within_lpm_set():
    # /8 与 /8 同前缀：metric 20 胜出，metric 50 被丢弃
    result = resolve_routes(
        [
            ("0.0.0.0/0", "1.1.1.1", 100),
            ("10.0.0.0/8", "10.0.0.1", 50),
            ("10.0.0.0/8", "10.0.0.2", 20),
            ("10.0.0.0/8", "10.0.0.3", 20),
        ],
        ["10.2.3.4"],
    )
    item = result["results"][0]
    assert item["matched_cidr"] == "10.0.0.0/8"
    assert item["metric"] == 20
    assert item["next_hops"] == ["10.0.0.2", "10.0.0.3"]


def test_ecmp_next_hops_deduplicated_in_input_order():
    # 同一路由重复、相同下一跳跨不同最低 metric 路由：去重且按 routes 顺序
    result = resolve_routes(
        [
            ("10.1.0.0/16", "10.1.0.9", 90),  # 先出现但 metric 高，落选
            ("10.1.0.0/16", "10.1.0.1", 60),
            ("10.1.0.0/16", "10.1.0.2", 60),
            ("10.1.0.0/16", "10.1.0.1", 60),  # 完全重复
            ("10.1.0.0/16", "10.1.0.2", 60),  # 完全重复
        ],
        ["10.1.0.5"],
    )
    assert result["results"][0]["next_hops"] == ["10.1.0.1", "10.1.0.2"]


def test_higher_metric_hop_does_not_pollute_dedup_order():
    # 高 metric 路由虽然先出现且下一跳不同，但不参与 ECMP，也不影响去重顺序
    result = resolve_routes(
        [
            ("10.0.0.0/8", "10.9.9.9", 90),
            ("10.0.0.0/8", "10.0.0.2", 10),
            ("10.0.0.0/8", "10.0.0.1", 10),
        ],
        ["10.0.0.9"],
    )
    assert result["results"][0]["next_hops"] == ["10.0.0.2", "10.0.0.1"]


def test_unreachable_target_shape():
    result = resolve_routes([("10.0.0.0/8", "10.0.0.1", 0)], ["8.8.8.8"])
    assert result == {
        "route_count": 1,
        "target_count": 1,
        "results": [
            {
                "target": "8.8.8.8",
                "status": "unreachable",
                "matched_cidr": None,
                "metric": None,
                "next_hops": [],
            }
        ],
        "summary": {
            "reachable_count": 0,
            "unreachable_count": 1,
            "next_hop_counts": [],
        },
    }


def test_empty_routes_all_unreachable():
    result = resolve_routes([], ["1.2.3.4", "5.6.7.8"])
    assert [r["status"] for r in result["results"]] == ["unreachable", "unreachable"]
    assert result["summary"] == {
        "reachable_count": 0,
        "unreachable_count": 2,
        "next_hop_counts": [],
    }


def test_results_preserve_target_order_and_normalization():
    result = resolve_routes(
        [("0.0.0.0/0", "1.1.1.1", 0)],
        ["8.8.8.8", "1.1.1.1", "8.8.4.4"],
    )
    assert [r["target"] for r in result["results"]] == [
        "8.8.8.8",
        "1.1.1.1",
        "8.8.4.4",
    ]


def test_next_hop_counts_ecmp_counted_separately():
    # 三个等价下一跳均命中两个目标（ECMP 结果里每个下一跳分别计数）；
    # 第三个目标不可达，不参与计数
    result = resolve_routes(
        [
            ("10.0.0.0/8", "10.0.0.1", 10),
            ("10.0.0.0/8", "10.0.0.2", 10),
            ("10.0.0.0/8", "10.0.0.3", 10),
        ],
        ["10.0.0.9", "10.1.0.9", "8.8.8.8"],
    )
    assert result["summary"] == {
        "reachable_count": 2,
        "unreachable_count": 1,
        "next_hop_counts": [
            {"next_hop": "10.0.0.1", "target_count": 2},
            {"next_hop": "10.0.0.2", "target_count": 2},
            {"next_hop": "10.0.0.3", "target_count": 2},
        ],
    }


def test_next_hop_counts_partial_ecmp_overlap():
    # a 命中 h1/h2，b 命中 h2/h3：h2 计数 2，h1/h3 各 1
    result = resolve_routes(
        [
            ("10.0.0.0/8", "10.0.0.1", 10),
            ("10.0.0.0/8", "10.0.0.2", 10),
            ("10.0.0.0/8", "10.0.0.3", 10),
            ("10.1.0.0/16", "10.0.0.1", 5),  # LPM 更高前缀：a 改走 h1 单跳
        ],
        ["10.1.0.9", "10.2.0.9"],
    )
    assert result["results"][0]["next_hops"] == ["10.0.0.1"]
    assert result["results"][1]["next_hops"] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert result["summary"]["next_hop_counts"] == [
        {"next_hop": "10.0.0.1", "target_count": 2},
        {"next_hop": "10.0.0.2", "target_count": 1},
        {"next_hop": "10.0.0.3", "target_count": 1},
    ]


def test_next_hop_counts_ordered_by_first_route_occurrence():
    # h-a 首次出现在 index 0（对目标 a 落选），h-b 在 index 2、h-c 在 index 1；
    # 汇总顺序按 routes 中首次出现位置：h-a(0), h-c(1), h-b(2)
    result = resolve_routes(
        [
            ("10.0.0.0/8", "10.0.0.9", 90),
            ("10.0.0.0/8", "10.0.0.3", 10),
            ("10.0.0.0/8", "10.0.0.2", 10),
            ("9.0.0.0/8", "10.0.0.9", 10),
        ],
        ["10.0.0.9", "9.0.0.9"],
    )
    assert result["summary"]["next_hop_counts"] == [
        {"next_hop": "10.0.0.9", "target_count": 1},
        {"next_hop": "10.0.0.3", "target_count": 1},
        {"next_hop": "10.0.0.2", "target_count": 1},
    ]


def test_bare_ip_route_cidr_is_slash32():
    result = resolve_routes(
        [("8.8.8.8", "1.1.1.1", 5)], ["8.8.8.8", "8.8.8.9"]
    )
    assert result["results"][0]["matched_cidr"] == "8.8.8.8/32"
    assert result["results"][0]["metric"] == 5
    assert result["results"][1]["status"] == "unreachable"


def test_default_route_covers_entire_space_without_enumeration():
    result = resolve_routes(
        [("0.0.0.0/0", "1.1.1.1", 65535)],
        ["0.0.0.0", "127.0.0.1", "255.255.255.255"],
    )
    assert all(r["status"] == "reachable" for r in result["results"])
    assert all(r["matched_cidr"] == "0.0.0.0/0" for r in result["results"])
    assert result["summary"] == {
        "reachable_count": 3,
        "unreachable_count": 0,
        "next_hop_counts": [
            {"next_hop": "1.1.1.1", "target_count": 3}
        ],
    }


def test_duplicate_targets_raises_with_indexes():
    with pytest.raises(DuplicateTargetsError) as exc:
        resolve_routes(
            [("0.0.0.0/0", "1.1.1.1", 0)],
            ["8.8.8.8", "9.9.9.9", "8.8.8.8", "9.9.9.9"],
        )
    assert exc.value.duplicates == [
        {"target": "8.8.8.8", "indexes": [0, 2]},
        {"target": "9.9.9.9", "indexes": [1, 3]},
    ]


def test_invalid_route_inputs_raise():
    with pytest.raises(InvalidMetricError):
        resolve_routes([("10.0.0.0/8", "1.1.1.1", 65536)], ["10.0.0.1"])
    with pytest.raises(InvalidMetricError):
        resolve_routes([("10.0.0.0/8", "1.1.1.1", True)], ["10.0.0.1"])
    with pytest.raises(InvalidIPv4AddressError):
        resolve_routes([("10.0.0.0/8", "1.1.1.1/32", 0)], ["10.0.0.1"])
    with pytest.raises(InvalidIPv4AddressError):
        resolve_routes([("10.0.0.0/8", "::1", 0)], ["10.0.0.1"])
    with pytest.raises(Exception):
        # CIDR 非法（主机位非零）
        resolve_routes([("10.0.0.1/8", "1.1.1.1", 0)], ["10.0.0.1"])
    with pytest.raises(InvalidIPv4AddressError):
        resolve_routes([("10.0.0.0/8", "1.1.1.1", 0)], ["2001:db8::1"])


def test_size_limits():
    with pytest.raises(ValueError):
        resolve_routes([], [])
    many_routes = [
        ("10.0.0.0/8", f"10.0.{i // 256}.{(i % 256) + 1}", i % (METRIC_MAX + 1))
        for i in range(ROUTES_MAX + 1)
    ]
    with pytest.raises(ValueError):
        resolve_routes(many_routes, ["10.0.0.1"])
    with pytest.raises(ValueError):
        resolve_routes(
            [("0.0.0.0/0", "1.1.1.1", 0)],
            [f"8.8.{i // 256}.{i % 256}" for i in range(TARGETS_MAX + 1)],
        )


def test_max_limits_accepted():
    routes = [("0.0.0.0/0", "1.1.1.1", 0) for _ in range(ROUTES_MAX)]
    targets = [f"8.8.{i // 256}.{i % 256}" for i in range(TARGETS_MAX)]
    result = resolve_routes(routes, targets)
    assert result["route_count"] == ROUTES_MAX
    assert result["target_count"] == TARGETS_MAX
    assert len(result["results"]) == TARGETS_MAX
    # 重复下一跳只保留一项，命中全部 500 个目标
    assert result["summary"]["next_hop_counts"] == [
        {"next_hop": "1.1.1.1", "target_count": TARGETS_MAX}
    ]


# ---------- 属性测试：与逐路由暴力 oracle 对比 ----------

def _oracle_resolve(routes, target_value):
    """暴力 LPM + 最低 metric + 输入顺序去重，返回 (cidr, metric, hops) 或 None。"""
    matched = []
    best_prefix = -1
    for cidr, next_hop, metric in routes:
        start, end, text = parse_cidr_v4(cidr)
        if start <= target_value <= end:
            prefixlen = int(text.rsplit("/", 1)[1])
            if prefixlen > best_prefix:
                best_prefix = prefixlen
                matched = [(text, next_hop, metric)]
            elif prefixlen == best_prefix:
                matched.append((text, next_hop, metric))
    if not matched:
        return None
    min_metric = min(m for _, _, m in matched)
    cidr = matched[0][0]
    hops = []
    for _, next_hop, metric in matched:
        if metric == min_metric and next_hop not in hops:
            hops.append(next_hop)
    return cidr, min_metric, hops


def test_resolve_random_oracle():
    rng = random.Random(20260918)
    # 在 10.0.0.0/16 内随机生成不同前缀长度的路由
    base = ip_network("10.0.0.0/16")
    candidate_nets = ["0.0.0.0/0", "10.0.0.0/8"]
    for prefixlen in (17, 20, 24, 28, 30, 32):
        candidate_nets.extend(str(n) for n in base.subnets(new_prefix=prefixlen))

    for _ in range(200):
        n_routes = rng.randint(0, 20)
        route_cidrs = [rng.choice(candidate_nets) for _ in range(n_routes)]
        raw_routes = []
        hops_pool = [f"192.0.2.{i}" for i in range(1, 9)]
        for cidr in route_cidrs:
            # 允许重复下一跳、重复 metric
            raw_routes.append(
                (cidr, rng.choice(hops_pool), rng.randint(0, 5))
            )

        targets = [
            f"10.0.{rng.randint(0, 255)}.{rng.randint(0, 255)}"
            for _ in range(rng.randint(1, 6))
        ]
        # oracle 前先去重（接口语义要求唯一目标）
        uniq = list(dict.fromkeys(targets))
        result = resolve_routes(raw_routes, uniq)

        assert [r["target"] for r in result["results"]] == uniq
        expected_counts: dict[str, int] = {}
        for item, target_text in zip(result["results"], uniq):
            value = parse_address_v4(target_text)[0]
            expected = _oracle_resolve(raw_routes, value)
            if expected is None:
                assert item["status"] == "unreachable"
                assert item["matched_cidr"] is None
                assert item["metric"] is None
                assert item["next_hops"] == []
                continue
            cidr, metric, hops = expected
            assert item["status"] == "reachable"
            assert item["matched_cidr"] == cidr
            assert item["metric"] == metric
            assert item["next_hops"] == hops
            for hop in hops:
                expected_counts[hop] = expected_counts.get(hop, 0) + 1

        # 汇总计数与逐目标展开一致
        got_counts = {
            c["next_hop"]: c["target_count"]
            for c in result["summary"]["next_hop_counts"]
        }
        assert got_counts == expected_counts
        # 汇总排序键：routes 中首次出现的序号单调递增
        first_index = {}
        for i, (_, hop, _) in enumerate(raw_routes):
            first_index.setdefault(hop, i)
        ordered = [c["next_hop"] for c in result["summary"]["next_hop_counts"]]
        assert ordered == sorted(ordered, key=lambda h: first_index[h])

        reachable = sum(1 for r in result["results"] if r["status"] == "reachable")
        assert result["summary"]["reachable_count"] == reachable
        assert result["summary"]["unreachable_count"] == len(uniq) - reachable


# ---------- 故障切换（failover） ----------

def test_failover_unchanged_when_failed_hop_unrelated():
    # 失败下一跳不在路由表中：结果完全不变
    result = failover_routes(
        [("10.0.0.0/8", "10.0.0.1", 10)],
        ["10.0.0.9"],
        ["192.0.2.1"],
    )
    item = result["results"][0]
    assert item["impact"] == "unchanged"
    assert item["before"] == item["after"]
    assert result["summary"] == {
        "unchanged": 1,
        "ecmp_reduced": 0,
        "rerouted": 0,
        "unreachable": 0,
    }


def test_failover_ecmp_reduced():
    # 移除 ECMP 中一个下一跳：命中网段与 metric 不变，等价下一跳减少
    result = failover_routes(
        [
            ("10.0.0.0/8", "10.0.0.1", 20),
            ("10.0.0.0/8", "10.0.0.2", 20),
            ("10.0.0.0/8", "10.0.0.3", 20),
        ],
        ["10.0.0.9"],
        ["10.0.0.2"],
    )
    item = result["results"][0]
    assert item["impact"] == "ecmp_reduced"
    assert item["before"] == {
        "status": "reachable",
        "matched_cidr": "10.0.0.0/8",
        "metric": 20,
        "next_hops": ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
    }
    assert item["after"] == {
        "status": "reachable",
        "matched_cidr": "10.0.0.0/8",
        "metric": 20,
        "next_hops": ["10.0.0.1", "10.0.0.3"],
    }
    assert result["summary"]["ecmp_reduced"] == 1


def test_failover_rerouted_to_higher_metric_same_prefix():
    # 最低 metric 路由全部失效：回退到同网段更高 metric，而非从 ECMP 删值
    result = failover_routes(
        [
            ("10.0.0.0/8", "10.0.0.1", 10),
            ("10.0.0.0/8", "10.0.0.2", 50),
        ],
        ["10.0.0.9"],
        ["10.0.0.1"],
    )
    item = result["results"][0]
    assert item["impact"] == "rerouted"
    assert item["before"]["metric"] == 10
    assert item["after"] == {
        "status": "reachable",
        "matched_cidr": "10.0.0.0/8",
        "metric": 50,
        "next_hops": ["10.0.0.2"],
    }


def test_failover_rerouted_to_shorter_prefix():
    # 长前缀路由全部失效：LPM 重新选择，回退到更短前缀
    result = failover_routes(
        [
            ("0.0.0.0/0", "192.0.2.254", 100),
            ("10.0.0.0/8", "10.0.0.1", 10),
            ("10.1.0.0/16", "10.1.0.1", 5),
        ],
        ["10.1.0.9"],
        ["10.1.0.1"],
    )
    item = result["results"][0]
    assert item["impact"] == "rerouted"
    assert item["before"]["matched_cidr"] == "10.1.0.0/16"
    assert item["after"] == {
        "status": "reachable",
        "matched_cidr": "10.0.0.0/8",
        "metric": 10,
        "next_hops": ["10.0.0.1"],
    }


def test_failover_unreachable_and_both_unreachable_unchanged():
    result = failover_routes(
        [("10.0.0.0/8", "10.0.0.1", 10)],
        ["10.0.0.9", "8.8.8.8"],
        ["10.0.0.1"],
    )
    first, second = result["results"]
    # 原本可达、故障后不可达
    assert first["impact"] == "unreachable"
    assert first["before"]["status"] == "reachable"
    assert first["after"] == {
        "status": "unreachable",
        "matched_cidr": None,
        "metric": None,
        "next_hops": [],
    }
    # 两侧均不可达视为 unchanged
    assert second["impact"] == "unchanged"
    assert second["before"] == second["after"]
    assert result["summary"] == {
        "unchanged": 1,
        "ecmp_reduced": 0,
        "rerouted": 0,
        "unreachable": 1,
    }


def test_failover_failed_hop_removes_all_its_routes():
    # 同一失败下一跳出现在多条路由（不同前缀）中：全部移除
    result = failover_routes(
        [
            ("10.0.0.0/8", "10.0.0.1", 10),
            ("10.1.0.0/16", "10.0.0.1", 5),  # 同一下一跳，更长前缀
            ("10.1.0.0/16", "10.1.0.2", 5),
        ],
        ["10.1.0.9"],
        ["10.0.0.1"],
    )
    item = result["results"][0]
    assert item["before"]["matched_cidr"] == "10.1.0.0/16"
    assert item["before"]["next_hops"] == ["10.0.0.1", "10.1.0.2"]
    # /16 中下一跳为 10.0.0.1 的路由也被移除，只剩 10.1.0.2
    assert item["impact"] == "ecmp_reduced"
    assert item["after"]["next_hops"] == ["10.1.0.2"]


def test_failover_all_four_impacts_in_one_request():
    result = failover_routes(
        [
            ("10.0.0.0/8", "10.0.0.1", 10),
            ("10.0.0.0/8", "10.0.0.2", 10),
            ("10.1.0.0/16", "10.1.0.1", 5),
            ("11.0.0.0/8", "11.0.0.1", 7),
            ("12.0.0.0/8", "12.0.0.1", 3),
        ],
        ["10.0.9.9", "10.1.0.9", "11.0.0.9", "12.0.0.9"],
        ["10.0.0.2", "10.1.0.1", "11.0.0.1"],
    )
    assert [r["target"] for r in result["results"]] == [
        "10.0.9.9",
        "10.1.0.9",
        "11.0.0.9",
        "12.0.0.9",
    ]
    assert [r["impact"] for r in result["results"]] == [
        "ecmp_reduced",  # /8 少了一个等价下一跳
        "rerouted",      # /16 失效，回退到 /8
        "unreachable",   # 唯一路由失效
        "unchanged",     # 不受影响
    ]
    assert result["summary"] == {
        "unchanged": 1,
        "ecmp_reduced": 1,
        "rerouted": 1,
        "unreachable": 1,
    }


def test_failover_empty_failed_list_all_unchanged():
    result = failover_routes(
        [("0.0.0.0/0", "1.1.1.1", 0)],
        ["8.8.8.8", "9.9.9.9"],
        [],
    )
    assert result["failed_next_hops"] == []
    assert [r["impact"] for r in result["results"]] == ["unchanged", "unchanged"]
    assert result["summary"] == {
        "unchanged": 2,
        "ecmp_reduced": 0,
        "rerouted": 0,
        "unreachable": 0,
    }


def test_failover_failed_next_hops_normalized_and_order_preserved():
    result = failover_routes(
        [("0.0.0.0/0", "1.1.1.1", 0)],
        ["8.8.8.8"],
        [" 2.2.2.2 ", "1.1.1.1"],
    )
    assert result["failed_next_hops"] == ["2.2.2.2", "1.1.1.1"]
    assert result["results"][0]["impact"] == "unreachable"


def test_failover_duplicate_failed_next_hops_raises_with_indexes():
    with pytest.raises(DuplicateNextHopsError) as exc:
        failover_routes(
            [("0.0.0.0/0", "1.1.1.1", 0)],
            ["8.8.8.8"],
            ["1.1.1.1", "2.2.2.2", "1.1.1.1", "2.2.2.2"],
        )
    assert exc.value.duplicates == [
        {"next_hop": "1.1.1.1", "indexes": [0, 2]},
        {"next_hop": "2.2.2.2", "indexes": [1, 3]},
    ]


def test_failover_duplicate_targets_still_raises():
    with pytest.raises(DuplicateTargetsError):
        failover_routes(
            [("0.0.0.0/0", "1.1.1.1", 0)],
            ["8.8.8.8", "8.8.8.8"],
            ["1.1.1.1"],
        )


def test_failover_invalid_inputs_raise():
    valid_route = ("10.0.0.0/8", "10.0.0.1", 10)
    # 非法 failed_next_hops：CIDR 写法 / IPv6 / 越界 / 前导零 / 非字符串
    for bad in ["10.0.0.1/32", "::1", "999.0.0.1", "010.0.0.1", 8, True, None, ""]:
        with pytest.raises(InvalidIPv4AddressError):
            failover_routes([valid_route], ["10.0.0.9"], [bad])
    # 非法路由 / 目标沿用 resolve 校验
    with pytest.raises(InvalidIPv4AddressError):
        failover_routes([("10.0.0.0/8", "::1", 0)], ["10.0.0.9"], ["1.1.1.1"])
    with pytest.raises(InvalidMetricError):
        failover_routes([("10.0.0.0/8", "1.1.1.1", 65536)], ["10.0.0.9"], [])
    with pytest.raises(InvalidIPv4AddressError):
        failover_routes([valid_route], ["2001:db8::1"], ["1.1.1.1"])


def test_failover_size_limits():
    valid_route = ("10.0.0.0/8", "10.0.0.1", 10)
    # 失败下一跳数量上限
    with pytest.raises(ValueError):
        failover_routes(
            [valid_route],
            ["10.0.0.9"],
            [f"192.0.{i // 256}.{i % 256}" for i in range(FAILED_NEXT_HOPS_MAX + 1)],
        )
    # 路由 / 目标规模沿用 resolve 限制（空路由表合法：所有目标不可达）
    result = failover_routes([], ["10.0.0.9"], [])
    assert result["results"][0]["impact"] == "unchanged"
    assert result["results"][0]["before"]["status"] == "unreachable"
    with pytest.raises(ValueError):
        failover_routes([], [], [])
    many_routes = [
        ("10.0.0.0/8", f"10.0.{i // 256}.{(i % 256) + 1}", i % (METRIC_MAX + 1))
        for i in range(ROUTES_MAX + 1)
    ]
    with pytest.raises(ValueError):
        failover_routes(many_routes, ["10.0.0.9"], [])
    with pytest.raises(ValueError):
        failover_routes(
            [valid_route],
            [f"8.8.{i // 256}.{i % 256}" for i in range(TARGETS_MAX + 1)],
            [],
        )


def test_failover_max_limits_accepted():
    routes = [("0.0.0.0/0", "1.1.1.1", 0) for _ in range(ROUTES_MAX)]
    targets = [f"8.8.{i // 256}.{i % 256}" for i in range(TARGETS_MAX)]
    failed = [f"192.0.{i // 256}.{i % 256}" for i in range(FAILED_NEXT_HOPS_MAX)]
    result = failover_routes(routes, targets, failed)
    assert result["route_count"] == ROUTES_MAX
    assert result["target_count"] == TARGETS_MAX
    assert len(result["failed_next_hops"]) == FAILED_NEXT_HOPS_MAX
    # 失败下一跳均不在路由表中：全部 unchanged
    assert result["summary"]["unchanged"] == TARGETS_MAX


# ---------- 属性测试：failover 与“过滤后重新 resolve”oracle 对比 ----------

def _oracle_impact(before, after):
    """独立实现的 impact 归类，用于交叉验证。"""
    if before["status"] == "unreachable" and after["status"] == "unreachable":
        return "unchanged"
    if after["status"] == "unreachable":
        return "unreachable"
    if before["status"] == "unreachable":
        return "rerouted"
    same_path = (
        before["matched_cidr"] == after["matched_cidr"]
        and before["metric"] == after["metric"]
    )
    if same_path:
        return "unchanged" if before["next_hops"] == after["next_hops"] else "ecmp_reduced"
    return "rerouted"


def test_failover_random_oracle():
    rng = random.Random(20260918)
    base = ip_network("10.0.0.0/16")
    candidate_nets = ["0.0.0.0/0", "10.0.0.0/8"]
    for prefixlen in (17, 20, 24, 28, 30, 32):
        candidate_nets.extend(str(n) for n in base.subnets(new_prefix=prefixlen))
    hops_pool = [f"192.0.2.{i}" for i in range(1, 9)]

    for _ in range(200):
        n_routes = rng.randint(0, 20)
        raw_routes = [
            (rng.choice(candidate_nets), rng.choice(hops_pool), rng.randint(0, 5))
            for _ in range(n_routes)
        ]
        targets = list(
            dict.fromkeys(
                f"10.0.{rng.randint(0, 255)}.{rng.randint(0, 255)}"
                for _ in range(rng.randint(1, 6))
            )
        )
        # 失败下一跳：部分来自路由表、部分为无关地址；允许为空
        failed = list(
            dict.fromkeys(
                rng.choice(hops_pool + ["203.0.113.1", "203.0.113.2"])
                for _ in range(rng.randint(0, 4))
            )
        )

        result = failover_routes(raw_routes, targets, failed)

        # oracle：before = 完整 resolve；after = 过滤失败下一跳全部路由后重新 resolve
        failed_set = set(failed)
        oracle_before = resolve_routes(raw_routes, targets)
        oracle_after = resolve_routes(
            [r for r in raw_routes if r[1] not in failed_set], targets
        )

        assert [r["target"] for r in result["results"]] == targets
        assert result["failed_next_hops"] == failed
        expected_counts = {"unchanged": 0, "ecmp_reduced": 0,
                           "rerouted": 0, "unreachable": 0}
        for item, before_item, after_item in zip(
            result["results"], oracle_before["results"], oracle_after["results"]
        ):
            expected_before = {k: before_item[k] for k in (
                "status", "matched_cidr", "metric", "next_hops")}
            expected_after = {k: after_item[k] for k in (
                "status", "matched_cidr", "metric", "next_hops")}
            assert item["before"] == expected_before
            assert item["after"] == expected_after
            # ecmp_reduced 的下一跳必然是原 ECMP 的严格子集
            if item["impact"] == "ecmp_reduced":
                assert set(item["after"]["next_hops"]) < set(
                    item["before"]["next_hops"]
                )
            expected_impact = _oracle_impact(expected_before, expected_after)
            assert item["impact"] == expected_impact
            expected_counts[expected_impact] += 1

        assert result["summary"] == expected_counts


# ---------- 全表审计（audit） ----------

def test_audit_lpm_metric_and_ecmp_sharing():
    # 综合场景：默认路由被 /8 挖掉一块；/8 内被两个 /16 挖掉；
    # /8 的 metric 30 路由被同前缀更低 metric 遮蔽；两条 /16 ECMP 共享
    result = audit_routes(
        [
            ("0.0.0.0/0", "192.0.2.254", 100),
            ("10.0.0.0/8", "10.0.0.1", 20),
            ("10.0.0.0/8", "10.0.0.2", 20),
            ("10.0.0.0/8", "10.0.0.3", 30),
            ("10.1.0.0/16", "10.1.0.1", 60),
            ("10.2.0.0/16", "10.2.0.1", 40),
            ("10.2.0.0/16", "10.2.0.2", 40),
        ]
    )
    assert result["route_count"] == 7
    routes = result["routes"]
    assert [r["index"] for r in routes] == list(range(7))  # 保持输入顺序
    assert [r["status"] for r in routes] == [
        "partial",
        "partial",
        "partial",
        "shadowed",
        "active",
        "active",
        "active",
    ]
    assert routes[0]["status_label"] == "部分生效"
    assert routes[4]["status_label"] == "生效"
    assert routes[3]["status_label"] == "完全遮蔽"

    # 默认路由：整个空间扣除 10.0.0.0/8（/16 在 /8 内，不重复扣除）
    assert routes[0]["total_addresses"] == V4_SPACE
    assert routes[0]["effective_addresses"] == V4_SPACE - (1 << 24)
    assert routes[0]["effective_cidrs"] == [
        "0.0.0.0/5",
        "8.0.0.0/7",
        "11.0.0.0/8",
        "12.0.0.0/6",
        "16.0.0.0/4",
        "32.0.0.0/3",
        "64.0.0.0/2",
        "128.0.0.0/1",
    ]
    assert routes[0]["ecmp_group"] == [0]

    # /8 的两个 ECMP 路由共享同一集合：扣除两个 /16
    expected_8 = [
        "10.0.0.0/16",
        "10.3.0.0/16",
        "10.4.0.0/14",
        "10.8.0.0/13",
        "10.16.0.0/12",
        "10.32.0.0/11",
        "10.64.0.0/10",
        "10.128.0.0/9",
    ]
    for i in (1, 2):
        assert routes[i]["effective_addresses"] == (1 << 24) - 2 * (1 << 16)
        assert routes[i]["effective_cidrs"] == expected_8
        assert routes[i]["ecmp_group"] == [1, 2]

    # 同前缀更高 metric：整体被遮蔽
    assert routes[3]["effective_addresses"] == 0
    assert routes[3]["effective_cidrs"] == []
    assert routes[3]["ecmp_group"] == [3]

    # 两条 /16：各自全生效，10.2.0.0/16 为 ECMP 对
    assert routes[4]["effective_cidrs"] == ["10.1.0.0/16"]
    assert routes[4]["ecmp_group"] == [4]
    for i in (5, 6):
        assert routes[i]["effective_cidrs"] == ["10.2.0.0/16"]
        assert routes[i]["ecmp_group"] == [5, 6]

    # 汇总：默认路由兜底，整个 IPv4 空间被完全覆盖
    assert result["summary"] == {
        "active": 3,
        "partial": 3,
        "shadowed": 1,
        "covered_addresses": V4_SPACE,
        "uncovered_addresses": 0,
    }


def test_audit_longer_prefix_wins_regardless_of_metric():
    # 短前缀 metric 0，长前缀 metric 100：LPM 仍然优先
    result = audit_routes(
        [
            ("10.0.0.0/8", "10.0.0.1", 0),
            ("10.1.0.0/16", "10.1.0.1", 100),
        ]
    )
    first, second = result["routes"]
    assert first["status"] == "partial"
    assert first["effective_addresses"] == (1 << 24) - (1 << 16)
    assert second["status"] == "active"
    assert second["effective_cidrs"] == ["10.1.0.0/16"]


def test_audit_fully_covered_by_longer_prefixes_is_shadowed():
    # 两个 /9 恰好拼满 /8：/8 路由完全遮蔽（即使 metric 更低）
    result = audit_routes(
        [
            ("10.0.0.0/8", "10.0.0.1", 0),
            ("10.0.0.0/9", "10.0.0.2", 20),
            ("10.128.0.0/9", "10.0.0.3", 20),
        ]
    )
    assert [r["status"] for r in result["routes"]] == [
        "shadowed",
        "active",
        "active",
    ]
    assert result["routes"][0]["effective_cidrs"] == []
    assert result["summary"]["covered_addresses"] == 1 << 24


def test_audit_same_network_lowest_metric_wins():
    # 同网段三个 metric：仅最低 metric 的 ECMP 组生效，其余 shadowed
    result = audit_routes(
        [
            ("10.0.0.0/8", "10.0.0.1", 20),
            ("10.0.0.0/8", "10.0.0.2", 10),
            ("10.0.0.0/8", "10.0.0.3", 10),
            ("10.0.0.0/8", "10.0.0.4", 30),
        ]
    )
    assert [r["status"] for r in result["routes"]] == [
        "shadowed",
        "active",
        "active",
        "shadowed",
    ]
    assert [r["ecmp_group"] for r in result["routes"]] == [[0], [1, 2], [1, 2], [3]]
    assert result["routes"][1]["effective_cidrs"] == ["10.0.0.0/8"]
    assert result["routes"][2]["effective_cidrs"] == ["10.0.0.0/8"]
    # ECMP 共享集合在汇总中只计一次
    assert result["summary"]["covered_addresses"] == 1 << 24


def test_audit_duplicate_routes_share_set_and_order():
    # 完全重复的路由（同 cidr/next_hop/metric）也是 ECMP 并行路由
    result = audit_routes(
        [
            ("10.0.0.0/8", "10.0.0.1", 10),
            ("10.0.0.0/8", "10.0.0.1", 10),
        ]
    )
    assert [r["ecmp_group"] for r in result["routes"]] == [[0, 1], [0, 1]]
    assert result["routes"][0]["effective_cidrs"] == ["10.0.0.0/8"]
    assert result["routes"][1]["effective_cidrs"] == ["10.0.0.0/8"]
    assert result["summary"]["active"] == 2
    assert result["summary"]["covered_addresses"] == 1 << 24


def test_audit_default_route_full_space_active():
    result = audit_routes([("0.0.0.0/0", "1.1.1.1", 65535)])
    item = result["routes"][0]
    assert item["status"] == "active"
    assert item["total_addresses"] == V4_SPACE
    assert item["effective_addresses"] == V4_SPACE
    assert item["effective_cidrs"] == ["0.0.0.0/0"]
    assert result["summary"] == {
        "active": 1,
        "partial": 0,
        "shadowed": 0,
        "covered_addresses": V4_SPACE,
        "uncovered_addresses": 0,
    }


def test_audit_empty_routes():
    assert audit_routes([]) == {
        "route_count": 0,
        "routes": [],
        "summary": {
            "active": 0,
            "partial": 0,
            "shadowed": 0,
            "covered_addresses": 0,
            "uncovered_addresses": V4_SPACE,
        },
    }


def test_audit_bare_ip_route_is_slash32():
    result = audit_routes([("8.8.8.8", "1.1.1.1", 5)])
    item = result["routes"][0]
    assert item["cidr"] == "8.8.8.8/32"
    assert item["total_addresses"] == 1
    assert item["status"] == "active"
    assert item["effective_cidrs"] == ["8.8.8.8/32"]


def test_audit_disjoint_routes_all_active():
    result = audit_routes(
        [
            ("10.0.0.0/8", "10.0.0.1", 10),
            ("192.168.0.0/16", "192.168.0.1", 20),
            ("8.8.8.8/32", "1.1.1.1", 0),
        ]
    )
    assert [r["status"] for r in result["routes"]] == ["active"] * 3
    assert result["summary"]["covered_addresses"] == (1 << 24) + (1 << 16) + 1
    assert result["summary"]["uncovered_addresses"] == (
        V4_SPACE - (1 << 24) - (1 << 16) - 1
    )


def test_audit_nested_three_levels():
    # /8 扣 /16，/16 扣 /24，/24 全生效
    result = audit_routes(
        [
            ("10.0.0.0/8", "10.0.0.1", 10),
            ("10.1.0.0/16", "10.1.0.1", 10),
            ("10.1.2.0/24", "10.1.2.1", 10),
        ]
    )
    r8, r16, r24 = result["routes"]
    assert r8["effective_addresses"] == (1 << 24) - (1 << 16)
    assert r16["effective_addresses"] == (1 << 16) - (1 << 8)
    assert r24["effective_addresses"] == 1 << 8
    assert [r["status"] for r in result["routes"]] == [
        "partial",
        "partial",
        "active",
    ]
    assert result["summary"]["covered_addresses"] == 1 << 24


def test_audit_invalid_inputs_raise():
    with pytest.raises(InvalidMetricError):
        audit_routes([("10.0.0.0/8", "1.1.1.1", 65536)])
    with pytest.raises(InvalidMetricError):
        audit_routes([("10.0.0.0/8", "1.1.1.1", True)])
    with pytest.raises(InvalidIPv4AddressError):
        audit_routes([("10.0.0.0/8", "1.1.1.1/32", 0)])
    with pytest.raises(InvalidIPv4AddressError):
        audit_routes([("10.0.0.0/8", "::1", 0)])
    with pytest.raises(Exception):
        # CIDR 非法（主机位非零）
        audit_routes([("10.0.0.1/8", "1.1.1.1", 0)])
    with pytest.raises(Exception):
        # IPv6 网段
        audit_routes([("2001:db8::/32", "1.1.1.1", 0)])


def test_audit_size_limits():
    many_routes = [
        ("10.0.0.0/8", f"10.0.{i // 256}.{(i % 256) + 1}", i % (METRIC_MAX + 1))
        for i in range(ROUTES_MAX + 1)
    ]
    with pytest.raises(ValueError):
        audit_routes(many_routes)


def test_audit_max_routes_accepted():
    routes = [("0.0.0.0/0", "1.1.1.1", 0) for _ in range(ROUTES_MAX)]
    result = audit_routes(routes)
    assert result["route_count"] == ROUTES_MAX
    # 1000 条完全相同的默认路由：同一 ECMP 组，共享整个空间
    assert result["summary"]["active"] == ROUTES_MAX
    assert result["summary"]["covered_addresses"] == V4_SPACE
    assert result["routes"][0]["ecmp_group"] == list(range(ROUTES_MAX))
    assert result["routes"][-1]["effective_cidrs"] == ["0.0.0.0/0"]


# ---------- 属性测试：audit 与逐地址暴力 oracle 对比 ----------

def _oracle_audit_sets(routes, space_start, space_end):
    """逐地址暴力解析：返回 {路由序号: 生效地址整数集合}（仅空间内部分）。

    对每个地址独立执行 LPM + 同网段最低 metric 选择，把地址记到全部
    ECMP 胜出路由名下（共享）。
    """
    parsed = []
    for cidr, _hop, metric in routes:
        start, end, text = parse_cidr_v4(cidr)
        parsed.append((start, end, int(text.rsplit("/", 1)[1]), metric))
    winners = {i: set() for i in range(len(routes))}
    for value in range(space_start, space_end + 1):
        best_prefix = -1
        best_key = None
        for start, end, prefixlen, _metric in parsed:
            if start <= value <= end and prefixlen > best_prefix:
                best_prefix = prefixlen
                best_key = (start, end)
        if best_key is None:
            continue
        min_metric = min(
            metric for start, end, _p, metric in parsed if (start, end) == best_key
        )
        for index, (start, end, _p, metric) in enumerate(parsed):
            if (start, end) == best_key and metric == min_metric:
                winners[index].add(value)
    return winners


def _cidrs_to_intervals(cidrs):
    """CIDR 列表转闭区间列表（不展开地址，可安全处理 0.0.0.0/0）。"""
    return [
        (int(net.network_address), int(net.broadcast_address))
        for net in (IPv4Network(c) for c in cidrs)
    ]


def _clip_to_space(intervals, space_start, space_end):
    """区间列表裁剪到审计空间并展开为地址集合（空间仅 1024 个地址）。"""
    out = set()
    for start, end in intervals:
        lo, hi = max(start, space_start), min(end, space_end)
        if lo <= hi:
            out.update(range(lo, hi + 1))
    return out


def test_audit_random_oracle():
    rng = random.Random(20260918)
    # 在 10.0.0.0/22（1024 个地址）内做逐地址暴力验证
    base = ip_network("10.0.0.0/22")
    space_start = int(base.network_address)
    space_end = int(base.broadcast_address)
    candidate_nets = ["0.0.0.0/0", "10.0.0.0/8", "10.0.0.0/16"]
    for prefixlen in (23, 24, 26, 28, 30, 32):
        candidate_nets.extend(str(n) for n in base.subnets(new_prefix=prefixlen))
    hops_pool = [f"192.0.2.{i}" for i in range(1, 9)]

    for _ in range(100):
        n_routes = rng.randint(0, 12)
        raw_routes = [
            (rng.choice(candidate_nets), rng.choice(hops_pool), rng.randint(0, 5))
            for _ in range(n_routes)
        ]
        result = audit_routes(raw_routes)
        oracle = _oracle_audit_sets(raw_routes, space_start, space_end)

        assert [r["index"] for r in result["routes"]] == list(range(n_routes))
        distinct_intervals = []  # 各 ECMP 组去重后的生效区间（用于并集/不相交检查）
        seen_sets = set()
        for index, item in enumerate(result["routes"]):
            intervals = _cidrs_to_intervals(item["effective_cidrs"])

            # 生效集合与逐地址 oracle 一致（比较裁剪到审计空间的部分）
            got_in_space = _clip_to_space(intervals, space_start, space_end)
            assert got_in_space == oracle[index], (index, raw_routes)

            # 无损：effective_addresses 等于 CIDR 区间总长度（不展开地址）
            assert item["effective_addresses"] == sum(
                e - s + 1 for s, e in intervals
            )
            # 状态与生效数一致
            if item["effective_addresses"] == 0:
                assert item["status"] == "shadowed"
                assert item["effective_cidrs"] == []
            elif item["effective_addresses"] == item["total_addresses"]:
                assert item["status"] == "active"
            else:
                assert item["status"] == "partial"

            # 最少块：与标准库 collapse_addresses 结果一致
            collapsed = [
                str(n)
                for n in collapse_addresses(IPv4Network(c) for c in item["effective_cidrs"])
            ]
            assert collapsed == item["effective_cidrs"]

            # ecmp_group：同网段同 metric 的全部路由，按输入顺序，含自身
            expected_group = [
                j
                for j, (c, _h, m) in enumerate(raw_routes)
                if parse_cidr_v4(c)[2] == item["cidr"] and m == item["metric"]
            ]
            assert item["ecmp_group"] == expected_group
            # 组内共享同一生效集合
            for peer in expected_group:
                assert (
                    result["routes"][peer]["effective_cidrs"]
                    == item["effective_cidrs"]
                )

            key = tuple(item["effective_cidrs"])
            if key not in seen_sets:
                seen_sets.add(key)
                distinct_intervals.extend(intervals)

        # 不同 ECMP 组的生效集合互不相交：合并后总长度不变
        total = sum(e - s + 1 for s, e in distinct_intervals)
        merged = merge_intervals(distinct_intervals)
        merged_total = sum(e - s + 1 for s, e in merged)
        assert merged_total == total

        # 汇总一致性
        statuses = [r["status"] for r in result["routes"]]
        assert result["summary"]["active"] == statuses.count("active")
        assert result["summary"]["partial"] == statuses.count("partial")
        assert result["summary"]["shadowed"] == statuses.count("shadowed")
        # 覆盖数 = 各 ECMP 组生效集合并集大小（共享集合只计一次）
        assert result["summary"]["covered_addresses"] == merged_total
        assert result["summary"]["uncovered_addresses"] == V4_SPACE - merged_total
        # 与 oracle 的空间内并集一致
        oracle_union = set().union(*oracle.values()) if oracle else set()
        assert _clip_to_space(merged, space_start, space_end) == oracle_union
