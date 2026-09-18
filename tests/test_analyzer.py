"""核心分析逻辑的单元测试。"""
import random

import pytest
from ipaddress import IPv4Address, IPv4Network, collapse_addresses, ip_network

from app.analyzer import (
    CIDR_DIFF_MAX_ENTRIES,
    HIERARCHY_MAX_ENTRIES,
    CidrDiffInputError,
    HierarchyInputError,
    InvalidCIDRError,
    V4_SPACE,
    analyze_rules,
    build_cidr_hierarchy,
    build_decision_intervals,
    compare_rule_sets,
    compress_intervals,
    diff_cidr_lists,
    explain_query,
    merge_intervals,
    parse_cidr_v4,
    range_to_cidrs,
    subtract_covered,
)


# ---------- 解析 ----------

def test_parse_basic_cidr():
    start, end, text = parse_cidr_v4("10.0.0.0/8")
    assert start == 10 << 24
    assert end == (10 << 24) + (1 << 24) - 1
    assert text == "10.0.0.0/8"


def test_parse_bare_ip_is_32():
    start, end, text = parse_cidr_v4("192.168.1.1")
    assert start == end
    assert text == "192.168.1.1/32"


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "   ",
        "10.0.0.0/33",
        "10.0.0.0/-1",
        "10.0.0",
        "999.0.0.0/8",
        "10.0.0.1/8",  # 主机位非零（strict）
        "not-a-cidr",
        "10.0.0.0/8/8",
        "2001:db8::/32",  # IPv6
        "::1/128",
        "fe80::1",
    ],
)
def test_parse_rejects_invalid_and_ipv6(bad):
    with pytest.raises(InvalidCIDRError):
        parse_cidr_v4(bad)


# ---------- 区间与压缩 ----------

def test_subtract_disjoint_and_overlap():
    covered = [(10, 20), (40, 50)]
    assert subtract_covered((0, 100), covered) == [(0, 9), (21, 39), (51, 100)]
    assert subtract_covered((10, 20), covered) == []
    assert subtract_covered((15, 45), covered) == [(21, 39)]
    assert subtract_covered((0, 5), covered) == [(0, 5)]


def test_merge_includes_adjacent():
    assert merge_intervals([(5, 9), (1, 3), (10, 12), (1, 2)]) == [(1, 3), (5, 12)]
    assert merge_intervals([]) == []


def test_range_to_cidrs_single_block():
    start, end, _ = parse_cidr_v4("10.0.0.0/16")
    assert range_to_cidrs(start, end) == ["10.0.0.0/16"]


def test_range_to_cidrs_full_space_is_slash0():
    assert range_to_cidrs(0, (1 << 32) - 1) == ["0.0.0.0/0"]


def test_compress_split_hole_is_minimal():
    # /8 挖掉开头的 /16，贪心结果必须与手工最优分块一致
    start, end, _ = parse_cidr_v4("10.0.0.0/8")
    pieces = subtract_covered((start, end), [parse_cidr_v4("10.0.0.0/16")[:2]])
    cidrs = compress_intervals(pieces)
    assert cidrs == [
        "10.1.0.0/16",
        "10.2.0.0/15",
        "10.4.0.0/14",
        "10.8.0.0/13",
        "10.16.0.0/12",
        "10.32.0.0/11",
        "10.64.0.0/10",
        "10.128.0.0/9",
    ]
    # 无损：数量守恒
    assert sum(IPv4Network(c).num_addresses for c in cidrs) == (1 << 24) - (1 << 16)


# ---------- 规则分析 ----------

def test_full_partial_shadowed_and_totals():
    result = analyze_rules(
        [
            ("allow", "10.0.0.0/8"),  # full, 2^24
            ("deny", "10.1.0.0/16"),  # shadowed
            ("allow", "192.168.0.0/16"),  # full, 2^16
            ("deny", "10.0.0.0/7"),  # partial: 只 11.0.0.0/8 生效
        ]
    )
    statuses = [r["status"] for r in result["rules"]]
    assert statuses == ["full", "shadowed", "full", "partial"]

    last = result["rules"][3]
    assert last["effective_addresses"] == 1 << 24
    assert last["covered_addresses"] == 1 << 24
    assert last["effective_cidrs"] == ["11.0.0.0/8"]

    summary = result["summary"]
    assert summary["full"] == 2
    assert summary["partial"] == 1
    assert summary["shadowed"] == 1
    assert summary["effective_allow_addresses"] == (1 << 24) + (1 << 16)
    assert summary["effective_deny_addresses"] == 1 << 24


def test_cross_action_shadowing():
    # 先前的 allow 同样遮蔽后面的 deny
    result = analyze_rules([("allow", "0.0.0.0/0"), ("deny", "8.8.8.8/32")])
    assert result["rules"][1]["status"] == "shadowed"
    assert result["rules"][1]["effective_cidrs"] == []
    assert result["summary"]["effective_deny_addresses"] == 0
    assert result["summary"]["effective_allow_addresses"] == 1 << 32


def test_order_matters_and_duplicates_shadow():
    first = analyze_rules([("allow", "10.1.0.0/16"), ("deny", "10.0.0.0/8")])
    second = analyze_rules([("deny", "10.0.0.0/8"), ("allow", "10.1.0.0/16")])
    assert first["rules"][1]["status"] == "partial"
    assert second["rules"][1]["status"] == "shadowed"

    dup = analyze_rules([("allow", "1.2.3.0/24"), ("allow", "1.2.3.0/24")])
    assert dup["rules"][1]["status"] == "shadowed"
    # 重复地址不重复计入
    assert dup["summary"]["effective_allow_addresses"] == 256


def test_empty_rules_rejected():
    with pytest.raises(ValueError):
        analyze_rules([])


def test_adjacent_fragments_merge_before_compress():
    # /30 中先遮蔽末端两个地址，剩余 .0/.1 相邻且 /31 对齐 -> 必须合并为单个 /31
    # （若不在压缩前合并相邻碎片，会退化为两个 /32）
    result = analyze_rules(
        [
            ("deny", "10.0.0.2/31"),
            ("allow", "10.0.0.0/30"),
        ]
    )
    last = result["rules"][1]
    assert last["effective_cidrs"] == ["10.0.0.0/31"]
    assert last["status"] == "partial"

    # 相邻但不对齐的两个地址（.1/.2）无法合并，最优仍是两个 /32
    result2 = analyze_rules(
        [
            ("deny", "10.0.0.0/32"),
            ("deny", "10.0.0.3/32"),
            ("allow", "10.0.0.0/30"),
        ]
    )
    assert result2["rules"][2]["effective_cidrs"] == [
        "10.0.0.1/32",
        "10.0.0.2/32",
    ]


# ---------- 属性测试：与 ipaddress 标准库 oracle 对比 ----------

def test_random_rules_oracle():
    rng = random.Random(20260918)
    universe = list(ip_network("10.0.0.0/16").subnets(new_prefix=24))  # 256 个 /24
    for _ in range(30):
        picked = rng.sample(universe, k=rng.randint(1, 12))
        actions = [rng.choice(["allow", "deny"]) for _ in picked]

        result = analyze_rules([(a, str(net)) for a, net in zip(actions, picked)])

        claimed: set = set()
        seen_effective: set = set()
        for net, res in zip(picked, result["rules"]):
            remaining = set(net) - claimed
            # 标准库给出的最少 CIDR 分块
            expected = [str(c) for c in collapse_addresses(remaining)]
            assert res["effective_cidrs"] == expected

            rebuilt = set()
            for c in res["effective_cidrs"]:
                rebuilt |= set(ip_network(c))
            assert rebuilt == remaining  # 无损
            assert not rebuilt & seen_effective  # 生效集合两两不相交
            seen_effective |= rebuilt
            claimed |= set(net)

        summary = result["summary"]
        assert summary["effective_allow_addresses"] == sum(
            r["effective_addresses"] for r in result["rules"] if r["action"] == "allow"
        )
        assert summary["effective_deny_addresses"] == sum(
            r["effective_addresses"] for r in result["rules"] if r["action"] == "deny"
        )
        assert (
            sum(r["effective_addresses"] for r in result["rules"])
            == len(seen_effective)
        )


# ---------- 规则集等价性比较 ----------

def test_decision_partition_covers_full_space_without_enumeration():
    rules = [("allow", "10.0.0.0/8"), ("deny", "10.1.0.0/16")]
    partition = build_decision_intervals(rules, "deny")

    # 有序、首尾相接、数量守恒：完整覆盖整个 IPv4 空间
    assert partition[0][0] == 0
    assert partition[-1][1] == V4_SPACE - 1
    assert sum(end - start + 1 for start, end, _ in partition) == V4_SPACE
    for (_, prev_end, _), (next_start, _, _) in zip(partition, partition[1:]):
        assert next_start == prev_end + 1

    # 10.1/16 先命中 allow；其余 10/8 为 allow；外部为默认 deny
    actions = {action for _, _, action in partition}
    assert actions == {"allow", "deny"}
    assert build_decision_intervals(rules, "deny")[0][2] == "deny"

    # 被完全遮蔽的规则不出现在最终判定中
    shadowed = [("allow", "10.0.0.0/8"), ("deny", "10.1.0.0/16")]
    assert build_decision_intervals(shadowed, "deny") == build_decision_intervals(
        [("allow", "10.0.0.0/8")], "deny"
    )


def test_compare_identical_and_shadowed_rules_equivalent():
    rules = [("allow", "10.0.0.0/8"), ("deny", "10.1.0.0/16")]
    # 相同规则集必然等价
    assert compare_rule_sets(rules, "deny", rules, "deny")["equivalent"]
    # 追加一条被完全遮蔽的规则不改变最终判定
    with_extra = [*rules, ("allow", "10.1.0.0/24")]
    assert compare_rule_sets(rules, "deny", with_extra, "deny") == {
        "equivalent": True,
        "differences": [],
    }
    # 空规则集 + 相同默认动作同样等价
    assert compare_rule_sets([], "allow", [], "allow") == {
        "equivalent": True,
        "differences": [],
    }


def test_compare_order_matters_first_match_wins():
    # 与 /analyze 一致的顺序敏感性：10.1/16 左侧 allow、右侧 deny
    left = [("allow", "10.0.0.0/8"), ("deny", "10.1.0.0/16")]
    right = [("deny", "10.1.0.0/16"), ("allow", "10.0.0.0/8")]
    result = compare_rule_sets(left, "deny", right, "deny")
    assert result["equivalent"] is False
    assert result["differences"] == [
        {
            "left_action": "allow",
            "right_action": "deny",
            "address_count": 1 << 16,
            "cidrs": ["10.1.0.0/16"],
        }
    ]


def test_compare_default_action_drives_full_space():
    # 两侧都没有规则，默认动作不同 -> 整个 IPv4 空间不同
    result = compare_rule_sets([], "allow", [], "deny")
    assert result == {
        "equivalent": False,
        "differences": [
            {
                "left_action": "allow",
                "right_action": "deny",
                "address_count": V4_SPACE,
                "cidrs": ["0.0.0.0/0"],
            }
        ],
    }

    # 左 allow 0/0（default deny 不生效）与右空规则 default allow 等价
    assert compare_rule_sets(
        [("allow", "0.0.0.0/0")], "deny", [], "allow"
    )["equivalent"]


def test_compare_bidirectional_groups_and_minimal_compression():
    left = [("allow", "10.0.0.0/8"), ("deny", "11.0.0.0/8")]
    right = [("deny", "10.0.0.0/8"), ("allow", "11.0.0.0/8")]
    result = compare_rule_sets(left, "deny", right, "allow")

    groups = {
        (g["left_action"], g["right_action"]): g for g in result["differences"]
    }
    assert set(groups) == {("allow", "deny"), ("deny", "allow")}
    assert groups[("allow", "deny")]["cidrs"] == ["10.0.0.0/8"]
    assert groups[("allow", "deny")]["address_count"] == 1 << 24
    # 11/8 双向 + default 在其余空间 deny/allow，压缩必须与标准库挖洞结果一致
    rest = groups[("deny", "allow")]
    expected = [
        str(c)
        for c in collapse_addresses(
            list(ip_network("0.0.0.0/0").address_exclude(ip_network("10.0.0.0/8")))
        )
    ]
    assert rest["cidrs"] == expected
    assert rest["address_count"] == V4_SPACE - (1 << 24)
    assert sum(g["address_count"] for g in result["differences"]) == V4_SPACE


def test_compare_rejects_invalid_inputs():
    with pytest.raises(InvalidCIDRError):
        compare_rule_sets([("allow", "10.0.0.1/8")], "deny", [], "deny")
    with pytest.raises(InvalidCIDRError):
        compare_rule_sets([], "deny", [("allow", "2001:db8::/32")], "deny")
    with pytest.raises(ValueError):
        compare_rule_sets([("permit", "10.0.0.0/8")], "deny", [], "deny")
    with pytest.raises(ValueError):
        compare_rule_sets([], "PERMIT", [], "deny")


def test_compare_random_rules_oracle():
    """与逐地址暴力 oracle 对比（差异仅可能出现在 10.0.0.0/24 内）。"""
    rng = random.Random(20260918)
    universe = [str(n) for n in ip_network("10.0.0.0/24").subnets(new_prefix=30)]
    base = int(ip_network("10.0.0.0/24").network_address)
    outside_nets = list(
        ip_network("0.0.0.0/0").address_exclude(ip_network("10.0.0.0/24"))
    )

    def make_rules():
        return [
            (rng.choice(["allow", "deny"]), rng.choice(universe))
            for _ in range(rng.randint(0, 10))
        ]

    def decide(parsed, default, value):
        for action, (start, end, _) in parsed:
            if start <= value <= end:
                return action
        return default

    for _ in range(200):
        left_raw, right_raw = make_rules(), make_rules()
        left_default = rng.choice(["allow", "deny"])
        right_default = rng.choice(["allow", "deny"])
        left_parsed = [(a, parse_cidr_v4(c)) for a, c in left_raw]
        right_parsed = [(a, parse_cidr_v4(c)) for a, c in right_raw]

        result = compare_rule_sets(left_raw, left_default, right_raw, right_default)

        expected: dict[tuple[str, str], set] = {}
        for value in range(base, base + 256):
            la = decide(left_parsed, left_default, value)
            ra = decide(right_parsed, right_default, value)
            if la != ra:
                expected.setdefault((la, ra), set()).add(value)

        # /24 之外只有 default 可能不同
        external = left_default != right_default
        got = {
            (g["left_action"], g["right_action"]): g for g in result["differences"]
        }
        expected_keys = set(expected) | (
            {(left_default, right_default)} if external else set()
        )
        assert set(got) == expected_keys

        for key, addresses in expected.items():
            group = got[key]
            if external and key == (left_default, right_default):
                # 该组同时包含 /24 外的 default 差异，稍后统一校验
                continue
            assert group["address_count"] == len(addresses)
            assert group["cidrs"] == [
                str(c)
                for c in collapse_addresses(
                    [ip_network(f"{IPv4Address(value)}/32") for value in addresses]
                )
            ]
        if external:
            group = got[(left_default, right_default)]
            within = expected.get((left_default, right_default), set())
            within_nets = [
                ip_network(f"{IPv4Address(value)}/32") for value in within
            ]
            assert group["cidrs"] == [
                str(c) for c in collapse_addresses([*within_nets, *outside_nets])
            ]
            assert group["address_count"] == len(within) + V4_SPACE - 256

        assert result["equivalent"] == (not expected and not external)


# ---------- 地址空间裁决归因（/explain） ----------

def test_explain_basic_attribution_and_default_last():
    result = explain_query(
        [
            ("allow", "10.0.0.0/16"),
            ("deny", "10.0.1.0/24"),  # 被规则 0 完全遮蔽
            ("deny", "10.2.0.0/16"),
        ],
        "deny",
        "10.0.0.0/8",
    )
    assert result["query"] == "10.0.0.0/8"
    assert result["total_addresses"] == 1 << 24

    attribution = result["attribution"]
    # 规则 1 在 query 内完全遮蔽 -> 不出现；规则索引升序、默认项最后
    assert [item["rule_index"] for item in attribution] == [0, 2, None]
    assert [item["source"] for item in attribution] == ["rule", "rule", "default"]
    assert attribution[0] == {
        "source": "rule",
        "rule_index": 0,
        "action": "allow",
        "address_count": 1 << 16,
        "cidrs": ["10.0.0.0/16"],
    }
    assert attribution[1] == {
        "source": "rule",
        "rule_index": 2,
        "action": "deny",
        "address_count": 1 << 16,
        "cidrs": ["10.2.0.0/16"],
    }
    # 默认项：10.0.0.0/8 挖掉 10.0.0.0/16 与 10.2.0.0/16 后的剩余
    default_item = attribution[2]
    assert default_item["action"] == "deny"
    assert default_item["cidrs"] == [
        "10.1.0.0/16",
        "10.3.0.0/16",
        "10.4.0.0/14",
        "10.8.0.0/13",
        "10.16.0.0/12",
        "10.32.0.0/11",
        "10.64.0.0/10",
        "10.128.0.0/9",
    ]
    # 不重不漏：各项地址数之和等于 query 总数
    assert sum(item["address_count"] for item in attribution) == 1 << 24


def test_explain_bare_ip_query_and_action_hit():
    result = explain_query(
        [("allow", "8.8.8.0/24"), ("deny", "8.8.8.8")],
        "allow",
        "8.8.8.8",
    )
    assert result["query"] == "8.8.8.8/32"
    assert result["total_addresses"] == 1
    # 首条匹配生效：8.8.8.8 先命中规则 0
    assert result["attribution"] == [
        {
            "source": "rule",
            "rule_index": 0,
            "action": "allow",
            "address_count": 1,
            "cidrs": ["8.8.8.8/32"],
        }
    ]


def test_explain_empty_rules_all_default():
    result = explain_query([], "allow", "192.168.0.0/16")
    assert result["attribution"] == [
        {
            "source": "default",
            "rule_index": None,
            "action": "allow",
            "address_count": 1 << 16,
            "cidrs": ["192.168.0.0/16"],
        }
    ]


def test_explain_full_coverage_has_no_default_item():
    result = explain_query(
        [("deny", "10.0.0.0/8")],
        "allow",
        "10.0.0.0/8",
    )
    assert result["attribution"] == [
        {
            "source": "rule",
            "rule_index": 0,
            "action": "deny",
            "address_count": 1 << 24,
            "cidrs": ["10.0.0.0/8"],
        }
    ]


def test_explain_ignores_rules_outside_query():
    result = explain_query(
        [
            ("allow", "192.168.0.0/16"),  # 与 query 不相交
            ("deny", "10.1.0.0/16"),
        ],
        "deny",
        "10.0.0.0/8",
    )
    assert [item["rule_index"] for item in result["attribution"]] == [1, None]
    assert result["attribution"][0]["cidrs"] == ["10.1.0.0/16"]
    assert result["attribution"][1]["cidrs"] == [
        "10.0.0.0/16",
        "10.2.0.0/15",
        "10.4.0.0/14",
        "10.8.0.0/13",
        "10.16.0.0/12",
        "10.32.0.0/11",
        "10.64.0.0/10",
        "10.128.0.0/9",
    ]


def test_explain_rejects_invalid_inputs():
    with pytest.raises(InvalidCIDRError):
        explain_query([], "deny", "10.0.0.1/8")
    with pytest.raises(InvalidCIDRError):
        explain_query([], "deny", "2001:db8::/32")
    with pytest.raises(InvalidCIDRError):
        explain_query([("allow", "garbage")], "deny", "10.0.0.0/8")
    with pytest.raises(ValueError):
        explain_query([("permit", "10.0.0.0/8")], "deny", "10.0.0.0/8")
    with pytest.raises(ValueError):
        explain_query([], "PERMIT", "10.0.0.0/8")


def test_explain_random_rules_oracle():
    """与逐地址暴力 oracle 对比：归属、覆盖不重不漏、最少 CIDR。"""
    rng = random.Random(20260918)
    universe = [str(n) for n in ip_network("10.0.0.0/24").subnets(new_prefix=30)]
    q_start, q_end, _ = parse_cidr_v4("10.0.0.0/24")

    for _ in range(200):
        rules = [
            (rng.choice(["allow", "deny"]), rng.choice(universe))
            for _ in range(rng.randint(0, 10))
        ]
        default = rng.choice(["allow", "deny"])
        parsed = [(a, parse_cidr_v4(c)) for a, c in rules]

        result = explain_query(rules, default, "10.0.0.0/24")
        assert result["query"] == "10.0.0.0/24"
        assert result["total_addresses"] == 256

        # 逐地址暴力判定归属：首条命中的规则索引，否则 default
        expected: dict[object, set] = {}
        for value in range(q_start, q_end + 1):
            owner: object = None
            for index, (_, (start, end, _)) in enumerate(parsed):
                if start <= value <= end:
                    owner = index
                    break
            expected.setdefault(owner, set()).add(value)

        attribution = result["attribution"]
        # 规则项按索引升序、默认项最后
        keys = [item["rule_index"] for item in attribution]
        rule_keys = [k for k in keys if k is not None]
        assert rule_keys == sorted(rule_keys)
        if None in keys:
            assert keys[-1] is None
        assert set(keys) == set(expected)

        for item in attribution:
            owner = item["rule_index"]
            addresses = expected[owner]
            if owner is None:
                assert item["source"] == "default"
                assert item["action"] == default
            else:
                assert item["source"] == "rule"
                assert item["action"] == parsed[owner][0]
            assert item["address_count"] == len(addresses)
            # 与标准库 oracle 对比：无损且块数最少
            assert item["cidrs"] == [
                str(c)
                for c in collapse_addresses(
                    [ip_network(f"{IPv4Address(v)}/32") for v in addresses]
                )
            ]

        # 不重不漏覆盖整个 query
        assert sum(item["address_count"] for item in attribution) == 256


# ---------- CIDR 包含层级（build_cidr_hierarchy） ----------

def _flatten(nodes):
    """先根遍历展平森林。"""
    out = []
    for node in nodes:
        out.append(node)
        out.extend(_flatten(node["children"]))
    return out


def _oracle_exclusive(entries):
    """用 ipaddress 计算 {id: 独占地址集合} 与 {id: 父节点对象或 None}。"""
    parsed = [(eid, ip_network(cidr)) for eid, cidr in entries]
    parents = {}
    exclusive = {}
    for eid, net in parsed:
        supers = [
            (other.prefixlen, other_id)
            for other_id, other in parsed
            if other_id != eid
            and other.version == net.version
            and other.supernet_of(net)
        ]
        if supers:
            # 前缀最长的严格超网唯一（无同网段重复前提）
            parents[eid] = max(supers)[1]
        else:
            parents[eid] = None
        child_union: set = set()
        for other_id, other in parsed:
            if parents.get(other_id) == eid:
                child_union |= set(other)
        exclusive[eid] = set(net) - child_union
    return parents, exclusive


def test_hierarchy_basic_nesting_and_exclusive_cidrs():
    result = build_cidr_hierarchy(
        [
            ("root", "10.0.0.0/8"),
            ("mid", "10.1.0.0/16"),
            ("leaf1", "10.1.1.0/24"),
            ("leaf2", "10.1.2.0/24"),
            ("other", "10.2.0.0/16"),
        ]
    )
    assert result["node_count"] == 5
    assert result["root_count"] == 1
    root = result["roots"][0]
    assert root["id"] == "root"
    assert root["parent_id"] is None
    assert root["total_addresses"] == 1 << 24
    assert root["exclusive_address_count"] == (1 << 24) - 2 * (1 << 16)
    # 独占集合：/8 挖掉两个直接子 /16（10.1/16、10.2/16）
    assert root["exclusive_cidrs"] == [
        "10.0.0.0/16",
        "10.3.0.0/16",
        "10.4.0.0/14",
        "10.8.0.0/13",
        "10.16.0.0/12",
        "10.32.0.0/11",
        "10.64.0.0/10",
        "10.128.0.0/9",
    ]

    mid, other = root["children"]
    assert mid["id"] == "mid" and mid["parent_id"] == "root"
    assert other["id"] == "other" and other["parent_id"] == "root"
    # 叶子为孙节点，不计入 mid 的直接子并集之外：扣除两个 /24
    assert mid["exclusive_address_count"] == (1 << 16) - 2 * (1 << 8)
    assert [c["id"] for c in mid["children"]] == ["leaf1", "leaf2"]
    for leaf in mid["children"]:
        assert leaf["parent_id"] == "mid"
        assert leaf["exclusive_address_count"] == 256
        assert leaf["exclusive_cidrs"] == [leaf["cidr"]]
        assert leaf["children"] == []
    # other 无直接子节点：独占整个自身网段
    assert other["exclusive_address_count"] == 1 << 16
    assert other["exclusive_cidrs"] == ["10.2.0.0/16"]


def test_hierarchy_longest_prefix_supernet_wins():
    # /8、/16、/24 三级：/24 的 parent 必须是 /16 而非 /8
    result = build_cidr_hierarchy(
        [("a", "10.0.0.0/8"), ("b", "10.1.0.0/16"), ("c", "10.1.0.0/24")]
    )
    flat = {n["id"]: n for n in _flatten(result["roots"])}
    assert flat["a"]["parent_id"] is None
    assert flat["b"]["parent_id"] == "a"
    assert flat["c"]["parent_id"] == "b"


def test_hierarchy_multiple_roots_and_sibling_order():
    result = build_cidr_hierarchy(
        [
            # 输入故意乱序；兄弟必须按 (网络地址, 前缀长度, 输入序号) 排
            ("n2", "192.168.0.0/16"),
            ("n0", "8.8.8.8/32"),
            ("n1", "10.0.0.0/8"),
        ]
    )
    assert result["root_count"] == 3
    assert [n["id"] for n in result["roots"]] == ["n0", "n1", "n2"]
    # 全为 root，各自独占自身
    for node in result["roots"]:
        assert node["parent_id"] is None
        assert node["exclusive_address_count"] == node["total_addresses"]
        assert node["exclusive_cidrs"] == [node["cidr"]]


def test_hierarchy_slash0_is_root_and_excludes_direct_children():
    result = build_cidr_hierarchy(
        [("inside", "10.0.0.0/8"), ("outside", "8.8.8.8/32"), ("all", "0.0.0.0/0")]
    )
    assert result["root_count"] == 1
    root = result["roots"][0]
    assert root["cidr"] == "0.0.0.0/0"
    assert root["total_addresses"] == 1 << 32
    # 独占 = 全空间扣除两个直接子节点并集
    assert root["exclusive_address_count"] == (1 << 32) - (1 << 24) - 1
    assert sum(
        IPv4Network(c).num_addresses for c in root["exclusive_cidrs"]
    ) == root["exclusive_address_count"]
    assert [c["id"] for c in root["children"]] == ["outside", "inside"]


def test_hierarchy_bare_ip_normalized_to_32():
    result = build_cidr_hierarchy([("h", "8.8.8.8"), ("net", "8.8.8.0/24")])
    flat = {n["id"]: n for n in _flatten(result["roots"])}
    assert flat["h"]["cidr"] == "8.8.8.8/32"
    assert flat["h"]["parent_id"] == "net"
    assert flat["net"]["parent_id"] is None


def test_hierarchy_input_order_tiebreak_is_stable():
    # 相同网络地址、不同前缀（严格包含）：兄弟按 (网络地址, 前缀长度, 输入序号) 排
    result = build_cidr_hierarchy(
        [("p", "10.128.0.0/9"), ("q", "10.0.0.0/8"), ("r", "11.0.0.0/8")]
    )
    # q(10/8) 与 r(11/8) 不相交，均为 root；p(10.128/9) 是 q 的子节点
    assert [n["cidr"] for n in result["roots"]] == ["10.0.0.0/8", "11.0.0.0/8"]
    q = result["roots"][0]
    assert [c["cidr"] for c in q["children"]] == ["10.128.0.0/9"]


def test_hierarchy_integer_ids_preserved():
    result = build_cidr_hierarchy([(7, "10.0.0.0/8"), (0, "10.1.0.0/16")])
    flat = {n["id"]: n for n in _flatten(result["roots"])}
    assert set(flat) == {7, 0}
    assert flat[0]["parent_id"] == 7
    assert flat[7]["parent_id"] is None


def test_hierarchy_duplicate_network_raises_and_lists_ids():
    with pytest.raises(HierarchyInputError) as exc:
        build_cidr_hierarchy(
            [("a", "10.0.0.0/8"), ("b", "10.0.0.0/08"), ("c", "8.8.8.8/32")]
        )
    assert exc.value.duplicate_ids == []
    assert exc.value.duplicate_networks == [
        {
            "cidr": "10.0.0.0/8",
            "entries": [
                {"index": 0, "id": "a", "cidr": "10.0.0.0/8"},
                {"index": 1, "id": "b", "cidr": "10.0.0.0/8"},
            ],
        }
    ]


def test_hierarchy_duplicate_id_raises_and_lists_indexes():
    with pytest.raises(HierarchyInputError) as exc:
        build_cidr_hierarchy(
            [("x", "10.0.0.0/8"), ("x", "11.0.0.0/8"), ("y", "8.8.8.8/32"),
             ("x", "12.0.0.0/8")]
        )
    assert exc.value.duplicate_ids == [{"id": "x", "indexes": [0, 1, 3]}]
    assert exc.value.duplicate_networks == []


def test_hierarchy_rejects_bad_ids_out_of_range_and_invalid_cidrs():
    with pytest.raises(ValueError):
        build_cidr_hierarchy([(True, "10.0.0.0/8")])
    with pytest.raises(ValueError):
        build_cidr_hierarchy([("   ", "10.0.0.0/8")])
    with pytest.raises(ValueError):
        build_cidr_hierarchy([])
    with pytest.raises(ValueError):
        build_cidr_hierarchy(
            [(i, f"1.0.{i // 256}.{i % 256}/32") for i in range(HIERARCHY_MAX_ENTRIES + 1)]
        )
    with pytest.raises(InvalidCIDRError):
        build_cidr_hierarchy([("a", "10.0.0.1/8")])
    with pytest.raises(InvalidCIDRError):
        build_cidr_hierarchy([("a", "2001:db8::/32")])


def test_hierarchy_random_oracle():
    """与 ipaddress oracle 对比：父节点、独占集合、最少 CIDR、稳定次序。"""
    rng = random.Random(20260918)
    base = ip_network("10.0.0.0/16")
    # 多种前缀长度的候选池（对齐、互不重复），抽样后可形成任意嵌套
    pool = [
        net
        for prefixlen in range(17, 31)
        for net in base.subnets(new_prefix=prefixlen)
    ]
    for _ in range(60):
        picked = rng.sample(pool, k=rng.randint(1, 14))
        entries = [(f"n{i}", str(net)) for i, net in enumerate(picked)]
        result = build_cidr_hierarchy(entries)
        expected_parents, expected_exclusive = _oracle_exclusive(entries)

        flat = _flatten(result["roots"])
        assert len(flat) == len(picked)
        by_id = {n["id"]: n for n in flat}

        # 全部地址数守恒：所有节点独占集合互不相交且覆盖全部输入并集
        covered = set()
        for node in flat:
            assert node["parent_id"] == expected_parents[node["id"]]
            addresses = expected_exclusive[node["id"]]
            assert node["exclusive_address_count"] == len(addresses)
            expected_cidrs = [
                str(c)
                for c in collapse_addresses(
                    [ip_network(f"{IPv4Address(v)}/32") for v in addresses]
                )
            ]
            assert node["exclusive_cidrs"] == expected_cidrs
            rebuilt = set()
            for cidr in node["exclusive_cidrs"]:
                rebuilt |= set(ip_network(cidr))
            assert rebuilt == addresses  # 无损
            assert not rebuilt & covered  # 独占集合两两不相交
            covered |= rebuilt
            assert node["total_addresses"] == ip_network(node["cidr"]).num_addresses

        assert covered == set().union(*[set(n) for n in picked])        # 结构：children 与 parent_id 一致，且整树有序
        for node in flat:
            parent = by_id.get(node["parent_id"]) if node["parent_id"] is not None else None
            if parent is None:
                assert node in result["roots"]
            else:
                assert node in parent["children"]

        def check_order(nodes):
            keys = [
                (int(ip_network(n["cidr"]).network_address),
                 ip_network(n["cidr"]).prefixlen)
                for n in nodes
            ]
            assert keys == sorted(keys)
            for n in nodes:
                check_order(n["children"])

        check_order(result["roots"])


# ---------- CIDR 清单差异（diff_cidr_lists） ----------


def test_diff_added_removed_changed_unchanged_and_order():
    result = diff_cidr_lists(
        [
            ("net", "10.0.0.0/8"),
            ("sub-a", "10.1.0.0/16"),
            ("sub-b", "10.2.0.0/16"),
            ("old-dns", "8.8.8.8/32"),
        ],
        [
            ("net", "10.0.0.0/8"),
            ("sub-a", "10.1.0.0/24"),
            ("sub-c", "10.2.0.0/16"),
            ("new-dns", "8.8.8.8/32"),
        ],
    )
    assert result["before_count"] == 4
    assert result["after_count"] == 4

    # 保持 before 顺序，新增项按 after 顺序追加
    assert [(c["id"], c["change"]) for c in result["changes"]] == [
        ("net", "unchanged"),
        ("sub-a", "cidr_changed"),
        ("sub-b", "removed"),
        ("old-dns", "removed"),
        ("sub-c", "added"),
        ("new-dns", "added"),
    ]

    by_id = {c["id"]: c for c in result["changes"]}
    assert by_id["net"] == {
        "id": "net",
        "change": "unchanged",
        "before_cidr": "10.0.0.0/8",
        "after_cidr": "10.0.0.0/8",
        "before_parent_id": None,
        "after_parent_id": None,
        "parent_changed": False,
        "affected_address_count": 0,
    }
    sub_a = by_id["sub-a"]
    assert sub_a["before_cidr"] == "10.1.0.0/16"
    assert sub_a["after_cidr"] == "10.1.0.0/24"
    assert sub_a["before_parent_id"] == "net"
    assert sub_a["after_parent_id"] == "net"
    assert sub_a["parent_changed"] is False
    # 对称差：/16 缩成 /24 -> 65536 - 256 = 65280
    assert sub_a["affected_address_count"] == 65536 - 256

    removed = by_id["sub-b"]
    assert removed["after_cidr"] is None
    assert removed["before_parent_id"] == "net"
    assert removed["after_parent_id"] is None
    assert removed["parent_changed"] is None
    assert removed["affected_address_count"] == 65536

    added = by_id["sub-c"]
    assert added["before_cidr"] is None
    assert added["before_parent_id"] is None
    assert added["after_parent_id"] == "net"
    assert added["parent_changed"] is None
    assert added["affected_address_count"] == 65536

    # 规范化后网段相同但 id 不同 -> 替换候选（含 sub-b/sub-c 与 old-dns/new-dns）
    assert result["replacement_candidates"] == [
        {
            "before_id": "sub-b",
            "after_id": "sub-c",
            "cidr": "10.2.0.0/16",
            "address_count": 65536,
        },
        {
            "before_id": "old-dns",
            "after_id": "new-dns",
            "cidr": "8.8.8.8/32",
            "address_count": 1,
        },
    ]

    assert result["summary"] == {
        "added": 2,
        "removed": 2,
        "cidr_changed": 1,
        "unchanged": 1,
        "parent_changed": 0,
        "replacement_candidate_count": 2,
        "affected_address_count": 65280 + 2 * 65536 + 2,
    }


def test_diff_parent_change_without_cidr_change():
    # 删除中间层 /16 后，host 的直接父节点由 /16 变为 /8（网段本身未变）
    result = diff_cidr_lists(
        [
            ("net", "10.0.0.0/8"),
            ("sub", "10.1.0.0/16"),
            ("host", "10.1.0.1/32"),
        ],
        [
            ("net", "10.0.0.0/8"),
            ("host", "10.1.0.1/32"),
        ],
    )
    by_id = {c["id"]: c for c in result["changes"]}
    host = by_id["host"]
    assert host["change"] == "unchanged"
    assert host["parent_changed"] is True
    assert host["before_parent_id"] == "sub"
    assert host["after_parent_id"] == "net"
    assert host["affected_address_count"] == 0
    assert by_id["net"]["parent_changed"] is False
    assert result["summary"]["parent_changed"] == 1
    assert result["summary"]["unchanged"] == 2
    assert result["summary"]["affected_address_count"] == 65536  # 仅 sub 删除


def test_diff_parent_change_together_with_cidr_change():
    # host 网段改为另一 /32，同时中间层被删：cidr_changed 与 parent_changed 同时成立
    result = diff_cidr_lists(
        [
            ("net", "10.0.0.0/8"),
            ("sub", "10.1.0.0/16"),
            ("host", "10.1.0.1/32"),
        ],
        [
            ("net", "10.0.0.0/8"),
            ("host", "10.2.2.2/32"),
        ],
    )
    host = {c["id"]: c for c in result["changes"]}["host"]
    assert host["change"] == "cidr_changed"
    assert host["parent_changed"] is True
    assert host["before_parent_id"] == "sub"
    assert host["after_parent_id"] == "net"
    # 两个不相交 /32 的对称差 = 2
    assert host["affected_address_count"] == 2
    summary = result["summary"]
    assert summary["cidr_changed"] == 1
    assert summary["parent_changed"] == 1
    assert summary["affected_address_count"] == 65536 + 2


def test_diff_affected_address_symmetric_difference_cases():
    # 扩张：/25 -> /24（包含），对称差 = 128
    r = diff_cidr_lists([("x", "10.0.0.0/25")], [("x", "10.0.0.0/24")])
    assert r["changes"][0]["affected_address_count"] == 128

    # 半重叠：10.0.0.0/24 -> 10.0.0.128/24 不可能（主机位），
    # 改用 /25 与 10.0.0.0..127 / 10.0.0.128..255 半重叠
    r = diff_cidr_lists([("x", "10.0.0.0/25")], [("x", "10.0.0.128/25")])
    assert r["changes"][0]["affected_address_count"] == 256  # 不相交的两个 /25

    # 完全相同（不同写法规范化后相等）-> unchanged，受影响 0
    r = diff_cidr_lists([("x", "10.0.0.0/8")], [("x", "10.0.0.0/08")])
    assert r["changes"][0]["change"] == "unchanged"
    assert r["changes"][0]["affected_address_count"] == 0

    # /0 改为 /32：对称差 = 2^32 - 1
    r = diff_cidr_lists([("x", "0.0.0.0/0")], [("x", "8.8.8.8/32")])
    assert r["changes"][0]["affected_address_count"] == (1 << 32) - 1


def test_diff_replacement_candidate_not_triggered_by_same_id():
    # 同 id 即便位置不同、且网段相同：unchanged，不是替换候选
    result = diff_cidr_lists(
        [("a", "10.0.0.0/8"), ("b", "8.8.8.8/32")],
        [("b", "8.8.8.8/32"), ("a", "10.0.0.0/8")],
    )
    assert {c["id"]: c["change"] for c in result["changes"]} == {
        "a": "unchanged",
        "b": "unchanged",
    }
    assert result["replacement_candidates"] == []
    # before 顺序保持不变（after 顺序不影响同 id 匹配项排序）
    assert [c["id"] for c in result["changes"]] == ["a", "b"]


def test_diff_integer_ids_and_bare_ips():
    result = diff_cidr_lists(
        [(1, "8.8.8.8")],
        [(1, "8.8.8.8/32"), (2, "9.9.9.9")],
    )
    by_id = {c["id"]: c for c in result["changes"]}
    assert by_id[1]["change"] == "unchanged"
    assert by_id[1]["before_cidr"] == by_id[1]["after_cidr"] == "8.8.8.8/32"
    assert by_id[2]["change"] == "added"
    assert by_id[2]["after_cidr"] == "9.9.9.9/32"
    assert by_id[2]["affected_address_count"] == 1


def test_diff_empty_sides():
    assert diff_cidr_lists([], []) == {
        "before_count": 0,
        "after_count": 0,
        "changes": [],
        "replacement_candidates": [],
        "summary": {
            "added": 0,
            "removed": 0,
            "cidr_changed": 0,
            "unchanged": 0,
            "parent_changed": 0,
            "replacement_candidate_count": 0,
            "affected_address_count": 0,
        },
    }

    only_after = diff_cidr_lists(
        [], [("a", "10.0.0.0/8"), ("b", "8.8.8.8/32")]
    )
    assert [c["id"] for c in only_after["changes"]] == ["a", "b"]
    assert all(c["change"] == "added" for c in only_after["changes"])
    assert only_after["summary"]["added"] == 2
    assert only_after["summary"]["affected_address_count"] == (1 << 24) + 1

    only_before = diff_cidr_lists(
        [("a", "10.0.0.0/8"), ("b", "8.8.8.8/32")], []
    )
    assert [c["id"] for c in only_before["changes"]] == ["a", "b"]
    assert all(c["change"] == "removed" for c in only_before["changes"])


def test_diff_duplicate_id_or_network_raises_with_partial_side_info():
    # before 重复 id，after 正常：before 有信息、after 为空结构
    with pytest.raises(CidrDiffInputError) as exc:
        diff_cidr_lists(
            [("x", "10.0.0.0/8"), ("x", "11.0.0.0/8")],
            [("y", "8.8.8.8/32")],
        )
    assert exc.value.sides["before"]["duplicate_ids"] == [
        {"id": "x", "indexes": [0, 1]}
    ]
    assert exc.value.sides["before"]["duplicate_networks"] == []
    assert exc.value.sides["after"] == {"duplicate_ids": [], "duplicate_networks": []}

    # 两侧问题一次性报告：before 重复 id、after 规范化网段重复
    with pytest.raises(CidrDiffInputError) as exc:
        diff_cidr_lists(
            [("x", "10.0.0.0/8"), ("x", "11.0.0.0/8")],
            [("y", "10.0.0.0/8"), ("z", "10.0.0.0/08")],
        )
    assert len(exc.value.sides["before"]["duplicate_ids"]) == 1
    assert len(exc.value.sides["after"]["duplicate_networks"]) == 1


def test_diff_invalid_cidr_and_bad_id_and_limits():
    with pytest.raises(InvalidCIDRError):
        diff_cidr_lists([("a", "10.0.0.1/8")], [])
    with pytest.raises(InvalidCIDRError):
        diff_cidr_lists([], [("a", "2001:db8::/32")])
    with pytest.raises(ValueError):
        diff_cidr_lists([(True, "10.0.0.0/8")], [])
    with pytest.raises(ValueError):
        diff_cidr_lists(
            [(i, f"1.0.{i // 256}.{i % 256}/32") for i in range(CIDR_DIFF_MAX_ENTRIES + 1)],
            [],
        )
    with pytest.raises(ValueError):
        diff_cidr_lists(
            [],
            [(i, f"1.0.{i // 256}.{i % 256}/32") for i in range(CIDR_DIFF_MAX_ENTRIES + 1)],
        )


def test_diff_random_oracle_against_ipaddress():
    """随机清单对：变化分类、对称差地址数与替换候选均与 ipaddress oracle 一致。"""
    rng = random.Random(20260918)
    base = ip_network("10.0.0.0/16")
    pool = [
        net
        for prefixlen in range(17, 31)
        for net in base.subnets(new_prefix=prefixlen)
    ]

    def oracle_parents(items):
        parents = {}
        for eid, net in items:
            supers = [
                (other.prefixlen, other_id)
                for other_id, other in items
                if other_id != eid and other.supernet_of(net)
            ]
            parents[eid] = max(supers)[1] if supers else None
        return parents

    for _ in range(80):
        before_picked = rng.sample(pool, k=rng.randint(0, 10))
        after_picked = rng.sample(pool, k=rng.randint(0, 10))
        before = [(f"b{i}", str(net)) for i, net in enumerate(before_picked)]
        # 复用一半 id，另一半用新 id 制造新增/删除/替换
        after = []
        for i, net in enumerate(after_picked):
            after.append((f"b{i}" if i % 2 == 0 and i < len(before) else f"a{i}", str(net)))

        b_items = [(eid, ip_network(cidr)) for eid, cidr in before]
        a_items = [(eid, ip_network(cidr)) for eid, cidr in after]
        b_map = dict(b_items)
        a_map = dict(a_items)
        b_parents = oracle_parents(b_items)
        a_parents = oracle_parents(a_items)

        result = diff_cidr_lists(before, after)

        expected_added = set(a_map) - set(b_map)
        expected_removed = set(b_map) - set(a_map)
        expected_changed = {
            eid for eid in set(a_map) & set(b_map) if a_map[eid] != b_map[eid]
        }
        expected_unchanged = {
            eid for eid in set(a_map) & set(b_map) if a_map[eid] == b_map[eid]
        }
        expected_parent_changed = {
            eid
            for eid in set(a_map) & set(b_map)
            if a_parents[eid] != b_parents[eid]
        }
        groups = {
            "added": expected_added,
            "removed": expected_removed,
            "cidr_changed": expected_changed,
            "unchanged": expected_unchanged,
        }
        for change in result["changes"]:
            eid = change["id"]
            assert change["id"] in groups[change["change"]]
            assert change["parent_changed"] == (
                eid in expected_parent_changed if eid in set(a_map) & set(b_map) else None
            )
            if change["change"] == "cidr_changed":
                symdiff = len(set(b_map[eid]) ^ set(a_map[eid]))
                assert change["affected_address_count"] == symdiff
            elif change["change"] in ("added", "removed"):
                net = a_map[eid] if change["change"] == "added" else b_map[eid]
                assert change["affected_address_count"] == net.num_addresses
            else:
                assert change["affected_address_count"] == 0

        # 顺序：before 的 id 在前（保持 before 顺序），仅 after 的 id 按 after 顺序追加
        expected_order = [eid for eid, _ in before] + [
            eid for eid, _ in after if eid not in b_map
        ]
        assert [c["id"] for c in result["changes"]] == expected_order

        # 替换候选 oracle：网段相同（且 id 不同）
        a_by_net = {net: eid for eid, net in a_items}
        expected_replacements = [
            (eid, a_by_net[net], str(net))
            for eid, net in b_items
            if net in a_by_net and a_by_net[net] != eid
        ]
        assert [
            (c["before_id"], c["after_id"], c["cidr"])
            for c in result["replacement_candidates"]
        ] == expected_replacements

        # 汇总计数
        summary = result["summary"]
        assert summary["added"] == len(expected_added)
        assert summary["removed"] == len(expected_removed)
        assert summary["cidr_changed"] == len(expected_changed)
        assert summary["unchanged"] == len(expected_unchanged)
        assert summary["parent_changed"] == len(expected_parent_changed)
        assert (
            summary["replacement_candidate_count"] == len(expected_replacements)
        )
        assert summary["affected_address_count"] == sum(
            c["affected_address_count"] for c in result["changes"]
        )
