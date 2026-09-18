"""IPv4 路由解析核心逻辑（纯标准库实现，无 Web 依赖）。

给定有序静态路由列表（``cidr`` / ``next_hop`` / ``metric``）与一组唯一的
目标 IPv4 地址，对每个目标按以下顺序解析：

1. **最长前缀匹配（LPM）**：在所有命中目标的路由中只保留前缀长度最大者；
2. **最低 metric 优先**：在 LPM 集合中再保留 metric 最小的全部路由；
3. 这些路由构成等价多路径（ECMP）结果，其 ``next_hop`` 按 **routes 输入
   顺序去重**后返回；未命中任何路由的目标标记为 ``unreachable``。

:func:`failover_routes` 在此基础上模拟下一跳失效：先在完整路由表上解析
一次，再移除失败下一跳对应的**全部路由**并重新执行完整的选择流程
（允许回退到更高 metric 或更短前缀），逐目标给出 before/after/impact。

:func:`audit_routes` 做全表审计：按“最长前缀优先、同前缀最低 metric、
同 metric 并行路由（ECMP）共享”的语义，计算每条路由在整个 IPv4 空间
**实际负责**的地址集合，给出 active/partial/shadowed 状态、生效地址数
与无损压缩后的最少 CIDR。

全程只做 32 位整数比较，**不逐地址展开网段**，可安全处理 ``0.0.0.0/0``。
"""
from __future__ import annotations

from collections import defaultdict
from ipaddress import IPv4Address, ip_address
from typing import Sequence

from .analyzer import (
    PARTIAL,
    SHADOWED,
    V4_SPACE,
    compress_intervals,
    merge_intervals,
    parse_cidr_v4,
    subtract_covered,
)

#: 单次请求允许的最大路由条数
ROUTES_MAX = 1000

#: 单次请求允许的目标数区间
TARGETS_MIN = 1
TARGETS_MAX = 500

#: 单次请求允许的失败下一跳数量上限（与路由条数上限一致）
FAILED_NEXT_HOPS_MAX = ROUTES_MAX

#: metric 取值范围
METRIC_MIN = 0
METRIC_MAX = 65535

REACHABLE = "reachable"
UNREACHABLE = "unreachable"

#: 审计状态：active 全生效（复用 analyzer 的 PARTIAL / SHADOWED 取值）
ACTIVE = "active"

#: 审计状态中文说明
AUDIT_STATUS_LABELS = {
    ACTIVE: "生效",
    PARTIAL: "部分生效",
    SHADOWED: "完全遮蔽",
}

#: 故障切换影响分类
UNCHANGED = "unchanged"
ECMP_REDUCED = "ecmp_reduced"
REROUTED = "rerouted"
#: 影响分类全集（unreachable 复用状态值）
IMPACTS = (UNCHANGED, ECMP_REDUCED, REROUTED, UNREACHABLE)


class InvalidIPv4AddressError(ValueError):
    """非法 IPv4 地址（格式错误、带前缀、IPv6 等）。"""


class DuplicateTargetsError(ValueError):
    """目标地址重复。

    ``duplicates`` 给出每个重复目标（按首次出现排序），形如
    ``{"target": "8.8.8.8", "indexes": [0, 3]}``。
    """

    def __init__(self, duplicates: list[dict]) -> None:
        self.duplicates = duplicates
        super().__init__(f"{len(duplicates)} 个重复目标地址")


class DuplicateNextHopsError(ValueError):
    """失败下一跳重复。

    ``duplicates`` 给出每个重复下一跳（按首次出现排序），形如
    ``{"next_hop": "10.0.0.1", "indexes": [0, 2]}``。
    """

    def __init__(self, duplicates: list[dict]) -> None:
        self.duplicates = duplicates
        super().__init__(f"{len(duplicates)} 个重复失败下一跳")


def parse_address_v4(text: str) -> tuple[int, str]:
    """严格解析单个 IPv4 地址（**禁止** CIDR 前缀与 IPv6）。

    返回 ``(地址整数, 规范化字符串)``；与 CIDR 校验同样严格：
    不接受主机位/前缀写法（``8.8.8.8/32``）、前导零（``010.0.0.1``）
    及 IPv6（``::1``）。
    """
    if not isinstance(text, str):
        raise InvalidIPv4AddressError("IPv4 地址必须是字符串")
    raw = text.strip()
    if not raw:
        raise InvalidIPv4AddressError("IPv4 地址不能为空")
    if "/" in raw:
        raise InvalidIPv4AddressError(f"非法 IPv4 地址（不允许前缀写法）: {text!r}")
    try:
        addr = ip_address(raw)
    except ValueError as exc:
        raise InvalidIPv4AddressError(f"非法 IPv4 地址: {text!r}（{exc}）") from exc
    if not isinstance(addr, IPv4Address):
        raise InvalidIPv4AddressError(f"仅支持 IPv4，不支持 IPv6: {text!r}")
    return int(addr), str(addr)


class InvalidMetricError(ValueError):
    """metric 不是 0～65535 的整数。"""


def normalize_metric(metric: object) -> int:
    """校验 metric：非 bool 整数且在 0～65535 之间。"""
    if isinstance(metric, bool) or not isinstance(metric, int):
        raise InvalidMetricError(f"metric 必须是 0～{METRIC_MAX} 的整数: {metric!r}")
    if not METRIC_MIN <= metric <= METRIC_MAX:
        raise InvalidMetricError(
            f"metric 必须在 {METRIC_MIN}～{METRIC_MAX} 之间，实际 {metric}"
        )
    return metric


def _collect_duplicates(parsed_items: list[tuple[int, str]], key: str) -> list[dict]:
    """从 ``(地址整数, 规范化文本)`` 列表中收集重复项（按首次出现排序）。

    每条形如 ``{key: 规范化文本, "indexes": [全部出现位置]}``。
    """
    positions: dict[int, list[int]] = defaultdict(list)
    first_seen: list[int] = []
    for index, (value, _text) in enumerate(parsed_items):
        if value not in positions:
            first_seen.append(value)
        positions[value].append(index)
    return [
        {key: parsed_items[positions[value][0]][1], "indexes": positions[value]}
        for value in first_seen
        if len(positions[value]) > 1
    ]


def _parse_route_entries(
    routes: Sequence[tuple[str, str, int]],
) -> tuple[list[dict], dict[str, int]]:
    """校验并解析路由列表。

    返回 ``(parsed_routes, hop_first_index)``：``parsed_routes`` 每项为含
    整数区间、前缀长度、metric 与下一跳的字典（保持输入顺序）；
    ``hop_first_index`` 记录每个规范化下一跳在 routes 中的最早输入序号，
    用于汇总排序。
    """
    if not 0 <= len(routes) <= ROUTES_MAX:
        raise ValueError(f"路由数必须在 0～{ROUTES_MAX} 之间，实际 {len(routes)}")

    parsed_routes: list[dict] = []
    hop_first_index: dict[str, int] = {}
    for index, (raw_cidr, raw_next_hop, raw_metric) in enumerate(routes):
        start, end, cidr = parse_cidr_v4(raw_cidr)
        hop_int, next_hop = parse_address_v4(raw_next_hop)
        metric = normalize_metric(raw_metric)
        parsed_routes.append(
            {
                "start": start,
                "end": end,
                "cidr": cidr,
                "prefixlen": int(cidr.rsplit("/", 1)[1]),
                "metric": metric,
                "hop_int": hop_int,
                "next_hop": next_hop,
            }
        )
        hop_first_index.setdefault(next_hop, index)
    return parsed_routes, hop_first_index


def _parse_target_list(targets: Sequence[str]) -> list[tuple[int, str]]:
    """校验目标列表规模与唯一性，返回 ``(地址整数, 规范化文本)`` 列表。"""
    if not TARGETS_MIN <= len(targets) <= TARGETS_MAX:
        raise ValueError(
            f"目标数必须在 {TARGETS_MIN}～{TARGETS_MAX} 之间，实际 {len(targets)}"
        )
    parsed_targets = [parse_address_v4(raw) for raw in targets]
    duplicates = _collect_duplicates(parsed_targets, "target")
    if duplicates:
        raise DuplicateTargetsError(duplicates)
    return parsed_targets


def _parse_failed_next_hops(
    failed_next_hops: Sequence[str],
) -> list[tuple[int, str]]:
    """校验失败下一跳列表规模与唯一性，返回 ``(地址整数, 规范化文本)`` 列表。"""
    if not 0 <= len(failed_next_hops) <= FAILED_NEXT_HOPS_MAX:
        raise ValueError(
            f"失败下一跳数必须在 0～{FAILED_NEXT_HOPS_MAX} 之间，"
            f"实际 {len(failed_next_hops)}"
        )
    parsed = [parse_address_v4(raw) for raw in failed_next_hops]
    duplicates = _collect_duplicates(parsed, "next_hop")
    if duplicates:
        raise DuplicateNextHopsError(duplicates)
    return parsed


def _resolve_targets(
    parsed_routes: Sequence[dict],
    parsed_targets: Sequence[tuple[int, str]],
) -> list[dict]:
    """对每个目标执行 LPM + 最低 metric + ECMP 选择。

    返回与 ``parsed_targets`` 等长的结果列表，每项含
    ``status`` / ``matched_cidr`` / ``metric`` / ``next_hops``
    （不含 target，由调用方按需补充）。
    """
    results: list[dict] = []
    for value, _text in parsed_targets:
        best_prefix = -1
        best_metric: int = 1 << 30  # 哨兵：尚无命中时大于任何合法 metric
        chosen: list[dict] = []
        # 线性扫描，仅做整数包含判断；同前缀长度且包含同一地址的 CIDR
        # 必然是同一网段，故 LPM 命中路由的 cidr 唯一。
        for route in parsed_routes:
            if not route["start"] <= value <= route["end"]:
                continue
            if route["prefixlen"] > best_prefix:
                best_prefix = route["prefixlen"]
                best_metric = route["metric"]
                chosen = [route]
            elif route["prefixlen"] == best_prefix and route["metric"] <= best_metric:
                if route["metric"] < best_metric:
                    best_metric = route["metric"]
                    chosen = [route]
                else:
                    chosen.append(route)

        if not chosen:
            results.append(
                {
                    "status": UNREACHABLE,
                    "matched_cidr": None,
                    "metric": None,
                    "next_hops": [],
                }
            )
            continue

        # chosen 已按 routes 输入顺序排列；next_hop 去重
        next_hops: list[str] = []
        counted_hops: set[int] = set()
        for route in chosen:
            if route["hop_int"] not in counted_hops:
                counted_hops.add(route["hop_int"])
                next_hops.append(route["next_hop"])

        results.append(
            {
                "status": REACHABLE,
                "matched_cidr": chosen[0]["cidr"],
                "metric": chosen[0]["metric"],
                "next_hops": next_hops,
            }
        )
    return results


def resolve_routes(
    routes: Sequence[tuple[str, str, int]],
    targets: Sequence[str],
) -> dict:
    """解析一组目标地址的最长前缀、最低 metric 等价下一跳。

    ``routes`` 每项为 ``(cidr, next_hop, metric)``，允许为空（此时所有目标
    均不可达）；``targets`` 每项为单个严格 IPv4 地址，**必须唯一**。

    返回可直接 JSON 序列化的字典：``results`` 严格保持 targets 输入顺序；
    命中项给出 ``status="reachable"``、共同命中的规范化 ``matched_cidr``、
    ``metric`` 与按 routes 输入顺序去重的 ``next_hops``；未命中项为
    ``status="unreachable"``、其余字段为 ``None`` / ``[]``。
    ``summary.next_hop_counts`` 汇总每个 next_hop 命中的**目标数**（同一
    ECMP 结果的各下一跳分别计一次），按 next_hop 在 routes 中的首次出现
    位置排序。目标重复时抛出 :class:`DuplicateTargetsError`，非法 CIDR /
    地址 / metric 抛出对应 ValueError 子类。
    """
    parsed_routes, hop_first_index = _parse_route_entries(routes)
    parsed_targets = _parse_target_list(targets)
    resolutions = _resolve_targets(parsed_routes, parsed_targets)

    results: list[dict] = []
    # 规范化 next_hop -> 命中目标数；同一 ECMP 结果的去重下一跳各计一次
    hop_counts: dict[str, int] = {}
    unreachable_count = 0
    for (_value, text), resolution in zip(parsed_targets, resolutions):
        if resolution["status"] == UNREACHABLE:
            unreachable_count += 1
        else:
            for hop in resolution["next_hops"]:
                hop_counts[hop] = hop_counts.get(hop, 0) + 1
        results.append({"target": text, **resolution})

    next_hop_counts = [
        {"next_hop": hop, "target_count": hop_counts[hop]}
        for hop in sorted(hop_counts, key=lambda hop: hop_first_index[hop])
    ]

    return {
        "route_count": len(parsed_routes),
        "target_count": len(parsed_targets),
        "results": results,
        "summary": {
            "reachable_count": len(results) - unreachable_count,
            "unreachable_count": unreachable_count,
            "next_hop_counts": next_hop_counts,
        },
    }


def _classify_impact(before: dict, after: dict) -> str:
    """比较同一目标故障前后的解析结果并归类影响。

    仅删除路由不可能产生新的可达性，因此 before 不可达时 after 必然
    也不可达（归为 unchanged）。
    """
    if before["status"] == UNREACHABLE and after["status"] == UNREACHABLE:
        return UNCHANGED
    if after["status"] == UNREACHABLE:
        return UNREACHABLE  # 原本可达，故障后不可达
    if before["status"] == UNREACHABLE:
        return REROUTED  # 防御性兜底：仅删除路由不会到达此分支
    if (
        before["matched_cidr"] == after["matched_cidr"]
        and before["metric"] == after["metric"]
    ):
        if before["next_hops"] == after["next_hops"]:
            return UNCHANGED
        # 剩余路由是原路由的子集，同网段同 metric 下下一跳必然严格减少
        return ECMP_REDUCED
    return REROUTED


def failover_routes(
    routes: Sequence[tuple[str, str, int]],
    targets: Sequence[str],
    failed_next_hops: Sequence[str],
) -> dict:
    """模拟若干下一跳失效后的路由切换影响。

    先在完整路由表上按 :func:`resolve_routes` 语义解析一次（before），
    再移除 ``failed_next_hops`` 对应的**全部路由**，重新执行最长前缀、
    最低 metric 与 ECMP 选择（after）——不是从原 ECMP 列表中删值，
    因此允许回退到**更高 metric** 或**更短前缀**。

    ``routes`` / ``targets`` 的校验与 :func:`resolve_routes` 完全一致；
    ``failed_next_hops`` 每项为单个严格 IPv4 地址，**必须唯一**，允许为空
    （此时所有目标均为 ``unchanged``）。

    返回可直接 JSON 序列化的字典：``results`` 严格保持 targets 输入顺序，
    每项含 ``target`` / ``before`` / ``after`` / ``impact``；``summary``
    汇总四类 impact 的数量。impact 取值：

    - ``unchanged``：解析结果完全不变（含两侧均不可达）；
    - ``ecmp_reduced``：命中网段与 metric 不变，等价下一跳减少；
    - ``rerouted``：仍可达但命中网段或 metric 改变（回退到更短前缀或
      更高 metric）；
    - ``unreachable``：原本可达、故障后不可达。

    目标重复抛出 :class:`DuplicateTargetsError`，失败下一跳重复抛出
    :class:`DuplicateNextHopsError`，非法 CIDR / 地址 / metric 抛出对应
    ValueError 子类。
    """
    parsed_routes, _hop_first_index = _parse_route_entries(routes)
    parsed_targets = _parse_target_list(targets)
    parsed_failed = _parse_failed_next_hops(failed_next_hops)

    failed_values = {value for value, _text in parsed_failed}
    remaining_routes = [
        route for route in parsed_routes if route["hop_int"] not in failed_values
    ]

    before_list = _resolve_targets(parsed_routes, parsed_targets)
    after_list = _resolve_targets(remaining_routes, parsed_targets)

    results: list[dict] = []
    impact_counts = {impact: 0 for impact in IMPACTS}
    for (_value, text), before, after in zip(
        parsed_targets, before_list, after_list
    ):
        impact = _classify_impact(before, after)
        impact_counts[impact] += 1
        results.append(
            {
                "target": text,
                "before": before,
                "after": after,
                "impact": impact,
            }
        )

    return {
        "route_count": len(parsed_routes),
        "target_count": len(parsed_targets),
        "failed_next_hops": [text for _value, text in parsed_failed],
        "results": results,
        "summary": impact_counts,
    }


# ---------- 全表审计（/routes/audit） ----------


def _group_effective_intervals(
    parsed_routes: Sequence[dict],
    groups: dict[tuple[int, int], list[int]],
) -> dict[tuple[int, int], list[tuple[int, int]]]:
    """计算每个网段（去重后）在 LPM 语义下留给本前缀的地址碎片。

    对网段 N，任何**前缀更长**的路由网段都会在 N 的范围内优先胜出
    （与 metric 无关），因此 N 留给本前缀的集合 = N 减去所有被 N 包含的
    更长前缀网段的并集。返回 ``{(start, end): 有序不相交碎片列表}``。
    """
    # 去重后的网段区间（合并遮蔽并集时与路由重复无关）
    distinct = sorted({(r["start"], r["end"]) for r in parsed_routes})
    effective: dict[tuple[int, int], list[tuple[int, int]]] = {}
    for key in groups:
        start, end = key
        # 被本网段严格包含的区间即“前缀更长”的网段（同网段已去重，不会相等）
        longer = [
            (s, e)
            for s, e in distinct
            if s >= start and e <= end and (s, e) != key
        ]
        effective[key] = subtract_covered(key, merge_intervals(longer))
    return effective


def audit_routes(
    routes: Sequence[tuple[str, str, int]],
) -> dict:
    """审计有序静态路由表：每条路由在整个 IPv4 空间实际负责的地址集合。

    语义与 :func:`resolve_routes` 的选择规则一致：

    1. **最长前缀优先**：地址 x 若被更长前缀的路由网段覆盖，则短前缀路由
       在 x 上永远不生效（与 metric 无关）；
    2. **同前缀最低 metric**：规范化网段相同的路由中，仅最低 metric 者生效，
       更高 metric 的路由整体被遮蔽（生效集合为空）；
    3. **ECMP 共享**：同网段、同（最低）metric 的并行路由**共享**同一生效
       集合，各自完整报告（不做拆分），``ecmp_group`` 按输入顺序列出同
       网段同 metric 的全部路由序号（含自身）。

    ``routes`` 每项为 ``(cidr, next_hop, metric)``，允许为空（此时
    ``routes`` 结果为空、整个 IPv4 空间均未覆盖）。返回可直接 JSON 序列化
    的字典：``routes`` 保持输入顺序，每项含 ``index`` / ``cidr`` /
    ``next_hop`` / ``metric`` / ``status``（``active`` / ``partial`` /
    ``shadowed``）/ ``status_label`` / ``total_addresses`` /
    ``effective_addresses`` / ``effective_cidrs``（无损、数量最少）/
    ``ecmp_group``；``summary`` 汇总三种状态的路由数，以及全表在整个
    IPv4 空间实际覆盖 / 未覆盖的地址数（ECMP 共享集合只计一次）。
    非法 CIDR / 地址 / metric 抛出对应 ValueError 子类。
    """
    parsed_routes, _hop_first_index = _parse_route_entries(routes)

    # 按规范化网段分组（组内保持输入顺序）
    groups: dict[tuple[int, int], list[int]] = {}
    for index, route in enumerate(parsed_routes):
        groups.setdefault((route["start"], route["end"]), []).append(index)

    # 每个网段的最低 metric：高于它的路由整体被遮蔽
    min_metric = {
        key: min(parsed_routes[i]["metric"] for i in indexes)
        for key, indexes in groups.items()
    }
    # 每个网段留给本前缀的地址碎片（LPM 语义，组内共享）
    group_remaining = _group_effective_intervals(parsed_routes, groups)

    # 同网段同 metric 的并行路由组（共享生效集合），按输入顺序
    ecmp_group_of: dict[int, list[int]] = {}
    for indexes in groups.values():
        by_metric: dict[int, list[int]] = defaultdict(list)
        for index in indexes:
            by_metric[parsed_routes[index]["metric"]].append(index)
        for peers in by_metric.values():
            for index in peers:
                ecmp_group_of[index] = peers

    result_routes: list[dict] = []
    status_counts = {ACTIVE: 0, PARTIAL: 0, SHADOWED: 0}

    for index, route in enumerate(parsed_routes):
        key = (route["start"], route["end"])
        total_addresses = route["end"] - route["start"] + 1
        if route["metric"] == min_metric[key]:
            remaining = group_remaining[key]
        else:
            # 同前缀存在更低 metric：本路由整体被遮蔽
            remaining = []
        effective_addresses = sum(e - s + 1 for s, e in remaining)

        if effective_addresses == 0:
            status = SHADOWED
        elif effective_addresses == total_addresses:
            status = ACTIVE
        else:
            status = PARTIAL
        status_counts[status] += 1

        result_routes.append(
            {
                "index": index,
                "cidr": route["cidr"],
                "next_hop": route["next_hop"],
                "metric": route["metric"],
                "status": status,
                "status_label": AUDIT_STATUS_LABELS[status],
                "total_addresses": total_addresses,
                "effective_addresses": effective_addresses,
                "effective_cidrs": compress_intervals(remaining),
                "ecmp_group": ecmp_group_of[index],
            }
        )

    # 各网段的生效集合两两不相交（不同网段的生效集合必不相交：
    # 相交网段必为包含关系，短前缀网段的生效集合已扣除长前缀网段），
    # 因此全表覆盖地址数 = 各网段生效碎片长度之和（ECMP 共享只计一次）
    covered_addresses = 0
    for key, remaining in group_remaining.items():
        covered_addresses += sum(e - s + 1 for s, e in remaining)

    return {
        "route_count": len(parsed_routes),
        "routes": result_routes,
        "summary": {
            "active": status_counts[ACTIVE],
            "partial": status_counts[PARTIAL],
            "shadowed": status_counts[SHADOWED],
            "covered_addresses": covered_addresses,
            "uncovered_addresses": V4_SPACE - covered_addresses,
        },
    }
