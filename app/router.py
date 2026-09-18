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

:func:`audit_routes` 则把同一套选择规则应用到**整个 IPv4 空间**：按最长
前缀优先、同前缀最低 metric 与 ECMP 语义，计算每条路由实际负责的地址
集合（同网段同最低 metric 的并行路由**共享同一集合**），并分类为
``active`` / ``partial`` / ``shadowed``，给出无损最少 CIDR。

全程只做 32 位整数比较与区间运算，**不逐地址展开网段**，可安全处理
``0.0.0.0/0``。
"""
from __future__ import annotations

from collections import defaultdict
from ipaddress import IPv4Address, ip_address
from typing import Sequence

from .analyzer import (
    V4_SPACE,
    PARTIAL,
    SHADOWED,
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

#: 路由审计状态（/routes/audit）
ACTIVE = "active"
# PARTIAL / SHADOWED 复用 analyzer 的定义
AUDIT_STATUSES = (ACTIVE, PARTIAL, SHADOWED)

AUDIT_STATUS_LABELS = {
    ACTIVE: "全部生效",
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


# ---------- 路由表空间审计（/routes/audit） ----------


def audit_routes(routes: Sequence[tuple[str, str, int]]) -> dict:
    """审计有序路由表，计算每条路由在整个 IPv4 空间实际负责的地址集合。

    对每个地址按以下顺序选择生效路由组：

    1. **最长前缀匹配（LPM）**：命中同一地址的不同网段中，只有前缀最长的
       网段参与选择——更短网段在该地址上被更长网段遮蔽（metric 再优也不例外）；
    2. **同前缀最低 metric**：同一网段内只保留 metric 最小的**全部**路由，
       metric 更高的同网段路由完全不生效；
    3. 这些最低 metric 路由构成等价多路径（ECMP）组，**共享**该网段扣除
       全部更具体（更长前缀）网段并集后的地址集合；其 ``next_hop`` 按
       routes 输入顺序去重。

    每条路由（保持输入顺序）返回：

    - ``status``：``active``（最低 metric 组且网段未被任何更长前缀覆盖）、
      ``partial``（属最低 metric 组但网段部分被更长前缀覆盖）、
      ``shadowed``（生效集合为空：metric 被同网段更低 metric 路由淘汰，
      或网段被更长前缀完全覆盖）；
    - ``effective_addresses`` / ``effective_cidrs``：生效地址集合的地址数
      与**无损、数量最少**的 CIDR 列表，``shadowed`` 路由为 ``0`` / ``[]``；
      属同一 ECMP 组（同网段同最低 metric）的路由两者完全相同；
    - ``ecmp_next_hops``：所属网段最低 metric 组按输入顺序去重的下一跳
      （非最低 metric 路由同样返回该组下一跳，便于定位遮蔽来源）。

    ``summary`` 汇总三类状态的路由数、整张表实际承载的地址数
    ``routed_address_count``、无任何路由覆盖的 ``unreachable_address_count``
    （二者之和恒为 2^32），以及逐条 ``effective_addresses`` 之和
    ``effective_address_sum``（同一 ECMP 组的并行路由各计一次）。

    ``routes`` 允许为空（此时所有路由数为 0、不可达地址为 2^32）；
    非法 CIDR / 地址 / metric 抛出对应 ValueError 子类，路由数超过
    :data:`ROUTES_MAX` 抛出 :class:`ValueError`。全程为区间运算，不逐地址
    枚举。
    """
    parsed_routes, _hop_first_index = _parse_route_entries(routes)

    # 按规范化网段分组（首次出现顺序），记录组内成员的输入位置与最低 metric
    group_order: list[tuple[int, int]] = []
    group_members: dict[tuple[int, int], list[int]] = defaultdict(list)
    group_min_metric: dict[tuple[int, int], int] = {}
    for index, route in enumerate(parsed_routes):
        key = (route["start"], route["end"])
        if key not in group_members:
            group_order.append(key)
            group_min_metric[key] = route["metric"]
        group_members[key].append(index)
        if route["metric"] < group_min_metric[key]:
            group_min_metric[key] = route["metric"]

    # 每个网段的生效集合 = 自身区间减去全部更具体（严格包含、前缀更长）
    # 网段的并集。同前缀长度的不同 IPv4 CIDR 必然不相交，无需扣除。
    effective: dict[tuple[int, int], list[tuple[int, int]]] = {}
    effective_cidrs: dict[tuple[int, int], list[str]] = {}
    ecmp_hops: dict[tuple[int, int], list[str]] = {}
    routed_fragments: list[tuple[int, int]] = []

    for key in group_order:
        start, end = key
        more_specific = [
            (other_start, other_end)
            for other_start, other_end in group_order
            if start <= other_start and other_end <= end and (other_start, other_end) != key
        ]
        covered = merge_intervals(more_specific)
        fragments = subtract_covered((start, end), covered)
        effective[key] = fragments
        effective_cidrs[key] = compress_intervals(fragments)
        routed_fragments.extend(fragments)

        min_metric = group_min_metric[key]
        hops: list[str] = []
        seen_hops: set[int] = set()
        for member_index in group_members[key]:
            member = parsed_routes[member_index]
            if member["metric"] == min_metric and member["hop_int"] not in seen_hops:
                seen_hops.add(member["hop_int"])
                hops.append(member["next_hop"])
        ecmp_hops[key] = hops

    results: list[dict] = []
    status_counts = {ACTIVE: 0, PARTIAL: 0, SHADOWED: 0}
    effective_address_sum = 0
    for index, route in enumerate(parsed_routes):
        key = (route["start"], route["end"])
        total_addresses = route["end"] - route["start"] + 1
        min_metric = group_min_metric[key]
        fragments = effective[key]
        address_count = sum(end - start + 1 for start, end in fragments)

        if route["metric"] != min_metric or address_count == 0:
            status = SHADOWED
        elif address_count == total_addresses:
            status = ACTIVE
        else:
            status = PARTIAL

        # 同网段更高 metric 的路由不承载任何地址：生效集合为空；
        # 同 metric 的并行路由才共享整个生效集合（含被更长前缀遮蔽的部分）
        if status == SHADOWED:
            effective_count = 0
            effective_list: list[str] = []
        else:
            effective_count = address_count
            effective_list = list(effective_cidrs[key])

        effective_address_sum += effective_count
        status_counts[status] += 1
        results.append(
            {
                "index": index,
                "cidr": route["cidr"],
                "next_hop": route["next_hop"],
                "metric": route["metric"],
                "status": status,
                "status_label": AUDIT_STATUS_LABELS[status],
                "total_addresses": total_addresses,
                "effective_addresses": effective_count,
                "effective_cidrs": effective_list,
                "ecmp_next_hops": list(ecmp_hops[key]),
            }
        )

    routed_intervals = merge_intervals(routed_fragments)
    routed_address_count = sum(end - start + 1 for start, end in routed_intervals)

    return {
        "route_count": len(parsed_routes),
        "results": results,
        "summary": {
            "active": status_counts[ACTIVE],
            "partial": status_counts[PARTIAL],
            "shadowed": status_counts[SHADOWED],
            "routed_address_count": routed_address_count,
            "unreachable_address_count": V4_SPACE - routed_address_count,
            "effective_address_sum": effective_address_sum,
        },
    }
