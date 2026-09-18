"""IPv4 CIDR 遮蔽分析核心逻辑（纯标准库实现，无 Web 依赖）。

规则按输入顺序逐条处理；对第 i 条规则，此前 i-1 条规则
（allow 与 deny 合并后的并集）已经覆盖的地址构成“遮蔽集合”。
规则自身地址区间减去遮蔽集合后，剩余部分无损压缩为数量最少的
IPv4 CIDR 列表，并按覆盖比例分类：

- full      全生效：规则地址均未被此前规则覆盖
- partial   部分遮蔽：部分地址此前已被覆盖
- shadowed  完全遮蔽：全部地址此前已被覆盖
"""
from __future__ import annotations

from collections import defaultdict
from ipaddress import IPv4Address, IPv4Network, ip_network
from typing import Iterable, Sequence

#: 整个 IPv4 地址空间的地址数量（2^32）
V4_SPACE = 1 << 32

FULL = "full"
PARTIAL = "partial"
SHADOWED = "shadowed"

ALLOW = "allow"
DENY = "deny"

STATUS_LABELS = {
    FULL: "全生效",
    PARTIAL: "部分遮蔽",
    SHADOWED: "完全遮蔽",
}


class InvalidCIDRError(ValueError):
    """非法 CIDR（格式错误、主机位非零、IPv6 等）。"""


class HierarchyInputError(ValueError):
    """层级分析输入不合法：id 重复，或规范化后网段重复。

    ``duplicate_ids`` 给出冲突 id 及其所有出现位置（按首次出现排序）；
    ``duplicate_networks`` 给出每个规范化网段下的全部条目（按网络地址
    排序），每条形如 ``{"index", "id", "cidr"}``。
    """

    def __init__(
        self,
        duplicate_ids: list[dict],
        duplicate_networks: list[dict],
    ) -> None:
        self.duplicate_ids = duplicate_ids
        self.duplicate_networks = duplicate_networks
        parts = []
        if duplicate_ids:
            parts.append(f"{len(duplicate_ids)} 个重复 id")
        if duplicate_networks:
            parts.append(f"{len(duplicate_networks)} 个规范化后重复的网段")
        super().__init__("；".join(parts) or "层级分析输入不合法")


def normalize_action(action: object) -> str:
    """规范化动作：去空白、转小写；非 allow/deny 抛出 ValueError。"""
    if not isinstance(action, str):
        raise ValueError(f"非法 action: {action!r}")
    normalized = action.strip().lower()
    if normalized not in (ALLOW, DENY):
        raise ValueError(f"非法 action: {action!r}")
    return normalized


def parse_cidr_v4(text: str) -> tuple[int, int, str]:
    """严格解析单个 IPv4 CIDR。

    返回 ``(起始地址整数, 结束地址整数, 规范化 CIDR 字符串)``。
    纯 IP（无前缀）按 /32 处理；IPv6 与任何非法输入抛出
    :class:`InvalidCIDRError`。
    """
    if not isinstance(text, str):
        raise InvalidCIDRError("CIDR 必须是字符串")
    raw = text.strip()
    if not raw:
        raise InvalidCIDRError("CIDR 不能为空")
    try:
        net = ip_network(raw, strict=True)
    except ValueError as exc:
        raise InvalidCIDRError(f"非法 CIDR: {text!r}（{exc}）") from exc
    if not isinstance(net, IPv4Network):
        raise InvalidCIDRError(f"仅支持 IPv4，不支持 IPv6: {text!r}")
    start = int(net.network_address)
    end = start + net.num_addresses - 1
    return start, end, str(net)


def merge_intervals(intervals: Iterable[Sequence[int]]) -> list[tuple[int, int]]:
    """合并若干 ``[start, end]`` 闭区间为有序、互不相交的最小区间集。

    首尾相接（相邻）的区间也会被合并，以便后续跨碎片做整体压缩。
    """
    ordered = sorted((int(s), int(e)) for s, e in intervals)
    merged: list[tuple[int, int]] = []
    for start, end in ordered:
        if start > end:
            raise ValueError("区间起点不能大于终点")
        if not merged or start > merged[-1][1] + 1:
            merged.append((start, end))
        elif end > merged[-1][1]:
            merged[-1] = (merged[-1][0], end)
    return merged


def subtract_covered(
    rule: tuple[int, int], covered: Sequence[tuple[int, int]]
) -> list[tuple[int, int]]:
    """计算 ``rule`` 闭区间减去已覆盖区间集 ``covered`` 后的剩余碎片。

    ``covered`` 须为有序、互不相交的区间（由 :func:`merge_intervals` 产出）。
    """
    start, end = rule
    remaining: list[tuple[int, int]] = []
    cur = start
    for cov_start, cov_end in covered:
        if cov_end < cur:
            continue  # 覆盖区间完全在当前游标之前
        if cov_start > end:
            break  # 覆盖区间已越过规则末端
        if cov_start > cur:
            remaining.append((cur, cov_start - 1))
        cur = max(cur, cov_end + 1)
        if cur > end:
            break
    if cur <= end:
        remaining.append((cur, end))
    return remaining


def range_to_cidrs(start: int, end: int) -> list[str]:
    """把单个连续 IPv4 地址区间无损压缩为数量最少的 CIDR 列表。

    贪心：每一步取以当前地址为起点、不越过区间末端的最大 2 的幂
    对齐块。该算法是 range-to-CIDR 的标准最优算法（块数最少）。
    """
    cidrs: list[str] = []
    cur = start
    while cur <= end:
        remaining = end - cur + 1
        # 当前地址的最低置位决定最大对齐块；地址 0 可对齐整个 /0。
        alignment_block = V4_SPACE if cur == 0 else (cur & -cur)
        size = min(alignment_block, 1 << (remaining.bit_length() - 1))
        prefixlen = 32 - (size.bit_length() - 1)
        cidrs.append(f"{IPv4Address(cur)}/{prefixlen}")
        cur += size
    return cidrs


def compress_intervals(intervals: Sequence[tuple[int, int]]) -> list[str]:
    """把碎片区间先合并，再压缩为全局数量最少的 CIDR 列表。"""
    cidrs: list[str] = []
    for start, end in merge_intervals(intervals):
        cidrs.extend(range_to_cidrs(start, end))
    return cidrs


def analyze_rules(
    rules: Sequence[tuple[str, str]],
) -> dict:
    """分析有序 (action, cidr) 规则列表的遮蔽情况。

    返回可直接 JSON 序列化的结果字典；``rules`` 为空时抛出
    :class:`ValueError`（Web 层通常已以 422 拦截）。
    """
    if not rules:
        raise ValueError("规则集不能为空")

    covered: list[tuple[int, int]] = []
    result_rules: list[dict] = []
    effective_totals = {"allow": 0, "deny": 0}
    status_counts = {FULL: 0, PARTIAL: 0, SHADOWED: 0}

    for index, (action, raw_cidr) in enumerate(rules):
        action = normalize_action(action)

        start, end, cidr = parse_cidr_v4(raw_cidr)
        total_addresses = end - start + 1

        remaining = subtract_covered((start, end), covered)
        effective_addresses = sum(b - a + 1 for a, b in remaining)
        covered_addresses = total_addresses - effective_addresses

        if effective_addresses == 0:
            status = SHADOWED
        elif effective_addresses == total_addresses:
            status = FULL
        else:
            status = PARTIAL

        effective_cidrs = compress_intervals(remaining)

        effective_totals[action] += effective_addresses
        status_counts[status] += 1

        result_rules.append(
            {
                "index": index,
                "action": action,
                "cidr": cidr,
                "status": status,
                "status_label": STATUS_LABELS[status],
                "total_addresses": total_addresses,
                "covered_addresses": covered_addresses,
                "effective_addresses": effective_addresses,
                "effective_cidrs": effective_cidrs,
            }
        )

        # 本规则（无论 allow/deny）的地址全部并入“已覆盖”集合
        covered = merge_intervals([*covered, (start, end)])

    return {
        "rule_count": len(rules),
        "rules": result_rules,
        "summary": {
            "full": status_counts[FULL],
            "partial": status_counts[PARTIAL],
            "shadowed": status_counts[SHADOWED],
            "effective_allow_addresses": effective_totals["allow"],
            "effective_deny_addresses": effective_totals["deny"],
        },
    }


def build_decision_intervals(
    rules: Sequence[tuple[str, str]],
    default_action: str,
) -> list[tuple[int, int, str]]:
    """构造一侧规则集在整个 IPv4 空间上的最终判定分区。

    按“首条匹配规则生效”的顺序语义：每条规则的生效集合为其 CIDR
    减去此前所有规则（allow/deny 不区分）覆盖地址的并集；未被任何
    规则命中的地址统一判定为 ``default_action``。

    返回有序、首尾相接且互不相交的 ``(start, end, action)`` 闭区间，
    完整覆盖 ``0 .. 2^32-1``。整个过程只做区间运算，不逐地址枚举。
    """
    default_action = normalize_action(default_action)

    covered: list[tuple[int, int]] = []
    pieces: list[tuple[int, int, str]] = []

    for action, raw_cidr in rules:
        action = normalize_action(action)
        start, end, _ = parse_cidr_v4(raw_cidr)
        remaining = subtract_covered((start, end), covered)
        for frag_start, frag_end in remaining:
            pieces.append((frag_start, frag_end, action))
        covered = merge_intervals([*covered, (start, end)])

    # 未命中任何规则的地址取默认动作
    for gap_start, gap_end in subtract_covered((0, V4_SPACE - 1), covered):
        pieces.append((gap_start, gap_end, default_action))

    # 按起点排序，合并相邻且动作相同的碎片，得到最小有序分区
    pieces.sort(key=lambda piece: piece[0])
    partition: list[tuple[int, int, str]] = []
    for start, end, action in pieces:
        if partition and start == partition[-1][1] + 1 and action == partition[-1][2]:
            partition[-1] = (partition[-1][0], end, action)
        else:
            partition.append((start, end, action))
    return partition


def explain_query(
    rules: Sequence[tuple[str, str]],
    default_action: str,
    query: str,
) -> dict:
    """解释一段 IPv4 地址空间由哪条规则或默认动作最终裁决。

    沿用“首条匹配规则生效”的顺序语义，但只在 ``query`` 范围内归因：
    query 中的每个地址归属于首条命中它的规则；未被任何规则命中的部分
    归于 ``default_action``。

    返回可直接 JSON 序列化的字典：规范化后的 ``query``、地址总数
    ``total_addresses``，以及 ``attribution`` 列表。归因项按规则索引
    升序排列、默认项最后；每项给出 ``source``（rule/default）、
    ``rule_index``（默认项为 None）、``action``、``address_count`` 与
    无损压缩后的最少 ``cidrs``。所有项不重不漏地覆盖整个 query。
    全程只做区间运算，不逐地址枚举。
    """
    default_action = normalize_action(default_action)
    q_start, q_end, q_cidr = parse_cidr_v4(query)

    covered: list[tuple[int, int]] = []
    attributed: list[tuple[int, str, list[tuple[int, int]]]] = []

    for index, (action, raw_cidr) in enumerate(rules):
        action = normalize_action(action)
        start, end, _ = parse_cidr_v4(raw_cidr)
        # 首条匹配语义下本规则的生效碎片，再裁剪到 query 范围
        remaining = subtract_covered((start, end), covered)
        fragments = [
            (max(frag_start, q_start), min(frag_end, q_end))
            for frag_start, frag_end in remaining
            if max(frag_start, q_start) <= min(frag_end, q_end)
        ]
        if fragments:
            attributed.append((index, action, fragments))
        covered = merge_intervals([*covered, (start, end)])

    # query 内未命中任何规则的部分归于默认动作
    default_fragments = subtract_covered((q_start, q_end), covered)

    attribution = [
        {
            "source": "rule",
            "rule_index": index,
            "action": action,
            "address_count": sum(end - start + 1 for start, end in fragments),
            "cidrs": compress_intervals(fragments),
        }
        for index, action, fragments in attributed
    ]
    if default_fragments:
        attribution.append(
            {
                "source": "default",
                "rule_index": None,
                "action": default_action,
                "address_count": sum(
                    end - start + 1 for start, end in default_fragments
                ),
                "cidrs": compress_intervals(default_fragments),
            }
        )

    return {
        "query": q_cidr,
        "total_addresses": q_end - q_start + 1,
        "attribution": attribution,
    }


def compare_rule_sets(
    left_rules: Sequence[tuple[str, str]],
    left_default: str,
    right_rules: Sequence[tuple[str, str]],
    right_default: str,
) -> dict:
    """比较两组有序规则在整个 IPv4 空间上的最终判定是否等价。

    两侧均按首条匹配规则生效、未命中时走各自 default_action。判定不同
    的地址按 ``(left_action, right_action)`` 分组，每组返回地址数与
    无损压缩后的最少 CIDR 列表。两侧分区以双指针归并求交，不逐地址枚举。
    """
    left = build_decision_intervals(left_rules, left_default)
    right = build_decision_intervals(right_rules, right_default)

    diffs: dict[tuple[str, str], list[tuple[int, int]]] = {}
    i = j = 0
    left_start, left_end, left_action = left[0]
    right_start, right_end, right_action = right[0]
    while i < len(left) and j < len(right):
        overlap_start = max(left_start, right_start)
        overlap_end = min(left_end, right_end)
        if overlap_start <= overlap_end and left_action != right_action:
            diffs.setdefault((left_action, right_action), []).append(
                (overlap_start, overlap_end)
            )
        # 先结束的区间游标前移；同时结束则一起推进（两侧都覆盖整个空间）
        if left_end < right_end:
            i += 1
            if i < len(left):
                left_start, left_end, left_action = left[i]
        elif right_end < left_end:
            j += 1
            if j < len(right):
                right_start, right_end, right_action = right[j]
        else:
            i += 1
            j += 1
            if i < len(left):
                left_start, left_end, left_action = left[i]
            if j < len(right):
                right_start, right_end, right_action = right[j]

    groups = [
        {
            "left_action": left_action,
            "right_action": right_action,
            "address_count": sum(end - start + 1 for start, end in intervals),
            "cidrs": compress_intervals(intervals),
        }
        for (left_action, right_action), intervals in sorted(diffs.items())
    ]
    return {"equivalent": not groups, "differences": groups}


# ---------- CIDR 包含层级（/cidrs/hierarchy） ----------

#: 层级分析允许的最大条目数
HIERARCHY_MAX_ENTRIES = 500


def _validate_hierarchy_id(raw_id: object) -> object:
    """校验单个层级条目的 id：仅接受非空字符串或非 bool 整数。

    字符串仅做首尾空白检查（不做截断）；bool 是 int 的子类，明确拒绝。
    """
    if isinstance(raw_id, bool) or not isinstance(raw_id, (str, int)):
        raise ValueError(f"非法 id: {raw_id!r}（仅支持字符串或整数）")
    if isinstance(raw_id, str) and not raw_id.strip():
        raise ValueError("id 不能为空字符串")
    return raw_id


def _parse_hierarchy_entries(
    entries: Sequence[tuple[object, str]],
) -> tuple[list[dict], list[dict], list[dict]]:
    """解析 ``(id, cidr)`` 条目并收集重复信息。

    返回 ``(nodes, duplicate_ids, duplicate_networks)``。每个 node 形如
    ``{"index", "id", "cidr", "start", "end", "prefixlen"}``；重复组的
    结构与 :class:`HierarchyInputError` 属性一致（id 组按首次出现位置
    有序，网段组按网络地址有序）。调用方负责长度与重复性检查。
    """
    nodes: list[dict] = []
    by_id: dict[object, list[int]] = defaultdict(list)
    by_network: dict[tuple[int, int], list[int]] = defaultdict(list)

    for index, (raw_id, raw_cidr) in enumerate(entries):
        entry_id = _validate_hierarchy_id(raw_id)
        start, end, cidr = parse_cidr_v4(raw_cidr)
        prefixlen = int(cidr.rsplit("/", 1)[1])
        nodes.append(
            {
                "index": index,
                "id": entry_id,
                "cidr": cidr,
                "start": start,
                "end": end,
                "prefixlen": prefixlen,
            }
        )
        by_id[entry_id].append(index)
        by_network[(start, end)].append(index)

    # by_id 按 id 首次出现的顺序插入，重复组天然按首次位置有序
    duplicate_ids = [
        {"id": nodes[indexes[0]]["id"], "indexes": indexes}
        for indexes in by_id.values()
        if len(indexes) > 1
    ]

    network_groups = [idxs for idxs in by_network.values() if len(idxs) > 1]

    def network_order(idxs: list[int]) -> tuple[int, int]:
        return nodes[idxs[0]]["start"], nodes[idxs[0]]["end"]

    duplicate_networks = [
        {
            "cidr": nodes[indexes[0]]["cidr"],
            "entries": [
                {"index": i, "id": nodes[i]["id"], "cidr": nodes[i]["cidr"]}
                for i in indexes
            ],
        }
        for indexes in sorted(network_groups, key=network_order)
    ]
    return nodes, duplicate_ids, duplicate_networks


def _direct_parent_indices(nodes: Sequence[dict]) -> list[int | None]:
    """为每个节点选择输入中前缀最长的严格超网作为唯一 parent。

    前提：节点间不存在规范化后相同的网段；此时“最长前缀严格超网”至多
    只有一个，根节点对应 ``None``。
    """
    parents: list[int | None] = []
    for node in nodes:
        parent_idx: int | None = None
        parent_prefix = -1
        for candidate in nodes:
            if (
                candidate["start"] <= node["start"]
                and candidate["end"] >= node["end"]
                and candidate["prefixlen"] < node["prefixlen"]
            ):
                if candidate["prefixlen"] > parent_prefix:
                    parent_prefix = candidate["prefixlen"]
                    parent_idx = candidate["index"]
        parents.append(parent_idx)
    return parents


def build_cidr_hierarchy(
    entries: Sequence[tuple[object, str]],
) -> dict:
    """构建 IPv4 CIDR 条目的包含层级（森林）。

    每个条目的唯一 parent = 输入中**前缀最长的严格超网**；不存在严格超网
    的条目作为 root。每个节点还给出 ``total_addresses``（自身网段地址数）、
    ``exclusive_address_count``（自身范围扣除**全部直接子节点**并集后的
    地址数）以及该独占集合无损压缩、数量最少的 ``exclusive_cidrs``。

    树按 ``(网络地址升序, 前缀长度升序, 输入序号升序)`` 稳定排列（先根
    遍历的兄弟顺序）。全程基于整数区间运算，不逐地址枚举。

    重复 id 或规范化后网段重复时抛出 :class:`HierarchyInputError`，
    非法 CIDR 抛出 :class:`InvalidCIDRError`。
    """
    if not 1 <= len(entries) <= HIERARCHY_MAX_ENTRIES:
        raise ValueError(
            f"条目数必须在 1..{HIERARCHY_MAX_ENTRIES} 之间，实际 {len(entries)}"
        )

    nodes, duplicate_ids, duplicate_networks = _parse_hierarchy_entries(entries)
    if duplicate_ids or duplicate_networks:
        raise HierarchyInputError(duplicate_ids, duplicate_networks)

    parents = _direct_parent_indices(nodes)

    children: dict[int | None, list[int]] = defaultdict(list)
    for index, parent_idx in enumerate(parents):
        children[parent_idx].append(index)

    def order_key(idx: int) -> tuple[int, int, int]:
        return nodes[idx]["start"], nodes[idx]["prefixlen"], nodes[idx]["index"]

    for siblings in children.values():
        siblings.sort(key=order_key)

    def build_node(index: int) -> dict:
        node = nodes[index]
        parent_idx = parents[index]
        child_indices = children.get(index, [])
        child_intervals = [
            (nodes[c]["start"], nodes[c]["end"]) for c in child_indices
        ]
        # 直接子节点两两不相交（同层网络不可能严格包含），合并仅用于规范化
        exclusive = subtract_covered(
            (node["start"], node["end"]),
            merge_intervals(child_intervals),
        )
        exclusive_count = sum(b - a + 1 for a, b in exclusive)
        return {
            "id": node["id"],
            "cidr": node["cidr"],
            "parent_id": None if parent_idx is None else nodes[parent_idx]["id"],
            "total_addresses": node["end"] - node["start"] + 1,
            "exclusive_address_count": exclusive_count,
            "exclusive_cidrs": compress_intervals(exclusive),
            "children": [build_node(c) for c in child_indices],
        }

    roots = [build_node(i) for i in children.get(None, [])]
    return {"node_count": len(nodes), "root_count": len(roots), "roots": roots}


# ---------- CIDR 清单差异（/cidrs/diff） ----------

#: 差异比对单侧清单允许的最大条目数
CIDR_DIFF_MAX_ENTRIES = HIERARCHY_MAX_ENTRIES


class CidrDiffInputError(ValueError):
    """差异比对输入不合法：任一侧 id 或规范化网段重复。

    ``sides`` 以侧别（``"before"`` / ``"after"``）为键，值与
    :class:`HierarchyInputError` 的两个属性同构：
    ``{"duplicate_ids": [...], "duplicate_networks": [...]}``。
    两侧会被完整校验后一次性报告（不存在的侧为空结构）。
    """

    def __init__(self, sides: dict[str, dict]) -> None:
        self.sides = sides
        parts = []
        for side in ("before", "after"):
            info = sides[side]
            if info["duplicate_ids"] or info["duplicate_networks"]:
                parts.append(
                    f"{side} 侧 {len(info['duplicate_ids'])} 个重复 id、"
                    f"{len(info['duplicate_networks'])} 个规范化后重复的网段"
                )
        super().__init__("；".join(parts) or "CIDR 差异比对输入不合法")


def _interval_overlap_size(
    a: tuple[int, int], b: tuple[int, int]
) -> int:
    """两个闭区间的交集长度（不相交时为 0）。"""
    lo = max(a[0], b[0])
    hi = min(a[1], b[1])
    return hi - lo + 1 if lo <= hi else 0


def _diff_parents(nodes: Sequence[dict]) -> dict[object, object | None]:
    """计算 ``{id: 直接父节点 id（root 为 None）}``。"""
    parent_indices = _direct_parent_indices(nodes)
    return {
        node["id"]: (None if parent_indices[i] is None else nodes[parent_indices[i]]["id"])
        for i, node in enumerate(nodes)
    }


def diff_cidr_lists(
    before: Sequence[tuple[object, str]],
    after: Sequence[tuple[object, str]],
) -> dict:
    """比对两份带唯一 id 的 IPv4 网段清单（before/after）。

    以 id 匹配两侧条目，将其分为：

    - ``added``：仅出现在 after；
    - ``removed``：仅出现在 before；
    - ``cidr_changed``：同 id 但规范化网段不同；
    - ``unchanged``：同 id 且规范化网段相同（``parent_changed`` 另作标记）。

    每个条目的直接父节点（前缀最长的严格超网）在**各自清单内独立**计算，
    仅同 id 匹配上的条目比较父节点变化。规范化后网段相同但 **id 不同**的
    前后条目两两配对，列入 ``replacement_candidates``（替换候选）。

    ``affected_address_count``：CIDR 变更取旧、新网段的**对称差**地址数；
    新增 / 删除取该网段自身地址数；其余为 0。

    结果条目保持 **before 顺序**（删除 / 匹配项），新增项按 **after 顺序**
    追加；替换候选同样按 before 侧位置（再按 after 侧位置）排列。

    任一侧条目超过 :data:`CIDR_DIFF_MAX_ENTRIES` 抛出 :class:`ValueError`；
    任一侧 id 或规范化网段重复时抛出 :class:`CidrDiffInputError`，
    两侧重复问题一次性报告，不产生部分结果；非法 CIDR 抛出
    :class:`InvalidCIDRError`。
    """
    for side_name, entries in (("before", before), ("after", after)):
        if len(entries) > CIDR_DIFF_MAX_ENTRIES:
            raise ValueError(
                f"{side_name} 侧条目数不能超过 {CIDR_DIFF_MAX_ENTRIES}，"
                f"实际 {len(entries)}"
            )

    # 两侧完整解析并收集重复；任一侧有重复即整体 422，不产生部分结果
    before_nodes, before_dup_ids, before_dup_nets = _parse_hierarchy_entries(before)
    after_nodes, after_dup_ids, after_dup_nets = _parse_hierarchy_entries(after)
    sides = {
        "before": {
            "duplicate_ids": before_dup_ids,
            "duplicate_networks": before_dup_nets,
        },
        "after": {
            "duplicate_ids": after_dup_ids,
            "duplicate_networks": after_dup_nets,
        },
    }
    if before_dup_ids or before_dup_nets or after_dup_ids or after_dup_nets:
        raise CidrDiffInputError(sides)

    before_by_id = {node["id"]: node for node in before_nodes}
    after_by_id = {node["id"]: node for node in after_nodes}
    before_parents = _diff_parents(before_nodes)
    after_parents = _diff_parents(after_nodes)

    changes: list[dict] = []
    counts = {
        "added": 0,
        "removed": 0,
        "cidr_changed": 0,
        "unchanged": 0,
        "parent_changed": 0,
    }
    affected_total = 0

    # 保持 before 顺序：删除项与同 id 匹配项按 before 出现位置输出
    for node in before_nodes:
        entry_id = node["id"]
        other = after_by_id.get(entry_id)
        if other is None:
            count = node["end"] - node["start"] + 1
            changes.append(
                {
                    "id": entry_id,
                    "change": "removed",
                    "before_cidr": node["cidr"],
                    "after_cidr": None,
                    "before_parent_id": before_parents[entry_id],
                    "after_parent_id": None,
                    "parent_changed": None,
                    "affected_address_count": count,
                }
            )
            counts["removed"] += 1
            affected_total += count
        else:
            cidr_changed = node["cidr"] != other["cidr"]
            parent_before = before_parents[entry_id]
            parent_after = after_parents[entry_id]
            parent_changed = parent_before != parent_after
            if cidr_changed:
                before_range = (node["start"], node["end"])
                after_range = (other["start"], other["end"])
                old_size = node["end"] - node["start"] + 1
                new_size = other["end"] - other["start"] + 1
                # 对称差 = 两侧大小之和 − 2×交集
                count = (
                    old_size
                    + new_size
                    - 2 * _interval_overlap_size(before_range, after_range)
                )
                change = "cidr_changed"
                counts["cidr_changed"] += 1
                affected_total += count
            else:
                count = 0
                change = "unchanged"
                counts["unchanged"] += 1
            if parent_changed:
                counts["parent_changed"] += 1
            changes.append(
                {
                    "id": entry_id,
                    "change": change,
                    "before_cidr": node["cidr"],
                    "after_cidr": other["cidr"],
                    "before_parent_id": parent_before,
                    "after_parent_id": parent_after,
                    "parent_changed": parent_changed,
                    "affected_address_count": count,
                }
            )

    # 新增项按 after 顺序追加
    for node in after_nodes:
        entry_id = node["id"]
        if entry_id in before_by_id:
            continue
        count = node["end"] - node["start"] + 1
        changes.append(
            {
                "id": entry_id,
                "change": "added",
                "before_cidr": None,
                "after_cidr": node["cidr"],
                "before_parent_id": None,
                "after_parent_id": after_parents[entry_id],
                "parent_changed": None,
                "affected_address_count": count,
            }
        )
        counts["added"] += 1
        affected_total += count

    # 替换候选：规范化后网段相同但 id 不同（同 id 的匹配不算替换）。
    # 两侧网段各自唯一，因此每个网段至多一条 before 与一条 after。
    after_by_network = {
        (node["start"], node["end"]): node for node in after_nodes
    }
    replacement_candidates: list[dict] = []
    for node in before_nodes:
        other = after_by_network.get((node["start"], node["end"]))
        if other is not None and node["id"] != other["id"]:
            count = node["end"] - node["start"] + 1
            replacement_candidates.append(
                {
                    "before_id": node["id"],
                    "after_id": other["id"],
                    "cidr": node["cidr"],
                    "address_count": count,
                }
            )

    return {
        "before_count": len(before_nodes),
        "after_count": len(after_nodes),
        "changes": changes,
        "replacement_candidates": replacement_candidates,
        "summary": {
            "added": counts["added"],
            "removed": counts["removed"],
            "cidr_changed": counts["cidr_changed"],
            "unchanged": counts["unchanged"],
            "parent_changed": counts["parent_changed"],
            "replacement_candidate_count": len(replacement_candidates),
            "affected_address_count": affected_total,
        },
    }
