"""FastAPI 应用：IPv4 CIDR 遮蔽分析、规则集等价性比较、包含层级分析与路由解析 API。"""
from __future__ import annotations

from typing import Literal

from fastapi import Body, FastAPI, HTTPException
from pydantic import BaseModel, Field, StrictInt, StrictStr, field_validator

from .analyzer import (
    CIDR_DIFF_MAX_ENTRIES,
    HIERARCHY_MAX_ENTRIES,
    CidrDiffInputError,
    HierarchyInputError,
    InvalidCIDRError,
    analyze_rules,
    build_cidr_hierarchy,
    compare_rule_sets,
    diff_cidr_lists,
    explain_query,
    parse_cidr_v4,
)
from .router import (
    FAILED_NEXT_HOPS_MAX,
    METRIC_MAX,
    ROUTES_MAX,
    TARGETS_MAX,
    DuplicateNextHopsError,
    DuplicateTargetsError,
    InvalidIPv4AddressError,
    failover_routes,
    parse_address_v4,
    resolve_routes,
)

app = FastAPI(
    title="IPv4 遮蔽分析 API",
    description=(
        "接收有序的 allow/deny CIDR 规则，计算每条规则未被此前规则覆盖的"
        "地址集合，按 **全生效 (full)** / **部分遮蔽 (partial)** / "
        "**完全遮蔽 (shadowed)** 分类，并将剩余集合无损压缩为数量最少的 CIDR；"
        "也可通过 /compare 比较两组规则在整个 IPv4 空间上的最终判定是否等价，"
        "通过 /explain 解释一段地址空间由哪条规则或默认动作最终裁决，"
        "通过 /cidrs/hierarchy 分析一组 CIDR 的包含层级（森林）与独占地址，"
        "通过 /cidrs/diff 比对两份带唯一 id 的网段清单的新增、删除、CIDR "
        "变更与直接父节点变化（并标记规范化后网段相同但 id 不同的替换候选），"
        "通过 /routes/resolve 对目标地址做最长前缀匹配、最低 metric 的"
        "等价多路径（ECMP）路由解析，或通过 /routes/failover 模拟一组下一跳"
        "失效后的路由切换影响（before/after/impact）。"
    ),
    version="1.6.0",
)


class Rule(BaseModel):
    """单条规则：动作 + IPv4 CIDR。"""

    action: Literal["allow", "deny"] = Field(
        ..., description="动作，仅允许 allow 或 deny（大小写不敏感）"
    )
    cidr: str = Field(
        ...,
        description="IPv4 CIDR，如 10.0.0.0/8；纯 IP 按 /32 处理；禁止 IPv6",
    )

    @field_validator("action", mode="before")
    @classmethod
    def normalize_action(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip().lower()
        return value

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, value: str) -> str:
        # 校验并规范化；非法 CIDR / IPv6 抛出 ValueError -> 422
        return parse_cidr_v4(value)[2]


class AnalyzeRequest(BaseModel):
    """分析请求：有序规则列表，至少 1 条。"""

    rules: list[Rule] = Field(..., min_length=1, description="有序规则列表（按序处理）")


class RuleResult(BaseModel):
    index: int = Field(..., description="规则在输入中的序号（从 0 开始）")
    action: Literal["allow", "deny"]
    cidr: str = Field(..., description="规范化后的规则 CIDR")
    status: Literal["full", "partial", "shadowed"]
    status_label: str = Field(..., description="状态中文说明")
    total_addresses: int
    covered_addresses: int = Field(..., description="被此前规则遮蔽的地址数")
    effective_addresses: int = Field(..., description="本规则实际生效的地址数")
    effective_cidrs: list[str] = Field(
        ..., description="生效地址集合无损压缩后的最少 CIDR 列表（空表示完全遮蔽）"
    )


class Summary(BaseModel):
    full: int
    partial: int
    shadowed: int
    effective_allow_addresses: int = Field(..., description="汇总生效的 allow 地址数")
    effective_deny_addresses: int = Field(..., description="汇总生效的 deny 地址数")


class AnalyzeResponse(BaseModel):
    rule_count: int
    rules: list[RuleResult]
    summary: Summary


class RuleSet(BaseModel):
    """一侧规则集：有序规则列表 + 未命中时的默认动作。"""

    rules: list[Rule] = Field(
        default_factory=list, description="有序规则列表（按序处理），可为空"
    )
    default_action: Literal["allow", "deny"] = Field(
        ...,
        description="未命中任何规则时的默认动作（大小写不敏感）",
    )

    @field_validator("default_action", mode="before")
    @classmethod
    def normalize_default_action(cls, value: object) -> object:
        if isinstance(value, str):
            return value.strip().lower()
        return value


class CompareRequest(BaseModel):
    """比较请求：左右两侧规则集及其默认动作。"""

    left: RuleSet
    right: RuleSet


class DifferenceGroup(BaseModel):
    left_action: Literal["allow", "deny"]
    right_action: Literal["allow", "deny"]
    address_count: int = Field(..., description="该判定组合覆盖的地址数")
    cidrs: list[str] = Field(
        ...,
        description="该组地址集合无损压缩后的最少 CIDR 列表",
    )


class CompareResponse(BaseModel):
    equivalent: bool = Field(
        ..., description="两侧在整个 IPv4 空间上的最终判定是否完全一致"
    )
    differences: list[DifferenceGroup] = Field(
        ...,
        description="判定不同的地址分组（按 left_action/right_action）；等价时为空",
    )


class ExplainRequest(RuleSet):
    """解释请求：有序规则列表 + 默认动作 + 单个待解释的 query CIDR。"""

    query: str = Field(
        ...,
        description="待解释的 IPv4 CIDR，如 10.0.0.0/8；纯 IP 按 /32 处理；禁止 IPv6",
    )

    @field_validator("query")
    @classmethod
    def validate_query(cls, value: str) -> str:
        # 校验并规范化；非法 CIDR / IPv6 抛出 ValueError -> 422
        return parse_cidr_v4(value)[2]


class AttributionItem(BaseModel):
    source: Literal["rule", "default"] = Field(
        ..., description="裁决来源：rule 表示命中规则，default 表示走默认动作"
    )
    rule_index: int | None = Field(
        ..., description="命中规则在输入中的序号（从 0 开始）；默认项为 null"
    )
    action: Literal["allow", "deny"]
    address_count: int = Field(..., description="该项覆盖的地址数")
    cidrs: list[str] = Field(
        ..., description="该项地址集合无损压缩后的最少 CIDR 列表"
    )


class ExplainResponse(BaseModel):
    query: str = Field(..., description="规范化后的 query CIDR")
    total_addresses: int = Field(..., description="query 覆盖的地址总数")
    attribution: list[AttributionItem] = Field(
        ...,
        description=(
            "归因列表：按规则索引升序、默认项最后；所有项不重不漏覆盖 query"
        ),
    )


# ---------- /cidrs/hierarchy ----------

#: 层级条目 id：非空字符串或整数（bool 明确拒绝，不做隐式类型转换）
EntryId = StrictStr | StrictInt


class CidrEntry(BaseModel):
    """单个层级条目：唯一 id + 严格 IPv4 CIDR。"""

    id: EntryId = Field(..., description="条目标识，字符串或整数，全请求内唯一")
    cidr: str = Field(
        ...,
        description="IPv4 CIDR，如 10.0.0.0/8；纯 IP 按 /32 处理；禁止 IPv6",
    )

    @field_validator("id")
    @classmethod
    def validate_id(cls, value: object) -> object:
        # 防御性校验：pydantic StrictStr|StrictInt 已拦截 bool/float 等，
        # 这里兜底拒绝空白字符串（独立使用 analyzer 时同样由核心层校验）
        if isinstance(value, bool) or not isinstance(value, (str, int)):
            raise ValueError("id 仅支持字符串或整数")
        if isinstance(value, str) and not value.strip():
            raise ValueError("id 不能为空字符串")
        return value

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, value: str) -> str:
        # 校验并规范化；非法 CIDR / IPv6 抛出 ValueError -> 422
        return parse_cidr_v4(value)[2]


class HierarchyRequest(BaseModel):
    """层级分析请求：1～500 个含 id 与 cidr 的条目。"""

    entries: list[CidrEntry] = Field(
        ...,
        min_length=1,
        max_length=HIERARCHY_MAX_ENTRIES,
        description="含 id 与 cidr 的条目列表（1～500 个）",
    )


class HierarchyNode(BaseModel):
    id: EntryId = Field(..., description="条目 id")
    cidr: str = Field(..., description="规范化后的条目 CIDR")
    parent_id: EntryId | None = Field(
        ..., description="唯一父节点 id（前缀最长的严格超网）；根节点为 null"
    )
    total_addresses: int = Field(..., description="本网段覆盖的地址总数")
    exclusive_address_count: int = Field(
        ...,
        description="自身范围扣除全部直接子节点并集后的独占地址数",
    )
    exclusive_cidrs: list[str] = Field(
        ...,
        description="独占地址集合无损压缩后的最少 CIDR 列表（无子节点时为本网段自身）",
    )
    children: list["HierarchyNode"] = Field(
        ...,
        description="直接子节点列表，按网络地址、前缀长度、输入顺序稳定排序",
    )


class HierarchyResponse(BaseModel):
    node_count: int = Field(..., description="节点（条目）总数")
    root_count: int = Field(..., description="根节点数量")
    roots: list[HierarchyNode] = Field(
        ...,
        description="根节点组成的森林，按网络地址、前缀长度、输入顺序稳定排序",
    )


HierarchyNode.model_rebuild()


# ---------- /cidrs/diff ----------


class CidrDiffRequest(BaseModel):
    """网段清单差异请求：before / after 各为 0～500 个含唯一 id 与 cidr 的条目。"""

    before: list[CidrEntry] = Field(
        ...,
        max_length=CIDR_DIFF_MAX_ENTRIES,
        description="变更前的条目列表（允许为空 []）；id 与规范化网段在本侧内必须唯一",
    )
    after: list[CidrEntry] = Field(
        ...,
        max_length=CIDR_DIFF_MAX_ENTRIES,
        description="变更后的条目列表（允许为空 []）；id 与规范化网段在本侧内必须唯一",
    )


class CidrReplacementCandidate(BaseModel):
    before_id: EntryId = Field(..., description="before 侧条目 id")
    after_id: EntryId = Field(..., description="after 侧条目 id")
    cidr: str = Field(..., description="两侧规范化后相同的网段")
    address_count: int = Field(..., description="该网段的地址数")


class CidrChangeItem(BaseModel):
    id: EntryId = Field(..., description="条目 id（before/after 两侧或其中一侧）")
    change: Literal["added", "removed", "cidr_changed", "unchanged"] = Field(
        ...,
        description=(
            "变化分类：added 仅 after 存在；removed 仅 before 存在；"
            "cidr_changed 同 id 但规范化网段不同；unchanged 同 id 且网段相同"
            "（parent_changed 可能同时为 true）"
        ),
    )
    before_cidr: str | None = Field(
        ..., description="before 侧规范化网段；新增项为 null"
    )
    after_cidr: str | None = Field(
        ..., description="after 侧规范化网段；删除项为 null"
    )
    before_parent_id: EntryId | None = Field(
        ...,
        description="before 侧的直接父节点 id（前缀最长的严格超网，root 为 null）；新增项为 null",
    )
    after_parent_id: EntryId | None = Field(
        ...,
        description="after 侧的直接父节点 id（前缀最长的严格超网，root 为 null）；删除项为 null",
    )
    parent_changed: bool | None = Field(
        ...,
        description=(
            "同 id 匹配项的直接父节点是否发生变化（仅在本侧清单内独立择父）；"
            "新增 / 删除项为 null"
        ),
    )
    affected_address_count: int = Field(
        ...,
        description=(
            "受影响地址数：CIDR 变更取旧、新网段的对称差地址数；"
            "新增 / 删除取该网段地址数；其余为 0"
        ),
    )


class CidrDiffSummary(BaseModel):
    added: int = Field(..., description="新增条目数")
    removed: int = Field(..., description="删除条目数")
    cidr_changed: int = Field(..., description="同 id 但 CIDR 变更的条目数")
    unchanged: int = Field(
        ...,
        description="同 id 且网段相同的条目数（其中部分可能 parent_changed=true）",
    )
    parent_changed: int = Field(
        ...,
        description="同 id 匹配且直接父节点发生变化的条目数（可与 cidr_changed 重叠）"
    )
    replacement_candidate_count: int = Field(
        ..., description="替换候选（网段相同但 id 不同）的配对数"
    )
    affected_address_count: int = Field(
        ..., description="全部新增、删除与 CIDR 变更条目的受影响地址数之和"
    )


class CidrDiffResponse(BaseModel):
    before_count: int = Field(..., description="before 侧条目数")
    after_count: int = Field(..., description="after 侧条目数")
    changes: list[CidrChangeItem] = Field(
        ...,
        description="逐条变化结果：保持 before 顺序（删除 / 匹配项），新增项按 after 顺序追加",
    )
    replacement_candidates: list[CidrReplacementCandidate] = Field(
        ...,
        description="规范化后网段相同但 id 不同的配对（替换候选），按 before 侧位置排序",
    )
    summary: CidrDiffSummary


# ---------- /routes/resolve ----------


class RouteEntry(BaseModel):
    """单条静态路由：严格 IPv4 CIDR + 严格 IPv4 下一跳 + metric。"""

    cidr: str = Field(
        ...,
        description="IPv4 CIDR，如 10.0.0.0/8；纯 IP 按 /32 处理；禁止 IPv6",
    )
    next_hop: str = Field(
        ..., description="下一跳 IPv4 地址（纯地址，禁止 CIDR 写法与 IPv6）"
    )
    metric: int = Field(
        ..., ge=0, le=METRIC_MAX, strict=True, description="路由度量，0～65535 的整数"
    )

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, value: str) -> str:
        # 校验并规范化；非法 CIDR / IPv6 抛出 ValueError -> 422
        return parse_cidr_v4(value)[2]

    @field_validator("next_hop")
    @classmethod
    def validate_next_hop(cls, value: str) -> str:
        # 校验并规范化；非法地址 / CIDR 写法 / IPv6 抛出 ValueError -> 422
        return parse_address_v4(value)[1]


class RouteResolveRequest(BaseModel):
    """路由解析请求：0～1000 条路由 + 1～500 个唯一目标地址。"""

    routes: list[RouteEntry] = Field(
        ..., max_length=ROUTES_MAX, description="静态路由列表，按数组顺序作为去重/ECMP 次序"
    )
    targets: list[str] = Field(
        ...,
        min_length=1,
        max_length=TARGETS_MAX,
        description="目标 IPv4 地址列表（纯地址），全请求内唯一；响应保持该顺序",
    )

    @field_validator("targets", mode="before")
    @classmethod
    def validate_targets(cls, value: object) -> object:
        # 逐地址严格校验并规范化；非法地址 / CIDR 写法 / IPv6 -> 422
        if isinstance(value, list):
            return [parse_address_v4(item)[1] for item in value]
        return value


class ResolvedTarget(BaseModel):
    target: str = Field(..., description="规范化后的目标 IPv4 地址")
    status: Literal["reachable", "unreachable"]
    matched_cidr: str | None = Field(
        ..., description="命中的最长前缀 CIDR（ECMP 路由共同网段）；不可达为 null"
    )
    metric: int | None = Field(
        ..., description="命中路由的最低 metric；不可达为 null"
    )
    next_hops: list[str] = Field(
        ...,
        description="等价下一跳列表，按 routes 输入顺序去重；不可达为空",
    )


class NextHopCount(BaseModel):
    next_hop: str = Field(..., description="规范化后的下一跳 IPv4 地址")
    target_count: int = Field(
        ..., description="该下一跳命中的目标数（同一 ECMP 结果的各下一跳分别计一次）"
    )


class RouteResolveSummary(BaseModel):
    reachable_count: int = Field(..., description="可达目标数")
    unreachable_count: int = Field(..., description="不可达目标数")
    next_hop_counts: list[NextHopCount] = Field(
        ...,
        description=(
            "每个 next_hop 命中的目标数，按 next_hop 在 routes 中的首次出现"
            "位置排序；仅列实际命中过的下一跳"
        ),
    )


class RouteResolveResponse(BaseModel):
    route_count: int = Field(..., description="请求中的路由条数")
    target_count: int = Field(..., description="请求中的目标数")
    results: list[ResolvedTarget] = Field(
        ..., description="逐目标解析结果，严格保持 targets 输入顺序"
    )
    summary: RouteResolveSummary


# ---------- /routes/failover ----------


class RouteFailoverRequest(RouteResolveRequest):
    """故障切换请求：在 /routes/resolve 请求基础上增加唯一失败下一跳列表。"""

    failed_next_hops: list[str] = Field(
        ...,
        max_length=FAILED_NEXT_HOPS_MAX,
        description=(
            "失效的下一跳 IPv4 地址列表（纯地址），全请求内唯一，允许为空；"
            "这些下一跳对应的全部路由将被移除后重新解析"
        ),
    )

    @field_validator("failed_next_hops", mode="before")
    @classmethod
    def validate_failed_next_hops(cls, value: object) -> object:
        # 逐地址严格校验并规范化；非法地址 / CIDR 写法 / IPv6 -> 422
        if isinstance(value, list):
            return [parse_address_v4(item)[1] for item in value]
        return value


class RouteResolution(BaseModel):
    """单次路由解析结果（before / after 共用，不含 target）。"""

    status: Literal["reachable", "unreachable"]
    matched_cidr: str | None = Field(
        ..., description="命中的最长前缀 CIDR（ECMP 路由共同网段）；不可达为 null"
    )
    metric: int | None = Field(
        ..., description="命中路由的最低 metric；不可达为 null"
    )
    next_hops: list[str] = Field(
        ...,
        description="等价下一跳列表，按 routes 输入顺序去重；不可达为空",
    )


class RouteFailoverResult(BaseModel):
    target: str = Field(..., description="规范化后的目标 IPv4 地址")
    before: RouteResolution = Field(..., description="故障前（完整路由表）的解析结果")
    after: RouteResolution = Field(
        ..., description="移除失败下一跳对应全部路由后的重新解析结果"
    )
    impact: Literal["unchanged", "ecmp_reduced", "rerouted", "unreachable"] = Field(
        ...,
        description=(
            "影响分类：unchanged 结果不变；ecmp_reduced 网段与 metric 不变、"
            "等价下一跳减少；rerouted 仍可达但网段或 metric 改变；"
            "unreachable 故障后不可达"
        ),
    )


class RouteFailoverSummary(BaseModel):
    unchanged: int = Field(..., description="解析结果完全不变的目标数（含两侧均不可达）")
    ecmp_reduced: int = Field(
        ..., description="命中网段与 metric 不变、等价下一跳减少的目标数"
    )
    rerouted: int = Field(
        ..., description="仍可达但命中网段或 metric 改变的目标数"
    )
    unreachable: int = Field(..., description="原本可达、故障后不可达的目标数")


class RouteFailoverResponse(BaseModel):
    route_count: int = Field(..., description="请求中的路由条数")
    target_count: int = Field(..., description="请求中的目标数")
    failed_next_hops: list[str] = Field(
        ..., description="规范化后的失败下一跳列表，保持输入顺序"
    )
    results: list[RouteFailoverResult] = Field(
        ..., description="逐目标故障切换结果，严格保持 targets 输入顺序"
    )
    summary: RouteFailoverSummary


@app.get("/", tags=["meta"])
def root() -> dict:
    """服务信息。"""
    return {
        "service": "ipv4-shadow-analyzer",
        "docs": "/docs",
        "openapi": "/openapi.json",
        "health": "/health",
    }


@app.get("/health", tags=["meta"])
def health() -> dict:
    """健康检查。"""
    return {"status": "ok"}


@app.post(
    "/analyze",
    response_model=AnalyzeResponse,
    tags=["analyze"],
    summary="分析有序 allow/deny 规则的遮蔽情况",
)
def analyze(request: AnalyzeRequest) -> dict:
    """按顺序计算每条规则未被此前规则覆盖的地址集合并分类。

    非法 CIDR、IPv6、空规则集均返回 **422 Unprocessable Entity**。
    """
    # analyzer 再做一次防御性校验（该模块也可独立使用）
    try:
        return analyze_rules([(r.action, r.cidr) for r in request.rules])
    except InvalidCIDRError:
        # 正常情况下 pydantic 已在入口拦截，这里兜底转为 422
        raise


@app.post(
    "/compare",
    response_model=CompareResponse,
    tags=["compare"],
    summary="比较两组有序规则在整个 IPv4 空间上的最终判定是否等价",
)
def compare(request: CompareRequest) -> dict:
    """两侧均沿用 /analyze 的 CIDR 校验与“首条匹配规则生效”顺序。

    未命中任何规则的地址取各自 ``default_action``；判定不同的地址按
    left_action/right_action 分组，返回地址数与无损压缩后的最少 CIDR。
    基于区间归并计算，不逐地址枚举。
    """
    try:
        return compare_rule_sets(
            [(r.action, r.cidr) for r in request.left.rules],
            request.left.default_action,
            [(r.action, r.cidr) for r in request.right.rules],
            request.right.default_action,
        )
    except InvalidCIDRError:
        # 正常情况下 pydantic 已在入口拦截，这里兜底转为 422
        raise


@app.post(
    "/explain",
    response_model=ExplainResponse,
    tags=["explain"],
    summary="解释一段 IPv4 地址空间由哪条规则或默认动作最终裁决",
)
def explain(request: ExplainRequest) -> dict:
    """在 ``query`` 范围内按“首条匹配规则生效”语义归因。

    query 中的每个地址归属于首条命中它的规则；未命中任何规则的部分
    归于 ``default_action``。归因项按规则索引升序、默认项最后返回，
    所有项不重不漏地覆盖整个 query；每项给出无损压缩后的最少 CIDR。
    基于区间归并计算，不逐地址枚举。
    """
    try:
        return explain_query(
            [(r.action, r.cidr) for r in request.rules],
            request.default_action,
            request.query,
        )
    except InvalidCIDRError:
        # 正常情况下 pydantic 已在入口拦截，这里兜底转为 422
        raise


@app.post(
    "/cidrs/hierarchy",
    response_model=HierarchyResponse,
    tags=["hierarchy"],
    summary="分析一组 IPv4 CIDR 的包含层级（森林）与各节点独占地址",
)
def cidr_hierarchy(request: HierarchyRequest) -> dict:
    """对每个网段选择输入中前缀最长的严格超网作为唯一 parent，没有则为 root。

    - 每个节点给出 ``total_addresses``；
    - ``exclusive_address_count`` / ``exclusive_cidrs`` 为自身范围扣除
      **全部直接子节点**并集后的独占地址集合，无损、数量最少；
    - 返回按网络地址、前缀长度、输入顺序稳定排列的树（兄弟有序的森林）。

    id 必须唯一；规范化后网段相同的条目（如 ``10.0.0.0/8`` 与
    ``10.0.0.0/08``）返回 **422** 并列出冲突 id；非法 CIDR / IPv6 同样 422。
    """
    try:
        return build_cidr_hierarchy(
            [(entry.id, entry.cidr) for entry in request.entries]
        )
    except HierarchyInputError as exc:
        # 重复 id / 规范化后重复网段：422 并列出冲突 id
        raise HTTPException(
            status_code=422,
            detail={
                "error": "duplicate_entries",
                "duplicate_ids": exc.duplicate_ids,
                "duplicate_networks": exc.duplicate_networks,
            },
        ) from exc
    except InvalidCIDRError:
        # 正常情况下 pydantic 已在入口拦截，这里兜底转为 422
        raise


@app.post(
    "/cidrs/diff",
    response_model=CidrDiffResponse,
    tags=["hierarchy"],
    summary="比对两份带唯一 id 的 IPv4 网段清单的新增、删除、CIDR 变更与父节点变化",
    responses={
        200: {
            "content": {
                "application/json": {
                    "examples": {
                        "diff": {
                            "summary": "新增 / 删除 / CIDR 变更 / 父节点变化 / 替换候选",
                            "value": {
                                "before_count": 4,
                                "after_count": 4,
                                "changes": [
                                    {
                                        "id": "net",
                                        "change": "unchanged",
                                        "before_cidr": "10.0.0.0/8",
                                        "after_cidr": "10.0.0.0/8",
                                        "before_parent_id": None,
                                        "after_parent_id": None,
                                        "parent_changed": False,
                                        "affected_address_count": 0,
                                    },
                                    {
                                        "id": "sub-a",
                                        "change": "cidr_changed",
                                        "before_cidr": "10.1.0.0/16",
                                        "after_cidr": "10.1.0.0/24",
                                        "before_parent_id": "net",
                                        "after_parent_id": "net",
                                        "parent_changed": False,
                                        "affected_address_count": 65280,
                                    },
                                    {
                                        "id": "sub-b",
                                        "change": "removed",
                                        "before_cidr": "10.2.0.0/16",
                                        "after_cidr": None,
                                        "before_parent_id": "net",
                                        "after_parent_id": None,
                                        "parent_changed": None,
                                        "affected_address_count": 65536,
                                    },
                                    {
                                        "id": "old-dns",
                                        "change": "removed",
                                        "before_cidr": "8.8.8.8/32",
                                        "after_cidr": None,
                                        "before_parent_id": None,
                                        "after_parent_id": None,
                                        "parent_changed": None,
                                        "affected_address_count": 1,
                                    },
                                    {
                                        "id": "sub-c",
                                        "change": "added",
                                        "before_cidr": None,
                                        "after_cidr": "10.2.0.0/16",
                                        "before_parent_id": None,
                                        "after_parent_id": "net",
                                        "parent_changed": None,
                                        "affected_address_count": 65536,
                                    },
                                    {
                                        "id": "new-dns",
                                        "change": "added",
                                        "before_cidr": None,
                                        "after_cidr": "8.8.8.8/32",
                                        "before_parent_id": None,
                                        "after_parent_id": None,
                                        "parent_changed": None,
                                        "affected_address_count": 1,
                                    },
                                ],
                                "replacement_candidates": [
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
                                ],
                                "summary": {
                                    "added": 2,
                                    "removed": 2,
                                    "cidr_changed": 1,
                                    "unchanged": 1,
                                    "parent_changed": 0,
                                    "replacement_candidate_count": 2,
                                    "affected_address_count": 196354,
                                },
                            },
                        }
                    }
                }
            }
        },
        422: {
            "content": {
                "application/json": {
                    "examples": {
                        "duplicates": {
                            "summary": "after 侧存在重复 id",
                            "value": {
                                "detail": {
                                    "error": "duplicate_entries",
                                    "before": {
                                        "duplicate_ids": [],
                                        "duplicate_networks": [],
                                    },
                                    "after": {
                                        "duplicate_ids": [
                                            {"id": "x", "indexes": [0, 2]}
                                        ],
                                        "duplicate_networks": [],
                                    },
                                }
                            },
                        }
                    }
                }
            }
        },
    },
)
def cidr_diff(
    request: CidrDiffRequest = Body(
        ...,
        openapi_examples={
            "diff": {
                "summary": "新增 / 删除 / CIDR 变更 / 父节点变化 / 替换候选",
                "value": {
                    "before": [
                        {"id": "net", "cidr": "10.0.0.0/8"},
                        {"id": "sub-a", "cidr": "10.1.0.0/16"},
                        {"id": "sub-b", "cidr": "10.2.0.0/16"},
                        {"id": "old-dns", "cidr": "8.8.8.8/32"},
                    ],
                    "after": [
                        {"id": "net", "cidr": "10.0.0.0/8"},
                        {"id": "sub-a", "cidr": "10.1.0.0/24"},
                        {"id": "sub-c", "cidr": "10.2.0.0/16"},
                        {"id": "new-dns", "cidr": "8.8.8.8/32"},
                    ],
                },
            }
        },
    ),
) -> dict:
    """按 **id** 匹配 before / after 两份清单并逐条报告差异。

    - ``change`` 分类：``added``（仅 after）、``removed``（仅 before）、
      ``cidr_changed``（同 id 但规范化网段不同）、``unchanged``（同 id 且
      网段相同）；
    - 每个条目的直接父节点（前缀最长的严格超网）在**各自清单内独立**
      计算，``parent_changed`` 标记同 id 条目的父节点变化（可与
      ``cidr_changed`` 同时出现；新增 / 删除项为 ``null``）；
    - 规范化后**网段相同但 id 不同**的前后条目两两配对，列入
      ``replacement_candidates``（替换候选）；
    - ``affected_address_count``：CIDR 变更取旧、新网段的**对称差**地址数，
      新增 / 删除取该网段地址数，其余为 0；
    - ``changes`` 保持 **before 顺序**（删除 / 匹配项），新增项按
      **after 顺序**追加。

    任一侧 id 或规范化网段重复时返回 **422**，两侧重复问题一次性报告、
    **不产生部分结果**；两侧均允许为空（``[]``），单侧最多 500 个条目。
    """
    try:
        return diff_cidr_lists(
            [(entry.id, entry.cidr) for entry in request.before],
            [(entry.id, entry.cidr) for entry in request.after],
        )
    except CidrDiffInputError as exc:
        # 任一侧重复 id / 规范化后重复网段：422 并一次性列出两侧冲突
        raise HTTPException(
            status_code=422,
            detail={
                "error": "duplicate_entries",
                "before": exc.sides["before"],
                "after": exc.sides["after"],
            },
        ) from exc
    except InvalidCIDRError:
        # 正常情况下 pydantic 已在入口拦截，这里兜底转为 422
        raise


@app.post(
    "/routes/resolve",
    response_model=RouteResolveResponse,
    tags=["routes"],
    summary="按最长前缀匹配、最低 metric 解析目标地址的等价下一跳",
)
def routes_resolve(request: RouteResolveRequest) -> dict:
    """对每个目标先做**最长前缀匹配（LPM）**，再在命中路由中保留
    **最低 metric** 的全部路由，其 `next_hop` 构成等价多路径（ECMP）结果，
    按 `routes` 输入顺序**去重**后返回；未命中任何路由的目标标记为
    `unreachable`。

    - `results` 严格保持 `targets` 输入顺序；
    - `summary.next_hop_counts` 汇总每个 next_hop 命中的**目标数**
      （同一 ECMP 结果的各下一跳分别计一次），按 next_hop 在 routes 中
      的首次出现位置排序；
    - `targets` 必须唯一，重复时返回 **422** 并列出冲突位置；
    - CIDR / 目标 / 下一跳均沿用严格 IPv4 校验，`metric` 为 0～65535；
      路由最多 1000 条、目标 1～500 个。

    全程只做 32 位整数比较，**不逐地址展开网段**。
    """
    try:
        return resolve_routes(
            [(route.cidr, route.next_hop, route.metric) for route in request.routes],
            list(request.targets),
        )
    except DuplicateTargetsError as exc:
        # 重复目标：422 并列出规范化目标与其全部出现位置
        raise HTTPException(
            status_code=422,
            detail={"error": "duplicate_targets", "duplicates": exc.duplicates},
        ) from exc
    except (InvalidCIDRError, InvalidIPv4AddressError):
        # 正常情况下 pydantic 已在入口拦截，这里兜底转为 422
        raise


@app.post(
    "/routes/failover",
    response_model=RouteFailoverResponse,
    tags=["routes"],
    summary="模拟一组下一跳失效后的路由切换影响（before/after/impact）",
)
def routes_failover(request: RouteFailoverRequest) -> dict:
    """先在完整路由表上按 /routes/resolve 语义解析一次（``before``），再移除
    ``failed_next_hops`` 对应的**全部路由**，重新执行最长前缀、最低 metric
    与 ECMP 选择（``after``）——**不是**从原 ECMP 列表中删值，因此允许
    回退到**更高 metric** 或**更短前缀**。

    - `results` 严格保持 `targets` 输入顺序，每项含 `before` / `after` /
      `impact`；
    - `impact` 分类：`unchanged`（结果不变，含两侧均不可达）、
      `ecmp_reduced`（网段与 metric 不变、等价下一跳减少）、
      `rerouted`（仍可达但网段或 metric 改变）、
      `unreachable`（原本可达、故障后不可达）；
    - `summary` 汇总四类影响的目标数；
    - `routes` / `targets` 校验与 /routes/resolve 完全一致；
      `failed_next_hops` 必须唯一，重复时返回 **422** 并在
      `detail.duplicates` 中列出冲突位置。
    """
    try:
        return failover_routes(
            [(route.cidr, route.next_hop, route.metric) for route in request.routes],
            list(request.targets),
            list(request.failed_next_hops),
        )
    except DuplicateTargetsError as exc:
        # 重复目标：422 并列出规范化目标与其全部出现位置
        raise HTTPException(
            status_code=422,
            detail={"error": "duplicate_targets", "duplicates": exc.duplicates},
        ) from exc
    except DuplicateNextHopsError as exc:
        # 重复失败下一跳：422 并列出规范化下一跳与其全部出现位置
        raise HTTPException(
            status_code=422,
            detail={"error": "duplicate_next_hops", "duplicates": exc.duplicates},
        ) from exc
    except (InvalidCIDRError, InvalidIPv4AddressError):
        # 正常情况下 pydantic 已在入口拦截，这里兜底转为 422
        raise
