# IPv4 遮蔽分析 API

基于 **Python + FastAPI** 的 IPv4 CIDR 规则遮蔽（shadowing）分析、等价性比较、
包含层级分析与静态路由解析服务。

按输入顺序处理一组有序的 `allow` / `deny` CIDR 规则，计算每条规则
**未被此前任何规则覆盖**的地址集合，并分为：

| 状态 | 值 | 含义 |
| --- | --- | --- |
| 全生效 | `full` | 规则地址均未被此前规则覆盖 |
| 部分遮蔽 | `partial` | 部分地址此前已被覆盖 |
| 完全遮蔽 | `shadowed` | 全部地址此前已被覆盖，规则不产生任何生效地址 |

每条规则的生效（剩余）地址集合会**无损压缩成数量最少的 CIDR 列表**，
并在 `summary` 中汇总生效的 `allow`、`deny` 地址数。

`POST /compare` 还可比较两组规则（各带未命中时的 `default_action`）在
**整个 IPv4 空间**上的最终判定是否等价，并按 left/right 动作分组给出
判定不同的地址集合及其最少 CIDR 表示。

`POST /explain` 则回答反向问题：给定一段 IPv4 地址空间（`query`），
其中每个地址最终由**哪条规则**（首条匹配）或**默认动作**裁决，
并按规则索引升序给出各归属方的地址集合及其最少 CIDR 表示。

`POST /cidrs/hierarchy` 分析 **1～500 个带唯一 id 的 IPv4 CIDR 条目**的
包含层级：为每个网段选择输入中**前缀最长的严格超网**作为唯一 parent
（没有则作为 root），返回按网络地址、前缀长度与输入顺序稳定排列的树；
每个节点给出 `total_addresses`，以及自身范围扣除全部直接子节点并集后的
`exclusive_address_count` 与无损、数量最少的 `exclusive_cidrs`。

`POST /cidrs/diff` 比对 **before / after 两份各 0～500 个带唯一 id 的
IPv4 网段清单**：按 id 匹配后逐条报告新增（`added`）、删除（`removed`）、
CIDR 变更（`cidr_changed`）与未变（`unchanged`），并在各自清单内独立
计算每个网段的**直接父节点**（前缀最长的严格超网），标记父节点变化
（`parent_changed`）；规范化后**网段相同但 id 不同**的前后条目标记为
**替换候选**（`replacement_candidates`）。CIDR 变更条目的受影响地址数
取旧、新网段的**对称差**，新增 / 删除取该网段地址数；结果保持
**before 顺序**，新增项按 **after 顺序**追加。

`POST /routes/resolve` 则是静态路由解析：给定最多 1000 条路由
（`cidr` / `next_hop` / `metric`）与最多 500 个唯一目标 IPv4 地址，对每个
目标先做**最长前缀匹配（LPM）**，再在命中路由中保留**最低 metric** 的全部
等价下一跳（ECMP），按 `routes` 输入顺序去重返回；未命中任何路由的目标标记为
`unreachable`，并汇总每个 `next_hop` 命中的目标数。

`POST /routes/failover` 在 `/routes/resolve` 的基础上模拟**下一跳故障**：
先在完整路由表上解析一次（`before`），再移除 `failed_next_hops` 对应的
**全部路由**并重新执行最长前缀、最低 metric 与 ECMP 选择（`after`）——
不是从原 ECMP 列表中删值，因此允许回退到**更高 metric** 或**更短前缀**。
逐目标返回 `before` / `after` / `impact`（`unchanged` / `ecmp_reduced` /
`rerouted` / `unreachable`），并汇总四类影响的目标数。

> 遮蔽来源不区分动作：先前的 **allow 与 deny 规则取并集**，共同遮蔽后续规则。

---

## 快速开始（Docker Compose 一条命令）

```bash
docker compose up --build -d
```

服务地址与端口：

- **API 基础地址：** http://localhost:8000
- **分析接口：** `POST http://localhost:8000/analyze`
- **比较接口：** `POST http://localhost:8000/compare`
- **解释接口：** `POST http://localhost:8000/explain`
- **层级接口：** `POST http://localhost:8000/cidrs/hierarchy`
- **网段清单差异接口：** `POST http://localhost:8000/cidrs/diff`
- **路由解析接口：** `POST http://localhost:8000/routes/resolve`
- **故障切换接口：** `POST http://localhost:8000/routes/failover`
- **交互式文档（Swagger UI）：** http://localhost:8000/docs
- **OpenAPI Schema：** http://localhost:8000/openapi.json
- **健康检查：** http://localhost:8000/health

如需更换宿主机端口（例如改用 18000）：

```bash
HTTP_PORT=18000 docker compose up --build -d
# 随后访问 http://localhost:18000
```

停止服务：

```bash
docker compose down
```

---

## 接口说明

### `POST /analyze`

#### 请求体

```json
{
  "rules": [
    {"action": "allow", "cidr": "10.0.0.0/8"},
    {"action": "deny",  "cidr": "10.1.0.0/16"},
    {"action": "allow", "cidr": "192.168.0.0/16"},
    {"action": "deny",  "cidr": "10.0.0.0/7"}
  ]
}
```

- `rules`：**有序**规则列表，按数组顺序逐条处理；至少 1 条。
- `action`：仅允许 `allow` / `deny`（大小写不敏感，会规范化为小写）。
- `cidr`：严格 IPv4 CIDR（如 `10.0.0.0/8`、`0.0.0.0/0`）；
  纯 IP 地址按 `/32` 处理；**主机位必须为零**（如 `10.0.0.1/8` 非法）；
  **禁止 IPv6**。

#### 响应示例（200）

```json
{
  "rule_count": 4,
  "rules": [
    {
      "index": 0,
      "action": "allow",
      "cidr": "10.0.0.0/8",
      "status": "full",
      "status_label": "全生效",
      "total_addresses": 16777216,
      "covered_addresses": 0,
      "effective_addresses": 16777216,
      "effective_cidrs": ["10.0.0.0/8"]
    },
    {
      "index": 1,
      "action": "deny",
      "cidr": "10.1.0.0/16",
      "status": "shadowed",
      "status_label": "完全遮蔽",
      "total_addresses": 65536,
      "covered_addresses": 65536,
      "effective_addresses": 0,
      "effective_cidrs": []
    },
    {
      "index": 2,
      "action": "allow",
      "cidr": "192.168.0.0/16",
      "status": "full",
      "status_label": "全生效",
      "total_addresses": 65536,
      "covered_addresses": 0,
      "effective_addresses": 65536,
      "effective_cidrs": ["192.168.0.0/16"]
    },
    {
      "index": 3,
      "action": "deny",
      "cidr": "10.0.0.0/7",
      "status": "partial",
      "status_label": "部分遮蔽",
      "total_addresses": 33554432,
      "covered_addresses": 16777216,
      "effective_addresses": 16777216,
      "effective_cidrs": ["11.0.0.0/8"]
    }
  ],
  "summary": {
    "full": 2,
    "partial": 1,
    "shadowed": 1,
    "effective_allow_addresses": 16842752,
    "effective_deny_addresses": 16777216
  }
}
```

`effective_cidrs` 为生效地址集合的最少 CIDR 表示：碎片会先合并
（首尾相邻也合并），再用贪心取最大对齐 2 的幂分块，保证**块数最少且无损**。

#### curl 示例

```bash
curl -s http://localhost:8000/analyze \
  -H 'Content-Type: application/json' \
  -d '{"rules":[{"action":"allow","cidr":"0.0.0.0/0"},{"action":"deny","cidr":"8.8.8.8/32"}]}'
```

---

### `POST /compare`

比较两组有序 allow/deny 规则在**整个 IPv4 空间**（`0.0.0.0/0`）上的最终
判定是否等价。两侧各自独立，均沿用 `/analyze` 的 CIDR 校验与
**首条匹配规则生效**的顺序语义；未命中任何规则的地址取该侧的
`default_action`。

#### 请求体

```json
{
  "left": {
    "rules": [
      {"action": "allow", "cidr": "10.0.0.0/8"},
      {"action": "deny",  "cidr": "10.1.0.0/16"}
    ],
    "default_action": "deny"
  },
  "right": {
    "rules": [
      {"action": "deny",  "cidr": "10.1.0.0/16"},
      {"action": "allow", "cidr": "10.0.0.0/8"}
    ],
    "default_action": "deny"
  }
}
```

- `left` / `right`：两侧规则集，结构相同。
  - `rules`：**有序**规则列表（按数组顺序逐条处理），**允许为空** `[]`；
    为空时该侧所有地址都走默认动作。
  - `default_action`：**必填**，未命中任何规则时的最终动作，仅允许
    `allow` / `deny`（大小写不敏感，会规范化为小写）。
- `rules` 内每条规则的 `action` / `cidr` 校验规则与 `/analyze` 完全一致
  （严格 IPv4 CIDR、纯 IP 按 `/32`、主机位必须为零、禁止 IPv6）。

#### 响应字段

| 字段 | 说明 |
| --- | --- |
| `equivalent` | 两侧在整个 IPv4 空间上的最终判定是否完全一致；为 `true` 时 `differences` 为空 |
| `differences[]` | 判定不同的地址分组，按 `left_action`、`right_action` 组合聚合，最多 2 组 |
| `differences[].left_action` / `.right_action` | 该组地址在左侧 / 右侧的最终动作 |
| `differences[].address_count` | 该组覆盖的地址数（各组之和 ≤ 2³²） |
| `differences[].cidrs` | 该组地址集合**无损压缩后的最少 CIDR 列表** |

分组按 `(left_action, right_action)` 字典序返回：
`(allow, deny)` 在前，`(deny, allow)` 在后。整个比较基于整数区间归并
计算，**不会逐地址枚举 IPv4 空间**。

#### 响应示例（200，不等价）

上例中 `10.1.0.0/16` 左侧先命中 `allow 10.0.0.0/8`，右侧先命中
`deny 10.1.0.0/16`，因此仅这一个 `/16` 的判定不同：

```json
{
  "equivalent": false,
  "differences": [
    {
      "left_action": "allow",
      "right_action": "deny",
      "address_count": 65536,
      "cidrs": ["10.1.0.0/16"]
    }
  ]
}
```

#### 响应示例（200，完全等价）

被此前规则**完全遮蔽**的规则不影响最终判定；`default_action` 大小写不敏感：

请求：

```json
{
  "left": {
    "rules": [{"action": "allow", "cidr": "10.0.0.0/8"}],
    "default_action": "deny"
  },
  "right": {
    "rules": [
      {"action": "allow", "cidr": "10.0.0.0/8"},
      {"action": "deny",  "cidr": "10.1.0.0/16"}
    ],
    "default_action": "DENY"
  }
}
```

响应：

```json
{
  "equivalent": true,
  "differences": []
}
```

#### 默认动作导致的全空间差异

左侧仅放行 `10.0.0.0/8`、其余默认 `deny`；右侧无规则、默认 `allow`。
除 `10.0.0.0/8` 外的全部地址构成一个 `deny → allow` 组，被压缩为
8 个 CIDR（地址计数 4294967296 − 16777216 = 4278190080）：

请求：

```json
{
  "left": {
    "rules": [{"action": "allow", "cidr": "10.0.0.0/8"}],
    "default_action": "deny"
  },
  "right": {
    "rules": [],
    "default_action": "allow"
  }
}
```

响应：

```json
{
  "equivalent": false,
  "differences": [
    {
      "left_action": "deny",
      "right_action": "allow",
      "address_count": 4278190080,
      "cidrs": [
        "0.0.0.0/5",
        "8.0.0.0/7",
        "11.0.0.0/8",
        "12.0.0.0/6",
        "16.0.0.0/4",
        "32.0.0.0/3",
        "64.0.0.0/2",
        "128.0.0.0/1"
      ]
    }
  ]
}
```

#### curl 示例

```bash
curl -s http://localhost:8000/compare \
  -H 'Content-Type: application/json' \
  -d '{
    "left":  {"rules":[{"action":"allow","cidr":"10.0.0.0/8"}], "default_action":"deny"},
    "right": {"rules": [],                                        "default_action":"allow"}
  }'
```

---

### `POST /explain`

解释一段 IPv4 地址空间（`query`）最终由**哪条规则或默认动作**裁决。
沿用 `/analyze` 的 CIDR 校验与**首条匹配规则生效**的顺序语义，
但只在 `query` 范围内归因：query 中的每个地址归属于首条命中它的规则；
未命中任何规则的部分归于 `default_action`。

#### 请求体

```json
{
  "rules": [
    {"action": "allow", "cidr": "10.0.0.0/16"},
    {"action": "deny",  "cidr": "10.0.1.0/24"},
    {"action": "deny",  "cidr": "10.2.0.0/16"}
  ],
  "default_action": "deny",
  "query": "10.0.0.0/8"
}
```

- `rules`：**有序**规则列表（按数组顺序逐条处理），**允许为空** `[]`；
  为空时整个 query 都走默认动作。每条规则的 `action` / `cidr` 校验规则
  与 `/analyze` 完全一致。
- `default_action`：**必填**，未命中任何规则时的最终动作，仅允许
  `allow` / `deny`（大小写不敏感，会规范化为小写）。
- `query`：**必填**，单个严格 IPv4 CIDR；纯 IP 按 `/32` 处理；
  主机位必须为零；禁止 IPv6。

#### 响应字段

| 字段 | 说明 |
| --- | --- |
| `query` | 规范化后的 query CIDR（纯 IP 规范化为 `/32`） |
| `total_addresses` | query 覆盖的地址总数 |
| `attribution[]` | 归因列表，**按规则索引升序、默认项最后**；所有项**不重不漏**覆盖整个 query |
| `attribution[].source` | `rule`（命中规则）或 `default`（走默认动作） |
| `attribution[].rule_index` | 命中规则在输入中的序号（从 0 开始）；默认项为 `null` |
| `attribution[].action` | 该项地址的最终动作 |
| `attribution[].address_count` | 该项覆盖的地址数（各项之和 = `total_addresses`） |
| `attribution[].cidrs` | 该项地址集合**无损压缩后的最少 CIDR 列表** |

在 query 范围内被此前规则完全遮蔽、或与 query 不相交的规则不会产生
归因项；若规则已完整覆盖 query，则不出现默认项。

#### 响应示例（200）

上例中 `deny 10.0.1.0/24` 被规则 0 完全遮蔽（不出现）；`10.0.0.0/16`
归规则 0、`10.2.0.0/16` 归规则 2，其余地址走默认动作 `deny`：

```json
{
  "query": "10.0.0.0/8",
  "total_addresses": 16777216,
  "attribution": [
    {
      "source": "rule",
      "rule_index": 0,
      "action": "allow",
      "address_count": 65536,
      "cidrs": ["10.0.0.0/16"]
    },
    {
      "source": "rule",
      "rule_index": 2,
      "action": "deny",
      "address_count": 65536,
      "cidrs": ["10.2.0.0/16"]
    },
    {
      "source": "default",
      "rule_index": null,
      "action": "deny",
      "address_count": 16646144,
      "cidrs": [
        "10.1.0.0/16",
        "10.3.0.0/16",
        "10.4.0.0/14",
        "10.8.0.0/13",
        "10.16.0.0/12",
        "10.32.0.0/11",
        "10.64.0.0/10",
        "10.128.0.0/9"
      ]
    }
  ]
}
```

#### curl 示例

```bash
curl -s http://localhost:8000/explain \
  -H 'Content-Type: application/json' \
  -d '{
    "rules": [{"action":"allow","cidr":"10.0.0.0/16"}],
    "default_action": "deny",
    "query": "10.0.0.0/8"
  }'
```

---

### `POST /cidrs/hierarchy`

分析 **1～500 个带唯一 `id` 的 IPv4 CIDR 条目**的包含层级。

- 对每个网段，选择输入中**前缀最长的严格超网**（strict supernet）作为它的
  **唯一 parent**；不存在严格超网的网段作为 **root**。
- 每个节点给出：
  - `total_addresses`：本网段覆盖的地址总数；
  - `exclusive_address_count`：自身范围扣除**全部直接子节点**并集后的
    独占地址数（孙节点不重复扣除）；
  - `exclusive_cidrs`：该独占地址集合**无损压缩、数量最少**的 CIDR 列表
    （无子节点时就是网段自身）。
- 树（森林）按 **网络地址升序 → 前缀长度升序 → 输入顺序** 稳定排列
  （先根遍历的兄弟顺序）。
- `id` 必须在全请求内唯一（字符串或整数）；**规范化后网络相同**的条目
  （如 `10.0.0.0/8` 与 `10.0.0.0/08`）返回 **422** 并列出冲突 id。
- CIDR 校验与其他接口完全一致：严格 IPv4、纯 IP 按 `/32`、主机位必须为零、
  禁止 IPv6。基于整数区间运算，**不逐地址枚举**。

#### 请求体

```json
{
  "entries": [
    {"id": "net",   "cidr": "10.0.0.0/8"},
    {"id": "sub",   "cidr": "10.1.0.0/16"},
    {"id": "host1", "cidr": "10.1.0.1/32"},
    {"id": "host2", "cidr": "10.1.0.2/32"},
    {"id": "dns",   "cidr": "8.8.8.8"}
  ]
}
```

- `entries`：**必填**，1～500 个条目。
- `id`：非空字符串或整数，全请求内唯一；不接受 `true` / `1.5` 等其他类型，
  不做隐式类型转换。
- `cidr`：严格 IPv4 CIDR；纯 IP 按 `/32` 处理；主机位必须为零；禁止 IPv6。

#### 响应字段

| 字段 | 说明 |
| --- | --- |
| `node_count` | 节点（条目）总数 |
| `root_count` | 根节点数量 |
| `roots[]` | 根节点组成的森林，按网络地址、前缀长度、输入顺序稳定排序 |
| `roots[].id` / `.cidr` | 节点 id 与规范化后的 CIDR |
| `roots[].parent_id` | 唯一父节点 id（前缀最长的严格超网）；根节点为 `null` |
| `roots[].total_addresses` | 本网段覆盖的地址总数（2^(32−前缀长度)） |
| `roots[].exclusive_address_count` | 自身范围扣除全部直接子节点并集后的地址数 |
| `roots[].exclusive_cidrs` | 独占地址集合**无损压缩后的最少 CIDR 列表** |
| `roots[].children[]` | 直接子节点（递归同构），排序规则与 `roots` 相同 |

#### 响应示例（200）

上例中 `host1` / `host2` 的 parent 是前缀最长的严格超网 `sub`（`/16`），
而非 `net`（`/8`）；`sub` 的独占范围要扣除这两个直接子节点，`net` 只扣除
它的直接子节点 `sub`（孙节点不重复扣除）。`dns`（`8.8.8.8/32`）与
`10.0.0.0/8` 不相交，是另一个 root；根按网络地址升序排列：

```json
{
  "node_count": 5,
  "root_count": 2,
  "roots": [
    {
      "id": "dns",
      "cidr": "8.8.8.8/32",
      "parent_id": null,
      "total_addresses": 1,
      "exclusive_address_count": 1,
      "exclusive_cidrs": ["8.8.8.8/32"],
      "children": []
    },
    {
      "id": "net",
      "cidr": "10.0.0.0/8",
      "parent_id": null,
      "total_addresses": 16777216,
      "exclusive_address_count": 16711680,
      "exclusive_cidrs": [
        "10.0.0.0/16",
        "10.2.0.0/15",
        "10.4.0.0/14",
        "10.8.0.0/13",
        "10.16.0.0/12",
        "10.32.0.0/11",
        "10.64.0.0/10",
        "10.128.0.0/9"
      ],
      "children": [
        {
          "id": "sub",
          "cidr": "10.1.0.0/16",
          "parent_id": "net",
          "total_addresses": 65536,
          "exclusive_address_count": 65534,
          "exclusive_cidrs": [
            "10.1.0.0/32",
            "10.1.0.3/32",
            "10.1.0.4/30",
            "10.1.0.8/29",
            "10.1.0.16/28",
            "10.1.0.32/27",
            "10.1.0.64/26",
            "10.1.0.128/25",
            "10.1.1.0/24",
            "10.1.2.0/23",
            "10.1.4.0/22",
            "10.1.8.0/21",
            "10.1.16.0/20",
            "10.1.32.0/19",
            "10.1.64.0/18",
            "10.1.128.0/17"
          ],
          "children": [
            {
              "id": "host1",
              "cidr": "10.1.0.1/32",
              "parent_id": "sub",
              "total_addresses": 1,
              "exclusive_address_count": 1,
              "exclusive_cidrs": ["10.1.0.1/32"],
              "children": []
            },
            {
              "id": "host2",
              "cidr": "10.1.0.2/32",
              "parent_id": "sub",
              "total_addresses": 1,
              "exclusive_address_count": 1,
              "exclusive_cidrs": ["10.1.0.2/32"],
              "children": []
            }
          ]
        }
      ]
    }
  ]
}
```

#### 错误示例（422，规范化后网络重复）

请求中 `b` 与 `a` 规范化后指向同一网络，返回 422 并在
`duplicate_networks[].entries` 中列出冲突条目（含冲突 id）：

```json
{
  "detail": {
    "error": "duplicate_entries",
    "duplicate_ids": [],
    "duplicate_networks": [
      {
        "cidr": "10.0.0.0/8",
        "entries": [
          {"index": 0, "id": "a", "cidr": "10.0.0.0/8"},
          {"index": 1, "id": "b", "cidr": "10.0.0.0/8"}
        ]
      }
    ]
  }
}
```

`id` 重复时，冲突位置列在 `duplicate_ids`（每项含 `id` 与全部出现位置
`indexes`）；两类问题可能同时出现。

#### curl 示例

```bash
curl -s http://localhost:8000/cidrs/hierarchy \
  -H 'Content-Type: application/json' \
  -d '{"entries":[{"id":"net","cidr":"10.0.0.0/8"},{"id":"sub","cidr":"10.1.0.0/16"},{"id":"host","cidr":"10.1.1.1"}]}'
```

---

### `POST /cidrs/diff`

比对 **before / after 两份带唯一 id 的 IPv4 网段清单**，回答“这批网段从
旧清单到新清单发生了什么变化”。

1. 两侧条目先做严格 IPv4 校验与规范化（纯 IP 按 `/32`），并分别检查
   **id 唯一**与**规范化后网段唯一**；
2. 按 **id** 匹配两侧条目，分为 `added` / `removed` / `cidr_changed` /
   `unchanged` 四类；
3. 每个条目的**直接父节点**（清单内前缀最长的严格超网，规则与
   `/cidrs/hierarchy` 相同）在**各自清单内独立**计算；同 id 匹配上的
   条目比较前后父节点，变化时 `parent_changed = true`（可与
   `cidr_changed` 同时成立）；新增 / 删除项两侧只有一侧有父节点，
   `parent_changed` 为 `null`；
4. 规范化后**网段相同但 id 不同**的前后条目两两配对（两侧网段各自唯一，
   每个网段至多一对），列入 `replacement_candidates`，提示“同网段换 id”
   的替换关系；
5. 受影响地址数 `affected_address_count`：
   - `cidr_changed`：旧、新网段的**对称差**（`|旧 △ 新| = |旧| + |新| − 2×|交集|`），
     网段缩小取差值、扩张取增量、互不相交取两者之和；
   - `added` / `removed`：该网段自身地址数；
   - `unchanged`：`0`（父节点变化不改变地址集合）。

- `before` / `after`：**各 0～500 个**条目，**允许两侧或任一侧为空** `[]`；
  条目的 `id` / `cidr` 校验与 `/cidrs/hierarchy` 完全一致
  （id 为非空字符串或整数；严格 IPv4 CIDR、纯 IP 按 `/32`、主机位必须为
  零、禁止 IPv6）。
- 排序：`changes` **保持 before 顺序**（删除项与同 id 匹配项按 before
  出现位置排列），**新增项按 after 顺序追加**；`replacement_candidates`
  按 before 侧位置排序。
- 任一侧 id 或规范化网段重复时返回 **422**，两侧重复问题在同一次响应中
  分别列出、**不产生任何部分结果**。基于整数区间运算，**不逐地址枚举**。

#### 请求体

```json
{
  "before": [
    {"id": "net",     "cidr": "10.0.0.0/8"},
    {"id": "sub-a",   "cidr": "10.1.0.0/16"},
    {"id": "sub-b",   "cidr": "10.2.0.0/16"},
    {"id": "old-dns", "cidr": "8.8.8.8/32"}
  ],
  "after": [
    {"id": "net",     "cidr": "10.0.0.0/8"},
    {"id": "sub-a",   "cidr": "10.1.0.0/24"},
    {"id": "sub-c",   "cidr": "10.2.0.0/16"},
    {"id": "new-dns", "cidr": "8.8.8.8/32"}
  ]
}
```

#### 响应字段

| 字段 | 说明 |
| --- | --- |
| `before_count` / `after_count` | before / after 侧条目数 |
| `changes[]` | 逐条变化结果：保持 before 顺序（删除 / 匹配项），新增项按 after 顺序追加 |
| `changes[].id` | 条目 id（两侧共有或仅一侧存在） |
| `changes[].change` | `added` / `removed` / `cidr_changed` / `unchanged` |
| `changes[].before_cidr` / `.after_cidr` | before / after 侧规范化网段；缺失侧为 `null` |
| `changes[].before_parent_id` / `.after_parent_id` | 各自清单内的直接父节点 id（root 为 `null`）；缺失侧为 `null` |
| `changes[].parent_changed` | 同 id 匹配项的直接父节点是否变化；新增 / 删除项为 `null` |
| `changes[].affected_address_count` | 受影响地址数：CIDR 变更取旧新对称差，新增 / 删除取该网段地址数，其余为 0 |
| `replacement_candidates[]` | 规范化后网段相同但 id 不同的配对：`before_id` / `after_id` / `cidr` / `address_count`，按 before 侧位置排序 |
| `summary.added` / `.removed` / `.cidr_changed` / `.unchanged` | 四类变化各自的条目数（四类之和 = `before_count + added`） |
| `summary.parent_changed` | 同 id 匹配且父节点变化的条目数（可与 `cidr_changed` 重叠） |
| `summary.replacement_candidate_count` | 替换候选配对数 |
| `summary.affected_address_count` | 全部新增、删除与 CIDR 变更条目的受影响地址数之和 |

#### 响应示例（200）

上例中：`net` 未变；`sub-a` 由 `/16` 缩成 `/24`（对称差
65536 − 256 = 65280）；`sub-b` 被删除、`sub-c` 为新增，二者网段同为
`10.2.0.0/16` 但 id 不同，构成替换候选；`old-dns` / `new-dns` 同理
（同一个 `/32` 换了 id）：

```json
{
  "before_count": 4,
  "after_count": 4,
  "changes": [
    {
      "id": "net",
      "change": "unchanged",
      "before_cidr": "10.0.0.0/8",
      "after_cidr": "10.0.0.0/8",
      "before_parent_id": null,
      "after_parent_id": null,
      "parent_changed": false,
      "affected_address_count": 0
    },
    {
      "id": "sub-a",
      "change": "cidr_changed",
      "before_cidr": "10.1.0.0/16",
      "after_cidr": "10.1.0.0/24",
      "before_parent_id": "net",
      "after_parent_id": "net",
      "parent_changed": false,
      "affected_address_count": 65280
    },
    {
      "id": "sub-b",
      "change": "removed",
      "before_cidr": "10.2.0.0/16",
      "after_cidr": null,
      "before_parent_id": "net",
      "after_parent_id": null,
      "parent_changed": null,
      "affected_address_count": 65536
    },
    {
      "id": "old-dns",
      "change": "removed",
      "before_cidr": "8.8.8.8/32",
      "after_cidr": null,
      "before_parent_id": null,
      "after_parent_id": null,
      "parent_changed": null,
      "affected_address_count": 1
    },
    {
      "id": "sub-c",
      "change": "added",
      "before_cidr": null,
      "after_cidr": "10.2.0.0/16",
      "before_parent_id": null,
      "after_parent_id": "net",
      "parent_changed": null,
      "affected_address_count": 65536
    },
    {
      "id": "new-dns",
      "change": "added",
      "before_cidr": null,
      "after_cidr": "8.8.8.8/32",
      "before_parent_id": null,
      "after_parent_id": null,
      "parent_changed": null,
      "affected_address_count": 1
    }
  ],
  "replacement_candidates": [
    {"before_id": "sub-b", "after_id": "sub-c", "cidr": "10.2.0.0/16", "address_count": 65536},
    {"before_id": "old-dns", "after_id": "new-dns", "cidr": "8.8.8.8/32", "address_count": 1}
  ],
  "summary": {
    "added": 2,
    "removed": 2,
    "cidr_changed": 1,
    "unchanged": 1,
    "parent_changed": 0,
    "replacement_candidate_count": 2,
    "affected_address_count": 196354
  }
}
```

父节点变化与 CIDR 变更可同时发生：例如删掉中间层 `10.1.0.0/16` 后，
`host`（`10.1.0.1/32`）网段未变（`change = "unchanged"`），但直接父节点
由 `sub` 变为 `net`，其 `parent_changed` 为 `true` 且
`affected_address_count` 为 `0`；若同时修改 `host` 的网段，则该条目
`change = "cidr_changed"`、`parent_changed = true`，受影响地址数仍按
旧新网段对称差计算（两个不相交 `/32` 时为 2）。

#### 错误示例（422，两侧重复一次性报告）

任一侧 id 或规范化网段重复均返回 422，`detail.before` / `detail.after`
分别给出该侧的 `duplicate_ids` / `duplicate_networks`（结构同
`/cidrs/hierarchy`，无问题一侧为空结构），**不产生部分结果**。下例中
before 侧 id `x` 重复，after 侧 `y` 与 `z` 规范化后网段相同：

```json
{
  "detail": {
    "error": "duplicate_entries",
    "before": {
      "duplicate_ids": [
        {"id": "x", "indexes": [0, 1]}
      ],
      "duplicate_networks": []
    },
    "after": {
      "duplicate_ids": [],
      "duplicate_networks": [
        {
          "cidr": "10.0.0.0/8",
          "entries": [
            {"index": 0, "id": "y", "cidr": "10.0.0.0/8"},
            {"index": 1, "id": "z", "cidr": "10.0.0.0/8"}
          ]
        }
      ]
    }
  }
}
```

#### curl 示例

```bash
curl -s http://localhost:8000/cidrs/diff \
  -H 'Content-Type: application/json' \
  -d '{
    "before": [{"id":"a","cidr":"10.0.0.0/8"},{"id":"b","cidr":"8.8.8.8"}],
    "after":  [{"id":"a","cidr":"10.0.0.0/8"},{"id":"c","cidr":"9.9.9.9"}]
  }'
```

---

### `POST /routes/resolve`

对一组唯一目标 IPv4 地址做静态路由解析。解析规则：

1. **最长前缀匹配（LPM）**：在所有覆盖目标的路由中只保留前缀长度最大者；
2. **最低 metric**：在 LPM 集合中再保留 metric 最小的**全部**路由，它们构成
   等价多路径（ECMP）结果；
3. ECMP 的 `next_hop` 按 **routes 输入顺序去重**后返回；
4. 未命中任何路由的目标标记为 `unreachable`。

- `routes`：**0～1000 条**路由（允许为空 `[]`，此时所有目标均不可达）。
  - `cidr`：严格 IPv4 CIDR，校验与其他接口完全一致（纯 IP 按 `/32`、
    主机位必须为零、禁止 IPv6）；
  - `next_hop`：严格 **IPv4 地址**（纯地址，不允许 `10.0.0.1/32` 这类
    CIDR 写法，禁止前导零与 IPv6）；
  - `metric`：**0～65535** 的整数（不接受 `true`、`1.5` 等）。
- `targets`：**1～500 个**唯一目标 IPv4 地址（纯地址，校验同 `next_hop`）；
  重复时返回 **422** 并在 `detail.duplicates` 中列出冲突位置。
- `results` **严格保持 targets 输入顺序**；`summary.next_hop_counts` 汇总每个
  next_hop 命中的**目标数**——同一 ECMP 结果中的各下一跳**分别计数一次**，
  仅列出实际命中过的下一跳，按其在 `routes` 中的首次出现位置排序。

全程只做 32 位整数比较，**不逐地址展开网段**，可安全处理 `0.0.0.0/0`。

#### 请求体

```json
{
  "routes": [
    {"cidr": "0.0.0.0/0",   "next_hop": "192.0.2.254", "metric": 100},
    {"cidr": "10.0.0.0/8",  "next_hop": "10.0.0.254",  "metric": 50},
    {"cidr": "10.0.0.0/8",  "next_hop": "10.0.0.1",    "metric": 20},
    {"cidr": "10.0.0.0/8",  "next_hop": "10.0.0.2",    "metric": 20},
    {"cidr": "10.0.0.0/8",  "next_hop": "10.0.0.1",    "metric": 20},
    {"cidr": "10.1.0.0/16", "next_hop": "10.1.0.1",    "metric": 60},
    {"cidr": "10.1.0.0/16", "next_hop": "10.1.0.2",    "metric": 60}
  ],
  "targets": ["10.1.0.5", "10.2.2.2", "8.8.8.8", "172.16.0.1"]
}
```

#### 响应字段

| 字段 | 说明 |
| --- | --- |
| `route_count` / `target_count` | 请求中的路由条数 / 目标数 |
| `results[]` | 逐目标解析结果，**严格保持 targets 输入顺序** |
| `results[].target` | 规范化后的目标 IPv4 地址 |
| `results[].status` | `reachable` 或 `unreachable` |
| `results[].matched_cidr` | 命中的最长前缀 CIDR（ECMP 路由的共同网段）；不可达为 `null` |
| `results[].metric` | 命中路由的最低 metric；不可达为 `null` |
| `results[].next_hops` | 等价下一跳，按 routes 输入顺序去重；不可达为 `[]` |
| `summary.reachable_count` / `.unreachable_count` | 可达 / 不可达目标数 |
| `summary.next_hop_counts[]` | 每个 next_hop 命中的目标数（ECMP 各下一跳分别计数），按 routes 首次出现位置排序 |

#### 响应示例（200）

上例中：`10.1.0.5` 走最长前缀 `/16`（两个 metric 60 的等价下一跳）；
`10.2.2.2` 命中 `/8`，metric 50 的下一跳被最低 metric 20 的两个等价下一跳
淘汰，重复的 `10.0.0.1` 只保留一次；`8.8.8.8` 与 `172.16.0.1` 走默认路由：

```json
{
  "route_count": 7,
  "target_count": 4,
  "results": [
    {
      "target": "10.1.0.5",
      "status": "reachable",
      "matched_cidr": "10.1.0.0/16",
      "metric": 60,
      "next_hops": ["10.1.0.1", "10.1.0.2"]
    },
    {
      "target": "10.2.2.2",
      "status": "reachable",
      "matched_cidr": "10.0.0.0/8",
      "metric": 20,
      "next_hops": ["10.0.0.1", "10.0.0.2"]
    },
    {
      "target": "8.8.8.8",
      "status": "reachable",
      "matched_cidr": "0.0.0.0/0",
      "metric": 100,
      "next_hops": ["192.0.2.254"]
    },
    {
      "target": "172.16.0.1",
      "status": "reachable",
      "matched_cidr": "0.0.0.0/0",
      "metric": 100,
      "next_hops": ["192.0.2.254"]
    }
  ],
  "summary": {
    "reachable_count": 4,
    "unreachable_count": 0,
    "next_hop_counts": [
      {"next_hop": "192.0.2.254", "target_count": 2},
      {"next_hop": "10.0.0.1", "target_count": 1},
      {"next_hop": "10.0.0.2", "target_count": 1},
      {"next_hop": "10.1.0.1", "target_count": 1},
      {"next_hop": "10.1.0.2", "target_count": 1}
    ]
  }
}
```

未命中任何路由的目标对应：

```json
{
  "target": "8.8.8.8",
  "status": "unreachable",
  "matched_cidr": null,
  "metric": null,
  "next_hops": []
}
```

#### 错误示例（422，目标重复）

```json
{
  "detail": {
    "error": "duplicate_targets",
    "duplicates": [
      {"target": "8.8.8.8", "indexes": [0, 2]}
    ]
  }
}
```

#### curl 示例

```bash
curl -s http://localhost:8000/routes/resolve \
  -H 'Content-Type: application/json' \
  -d '{
    "routes": [
      {"cidr": "0.0.0.0/0", "next_hop": "192.0.2.254", "metric": 100},
      {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.1", "metric": 20},
      {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.2", "metric": 20}
    ],
    "targets": ["10.0.0.9", "8.8.8.8"]
  }'
```

---

### `POST /routes/failover`

模拟一组下一跳失效后的路由切换影响。处理流程：

1. 先在完整路由表上按 `/routes/resolve` 语义解析一次（`before`）；
2. 移除 `failed_next_hops` 对应的**全部路由**（同一失败下一跳出现在多条
   路由中时全部移除），**重新执行**最长前缀、最低 metric 与 ECMP 选择
   （`after`）——**不是**从原 ECMP 列表中删值，因此允许回退到
   **更高 metric** 或**更短前缀**；
3. 逐目标比较前后结果并归类 `impact`，`summary` 汇总四类数量。

- `routes` / `targets`：与 `/routes/resolve` 完全一致（路由 0～1000 条、
  目标 1～500 个且唯一，校验规则相同）。
- `failed_next_hops`：**0～1000 个**唯一失败下一跳 IPv4 地址（纯地址，
  校验同 `next_hop`），允许为空 `[]`（此时所有目标均为 `unchanged`）；
  重复时返回 **422** 并在 `detail.duplicates` 中列出冲突位置。
- `results` **严格保持 targets 输入顺序**。

`impact` 分类：

| 值 | 含义 |
| --- | --- |
| `unchanged` | 解析结果完全不变（含两侧均不可达） |
| `ecmp_reduced` | 命中网段与 metric 不变，等价下一跳减少（after 是 before 的严格子集） |
| `rerouted` | 仍可达但命中网段或 metric 改变（回退到更短前缀或更高 metric） |
| `unreachable` | 原本可达、故障后不可达 |

#### 请求体

```json
{
  "routes": [
    {"cidr": "0.0.0.0/0",   "next_hop": "192.0.2.254", "metric": 100},
    {"cidr": "10.0.0.0/8",  "next_hop": "10.0.0.1",    "metric": 10},
    {"cidr": "10.0.0.0/8",  "next_hop": "10.0.0.2",    "metric": 10},
    {"cidr": "10.1.0.0/16", "next_hop": "10.1.0.1",    "metric": 5},
    {"cidr": "11.0.0.0/8",  "next_hop": "11.0.0.1",    "metric": 7}
  ],
  "targets": ["10.0.9.9", "10.1.0.9", "11.0.0.9", "8.8.8.8"],
  "failed_next_hops": ["10.0.0.2", "10.1.0.1", "11.0.0.1"]
}
```

#### 响应字段

| 字段 | 说明 |
| --- | --- |
| `route_count` / `target_count` | 请求中的路由条数 / 目标数 |
| `failed_next_hops` | 规范化后的失败下一跳列表，保持输入顺序 |
| `results[]` | 逐目标故障切换结果，**严格保持 targets 输入顺序** |
| `results[].target` | 规范化后的目标 IPv4 地址 |
| `results[].before` / `.after` | 故障前 / 后的解析结果，结构同 `/routes/resolve` 的单目标结果（`status` / `matched_cidr` / `metric` / `next_hops`） |
| `results[].impact` | 影响分类：`unchanged` / `ecmp_reduced` / `rerouted` / `unreachable` |
| `summary.unchanged` / `.ecmp_reduced` / `.rerouted` / `.unreachable` | 四类影响各自的目标数（总和 = `target_count`） |

#### 响应示例（200）

上例中：`10.0.9.9` 的 ECMP 少了一个下一跳（`ecmp_reduced`）；`10.1.0.9`
的 `/16` 路由失效，回退到更短前缀 `/8`（`rerouted`）；`11.0.0.9` 的唯一
路由失效，回退到默认路由 `0.0.0.0/0`（`rerouted`）；`8.8.8.8` 不受影响
（`unchanged`）：

```json
{
  "route_count": 5,
  "target_count": 4,
  "failed_next_hops": ["10.0.0.2", "10.1.0.1", "11.0.0.1"],
  "results": [
    {
      "target": "10.0.9.9",
      "before": {
        "status": "reachable",
        "matched_cidr": "10.0.0.0/8",
        "metric": 10,
        "next_hops": ["10.0.0.1", "10.0.0.2"]
      },
      "after": {
        "status": "reachable",
        "matched_cidr": "10.0.0.0/8",
        "metric": 10,
        "next_hops": ["10.0.0.1"]
      },
      "impact": "ecmp_reduced"
    },
    {
      "target": "10.1.0.9",
      "before": {
        "status": "reachable",
        "matched_cidr": "10.1.0.0/16",
        "metric": 5,
        "next_hops": ["10.1.0.1"]
      },
      "after": {
        "status": "reachable",
        "matched_cidr": "10.0.0.0/8",
        "metric": 10,
        "next_hops": ["10.0.0.1"]
      },
      "impact": "rerouted"
    },
    {
      "target": "11.0.0.9",
      "before": {
        "status": "reachable",
        "matched_cidr": "11.0.0.0/8",
        "metric": 7,
        "next_hops": ["11.0.0.1"]
      },
      "after": {
        "status": "reachable",
        "matched_cidr": "0.0.0.0/0",
        "metric": 100,
        "next_hops": ["192.0.2.254"]
      },
      "impact": "rerouted"
    },
    {
      "target": "8.8.8.8",
      "before": {
        "status": "reachable",
        "matched_cidr": "0.0.0.0/0",
        "metric": 100,
        "next_hops": ["192.0.2.254"]
      },
      "after": {
        "status": "reachable",
        "matched_cidr": "0.0.0.0/0",
        "metric": 100,
        "next_hops": ["192.0.2.254"]
      },
      "impact": "unchanged"
    }
  ],
  "summary": {
    "unchanged": 1,
    "ecmp_reduced": 1,
    "rerouted": 2,
    "unreachable": 0
  }
}
```

若失败下一跳是某目标的唯一可达路径，`after` 为不可达：

```json
{
  "target": "11.0.0.9",
  "before": {
    "status": "reachable",
    "matched_cidr": "11.0.0.0/8",
    "metric": 7,
    "next_hops": ["11.0.0.1"]
  },
  "after": {
    "status": "unreachable",
    "matched_cidr": null,
    "metric": null,
    "next_hops": []
  },
  "impact": "unreachable"
}
```

#### 错误示例（422，失败下一跳重复）

```json
{
  "detail": {
    "error": "duplicate_next_hops",
    "duplicates": [
      {"next_hop": "1.1.1.1", "indexes": [0, 2]}
    ]
  }
}
```

#### curl 示例

```bash
curl -s http://localhost:8000/routes/failover \
  -H 'Content-Type: application/json' \
  -d '{
    "routes": [
      {"cidr": "0.0.0.0/0", "next_hop": "192.0.2.254", "metric": 100},
      {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.1", "metric": 20},
      {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.2", "metric": 20}
    ],
    "targets": ["10.0.0.9", "8.8.8.8"],
    "failed_next_hops": ["10.0.0.1"]
  }'
```

### 错误响应（422 Unprocessable Entity）

以下输入均返回 HTTP `422`，错误明细位于 `detail`：

- 空规则集（仅 `/analyze`）：`{"rules": []}` 或缺少 `rules`
- `/compare` 缺少 `left` / `right`，或任一侧缺少 `default_action`
- `/explain` 缺少 `query` 或 `default_action`
- `/cidrs/hierarchy` 缺少 `entries`、条目数不在 1～500、`id` 缺失/为空/
  类型非法（如 `true`、`1.5`）、**`id` 重复**或**规范化后网段重复**
  （后两者在 `detail.duplicate_ids` / `detail.duplicate_networks` 中列出
  冲突 id 与位置）
- `/cidrs/diff` 缺少 `before` / `after`、任一侧条目数超过 500、任一侧
  **`id` 重复**或**规范化后网段重复**：422 明细在
  `detail.before.duplicate_ids` / `detail.before.duplicate_networks` 与
  `detail.after.duplicate_ids` / `detail.after.duplicate_networks` 中**两侧
  分别列出**（无问题一侧为空结构），不产生部分结果；条目字段校验同
  `/cidrs/hierarchy`（两侧均允许为空 `[]`）
- `/routes/resolve` 缺少 `routes` / `targets`、路由数超过 1000、目标数不在
  1～500、**目标地址重复**（在 `detail.duplicates` 中列出规范化目标及全部
  出现位置 `indexes`）、`next_hop` / `targets` 不是严格 IPv4 地址
  （CIDR 写法、前导零、IPv6 等）、`metric` 不在 0～65535 或不是整数
- `/routes/failover` 除沿用 `/routes/resolve` 的全部校验外，还要求
  `failed_next_hops` 为 0～1000 个**唯一**的严格 IPv4 地址，重复时在
  `detail.duplicates` 中列出规范化下一跳及全部出现位置 `indexes`
- 非法 CIDR：格式错误、前缀越界（`/33`）、主机位非零（`10.0.0.1/8`）等
- IPv6 地址或网段：`2001:db8::/32`、`::1` 等
- 非法 / 缺失 `action` 或 `default_action`、字段类型错误、JSON 格式错误

---

## 本地开发（不使用 Docker）

需要 Python 3.11+。

```bash
pip install -r requirements-dev.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

运行测试：

```bash
pytest -q
```

测试覆盖：解析校验（含 IPv6 拒绝）、区间差集与合并、最少 CIDR 压缩、
三种遮蔽分类、跨动作遮蔽、顺序敏感性，`/compare` 的等价判定、顺序/默认
动作差异、双向分组与全空间压缩，`/explain` 的归因归属、默认项位置、
不重不漏覆盖，`/cidrs/hierarchy` 的最长前缀超网择父、森林稳定排序、
独占集合（仅扣直接子节点）、重复 id / 重复网段 422 与 1～500 数量边界，
`/cidrs/diff` 的新增/删除/CIDR 变更/未变分类与 before 顺序、新增项 after
顺序追加、父节点在各侧独立择父与 `parent_changed`（含与 CIDR 变更同时
发生）、对称差受影响地址数（扩张/收缩/不相交）、网段相同但 id 不同的
替换候选、任一侧重复 id / 网段 422 且两侧一次性报告不产生部分结果、
两侧为空与各 500 条边界，
`/routes/resolve` 的最长前缀优先于 metric、同前缀最低 metric 选择、ECMP
下一跳按输入顺序去重、未命中标记、逐下一跳命中汇总、重复目标 422 与
数量/metric 边界，`/routes/failover` 的四类影响归类（unchanged /
ecmp_reduced / rerouted / unreachable）、回退到更高 metric 与更短前缀、
失败下一跳整体移除其全部路由、重复失败下一跳 422 与数量边界，
以及用标准库 `ipaddress.collapse_addresses` 作为 oracle
的随机属性测试（无损 + 最少块，并与逐地址暴力判定/逐路由暴力 LPM 对比；
failover 与“过滤失败下一跳后重新 resolve”的 oracle 交叉验证）。

---

## 项目结构

```
.
├── app/
│   ├── __init__.py
│   ├── analyzer.py    # 核心：CIDR 解析、区间差集、最少 CIDR 压缩、规则分析、等价比较、裁决归因、包含层级与网段清单差异
│   ├── router.py      # 核心：严格 IPv4 地址校验、最长前缀匹配 + 最低 metric 的 ECMP 路由解析与下一跳故障切换
│   └── main.py        # FastAPI 应用、请求/响应模型与 /analyze、/compare、/explain、/cidrs/hierarchy、/cidrs/diff、/routes/resolve、/routes/failover 接口
├── tests/
│   ├── test_analyzer.py
│   ├── test_router.py
│   └── test_api.py
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── requirements-dev.txt
└── README.md
```

## 设计要点

- **遮蔽语义**：处理第 *i* 条规则时，遮蔽集合 = 前 *i-1* 条规则
  （allow ∪ deny）覆盖地址的并集；规则区间减去遮蔽集合即生效集合。
- **无损压缩**：剩余碎片先合并相邻区间，再以“当前地址能对齐的最大
  2 的幂块、且不越过区间末端”贪心切块，得到最少数量的 CIDR。
- **等价比较**：先为每侧构造覆盖整个 IPv4 空间的有序判定分区
  （规则生效碎片 + 未命中地址的 default_action），再以双指针归并两个
  分区，交叠处动作不同即记入对应 `(left_action, right_action)` 分组；
  分组碎片同样走“合并 + 贪心切块”。时间复杂度仅取决于区间数量，
  **不逐地址枚举**，可安全处理 `0.0.0.0/0` 全空间。
- **裁决归因**：`/explain` 复用同一套区间运算，把每条规则的生效碎片
  裁剪到 query 范围并记到该规则名下，query 内未被任何规则覆盖的剩余
  部分记为默认项；各归属集合分别做“合并 + 贪心切块”，最终按规则索引
  升序、默认项最后输出，不重不漏覆盖整个 query。
- **包含层级**：`/cidrs/hierarchy` 先按严格 IPv4 校验解析全部条目并
  检查 id 与规范化网段的唯一性；为每个网段在全部条目中选择前缀最长的
  严格超网作为唯一 parent（无同网段重复时该选择唯一），形成森林。
  节点独占集合 = 自身区间减去其**直接子节点**区间并集（孙节点已包含在
  子节点内，不重复扣除），再走“合并 + 贪心切块”得到数量最少的
  `exclusive_cidrs`；兄弟节点按 `(网络地址, 前缀长度, 输入序号)` 稳定
  排序。全程为区间运算，不逐地址枚举。
- **清单差异**：`/cidrs/diff` 复用层级接口的条目解析与“最长前缀严格超网
  择父”逻辑，在 before / after 两侧**分别独立**解析、查重并计算父节点；
  任一侧存在重复 id 或规范化网段重复时收集两侧问题后一次性抛出
  （不产生部分结果）。以 id 匹配分类新增 / 删除 / CIDR 变更 / 未变，
  父节点变化只比较同 id 匹配项（新增 / 删除为 `null`）；CIDR 变更的受
  影响地址数以闭区间长度计算对称差 `|旧| + |新| − 2×|交集|`，无需展开
  地址。网段相同但 id 不同的配对通过“after 网段 → 条目”索引在一次 before
  扫描中得到（两侧网段各自唯一，故每个网段至多一对）。输出先按 before
  顺序、再追加 after 顺序的新增项，排序不依赖任何哈希遍历次序。
- **路由解析**：`/routes/resolve` 先把路由 CIDR 解析为 32 位整数区间，
  对每个目标线性扫描，仅以区间包含判断命中，先取前缀长度最大者（LPM），
  再在其中取 metric 最小值并保留全部并列路由；其 next_hop 按 routes 输入
  顺序去重得到 ECMP 列表。命中计数只随目标遍历累加（同一 ECMP 结果的
  每个下一跳各计一次），汇总按 next_hop 首次出现的路由序号排序。
  复杂度为 O(路由数 × 目标数) 的整数比较，**不逐地址展开网段**。
- **故障切换**：`/routes/failover` 复用同一套解析流程跑两遍——完整路由表
  得到 `before`，剔除失败下一跳对应的全部路由后重新解析得到 `after`
  （因此可回退到更高 metric 或更短前缀，而非收缩原 ECMP 列表）；逐目标
  比较归类 `impact`：两侧均不可达或结果一致为 `unchanged`，同网段同
  metric 但下一跳减少为 `ecmp_reduced`，仍可达但网段或 metric 改变为
  `rerouted`，原本可达而后不可达为 `unreachable`。
- **整数运算**：全部基于 32 位无符号整数区间处理，避免字符串/对象开销，
  可正确支持 `0.0.0.0/0` 全空间等边界场景。
