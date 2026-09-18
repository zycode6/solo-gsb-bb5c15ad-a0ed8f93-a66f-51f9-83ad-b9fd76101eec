"""FastAPI 接口测试。"""
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def post_analyze(rules):
    return client.post("/analyze", json={"rules": rules})


def post_compare(left, right):
    return client.post("/compare", json={"left": left, "right": right})


def test_root_and_health():
    assert client.get("/").status_code == 200
    assert client.get("/health").json() == {"status": "ok"}


def test_analyze_full_partial_shadowed():
    resp = post_analyze(
        [
            {"action": "allow", "cidr": "10.0.0.0/8"},
            {"action": "deny", "cidr": "10.1.0.0/16"},
            {"action": "ALLOW", "cidr": "192.168.0.0/16"},
            {"action": "deny", "cidr": "10.0.0.0/7"},
        ]
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["rule_count"] == 4
    assert [r["status"] for r in body["rules"]] == [
        "full",
        "shadowed",
        "full",
        "partial",
    ]
    # action 大小写不敏感并规范化
    assert body["rules"][2]["action"] == "allow"
    assert body["rules"][0]["status_label"] == "全生效"
    assert body["rules"][3]["effective_cidrs"] == ["11.0.0.0/8"]
    assert body["summary"] == {
        "full": 2,
        "partial": 1,
        "shadowed": 1,
        "effective_allow_addresses": (1 << 24) + (1 << 16),
        "effective_deny_addresses": 1 << 24,
    }


def test_bare_ip_accepted_as_32():
    resp = post_analyze([{"action": "allow", "cidr": "8.8.8.8"}])
    assert resp.status_code == 200
    rule = resp.json()["rules"][0]
    assert rule["cidr"] == "8.8.8.8/32"
    assert rule["total_addresses"] == 1
    assert rule["status"] == "full"


def test_empty_rules_422():
    assert client.post("/analyze", json={"rules": []}).status_code == 422
    assert client.post("/analyze", json={}).status_code == 422


def test_invalid_cidr_422():
    for bad in ["10.0.0.0/33", "10.0.0.1/8", "garbage", "9.9.9.9/99"]:
        resp = post_analyze([{"action": "allow", "cidr": bad}])
        assert resp.status_code == 422, bad
        assert resp.json()["detail"]


def test_ipv6_422():
    for bad in ["2001:db8::/32", "::1", "fe80::1/64"]:
        assert post_analyze([{"action": "allow", "cidr": bad}]).status_code == 422, bad


def test_bad_action_422():
    assert post_analyze(
        [{"action": "permit", "cidr": "10.0.0.0/8"}]
    ).status_code == 422


def test_missing_field_422():
    assert client.post("/analyze", json={"rules": [{"cidr": "10.0.0.0/8"}]}).status_code == 422
    assert client.post("/analyze", json={"rules": [{"action": "allow"}]}).status_code == 422


def test_non_list_body_422():
    assert client.post("/analyze", json={"rules": "nope"}).status_code == 422


def test_malformed_json_422():
    resp = client.post(
        "/analyze",
        content="{not json",
        headers={"content-type": "application/json"},
    )
    assert resp.status_code == 422


def test_openapi_docs_available():
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/docs").status_code == 200


# ---------- /compare ----------

def test_compare_equivalent_empty_sets():
    resp = post_compare(
        {"rules": [], "default_action": "allow"},
        {"rules": [], "default_action": "ALLOW"},
    )
    assert resp.status_code == 200
    assert resp.json() == {"equivalent": True, "differences": []}


def test_compare_default_only_full_space_diff():
    resp = post_compare(
        {"rules": [], "default_action": "deny"},
        {"rules": [], "default_action": "allow"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["equivalent"] is False
    assert body["differences"] == [
        {
            "left_action": "deny",
            "right_action": "allow",
            "address_count": 1 << 32,
            "cidrs": ["0.0.0.0/0"],
        }
    ]


def test_compare_rules_only_one_side():
    resp = post_compare(
        {"rules": [{"action": "allow", "cidr": "10.0.0.0/8"}],
         "default_action": "deny"},
        {"rules": [], "default_action": "deny"},
    )
    assert resp.status_code == 200
    assert resp.json()["differences"] == [
        {
            "left_action": "allow",
            "right_action": "deny",
            "address_count": 1 << 24,
            "cidrs": ["10.0.0.0/8"],
        }
    ]


def test_compare_order_sensitivity_and_bidirectional_groups():
    resp = post_compare(
        {
            "rules": [
                {"action": "allow", "cidr": "10.0.0.0/8"},
                {"action": "deny", "cidr": "10.1.0.0/16"},
            ],
            "default_action": "deny",
        },
        {
            "rules": [
                {"action": "deny", "cidr": "10.1.0.0/16"},
                {"action": "allow", "cidr": "10.0.0.0/8"},
            ],
            "default_action": "deny",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["differences"] == [
        {
            "left_action": "allow",
            "right_action": "deny",
            "address_count": 1 << 16,
            "cidrs": ["10.1.0.0/16"],
        }
    ]


def test_compare_shadowed_rule_still_equivalent():
    resp = post_compare(
        {
            "rules": [{"action": "allow", "cidr": "10.0.0.0/8"}],
            "default_action": "deny",
        },
        {
            "rules": [
                {"action": "allow", "cidr": "10.0.0.0/8"},
                {"action": "deny", "cidr": "10.0.0.1/32"},
            ],
            "default_action": "Deny",
        },
    )
    assert resp.status_code == 200
    assert resp.json() == {"equivalent": True, "differences": []}


def test_compare_validation_422():
    base = {"rules": [], "default_action": "deny"}

    # 缺少 default_action
    resp = client.post("/compare", json={"left": {"rules": []}, "right": base})
    assert resp.status_code == 422

    # 非法 default_action / action
    assert post_compare(
        {"rules": [], "default_action": "permit"}, base
    ).status_code == 422
    assert post_compare(
        {"rules": [{"action": "permit", "cidr": "10.0.0.0/8"}],
         "default_action": "deny"},
        base,
    ).status_code == 422

    # 非法 CIDR / IPv6（沿用 /analyze 校验）
    for bad in ["10.0.0.1/8", "10.0.0.0/33", "2001:db8::/32", "garbage"]:
        resp = post_compare(
            {"rules": [{"action": "allow", "cidr": bad}],
             "default_action": "deny"},
            base,
        )
        assert resp.status_code == 422, bad

    # 缺少一侧 / 请求体为空
    assert client.post("/compare", json={"left": base}).status_code == 422
    assert client.post("/compare", json={}).status_code == 422


# ---------- /explain ----------

def post_explain(rules, default_action, query):
    return client.post(
        "/explain",
        json={"rules": rules, "default_action": default_action, "query": query},
    )


def test_explain_basic_attribution():
    resp = post_explain(
        [
            {"action": "allow", "cidr": "10.0.0.0/16"},
            {"action": "deny", "cidr": "10.0.1.0/24"},
            {"action": "deny", "cidr": "10.2.0.0/16"},
        ],
        "deny",
        "10.0.0.0/8",
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["query"] == "10.0.0.0/8"
    assert body["total_addresses"] == 1 << 24

    attribution = body["attribution"]
    # 规则 1 在 query 内被完全遮蔽 -> 不出现；规则索引升序、默认项最后
    assert [item["rule_index"] for item in attribution] == [0, 2, None]
    assert [item["source"] for item in attribution] == ["rule", "rule", "default"]
    assert attribution[0]["action"] == "allow"
    assert attribution[0]["cidrs"] == ["10.0.0.0/16"]
    assert attribution[1]["action"] == "deny"
    assert attribution[1]["cidrs"] == ["10.2.0.0/16"]
    assert attribution[2]["action"] == "deny"
    # 不重不漏：各项地址数之和等于 query 总数
    assert sum(item["address_count"] for item in attribution) == 1 << 24


def test_explain_bare_ip_query_normalized():
    resp = post_explain(
        [{"action": "ALLOW", "cidr": "8.8.8.0/24"}],
        "Deny",
        "8.8.8.8",
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["query"] == "8.8.8.8/32"
    assert body["total_addresses"] == 1
    # action / default_action 大小写不敏感并规范化
    assert body["attribution"] == [
        {
            "source": "rule",
            "rule_index": 0,
            "action": "allow",
            "address_count": 1,
            "cidrs": ["8.8.8.8/32"],
        }
    ]


def test_explain_empty_rules_all_default():
    resp = post_explain([], "allow", "192.168.0.0/16")
    assert resp.status_code == 200
    assert resp.json()["attribution"] == [
        {
            "source": "default",
            "rule_index": None,
            "action": "allow",
            "address_count": 1 << 16,
            "cidrs": ["192.168.0.0/16"],
        }
    ]


def test_explain_validation_422():
    # 缺少 default_action / query、空请求体
    assert client.post(
        "/explain", json={"rules": [], "query": "10.0.0.0/8"}
    ).status_code == 422
    assert client.post(
        "/explain", json={"rules": [], "default_action": "deny"}
    ).status_code == 422
    assert client.post("/explain", json={}).status_code == 422

    # 非法 query：格式错误、主机位非零、IPv6
    for bad in ["10.0.0.1/8", "10.0.0.0/33", "2001:db8::/32", "garbage"]:
        assert post_explain([], "deny", bad).status_code == 422, bad

    # 非法 default_action / action / 规则 CIDR（沿用现有校验）
    assert post_explain([], "permit", "10.0.0.0/8").status_code == 422
    assert post_explain(
        [{"action": "permit", "cidr": "10.0.0.0/8"}], "deny", "10.0.0.0/8"
    ).status_code == 422
    assert post_explain(
        [{"action": "allow", "cidr": "10.0.0.1/8"}], "deny", "10.0.0.0/8"
    ).status_code == 422


# ---------- /cidrs/hierarchy ----------

def post_hierarchy(entries):
    return client.post("/cidrs/hierarchy", json={"entries": entries})


def test_hierarchy_basic_tree():
    resp = post_hierarchy(
        [
            {"id": "net", "cidr": "10.0.0.0/8"},
            {"id": "sub", "cidr": "10.1.0.0/16"},
            {"id": "host", "cidr": "10.1.1.1"},
            {"id": "other", "cidr": "8.8.8.0/24"},
        ]
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["node_count"] == 4
    assert body["root_count"] == 2

    # 根按网络地址稳定排序：8.8.8.0/24 在 10.0.0.0/8 之前
    other, net = body["roots"]
    assert other["id"] == "other"
    assert other["cidr"] == "8.8.8.0/24"
    assert other["parent_id"] is None
    assert other["children"] == []
    assert other["total_addresses"] == 256
    assert other["exclusive_address_count"] == 256
    assert other["exclusive_cidrs"] == ["8.8.8.0/24"]

    assert net["id"] == "net"
    assert net["cidr"] == "10.0.0.0/8"
    assert net["parent_id"] is None
    assert net["total_addresses"] == 1 << 24
    # /8 的直接子节点仅 10.1.0.0/16（host 是孙节点，不重复扣除）
    assert net["exclusive_address_count"] == (1 << 24) - (1 << 16)

    sub = net["children"][0]
    assert sub["id"] == "sub"
    assert sub["parent_id"] == "net"
    assert sub["total_addresses"] == 1 << 16
    # /16 扣除直接子节点 10.1.1.1/32
    assert sub["exclusive_address_count"] == (1 << 16) - 1
    assert sub["exclusive_cidrs"][0] == "10.1.0.0/24"

    host = sub["children"][0]
    assert host["id"] == "host"
    assert host["cidr"] == "10.1.1.1/32"  # 纯 IP 规范化为 /32
    assert host["parent_id"] == "sub"
    assert host["total_addresses"] == 1
    assert host["exclusive_address_count"] == 1
    assert host["exclusive_cidrs"] == ["10.1.1.1/32"]
    assert host["children"] == []


def test_hierarchy_longest_prefix_supernet_is_parent():
    resp = post_hierarchy(
        [
            {"id": "a", "cidr": "10.0.0.0/8"},
            {"id": "b", "cidr": "10.1.0.0/16"},
            {"id": "c", "cidr": "10.1.2.0/24"},
        ]
    )
    assert resp.status_code == 200
    roots = resp.json()["roots"]
    assert [n["id"] for n in roots] == ["a"]
    b = roots[0]["children"][0]
    assert b["id"] == "b"
    # /24 的唯一 parent 是前缀最长的严格超网 /16，而非 /8
    assert [c["id"] for c in b["children"]] == ["c"]
    assert b["children"][0]["parent_id"] == "b"


def test_hierarchy_integer_ids_and_root_order():
    resp = post_hierarchy(
        [
            {"id": 2, "cidr": "192.168.0.0/16"},
            {"id": 1, "cidr": "10.0.0.0/8"},
        ]
    )
    assert resp.status_code == 200
    assert [n["id"] for n in resp.json()["roots"]] == [1, 2]


def test_hierarchy_duplicate_network_422_lists_ids():
    resp = post_hierarchy(
        [
            {"id": "a", "cidr": "10.0.0.0/8"},
            {"id": "b", "cidr": "10.0.0.0/08"},  # 规范化后与 a 相同
            {"id": "c", "cidr": "8.8.8.8/32"},
        ]
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["error"] == "duplicate_entries"
    assert detail["duplicate_ids"] == []
    assert detail["duplicate_networks"] == [
        {
            "cidr": "10.0.0.0/8",
            "entries": [
                {"index": 0, "id": "a", "cidr": "10.0.0.0/8"},
                {"index": 1, "id": "b", "cidr": "10.0.0.0/8"},
            ],
        }
    ]


def test_hierarchy_duplicate_id_422_lists_indexes():
    resp = post_hierarchy(
        [
            {"id": "x", "cidr": "10.0.0.0/8"},
            {"id": "x", "cidr": "11.0.0.0/8"},
            {"id": 5, "cidr": "12.0.0.0/8"},
            {"id": 5, "cidr": "13.0.0.0/8"},
        ]
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["error"] == "duplicate_entries"
    assert detail["duplicate_ids"] == [
        {"id": "x", "indexes": [0, 1]},
        {"id": 5, "indexes": [2, 3]},
    ]
    assert detail["duplicate_networks"] == []


def test_hierarchy_both_duplicates_reported_together():
    resp = post_hierarchy(
        [
            {"id": "x", "cidr": "10.0.0.0/8"},
            {"id": "x", "cidr": "10.0.0.0/8"},
        ]
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert len(detail["duplicate_ids"]) == 1
    assert len(detail["duplicate_networks"]) == 1


def test_hierarchy_validation_422():
    # 空列表 / 缺少 entries
    assert post_hierarchy([]).status_code == 422
    assert client.post("/cidrs/hierarchy", json={}).status_code == 422

    # 超过 500 条
    too_many = [{"id": i, "cidr": f"1.0.{i // 256}.{i % 256}/32"} for i in range(501)]
    assert post_hierarchy(too_many).status_code == 422

    # 非法 CIDR / IPv6（沿用现有严格校验）
    for bad in ["10.0.0.1/8", "10.0.0.0/33", "garbage", "2001:db8::/32", "::1"]:
        assert post_hierarchy([{"id": "a", "cidr": bad}]).status_code == 422, bad

    # 非法 id：bool / float / 对象 / 空字符串 / 缺字段
    for bad_id in [True, 1.5, ["x"], {"k": 1}, "   "]:
        assert post_hierarchy(
            [{"id": bad_id, "cidr": "10.0.0.0/8"}]
        ).status_code == 422, bad_id
    assert post_hierarchy([{"cidr": "10.0.0.0/8"}]).status_code == 422
    assert post_hierarchy([{"id": "a"}]).status_code == 422


def test_hierarchy_max_500_entries_accepted():
    entries = [
        {"id": i, "cidr": f"1.0.{i // 256}.{i % 256}/32"} for i in range(500)
    ]
    resp = post_hierarchy(entries)
    assert resp.status_code == 200
    body = resp.json()
    assert body["node_count"] == 500
    # 500 个互不相交的 /32：全部为 root，独占 1 个地址
    assert body["root_count"] == 500
    assert all(n["exclusive_address_count"] == 1 for n in body["roots"])
    # 按网络地址稳定排序（与输入顺序一致）
    assert [n["id"] for n in body["roots"]] == list(range(500))


def test_hierarchy_existing_endpoints_unchanged():
    # 新接口不影响既有接口
    assert client.get("/health").status_code == 200
    resp = post_analyze([{"action": "allow", "cidr": "10.0.0.0/8"}])
    assert resp.status_code == 200
    assert resp.json()["rules"][0]["status"] == "full"


# ---------- /cidrs/diff ----------

def post_diff(before, after):
    return client.post("/cidrs/diff", json={"before": before, "after": after})


def test_diff_basic_changes_order_and_replacement():
    resp = post_diff(
        [
            {"id": "net", "cidr": "10.0.0.0/8"},
            {"id": "sub-a", "cidr": "10.1.0.0/16"},
            {"id": "sub-b", "cidr": "10.2.0.0/16"},
            {"id": "old-dns", "cidr": "8.8.8.8/32"},
        ],
        [
            {"id": "net", "cidr": "10.0.0.0/8"},
            {"id": "sub-a", "cidr": "10.1.0.0/24"},
            {"id": "sub-c", "cidr": "10.2.0.0/16"},
            {"id": "new-dns", "cidr": "8.8.8.8/32"},
        ],
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["before_count"] == 4
    assert body["after_count"] == 4

    # 保持 before 顺序，新增项按 after 顺序追加
    assert [(c["id"], c["change"]) for c in body["changes"]] == [
        ("net", "unchanged"),
        ("sub-a", "cidr_changed"),
        ("sub-b", "removed"),
        ("old-dns", "removed"),
        ("sub-c", "added"),
        ("new-dns", "added"),
    ]

    by_id = {c["id"]: c for c in body["changes"]}
    assert by_id["sub-a"]["before_parent_id"] == "net"
    assert by_id["sub-a"]["after_parent_id"] == "net"
    assert by_id["sub-a"]["parent_changed"] is False
    assert by_id["sub-a"]["affected_address_count"] == 65536 - 256  # 对称差
    assert by_id["sub-b"]["parent_changed"] is None
    assert by_id["sub-b"]["affected_address_count"] == 65536
    assert by_id["sub-c"]["before_parent_id"] is None
    assert by_id["sub-c"]["after_parent_id"] == "net"
    assert by_id["sub-c"]["parent_changed"] is None
    assert by_id["sub-c"]["affected_address_count"] == 65536
    assert by_id["new-dns"]["affected_address_count"] == 1

    # 规范化后网段相同但 id 不同 -> 替换候选（按 before 位置排序）
    assert body["replacement_candidates"] == [
        {"before_id": "sub-b", "after_id": "sub-c", "cidr": "10.2.0.0/16", "address_count": 65536},
        {"before_id": "old-dns", "after_id": "new-dns", "cidr": "8.8.8.8/32", "address_count": 1},
    ]
    assert body["summary"] == {
        "added": 2,
        "removed": 2,
        "cidr_changed": 1,
        "unchanged": 1,
        "parent_changed": 0,
        "replacement_candidate_count": 2,
        "affected_address_count": 65280 + 2 * 65536 + 2,
    }


def test_diff_parent_only_change_flagged():
    # 删除中间层 /16，host 网段不变但直接父节点从 sub 变为 net
    resp = post_diff(
        [
            {"id": "net", "cidr": "10.0.0.0/8"},
            {"id": "sub", "cidr": "10.1.0.0/16"},
            {"id": "host", "cidr": "10.1.0.1/32"},
        ],
        [
            {"id": "net", "cidr": "10.0.0.0/8"},
            {"id": "host", "cidr": "10.1.0.1/32"},
        ],
    )
    assert resp.status_code == 200
    by_id = {c["id"]: c for c in resp.json()["changes"]}
    host = by_id["host"]
    assert host["change"] == "unchanged"
    assert host["parent_changed"] is True
    assert host["before_parent_id"] == "sub"
    assert host["after_parent_id"] == "net"
    assert host["affected_address_count"] == 0
    summary = resp.json()["summary"]
    assert summary["parent_changed"] == 1
    assert summary["affected_address_count"] == 65536  # 仅 sub 删除


def test_diff_normalized_same_network_different_writing_is_unchanged():
    resp = post_diff(
        [{"id": "a", "cidr": "10.0.0.0/8"}],
        [{"id": "a", "cidr": "10.0.0.0/08"}],
    )
    assert resp.status_code == 200
    change = resp.json()["changes"][0]
    assert change["change"] == "unchanged"
    assert change["before_cidr"] == change["after_cidr"] == "10.0.0.0/8"
    assert change["affected_address_count"] == 0
    assert resp.json()["replacement_candidates"] == []


def test_diff_empty_sides_accepted():
    assert post_diff([], []).json() == {
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
    # 仅 after：全部 added，顺序即 after 顺序
    resp = post_diff([], [{"id": "a", "cidr": "10.0.0.0/8"}, {"id": "b", "cidr": "8.8.8.8"}])
    assert resp.status_code == 200
    body = resp.json()
    assert [c["id"] for c in body["changes"]] == ["a", "b"]
    assert body["changes"][1]["after_cidr"] == "8.8.8.8/32"  # 纯 IP 规范化
    assert body["summary"]["added"] == 2


def test_diff_integer_ids_preserved():
    resp = post_diff(
        [{"id": 1, "cidr": "10.0.0.0/8"}, {"id": 2, "cidr": "11.0.0.0/8"}],
        [{"id": 1, "cidr": "11.0.0.0/8"}, {"id": 3, "cidr": "8.8.8.8"}],
    )
    assert resp.status_code == 200
    by_id = {c["id"]: c for c in resp.json()["changes"]}
    assert by_id[1]["change"] == "cidr_changed"
    assert by_id[1]["affected_address_count"] == 2 * (1 << 24)  # 不相交的两个 /8
    assert by_id[2]["change"] == "removed"
    assert by_id[3]["change"] == "added"


def test_diff_duplicate_id_after_side_422_no_partial_result():
    resp = post_diff(
        [{"id": "a", "cidr": "10.0.0.0/8"}],
        [
            {"id": "x", "cidr": "10.0.0.0/8"},
            {"id": "y", "cidr": "8.8.8.8/32"},
            {"id": "x", "cidr": "11.0.0.0/8"},
        ],
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["error"] == "duplicate_entries"
    assert detail["before"] == {"duplicate_ids": [], "duplicate_networks": []}
    assert detail["after"]["duplicate_ids"] == [
        {"id": "x", "indexes": [0, 2]}
    ]
    assert detail["after"]["duplicate_networks"] == []


def test_diff_duplicate_network_before_side_422():
    resp = post_diff(
        [
            {"id": "a", "cidr": "10.0.0.0/8"},
            {"id": "b", "cidr": "10.0.0.0/08"},
        ],
        [{"id": "a", "cidr": "10.0.0.0/8"}],
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail["after"] == {"duplicate_ids": [], "duplicate_networks": []}
    assert detail["before"]["duplicate_ids"] == []
    assert len(detail["before"]["duplicate_networks"]) == 1
    assert detail["before"]["duplicate_networks"][0]["cidr"] == "10.0.0.0/8"


def test_diff_both_sides_duplicates_reported_together():
    resp = post_diff(
        [{"id": "x", "cidr": "10.0.0.0/8"}, {"id": "x", "cidr": "11.0.0.0/8"}],
        [{"id": "y", "cidr": "10.0.0.0/8"}, {"id": "z", "cidr": "10.0.0.0/08"}],
    )
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert len(detail["before"]["duplicate_ids"]) == 1
    assert len(detail["after"]["duplicate_networks"]) == 1


def test_diff_validation_422():
    # 缺少 before / after、空请求体
    assert client.post("/cidrs/diff", json={}).status_code == 422
    assert client.post(
        "/cidrs/diff", json={"before": []}
    ).status_code == 422
    assert client.post(
        "/cidrs/diff", json={"after": []}
    ).status_code == 422

    # 非法 CIDR / IPv6（沿用现有严格校验）
    for bad in ["10.0.0.1/8", "10.0.0.0/33", "garbage", "2001:db8::/32", "::1"]:
        assert post_diff(
            [{"id": "a", "cidr": bad}], []
        ).status_code == 422, bad
        assert post_diff(
            [], [{"id": "a", "cidr": bad}]
        ).status_code == 422, bad

    # 非法 id：bool / float / 对象 / 空字符串 / 缺字段
    for bad_id in [True, 1.5, ["x"], {"k": 1}, "   "]:
        assert post_diff(
            [{"id": bad_id, "cidr": "10.0.0.0/8"}], []
        ).status_code == 422, bad_id
    assert post_diff([{"cidr": "10.0.0.0/8"}], []).status_code == 422
    assert post_diff([{"id": "a"}], []).status_code == 422

    # 单侧超过 500 条
    too_many = [{"id": i, "cidr": f"1.0.{i // 256}.{i % 256}/32"} for i in range(501)]
    assert post_diff(too_many, []).status_code == 422
    assert post_diff([], too_many).status_code == 422

    # 字段类型错误
    assert client.post(
        "/cidrs/diff", json={"before": "x", "after": []}
    ).status_code == 422


def test_diff_max_500_entries_each_side_accepted():
    before = [
        {"id": i, "cidr": f"1.0.{i // 256}.{i % 256}/32"} for i in range(500)
    ]
    after = [
        {"id": 500 + i, "cidr": f"2.0.{i // 256}.{i % 256}/32"} for i in range(500)
    ]
    resp = post_diff(before, after)
    assert resp.status_code == 200
    body = resp.json()
    assert body["summary"]["removed"] == 500
    assert body["summary"]["added"] == 500
    assert body["summary"]["affected_address_count"] == 1000  # 全是 /32
    # before 顺序在前，after 顺序追加
    assert [c["id"] for c in body["changes"]] == list(range(1000))


def test_diff_openapi_examples_present():
    schema = client.get("/openapi.json").json()
    op = schema["paths"]["/cidrs/diff"]["post"]
    assert "CIDR 变更" in op["summary"] or "cidr" in op["summary"].lower()
    # 请求示例
    examples = op["requestBody"]["content"]["application/json"]["examples"]
    assert "before" in list(examples.values())[0]["value"]
    # 200 响应示例与 422 错误示例
    responses = op["responses"]
    assert "200" in responses and "422" in responses
    ok_example = responses["200"]["content"]["application/json"]["examples"]["diff"]
    assert ok_example["value"]["replacement_candidates"]
    err_example = responses["422"]["content"]["application/json"]["examples"]["duplicates"]
    assert err_example["value"]["detail"]["error"] == "duplicate_entries"


def test_diff_existing_endpoints_unchanged():
    # 新接口不影响既有接口
    assert client.get("/health").status_code == 200
    assert post_hierarchy(
        [{"id": "a", "cidr": "10.0.0.0/8"}]
    ).status_code == 200


# ---------- /routes/resolve ----------

def post_resolve(routes, targets):
    return client.post(
        "/routes/resolve", json={"routes": routes, "targets": targets}
    )


def test_resolve_lpm_lowest_metric_and_ecmp_dedup():
    resp = post_resolve(
        [
            {"cidr": "0.0.0.0/0", "next_hop": "192.0.2.254", "metric": 100},
            {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.254", "metric": 50},
            {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.1", "metric": 20},
            {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.2", "metric": 20},
            {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.1", "metric": 20},  # 重复
            {"cidr": "10.1.0.0/16", "next_hop": "10.1.0.1", "metric": 60},
            {"cidr": "10.1.0.0/16", "next_hop": "10.1.0.2", "metric": 60},
        ],
        ["10.1.0.5", "10.2.2.2", "8.8.8.8", "172.16.0.1"],
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["route_count"] == 7
    assert body["target_count"] == 4

    results = body["results"]
    # targets 输入顺序保持不变
    assert [r["target"] for r in results] == [
        "10.1.0.5",
        "10.2.2.2",
        "8.8.8.8",
        "172.16.0.1",
    ]
    assert results[0] == {
        "target": "10.1.0.5",
        "status": "reachable",
        "matched_cidr": "10.1.0.0/16",
        "metric": 60,
        "next_hops": ["10.1.0.1", "10.1.0.2"],
    }
    assert results[1] == {
        "target": "10.2.2.2",
        "status": "reachable",
        "matched_cidr": "10.0.0.0/8",
        "metric": 20,
        "next_hops": ["10.0.0.1", "10.0.0.2"],  # 去重且按 routes 顺序
    }
    for outside in results[2:]:
        assert outside["status"] == "reachable"
        assert outside["matched_cidr"] == "0.0.0.0/0"
        assert outside["metric"] == 100
        assert outside["next_hops"] == ["192.0.2.254"]

    # ECMP 各下一跳分别计数；顺序按 next_hop 在 routes 中首次出现位置
    assert body["summary"] == {
        "reachable_count": 4,
        "unreachable_count": 0,
        "next_hop_counts": [
            {"next_hop": "192.0.2.254", "target_count": 2},
            {"next_hop": "10.0.0.1", "target_count": 1},
            {"next_hop": "10.0.0.2", "target_count": 1},
            {"next_hop": "10.1.0.1", "target_count": 1},
            {"next_hop": "10.1.0.2", "target_count": 1},
        ],
    }


def test_resolve_unreachable_targets():
    resp = post_resolve(
        [
            {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.1", "metric": 0},
            {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.2", "metric": 0},
        ],
        ["8.8.8.8", "10.0.0.1", "9.9.9.9"],
    )
    assert resp.status_code == 200
    body = resp.json()
    assert [r["status"] for r in body["results"]] == [
        "unreachable",
        "reachable",
        "unreachable",
    ]
    assert body["results"][0] == {
        "target": "8.8.8.8",
        "status": "unreachable",
        "matched_cidr": None,
        "metric": None,
        "next_hops": [],
    }
    # 仅 10.0.0.1 这一目标命中，ECMP 两个下一跳各计一次
    assert body["summary"] == {
        "reachable_count": 1,
        "unreachable_count": 2,
        "next_hop_counts": [
            {"next_hop": "10.0.0.1", "target_count": 1},
            {"next_hop": "10.0.0.2", "target_count": 1},
        ],
    }


def test_resolve_empty_routes_all_unreachable():
    resp = post_resolve([], ["8.8.8.8"])
    assert resp.status_code == 200
    body = resp.json()
    assert body["route_count"] == 0
    assert body["results"][0]["status"] == "unreachable"
    assert body["summary"] == {
        "reachable_count": 0,
        "unreachable_count": 1,
        "next_hop_counts": [],
    }


def test_resolve_bare_ip_accepted_for_target_and_route():
    resp = post_resolve(
        [{"cidr": "8.8.8.8", "next_hop": "1.1.1.1", "metric": 5}],
        ["8.8.8.8"],
    )
    assert resp.status_code == 200
    item = resp.json()["results"][0]
    assert item["matched_cidr"] == "8.8.8.8/32"
    assert item["metric"] == 5
    assert item["next_hops"] == ["1.1.1.1"]


def test_resolve_metric_boundaries():
    for metric in (0, 65535):
        resp = post_resolve(
            [{"cidr": "0.0.0.0/0", "next_hop": "1.1.1.1", "metric": metric}],
            ["8.8.8.8"],
        )
        assert resp.status_code == 200, metric
        assert resp.json()["results"][0]["metric"] == metric


def test_resolve_duplicate_targets_422_lists_indexes():
    resp = post_resolve(
        [{"cidr": "0.0.0.0/0", "next_hop": "1.1.1.1", "metric": 0}],
        ["8.8.8.8", "9.9.9.9", "8.8.8.8"],
    )
    assert resp.status_code == 422
    assert resp.json()["detail"] == {
        "error": "duplicate_targets",
        "duplicates": [{"target": "8.8.8.8", "indexes": [0, 2]}],
    }


def test_resolve_validation_422():
    valid_route = {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.1", "metric": 10}

    # 缺少字段 / 请求体为空
    assert client.post("/routes/resolve", json={}).status_code == 422
    assert client.post(
        "/routes/resolve", json={"routes": []}
    ).status_code == 422
    assert client.post(
        "/routes/resolve", json={"targets": ["8.8.8.8"]}
    ).status_code == 422

    # 空目标 / 超过 500 个目标
    assert post_resolve([valid_route], []).status_code == 422
    too_many_targets = [f"8.8.{i // 256}.{i % 256}" for i in range(501)]
    assert post_resolve([valid_route], too_many_targets).status_code == 422

    # 超过 1000 条路由
    too_many_routes = [
        {"cidr": "0.0.0.0/0", "next_hop": "1.1.1.1", "metric": 0}
        for _ in range(1001)
    ]
    assert post_resolve(too_many_routes, ["8.8.8.8"]).status_code == 422

    # 非法 route cidr（主机位非零 / 前缀越界 / IPv6）
    for bad in ["10.0.0.1/8", "10.0.0.0/33", "2001:db8::/32", "garbage"]:
        route = {"cidr": bad, "next_hop": "10.0.0.1", "metric": 10}
        assert post_resolve([route], ["8.8.8.8"]).status_code == 422, bad

    # 非法 next_hop（CIDR 写法 / IPv6 / 越界）
    for bad in ["10.0.0.1/32", "::1", "999.0.0.1", ""]:
        route = {"cidr": "10.0.0.0/8", "next_hop": bad, "metric": 10}
        assert post_resolve([route], ["8.8.8.8"]).status_code == 422, bad

    # 非法 target（CIDR 写法 / IPv6 / 前导零 / 非字符串）
    for bad in ["8.8.8.8/32", "2001:db8::1", "010.0.0.1", 8, True, None]:
        assert post_resolve([valid_route], [bad]).status_code == 422, bad

    # 非法 metric：越界 / bool / float / 字符串
    for bad_metric in [-1, 65536, True, 1.5, "10"]:
        route = {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.1", "metric": bad_metric}
        assert post_resolve([route], ["8.8.8.8"]).status_code == 422, bad_metric

    # routes / targets 类型错误
    assert client.post(
        "/routes/resolve", json={"routes": "x", "targets": ["8.8.8.8"]}
    ).status_code == 422
    assert post_resolve(valid_route, ["8.8.8.8"]).status_code == 422


def test_resolve_limits_accepted():
    routes = [
        {"cidr": "0.0.0.0/0", "next_hop": "1.1.1.1", "metric": 0}
        for _ in range(1000)
    ]
    targets = [f"8.8.{i // 256}.{i % 256}" for i in range(500)]
    resp = post_resolve(routes, targets)
    assert resp.status_code == 200
    body = resp.json()
    assert body["route_count"] == 1000
    assert body["target_count"] == 500
    assert len(body["results"]) == 500
    assert body["summary"]["reachable_count"] == 500
    assert body["summary"]["unreachable_count"] == 0
    # 重复下一跳去重为一项，命中全部目标
    assert body["summary"]["next_hop_counts"] == [
        {"next_hop": "1.1.1.1", "target_count": 500}
    ]


def test_resolve_existing_endpoints_unchanged():
    # 新接口不影响既有接口
    assert client.get("/health").status_code == 200
    assert client.get("/").status_code == 200
    resp = post_analyze([{"action": "allow", "cidr": "10.0.0.0/8"}])
    assert resp.status_code == 200
    assert post_hierarchy(
        [{"id": "a", "cidr": "10.0.0.0/8"}]
    ).status_code == 200


# ---------- /routes/failover ----------

def post_failover(routes, targets, failed_next_hops):
    return client.post(
        "/routes/failover",
        json={
            "routes": routes,
            "targets": targets,
            "failed_next_hops": failed_next_hops,
        },
    )


def test_failover_all_four_impacts():
    resp = post_failover(
        [
            {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.1", "metric": 10},
            {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.2", "metric": 10},
            {"cidr": "10.1.0.0/16", "next_hop": "10.1.0.1", "metric": 5},
            {"cidr": "11.0.0.0/8", "next_hop": "11.0.0.1", "metric": 7},
            {"cidr": "12.0.0.0/8", "next_hop": "12.0.0.1", "metric": 3},
        ],
        ["10.0.9.9", "10.1.0.9", "11.0.0.9", "12.0.0.9"],
        ["10.0.0.2", "10.1.0.1", "11.0.0.1"],
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["route_count"] == 5
    assert body["target_count"] == 4
    assert body["failed_next_hops"] == ["10.0.0.2", "10.1.0.1", "11.0.0.1"]

    results = body["results"]
    # 严格保持 targets 输入顺序
    assert [r["target"] for r in results] == [
        "10.0.9.9",
        "10.1.0.9",
        "11.0.0.9",
        "12.0.0.9",
    ]
    assert [r["impact"] for r in results] == [
        "ecmp_reduced",
        "rerouted",
        "unreachable",
        "unchanged",
    ]

    # ecmp_reduced：命中网段与 metric 不变，等价下一跳减少
    assert results[0]["before"] == {
        "status": "reachable",
        "matched_cidr": "10.0.0.0/8",
        "metric": 10,
        "next_hops": ["10.0.0.1", "10.0.0.2"],
    }
    assert results[0]["after"] == {
        "status": "reachable",
        "matched_cidr": "10.0.0.0/8",
        "metric": 10,
        "next_hops": ["10.0.0.1"],
    }
    # rerouted：/16 失效后回退到更短前缀 /8
    assert results[1]["before"]["matched_cidr"] == "10.1.0.0/16"
    assert results[1]["after"] == {
        "status": "reachable",
        "matched_cidr": "10.0.0.0/8",
        "metric": 10,
        "next_hops": ["10.0.0.1"],
    }
    # unreachable：唯一路由失效
    assert results[2]["after"] == {
        "status": "unreachable",
        "matched_cidr": None,
        "metric": None,
        "next_hops": [],
    }
    # unchanged：before/after 完全一致
    assert results[3]["before"] == results[3]["after"]

    assert body["summary"] == {
        "unchanged": 1,
        "ecmp_reduced": 1,
        "rerouted": 1,
        "unreachable": 1,
    }


def test_failover_fallback_to_higher_metric_not_ecmp_shrink():
    # 同网段最低 metric 路由全部失效：回退到更高 metric，而不是把 ECMP 删空
    resp = post_failover(
        [
            {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.1", "metric": 10},
            {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.2", "metric": 50},
        ],
        ["10.0.0.9"],
        ["10.0.0.1"],
    )
    assert resp.status_code == 200
    item = resp.json()["results"][0]
    assert item["impact"] == "rerouted"
    assert item["before"]["metric"] == 10
    assert item["after"] == {
        "status": "reachable",
        "matched_cidr": "10.0.0.0/8",
        "metric": 50,
        "next_hops": ["10.0.0.2"],
    }


def test_failover_empty_failed_next_hops_all_unchanged():
    resp = post_failover(
        [{"cidr": "0.0.0.0/0", "next_hop": "1.1.1.1", "metric": 0}],
        ["8.8.8.8", "9.9.9.9"],
        [],
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["failed_next_hops"] == []
    assert [r["impact"] for r in body["results"]] == ["unchanged", "unchanged"]
    assert body["summary"] == {
        "unchanged": 2,
        "ecmp_reduced": 0,
        "rerouted": 0,
        "unreachable": 0,
    }


def test_failover_failed_next_hops_normalized():
    resp = post_failover(
        [{"cidr": "0.0.0.0/0", "next_hop": "1.1.1.1", "metric": 0}],
        ["8.8.8.8"],
        [" 1.1.1.1 "],
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["failed_next_hops"] == ["1.1.1.1"]
    assert body["results"][0]["impact"] == "unreachable"


def test_failover_duplicate_failed_next_hops_422_lists_indexes():
    resp = post_failover(
        [{"cidr": "0.0.0.0/0", "next_hop": "1.1.1.1", "metric": 0}],
        ["8.8.8.8"],
        ["1.1.1.1", "2.2.2.2", "1.1.1.1"],
    )
    assert resp.status_code == 422
    assert resp.json()["detail"] == {
        "error": "duplicate_next_hops",
        "duplicates": [{"next_hop": "1.1.1.1", "indexes": [0, 2]}],
    }


def test_failover_duplicate_targets_422():
    resp = post_failover(
        [{"cidr": "0.0.0.0/0", "next_hop": "1.1.1.1", "metric": 0}],
        ["8.8.8.8", "9.9.9.9", "8.8.8.8"],
        ["1.1.1.1"],
    )
    assert resp.status_code == 422
    assert resp.json()["detail"] == {
        "error": "duplicate_targets",
        "duplicates": [{"target": "8.8.8.8", "indexes": [0, 2]}],
    }


def test_failover_validation_422():
    valid_route = {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.1", "metric": 10}

    # 缺少字段 / 请求体为空
    assert client.post("/routes/failover", json={}).status_code == 422
    assert client.post(
        "/routes/failover", json={"routes": [], "targets": ["8.8.8.8"]}
    ).status_code == 422
    assert client.post(
        "/routes/failover",
        json={"routes": [], "failed_next_hops": ["1.1.1.1"]},
    ).status_code == 422
    assert client.post(
        "/routes/failover",
        json={"targets": ["8.8.8.8"], "failed_next_hops": []},
    ).status_code == 422

    # 非法 failed_next_hops：CIDR 写法 / IPv6 / 越界 / 前导零 / 空串 / 非字符串
    for bad in ["10.0.0.1/32", "::1", "999.0.0.1", "010.0.0.1", "", 8, True, None]:
        resp = post_failover([valid_route], ["10.0.0.9"], [bad])
        assert resp.status_code == 422, bad

    # 非法 route cidr / next_hop / metric / target：沿用 /routes/resolve 校验
    for bad in ["10.0.0.1/8", "10.0.0.0/33", "2001:db8::/32", "garbage"]:
        route = {"cidr": bad, "next_hop": "10.0.0.1", "metric": 10}
        assert post_failover([route], ["10.0.0.9"], []).status_code == 422, bad
    for bad in ["10.0.0.1/32", "::1", "999.0.0.1"]:
        route = {"cidr": "10.0.0.0/8", "next_hop": bad, "metric": 10}
        assert post_failover([route], ["10.0.0.9"], []).status_code == 422, bad
    for bad_metric in [-1, 65536, True, 1.5, "10"]:
        route = {"cidr": "10.0.0.0/8", "next_hop": "10.0.0.1", "metric": bad_metric}
        assert post_failover([route], ["10.0.0.9"], []).status_code == 422, bad_metric
    for bad in ["8.8.8.8/32", "2001:db8::1", "010.0.0.1", 8, True, None]:
        assert post_failover([valid_route], [bad], []).status_code == 422, bad

    # 数量限制：路由 > 1000、目标 > 500、目标为空、失败下一跳 > 1000
    too_many_routes = [
        {"cidr": "0.0.0.0/0", "next_hop": "1.1.1.1", "metric": 0}
        for _ in range(1001)
    ]
    assert post_failover(too_many_routes, ["8.8.8.8"], []).status_code == 422
    too_many_targets = [f"8.8.{i // 256}.{i % 256}" for i in range(501)]
    assert post_failover([valid_route], too_many_targets, []).status_code == 422
    assert post_failover([valid_route], [], []).status_code == 422
    too_many_failed = [f"192.0.{i // 256}.{i % 256}" for i in range(1001)]
    assert post_failover([valid_route], ["10.0.0.9"], too_many_failed).status_code == 422

    # 字段类型错误
    assert client.post(
        "/routes/failover",
        json={"routes": "x", "targets": ["8.8.8.8"], "failed_next_hops": []},
    ).status_code == 422
    assert client.post(
        "/routes/failover",
        json={"routes": [], "targets": ["8.8.8.8"], "failed_next_hops": "x"},
    ).status_code == 422


def test_failover_limits_accepted():
    routes = [
        {"cidr": "0.0.0.0/0", "next_hop": "1.1.1.1", "metric": 0}
        for _ in range(1000)
    ]
    targets = [f"8.8.{i // 256}.{i % 256}" for i in range(500)]
    failed = [f"192.0.{i // 256}.{i % 256}" for i in range(1000)]
    resp = post_failover(routes, targets, failed)
    assert resp.status_code == 200
    body = resp.json()
    assert body["route_count"] == 1000
    assert body["target_count"] == 500
    assert len(body["failed_next_hops"]) == 1000
    # 失败下一跳均不在路由表中：全部 unchanged
    assert body["summary"] == {
        "unchanged": 500,
        "ecmp_reduced": 0,
        "rerouted": 0,
        "unreachable": 0,
    }


def test_failover_existing_endpoints_unchanged():
    # 新接口不影响既有接口
    assert client.get("/health").status_code == 200
    resp = post_resolve(
        [{"cidr": "0.0.0.0/0", "next_hop": "1.1.1.1", "metric": 0}],
        ["8.8.8.8"],
    )
    assert resp.status_code == 200
    assert resp.json()["results"][0]["next_hops"] == ["1.1.1.1"]
    assert post_analyze([{"action": "allow", "cidr": "10.0.0.0/8"}]).status_code == 200
