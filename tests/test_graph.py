import json
import re

from broom365.services.graph import GraphClient, GraphError


class Resp:
    def __init__(self, status, body=None, headers=None):
        self.status_code, self._body, self.headers = status, body if body is not None else {}, headers or {}

    @property
    def ok(self):
        return self.status_code < 400

    @property
    def text(self):
        return json.dumps(self._body)

    @property
    def content(self):
        return b"x"

    def json(self):
        return self._body


class FakeSession:
    """Records requests; `script` maps a predicate on (url, params) to a response."""

    def __init__(self, handler):
        self.handler, self.requests = handler, []

    def get(self, url, params=None, headers=None, timeout=None):
        self.requests.append((url, dict(params) if params else None))
        return self.handler(url, params)


def client(handler):
    s = FakeSession(handler)
    return GraphClient(lambda: "tok", s), s


def test_error_message_is_extracted_from_graph_json():
    e = GraphError(400, "u", json.dumps({"error": {"code": "BadRequest", "message": "Invalid filter clause"}}))
    assert e.message == "Invalid filter clause"
    assert GraphError(500, "u", "plain text").message == "plain text"


def test_audit_query_retries_without_top_on_400():
    def handler(url, params):
        if params and "$top" in params:
            return Resp(400, {"error": {"message": "Invalid page size"}})
        return Resp(200, {"value": [{"id": "e1"}]})

    c, s = client(handler)
    assert list(c.list_group_membership_audits("2026-04-28T19:00:00Z")) == [{"id": "e1"}]
    assert len(s.requests) == 2 and "$top" in s.requests[0][1] and "$top" not in s.requests[1][1]


def test_audit_query_follows_next_link():
    def handler(url, params):
        if "page2" in url:
            return Resp(200, {"value": [{"id": "e2"}]})
        return Resp(200, {"value": [{"id": "e1"}], "@odata.nextLink": "https://graph.microsoft.com/v1.0/x?page2"})

    c, _ = client(handler)
    assert [e["id"] for e in c.list_group_membership_audits("2026-04-28T19:00:00Z")] == ["e1", "e2"]


def test_audit_query_does_not_swallow_other_errors():
    c, _ = client(lambda u, p: Resp(500, {"error": {"message": "boom"}}))
    c.MAX_RETRIES = 0
    try:
        list(c.list_group_membership_audits("2026-04-28T19:00:00Z"))
    except GraphError as e:
        assert e.status == 500
    else:
        raise AssertionError("expected GraphError")


def test_role_assignments_expand_only_principal():
    c, s = client(lambda u, p: Resp(200, {"value": []}))
    list(c.list_role_assignments())
    assert s.requests[0][1] == {"$expand": "principal"}
    assert s.requests[0][0].endswith("/roleManagement/directory/roleAssignments")


def test_audit_filter_uses_z_datetime_without_offset(monkeypatch):
    from datetime import datetime, timezone
    from broom365.services.sync import _odata_dt
    out = _odata_dt(datetime(2026, 4, 28, 19, 0, 0, 123456, tzinfo=timezone.utc))
    assert out == "2026-04-28T19:00:00Z" and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", out)


# --------------------------------------------------------------- users in batches ---
G1 = "11111111-2222-3333-4444-555555555555"
G2 = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def test_users_by_ids_builds_one_in_filter_and_uses_beta_only_for_sign_in():
    c, s = client(lambda u, p: Resp(200, {"value": [{"id": G1}]}))
    assert c.users_by_ids([G1, G2], with_sign_in=True) == [{"id": G1}]
    url, params = s.requests[0]
    assert "/beta/users" in url and params["$filter"] == f"id in ('{G1}','{G2}')" and "signInActivity" in params["$select"]
    c.users_by_ids([G1], with_sign_in=False)
    url, params = s.requests[1]
    assert "/v1.0/users" in url and "signInActivity" not in params["$select"]


def test_users_by_ids_ignores_non_guid_ids_so_nothing_odd_reaches_the_filter():
    c, s = client(lambda u, p: Resp(200, {"value": []}))
    c.users_by_ids([G1, "x') or id ne ('y", "u1"], with_sign_in=False)
    assert s.requests[0][1]["$filter"] == f"id in ('{G1}')"
    c.users_by_ids(["u1", ""], with_sign_in=False)
    assert len(s.requests) == 1  # nothing valid: no request at all


def test_users_by_ids_refuses_more_than_the_filter_limit():
    import pytest
    c, _ = client(lambda u, p: Resp(200, {"value": []}))
    with pytest.raises(ValueError):
        c.users_by_ids([G1] * 16)
