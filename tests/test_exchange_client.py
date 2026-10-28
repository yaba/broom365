from datetime import datetime, timedelta, timezone

import pytest

from broom365.services.exchange import ExchangeClient, TRACE_WINDOW_DAYS
from broom365.services.graph import GraphError, SignalUnavailable

NOW = datetime(2026, 10, 25, 12, 0, 0, tzinfo=timezone.utc)


class Resp:
    def __init__(self, status=200, body=None, headers=None):
        self.status_code, self._body, self.headers = status, body if body is not None else {"value": []}, headers or {}

    @property
    def ok(self):
        return self.status_code < 400

    @property
    def text(self):
        return str(self._body)

    @property
    def content(self):
        return b"x"

    def json(self):
        return self._body


class Session:
    """Records every POST; `handler(url, payload)` returns a Resp."""

    def __init__(self, handler):
        self.handler, self.calls = handler, []

    def post(self, url, json=None, headers=None, timeout=None):
        self.calls.append((url, json["CmdletInput"], headers))
        return self.handler(url, json["CmdletInput"])


def client(handler):
    s = Session(handler)
    return ExchangeClient(lambda: "tok", "tenant-1", s), s


@pytest.mark.parametrize("cmdlet", ["Set-Mailbox", "Remove-DistributionGroup", "New-TransportRule", "Add-DistributionGroupMember",
                                    "Invoke-Anything", "get-distributiongroup", ""])
def test_anything_but_get_cmdlets_is_refused_before_any_request(cmdlet):
    c, s = client(lambda u, p: Resp())
    with pytest.raises(ValueError, match="read-only"):
        c.invoke(cmdlet)
    assert s.calls == []


def test_every_typed_read_uses_only_get_cmdlets():
    c, s = client(lambda u, p: Resp(body={"value": [{"Identity": "x"}]}))
    c.distribution_groups(); c.dynamic_distribution_groups(); c.transport_rules(); c.mailboxes(); c.member_count("a@x.com")
    c.member_count("d@x.com", dynamic=True); c.last_mail_received("a@x.com", NOW)
    assert s.calls and all(call[1]["CmdletName"].startswith("Get-") for call in s.calls)


def test_request_shape_and_headers():
    c, s = client(lambda u, p: Resp())
    c.distribution_groups()
    url, payload, headers = s.calls[0]
    assert url == "https://outlook.office365.com/adminapi/beta/tenant-1/InvokeCommand"
    assert payload == {"CmdletName": "Get-DistributionGroup", "Parameters": {"ResultSize": "Unlimited"}}
    assert headers["Authorization"] == "Bearer tok" and headers["Accept-Encoding"] == "identity" and "AnchorMailbox" in str(headers)


def test_pages_are_followed_through_next_link():
    def handler(url, payload):
        if url.endswith("page2"):
            return Resp(body={"value": [{"n": 3}]})
        return Resp(body={"value": [{"n": 1}, {"n": 2}], "@odata.nextLink": "https://outlook.office365.com/adminapi/beta/t/InvokeCommand?page2"})

    c, s = client(handler)
    assert [r["n"] for r in c.invoke("Get-Thing")] == [1, 2, 3] and len(s.calls) == 2


def test_mailboxes_are_requested_by_type_only():
    c, s = client(lambda u, p: Resp())
    c.mailboxes()
    assert s.calls[0][1]["Parameters"]["RecipientTypeDetails"] == ["SharedMailbox", "RoomMailbox", "EquipmentMailbox"]


def test_403_means_the_signal_is_unavailable_and_other_errors_are_graph_errors():
    c, _ = client(lambda u, p: Resp(403, {"error": {"message": "role missing"}}))
    with pytest.raises(SignalUnavailable):
        c.distribution_groups()
    c, _ = client(lambda u, p: Resp(400, {"error": {"message": "Error executing cmdlet"}}))
    with pytest.raises(GraphError) as e:
        c.distribution_groups()
    assert e.value.status == 400 and not isinstance(e.value, SignalUnavailable)


def test_no_token_is_reported_as_unavailable_without_a_request():
    s = Session(lambda u, p: Resp())
    with pytest.raises(SignalUnavailable):
        ExchangeClient(lambda: None, "t", s).distribution_groups()
    assert s.calls == []


def test_throttling_is_retried(monkeypatch):
    monkeypatch.setattr("broom365.services.exchange.time.sleep", lambda s: None)
    seen = []

    def handler(url, payload):
        seen.append(1)
        return Resp(429, {}, {"Retry-After": "1"}) if len(seen) == 1 else Resp(body={"value": [{"ok": True}]})

    c, _ = client(handler)
    assert c.distribution_groups() == [{"ok": True}] and len(seen) == 2


def test_member_count_counts_rows():
    c, s = client(lambda u, p: Resp(body={"value": [{"a": 1}, {"a": 2}, {"a": 3}]}))
    assert c.member_count("list@x.com") == 3 and s.calls[0][1]["Parameters"]["Identity"] == "list@x.com"


# ---------------------------------------------------------------- message trace ---
def trace_handler(mail_days_ago):
    """A message exists only in the 10-day slice that contains `mail_days_ago`."""
    def handler(url, payload):
        p = payload["Parameters"]
        start = datetime.strptime(p["StartDate"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        end = datetime.strptime(p["EndDate"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        when = NOW - timedelta(days=mail_days_ago) if mail_days_ago is not None else None
        if when and start <= when <= end:
            return Resp(body={"value": [{"Received": when.strftime("%Y-%m-%dT%H:%M:%S.123Z")}]})
        return Resp()
    return handler


def test_recent_mail_is_found_in_the_first_slice_and_the_search_stops():
    c, s = client(trace_handler(3))
    got = c.last_mail_received("dl@x.com", NOW)
    assert got is not None and round((NOW - got).total_seconds() / 86400) == 3 and len(s.calls) == 1


def test_old_mail_is_found_by_walking_back_in_ten_day_slices():
    c, s = client(trace_handler(47))
    got = c.last_mail_received("dl@x.com", NOW)
    assert round((NOW - got).total_seconds() / 86400) == 47 and len(s.calls) == 5   # slices 0-10, 10-20, 20-30, 30-40, 40-50


def test_a_list_with_no_mail_is_checked_over_the_whole_window_and_returns_none():
    c, s = client(trace_handler(None))
    assert c.last_mail_received("dl@x.com", NOW) is None
    assert len(s.calls) == 9   # 89 days in 10-day slices
    starts = [datetime.strptime(call[1]["Parameters"]["StartDate"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) for call in s.calls]
    assert min(starts) == NOW - timedelta(days=TRACE_WINDOW_DAYS)   # never asks beyond 89 days (the service errors past 90)


def test_no_slice_is_wider_than_ten_days_and_slices_do_not_overlap_the_future():
    c, s = client(trace_handler(None))
    c.last_mail_received("dl@x.com", NOW)
    for call in s.calls:
        p = call[1]["Parameters"]
        a = datetime.strptime(p["StartDate"], "%Y-%m-%dT%H:%M:%SZ"); b = datetime.strptime(p["EndDate"], "%Y-%m-%dT%H:%M:%SZ")
        assert timedelta(0) < b - a <= timedelta(days=10) and b <= NOW.replace(tzinfo=None)


def test_the_newest_message_of_the_slice_is_reported():
    def handler(url, payload):
        return Resp(body={"value": [{"Received": "2026-10-01T10:00:00Z"}, {"Received": "2026-10-04T10:00:00Z"}, {"Received": "2026-10-02T10:00:00Z"}]})

    c, _ = client(handler)
    assert c.last_mail_received("dl@x.com", NOW) == datetime(2026, 10, 4, 10, 0, tzinfo=timezone.utc)


def test_trace_asks_for_the_address_as_recipient():
    c, s = client(trace_handler(None))
    c.last_mail_received("team@x.com", NOW)
    assert all(call[1]["Parameters"]["RecipientAddress"] == "team@x.com" for call in s.calls)
