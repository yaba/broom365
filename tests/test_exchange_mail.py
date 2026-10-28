"""Shared/room/equipment mailbox findings and mail flow rule findings (pure), plus the new read-only client calls."""
from datetime import datetime, timedelta, timezone

import pytest

from broom365.models.types import Delegate, FlagCode as F, MailboxFacts, RuleFacts, Thresholds
from broom365.services.exchange import ExchangeClient
from broom365.services.exchange_mail import (classify_trustee, evaluate_mailbox, evaluate_rule, extract_addresses, full_access_trustees,
                                             send_as_trustees)
from tests.test_exchange_client import Resp, client

NOW = datetime(2026, 10, 26, tzinfo=timezone.utc)
T = Thresholds()


def ago(days):
    return NOW - timedelta(days=days)


def box(**kw):
    base = dict(id="m1", mailbox_type="SharedMailbox", display_name="Support", address="support@x.com", created_at=ago(900), checked=True,
                last_logon_at=ago(5), logon_known=True, item_count=10, last_mail_at=ago(1), traffic_known=True, delegates_known=True,
                full_access=(Delegate("ann@x.com", "active"),))
    base.update(kw)
    return MailboxFacts(**base)


def codes(a):
    return {f.code for f in a.flags}


# ------------------------------------------------------------- parsing -------
def test_full_access_ignores_inherited_denied_and_system_accounts():
    rows = [{"User": "NT AUTHORITY\\SELF", "AccessRights": ["FullAccess, ReadPermission"]},
            {"User": "Domain Admins", "AccessRights": ["FullAccess"], "IsInherited": True},
            {"User": "bad@x.com", "AccessRights": ["FullAccess"], "Deny": True},
            {"User": "ann@x.com", "AccessRights": ["FullAccess, ReadPermission"], "IsInherited": False},
            {"User": "ann@x.com", "AccessRights": ["FullAccess"]},
            {"User": "bob@x.com", "AccessRights": ["ReadPermission"]},
            {"User": "S-1-5-21-1-2-3-9", "AccessRights": ["FullAccess, ExternalAccount"]}]
    assert full_access_trustees(rows) == ["ann@x.com", "S-1-5-21-1-2-3-9"]


def test_send_as_keeps_allowed_direct_trustees_only():
    rows = [{"Trustee": "NT AUTHORITY\\SELF", "AccessRights": ["SendAs"], "AccessControlType": "Allow"},
            {"Trustee": "ann@x.com", "AccessRights": ["SendAs"], "AccessControlType": "Allow", "IsInherited": False},
            {"Trustee": "bob@x.com", "AccessRights": ["SendAs"], "AccessControlType": "Deny"},
            {"Trustee": "cy@x.com", "AccessRights": ["SendAs"], "AccessControlType": "Allow", "IsInherited": True}]
    assert send_as_trustees(rows) == ["ann@x.com"]


def test_trustees_are_classified_from_the_internal_users():
    accounts = {"ann@x.com": True, "gone@x.com": False}
    assert [classify_trustee(n, accounts) for n in ("ANN@x.com", "gone@x.com", "S-1-5-21-1-2-3", "Sales Group")] == [
        "active", "disabled", "deleted", "unknown"]


def test_rule_addresses_are_found_in_any_field_without_quotes():
    rule = {"Name": "n@x.com", "SentTo": ["A@x.com", "b@y.org"], "Actions": {"x": "redirect to c@x.com"}, "Description": "d@x.com", "Empty": None}
    assert extract_addresses(rule) == ["a@x.com", "b@y.org", "c@x.com"]


# ------------------------------------------------------------- mailboxes -----
def test_a_used_shared_mailbox_has_no_findings():
    assert evaluate_mailbox(box(), T, NOW).flags == ()


def test_unchecked_mailboxes_say_so_and_have_no_flags():
    a = evaluate_mailbox(box(checked=False), T, NOW)
    assert a.flags == () and "not checked" in a.unavailable_signals[0]


def test_no_sign_in_and_no_mail_is_no_activity():
    a = evaluate_mailbox(box(last_logon_at=ago(400), last_mail_at=None), T, NOW)
    assert codes(a) == {F.MAILBOX_NO_ACTIVITY} and "400" not in a.flags[0].explanation and "2025-" in a.flags[0].explanation


def test_mail_or_a_recent_sign_in_means_activity():
    assert not evaluate_mailbox(box(last_logon_at=ago(400), last_mail_at=ago(10)), T, NOW).flags
    assert not evaluate_mailbox(box(last_logon_at=ago(10), last_mail_at=None), T, NOW).flags


def test_never_signed_in_counts_as_idle():
    a = evaluate_mailbox(box(last_logon_at=None, last_mail_at=None), T, NOW)
    assert F.MAILBOX_NO_ACTIVITY in codes(a) and "never signed in" in a.flags[0].explanation


def test_the_idle_threshold_is_configurable():
    b = box(last_logon_at=ago(60), last_mail_at=None)
    assert not evaluate_mailbox(b, T, NOW).flags and F.MAILBOX_NO_ACTIVITY in codes(evaluate_mailbox(b, Thresholds(stale_days_mailbox=30), NOW))


def test_a_shared_mailbox_nobody_can_open_is_flagged_and_unused_when_also_idle():
    gone = (Delegate("gone@x.com", "disabled"), Delegate("S-1-5-21-1", "deleted"))
    a = evaluate_mailbox(box(full_access=gone), T, NOW)
    assert codes(a) == {F.MAILBOX_NO_DELEGATES} and "gone@x.com" in a.flags[0].explanation
    idle = evaluate_mailbox(box(full_access=gone, last_logon_at=None, last_mail_at=None), T, NOW)
    assert codes(idle) == {F.MAILBOX_NO_ACTIVITY, F.MAILBOX_NO_DELEGATES, F.LIKELY_UNUSED_MAILBOX}
    assert "safe to delete" not in " ".join(f.explanation for f in idle.flags).lower() and "Candidate for review" in idle.flags[-1].explanation


def test_a_group_or_guest_holder_counts_as_usable_because_it_cannot_be_judged():
    assert not evaluate_mailbox(box(full_access=(Delegate("Sales Group", "unknown"),)), T, NOW).flags


def test_a_usable_send_as_holder_keeps_a_silent_mailbox_from_being_unused():
    b = box(full_access=(), send_as=(Delegate("ann@x.com", "active"),), last_logon_at=None, last_mail_at=None)
    assert codes(evaluate_mailbox(b, T, NOW)) == {F.MAILBOX_NO_ACTIVITY, F.MAILBOX_NO_DELEGATES}


def test_dead_holders_next_to_live_ones_are_a_low_finding():
    a = evaluate_mailbox(box(full_access=(Delegate("ann@x.com", "active"), Delegate("S-1-5-21-1", "deleted"))), T, NOW)
    assert codes(a) == {F.MAILBOX_ORPHAN_DELEGATES} and a.risk.value == "LOW"


def test_a_silent_room_is_unused_without_looking_at_delegates():
    a = evaluate_mailbox(box(mailbox_type="RoomMailbox", full_access=(), last_logon_at=None, last_mail_at=None), T, NOW)
    assert codes(a) == {F.MAILBOX_NO_ACTIVITY, F.LIKELY_UNUSED_MAILBOX}
    assert not evaluate_mailbox(box(mailbox_type="RoomMailbox", full_access=()), T, NOW).flags     # rooms need no Full Access holder


def test_unread_signals_are_reported_not_guessed():
    a = evaluate_mailbox(box(logon_known=False, traffic_known=False, delegates_known=False, full_access=(), last_logon_at=None, last_mail_at=None), T, NOW)
    assert a.flags == () and len(a.unavailable_signals) == 3


# ----------------------------------------------------------------- rules -----
def rule(**kw):
    base = dict(name="R", state="Enabled", mode="Enforce", priority=1, changed_at=ago(100), references_checked=True)
    base.update(kw)
    return RuleFacts(**base)


def test_a_normal_rule_has_no_findings():
    assert evaluate_rule(rule(), NOW).flags == ()


@pytest.mark.parametrize("kw,code", [({"state": "Disabled"}, F.RULE_DISABLED), ({"expiry_at": ago(1)}, F.RULE_EXPIRED),
                                     ({"mode": "AuditAndNotify"}, F.RULE_NOT_ENFORCING),
                                     ({"dead_references": ("old@x.com",)}, F.RULE_DEAD_REFERENCE)])
def test_each_rule_finding(kw, code):
    a = evaluate_rule(rule(**kw), NOW)
    assert codes(a) == {code} and a.risk.value == "LOW"


def test_a_future_expiry_is_not_a_finding_and_unchecked_references_are_reported():
    a = evaluate_rule(rule(expiry_at=NOW + timedelta(days=30), references_checked=False), NOW)
    assert a.flags == () and "not checked" in a.unavailable_signals[0]


def test_dead_reference_wording_admits_aliases_may_exist():
    text = evaluate_rule(rule(dead_references=("a@x.com", "b@x.com")), NOW).flags[0].explanation
    assert "contacts" in text and "a@x.com" in text


# ------------------------------------------------------------- the client ----
def test_the_new_calls_are_plain_get_cmdlets():
    c, s = client(lambda u, p: Resp(body={"value": [{"DomainName": "X.com"}, {"DomainName": "y.onmicrosoft.com"}]}))
    assert c.accepted_domains() == ["x.com", "y.onmicrosoft.com"]
    c.mailbox_permissions("m1")
    c.recipient_permissions("m1")
    assert [(p["CmdletName"], p["Parameters"]) for _, p, _ in s.calls] == [
        ("Get-AcceptedDomain", {}), ("Get-MailboxPermission", {"Identity": "m1"}), ("Get-RecipientPermission", {"Identity": "m1"})]


def test_mailbox_statistics_returns_the_row_or_none():
    c, _ = client(lambda u, p: Resp(body={"value": [{"LastLogonTime": "2024-01-01T00:00:00", "ItemCount": 3}]}))
    assert c.mailbox_statistics("m1")["ItemCount"] == 3
    c2, _ = client(lambda u, p: Resp(body={"value": []}))
    assert c2.mailbox_statistics("m1") is None
