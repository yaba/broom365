from datetime import datetime, timedelta, timezone

import pytest

from broom365.models.types import FlagCode as F, GuestFacts, GuestMembership as M, RiskLevel as R, Thresholds
from broom365.services.guests import evaluate_guest, guest_domain

NOW = datetime(2026, 10, 25, tzinfo=timezone.utc)
T = Thresholds()


def ago(days):
    return NOW - timedelta(days=days)


def guest(**kw):
    base = dict(id="g1", display_name="Pat", mail="pat@partner-corp.com", user_principal_name="pat_partner-corp.com#EXT#@t.onmicrosoft.com",
                account_enabled=True, created_at=ago(1500), external_state="Accepted", state_changed_at=ago(1500),
                last_sign_in_at=ago(10), sign_in_available=True)
    base.update(kw)
    return GuestFacts(**base)


def test_guest_used_four_years_ago_and_never_back_is_stale_medium():
    a = evaluate_guest(guest(last_sign_in_at=ago(1460)), T, NOW)
    assert a.codes == {F.STALE_GUEST} and a.risk is R.MEDIUM
    text = a.flags[0].explanation
    assert "External guest from partner-corp.com" in text and "1460 days ago" in text and "threshold 365" in text
    assert "Candidate for review" in text and "safe to delete" not in text.lower()


def test_recently_active_guest_is_not_flagged():
    assert evaluate_guest(guest(), T, NOW).flags == ()


def test_threshold_boundary():
    assert evaluate_guest(guest(last_sign_in_at=ago(365)), T, NOW).flags == ()
    assert evaluate_guest(guest(last_sign_in_at=ago(366)), T, NOW).codes == {F.STALE_GUEST}
    assert evaluate_guest(guest(last_sign_in_at=ago(100)), Thresholds(stale_days_guest=60), NOW).codes == {F.STALE_GUEST}


def test_guest_who_never_signed_in_is_stale_by_the_date_it_was_added():
    a = evaluate_guest(guest(last_sign_in_at=None, created_at=ago(800), state_changed_at=ago(800)), T, NOW)
    assert a.codes == {F.STALE_GUEST} and "no sign-in on record" in a.flags[0].explanation and "800 days ago" in a.flags[0].explanation
    assert evaluate_guest(guest(last_sign_in_at=None, created_at=ago(30), state_changed_at=ago(30)), T, NOW).flags == ()


def test_disabled_stale_guest_is_only_low_and_says_it_is_inert():
    a = evaluate_guest(guest(account_enabled=False, last_sign_in_at=ago(1500)), T, NOW)
    assert a.risk is R.LOW and "already inert" in a.flags[0].explanation


def test_pending_invitation_is_flagged_after_the_threshold_and_not_also_stale():
    a = evaluate_guest(guest(external_state="PendingAcceptance", last_sign_in_at=None, created_at=ago(200), state_changed_at=ago(200)), T, NOW)
    assert a.codes == {F.PENDING_GUEST} and a.risk is R.LOW and "never accepted" in a.flags[0].explanation
    fresh = evaluate_guest(guest(external_state="PendingAcceptance", last_sign_in_at=None, created_at=ago(5), state_changed_at=ago(5)), T, NOW)
    assert fresh.flags == ()


def test_pending_guest_is_still_found_without_sign_in_data_but_stale_is_not_guessed():
    pending = evaluate_guest(guest(external_state="PendingAcceptance", sign_in_available=False, last_sign_in_at=None,
                                   state_changed_at=ago(200)), T, NOW)
    assert pending.codes == {F.PENDING_GUEST}
    accepted = evaluate_guest(guest(sign_in_available=False, last_sign_in_at=None), T, NOW)
    assert accepted.flags == () and "unavailable" in accepted.unavailable_signals[0]


def test_unknown_state_older_guest_uses_sign_in_only():
    assert evaluate_guest(guest(external_state=None, last_sign_in_at=ago(2000)), T, NOW).codes == {F.STALE_GUEST}


@pytest.mark.parametrize("mail,upn,expected", [
    ("pat@Partner-Corp.com", None, "partner-corp.com"),
    (None, "pat_partner-corp.com#EXT#@t.onmicrosoft.com", "partner-corp.com"),
    (None, "first_last_other.org#EXT#@t.onmicrosoft.com", "other.org"),
    (None, "member@t.onmicrosoft.com", None), (None, None, None), ("no-at-sign", None, None)])
def test_guest_domain(mail, upn, expected):
    assert guest_domain(mail, upn) == expected


def test_company_domain_is_named_even_when_only_the_upn_is_known():
    assert "from partner-corp.com" in evaluate_guest(guest(mail=None, last_sign_in_at=ago(900)), T, NOW).flags[0].explanation


# ----------------------------------------------------- what access is still open ---
def stale(**kw):
    return guest(last_sign_in_at=ago(1460), **kw)


def test_unchecked_memberships_are_disclosed_not_guessed():
    a = evaluate_guest(stale(), T, NOW)
    assert "member of" not in a.flags[0].explanation and a.flags[0].evidence["member_of"] is None
    assert "not checked yet" in a.unavailable_signals[0]


def test_a_stale_guest_with_no_group_says_so():
    a = evaluate_guest(stale(memberships=()), T, NOW)
    assert "member of no group" in a.flags[0].explanation and a.flags[0].evidence["member_of"] == [] and a.unavailable_signals == ()


def test_teams_come_first_and_the_list_is_capped():
    members = tuple([M("t", "Project Atlas", "team")] + [M(f"g{i}", f"Group {i}", "security") for i in range(6)])
    text = evaluate_guest(stale(memberships=members), T, NOW).flags[0].explanation
    assert "still a member of 7 group(s) by assignment: 'Project Atlas' (Team), 'Group 0'" in text and "and 3 more" in text
    assert "Group 5" not in text


def test_memberships_also_appear_on_pending_guests():
    a = evaluate_guest(guest(external_state="PendingAcceptance", last_sign_in_at=None, created_at=ago(200), state_changed_at=ago(200),
                             memberships=(M("g", "Partners", "security"),)), T, NOW)
    assert a.codes == {F.PENDING_GUEST} and "'Partners'" in a.flags[0].explanation


def test_memberships_do_not_change_the_risk():
    assert evaluate_guest(stale(memberships=(M("g", "X", "team"),)), T, NOW).risk is R.MEDIUM
    assert evaluate_guest(stale(memberships=()), T, NOW).risk is R.MEDIUM


# --------------------------------- dynamic (rule-based) groups are not granted access ---
ALL = M("g-all", "All Users", "security", True)


def test_only_dynamic_memberships_say_no_deliberate_access_would_be_lost():
    text = evaluate_guest(stale(memberships=(ALL, M("g-all2", "All Users - b0b0", "security", True))), T, NOW).flags[0].explanation
    assert "no group by assignment, only to 2 dynamic (rule-based) group(s) such as 'All Users'" in text
    assert "no deliberate group access would be lost" in text and "still a member" not in text


def test_assigned_and_dynamic_memberships_are_reported_apart():
    text = evaluate_guest(stale(memberships=(ALL, M("t", "Project Atlas", "team", False), M("s", "Partners", "security", False))), T, NOW).flags[0].explanation
    assert "still a member of 2 group(s) by assignment: 'Project Atlas' (Team), 'Partners'" in text
    assert "It is also in 1 dynamic (rule-based) group(s) such as 'All Users'" in text


def test_a_group_missing_from_the_inventory_counts_as_assigned():
    text = evaluate_guest(stale(memberships=(M("x", "Mystery", "security", None),)), T, NOW).flags[0].explanation
    assert "by assignment: 'Mystery'" in text


def test_evidence_counts_dynamic_groups_separately():
    ev = evaluate_guest(stale(memberships=(ALL, M("s", "Partners", "security", False))), T, NOW).flags[0].evidence
    assert ev["member_of"] == ["'Partners'"] and ev["dynamic_groups"] == 1
