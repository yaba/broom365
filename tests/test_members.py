from datetime import datetime, timedelta, timezone

from broom365.models.types import FlagCode as F, MemberFacts, RiskLevel as R, Thresholds
from broom365.services.members import FREE_LICENCES, evaluate_member, paid_licences

NOW = datetime(2026, 10, 25, tzinfo=timezone.utc)
T = Thresholds()


def ago(days):
    return NOW - timedelta(days=days)


def member(**kw):
    base = dict(id="m1", display_name="Ivan", mail="ivan@x.com", user_principal_name="ivan@x.com", account_enabled=True,
                created_at=ago(1000), on_prem_synced=False, licences=("SPE_E3",), last_sign_in_at=ago(5), sign_in_available=True)
    base.update(kw)
    return MemberFacts(**base)


def test_active_account_is_not_flagged():
    assert evaluate_member(member(), T, NOW).flags == ()


def test_disabled_account_with_a_paid_licence_is_medium_and_says_what_to_do():
    a = evaluate_member(member(account_enabled=False, licences=("SPE_E3", "FLOW_FREE")), T, NOW)
    assert a.codes == {F.DISABLED_LICENSED_MEMBER} and a.risk is R.MEDIUM
    text = a.flags[0].explanation
    assert "1 paid licence(s): SPE_E3" in text and "FLOW_FREE" not in text and "remove them" in text and "safe to delete" not in text.lower()


def test_disabled_account_with_only_free_licences_or_none_is_not_flagged():
    assert evaluate_member(member(account_enabled=False, licences=("FLOW_FREE", "POWER_BI_STANDARD")), T, NOW).flags == ()
    assert evaluate_member(member(account_enabled=False, licences=()), T, NOW).flags == ()


def test_disabled_account_needs_no_sign_in_data():
    a = evaluate_member(member(account_enabled=False, sign_in_available=False, last_sign_in_at=None), T, NOW)
    assert a.codes == {F.DISABLED_LICENSED_MEMBER} and a.unavailable_signals == ()


def test_stale_enabled_account_with_a_paid_licence_is_medium_without_it_is_low():
    paid = evaluate_member(member(last_sign_in_at=ago(400)), T, NOW)
    assert paid.codes == {F.STALE_MEMBER} and paid.risk is R.MEDIUM and "paid licence(s): SPE_E3" in paid.flags[0].explanation
    free = evaluate_member(member(last_sign_in_at=ago(400), licences=("FLOW_FREE",)), T, NOW)
    assert free.risk is R.LOW and "holds no paid licence" in free.flags[0].explanation


def test_threshold_boundary_and_custom_threshold():
    assert evaluate_member(member(last_sign_in_at=ago(180)), T, NOW).flags == ()
    assert evaluate_member(member(last_sign_in_at=ago(181)), T, NOW).codes == {F.STALE_MEMBER}
    assert evaluate_member(member(last_sign_in_at=ago(50)), Thresholds(stale_days_member=30), NOW).codes == {F.STALE_MEMBER}


def test_never_signed_in_is_stale_only_if_the_account_is_old_enough():
    a = evaluate_member(member(last_sign_in_at=None, created_at=ago(800)), T, NOW)
    assert a.codes == {F.STALE_MEMBER} and "no sign-in on record" in a.flags[0].explanation and "800 days ago" in a.flags[0].explanation
    assert evaluate_member(member(last_sign_in_at=None, created_at=ago(20)), T, NOW).flags == ()
    assert evaluate_member(member(last_sign_in_at=None, created_at=None), T, NOW).flags == ()


def test_unreadable_sign_in_is_disclosed_not_guessed():
    a = evaluate_member(member(sign_in_available=False, last_sign_in_at=None), T, NOW)
    assert a.flags == () and "unavailable" in a.unavailable_signals[0]


def test_accounts_synced_from_ad_are_called_out():
    a = evaluate_member(member(last_sign_in_at=ago(400), on_prem_synced=True), T, NOW)
    assert "synced from on-premises Active Directory, so it must be changed there" in a.flags[0].explanation
    assert "synced from" not in evaluate_member(member(last_sign_in_at=ago(400)), T, NOW).flags[0].explanation


def test_service_accounts_are_mentioned_as_a_possible_reason():
    assert "Service and shared accounts may not sign in interactively" in evaluate_member(member(last_sign_in_at=ago(400)), T, NOW).flags[0].explanation


def test_paid_licences_are_sorted_and_exclude_the_free_list():
    assert paid_licences(member(licences=("SPE_E3", "FLOW_FREE", "EXCHANGESTANDARD"))) == ["EXCHANGESTANDARD", "SPE_E3"]
    assert {"FLOW_FREE", "POWER_BI_STANDARD"} <= FREE_LICENCES


def test_many_licences_are_capped_in_the_text():
    text = evaluate_member(member(account_enabled=False, licences=tuple(f"SKU_{i}" for i in range(7))), T, NOW).flags[0].explanation
    assert "7 paid licence(s)" in text and "and 3 more" in text


# ------------------------------- disabled leftovers vs mailboxes disabled by design ---
def disabled(**kw):
    return member(account_enabled=False, licences=(), **kw)


def test_disabled_unlicensed_account_is_a_leftover_once_the_mailbox_types_are_known():
    a = evaluate_member(disabled(mailboxes_read=True, last_sign_in_at=ago(900)), T, NOW)
    assert a.codes == {F.DISABLED_MEMBER} and a.risk is R.LOW
    text = a.flags[0].explanation
    assert "not a shared, room or equipment mailbox" in text and "last signed in on" in text and "Candidate for review" in text


def test_a_shared_room_or_equipment_mailbox_is_disabled_by_design_and_not_flagged():
    for kind in ("SharedMailbox", "RoomMailbox", "EquipmentMailbox"):
        assert evaluate_member(disabled(mailboxes_read=True, mailbox_type=kind), T, NOW).flags == (), kind


def test_before_the_mailbox_types_are_read_nothing_is_guessed_and_the_gap_is_stated():
    a = evaluate_member(disabled(mailboxes_read=False), T, NOW)
    assert a.flags == () and "mailbox types not read yet" in a.unavailable_signals[0]


def test_only_free_licences_still_count_as_a_leftover():
    assert evaluate_member(member(account_enabled=False, licences=("FLOW_FREE",), mailboxes_read=True), T, NOW).codes == {F.DISABLED_MEMBER}


def test_a_paid_licence_wins_over_the_leftover_flag():
    a = evaluate_member(member(account_enabled=False, licences=("SPE_E3",), mailboxes_read=True), T, NOW)
    assert a.codes == {F.DISABLED_LICENSED_MEMBER}


def test_leftover_text_without_sign_in_data_does_not_invent_a_date():
    text = evaluate_member(disabled(mailboxes_read=True, sign_in_available=False, last_sign_in_at=None), T, NOW).flags[0].explanation
    assert "last signed in" not in text and "No sign-in is on record" not in text
