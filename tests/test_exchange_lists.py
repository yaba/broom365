from datetime import datetime, timedelta, timezone

from broom365.models.types import DistributionListFacts, FlagCode as F, RiskLevel as R
from broom365.services.exchange import TRACE_WINDOW_DAYS
from broom365.services.exchange_lists import evaluate_distribution_list

NOW = datetime(2026, 10, 25, tzinfo=timezone.utc)


def ago(days):
    return NOW - timedelta(days=days)


def dl(**kw):
    base = dict(id="d1", kind="distribution", display_name="Old Project", address="old@x.com", created_at=ago(2000), changed_at=ago(1500),
                owners=("Ann",), synced=False, rules=(), rules_known=True, checked=True, member_count=5, last_mail_at=ago(3), traffic_known=True)
    base.update(kw)
    return DistributionListFacts(**base)


def codes(**kw):
    return evaluate_distribution_list(dl(**kw), NOW).codes


def test_a_healthy_list_is_not_flagged():
    assert evaluate_distribution_list(dl(), NOW).flags == ()


def test_no_owner_comes_from_the_inventory_alone_and_is_low():
    a = evaluate_distribution_list(dl(owners=(), checked=False, member_count=None, last_mail_at=None, traffic_known=False), NOW)
    assert a.codes == {F.DL_NO_OWNER} and a.risk is R.LOW
    assert "not checked yet" in a.unavailable_signals[0]


def test_an_empty_list_is_flagged_medium():
    a = evaluate_distribution_list(dl(member_count=0), NOW)
    assert a.codes == {F.DL_EMPTY} and a.risk is R.MEDIUM and "goes nowhere" in a.flags[0].explanation


def test_no_mail_in_the_window_is_flagged_and_names_the_window():
    a = evaluate_distribution_list(dl(last_mail_at=None), NOW)
    f = next(x for x in a.flags if x.code is F.DL_NO_MAIL)
    assert f"last {TRACE_WINDOW_DAYS} days" in f.explanation and "No transport rule mentions it" in f.explanation


def test_recent_mail_means_not_unused():
    assert F.DL_NO_MAIL not in codes(last_mail_at=ago(80))


def test_empty_and_no_mail_and_no_rule_is_likely_unused_with_the_reason():
    a = evaluate_distribution_list(dl(member_count=0, last_mail_at=None), NOW)
    assert {F.DL_EMPTY, F.DL_NO_MAIL, F.LIKELY_UNUSED_DL} <= a.codes
    text = next(x for x in a.flags if x.code is F.LIKELY_UNUSED_DL).explanation
    assert "it has no members" in text and "candidate for review" in text and "safe to delete" not in text.lower()
    assert "shared mailbox and calendar permissions" in text and "created 2021" in text.replace("created 2021", "created 2021")


def test_ownerless_and_no_mail_is_likely_unused_even_with_members():
    text = next(x for x in evaluate_distribution_list(dl(owners=(), last_mail_at=None), NOW).flags if x.code is F.LIKELY_UNUSED_DL).explanation
    assert "it has no owner" in text and "no members" not in text


def test_owned_populated_list_without_mail_is_not_called_unused():
    a = evaluate_distribution_list(dl(last_mail_at=None), NOW)
    assert F.DL_NO_MAIL in a.codes and F.LIKELY_UNUSED_DL not in a.codes


def test_a_transport_rule_that_mentions_the_list_protects_it_from_likely_unused():
    a = evaluate_distribution_list(dl(member_count=0, last_mail_at=None, rules=("Archive finance mail",)), NOW)
    assert F.LIKELY_UNUSED_DL not in a.codes and "A transport rule mentions it: 'Archive finance mail'" in next(
        x for x in a.flags if x.code is F.DL_NO_MAIL).explanation


def test_unreadable_transport_rules_never_allow_the_unused_verdict():
    a = evaluate_distribution_list(dl(member_count=0, last_mail_at=None, rules_known=False), NOW)
    assert F.LIKELY_UNUSED_DL not in a.codes and "Transport rules could not be read" in next(x for x in a.flags if x.code is F.DL_NO_MAIL).explanation


def test_unreadable_traffic_is_not_called_no_mail():
    a = evaluate_distribution_list(dl(last_mail_at=None, traffic_known=False), NOW)
    assert F.DL_NO_MAIL not in a.codes and any("message trace" in u for u in a.unavailable_signals)


def test_unreadable_member_count_is_disclosed_not_called_empty():
    a = evaluate_distribution_list(dl(member_count=None), NOW)
    assert F.DL_EMPTY not in a.codes and any("Member count" in u for u in a.unavailable_signals)


def test_synced_lists_are_told_to_be_changed_on_premises():
    a = evaluate_distribution_list(dl(owners=(), synced=True), NOW)
    assert "must be changed there" in a.flags[0].explanation


def test_the_kind_is_named_in_the_text():
    assert "mail-enabled security group" in evaluate_distribution_list(dl(kind="security", owners=()), NOW).flags[0].explanation
    assert "dynamic distribution list" in evaluate_distribution_list(dl(kind="dynamic", owners=()), NOW).flags[0].explanation
