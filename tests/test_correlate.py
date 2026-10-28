from datetime import datetime, timedelta, timezone

from broom365.models.types import (
    GroupUsage, AppFacts, Credential, FlagCode as F, GroupAppAssignment, GroupFacts, Permission, RiskLevel as R,
    Thresholds, UserFacts,
)
from broom365.services.correlate import evaluate_group
from broom365.services.extended_signals import evaluate_app, evaluate_user

NOW = datetime(2026, 10, 25, tzinfo=timezone.utc)
T = Thresholds()


def ago(days: int) -> datetime:
    return NOW - timedelta(days=days)


def ahead(days: int) -> datetime:
    return NOW + timedelta(days=days)


def group(**kw) -> GroupFacts:
    base = dict(id="g1", display_name="Team", created_at=ago(30), member_count=5, owner_count=1,
                has_license_assignment=True)
    base.update(kw)
    return GroupFacts(**base)


def assign(exists=True, enabled=True, **kw) -> GroupAppAssignment:
    return GroupAppAssignment("sp1", "Payroll", exists, enabled if exists else None, **kw)


# ------------------------------------------------------------------ groups --
def test_healthy_group_is_low_and_unflagged():
    a = evaluate_group(group(), T, NOW)
    assert a.risk is R.LOW and a.flags == ()


def test_orphaned_assignment_missing_sp_is_high_and_names_deletion_date():
    a = evaluate_group(group(app_assignments=(assign(exists=False, target_deleted_at=ago(10)),)), T, NOW)
    assert a.risk is R.HIGH and F.ORPHANED_APP_ASSIGNMENT in a.codes
    assert "Payroll" in a.flags[0].explanation and "2026-10-15" in a.flags[0].explanation


def test_orphaned_assignment_disabled_sp():
    a = evaluate_group(group(app_assignments=(assign(enabled=False),)), T, NOW)
    assert F.ORPHANED_APP_ASSIGNMENT in a.codes and a.risk is R.HIGH


def test_unknown_sp_enabled_state_is_not_orphaned():
    g = group(app_assignments=(GroupAppAssignment("sp1", "X", True, None),))
    assert F.ORPHANED_APP_ASSIGNMENT not in evaluate_group(g, T, NOW).codes


def test_no_owner_and_empty_is_high():
    a = evaluate_group(group(member_count=0, owner_count=0), T, NOW)
    assert {F.EMPTY_GROUP, F.NO_OWNER} <= a.codes and a.risk is R.HIGH


def test_empty_alone_is_low_and_no_owner_alone_is_low():
    assert evaluate_group(group(member_count=0), T, NOW).risk is R.LOW
    assert evaluate_group(group(owner_count=0), T, NOW).risk is R.LOW


def test_stale_and_empty_is_medium():
    a = evaluate_group(group(member_count=0, created_at=ago(400)), T, NOW)
    assert {F.STALE, F.EMPTY_GROUP} <= a.codes and a.risk is R.MEDIUM


def test_stale_uses_audit_date_over_creation_date():
    g = group(created_at=ago(900), last_membership_change_at=ago(10))
    assert F.STALE not in evaluate_group(g, T, NOW).codes


def test_stale_fallback_to_creation_is_disclosed():
    a = evaluate_group(group(created_at=ago(400)), T, NOW)
    assert F.STALE in a.codes
    assert "creation date" in a.flags[0].explanation
    assert any("Audit-log" in u for u in a.unavailable_signals)


def test_stale_boundary_not_flagged_at_threshold():
    assert F.STALE not in evaluate_group(group(created_at=ago(180)), T, NOW).codes


def test_unknown_use_is_medium_and_never_says_safe():
    a = evaluate_group(group(has_license_assignment=False), T, NOW)
    assert a.risk is R.MEDIUM and F.UNKNOWN_USE in a.codes
    assert "safe to delete" not in a.flags[0].explanation.lower()


def test_unknown_use_names_unchecked_signals():
    a = evaluate_group(group(has_license_assignment=None, unchecked_usage_sources=("intune_apps",)), T, NOW)
    assert "could not check" in a.flags[0].explanation and "Intune apps" in a.flags[0].explanation


def test_unknown_use_suppressed_by_role_or_assignment():
    assert F.UNKNOWN_USE not in evaluate_group(group(has_license_assignment=False, directory_role_names=("X",)), T, NOW).codes
    assert F.UNKNOWN_USE not in evaluate_group(
        group(has_license_assignment=False, app_assignments=(assign(),)), T, NOW).codes


def test_unknown_counts_are_not_treated_as_zero():
    a = evaluate_group(group(member_count=None, owner_count=None), T, NOW)
    assert not ({F.EMPTY_GROUP, F.NO_OWNER, F.UNKNOWN_USE} & a.codes)


def test_privileged_orphan_group_no_owner_is_high():
    a = evaluate_group(group(owner_count=0, directory_role_names=("Global Administrator",)), T, NOW)
    assert F.PRIVILEGED_ORPHAN_GROUP in a.codes and a.risk is R.HIGH


def test_privileged_group_with_owner_not_flagged():
    a = evaluate_group(group(directory_role_names=("Global Administrator",)), T, NOW)
    assert F.PRIVILEGED_ORPHAN_GROUP not in a.codes


def test_privileged_orphan_group_empty_and_stale():
    a = evaluate_group(group(member_count=0, created_at=ago(400), directory_role_names=("User Administrator",)), T, NOW)
    assert F.PRIVILEGED_ORPHAN_GROUP in a.codes


# -------------------------------------------------------------------- apps --
def cred(end, kind="password", key="k1"):
    return Credential(key, kind, "secret", end)


def app(**kw) -> AppFacts:
    base = dict(id="a1", app_id="c1", display_name="App", sign_in_available=True, last_sign_in_at=ago(5))
    base.update(kw)
    return AppFacts(**base)


def test_expired_secret_reports_days_since_expiry_medium_when_none_valid():
    a = evaluate_app(app(credentials=(cred(ago(12)),)), T, NOW)
    f = a.flags[0]
    assert f.code is F.EXPIRED_SECRET and f.risk is R.MEDIUM
    assert f.evidence["credentials"][0]["days_since_expiry"] == 12 and "12 days ago" in f.explanation


def test_expired_secret_with_valid_sibling_is_low_rotation_leftover():
    a = evaluate_app(app(credentials=(cred(ago(12)), cred(ahead(300), key="k2"))), T, NOW)
    assert a.risk is R.LOW and "rotation leftover" in a.flags[0].explanation


def test_expiring_secret_within_window_only():
    a = evaluate_app(app(credentials=(cred(ahead(10)),)), T, NOW)
    assert a.codes == {F.EXPIRING_SECRET}
    assert evaluate_app(app(credentials=(cred(ahead(31)),)), T, NOW).flags == ()


def test_credential_without_end_date_ignored():
    assert evaluate_app(app(credentials=(cred(None),)), T, NOW).flags == ()


def test_likely_abandoned_expired_plus_stale_is_high():
    a = evaluate_app(app(credentials=(cred(ago(40)),), last_sign_in_at=ago(300)), T, NOW)
    assert {F.EXPIRED_SECRET, F.STALE_APP, F.LIKELY_ABANDONED_APP} <= a.codes and a.risk is R.HIGH


def test_expired_but_recently_used_is_not_abandoned():
    a = evaluate_app(app(credentials=(cred(ago(40)),), last_sign_in_at=ago(3)), T, NOW)
    assert F.LIKELY_ABANDONED_APP not in a.codes


def test_no_sign_in_on_record_counts_as_inactive_and_says_so():
    a = evaluate_app(app(last_sign_in_at=None), T, NOW)
    assert F.STALE_APP in a.codes and "no sign-in on record" in a.flags[0].explanation


def test_dangerous_delegated_permission_alone_is_medium_and_names_scope():
    a = evaluate_app(app(permissions=(Permission("delegated", "Microsoft Graph", "mail.read"),)), T, NOW)
    f = a.flags[0]
    assert f.code is F.DANGEROUS_PERMISSION and a.risk is R.MEDIUM
    assert "mail.read" in f.explanation and "unnecessary" not in f.explanation.lower()
    assert "limited to what the signed-in user can do" in f.explanation


def test_the_same_permission_held_as_an_application_role_is_high():
    a = evaluate_app(app(permissions=(Permission("application", "Microsoft Graph", "Mail.Read"),)), T, NOW)
    assert a.flags[0].code is F.DANGEROUS_PERMISSION and a.risk is R.HIGH and "acts tenant-wide" in a.flags[0].explanation


def test_any_application_permission_among_delegated_ones_makes_it_high():
    perms = (Permission("delegated", "Microsoft Graph", "Mail.Read"), Permission("application", "Microsoft Graph", "Files.ReadWrite.All"))
    assert evaluate_app(app(permissions=perms), T, NOW).risk is R.HIGH


# ------------------------------------------------ the second tier: broad directory reads ---
def test_broad_directory_read_is_not_called_dangerous():
    a = evaluate_app(app(permissions=(Permission("application", "Microsoft Graph", "Directory.Read.All"),)), T, NOW)
    assert a.codes == {F.BROAD_READ_PERMISSION} and a.risk is R.MEDIUM
    text = a.flags[0].explanation
    assert "cannot change anything" in text and "Directory.Read.All (application, Microsoft Graph)" in text


def test_broad_read_held_only_as_delegated_is_low():
    a = evaluate_app(app(permissions=(Permission("delegated", "Microsoft Graph", "User.Read.All"),)), T, NOW)
    assert a.codes == {F.BROAD_READ_PERMISSION} and a.risk is R.LOW


def test_content_reads_stay_in_the_dangerous_tier():
    for scope in ("Mail.Read", "Files.Read.All", "Chat.Read.All", "Sites.Read.All", "Calendars.Read"):
        assert evaluate_app(app(permissions=(Permission("delegated", "Microsoft Graph", scope),)), T, NOW).codes == {F.DANGEROUS_PERMISSION}, scope


def test_a_permission_on_both_lists_counts_once_as_dangerous():
    t = Thresholds(high_risk_scopes=("Directory.Read.All",), broad_read_scopes=("Directory.Read.All",))
    a = evaluate_app(app(permissions=(Permission("application", "Microsoft Graph", "Directory.Read.All"),)), t, NOW)
    assert a.codes == {F.DANGEROUS_PERMISSION}


def test_broad_application_read_with_no_sign_in_is_flagged_medium_but_a_delegated_one_is_not():
    app_perm = app(permissions=(Permission("application", "Microsoft Graph", "Directory.Read.All"),), last_sign_in_at=ago(200))
    flag = next(f for f in evaluate_app(app_perm, T, NOW).flags if f.code is F.RISK_WITHOUT_USAGE)
    assert flag.risk is R.MEDIUM and "read access without evidence of use" in flag.explanation
    deleg = app(permissions=(Permission("delegated", "Microsoft Graph", "Directory.Read.All"),), last_sign_in_at=ago(200))
    assert F.RISK_WITHOUT_USAGE not in evaluate_app(deleg, T, NOW).codes


def test_dangerous_permission_without_usage_is_still_high_and_wins_over_the_broad_wording():
    perms = (Permission("application", "Microsoft Graph", "Directory.Read.All"), Permission("delegated", "Microsoft Graph", "Mail.Read"))
    flags = [f for f in evaluate_app(app(permissions=perms, last_sign_in_at=ago(200)), T, NOW).flags if f.code is F.RISK_WITHOUT_USAGE]
    assert len(flags) == 1 and flags[0].risk is R.HIGH and "high-risk" in flags[0].explanation


def test_risk_without_usage_uses_its_own_90_day_threshold():
    perms = (Permission("delegated", "Microsoft Graph", "Mail.ReadWrite"),)
    a = evaluate_app(app(permissions=perms, last_sign_in_at=ago(120)), T, NOW)  # <180 stale, >90 danger
    assert F.RISK_WITHOUT_USAGE in a.codes and F.STALE_APP not in a.codes and a.risk is R.HIGH


def test_signin_unavailable_skips_signin_flags_and_discloses():
    perms = (Permission("delegated", "Microsoft Graph", "Mail.ReadWrite"),)
    a = evaluate_app(app(permissions=perms, credentials=(cred(ago(40)),), sign_in_available=False,
                         last_sign_in_at=None), T, NOW)
    assert not ({F.STALE_APP, F.LIKELY_ABANDONED_APP, F.RISK_WITHOUT_USAGE} & a.codes)
    assert a.unavailable_signals


def test_custom_high_risk_list_respected():
    t = Thresholds(high_risk_scopes=("Custom.Scope",))
    a = evaluate_app(app(permissions=(Permission("delegated", None, "Custom.Scope"),)), t, NOW)
    assert F.DANGEROUS_PERMISSION in a.codes


# ------------------------------------------------------------------- users --
def test_dormant_privileged_user_flagged_high():
    u = UserFacts("u1", "Ann", "ann@x", ("Global Administrator",), True, ago(90))
    a = evaluate_user(u, T, NOW)
    assert a.codes == {F.DORMANT_PRIVILEGED_USER} and a.risk is R.HIGH


def test_active_privileged_user_not_flagged():
    assert evaluate_user(UserFacts("u1", "Ann", None, ("GA",), True, ago(5)), T, NOW).flags == ()


def test_unprivileged_dormant_user_not_flagged():
    assert evaluate_user(UserFacts("u1", "Bob", None, (), True, ago(500)), T, NOW).flags == ()


def test_privileged_user_signin_unavailable_discloses_instead_of_guessing():
    a = evaluate_user(UserFacts("u1", "Ann", None, ("GA",), False, None), T, NOW)
    assert a.flags == () and a.unavailable_signals


# ----------------------------------------------- where else a group is used ---
INTUNE_APP = GroupUsage("intune_apps", "Intune app", "Adobe 2024 Uninstall", "assigned", "uninstall")
CA = GroupUsage("policy_binding", "Conditional Access policy", "Require MFA", "exclude", "enabled")


def empty_ownerless(**kw):
    return group(member_count=0, owner_count=0, created_at=ago(700), **kw)


def test_empty_ownerless_group_without_references_is_high():
    assert evaluate_group(empty_ownerless(parent_group_names=()), T, NOW).risk is R.HIGH


def test_empty_ownerless_group_referenced_by_intune_is_not_likely_orphaned():
    a = evaluate_group(empty_ownerless(usages=(INTUNE_APP,), parent_group_names=()), T, NOW)
    assert a.risk is R.MEDIUM and {F.EMPTY_GROUP, F.NO_OWNER} <= a.codes
    empty = next(f for f in a.flags if f.code is F.EMPTY_GROUP)
    assert "still referenced elsewhere" in empty.explanation and "Adobe 2024 Uninstall" in empty.explanation
    assert "uninstall" in empty.explanation


def test_nested_group_is_referenced_even_with_no_other_use():
    a = evaluate_group(empty_ownerless(parent_group_names=("All Staff",)), T, NOW)
    assert a.risk is R.MEDIUM and "member of group(s) 'All Staff'" in next(
        f for f in a.flags if f.code is F.EMPTY_GROUP).explanation


def test_orphaned_app_assignment_stays_high_even_if_referenced():
    a = evaluate_group(group(app_assignments=(assign(exists=False),), usages=(CA,), parent_group_names=()), T, NOW)
    assert a.risk is R.HIGH


def test_unknown_use_suppressed_by_usage_or_nesting():
    base = dict(has_license_assignment=False, parent_group_names=())
    assert F.UNKNOWN_USE in evaluate_group(group(**base), T, NOW).codes
    assert F.UNKNOWN_USE not in evaluate_group(group(**{**base, "usages": (CA,)}), T, NOW).codes
    assert F.UNKNOWN_USE not in evaluate_group(group(**{**base, "parent_group_names": ("X",)}), T, NOW).codes


def test_unchecked_sources_and_nesting_are_disclosed_never_silently_dropped():
    a = evaluate_group(group(unchecked_usage_sources=("intune_apps", "policy_binding")), T, NOW)  # nesting not checked (None)
    note = next(u for u in a.unavailable_signals if u.startswith("Usage not checked in"))
    assert "Intune apps" in note and "Conditional Access policies" in note and "Membership in other groups" in note
    assert "verify manually" in note


def test_no_unchecked_note_when_everything_was_checked():
    a = evaluate_group(group(parent_group_names=()), T, NOW)
    assert not any(u.startswith("Usage not checked") for u in a.unavailable_signals)


# --------------------------------------------------- disabled / external privileged users ---
def admin(enabled, days=588, user_type="Member", available=True):
    return UserFacts("u1", "James", "j@x", ("Global Reader", "License Administrator"), available, ago(days), enabled, user_type)


def test_disabled_admin_gets_its_own_flag_medium_and_no_dormant_flag():
    a = evaluate_user(admin(False), T, NOW)
    assert a.codes == {F.DISABLED_PRIVILEGED_USER} and a.risk is R.MEDIUM
    text = a.flags[0].explanation
    assert text.startswith("Disabled account that still holds directory role(s) Global Reader, License Administrator")
    assert "cannot sign in" in text and "leftover" in text and "Last sign-in 2025-03-16, 588 days ago" in text
    assert a.flags[0].evidence["account_enabled"] is False


def test_disabled_admin_is_flagged_even_if_active_recently_or_sign_in_is_unavailable():
    assert evaluate_user(admin(False, days=5), T, NOW).codes == {F.DISABLED_PRIVILEGED_USER}
    a = evaluate_user(admin(False, available=False), T, NOW)
    assert a.codes == {F.DISABLED_PRIVILEGED_USER} and a.unavailable_signals == () and "Last sign-in" not in a.flags[0].explanation


def test_dormant_admin_with_an_enabled_or_unknown_account_stays_high_without_the_disabled_text():
    for enabled in (True, None):
        a = evaluate_user(admin(enabled), T, NOW)
        assert a.codes == {F.DORMANT_PRIVILEGED_USER} and a.risk is R.HIGH
        assert "Disabled" not in a.flags[0].explanation and "Dormant admin access" in a.flags[0].explanation


def test_activity_wording_has_no_doubled_parentheses():
    text = evaluate_user(admin(True), T, NOW).flags[0].explanation
    assert "((" not in text and "))" not in text and "last sign-in" in text and "588 days ago" in text
    app_text = evaluate_app(app(last_sign_in_at=ago(300)), T, NOW).flags[0].explanation
    assert "((" not in app_text


def test_external_admin_is_flagged_and_can_also_be_dormant():
    a = evaluate_user(admin(True, days=5, user_type="Guest"), T, NOW)
    assert a.codes == {F.EXTERNAL_PRIVILEGED_USER} and a.risk is R.MEDIUM and "external (guest) account" in a.flags[0].explanation
    both = evaluate_user(admin(True, days=300, user_type="Guest"), T, NOW)
    assert both.codes == {F.EXTERNAL_PRIVILEGED_USER, F.DORMANT_PRIVILEGED_USER} and both.risk is R.HIGH


def test_internal_member_without_a_role_is_never_flagged():
    assert evaluate_user(UserFacts("u2", "Bob", None, (), True, ago(900), False, "Guest"), T, NOW).flags == ()
