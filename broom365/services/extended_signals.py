"""Extended risk signals (secrets, permissions, sign-in activity, privileged objects).

Pure functions, no I/O. Kept separate from correlate.py (core group logic) so these
signals can be disabled or evolved independently. Wording never claims anything is safe
to remove: findings are "candidates for review" / "likely abandoned".

Risk assigned per flag (each Flag carries its own `risk`; assessment risk is the max):
    LIKELY_ABANDONED_APP, RISK_WITHOUT_USAGE, PRIVILEGED_ORPHAN_GROUP,
    DORMANT_PRIVILEGED_USER                         -> HIGH
    DANGEROUS_PERMISSION                            -> MEDIUM
    EXPIRED_SECRET                                  -> MEDIUM (LOW if another valid credential exists)
    EXPIRING_SECRET, STALE_APP                      -> LOW
"""
from __future__ import annotations

from datetime import datetime, timedelta

from ..models.types import (
    AppFacts, Assessment, Credential, Flag, FlagCode, GroupFacts, RiskLevel, Thresholds, UserFacts,
)
from ._time import days_between


# ------------------------------------------------------------------ helpers --
def inactive_days(last_sign_in_at: datetime | None, now: datetime) -> int | None:
    """Days since the last sign-in, or None when no sign-in is on record."""
    return None if last_sign_in_at is None else days_between(last_sign_in_at, now)


def _is_inactive(last_sign_in_at: datetime | None, now: datetime, threshold_days: int) -> bool:
    """True if there is no sign-in on record or it is older than `threshold_days`."""
    days = inactive_days(last_sign_in_at, now)
    return days is None or days > threshold_days


def _activity_phrase(last_sign_in_at: datetime | None, now: datetime) -> str:
    days = inactive_days(last_sign_in_at, now)
    if days is None:
        return "no sign-in on record"
    return f"last sign-in {last_sign_in_at:%Y-%m-%d}, {days} days ago"  # type: ignore[union-attr]


# ------------------------------------------------------------------ secrets --
def split_credentials(
    credentials: tuple[Credential, ...], now: datetime, expiring_days: int
) -> tuple[list[Credential], list[Credential], list[Credential]]:
    """Partition credentials into (expired, expiring_soon, valid_beyond_window).

    Credentials without an end date are ignored. `expiring_soon` ends within
    `expiring_days` from `now`; `valid_beyond_window` ends later than that.
    """
    expired: list[Credential] = []
    expiring: list[Credential] = []
    valid: list[Credential] = []
    horizon = now + timedelta(days=expiring_days)
    for c in credentials:
        if c.end_at is None:
            continue
        if c.end_at < now:
            expired.append(c)
        elif c.end_at <= horizon:
            expiring.append(c)
        else:
            valid.append(c)
    return expired, expiring, valid


def credential_status(c: Credential, now: datetime, expiring_days: int) -> tuple[str, str]:
    """Display status for one credential as (kind, text); kind is 'expired' | 'expiring' | 'valid' | 'unknown'."""
    if c.end_at is None:
        return "unknown", "No end date"
    if c.end_at < now:
        return "expired", f"Expired {days_between(c.end_at, now)} days ago"
    days = days_between(now, c.end_at)
    if c.end_at <= now + timedelta(days=expiring_days):
        return "expiring", f"Expires in {days} days"
    return "valid", f"Valid, {days} days left"


def _cred_label(c: Credential) -> str:
    return f"{c.kind} credential '{c.display_name or c.key_id}'"


def expired_secret_flag(app: AppFacts, now: datetime, t: Thresholds) -> Flag | None:
    """EXPIRED_SECRET: any password/key credential whose end date is in the past.

    Includes days since expiry per credential. If a still-valid credential exists the
    expired one is likely a rotation leftover, so risk drops from MEDIUM to LOW.
    """
    expired, expiring, valid = split_credentials(app.credentials, now, t.expiring_days)
    if not expired:
        return None
    details = [f"{_cred_label(c)} expired {c.end_at:%Y-%m-%d} ({days_between(c.end_at, now)} days ago)"  # type: ignore[arg-type]
               for c in expired]
    has_valid = bool(valid or expiring)
    note = (" Another credential is still valid, so this may be a rotation leftover."
            if has_valid else " No valid credential remains on this app.")
    return Flag(
        FlagCode.EXPIRED_SECRET,
        "Expired: " + "; ".join(details) + "." + note,
        {"credentials": [{"key_id": c.key_id, "kind": c.kind, "end_at": c.end_at.isoformat(),  # type: ignore[union-attr]
                          "days_since_expiry": days_between(c.end_at, now)} for c in expired],  # type: ignore[arg-type]
         "has_valid_credential": has_valid},
        RiskLevel.LOW if has_valid else RiskLevel.MEDIUM,
    )


def expiring_secret_flag(app: AppFacts, now: datetime, t: Thresholds) -> Flag | None:
    """EXPIRING_SECRET: credentials ending within `expiring_days` (and not yet expired)."""
    _, expiring, _ = split_credentials(app.credentials, now, t.expiring_days)
    if not expiring:
        return None
    details = [f"{_cred_label(c)} expires {c.end_at:%Y-%m-%d} (in {days_between(now, c.end_at)} days)"  # type: ignore[arg-type]
               for c in expiring]
    return Flag(
        FlagCode.EXPIRING_SECRET,
        f"Expiring within {t.expiring_days} days: " + "; ".join(details) + ".",
        {"credentials": [{"key_id": c.key_id, "end_at": c.end_at.isoformat()} for c in expiring]},  # type: ignore[union-attr]
        RiskLevel.LOW,
    )


# -------------------------------------------------------------- permissions --
def dangerous_permissions(app: AppFacts, t: Thresholds) -> list[tuple[str, str, str]]:
    """(kind, resource, scope) for each permission in the high-risk list (tier 1, case-insensitive)."""
    risky = {x.lower() for x in t.high_risk_scopes}
    return [(p.kind, p.resource_name or "unknown resource", p.scope) for p in app.permissions if p.scope.lower() in risky]


def broad_read_permissions(app: AppFacts, t: Thresholds) -> list[tuple[str, str, str]]:
    """(kind, resource, scope) for each broad directory-read permission (tier 2); anything also in tier 1 counts as tier 1."""
    risky = {x.lower() for x in t.high_risk_scopes}
    broad = {x.lower() for x in t.broad_read_scopes}
    return [(p.kind, p.resource_name or "unknown resource", p.scope) for p in app.permissions
            if p.scope.lower() in broad and p.scope.lower() not in risky]


def _listing(found: list[tuple[str, str, str]]) -> str:
    return ", ".join(f"{scope} ({kind}, {res})" for kind, res, scope in found)


def dangerous_permission_flag(app: AppFacts, t: Thresholds) -> Flag | None:
    """DANGEROUS_PERMISSION: names each high-risk scope held. Never calls a permission 'unnecessary'.

    HIGH if the app holds any of them as an *application* permission (it acts on its own, tenant-wide); MEDIUM if only
    as delegated (limited to what the signed-in user can do).
    """
    found = dangerous_permissions(app, t)
    if not found:
        return None
    application = any(kind == "application" for kind, _, _ in found)
    scope_note = (" As an application permission it acts tenant-wide, without a signed-in user." if application
                  else " Delegated permissions are limited to what the signed-in user can do.")
    return Flag(
        FlagCode.DANGEROUS_PERMISSION,
        f"Holds high-risk permission(s): {_listing(found)}.{scope_note} Whether they are required needs manual review.",
        {"permissions": [{"kind": k, "resource": r, "scope": s} for k, r, s in found]},
        RiskLevel.HIGH if application else RiskLevel.MEDIUM,
    )


def broad_read_permission_flag(app: AppFacts, t: Thresholds) -> Flag | None:
    """BROAD_READ_PERMISSION: broad directory reads (Directory.Read.All, User.Read.All...). To review, not 'dangerous'.

    They cannot change anything and many legitimate products need them. MEDIUM if held as an application permission,
    LOW if only delegated.
    """
    found = broad_read_permissions(app, t)
    if not found:
        return None
    application = any(kind == "application" for kind, _, _ in found)
    return Flag(
        FlagCode.BROAD_READ_PERMISSION,
        f"Holds broad directory read permission(s): {_listing(found)}. They can read a lot of directory data but cannot "
        "change anything, and many products need them; whether this app does is for manual review.",
        {"permissions": [{"kind": k, "resource": r, "scope": s} for k, r, s in found]},
        RiskLevel.MEDIUM if application else RiskLevel.LOW,
    )


# ----------------------------------------------------------------- app eval --
def evaluate_app(app: AppFacts, t: Thresholds, now: datetime) -> Assessment:
    """Compute all app-level flags, correlations and the resulting risk.

    Correlations (computed, not just displayed):
      * expired secret + no sign-in > stale_days_app      -> LIKELY_ABANDONED_APP
      * dangerous permission + no sign-in > danger_no_signin_days -> RISK_WITHOUT_USAGE
    If sign-in data is unavailable the sign-in based flags are skipped and the gap is
    reported in `unavailable_signals` instead of guessing.
    """
    flags: list[Flag] = []
    unavailable: list[str] = []

    expired = expired_secret_flag(app, now, t)
    expiring = expiring_secret_flag(app, now, t)
    danger = dangerous_permission_flag(app, t)
    broad = broad_read_permission_flag(app, t)
    for f in (expired, expiring, danger, broad):
        if f:
            flags.append(f)

    if not app.sign_in_available:
        unavailable.append("Sign-in activity unavailable for this app (beta endpoint or AuditLog.Read.All missing); "
                           "stale / abandoned / risk-without-usage checks were skipped.")
    else:
        activity = _activity_phrase(app.last_sign_in_at, now)
        stale = _is_inactive(app.last_sign_in_at, now, t.stale_days_app)
        if stale:
            flags.append(Flag(
                FlagCode.STALE_APP,
                f"No sign-in within {t.stale_days_app} days ({activity}).",
                {"last_sign_in_at": app.last_sign_in_at.isoformat() if app.last_sign_in_at else None},
                RiskLevel.LOW,
            ))
        if expired and stale:
            flags.append(Flag(
                FlagCode.LIKELY_ABANDONED_APP,
                f"Has an expired credential and {activity}; this app is likely abandoned and is a candidate for review.",
                {"last_sign_in_at": app.last_sign_in_at.isoformat() if app.last_sign_in_at else None},
                RiskLevel.HIGH,
            ))
        if (danger or broad) and _is_inactive(app.last_sign_in_at, now, t.danger_no_signin_days):
            if danger:
                scopes = ", ".join(x for _, _, x in dangerous_permissions(app, t))
                flags.append(Flag(
                    FlagCode.RISK_WITHOUT_USAGE,
                    f"Holds high-risk permission(s) ({scopes}) with no sign-in in {t.danger_no_signin_days} days "
                    f"({activity}): privilege without evidence of use. Candidate for review.",
                    {"scopes": [x for _, _, x in dangerous_permissions(app, t)]}, RiskLevel.HIGH))
            elif any(kind == "application" for kind, _, _ in broad_read_permissions(app, t)):
                scopes = ", ".join(x for _, _, x in broad_read_permissions(app, t))
                flags.append(Flag(
                    FlagCode.RISK_WITHOUT_USAGE,
                    f"Holds broad directory read permission(s) ({scopes}) with no sign-in in {t.danger_no_signin_days} days "
                    f"({activity}): read access without evidence of use. Candidate for review.",
                    {"scopes": [x for _, _, x in broad_read_permissions(app, t)]}, RiskLevel.MEDIUM))

    risk = max((f.risk for f in flags), key=lambda r: r.rank, default=RiskLevel.LOW)
    return Assessment("app", app.id, app.display_name, risk, tuple(flags), tuple(unavailable))


# ---------------------------------------------------------------- user eval --
def evaluate_user(user: UserFacts, t: Thresholds, now: datetime) -> Assessment:
    """Findings for a user that holds a directory role.

    DISABLED_PRIVILEGED_USER  the account is disabled but still holds role(s): it cannot sign in, so the assignment is a
                              leftover (MEDIUM). Reported whether or not the account is also dormant.
    DORMANT_PRIVILEGED_USER   enabled (or unknown), and no sign-in within `dormant_days_user` (HIGH). Needs sign-in data:
                              if unavailable it is skipped and reported in `unavailable_signals`.
    EXTERNAL_PRIVILEGED_USER  a guest (external) account holds a role (MEDIUM): confirm it is intended.

    Users without a role are never flagged here.
    """
    flags: list[Flag] = []
    unavailable: list[str] = []
    if user.role_names:
        roles = ", ".join(user.role_names)
        last = {"last_sign_in_at": user.last_sign_in_at.isoformat() if user.last_sign_in_at else None}
        if user.account_enabled is False:
            seen = f" {_activity_phrase(user.last_sign_in_at, now).capitalize()}." if user.sign_in_available else ""
            flags.append(Flag(
                FlagCode.DISABLED_PRIVILEGED_USER,
                f"Disabled account that still holds directory role(s) {roles}. It cannot sign in, so the role assignment is "
                f"a leftover and a candidate for review.{seen}",
                {"roles": list(user.role_names), "account_enabled": False, **last}, RiskLevel.MEDIUM))
        elif not user.sign_in_available:
            unavailable.append("User sign-in activity unavailable (beta endpoint, licence or AuditLog.Read.All); "
                               "dormant-privileged-user check skipped.")
        elif _is_inactive(user.last_sign_in_at, now, t.dormant_days_user):
            flags.append(Flag(
                FlagCode.DORMANT_PRIVILEGED_USER,
                f"Holds directory role(s) {roles} but has had no sign-in within {t.dormant_days_user} days "
                f"({_activity_phrase(user.last_sign_in_at, now)}). Dormant admin access needs manual review.",
                {"roles": list(user.role_names), "account_enabled": user.account_enabled, **last}, RiskLevel.HIGH))
        if user.user_type == "Guest":
            flags.append(Flag(
                FlagCode.EXTERNAL_PRIVILEGED_USER,
                f"This is an external (guest) account and it holds directory role(s) {roles}. Confirm that an external "
                "identity should have this access.", {"roles": list(user.role_names), "user_type": "Guest"}, RiskLevel.MEDIUM))
    risk = max((f.risk for f in flags), key=lambda r: r.rank, default=RiskLevel.LOW)
    return Assessment("user", user.id, user.display_name, risk, tuple(flags), tuple(unavailable))


# --------------------------------------------------------- group extension --
def privileged_orphan_group_flag(group: GroupFacts, base_codes: frozenset[FlagCode]) -> Flag | None:
    """PRIVILEGED_ORPHAN_GROUP: group has a directory role AND (no owner OR (empty AND stale)).

    `base_codes` are the core flags already computed by correlate.evaluate_group.
    This is the "privileged role + no owner = orphaned admin power" correlation.
    """
    if not group.directory_role_names:
        return None
    no_owner = FlagCode.NO_OWNER in base_codes
    empty_and_stale = FlagCode.EMPTY_GROUP in base_codes and FlagCode.STALE in base_codes
    if not (no_owner or empty_and_stale):
        return None
    roles = ", ".join(group.directory_role_names)
    why = "has no owner" if no_owner else "is empty and has not changed recently"
    return Flag(
        FlagCode.PRIVILEGED_ORPHAN_GROUP,
        f"This group is assigned directory role(s) {roles} and {why}: admin power with no accountable owner. "
        "Needs manual review.",
        {"roles": list(group.directory_role_names), "no_owner": no_owner, "empty_and_stale": empty_and_stale},
        RiskLevel.HIGH,
    )
