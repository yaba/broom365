"""Core group correlation: flags and risk levels. Pure functions, no I/O.

Wording rule: nothing is ever "safe to delete". Findings are "candidate for review",
"needs manual review" or "likely orphaned". "Not used" is only ever claimed for the places that were
actually checked (see usage.py); a group can be used in places Broom365 does not look at.

Risk rules (groups):
    HIGH    ORPHANED_APP_ASSIGNMENT, or (NO_OWNER and EMPTY_GROUP)
    MEDIUM  (STALE and EMPTY_GROUP), or UNKNOWN_USE
    LOW     everything else
A group that is still referenced elsewhere (Conditional Access, Intune, nested in another group) is never
"likely orphaned": a HIGH that came only from NO_OWNER + EMPTY_GROUP is lowered to MEDIUM and the references
are named. Extended group signals (PRIVILEGED_ORPHAN_GROUP) can only raise the result.
"""
from __future__ import annotations

from datetime import datetime

from ..models.types import (
    Assessment, Flag, FlagCode, GroupAppAssignment, GroupFacts, RiskLevel, Thresholds,
)
from ._time import days_between
from .extended_signals import privileged_orphan_group_flag
from .usage import LABELS, describe, only_uninstall_references


def references(group: GroupFacts) -> list[str]:
    """Human-readable list of places that still reference the group (empty if none were found)."""
    refs = []
    for u in group.usages:
        refs.append(f"{u.kind} {describe(u.source, repr(u.object_name), u.mode, u.detail)}")
    if group.parent_group_names:
        refs.append("member of group(s) " + ", ".join(f"'{n}'" for n in group.parent_group_names))
    return refs


def _reference_note(group: GroupFacts) -> str:
    refs = references(group)
    if not refs:
        return ""
    shown = "; ".join(refs[:3]) + (f"; and {len(refs) - 3} more" if len(refs) > 3 else "")
    note = f" It is still referenced elsewhere: {shown}."
    if not group.parent_group_names and only_uninstall_references(group.usages):
        note += (" Every reference is an uninstall assignment, which only has an effect while devices in this group "
                 "still need the app removed; with no members it currently does nothing.")
    return note


def orphaned_assignment_flag(group: GroupFacts) -> Flag | None:
    """ORPHANED_APP_ASSIGNMENT: assigned to an app whose service principal is gone or disabled.

    A missing SP is reported with its deletion date when known. An SP whose enabled
    state is unknown (None) is not treated as disabled.
    """
    broken: list[tuple[GroupAppAssignment, str]] = []
    for a in group.app_assignments:
        name = a.resource_display_name or a.resource_sp_id
        if not a.target_sp_exists:
            when = f" on {a.target_deleted_at:%Y-%m-%d}" if a.target_deleted_at else ""
            broken.append((a, f"'{name}' no longer exists (deleted{when} or not found in the directory)"))
        elif a.target_sp_enabled is False:
            broken.append((a, f"'{name}' exists but its service principal is disabled"))
    if not broken:
        return None
    return Flag(
        FlagCode.ORPHANED_APP_ASSIGNMENT,
        "This group is assigned to an application that is gone or disabled: "
        + "; ".join(text for _, text in broken) + ". Likely orphaned; candidate for review.",
        {"assignments": [{"resource_sp_id": a.resource_sp_id, "name": a.resource_display_name,
                          "exists": a.target_sp_exists, "enabled": a.target_sp_enabled} for a, _ in broken]},
    )


def empty_group_flag(group: GroupFacts) -> Flag | None:
    """EMPTY_GROUP: zero members. Unknown count (None) is never treated as empty.

    A signal, not a verdict: the group may still carry license or policy assignments.
    """
    if group.member_count != 0:
        return None
    return Flag(FlagCode.EMPTY_GROUP,
                "This group has no members. This is a signal only: it may still carry license or policy assignments."
                + _reference_note(group),
                {"member_count": 0})


def no_owner_flag(group: GroupFacts) -> Flag | None:
    """NO_OWNER: zero owners. Unknown count (None) is not flagged."""
    if group.owner_count != 0:
        return None
    return Flag(FlagCode.NO_OWNER, "This group has no owner, so nobody is accountable for its membership.",
                {"owner_count": 0})


def stale_flag(group: GroupFacts, now: datetime, t: Thresholds) -> Flag | None:
    """STALE: no member/owner change within `stale_days_group`.

    Uses the audit-log change date; if unavailable falls back to createdDateTime and says so.
    With neither date the group cannot be judged and is not flagged.
    """
    if group.last_membership_change_at is not None:
        ref, basis = group.last_membership_change_at, "last membership/owner change"
    elif group.created_at is not None:
        ref, basis = group.created_at, ("creation date (no change was found in the audit log, which only keeps about 30 days, "
                                        "so the real last change is unknown)")
    else:
        return None
    age = days_between(ref, now)
    if age <= t.stale_days_group:
        return None
    return Flag(FlagCode.STALE,
                f"No membership or owner change for {age} days (threshold {t.stale_days_group}); "
                f"based on {basis}, {ref:%Y-%m-%d}.",
                {"reference_date": ref.isoformat(), "basis": basis, "age_days": age})


def unknown_use_flag(group: GroupFacts) -> Flag | None:
    """UNKNOWN_USE: has members but no use was found in any checked place.

    Checked places: app assignments, licence, directory role, Conditional Access, Intune assignments, nesting.
    Anything that could not be read is named in the explanation. Means "needs manual review", never "safe to delete".
    """
    if not (group.member_count and group.member_count > 0):
        return None
    if (group.app_assignments or group.has_license_assignment or group.directory_role_names
            or group.usages or group.parent_group_names):
        return None
    unchecked = [LABELS.get(s, s) for s in group.unchecked_usage_sources]
    if group.has_license_assignment is None:
        unchecked.append("licence assignment")
    if group.parent_group_names is None and "Membership in other groups" not in unchecked:
        unchecked.append("Membership in other groups")
    caveat = f" (could not check: {', '.join(unchecked)})" if unchecked else ""
    return Flag(FlagCode.UNKNOWN_USE,
                f"This group has {group.member_count} member(s) but no app assignment, licence, directory role, "
                f"Conditional Access / Intune reference or nesting was found{caveat}. Its purpose is unknown; needs manual review.",
                {"member_count": group.member_count, "unchecked": unchecked})


def group_risk(codes: frozenset[FlagCode]) -> RiskLevel:
    """Map core group flag codes to a risk level (see module docstring)."""
    if FlagCode.ORPHANED_APP_ASSIGNMENT in codes or {FlagCode.NO_OWNER, FlagCode.EMPTY_GROUP} <= codes:
        return RiskLevel.HIGH
    if {FlagCode.STALE, FlagCode.EMPTY_GROUP} <= codes or FlagCode.UNKNOWN_USE in codes:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def evaluate_group(group: GroupFacts, t: Thresholds, now: datetime) -> Assessment:
    """Compute all flags and the risk level for one group.

    `now` is injected for determinism. A group that is still referenced elsewhere is not "likely orphaned":
    HIGH caused only by NO_OWNER + EMPTY_GROUP drops to MEDIUM. Extended PRIVILEGED_ORPHAN_GROUP is evaluated
    from the core flags and may raise the risk to HIGH.
    """
    candidates = (orphaned_assignment_flag(group), empty_group_flag(group), no_owner_flag(group),
                  stale_flag(group, now, t), unknown_use_flag(group))
    flags = [f for f in candidates if f]
    codes = frozenset(f.code for f in flags)
    risk = group_risk(codes)
    if risk is RiskLevel.HIGH and FlagCode.ORPHANED_APP_ASSIGNMENT not in codes and references(group):
        risk = RiskLevel.MEDIUM

    priv = privileged_orphan_group_flag(group, codes)
    if priv:
        flags.append(priv)
        risk = max(risk, priv.risk, key=lambda r: r.rank)

    unavailable: list[str] = []
    if group.member_count is None:
        unavailable.append("Member count not retrieved; empty/unknown-use checks skipped.")
    if group.owner_count is None:
        unavailable.append("Owner count not retrieved; no-owner check skipped.")
    if group.last_membership_change_at is None:
        unavailable.append("Audit-log change date unavailable; staleness uses creation date.")
    missing = [LABELS.get(s, s) for s in group.unchecked_usage_sources]
    if group.parent_group_names is None:
        missing.append(LABELS["group_nesting"])
    if missing:
        unavailable.append("Usage not checked in: " + ", ".join(missing)
                           + ". A group referenced there would look unused; verify manually.")
    return Assessment("group", group.id, group.display_name, risk, tuple(flags), tuple(unavailable))
