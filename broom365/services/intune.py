"""Intune cleanup correlation: apps and scripts that are obsolete. Pure functions, no I/O.

Apps
  UNINSTALL_ONLY_APP  every include-assignment is `uninstall`: no longer deployed, only removed.
  UNASSIGNED_APP      no include-assignment at all, and no other app depends on it. If a newer app supersedes it
                      the explanation says so (and warns what deleting it breaks); if relationships could not be
                      read it says so. Exclusion targets also carry an `intent` in Graph but never install anything.

Scripts (PowerShell, macOS shell, Remediations)
  UNASSIGNED_SCRIPT, STALE_SCRIPT, EMPTY_TARGETS_SCRIPT, FAILING_SCRIPT, IDLE_REMEDIATION, and the correlation
  LIKELY_OBSOLETE_SCRIPT = stale AND (unassigned OR empty targets OR failing OR idle).

Nothing here says "safe to delete": the findings are candidates for review.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from ..models.types import (
    Assessment, Flag, FlagCode, IntuneAppFacts, IntuneAssignment, IntuneScriptFacts, RiskLevel, Thresholds,
)
from ._time import days_between

INSTALL_INTENTS = frozenset({"required", "available", "availableWithoutEnrollment"})
KIND_LABEL = {"powershell": "PowerShell script", "shell": "macOS shell script", "remediation": "remediation"}


def _target_label(a: IntuneAssignment) -> str:
    if a.target == "all_users":
        return "All licensed users"
    if a.target == "all_devices":
        return "All devices"
    name = a.group_name or f"unknown group {a.group_id[:8]}"
    if a.group_member_count is None:
        return f"'{name}' (members unknown: group not scanned)"
    return f"'{name}' ({a.group_member_count} member{'s' if a.group_member_count != 1 else ''})"


def _dates(created: datetime | None, modified: datetime | None) -> str:
    parts = []
    if created:
        parts.append(f"created {created:%Y-%m-%d}")
    if modified:
        parts.append(f"last modified {modified:%Y-%m-%d}")
    return f"({', '.join(parts)}) " if parts else ""


# --------------------------------------------------------------------- apps ---
def evaluate_intune_app(app: IntuneAppFacts, now: datetime) -> Assessment:
    """Flag an Intune app that is only being removed, or that is assigned to nobody and needed by nobody."""
    includes = [a for a in app.assignments if a.mode == "include"]
    if not includes:
        return _unassigned_app(app)
    if any(a.intent != "uninstall" for a in includes):
        return Assessment("intune_app", app.id, app.display_name, RiskLevel.LOW, ())
    groups = [a for a in includes if a.target == "group"]
    empty = [a for a in groups if a.group_member_count == 0]
    unknown = [a for a in groups if a.group_member_count is None]
    targets = "; ".join(_target_label(a) for a in includes)
    counts = f" {len(empty)} of {len(groups)} target group(s) are empty" if groups else ""
    counts += f", {len(unknown)} not scanned yet" if groups and unknown else ""
    explanation = (
        f"This Intune app has only uninstall assignments and no install (required/available) assignment, so it is "
        f"no longer deployed, only removed. Targets: {targets}.{counts + '.' if counts else ''} "
        f"{_dates(app.created_at, app.modified_at)}"
        "Once devices have finished uninstalling, the assignments and the target groups are candidates for review. "
        "Dependencies and supersedence relationships are not checked.")
    flag = Flag(FlagCode.UNINSTALL_ONLY_APP, " ".join(explanation.split()),
                {"targets": [{"target": a.target, "group_id": a.group_id or None, "group": a.group_name,
                              "members": a.group_member_count} for a in includes],
                 "empty_groups": len(empty), "groups": len(groups), "unscanned_groups": len(unknown),
                 "app_type": app.app_type, "created_at": app.created_at.isoformat() if app.created_at else None,
                 "modified_at": app.modified_at.isoformat() if app.modified_at else None},
                RiskLevel.MEDIUM)
    return Assessment("intune_app", app.id, app.display_name, RiskLevel.MEDIUM, (flag,))


def _unassigned_app(app: IntuneAppFacts) -> Assessment:
    rels = app.relationships
    none = Assessment("intune_app", app.id, app.display_name, RiskLevel.LOW, ())
    if not app.scanned:
        return Assessment("intune_app", app.id, app.display_name, RiskLevel.LOW, (),
                          ("No assignment, but dependencies and supersedence were not checked yet; scan this app to find out whether it is an unused app, an old version or a dependency.",))
    superseded_by = [r for r in (rels or ()) if r.kind == "supersedence" and r.role == "parent"]
    supersedes = [r for r in (rels or ()) if r.kind == "supersedence" and r.role == "child"]
    if any(r.kind == "dependency" and r.role == "parent" for r in (rels or ())):
        return none  # another app depends on this one: it is needed even though nobody is assigned to it
    if rels is None:
        context = "Dependencies and supersedence relationships could not be read, so it may still be needed by another app."
        risk = RiskLevel.LOW
    elif superseded_by:
        names = ", ".join(f"'{r.other_name or r.other_id}' ({'assigned' if r.other_assigned else 'also unassigned'})"
                          for r in superseded_by)
        context = (f"It is superseded by {names}, so it looks like an old version. Deleting it removes that supersedence "
                   "link: devices still on this version would no longer be upgraded through it.")
        risk = RiskLevel.MEDIUM
    else:
        context = "No other app depends on it and no newer app supersedes it."
        risk = RiskLevel.LOW
    if supersedes:
        context += f" It supersedes {len(supersedes)} older app(s): " + ", ".join(f"'{r.other_name or r.other_id}'" for r in supersedes[:3]) + "."
    text = (f"This Intune app has no assignment, so it is not deployed to anyone. {_dates(app.created_at, app.modified_at)}"
            f"{context} Candidate for review.")
    flag = Flag(FlagCode.UNASSIGNED_APP, " ".join(text.split()),
                {"superseded_by": [r.other_name for r in superseded_by], "supersedes": [r.other_name for r in supersedes],
                 "relationships_checked": rels is not None, "app_type": app.app_type,
                 "created_at": app.created_at.isoformat() if app.created_at else None,
                 "modified_at": app.modified_at.isoformat() if app.modified_at else None}, risk)
    return Assessment("intune_app", app.id, app.display_name, risk, (flag,))


# ------------------------------------------------------------------ scripts ---
def _count(run: dict[str, Any] | None, *keys: str) -> int:
    return sum(int((run or {}).get(k) or 0) for k in keys)


def evaluate_intune_script(s: IntuneScriptFacts, t: Thresholds, now: datetime) -> Assessment:
    """Flag a PowerShell script, macOS shell script or Remediation that looks obsolete (see module docstring)."""
    label = KIND_LABEL[s.kind]
    includes = [a for a in s.assignments if a.mode == "include"]
    groups = [a for a in includes if a.target == "group"]
    ref = s.modified_at or s.created_at
    age = days_between(ref, now) if ref else None
    run = dict(s.run) if s.run is not None else None
    flags: list[Flag] = []
    reasons: list[str] = []

    unassigned = not includes
    if unassigned:
        text = f"This {label} has no assignment, so it does not run on any device."
        flags.append(Flag(FlagCode.UNASSIGNED_SCRIPT, text, {}, RiskLevel.LOW))
        reasons.append("unassigned")

    empty = bool(groups) and len(groups) == len(includes) and all(g.group_member_count == 0 for g in groups)
    if empty:
        names = ", ".join(f"'{g.group_name or g.group_id[:8]}'" for g in groups[:4])
        flags.append(Flag(FlagCode.EMPTY_TARGETS_SCRIPT,
                          f"Every target group of this {label} is empty ({names}), so it currently reaches no device.",
                          {"groups": [g.group_name for g in groups]}, RiskLevel.MEDIUM))
        reasons.append("it targets only empty groups")

    if s.kind in ("powershell", "shell") and run is not None:
        ok, bad = _count(run, "successDeviceCount", "successUserCount"), _count(run, "errorDeviceCount", "errorUserCount")
        if ok == 0 and bad > 0:
            flags.append(Flag(FlagCode.FAILING_SCRIPT,
                              f"This {label} has never succeeded: {bad} run(s) failed and none succeeded. A script that always "
                              "fails is either broken or no longer relevant.", {"failed": bad, "succeeded": ok}, RiskLevel.MEDIUM))
            reasons.append(f"it has failed {bad} time(s) and never succeeded")

    if s.kind == "remediation" and includes and run is not None:
        last = _as_dt(run.get("lastScriptRunDateTime"))
        idle_days = days_between(last, now) if last else None
        if last is None or idle_days > t.idle_days_script:
            when = "has never run on any device" if last is None else f"last ran on {last:%Y-%m-%d} ({idle_days} days ago)"
            flags.append(Flag(FlagCode.IDLE_REMEDIATION,
                              f"This remediation is assigned but {when} (threshold {t.idle_days_script} days).",
                              {"last_run": run.get("lastScriptRunDateTime"), "idle_days": idle_days}, RiskLevel.MEDIUM))
            reasons.append("it is not running on any device")

    stale = age is not None and age > t.stale_days_script
    if stale:
        flags.append(Flag(FlagCode.STALE_SCRIPT,
                          f"This {label} was last modified on {ref:%Y-%m-%d}, {age} days ago (threshold {t.stale_days_script}).",  # type: ignore[union-attr]
                          {"age_days": age}, RiskLevel.LOW))
        if reasons:
            flags.append(Flag(FlagCode.LIKELY_OBSOLETE_SCRIPT,
                              f"This {label} was last modified {age} days ago and {' and '.join(reasons)}: it is likely "
                              "obsolete and a candidate for review.", {"age_days": age, "reasons": reasons}, RiskLevel.MEDIUM))

    risk = max((f.risk for f in flags), key=lambda r: r.rank, default=RiskLevel.LOW)
    if s.run is not None:
        unavailable: tuple[str, ...] = ()
    elif not s.scanned:
        unavailable = ("Run results not read yet; scan this script to check whether it is failing or idle.",)
    else:
        unavailable = ("Run results could not be read (Intune script run summaries); failing/idle checks were skipped.",)
    return Assessment("intune_script", s.id, s.display_name, risk, tuple(flags), unavailable)


def _as_dt(value: Any) -> datetime | None:
    from ._time import parse_graph_dt
    return parse_graph_dt(value) if isinstance(value, str) and value else None
