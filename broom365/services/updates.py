"""Windows update policies of Intune: update rings, feature update profiles, expedite (quality) profiles and driver update profiles.
Pure functions, no I/O.

The checks stick to what Microsoft documents and to what the policy itself says:

  UPDATE_UNASSIGNED       nobody is targeted, so the policy does nothing.
  UPDATE_EMPTY_TARGETS    every target group is empty.
  UPDATE_OVERLAP          another policy of the same kind reaches the same group (or everybody).
  UPDATE_NO_DEADLINE      a ring without a quality or feature deadline. Microsoft's recommended experience is to set deadlines
                          (Windows Update client policies), otherwise a device installs only when the user or the schedule allows.
  UPDATE_PAUSED           a ring that pauses quality or feature updates. A pause lasts at most 35 days, so one that is still set
                          after its expiry is stale.
  UPDATE_FEATURE_ENDING   the Windows version of a feature update profile is out of support, or will be within `eos_warning_days`
                          (the end-of-support date comes from the profile itself, as Intune reports it).
  UPDATE_DRIVERS_WAITING  a driver profile with manual approval and updates waiting.
  UPDATE_STALE_EXPEDITE   an expedite profile covers a single release; an old one has done its job.

Nothing here says "wrong": the findings are candidates for review.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from ..models.types import Assessment, Flag, FlagCode, RiskLevel, Thresholds, UpdatePolicyFacts
from ._time import days_between, parse_graph_dt
from .intune import _target_label

KIND_LABEL = {"ring": "update ring", "feature": "feature update profile", "quality": "expedite (quality update) profile",
              "driver": "driver update profile"}
KIND_SHORT = {"ring": "Update ring", "feature": "Feature updates", "quality": "Expedite", "driver": "Driver updates"}


def _dt(value: Any) -> datetime | None:
    return parse_graph_dt(value) if isinstance(value, str) and value else None


def _fmt_days(value: Any) -> str:
    return "not set" if value is None else f"{value} d"


def targets_text(p: UpdatePolicyFacts) -> str:
    """Who the policy is assigned to (includes), with exclusions called out."""
    inc = [_target_label(a) for a in p.assignments if a.mode == "include"]
    exc = [a.group_name or a.group_id[:8] for a in p.assignments if a.mode == "exclude"]
    text = "; ".join(inc) if inc else "nobody"
    return text + (f" (excluding {', '.join(exc)})" if exc else "")


def summarize(p: UpdatePolicyFacts) -> str:
    """The settings that matter, in one line."""
    s = p.settings
    if p.kind == "ring":
        paused = [n for n, k in (("quality", "qualityUpdatesPaused"), ("feature", "featureUpdatesPaused")) if s.get(k)]
        parts = [f"Quality: defer {_fmt_days(s.get('qualityUpdatesDeferralPeriodInDays'))}, deadline {_fmt_days(s.get('deadlineForQualityUpdatesInDays'))}",
                 f"Feature: defer {_fmt_days(s.get('featureUpdatesDeferralPeriodInDays'))}, deadline {_fmt_days(s.get('deadlineForFeatureUpdatesInDays'))}",
                 f"restart grace {_fmt_days(s.get('deadlineGracePeriodInDays'))}"]
        if paused:
            parts.append("paused: " + " and ".join(paused))
        return " · ".join(parts)
    if p.kind == "feature":
        end = _dt(s.get("endOfSupportDate"))
        return f"{s.get('featureUpdateVersion') or 'version unknown'}" + (f" · support ends {end:%Y-%m-%d}" if end else "")
    if p.kind == "quality":
        ex = s.get("expeditedUpdateSettings") or {}
        release = _dt(ex.get("qualityUpdateRelease"))
        name = f"{release:%Y-%m-%d}" if release else (ex.get("qualityUpdateRelease") or s.get("releaseDateDisplayName") or "unknown")
        return f"Release {name}" + (f" · forced restart after {ex['daysUntilForcedReboot']} d" if ex.get("daysUntilForcedReboot") is not None else "")
    approval = s.get("approvalType") or "unknown"
    return f"{approval.capitalize()} approval" + (f" · deferral {s['deploymentDeferralInDays']} d" if approval == "automatic" and s.get("deploymentDeferralInDays") is not None else "")


def evaluate_update_policy(p: UpdatePolicyFacts, t: Thresholds, now: datetime) -> Assessment:
    """Flag one update policy (see the module docstring)."""
    label = KIND_LABEL[p.kind]
    includes = [a for a in p.assignments if a.mode == "include"]
    groups = [a for a in includes if a.target == "group"]
    s = p.settings
    flags: list[Flag] = []

    if not includes:
        flags.append(Flag(FlagCode.UPDATE_UNASSIGNED,
                          f"This {label} is assigned to nobody, so it changes nothing on any device. Candidate for review.", {}, RiskLevel.LOW))
    elif groups and len(groups) == len(includes) and all(g.group_member_count == 0 for g in groups):
        names = ", ".join(f"'{g.group_name or g.group_id[:8]}'" for g in groups[:4])
        flags.append(Flag(FlagCode.UPDATE_EMPTY_TARGETS,
                          f"Every group this {label} is assigned to is empty ({names}), so it currently reaches no device.",
                          {"groups": [g.group_name for g in groups]}, RiskLevel.MEDIUM))

    if p.overlaps:
        flags.append(Flag(FlagCode.UPDATE_OVERLAP,
                          f"This {label} reaches the same devices as {', '.join(repr(n) for n in p.overlaps[:4])}"
                          f"{' and more' if len(p.overlaps) > 4 else ''}. A device in both gets two sets of settings and Windows Update may not "
                          "apply the one you expect; assign each device to a single policy of this kind (or exclude the shared group from one).",
                          {"overlaps": list(p.overlaps)}, RiskLevel.MEDIUM))

    if p.kind == "ring":
        missing = [name for name, key in (("quality", "deadlineForQualityUpdatesInDays"), ("feature", "deadlineForFeatureUpdatesInDays"))
                   if s.get(key) is None]
        if missing:
            flags.append(Flag(FlagCode.UPDATE_NO_DEADLINE,
                              f"This update ring sets no {' and no '.join(missing)} update deadline. Microsoft recommends setting deadlines so that "
                              "updates are installed by a known date even when the user does not act.",
                              {"missing": missing}, RiskLevel.MEDIUM))
        for name, paused, expiry in (("quality", s.get("qualityUpdatesPaused"), s.get("qualityUpdatesPauseExpiryDateTime")),
                                     ("feature", s.get("featureUpdatesPaused"), s.get("featureUpdatesPauseExpiryDateTime"))):
            if not paused:
                continue
            end = _dt(expiry)
            if end is not None and end < now:
                flags.append(Flag(FlagCode.UPDATE_PAUSED,
                                  f"{name.capitalize()} updates are still marked as paused on this ring, but the pause ended on {end:%Y-%m-%d}: "
                                  "a pause lasts at most 35 days. Resume or clear it.", {"type": name, "expired": end.isoformat()}, RiskLevel.LOW))
            else:
                until = f" until {end:%Y-%m-%d}" if end else ""
                flags.append(Flag(FlagCode.UPDATE_PAUSED,
                                  f"{name.capitalize()} updates are paused on this ring{until}. Devices assigned to it receive no {name} updates meanwhile.",
                                  {"type": name, "until": end.isoformat() if end else None}, RiskLevel.MEDIUM))

    if p.kind == "feature":
        end = _dt(s.get("endOfSupportDate"))
        version = s.get("featureUpdateVersion") or "this version"
        if end is not None and end < now:
            flags.append(Flag(FlagCode.UPDATE_FEATURE_ENDING,
                              f"{version} stopped being serviced on {end:%Y-%m-%d} ({days_between(end, now)} days ago), and this profile keeps devices "
                              "on it. Move to a supported version.", {"version": version, "end_of_support": end.isoformat()}, RiskLevel.HIGH))
        elif end is not None and days_between(now, end) <= t.eos_warning_days:
            flags.append(Flag(FlagCode.UPDATE_FEATURE_ENDING,
                              f"{version} stops being serviced on {end:%Y-%m-%d} (in {days_between(now, end)} days, threshold {t.eos_warning_days}). "
                              "Plan the move to a newer version.", {"version": version, "end_of_support": end.isoformat()}, RiskLevel.MEDIUM))

    if p.kind == "driver" and s.get("approvalType") == "manual" and (s.get("newUpdates") or 0) > 0:
        flags.append(Flag(FlagCode.UPDATE_DRIVERS_WAITING,
                          f"This driver update profile needs manual approval and {s['newUpdates']} new driver update(s) are waiting, so none reaches the devices.",
                          {"new_updates": s["newUpdates"]}, RiskLevel.LOW))

    if p.kind == "quality":
        ref = p.modified_at or p.created_at
        age = days_between(ref, now) if ref else None
        if age is not None and age > t.stale_days_expedite:
            flags.append(Flag(FlagCode.UPDATE_STALE_EXPEDITE,
                              f"This expedite profile was last modified on {ref:%Y-%m-%d}, {age} days ago (threshold {t.stale_days_expedite}). "
                              "It covers a single release, so a newer cumulative update has long replaced it.",  # type: ignore[union-attr]
                              {"age_days": age}, RiskLevel.LOW))

    risk = max((f.risk for f in flags), key=lambda r: r.rank, default=RiskLevel.LOW)
    return Assessment("update", p.id, p.display_name, risk, tuple(flags))
