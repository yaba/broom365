"""External (guest) users: stale and never-accepted guests. Pure functions, no I/O.

Guests are people from other organisations who were invited once. Many are used for a project and never
return, yet keep an access path into the tenant. Two findings:

  STALE_GUEST    no sign-in for N days (default 365); or, for a guest who never signed in, invited longer ago than N days.
  PENDING_GUEST  the invitation was never accepted after N days (default 90). A pending guest never signed in, so it
                 gets this flag only, not STALE_GUEST as well.

A disabled guest is inert, so it is only LOW; an enabled one is MEDIUM. When the guest's group memberships have been
checked on demand, the explanation says what access is still open (groups and Teams, nested ones included); if they have
not been checked the finding says so. Nothing says "safe to delete".
"""
from __future__ import annotations

from datetime import datetime

from ..models.types import Assessment, Flag, FlagCode, GuestFacts, RiskLevel, Thresholds
from ._time import days_between


def guest_domain(mail: str | None, upn: str | None) -> str | None:
    """The guest's home domain: from `mail`, else from the `name_domain#EXT#@tenant` user principal name."""
    if mail and "@" in mail:
        return mail.rsplit("@", 1)[1].lower()
    if upn and "#EXT#" in upn:
        local = upn.split("#EXT#", 1)[0]
        if "_" in local:
            return local.rsplit("_", 1)[1].lower()
    return None


def _who(g: GuestFacts) -> str:
    d = guest_domain(g.mail, g.user_principal_name)
    return f"External guest from {d}" if d else "External guest"


def _by_assignment(g: GuestFacts) -> list:
    """Memberships that were given deliberately (a Team or an assigned group); unknown groups count as assigned."""
    return [m for m in (g.memberships or ()) if m.dynamic is not True]


def _dynamic(g: GuestFacts) -> list:
    return [m for m in (g.memberships or ()) if m.dynamic is True]


def _member_names(g: GuestFacts) -> list[str]:
    """Assigned memberships, Teams first."""
    ordered = sorted(_by_assignment(g), key=lambda m: (m.kind != "team", m.name.lower()))
    return [f"'{m.name}'" + (" (Team)" if m.kind == "team" else "") for m in ordered]


def _member_phrase(g: GuestFacts) -> str:
    """What the guest can still reach through groups; empty when memberships were not checked.

    Dynamic (rule-based) groups such as 'All Users' catch nearly every guest automatically, so they are reported
    apart: they are not access that someone granted on purpose.
    """
    if g.memberships is None:
        return ""
    if not g.memberships:
        return " It is a member of no group, so no group-based access would be lost."
    names, dyn = _member_names(g), _dynamic(g)
    dyn_text = (f"{len(dyn)} dynamic (rule-based) group(s) such as '{sorted(dyn, key=lambda m: m.name.lower())[0].name}'" if dyn else "")
    if not names:
        return f" It belongs to no group by assignment, only to {dyn_text}, so no deliberate group access would be lost."
    more = f" and {len(names) - 4} more" if len(names) > 4 else ""
    tail = f" It is also in {dyn_text}." if dyn else ""
    return f" It is still a member of {len(names)} group(s) by assignment: {', '.join(names[:4])}{more}.{tail}"


def evaluate_guest(g: GuestFacts, t: Thresholds, now: datetime) -> Assessment:
    """Flag a guest that looks abandoned (see module docstring)."""
    flags: list[Flag] = []
    unavailable: list[str] = []
    disabled = g.account_enabled is False
    risk = RiskLevel.LOW if disabled else RiskLevel.MEDIUM
    inert = " The account is disabled, so it is already inert; only the leftover object remains." if disabled else ""
    invited = g.state_changed_at or g.created_at
    members = _member_phrase(g)
    member_evidence = {"member_of": _member_names(g) if g.memberships is not None else None,
                       "dynamic_groups": len(_dynamic(g)) if g.memberships is not None else None}

    if g.external_state == "PendingAcceptance":
        age = days_between(invited, now) if invited else None
        if age is not None and age > t.pending_days_guest:
            flags.append(Flag(
                FlagCode.PENDING_GUEST,
                f"{_who(g)} was invited on {invited:%Y-%m-%d}, {age} days ago (threshold {t.pending_days_guest}), and never accepted "
                f"the invitation.{members}{inert} Candidate for review.",
                {"invited_at": invited.isoformat(), "age_days": age, "account_enabled": g.account_enabled, **member_evidence},
                RiskLevel.LOW))
    elif not g.sign_in_available:
        unavailable.append("Guest sign-in activity unavailable (beta endpoint, licence or AuditLog.Read.All); stale-guest check skipped.")
    elif g.last_sign_in_at is not None:
        idle = days_between(g.last_sign_in_at, now)
        if idle > t.stale_days_guest:
            flags.append(Flag(
                FlagCode.STALE_GUEST,
                f"{_who(g)} last signed in on {g.last_sign_in_at:%Y-%m-%d}, {idle} days ago (threshold {t.stale_days_guest}).{members}{inert} "
                "Candidate for review.",
                {"last_sign_in_at": g.last_sign_in_at.isoformat(), "idle_days": idle, "account_enabled": g.account_enabled,
                 **member_evidence}, risk))
    elif invited is not None and days_between(invited, now) > t.stale_days_guest:
        age = days_between(invited, now)
        flags.append(Flag(
            FlagCode.STALE_GUEST,
            f"{_who(g)} has no sign-in on record and was added on {invited:%Y-%m-%d}, {age} days ago (threshold {t.stale_days_guest}).{members}"
            f"{inert} Candidate for review.",
            {"last_sign_in_at": None, "added_at": invited.isoformat(), "age_days": age, "account_enabled": g.account_enabled,
             **member_evidence}, risk))

    if flags and g.memberships is None:
        unavailable.append("Group memberships not checked yet; check this guest to see what access it still has.")
    out_risk = max((f.risk for f in flags), key=lambda r: r.rank, default=RiskLevel.LOW)
    return Assessment("guest", g.id, g.display_name, out_risk, tuple(flags), tuple(unavailable))
