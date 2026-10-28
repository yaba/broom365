"""Internal (member) users: accounts that cost money or linger without being used. Pure functions, no I/O.

  DISABLED_LICENSED_MEMBER  the account is disabled but still holds paid licences: paid for, usable by nobody (MEDIUM).
  DISABLED_MEMBER           a disabled account with no paid licence that is NOT a shared, room or equipment mailbox (those are
                            disabled by design): a leftover account (LOW). Needs the Exchange mailbox types to have been read.
  STALE_MEMBER              an enabled account with no sign-in for N days (default 180), or created longer ago than that
                            and never signed in. MEDIUM if it holds a paid licence, otherwise LOW.

Sign-in is the newest of the interactive, non-interactive and successful sign-ins, so a service account that only signs in
non-interactively is not reported as idle. Free licences (Power Automate free, Power BI free...) are not treated as spend.
Accounts synced from on-premises Active Directory are called out: they must be changed there. Nothing says "safe to delete".
"""
from __future__ import annotations

from datetime import datetime

from ..models.types import Assessment, Flag, FlagCode, MemberFacts, RiskLevel, Thresholds
from ._time import days_between

# SKUs that cost nothing, by skuPartNumber. Holding only these is not wasted spend.
FREE_LICENCES = frozenset({
    "FLOW_FREE", "POWER_BI_STANDARD", "POWERAPPS_VIRAL", "STREAM", "WINDOWS_STORE", "TEAMS_EXPLORATORY",
    "MICROSOFT_BUSINESS_CENTER", "CCIBOTS_PRIVPREV_VIRAL", "POWERAUTOMATE_ATTENDED_RPA", "DYN365_BUSCENTRAL_ESSENTIAL",
})


def paid_licences(m: MemberFacts) -> list[str]:
    """The licences of an account that are not on the free list, sorted."""
    return sorted(x for x in m.licences if x not in FREE_LICENCES)


def _licence_text(paid: list[str]) -> str:
    if not paid:
        return " It holds no paid licence."
    shown = ", ".join(paid[:4]) + (f" and {len(paid) - 4} more" if len(paid) > 4 else "")
    return f" It holds {len(paid)} paid licence(s): {shown}."


def evaluate_member(m: MemberFacts, t: Thresholds, now: datetime) -> Assessment:
    """Flag an internal account that is disabled-but-licensed, a disabled leftover, or idle (see module docstring)."""
    flags: list[Flag] = []
    unavailable: list[str] = []
    paid = paid_licences(m)
    synced = " It is synced from on-premises Active Directory, so it must be changed there." if m.on_prem_synced else ""
    evidence = {"account_enabled": m.account_enabled, "licences": list(m.licences), "paid_licences": paid,
                "on_prem_synced": m.on_prem_synced}

    if m.account_enabled is False:
        if paid:
            shown = ", ".join(paid[:4]) + (f" and {len(paid) - 4} more" if len(paid) > 4 else "")
            flags.append(Flag(
                FlagCode.DISABLED_LICENSED_MEMBER,
                f"Disabled account that still holds {len(paid)} paid licence(s): {shown}. The licence(s) are paid for but nobody can "
                f"use them; remove them, then review the account for deletion.{synced}",
                evidence, RiskLevel.MEDIUM))
        elif m.mailbox_type:
            pass  # a shared, room or equipment mailbox: Exchange disables the sign-in on purpose
        elif m.mailboxes_read:
            seen = (f" It last signed in on {m.last_sign_in_at:%Y-%m-%d}." if m.last_sign_in_at
                    else " No sign-in is on record.") if m.sign_in_available else ""
            created = f" Created {m.created_at:%Y-%m-%d}." if m.created_at else ""
            flags.append(Flag(
                FlagCode.DISABLED_MEMBER,
                "Disabled account with no paid licence that is not a shared, room or equipment mailbox: a leftover account."
                f"{created}{seen}{synced} Candidate for review.",
                {**evidence, "last_sign_in_at": m.last_sign_in_at.isoformat() if m.last_sign_in_at else None}, RiskLevel.LOW))
        else:
            unavailable.append("Exchange mailbox types not read yet: a disabled account without a licence cannot be told apart from a "
                               "shared, room or equipment mailbox (disabled by design).")
    elif not m.sign_in_available:
        unavailable.append("Internal-user sign-in activity unavailable (beta endpoint, licence or AuditLog.Read.All); stale-account check skipped.")
    elif m.last_sign_in_at is not None:
        idle = days_between(m.last_sign_in_at, now)
        if idle > t.stale_days_member:
            flags.append(Flag(
                FlagCode.STALE_MEMBER,
                f"Internal user last signed in on {m.last_sign_in_at:%Y-%m-%d}, {idle} days ago (threshold {t.stale_days_member}).{_licence_text(paid)}"
                f"{synced} Service and shared accounts may not sign in interactively. Candidate for review.",
                {**evidence, "last_sign_in_at": m.last_sign_in_at.isoformat(), "idle_days": idle},
                RiskLevel.MEDIUM if paid else RiskLevel.LOW))
    elif m.created_at is not None and days_between(m.created_at, now) > t.stale_days_member:
        age = days_between(m.created_at, now)
        flags.append(Flag(
            FlagCode.STALE_MEMBER,
            f"Internal user has no sign-in on record and was created on {m.created_at:%Y-%m-%d}, {age} days ago (threshold {t.stale_days_member})."
            f"{_licence_text(paid)}{synced} Service and shared accounts may not sign in interactively. Candidate for review.",
            {**evidence, "last_sign_in_at": None, "age_days": age}, RiskLevel.MEDIUM if paid else RiskLevel.LOW))

    risk = max((f.risk for f in flags), key=lambda r: r.rank, default=RiskLevel.LOW)
    return Assessment("member", m.id, m.display_name, risk, tuple(flags), tuple(unavailable))
