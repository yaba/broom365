"""Exchange distribution lists: unused, empty and ownerless lists. Pure functions, no I/O.

  DL_NO_OWNER       the list has no owner (LOW). Known from the inventory.
  DL_EMPTY          checked, and it has no members: mail sent to it goes nowhere (MEDIUM).
  DL_NO_MAIL        checked, and no mail was addressed to it in the last 89 days, the longest history message trace keeps (MEDIUM).
  LIKELY_UNUSED_DL  correlation: no mail AND (empty OR ownerless) AND no transport rule mentions it (MEDIUM).

Members and mail traffic are per-list reads, so they are checked on demand; until then the finding says so. A list can also be
used where this module cannot see (shared mailbox and calendar permissions, membership of other lists, SharePoint): every
explanation says "candidate for review", never "safe to delete".
"""
from __future__ import annotations

from datetime import datetime

from ..models.types import Assessment, DistributionListFacts, Flag, FlagCode, RiskLevel
from .exchange import TRACE_WINDOW_DAYS

LABEL = {"distribution": "distribution list", "security": "mail-enabled security group", "dynamic": "dynamic distribution list"}


def _dates(dl: DistributionListFacts) -> str:
    parts = []
    if dl.created_at:
        parts.append(f"created {dl.created_at:%Y-%m-%d}")
    if dl.changed_at:
        parts.append(f"last changed {dl.changed_at:%Y-%m-%d}")
    return f" ({', '.join(parts)})" if parts else ""


def evaluate_distribution_list(dl: DistributionListFacts, now: datetime) -> Assessment:
    """Flag a list that looks unused or unowned (see module docstring)."""
    label = LABEL[dl.kind]
    flags: list[Flag] = []
    unavailable: list[str] = []
    synced = " It is synced from on-premises Active Directory, so it must be changed there." if dl.synced else ""

    if not dl.owners:
        flags.append(Flag(FlagCode.DL_NO_OWNER, f"This {label} has no owner, so nobody is accountable for it.{synced}",
                          {"owners": 0}, RiskLevel.LOW))

    empty = dl.checked and dl.member_count == 0
    if empty:
        flags.append(Flag(FlagCode.DL_EMPTY, f"This {label} has no members, so mail sent to it goes nowhere.{synced}",
                          {"member_count": 0}, RiskLevel.MEDIUM))

    no_mail = dl.checked and dl.traffic_known and dl.last_mail_at is None
    if dl.rules:
        rule_text = f" A transport rule mentions it: {', '.join(repr(r) for r in dl.rules[:3])}."
    elif dl.rules_known:
        rule_text = " No transport rule mentions it."
    else:
        rule_text = " Transport rules could not be read."
    if no_mail:
        flags.append(Flag(
            FlagCode.DL_NO_MAIL,
            f"No mail was addressed to this {label} in the last {TRACE_WINDOW_DAYS} days (the longest history Exchange keeps for "
            f"message trace).{rule_text}",
            {"window_days": TRACE_WINDOW_DAYS, "rules": list(dl.rules)}, RiskLevel.MEDIUM))
        if (empty or not dl.owners) and dl.rules_known and not dl.rules:
            why = " and ".join(x for x in ("it has no members" if empty else "", "it has no owner" if not dl.owners else "") if x)
            flags.append(Flag(
                FlagCode.LIKELY_UNUSED_DL,
                f"No mail in the last {TRACE_WINDOW_DAYS} days, {why}, and no transport rule mentions it{_dates(dl)}: this {label} is "
                "likely unused and a candidate for review. It may still be used where Broom365 does not look (shared mailbox and "
                f"calendar permissions, membership of other lists, SharePoint).{synced}",
                {"empty": empty, "ownerless": not dl.owners, "window_days": TRACE_WINDOW_DAYS}, RiskLevel.MEDIUM))

    if not dl.checked:
        unavailable.append("Members and mail traffic not checked yet; check this list to see whether it is used.")
    else:
        if dl.member_count is None:
            unavailable.append("Member count could not be read.")
        if not dl.traffic_known:
            unavailable.append("Mail traffic could not be read (message trace).")
    risk = max((f.risk for f in flags), key=lambda r: r.rank, default=RiskLevel.LOW)
    return Assessment("dl", dl.id, dl.display_name, risk, tuple(flags), tuple(unavailable))
