"""Exchange mailboxes (shared, room, equipment) and mail flow (transport) rules. Pure functions, no I/O.

Mailbox findings need a per-mailbox check (statistics, permissions, message trace), so they exist only for the mailboxes you select:

  MAILBOX_NO_ACTIVITY       no sign-in to the mailbox for N days (default 180, or never) and no mail received in the last 89 days (MEDIUM).
  MAILBOX_NO_DELEGATES      a shared mailbox nobody can open: no Full Access holder that is an enabled account (MEDIUM).
  MAILBOX_ORPHAN_DELEGATES  Full Access or Send As given to accounts that are deleted (a bare SID) or disabled (LOW).
  LIKELY_UNUSED_MAILBOX     correlation: no activity AND (a room/equipment mailbox, or a shared one with nobody who can use it) (MEDIUM).

Rule findings come straight from the inventory (the rules are one list):

  RULE_DISABLED       the rule is switched off (LOW).
  RULE_EXPIRED        the rule has an expiry date in the past, so it no longer applies (LOW).
  RULE_NOT_ENFORCING  the rule only audits or tests (mode is not Enforce) (LOW).
  RULE_DEAD_REFERENCE the rule names an address of this tenant that matches no distribution list, mailbox, user alias or group (LOW).
                      Mail contacts and public folders are not known to Broom365, so this is a pointer to check, never a verdict.

Nothing here says "safe to delete".
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Iterable

from ..models.types import Assessment, Delegate, Flag, FlagCode, MailboxFacts, RiskLevel, RuleFacts, Thresholds
from ._time import days_between
from .exchange import TRACE_WINDOW_DAYS

LABEL = {"SharedMailbox": "shared mailbox", "RoomMailbox": "room mailbox", "EquipmentMailbox": "equipment mailbox"}
_ADDRESS = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
RULE_FIELDS_SKIPPED = {"Description", "Comments", "Name", "Identity", "DistinguishedName", "Guid", "ImmutableId"}


# ------------------------------------------------------------ parsing -------
def _rights(row: dict[str, Any]) -> str:
    raw = row.get("AccessRights")
    return " ".join(str(x) for x in raw) if isinstance(raw, (list, tuple)) else str(raw or "")


def _system_account(user: str) -> bool:
    u = user.upper()
    return u.startswith(("NT AUTHORITY\\", "NT SERVICE\\", "BUILTIN\\")) or u in ("SELF", "NT AUTHORITY\\SELF")


def full_access_trustees(rows: Iterable[dict[str, Any]]) -> list[str]:
    """Who was explicitly given Full Access (Get-MailboxPermission): not inherited, not denied, not a system account."""
    out = []
    for r in rows:
        user = str(r.get("User") or "").strip()
        if (user and "FullAccess" in _rights(r) and not r.get("IsInherited") and not r.get("Deny") and not _system_account(user)
                and user not in out):
            out.append(user)
    return out


def send_as_trustees(rows: Iterable[dict[str, Any]]) -> list[str]:
    """Who may send as the mailbox (Get-RecipientPermission): allowed, not inherited, not the mailbox itself."""
    out = []
    for r in rows:
        who = str(r.get("Trustee") or "").strip()
        if (who and "SendAs" in _rights(r) and str(r.get("AccessControlType", "Allow")) == "Allow" and not r.get("IsInherited")
                and not _system_account(who) and who not in out):
            out.append(who)
    return out


def classify_trustee(name: str, accounts: dict[str, bool | None]) -> str:
    """'deleted' (a bare SID: the account is gone), 'disabled', 'active', or 'unknown' (a group, a guest, a name Broom365 has no data for).

    `accounts` maps a lower-case UPN or mail address of an internal user to whether the account is enabled.
    """
    if re.match(r"^S-1-\d+(-\d+)+$", name.strip(), re.I):
        return "deleted"
    enabled = accounts.get(name.strip().lower())
    return "unknown" if enabled is None else ("active" if enabled else "disabled")


def extract_addresses(rule: dict[str, Any]) -> list[str]:
    """Every e-mail address mentioned by a rule's conditions, exceptions and actions (lower case, without duplicates)."""
    found: list[str] = []
    for field, value in rule.items():
        if field in RULE_FIELDS_SKIPPED or not value:
            continue
        for a in _ADDRESS.findall(str(value) if not isinstance(value, (list, dict)) else repr(value)):
            if a.lower() not in found:
                found.append(a.lower())
    return found


# ----------------------------------------------------------- mailboxes ------
def _names(ds: Iterable[Delegate], limit: int = 4) -> str:
    ds = list(ds)
    shown = ", ".join(d.name for d in ds[:limit])
    return shown + (f" and {len(ds) - limit} more" if len(ds) > limit else "")


def evaluate_mailbox(m: MailboxFacts, t: Thresholds, now: datetime) -> Assessment:
    """Flag a shared, room or equipment mailbox that looks unused or unreachable (see module docstring)."""
    label = LABEL.get(m.mailbox_type, "mailbox")
    shared = m.mailbox_type == "SharedMailbox"
    flags: list[Flag] = []
    unavailable: list[str] = []
    if not m.checked:
        unavailable.append("Sign-in, mail traffic and permissions not checked yet; check this mailbox to see whether it is used.")
        return Assessment("mailbox", m.id, m.display_name, RiskLevel.LOW, (), tuple(unavailable))

    full = [d for d in m.full_access]
    usable_full = [d for d in full if d.state in ("active", "unknown")]
    broken = [d for d in (*full, *m.send_as) if d.state in ("disabled", "deleted")]
    usable_send = [d for d in m.send_as if d.state in ("active", "unknown")]

    idle_logon = m.logon_known and (m.last_logon_at is None or days_between(m.last_logon_at, now) > t.stale_days_mailbox)
    no_mail = m.traffic_known and m.last_mail_at is None
    no_activity = bool(idle_logon and no_mail)
    last = f"last sign-in {m.last_logon_at:%Y-%m-%d}" if m.last_logon_at else "never signed in to"
    if no_activity:
        flags.append(Flag(
            FlagCode.MAILBOX_NO_ACTIVITY,
            f"This {label} has had no sign-in for more than {t.stale_days_mailbox} days ({last}) and received no mail in the last "
            f"{TRACE_WINDOW_DAYS} days.",
            {"last_logon_at": m.last_logon_at.isoformat() if m.last_logon_at else None, "window_days": TRACE_WINDOW_DAYS,
             "item_count": m.item_count}, RiskLevel.MEDIUM))

    if shared and m.delegates_known:
        if not usable_full:
            extra = f" The Full Access holders it has are not usable: {_names(d for d in full)}." if full else " Nobody has Full Access to it."
            flags.append(Flag(
                FlagCode.MAILBOX_NO_DELEGATES,
                f"Nobody can open this shared mailbox: no enabled account has Full Access.{extra}"
                + (f" It can still be used for sending ({_names(usable_send)} may send as it)." if usable_send else ""),
                {"full_access": [d.name for d in full], "send_as": [d.name for d in m.send_as]}, RiskLevel.MEDIUM))
        elif broken:
            flags.append(Flag(
                FlagCode.MAILBOX_ORPHAN_DELEGATES,
                f"{len(broken)} permission holder(s) are deleted or disabled accounts: {_names(broken)}. The permission can be removed.",
                {"orphans": [{"name": d.name, "state": d.state} for d in broken]}, RiskLevel.LOW))
    elif m.delegates_known and broken:
        flags.append(Flag(
            FlagCode.MAILBOX_ORPHAN_DELEGATES,
            f"{len(broken)} permission holder(s) are deleted or disabled accounts: {_names(broken)}.",
            {"orphans": [{"name": d.name, "state": d.state} for d in broken]}, RiskLevel.LOW))

    unreachable = shared and m.delegates_known and not usable_full and not usable_send
    if no_activity and (not shared or unreachable):
        created = f" It was created {m.created_at:%Y-%m-%d}." if m.created_at else ""
        flags.append(Flag(
            FlagCode.LIKELY_UNUSED_MAILBOX,
            f"Likely unused {label}: no sign-in or mail" + (", and nobody who could use it." if shared else ".") + created
            + " Candidate for review; it may be used where Broom365 does not look (a service sending as it, an app registration, forwarding).",
            {"shared": shared}, RiskLevel.MEDIUM))

    if not m.logon_known:
        unavailable.append("Mailbox statistics could not be read (last sign-in unknown).")
    if not m.traffic_known:
        unavailable.append("Mail traffic could not be read (message trace).")
    if shared and not m.delegates_known:
        unavailable.append("Mailbox permissions could not be read.")
    risk = max((f.risk for f in flags), key=lambda r: r.rank, default=RiskLevel.LOW)
    return Assessment("mailbox", m.id, m.display_name, risk, tuple(flags), tuple(unavailable))


# --------------------------------------------------------------- rules ------
def evaluate_rule(r: RuleFacts, now: datetime) -> Assessment:
    """Flag a mail flow rule that is off, expired, only auditing, or points at an address that no longer exists."""
    flags: list[Flag] = []
    unavailable: list[str] = []
    changed = f", last changed {r.changed_at:%Y-%m-%d}" if r.changed_at else ""
    if r.state.lower() == "disabled":
        flags.append(Flag(FlagCode.RULE_DISABLED, f"This rule is disabled, so it does nothing{changed}. Priority {r.priority}.",
                          {"state": r.state, "priority": r.priority}, RiskLevel.LOW))
    if r.expiry_at is not None and r.expiry_at < now:
        flags.append(Flag(FlagCode.RULE_EXPIRED, f"This rule expired on {r.expiry_at:%Y-%m-%d}, so it no longer applies{changed}.",
                          {"expiry_at": r.expiry_at.isoformat()}, RiskLevel.LOW))
    if r.mode and r.mode.lower() != "enforce":
        flags.append(Flag(FlagCode.RULE_NOT_ENFORCING, f"This rule is in '{r.mode}' mode: it only tests or audits and does not act on mail{changed}.",
                          {"mode": r.mode}, RiskLevel.LOW))
    if r.dead_references:
        shown = ", ".join(r.dead_references[:4]) + (f" and {len(r.dead_references) - 4} more" if len(r.dead_references) > 4 else "")
        flags.append(Flag(
            FlagCode.RULE_DEAD_REFERENCE,
            f"This rule names address(es) of this tenant that match no distribution list, mailbox, user (aliases included) or group: {shown}. "
            "They may have been deleted, or they may be mail contacts or public folders, which Broom365 does not read: check them in Exchange.",
            {"addresses": list(r.dead_references)}, RiskLevel.LOW))
    if not r.references_checked:
        unavailable.append("References to deleted addresses not checked: it needs the distribution lists, the mailbox types and the tenant's "
                           "domains to have been read.")
    risk = max((f.risk for f in flags), key=lambda x: x.rank, default=RiskLevel.LOW)
    return Assessment("rule", r.name, r.name, risk, tuple(flags), tuple(unavailable))
