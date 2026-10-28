"""Preflight check: which Graph delegated permissions were actually granted?

Pure function over a list of granted scope names (from the token response), so it is
testable without Graph. A scope may be satisfied by a broader one (e.g. Group.ReadWrite.All).
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Iterable


@dataclass(frozen=True)
class ScopeRequirement:
    scope: str
    required: bool          # True: app cannot work without it. False: some signals degrade.
    enables: str            # what this scope is used for / what is lost without it
    satisfied_by: tuple[str, ...] = ()  # broader scopes that also cover it


REQUIREMENTS: tuple[ScopeRequirement, ...] = (
    ScopeRequirement("User.Read", True, "Sign-in and identity of the operator."),
    ScopeRequirement("Group.Read.All", True, "Group list, owners, members and app assignments.",
                     ("Group.ReadWrite.All", "Directory.Read.All", "Directory.ReadWrite.All")),
    ScopeRequirement("Application.Read.All", True, "App registrations, service principals, credentials and permissions.",
                     ("Application.ReadWrite.All", "Directory.Read.All", "Directory.ReadWrite.All")),
    ScopeRequirement("Directory.Read.All", True, "Directory objects: users, deleted items, service principals.",
                     ("Directory.ReadWrite.All",)),
    ScopeRequirement("RoleManagement.Read.Directory", False,
                     "Privileged role assignments. Without it: no PRIVILEGED_ORPHAN_GROUP / DORMANT_PRIVILEGED_USER.",
                     ("RoleManagement.ReadWrite.Directory", "RoleManagement.Read.All")),
    ScopeRequirement("AuditLog.Read.All", False,
                     "Sign-in activity and audit logs. Without it: no STALE_APP, abandoned-app or dormant-user "
                     "signals; group staleness falls back to creation date."),
    ScopeRequirement("Policy.Read.All", False,
                     "Conditional Access references to groups. Without it: a group used only in a policy looks unused.",
                     ("Policy.ReadWrite.ConditionalAccess",)),
    ScopeRequirement("Exchange.ManageAsApp", False,
                     "Exchange Online: distribution lists, shared mailbox types, transport rules and message trace. It is an Application "
                     "permission of the Office 365 Exchange Online API (not Microsoft Graph), and the app also needs an Entra role such as "
                     "Global Reader. Without it: no distribution-list findings, and disabled accounts cannot be told apart from shared mailboxes."),
    ScopeRequirement("DeviceManagementApps.Read.All", False,
                     "Intune app assignments to groups. Without it: a group used only by an Intune app looks unused.",
                     ("DeviceManagementApps.ReadWrite.All",)),
    ScopeRequirement("DeviceManagementConfiguration.Read.All", False,
                     "Intune configuration, compliance, settings-catalog and script assignments to groups. "
                     "Without it: a group used only there looks unused.",
                     ("DeviceManagementConfiguration.ReadWrite.All",)),
)


@dataclass(frozen=True)
class PermissionReport:
    granted: tuple[str, ...]
    missing_required: tuple[ScopeRequirement, ...]
    missing_optional: tuple[ScopeRequirement, ...]

    @property
    def status(self) -> str:
        """'blocked' (required scope missing), 'degraded' (only optional missing) or 'ok'."""
        if self.missing_required:
            return "blocked"
        return "degraded" if self.missing_optional else "ok"

    @property
    def missing_scopes(self) -> tuple[str, ...]:
        return tuple(r.scope for r in self.missing_required + self.missing_optional)


def is_granted(permission: str, granted: Iterable[str]) -> bool:
    """True if `permission` (or a broader permission that covers it) is among the granted names."""
    have = {s.lower() for s in granted}
    covers = next(((r.scope, *r.satisfied_by) for r in REQUIREMENTS if r.scope.lower() == permission.lower()), (permission,))
    return any(c.lower() in have for c in covers)


def scopes_from_access_token(token: str) -> list[str]:
    """Permission names carried by a Graph access token: `roles` (application) plus `scp` (delegated).

    The payload is only decoded, not verified: this is used to *report* what was granted to the
    app, never to authorize anything (Graph validates the token on every call).
    """
    try:
        payload = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (IndexError, ValueError):
        return []
    return [*(claims.get("roles") or []), *str(claims.get("scp") or "").split()]


def check_permissions(granted: Iterable[str], app_only: bool = False) -> PermissionReport:
    """Compare granted permission names (case-insensitive) with REQUIREMENTS.

    `app_only` skips `User.Read`, which only exists to identify a signed-in user.
    """
    have = {s.lower() for s in granted}
    missing_req: list[ScopeRequirement] = []
    missing_opt: list[ScopeRequirement] = []
    for r in REQUIREMENTS:
        if app_only and r.scope == "User.Read":
            continue
        if not app_only and r.scope == "Exchange.ManageAsApp":
            continue  # an application role: it cannot be granted to a signed-in user
        if any(s.lower() in have for s in (r.scope, *r.satisfied_by)):
            continue
        (missing_req if r.required else missing_opt).append(r)
    return PermissionReport(tuple(sorted(have)), tuple(missing_req), tuple(missing_opt))
