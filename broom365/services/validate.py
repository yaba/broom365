"""Permission validation: one real, minimal Graph call per data source Broom365 reads.

Reading the token's roles only says what was *granted*. Probing each endpoint says what actually *works*, and
separates three very different failures: the permission is missing (add it), the permission is granted but
Graph still refuses (licence / role), or Graph rejected the request itself (not a permission problem).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

import requests

from .graph import BETA, V1, GraphClient, GraphError, SignalUnavailable
from .permissions import is_granted
from .usage import USAGE_SOURCES


@dataclass(frozen=True)
class Probe:
    key: str
    label: str
    permission: str            # exact Graph permission name that unlocks it
    api: str                   # "v1.0" | "beta"
    path: str
    params: dict[str, str] = field(default_factory=dict)


_TOP = {"$top": "1"}
PROBES: tuple[Probe, ...] = (
    Probe("groups", "Groups", "Group.Read.All", "v1.0", "/groups", {**_TOP, "$select": "id"}),
    Probe("applications", "App registrations", "Application.Read.All", "v1.0", "/applications", {**_TOP, "$select": "id"}),
    Probe("service_principals", "Service principals", "Application.Read.All", "v1.0", "/servicePrincipals", {**_TOP, "$select": "id"}),
    Probe("users", "Users", "Directory.Read.All", "v1.0", "/users", {**_TOP, "$select": "id"}),
    Probe("guests", "External (guest) users", "Directory.Read.All", "v1.0", "/users",
          {"$filter": "userType eq 'Guest'", "$select": "id", "$top": "1"}),
    Probe("members", "Internal (member) users", "Directory.Read.All", "v1.0", "/users",
          {"$filter": "userType eq 'Member'", "$select": "id", "$top": "1"}),
    Probe("skus", "Licence SKUs", "Directory.Read.All", "v1.0", "/subscribedSkus"),
    Probe("grants", "Delegated permission grants", "Directory.Read.All", "v1.0", "/oauth2PermissionGrants", dict(_TOP)),
    Probe("deleted", "Deleted service principals", "Directory.Read.All", "v1.0",
          "/directory/deletedItems/microsoft.graph.servicePrincipal", {**_TOP, "$select": "id"}),
    Probe("role_assignments", "Directory role assignments", "RoleManagement.Read.Directory", "v1.0",
          "/roleManagement/directory/roleAssignments", {"$expand": "principal", **_TOP}),
    Probe("role_definitions", "Directory role definitions", "RoleManagement.Read.Directory", "v1.0",
          "/roleManagement/directory/roleDefinitions", {"$select": "id"}),  # rejects $top below 20
    Probe("audit", "Directory audit log", "AuditLog.Read.All", "v1.0", "/auditLogs/directoryAudits", dict(_TOP)),
    Probe("sp_sign_ins", "Service principal sign-in activity (beta)", "AuditLog.Read.All", "beta",
          "/reports/servicePrincipalSignInActivities", dict(_TOP)),
    Probe("user_sign_ins", "User sign-in activity (beta)", "AuditLog.Read.All", "beta", "/users",
          {"$select": "id,signInActivity", **_TOP}),
    Probe("policy_binding", "Conditional Access policies", "Policy.Read.All", "v1.0", "/identity/conditionalAccess/policies"),
    *(Probe(s.signal, s.label, s.permission, s.api, s.path, {"$expand": "assignments", **_TOP})
      for s in USAGE_SOURCES if s.path),
)


@dataclass(frozen=True)
class ProbeResult:
    probe: Probe
    permission_granted: bool
    status: str        # ok | missing | denied | rejected | not_found | error
    http: int | None
    message: str
    advice: str

    @property
    def ok(self) -> bool:
        return self.status == "ok"


def _advice(status: str, permission: str, perm_type: str, message: str) -> str:
    if permission == "Exchange.ManageAsApp" and status in ("missing", "denied"):
        return ("Add the Application permission Exchange.ManageAsApp (API: Office 365 Exchange Online), grant admin consent, and assign the "
                f"app an Entra role such as Global Reader (or Exchange Administrator). Exchange said: {message or 'access denied'}.")
    if status == "missing":
        return (f"Add the {perm_type} permission {permission} (Microsoft Graph) to the app registration "
                "and grant admin consent.")
    if status == "denied":
        return (f"{permission} is granted, but Graph still refused access ({message}). Check the licence this data needs "
                "(for example Microsoft Entra ID P1/P2 for sign-in activity, or Intune) and any directory role requirement.")
    if status == "rejected":
        return (f"Not a permission problem: Graph rejected the request itself ({message}). Broom365 skips this signal; "
                "please report this message.")
    if status == "not_found":
        return f"Graph says the resource does not exist ({message}). Usually the service is not licensed or enabled in this tenant."
    return f"Unexpected response: {message}" if status == "error" else ""


def run_probes(graph: GraphClient, granted: Iterable[str], perm_type: str = "Application",
               probes: tuple[Probe, ...] = PROBES, exchange: Any = None) -> list[ProbeResult]:
    """Probe every data source with a minimal read. Never raises: each failure becomes a classified result."""
    have = list(granted)
    results: list[ProbeResult] = []
    for p in probes:
        is_ok = is_granted(p.permission, have)
        http: int | None = 200
        message = ""
        try:
            graph.get(f"{BETA if p.api == 'beta' else V1}{p.path}", dict(p.params) or None)
            status = "ok"
        except SignalUnavailable as exc:
            status, http, message = ("denied" if is_ok else "missing"), exc.status, exc.message
        except GraphError as exc:
            status, http, message = {400: "rejected", 404: "not_found"}.get(exc.status, "error"), exc.status, exc.message
        except requests.RequestException as exc:
            status, http, message = "error", None, str(exc)[:200]
        results.append(ProbeResult(p, is_ok, status, http, message, _advice(status, p.permission, perm_type, message)))
    if exchange is not None:
        probe = Probe("exchange", "Exchange Online (distribution lists)", "Exchange.ManageAsApp", "exchange", "Get-DistributionGroup")
        is_ok = is_granted(probe.permission, have)
        http, message = 200, ""
        try:
            exchange.invoke("Get-DistributionGroup", ResultSize=1)
            status = "ok"
        except SignalUnavailable as exc:
            status, http, message = ("denied" if is_ok else "missing"), exc.status, exc.message
        except GraphError as exc:
            status, http, message = {400: "rejected", 404: "not_found"}.get(exc.status, "error"), exc.status, exc.message
        except requests.RequestException as exc:
            status, http, message = "error", None, str(exc)[:200]
        results.append(ProbeResult(probe, is_ok, status, http, message, _advice(status, probe.permission, perm_type, message)))
    return results


def missing_permissions(results: Iterable[ProbeResult]) -> list[str]:
    """Distinct permission names that must be added, in the order they were first needed."""
    seen: list[str] = []
    for r in results:
        if r.status == "missing" and r.probe.permission not in seen:
            seen.append(r.probe.permission)
    return seen
