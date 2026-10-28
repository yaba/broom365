"""Typed Microsoft Graph helpers: pagination, retry/backoff, per-endpoint accessors.

This module only fetches raw JSON (as dicts). Mapping to dataclasses happens in sync.py.
Endpoints that may be unavailable raise `SignalUnavailable` so sync can record the reason
and carry on, instead of crashing.
"""
from __future__ import annotations

import json
import re
import time
from typing import Any, Callable, Iterator

import requests

V1 = "https://graph.microsoft.com/v1.0"
BETA = "https://graph.microsoft.com/beta"
Json = dict[str, Any]
_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


class GraphError(RuntimeError):
    """Unexpected Graph failure (after retries)."""

    def __init__(self, status: int, url: str, body: str) -> None:
        super().__init__(f"Graph {status} for {url}: {body[:300]}")
        self.status = status
        self.url = url
        self.body = body

    @property
    def message(self) -> str:
        """Graph's own error message when the body is the usual {"error": {"message": ...}} JSON."""
        try:
            return str(json.loads(self.body)["error"]["message"])[:200]
        except (ValueError, KeyError, TypeError):
            return self.body[:200]


class SignalUnavailable(GraphError):
    """401/403/404-on-beta etc.: the data source cannot be read in this tenant."""


class GraphClient:
    """Thin client over `requests` with 429/5xx backoff and @odata.nextLink paging."""

    MAX_RETRIES = 6
    RETRYABLE = {429, 502, 503, 504}

    def __init__(self, token_provider: Callable[[], str | None], session: requests.Session | None = None) -> None:
        self._token_provider = token_provider
        self._http = session or requests.Session()

    # ------------------------------------------------------------ transport
    def get(self, url: str, params: Json | None = None, headers: Json | None = None) -> Json:
        """GET one URL, retrying on throttling. Raises SignalUnavailable on 401/403."""
        for attempt in range(self.MAX_RETRIES + 1):
            token = self._token_provider()
            if token is None:
                raise SignalUnavailable(401, url, "no access token")
            resp = self._http.get(
                url, params=params, timeout=60,
                headers={"Authorization": f"Bearer {token}", **(headers or {})},
            )
            if resp.status_code in self.RETRYABLE and attempt < self.MAX_RETRIES:
                time.sleep(self._retry_delay(resp, attempt))
                continue
            if resp.status_code in (401, 403):
                raise SignalUnavailable(resp.status_code, url, resp.text)
            if not resp.ok:
                raise GraphError(resp.status_code, url, resp.text)
            return resp.json() if resp.content else {}
        raise GraphError(429, url, "retries exhausted")  # pragma: no cover

    @staticmethod
    def _retry_delay(resp: requests.Response, attempt: int) -> float:
        """Honour Retry-After when present, else exponential backoff capped at 60s."""
        retry_after = resp.headers.get("Retry-After")
        if retry_after and retry_after.isdigit():
            return float(retry_after)
        return float(min(60, 2 ** attempt))

    def paginate(self, url: str, params: Json | None = None, headers: Json | None = None) -> Iterator[Json]:
        """Yield every item across all pages of a collection."""
        next_url: str | None = url
        while next_url:
            page = self.get(next_url, params=params if next_url == url else None, headers=headers)
            yield from page.get("value", [])
            next_url = page.get("@odata.nextLink")

    def count(self, url: str) -> int:
        """Return `$count` for a collection (requires ConsistencyLevel: eventual)."""
        resp = self._http.get(
            f"{url}/$count", timeout=60,
            headers={"Authorization": f"Bearer {self._token_provider()}", "ConsistencyLevel": "eventual"},
        )
        if resp.status_code in (401, 403):
            raise SignalUnavailable(resp.status_code, url, resp.text)
        if not resp.ok:
            raise GraphError(resp.status_code, url, resp.text)
        return int(resp.text)

    # ------------------------------------------------------------- groups
    def list_groups(self) -> Iterator[Json]:
        select = "id,displayName,description,createdDateTime,membershipRule,mailEnabled,securityEnabled,assignedLicenses,groupTypes,mail,proxyAddresses"
        yield from self.paginate(f"{V1}/groups", {"$select": select, "$top": 999})

    def group_owners(self, group_id: str) -> list[Json]:
        return list(self.paginate(f"{V1}/groups/{group_id}/owners", {"$select": "id,displayName"}))

    def group_member_count(self, group_id: str) -> int:
        """Direct member count via $count (cheap; never enumerates members)."""
        return self.count(f"{V1}/groups/{group_id}/members")

    def group_transitive_member_count(self, group_id: str) -> int:
        """Transitive count via $count. Use sparingly: expensive for large nested groups."""
        return self.count(f"{V1}/groups/{group_id}/transitiveMembers")

    def group_app_role_assignments(self, group_id: str) -> list[Json]:
        return list(self.paginate(f"{V1}/groups/{group_id}/appRoleAssignments"))

    # --------------------------------------------- applications / SPs (extended)
    def list_applications(self) -> Iterator[Json]:
        select = "id,appId,displayName,createdDateTime,passwordCredentials,keyCredentials"
        yield from self.paginate(f"{V1}/applications", {"$select": select, "$top": 999})

    def application_owners(self, application_id: str) -> list[Json]:
        return list(self.paginate(f"{V1}/applications/{application_id}/owners", {"$select": "id,displayName"}))

    def list_service_principals(self) -> Iterator[Json]:
        select = "id,appId,displayName,accountEnabled,servicePrincipalType,appOwnerOrganizationId"
        yield from self.paginate(f"{V1}/servicePrincipals", {"$select": select, "$top": 999})

    def get_service_principal(self, sp_id: str) -> Json | None:
        """Return the SP or None if it no longer exists (404)."""
        try:
            return self.get(f"{V1}/servicePrincipals/{sp_id}")
        except GraphError as exc:
            if exc.status == 404:
                return None
            raise

    def sp_oauth2_permission_grants(self, sp_id: str) -> list[Json]:
        """Delegated permission grants where this SP is the client."""
        return list(self.paginate(f"{V1}/servicePrincipals/{sp_id}/oauth2PermissionGrants"))

    def sp_app_role_assignments(self, sp_id: str) -> list[Json]:
        """Application permissions granted to this SP."""
        return list(self.paginate(f"{V1}/servicePrincipals/{sp_id}/appRoleAssignments"))

    # ------------------------------------------------------- roles / users
    def list_role_assignments(self) -> Iterator[Json]:
        """Active directory role assignments. Only `principal` is expanded (it carries the object type);
        role names come from `list_role_definitions`, since this endpoint can reject combined expands."""
        yield from self.paginate(f"{V1}/roleManagement/directory/roleAssignments", {"$expand": "principal"})

    def list_role_definitions(self) -> Iterator[Json]:
        """Directory role definitions (id -> displayName)."""
        yield from self.paginate(f"{V1}/roleManagement/directory/roleDefinitions", {"$select": "id,displayName"})

    # ------------------------------------------------------------- users, in batches
    USER_BATCH = 15   # Graph rejects an `id in (...)` filter with more than 15 values

    def users_by_ids(self, ids: list[str], with_sign_in: bool = False) -> list[Json]:
        """Look up users by id in ONE call (at most `USER_BATCH` ids; non-GUID ids are ignored).

        With `with_sign_in` the BETA endpoint is used so each user also carries `signInActivity`
        (needs AuditLog.Read.All and Entra ID P1/P2). A single-user read of that property takes seconds;
        this returns the whole batch in about one.
        """
        if len(ids) > self.USER_BATCH:
            raise ValueError(f"at most {self.USER_BATCH} ids per call")
        valid = [i for i in ids if _GUID.match(i or "")]
        if not valid:
            return []
        select = "id,displayName,userPrincipalName,accountEnabled,userType" + (",signInActivity" if with_sign_in else "")
        quoted = ",".join(f"'{i}'" for i in valid)
        return list(self.paginate(f"{BETA if with_sign_in else V1}/users", {"$select": select, "$filter": f"id in ({quoted})"}))

    # ------------------------------------------------ BETA: sign-in activity
    def list_sp_sign_in_activities(self) -> Iterator[Json]:
        """BETA. Bulk SP activity report (`lastSignInActivity` per appId).

        Note: Graph exposes SP sign-in activity via /reports/servicePrincipalSignInActivities,
        not /servicePrincipals/{id}/signInActivity, so one bulk call replaces N per-SP calls.
        """
        yield from self.paginate(f"{BETA}/reports/servicePrincipalSignInActivities")

    # ------------------------------------------- bulk / lookup helpers (sync)
    def list_oauth2_permission_grants(self) -> Iterator[Json]:
        """All delegated permission grants in the tenant (one paged call instead of one per SP)."""
        yield from self.paginate(f"{V1}/oauth2PermissionGrants", {"$top": 999})

    def get_service_principal_roles(self, sp_id: str) -> Json:
        """A resource SP's appRoles, used to translate appRoleId GUIDs into permission names."""
        return self.get(f"{V1}/servicePrincipals/{sp_id}", {"$select": "id,displayName,appRoles"})

    def list_deleted_service_principals(self) -> Iterator[Json]:
        """Soft-deleted service principals (id, deletedDateTime), kept ~30 days."""
        yield from self.paginate(
            f"{V1}/directory/deletedItems/microsoft.graph.servicePrincipal", {"$select": "id,displayName,deletedDateTime"}
        )

    def list_conditional_access_policies(self) -> Iterator[Json]:
        """Conditional Access policies (needs Policy.Read.All); used to detect group policy bindings."""
        yield from self.paginate(f"{V1}/identity/conditionalAccess/policies")

    def list_group_membership_audits(self, since: str) -> Iterator[Json]:
        """GroupManagement audit events since `since` (needs AuditLog.Read.All; short retention).

        `since` must be an OData datetime such as 2026-04-28T19:00:00Z (a '+00:00' offset is rejected).
        A large page size is tried first; if Graph answers 400 the request is repeated with its default.
        """
        url = f"{V1}/auditLogs/directoryAudits"
        params: Json = {"$filter": f"category eq 'GroupManagement' and activityDateTime ge {since}", "$top": 999}
        try:
            page = self.get(url, params)
        except GraphError as exc:
            if exc.status != 400:
                raise
            params.pop("$top")
            page = self.get(url, params)
        yield from page.get("value", [])
        next_url = page.get("@odata.nextLink")
        if next_url:
            yield from self.paginate(next_url)

    # ------------------------------------------------- where a group is used
    def list_with_assignments(self, api: str, path: str) -> Iterator[Json]:
        """A collection with its `assignments` expanded (Intune apps, profiles, policies...)."""
        base = BETA if api == "beta" else V1
        yield from self.paginate(f"{base}{path}", {"$expand": "assignments"})

    def group_member_of(self, group_id: str) -> list[Json]:
        """Groups that this group is a direct member of (nesting)."""
        return list(self.paginate(f"{V1}/groups/{group_id}/memberOf/microsoft.graph.group", {"$select": "id,displayName"}))

    # --------------------------------------------- Intune: details per object
    def app_relationships(self, app_id: str) -> list[Json]:
        """BETA. Dependency / supersedence links of an Intune app (`source` is always this app)."""
        return list(self.paginate(f"{BETA}/deviceAppManagement/mobileApps/{app_id}/relationships"))

    def script_run_summary(self, collection_path: str, script_id: str) -> Json:
        """BETA. runSummary of a script or remediation: success/error counts, last run time."""
        return self.get(f"{BETA}{collection_path}/{script_id}/runSummary")

    # ------------------------------------------------------ external (guest) users
    def list_guests(self, with_sign_in: bool = False) -> Iterator[Json]:
        """Every guest user, as one paged list. With `with_sign_in` the BETA endpoint adds `signInActivity` (120 per page)."""
        select = ("id,displayName,mail,userPrincipalName,accountEnabled,createdDateTime,externalUserState,"
                  "externalUserStateChangeDateTime,userType" + (",signInActivity" if with_sign_in else ""))
        yield from self.paginate(f"{BETA if with_sign_in else V1}/users",
                                 {"$filter": "userType eq 'Guest'", "$select": select, "$top": "120" if with_sign_in else "999"},
                                 {"ConsistencyLevel": "eventual"})

    def guest_memberships(self, user_id: str) -> list[Json]:
        """Groups and Teams a user belongs to, including through nested groups (one call per user)."""
        return list(self.paginate(
            f"{V1}/users/{user_id}/transitiveMemberOf/microsoft.graph.group",
            {"$select": "id,displayName,groupTypes,securityEnabled,resourceProvisioningOptions", "$top": "999"},
            {"ConsistencyLevel": "eventual"}))

    # ------------------------------------------------- internal (member) users
    def list_members(self, with_sign_in: bool = False) -> Iterator[Json]:
        """Every internal user, as one paged list, with licences. The BETA endpoint adds `signInActivity` (120 per page)."""
        select = ("id,displayName,mail,userPrincipalName,accountEnabled,createdDateTime,onPremisesSyncEnabled,assignedLicenses,userType,proxyAddresses"
                  + (",signInActivity" if with_sign_in else ""))
        yield from self.paginate(f"{BETA if with_sign_in else V1}/users",
                                 {"$filter": "userType eq 'Member'", "$select": select, "$top": "120" if with_sign_in else "999"},
                                 {"ConsistencyLevel": "eventual"})

    def list_skus(self) -> list[Json]:
        """Licence SKUs of the tenant: skuId -> skuPartNumber."""
        return list(self.paginate(f"{V1}/subscribedSkus"))
