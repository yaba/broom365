"""Deep links into the Intune / Entra admin centers for an object. Pure functions.

Ids are only ever put into a URL if they are GUIDs, so a hostile display name or id coming from
the tenant can never shape the link. When the tenant id is a GUID the link carries it
(`#@<tenant>/`) so the portal opens the right directory for admins with several tenants.
"""
from __future__ import annotations

import re

_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
INTUNE = "https://intune.microsoft.com/"
ENTRA = "https://entra.microsoft.com/"


def _hash(tenant_id: str | None) -> str:
    return f"#@{tenant_id}/" if tenant_id and _GUID.match(tenant_id) else "#"


def group_links(group_id: str, tenant_id: str | None = None) -> list[tuple[str, str]]:
    """[(label, url)] to open a group in Intune and in Entra; empty if the id is not a GUID."""
    if not _GUID.match(group_id or ""):
        return []
    blade = f"view/Microsoft_AAD_IAM/GroupDetailsMenuBlade/~/Overview/groupId/{group_id}/menuId/"
    return [("Open in Intune", f"{INTUNE}{_hash(tenant_id)}{blade}"), ("Open in Entra", f"{ENTRA}{_hash(tenant_id)}{blade}")]


def app_links(object_id: str, app_id: str, tenant_id: str | None = None) -> list[tuple[str, str]]:
    """[(label, url)] for the app registration (by client id) and, when a service principal id is known, the enterprise app."""
    if not _GUID.match(app_id or ""):
        return []
    h = _hash(tenant_id)
    return [("Open app registration", f"{ENTRA}{h}view/Microsoft_AAD_RegisteredApps/ApplicationMenuBlade/~/Overview/appId/{app_id}/isMSAApp~/false")]


def enterprise_app_link(sp_id: str, app_id: str, tenant_id: str | None = None) -> list[tuple[str, str]]:
    if not (_GUID.match(sp_id or "") and _GUID.match(app_id or "")):
        return []
    return [("Open enterprise app", f"{ENTRA}{_hash(tenant_id)}view/Microsoft_AAD_IAM/ManagedAppMenuBlade/~/Overview/objectId/{sp_id}/appId/{app_id}")]


def user_links(user_id: str, tenant_id: str | None = None) -> list[tuple[str, str]]:
    if not _GUID.match(user_id or ""):
        return []
    return [("Open in Entra", f"{ENTRA}{_hash(tenant_id)}view/Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/overview/userId/{user_id}")]


def intune_app_links(app_id: str, tenant_id: str | None = None) -> list[tuple[str, str]]:
    if not _GUID.match(app_id or ""):
        return []
    return [("Open in Intune", f"{INTUNE}{_hash(tenant_id)}view/Microsoft_Intune_Apps/SettingsMenu/~/0/appId/{app_id}")]
