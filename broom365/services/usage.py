"""Where a group can be *used*, and which of those places Broom365 actually checks. Pure data, no I/O.

A group with no members and no owner can still be the target of an Intune app assignment, a
Conditional Access exclusion, a licence, or a member of another group. "No usage found" therefore only
means "not found in the places listed here"; the places NOT checked are listed in `NOT_CHECKED` so the
operator knows what still has to be verified by hand.
"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True)
class UsageSource:
    signal: str        # key in signal_availability
    label: str         # plural, shown in coverage lists, e.g. "Intune apps"
    kind: str          # singular, e.g. "Intune app"
    permission: str    # Application permission needed (Graph)
    api: str           # "v1.0" or "beta"
    path: str          # collection that supports $expand=assignments ('' = handled specially)


USAGE_SOURCES: tuple[UsageSource, ...] = (
    UsageSource("policy_binding", "Conditional Access policies", "Conditional Access policy",
                "Policy.Read.All", "v1.0", ""),
    UsageSource("intune_apps", "Intune apps", "Intune app",
                "DeviceManagementApps.Read.All", "v1.0", "/deviceAppManagement/mobileApps"),
    UsageSource("intune_device_config", "Intune device configuration profiles", "Intune configuration profile",
                "DeviceManagementConfiguration.Read.All", "v1.0", "/deviceManagement/deviceConfigurations"),
    UsageSource("intune_compliance", "Intune compliance policies", "Intune compliance policy",
                "DeviceManagementConfiguration.Read.All", "v1.0", "/deviceManagement/deviceCompliancePolicies"),
    UsageSource("intune_settings_catalog", "Intune settings catalog policies", "Intune settings catalog policy",
                "DeviceManagementConfiguration.Read.All", "beta", "/deviceManagement/configurationPolicies"),
    UsageSource("intune_admx", "Intune administrative templates", "Intune administrative template",
                "DeviceManagementConfiguration.Read.All", "beta", "/deviceManagement/groupPolicyConfigurations"),
    UsageSource("intune_feature_updates", "Intune feature update profiles", "Intune feature update profile",
                "DeviceManagementConfiguration.Read.All", "beta", "/deviceManagement/windowsFeatureUpdateProfiles"),
    UsageSource("intune_quality_updates", "Intune quality update (expedite) profiles", "Intune quality update profile",
                "DeviceManagementConfiguration.Read.All", "beta", "/deviceManagement/windowsQualityUpdateProfiles"),
    UsageSource("intune_driver_updates", "Intune driver update profiles", "Intune driver update profile",
                "DeviceManagementConfiguration.Read.All", "beta", "/deviceManagement/windowsDriverUpdateProfiles"),
    UsageSource("intune_scripts", "Intune PowerShell scripts", "Intune PowerShell script",
                "DeviceManagementConfiguration.Read.All", "beta", "/deviceManagement/deviceManagementScripts"),
    UsageSource("intune_shell_scripts", "Intune macOS shell scripts", "Intune macOS shell script",
                "DeviceManagementConfiguration.Read.All", "beta", "/deviceManagement/deviceShellScripts"),
    UsageSource("intune_remediations", "Intune remediations", "Intune remediation",
                "DeviceManagementConfiguration.Read.All", "beta", "/deviceManagement/deviceHealthScripts"),
)

# Usage sources whose objects are also evaluated on their own (script kind per signal).
SCRIPT_KINDS: dict[str, str] = {"intune_scripts": "powershell", "intune_shell_scripts": "shell", "intune_remediations": "remediation"}

# Usage sources that are Windows update policies, evaluated on their own (update policy kind per signal).
# Update rings come out of the device configuration profiles ("intune_device_config") by their type.
UPDATE_KINDS: dict[str, str] = {"intune_feature_updates": "feature", "intune_quality_updates": "quality", "intune_driver_updates": "driver"}
UPDATE_RING_TYPE = "windowsUpdateForBusinessConfiguration"

LABELS: dict[str, str] = {s.signal: s.label for s in USAGE_SOURCES}
LABELS["group_nesting"] = "Membership in other groups"

# Places a group can be used that Broom365 does not look at. Shown on every group page.
NOT_CHECKED: tuple[str, ...] = (
    "Exchange Online: distribution list use, shared mailbox or calendar permissions, mail flow rules",
    "SharePoint / Teams: site, library or channel permissions granted to this group",
    "Azure RBAC role assignments on subscriptions and resources",
    "Entitlement management (access packages) and access reviews",
    "Other Intune areas: app protection, enrollment restrictions, Autopilot, filters, scope tags",
    "Administrative units and PIM for Groups",
    "Third-party apps and on-premises systems that read this group (SSO assignments in other tenants, scripts)",
)


def describe(source: str, name: str, mode: str, detail: str | None) -> str:
    """One reference as text, e.g. "Adobe Reader (assigned, uninstall)" or "Adobe Reader (excluded)".

    For an Intune exclusion Graph still reports an `intent`, but it belongs to the install assignment the group is
    excluded from, not to the group, so it is left out.
    """
    if mode == "exclude" and source.startswith("intune_"):
        return f"{name} (excluded)"
    return f"{name} ({mode}{', ' + detail if detail else ''})"


def only_uninstall_references(usages: Iterable[object]) -> bool:
    """True if the group's Intune references are uninstall assignments (plus exclusions) and nothing else.

    Needs at least one uninstall assignment; any other kind of reference (Conditional Access, install
    assignments, profiles...) makes it False.
    """
    has_uninstall = False
    for u in usages:
        if not getattr(u, "source", "").startswith("intune_"):
            return False
        if getattr(u, "mode", "") == "exclude":
            continue
        if getattr(u, "detail", None) != "uninstall":
            return False
        has_uninstall = True
    return has_uninstall
