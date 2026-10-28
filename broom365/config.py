"""Application configuration: environment values plus default thresholds.

Secrets come from the environment (.env). Thresholds and the high-risk scope list are
only *defaults* here; the user-editable values live in the `settings` table.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

# `offline_access` is required by the product, but MSAL adds it (and openid/profile)
# automatically and raises if it is passed explicitly. It is therefore not listed here.
GRAPH_SCOPES: tuple[str, ...] = (
    "User.Read",
    "Group.Read.All",
    "Application.Read.All",
    "Directory.Read.All",
    "RoleManagement.Read.Directory",
    "AuditLog.Read.All",
    "Policy.Read.All",  # Conditional Access references, for UNKNOWN_USE
    "DeviceManagementApps.Read.All",           # Intune app assignments to groups
    "DeviceManagementConfiguration.Read.All",  # Intune profiles, compliance, scripts assigned to groups
)

# Everything the demo pretends to have been granted: the Graph scopes plus the Exchange application role (not a Graph scope).
DEMO_PERMISSIONS: tuple[str, ...] = GRAPH_SCOPES + ("Exchange.ManageAsApp",)

_BUILTIN_RISKY_SCOPES: tuple[str, ...] = (
    "AccessReview.ReadWrite.All",
    "AdministrativeUnit.ReadWrite.All",
    "APIConnectors.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "Application.ReadWrite.All",
    "Application.ReadWrite.OwnedBy",
    "AttackSimulation.ReadWrite.All",
    "AuditLog.Read.All",
    "AuthenticationContext.ReadWrite.All",
    "Calendars.Read",
    "Calendars.Read.Shared",
    "Calendars.ReadWrite",
    "Calendars.ReadWrite.Shared",
    "ChannelMessage.Read.All",
    "ChannelMessage.Send",
    "Chat.Read",
    "Chat.Read.All",
    "Chat.Read.WhereInstalled",
    "Chat.ReadWrite",
    "Chat.ReadWrite.All",
    "Chat.ReadWrite.WhereInstalled",
    "ChatMember.ReadWrite",
    "ChatMember.ReadWrite.All",
    "ChatMessage.Send",
    "Contacts.Read",
    "Contacts.Read.Shared",
    "Contacts.ReadWrite",
    "Contacts.ReadWrite.Shared",
    "CustomSecAttributeAssignment.ReadWrite.All",
    "CustomSecAttributeDefinition.ReadWrite.All",
    "DelegatedPermissionGrant.ReadWrite.All",
    "Device.ReadWrite.All",
    "DeviceManagementApps.ReadWrite.All",
    "DeviceManagementConfiguration.ReadWrite.All",
    "DeviceManagementManagedDevices.PrivilegedOperations.All",
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementManagedDevices.ReadWrite.All",
    "DeviceManagementRBAC.ReadWrite.All",
    "DeviceManagementServiceConfig.ReadWrite.All",
    "Directory.AccessAsUser.All",
    "Directory.Read.All",
    "Directory.ReadWrite.All",
    "Domain.ReadWrite.All",
    "EntitlementManagement.ReadWrite.All",
    "Files.Read",
    "Files.Read.All",
    "Files.ReadWrite",
    "Files.ReadWrite.All",
    "Files.ReadWrite.AppFolder",
    "Files.ReadWrite.Selected",
    "Group.Read.All",
    "Group.ReadWrite.All",
    "GroupMember.Read.All",
    "GroupMember.ReadWrite.All",
    "IdentityProvider.ReadWrite.All",
    "IdentityRiskEvent.Read.All",
    "IdentityRiskyServicePrincipal.ReadWrite.All",
    "IdentityRiskyUser.ReadWrite.All",
    "LifecycleWorkflows.ReadWrite.All",
    "Mail.Read",
    "Mail.Read.Shared",
    "Mail.ReadWrite",
    "Mail.ReadWrite.Shared",
    "Mail.Send",
    "Mail.Send.Shared",
    "MailboxSettings.ReadWrite",
    "Member.Read.Hidden",
    "Notes.Read.All",
    "Notes.ReadWrite.All",
    "OnPremDirectorySynchronization.ReadWrite.All",
    "OnlineMeetingArtifact.Read.All",
    "OnlineMeetingRecording.Read.All",
    "OnlineMeetingTranscript.Read.All",
    "OnlineMeetings.ReadWrite.All",
    "Organization.ReadWrite.All",
    "PermissionGrantPolicy.ReadWrite.All",
    "Policy.ReadWrite.ApplicationConfiguration",
    "Policy.ReadWrite.AuthenticationFlows",
    "Policy.ReadWrite.AuthenticationMethod",
    "Policy.ReadWrite.Authorization",
    "Policy.ReadWrite.ConditionalAccess",
    "Policy.ReadWrite.CrossTenantAccess",
    "Policy.ReadWrite.FeatureRollout",
    "Policy.ReadWrite.PermissionGrant",
    "Policy.ReadWrite.SecurityDefaults",
    "Policy.ReadWrite.TrustFramework",
    "PrivilegedAccess.ReadWrite.AzureAD",
    "PrivilegedAccess.ReadWrite.AzureADGroup",
    "PrivilegedAccess.ReadWrite.AzureResources",
    "RoleAssignmentSchedule.ReadWrite.Directory",
    "RoleEligibilitySchedule.ReadWrite.Directory",
    "RoleManagement.ReadWrite.Directory",
    "SecurityActions.ReadWrite.All",
    "SecurityAlert.ReadWrite.All",
    "SecurityEvents.ReadWrite.All",
    "SecurityIncident.ReadWrite.All",
    "Sites.FullControl.All",
    "Sites.Manage.All",
    "Sites.Read.All",
    "Sites.ReadWrite.All",
    "Synchronization.ReadWrite.All",
    "TeamMember.ReadWrite.All",
    "TeamsAppInstallation.ReadWriteForChat.All",
    "TeamsAppInstallation.ReadWriteForTeam.All",
    "TeamsAppInstallation.ReadWriteForUser.All",
    "TeamSettings.ReadWrite.All",
    "Teamwork.Migrate.All",
    "ThreatHunting.Read.All",
    "ThreatIndicators.ReadWrite.OwnedBy",
    "TrustFrameworkKeySet.ReadWrite.All",
    "User.Read.All",
    "User.ReadWrite.All",
    "UserAuthenticationMethod.Read.All",
    "UserAuthenticationMethod.ReadWrite.All",
)

# Tier 2: broad reads of directory *metadata*. They expose a lot but not mail, files or chats, and many legitimate products need
# them, so they are "to review" rather than "dangerous". Content reads (Mail.Read, Files.Read.All, Chat.Read.All...) stay in tier 1.
DEFAULT_BROAD_READ_SCOPES: tuple[str, ...] = (
    "AuditLog.Read.All",
    "DeviceManagementManagedDevices.Read.All",
    "Directory.Read.All",
    "Group.Read.All",
    "GroupMember.Read.All",
    "IdentityRiskEvent.Read.All",
    "Member.Read.Hidden",
    "ThreatHunting.Read.All",
    "User.Read.All",
)
assert set(DEFAULT_BROAD_READ_SCOPES) <= set(_BUILTIN_RISKY_SCOPES)

# Tier 1: everything else in the built-in list (every write permission, plus reads of mail, files, chats, sites...).
DEFAULT_HIGH_RISK_SCOPES: tuple[str, ...] = tuple(x for x in _BUILTIN_RISKY_SCOPES if x not in set(DEFAULT_BROAD_READ_SCOPES))

DEFAULT_THRESHOLDS: dict[str, int] = {
    "stale_days_group": 180,
    "stale_days_app": 180,
    "expiring_days": 30,
    "dormant_days_user": 60,
    "danger_no_signin_days": 90,
    "stale_days_script": 730,
    "idle_days_script": 90,
    "stale_days_guest": 365,
    "pending_days_guest": 90,
    "stale_days_member": 180,
    "stale_days_mailbox": 180,
    "eos_warning_days": 180,
    "stale_days_expedite": 90,
}


class ConfigError(RuntimeError):
    """Raised when a required environment value is missing."""


def _require(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise ConfigError(f"Missing required environment variable: {name}")
    return value


@dataclass(frozen=True)
class Config:
    database_path: Path
    tenant_id: str = ""               # the Entra app connection is normally entered in Settings and kept in the database;
    client_id: str = ""               # these environment values are only a fallback for development
    client_secret: str = ""
    secret_key: str = ""              # empty = generated once and kept in the database
    database_url: str = ""           # DATABASE_URL: mssql+pyodbc://... in production; empty = the SQLite file at database_path
    redirect_uri: str = ""            # only used by AUTH_MODE=delegated
    auth_mode: str = "app"            # "app" (client credentials) or "delegated" (user sign-in)
    scopes: tuple[str, ...] = GRAPH_SCOPES
    thresholds: dict[str, int] = field(default_factory=lambda: dict(DEFAULT_THRESHOLDS))
    high_risk_scopes: tuple[str, ...] = DEFAULT_HIGH_RISK_SCOPES

    @property
    def authority(self) -> str:
        return f"https://login.microsoftonline.com/{self.tenant_id}"

    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from the process environment (after reading .env)."""
        load_dotenv()
        from . import bootstrap   # the installer's file: used where the environment says nothing
        mode = os.environ.get("AUTH_MODE", "app").strip().lower()
        if mode not in ("app", "delegated"):
            raise ConfigError("AUTH_MODE must be 'app' or 'delegated'")
        return cls(
            tenant_id=os.environ.get("TENANT_ID", "").strip(),
            client_id=os.environ.get("CLIENT_ID", "").strip(),
            client_secret=os.environ.get("CLIENT_SECRET", "").strip(),
            secret_key=os.environ.get("SECRET_KEY", "").strip(),
            database_path=Path(os.environ.get("DATABASE_PATH", "instance/broom365.sqlite")),
            database_url=os.environ.get("DATABASE_URL", "").strip() or bootstrap.load().get("database_url", ""),
            redirect_uri=_require("REDIRECT_URI") if mode == "delegated" else os.environ.get("REDIRECT_URI", ""),
            auth_mode=mode,
        )
