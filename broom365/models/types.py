"""Plain, immutable domain types shared by sync.py (producer) and correlate.py (consumer).

correlate.py never sees Graph JSON or SQL rows, only these. `None` always means
"unknown / signal unavailable", never "zero" or "false".
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Literal, Mapping

from ..config import DEFAULT_BROAD_READ_SCOPES, DEFAULT_HIGH_RISK_SCOPES


class RiskLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

    @property
    def rank(self) -> int:
        """Sortable weight: HIGH=3, MEDIUM=2, LOW=1."""
        return {"HIGH": 3, "MEDIUM": 2, "LOW": 1}[self.value]


class FlagCode(str, Enum):
    # Core group flags
    ORPHANED_APP_ASSIGNMENT = "ORPHANED_APP_ASSIGNMENT"
    EMPTY_GROUP = "EMPTY_GROUP"
    NO_OWNER = "NO_OWNER"
    STALE = "STALE"
    UNKNOWN_USE = "UNKNOWN_USE"
    # Extended signals
    EXPIRED_SECRET = "EXPIRED_SECRET"
    EXPIRING_SECRET = "EXPIRING_SECRET"
    STALE_APP = "STALE_APP"
    DANGEROUS_PERMISSION = "DANGEROUS_PERMISSION"
    BROAD_READ_PERMISSION = "BROAD_READ_PERMISSION"
    PRIVILEGED_ORPHAN_GROUP = "PRIVILEGED_ORPHAN_GROUP"
    DORMANT_PRIVILEGED_USER = "DORMANT_PRIVILEGED_USER"
    # Correlations (combinations of the above)
    LIKELY_ABANDONED_APP = "LIKELY_ABANDONED_APP"
    UNINSTALL_ONLY_APP = "UNINSTALL_ONLY_APP"
    UNASSIGNED_APP = "UNASSIGNED_APP"
    UNASSIGNED_SCRIPT = "UNASSIGNED_SCRIPT"
    STALE_SCRIPT = "STALE_SCRIPT"
    EMPTY_TARGETS_SCRIPT = "EMPTY_TARGETS_SCRIPT"
    FAILING_SCRIPT = "FAILING_SCRIPT"
    IDLE_REMEDIATION = "IDLE_REMEDIATION"
    LIKELY_OBSOLETE_SCRIPT = "LIKELY_OBSOLETE_SCRIPT"
    DISABLED_PRIVILEGED_USER = "DISABLED_PRIVILEGED_USER"
    EXTERNAL_PRIVILEGED_USER = "EXTERNAL_PRIVILEGED_USER"
    STALE_GUEST = "STALE_GUEST"
    PENDING_GUEST = "PENDING_GUEST"
    STALE_MEMBER = "STALE_MEMBER"
    DISABLED_LICENSED_MEMBER = "DISABLED_LICENSED_MEMBER"
    DISABLED_MEMBER = "DISABLED_MEMBER"
    DL_NO_OWNER = "DL_NO_OWNER"
    DL_EMPTY = "DL_EMPTY"
    DL_NO_MAIL = "DL_NO_MAIL"
    LIKELY_UNUSED_DL = "LIKELY_UNUSED_DL"
    MAILBOX_NO_ACTIVITY = "MAILBOX_NO_ACTIVITY"
    MAILBOX_NO_DELEGATES = "MAILBOX_NO_DELEGATES"
    MAILBOX_ORPHAN_DELEGATES = "MAILBOX_ORPHAN_DELEGATES"
    LIKELY_UNUSED_MAILBOX = "LIKELY_UNUSED_MAILBOX"
    RULE_DISABLED = "RULE_DISABLED"
    RULE_EXPIRED = "RULE_EXPIRED"
    RULE_NOT_ENFORCING = "RULE_NOT_ENFORCING"
    RULE_DEAD_REFERENCE = "RULE_DEAD_REFERENCE"
    UPDATE_UNASSIGNED = "UPDATE_UNASSIGNED"
    UPDATE_EMPTY_TARGETS = "UPDATE_EMPTY_TARGETS"
    UPDATE_OVERLAP = "UPDATE_OVERLAP"
    UPDATE_NO_DEADLINE = "UPDATE_NO_DEADLINE"
    UPDATE_PAUSED = "UPDATE_PAUSED"
    UPDATE_FEATURE_ENDING = "UPDATE_FEATURE_ENDING"
    UPDATE_DRIVERS_WAITING = "UPDATE_DRIVERS_WAITING"
    UPDATE_STALE_EXPEDITE = "UPDATE_STALE_EXPEDITE"
    RISK_WITHOUT_USAGE = "RISK_WITHOUT_USAGE"


@dataclass(frozen=True)
class Thresholds:
    """Configurable day counts. Defaults mirror config.DEFAULT_THRESHOLDS."""

    stale_days_group: int = 180
    stale_days_app: int = 180
    expiring_days: int = 30
    dormant_days_user: int = 60
    danger_no_signin_days: int = 90
    stale_days_script: int = 730
    idle_days_script: int = 90
    stale_days_guest: int = 365
    pending_days_guest: int = 90
    stale_days_member: int = 180
    stale_days_mailbox: int = 180
    eos_warning_days: int = 180
    stale_days_expedite: int = 90
    high_risk_scopes: tuple[str, ...] = DEFAULT_HIGH_RISK_SCOPES
    broad_read_scopes: tuple[str, ...] = DEFAULT_BROAD_READ_SCOPES


@dataclass(frozen=True)
class Flag:
    """One finding: what, why (plain language with concrete data), and the raw evidence.

    `risk` is the minimum risk this flag alone implies for apps/users. Group risk is
    derived from flag *combinations* in correlate.py, so core group flags stay LOW here.
    """

    code: FlagCode
    explanation: str
    evidence: Mapping[str, Any] = field(default_factory=dict)
    risk: RiskLevel = RiskLevel.LOW


@dataclass(frozen=True)
class Assessment:
    """Result of evaluating one object."""

    object_type: Literal["group", "app", "user", "intune_app", "intune_script", "guest", "member", "dl", "mailbox", "rule", "update"]
    object_id: str
    display_name: str
    risk: RiskLevel
    flags: tuple[Flag, ...]
    # Human-readable notes on signals that could not be evaluated for this object.
    unavailable_signals: tuple[str, ...] = ()

    @property
    def codes(self) -> frozenset[FlagCode]:
        return frozenset(f.code for f in self.flags)


# ----------------------------------------------------------------- groups ---
@dataclass(frozen=True)
class GroupAppAssignment:
    resource_sp_id: str
    resource_display_name: str | None
    target_sp_exists: bool
    target_sp_enabled: bool | None  # None when the SP is missing or state unknown
    assigned_at: datetime | None = None
    target_deleted_at: datetime | None = None  # from deleted items, when recoverable


@dataclass(frozen=True)
class GroupUsage:
    """One place that references a group (Conditional Access, an Intune assignment...)."""

    source: str                # signal name, see services/usage.py
    kind: str                  # e.g. 'Intune app'
    object_name: str
    mode: str                  # include | exclude | assigned
    detail: str | None = None  # intent / policy state


@dataclass(frozen=True)
class GroupFacts:
    id: str
    display_name: str
    created_at: datetime | None
    member_count: int | None
    owner_count: int | None
    last_membership_change_at: datetime | None = None  # audit logs; None => unavailable
    has_license_assignment: bool | None = None
    app_assignments: tuple[GroupAppAssignment, ...] = ()
    directory_role_names: tuple[str, ...] = ()
    usages: tuple[GroupUsage, ...] = ()                      # Conditional Access / Intune references found
    parent_group_names: tuple[str, ...] | None = None        # groups it is nested in; None = not checked
    unchecked_usage_sources: tuple[str, ...] = ()            # usage signals that could not be read
    is_m365: bool = False                                    # Microsoft 365 (Unified) group


# ------------------------------------------------------------------- apps ---
@dataclass(frozen=True)
class Credential:
    key_id: str
    kind: Literal["password", "key"]
    display_name: str | None
    end_at: datetime | None


@dataclass(frozen=True)
class Permission:
    kind: Literal["delegated", "application"]
    resource_name: str | None
    scope: str


@dataclass(frozen=True)
class AppFacts:
    id: str
    app_id: str
    display_name: str
    credentials: tuple[Credential, ...] = ()
    permissions: tuple[Permission, ...] = ()
    owner_count: int | None = None
    sign_in_available: bool = False  # False => beta endpoint unavailable for this app
    last_sign_in_at: datetime | None = None  # None + available => no sign-in on record


# ------------------------------------------------------------------ users ---
@dataclass(frozen=True)
class UserFacts:
    id: str
    display_name: str
    user_principal_name: str | None
    role_names: tuple[str, ...] = ()
    sign_in_available: bool = False
    last_sign_in_at: datetime | None = None
    account_enabled: bool | None = None   # None = unknown
    user_type: str | None = None          # Member | Guest


# ------------------------------------------------------------ Intune apps ---
@dataclass(frozen=True)
class IntuneAssignment:
    target: Literal["group", "all_users", "all_devices"]
    mode: Literal["include", "exclude"]
    intent: str                       # required | available | uninstall | availableWithoutEnrollment | ''
    group_id: str = ""
    group_name: str | None = None
    group_member_count: int | None = None   # None = group not scanned (or not in the inventory)


@dataclass(frozen=True)
class IntuneRelationship:
    """Dependency / supersedence link of an Intune app. `role` is the other app's role relative to this one."""

    kind: Literal["dependency", "supersedence"]
    role: Literal["parent", "child"]     # dependency/parent: that app depends on this one; supersedence/parent: that app replaces this one
    other_id: str
    other_name: str | None = None
    other_assigned: bool | None = None   # None = other app not in the inventory
    detail: str | None = None            # autoInstall | detect | replace | update


@dataclass(frozen=True)
class IntuneAppFacts:
    id: str
    display_name: str
    app_type: str | None = None
    publisher: str | None = None
    created_at: datetime | None = None
    modified_at: datetime | None = None
    assignments: tuple[IntuneAssignment, ...] = ()
    relationships: tuple[IntuneRelationship, ...] | None = None   # None = not readable (only read on demand)
    scanned: bool = True                                          # False = relationships not requested yet


@dataclass(frozen=True)
class IntuneScriptFacts:
    """A PowerShell script, macOS shell script or Remediation."""

    id: str
    display_name: str
    kind: Literal["powershell", "shell", "remediation"]
    created_at: datetime | None = None
    modified_at: datetime | None = None
    assignments: tuple[IntuneAssignment, ...] = ()
    run: Mapping[str, Any] | None = None   # Graph runSummary; None = not read or not available
    scanned: bool = True                   # False = run results not requested yet


@dataclass(frozen=True)
class GuestMembership:
    """A group or Team a guest belongs to (nested groups included)."""

    group_id: str
    name: str
    kind: Literal["team", "microsoft365", "security"]
    dynamic: bool | None = None   # rule-based (automatic) membership; None = group not in the inventory


@dataclass(frozen=True)
class GuestFacts:
    """An external (guest) user."""

    id: str
    display_name: str
    mail: str | None = None
    user_principal_name: str | None = None
    account_enabled: bool | None = None
    created_at: datetime | None = None
    external_state: str | None = None          # Accepted | PendingAcceptance | None (unknown / older guests)
    state_changed_at: datetime | None = None
    last_sign_in_at: datetime | None = None
    sign_in_available: bool = False            # False = sign-in activity could not be read
    memberships: tuple[GuestMembership, ...] | None = None   # None = not checked yet (or not readable)


@dataclass(frozen=True)
class MemberFacts:
    """An internal (member) user."""

    id: str
    display_name: str
    mail: str | None = None
    user_principal_name: str | None = None
    account_enabled: bool | None = None
    created_at: datetime | None = None
    on_prem_synced: bool = False
    licences: tuple[str, ...] = ()                 # skuPartNumber of each assigned licence
    last_sign_in_at: datetime | None = None
    sign_in_available: bool = False                # False = sign-in activity could not be read
    mailbox_type: str | None = None                # SharedMailbox | RoomMailbox | EquipmentMailbox (disabled by design)
    mailboxes_read: bool = False                   # False = the Exchange mailbox types have not been read


@dataclass(frozen=True)
class DistributionListFacts:
    """An Exchange distribution list, mail-enabled security group or dynamic distribution list."""

    id: str                                    # ExternalDirectoryObjectId (= the Entra group id)
    kind: Literal["distribution", "security", "dynamic"]
    display_name: str
    address: str | None = None
    created_at: datetime | None = None
    changed_at: datetime | None = None
    owners: tuple[str, ...] = ()
    synced: bool | None = None                 # synced from on-premises AD
    hidden: bool | None = None
    rules: tuple[str, ...] = ()                # transport rules that mention the list
    rules_known: bool = False                  # False = transport rules could not be read
    checked: bool = False                      # members and mail traffic were read on demand
    member_count: int | None = None
    last_mail_at: datetime | None = None       # newest message addressed to it within the trace window
    traffic_known: bool = False


@dataclass(frozen=True)
class Delegate:
    """Someone with a permission on a mailbox. `state` is 'active', 'disabled', 'deleted' (a bare SID) or 'unknown' (group, guest...)."""

    name: str
    state: str = "unknown"


@dataclass(frozen=True)
class MailboxFacts:
    """A shared, room or equipment mailbox."""

    id: str
    mailbox_type: str                                  # SharedMailbox | RoomMailbox | EquipmentMailbox
    display_name: str
    address: str | None = None
    created_at: datetime | None = None
    checked: bool = False                              # statistics, permissions and traffic were read on demand
    last_logon_at: datetime | None = None
    logon_known: bool = False                          # False = mailbox statistics could not be read
    item_count: int | None = None
    last_mail_at: datetime | None = None
    traffic_known: bool = False
    delegates_known: bool = False                      # False = permissions could not be read
    full_access: tuple[Delegate, ...] = ()
    send_as: tuple[Delegate, ...] = ()


@dataclass(frozen=True)
class RuleFacts:
    """An Exchange mail flow (transport) rule."""

    name: str
    state: str = "Enabled"
    mode: str = "Enforce"
    priority: int | None = None
    changed_at: datetime | None = None
    expiry_at: datetime | None = None
    dead_references: tuple[str, ...] = ()              # addresses of this tenant that match no list, mailbox or user
    references_checked: bool = False


@dataclass(frozen=True)
class UpdatePolicyFacts:
    """A Windows update policy of Intune: an update ring, a feature update profile, an expedite (quality) profile or a driver update profile."""

    id: str
    kind: Literal["ring", "feature", "quality", "driver"]
    display_name: str
    created_at: datetime | None = None
    modified_at: datetime | None = None
    assignments: tuple[IntuneAssignment, ...] = ()
    settings: Mapping[str, Any] = field(default_factory=dict)   # the Graph properties that matter, as read
    overlaps: tuple[str, ...] = ()                              # other policies of the same kind that reach the same group
