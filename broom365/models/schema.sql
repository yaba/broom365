-- Broom365 SQLite schema (v1, read-only; remediation table present but unused).
--
-- Two-phase data model:
--   INVENTORY (cheap, bulk Graph calls): names/metadata of every group, app, SP, role assignment...
--   SCAN      (expensive, per-object calls): owners, member counts, app assignments, audit
--             activity, app permissions - only for objects matching the chosen scope patterns.
-- Rows are updated in place. `scanned_at IS NULL` means "inventoried only, never evaluated";
-- such objects never produce flags. Nullable columns mean "unknown / signal unavailable".
-- Timestamps are ISO-8601 UTC TEXT.

PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------- sync -----
CREATE TABLE IF NOT EXISTS sync_runs (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    kind          TEXT NOT NULL CHECK (kind IN ('inventory','scan')),
    started_at    TEXT NOT NULL,
    finished_at   TEXT,
    status        TEXT NOT NULL CHECK (status IN ('running','success','partial','failed')),
    progress      TEXT,
    detail        TEXT,            -- JSON summary, e.g. objects scanned
    error         TEXT
);

-- What the inventory counted: only totals (cheap), per kind of object. A tab shows its total here until it is analysed.
CREATE TABLE IF NOT EXISTS inventory_totals (
    kind        TEXT PRIMARY KEY,
    total       INTEGER NOT NULL,
    counted_at  TEXT NOT NULL
);

-- Which tabs have been analysed (their data read and evaluated), and when.
CREATE TABLE IF NOT EXISTS analyses (
    tab          TEXT PRIMARY KEY,
    analysed_at  TEXT NOT NULL
);

-- Current state per signal (upserted by whichever run touched it); drives /settings.
CREATE TABLE IF NOT EXISTS signal_availability (
    signal        TEXT PRIMARY KEY,   -- e.g. 'group_audit_activity', 'sp_sign_in_activity'
    available     INTEGER NOT NULL CHECK (available IN (0,1)),
    reason        TEXT,               -- e.g. 'missing scope AuditLog.Read.All'
    checked_at    TEXT NOT NULL
);

-- ------------------------------------------------------------- groups ------
CREATE TABLE IF NOT EXISTS groups (
    id                 TEXT PRIMARY KEY,
    display_name       TEXT,
    description        TEXT,
    created_at         TEXT,
    membership_rule    TEXT,        -- non-null => dynamic group
    mail_enabled       INTEGER,
    security_enabled   INTEGER,
    has_license_assignment INTEGER, -- inventory
    group_types        TEXT,        -- inventory: comma-separated Graph groupTypes, 'Unified' = Microsoft 365 group
    aliases            TEXT,        -- inventory: JSON list of the group's e-mail addresses (mail + proxyAddresses)
    inventoried_at     TEXT NOT NULL,
    -- scan fields
    scanned_at         TEXT,
    member_count       INTEGER,     -- NULL if not retrieved
    owner_count        INTEGER,
    parent_count       INTEGER,     -- groups this group is a member of; NULL = not checked
    last_membership_change_at TEXT  -- from audit logs; NULL => fall back to created_at
);
CREATE INDEX IF NOT EXISTS ix_groups_name ON groups(display_name COLLATE NOCASE);

CREATE TABLE IF NOT EXISTS group_owners (
    group_id      TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    owner_id      TEXT NOT NULL,
    owner_type    TEXT,             -- user | group | servicePrincipal
    display_name  TEXT,
    PRIMARY KEY (group_id, owner_id)
);

-- Groups this group is a member of (nesting). A nested group is "used" even if empty and ownerless.
CREATE TABLE IF NOT EXISTS group_parents (
    group_id     TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    parent_id    TEXT NOT NULL,
    parent_name  TEXT,
    PRIMARY KEY (group_id, parent_id)
);

-- Places that reference a group: Conditional Access, Intune assignments... (inventory, tenant-wide, bulk).
-- group_id has no foreign key: the referenced group may not be in the inventory yet.
CREATE TABLE IF NOT EXISTS group_usages (
    group_id     TEXT NOT NULL,
    source       TEXT NOT NULL,     -- signal name, see services/usage.py
    kind         TEXT NOT NULL,     -- 'Intune app', 'Conditional Access policy', ...
    object_id    TEXT NOT NULL,
    object_name  TEXT,
    mode         TEXT NOT NULL,     -- include | exclude | assigned
    detail       TEXT,              -- app intent (required/available/uninstall), CA policy state...
    PRIMARY KEY (group_id, source, object_id, mode)
);
CREATE INDEX IF NOT EXISTS ix_usages_group ON group_usages(group_id);

-- Group -> application assignment (/groups/{id}/appRoleAssignments). Whether the target SP
-- exists / is enabled is derived at read time by joining service_principals, so it never goes stale.
CREATE TABLE IF NOT EXISTS group_app_assignments (
    id                 TEXT PRIMARY KEY,
    group_id           TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    resource_sp_id     TEXT NOT NULL,
    resource_display_name TEXT,     -- Graph returns this even if the SP is gone
    app_role_id        TEXT,
    assigned_at        TEXT
);

-- ------------------------------------------------- apps / service principals
CREATE TABLE IF NOT EXISTS service_principals (
    id               TEXT PRIMARY KEY,
    app_id           TEXT NOT NULL,
    display_name     TEXT,
    account_enabled  INTEGER,
    sp_type          TEXT,
    app_owner_tenant_id TEXT,
    inventoried_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_sp_app_id ON service_principals(app_id);

CREATE TABLE IF NOT EXISTS deleted_service_principals (
    id          TEXT PRIMARY KEY,
    deleted_at  TEXT
);

CREATE TABLE IF NOT EXISTS applications (
    id            TEXT PRIMARY KEY,
    app_id        TEXT NOT NULL,     -- client id; join key to service_principals.app_id
    display_name  TEXT,
    created_at    TEXT,
    inventoried_at TEXT NOT NULL,
    scanned_at    TEXT,
    owner_count   INTEGER            -- scan
);
CREATE INDEX IF NOT EXISTS ix_apps_name ON applications(display_name COLLATE NOCASE);

CREATE TABLE IF NOT EXISTS app_credentials (   -- inventory (comes with the applications list)
    application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    key_id        TEXT NOT NULL,
    kind          TEXT NOT NULL CHECK (kind IN ('password','key')),
    display_name  TEXT,
    start_at      TEXT,
    end_at        TEXT,
    PRIMARY KEY (application_id, key_id)
);

CREATE TABLE IF NOT EXISTS app_owners (
    application_id TEXT NOT NULL REFERENCES applications(id) ON DELETE CASCADE,
    owner_id       TEXT NOT NULL,
    display_name   TEXT,
    PRIMARY KEY (application_id, owner_id)
);

-- Delegated grants arrive with the inventory; application permissions with the scan.
CREATE TABLE IF NOT EXISTS permission_grants (
    id             TEXT NOT NULL,
    sp_id          TEXT NOT NULL REFERENCES service_principals(id) ON DELETE CASCADE,
    kind           TEXT NOT NULL CHECK (kind IN ('delegated','application')),
    resource_sp_id TEXT,
    resource_name  TEXT,
    scope          TEXT NOT NULL,
    consent_type   TEXT,
    PRIMARY KEY (id, scope)
);
CREATE INDEX IF NOT EXISTS ix_grants_sp ON permission_grants(sp_id);

-- ------------------------------------------------------- roles / users -----
CREATE TABLE IF NOT EXISTS users (          -- only principals holding a directory role
    id                  TEXT PRIMARY KEY,
    display_name        TEXT,
    user_principal_name TEXT,
    account_enabled     INTEGER,
    user_type           TEXT
);

CREATE TABLE IF NOT EXISTS role_assignments (
    id                TEXT PRIMARY KEY,
    principal_id      TEXT NOT NULL,
    principal_type    TEXT NOT NULL CHECK (principal_type IN ('user','group','servicePrincipal')),
    role_definition_id TEXT NOT NULL,
    role_name         TEXT,
    directory_scope_id TEXT
);
CREATE INDEX IF NOT EXISTS ix_roles_principal ON role_assignments(principal_id);

-- Row absent = signal unavailable for that object; row with NULL date = no sign-in on record.
CREATE TABLE IF NOT EXISTS sign_in_activity (
    object_id        TEXT NOT NULL,
    object_type      TEXT NOT NULL CHECK (object_type IN ('servicePrincipal','user')),
    last_sign_in_at  TEXT,
    last_interactive_at     TEXT,
    last_non_interactive_at TEXT,
    PRIMARY KEY (object_id, object_type)
);

-- ---------------------------------------------------------- Intune apps -----
-- Inventory only (comes with the bulk mobileApps call); evaluated for every app, no scan needed.
CREATE TABLE IF NOT EXISTS intune_apps (
    id             TEXT PRIMARY KEY,
    display_name   TEXT,
    app_type       TEXT,             -- e.g. win32LobApp
    publisher      TEXT,
    created_at     TEXT,
    modified_at    TEXT,
    inventoried_at TEXT NOT NULL,
    scanned_at     TEXT              -- set when its relationships were read on demand
);

CREATE TABLE IF NOT EXISTS intune_app_assignments (
    app_id    TEXT NOT NULL REFERENCES intune_apps(id) ON DELETE CASCADE,
    target    TEXT NOT NULL CHECK (target IN ('group','all_users','all_devices')),
    group_id  TEXT NOT NULL DEFAULT '',
    mode      TEXT NOT NULL CHECK (mode IN ('include','exclude')),
    intent    TEXT NOT NULL DEFAULT '',   -- required | available | uninstall | availableWithoutEnrollment
    PRIMARY KEY (app_id, target, group_id, mode, intent)
);

-- Dependency / supersedence links, read only for apps with no assignment (the case where they matter).
CREATE TABLE IF NOT EXISTS intune_app_relationships (
    app_id      TEXT NOT NULL REFERENCES intune_apps(id) ON DELETE CASCADE,
    kind        TEXT NOT NULL CHECK (kind IN ('dependency','supersedence')),
    role        TEXT NOT NULL CHECK (role IN ('parent','child')),
    other_id    TEXT NOT NULL,
    other_name  TEXT,
    detail      TEXT,
    PRIMARY KEY (app_id, kind, role, other_id)
);

-- PowerShell scripts, macOS shell scripts and Remediations (inventory; evaluated without a scan).
CREATE TABLE IF NOT EXISTS intune_scripts (
    id             TEXT PRIMARY KEY,
    kind           TEXT NOT NULL CHECK (kind IN ('powershell','shell','remediation')),
    display_name   TEXT,
    created_at     TEXT,
    modified_at    TEXT,
    run_json       TEXT,             -- Graph runSummary as JSON; NULL = not read / not available
    inventoried_at TEXT NOT NULL,
    scanned_at     TEXT              -- set when its run results were read on demand
);

CREATE TABLE IF NOT EXISTS intune_script_assignments (
    script_id TEXT NOT NULL REFERENCES intune_scripts(id) ON DELETE CASCADE,
    target    TEXT NOT NULL CHECK (target IN ('group','all_users','all_devices')),
    group_id  TEXT NOT NULL DEFAULT '',
    mode      TEXT NOT NULL CHECK (mode IN ('include','exclude')),
    PRIMARY KEY (script_id, target, group_id, mode)
);

-- Windows update policies: update rings, feature update profiles, expedite (quality) profiles, driver update profiles.
-- Inventory only (they come with the usage sources); evaluated without a scan.
CREATE TABLE IF NOT EXISTS update_policies (
    id             TEXT PRIMARY KEY,
    kind           TEXT NOT NULL CHECK (kind IN ('ring','feature','quality','driver')),
    display_name   TEXT,
    created_at     TEXT,
    modified_at    TEXT,
    settings_json  TEXT,             -- the Graph properties of the policy as read (JSON)
    inventoried_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS update_policy_assignments (
    policy_id TEXT NOT NULL REFERENCES update_policies(id) ON DELETE CASCADE,
    target    TEXT NOT NULL CHECK (target IN ('group','all_users','all_devices')),
    group_id  TEXT NOT NULL DEFAULT '',
    mode      TEXT NOT NULL CHECK (mode IN ('include','exclude')),
    PRIMARY KEY (policy_id, target, group_id, mode)
);

-- External (guest) users: one paged list in the inventory, with last sign-in when it can be read.
CREATE TABLE IF NOT EXISTS guests (
    id             TEXT PRIMARY KEY,
    display_name   TEXT,
    mail           TEXT,
    user_principal_name TEXT,
    account_enabled INTEGER,
    created_at     TEXT,
    external_state TEXT,
    state_changed_at TEXT,
    last_sign_in_at TEXT,
    sign_in_known  INTEGER NOT NULL DEFAULT 0,   -- 0 = sign-in activity could not be read for this inventory
    inventoried_at TEXT NOT NULL,
    scanned_at     TEXT                          -- set when its group memberships were read on demand
);

-- Groups and Teams a guest belongs to (including nested groups), read on demand.
CREATE TABLE IF NOT EXISTS guest_memberships (
    guest_id   TEXT NOT NULL REFERENCES guests(id) ON DELETE CASCADE,
    group_id   TEXT NOT NULL,
    group_name TEXT,
    kind       TEXT NOT NULL CHECK (kind IN ('team','microsoft365','security')),
    PRIMARY KEY (guest_id, group_id)
);

-- Internal (member) users: one paged list in the inventory, with licences and last sign-in when they can be read.
CREATE TABLE IF NOT EXISTS members (
    id             TEXT PRIMARY KEY,
    display_name   TEXT,
    mail           TEXT,
    user_principal_name TEXT,
    account_enabled INTEGER,
    created_at     TEXT,
    on_prem_synced INTEGER NOT NULL DEFAULT 0,
    licences       TEXT NOT NULL DEFAULT '[]',   -- JSON list of skuPartNumber
    aliases        TEXT NOT NULL DEFAULT '[]',   -- JSON list of the user's e-mail addresses (mail + proxyAddresses)
    last_sign_in_at TEXT,
    sign_in_known  INTEGER NOT NULL DEFAULT 0,
    inventoried_at TEXT NOT NULL
);

-- Exchange distribution lists: listed by the inventory (one call), members and mail traffic read on demand.
CREATE TABLE IF NOT EXISTS distribution_lists (
    id             TEXT PRIMARY KEY,           -- ExternalDirectoryObjectId (= Entra group id)
    kind           TEXT NOT NULL CHECK (kind IN ('distribution','security','dynamic')),
    display_name   TEXT,
    address        TEXT,
    created_at     TEXT,
    changed_at     TEXT,
    owners         TEXT NOT NULL DEFAULT '[]', -- JSON list of owner names
    hidden         INTEGER,
    synced         INTEGER,
    inventoried_at TEXT NOT NULL,
    scanned_at     TEXT,                       -- on-demand check
    member_count   INTEGER,
    last_mail_at   TEXT,                       -- newest message to the list in the trace window; NULL = none seen
    traffic_known  INTEGER NOT NULL DEFAULT 0  -- 0 = message trace could not be read
);

-- Transport rules that mention a list (by its address), from the single rule list read in the inventory.
CREATE TABLE IF NOT EXISTS dl_rule_refs (
    dl_id     TEXT NOT NULL REFERENCES distribution_lists(id) ON DELETE CASCADE,
    rule_name TEXT NOT NULL,
    field     TEXT NOT NULL,
    PRIMARY KEY (dl_id, rule_name, field)
);

-- Shared, room and equipment mailboxes (disabled sign-in by design), read on demand.
CREATE TABLE IF NOT EXISTS mailboxes (
    id             TEXT PRIMARY KEY,           -- ExternalDirectoryObjectId (= the user id)
    mailbox_type   TEXT NOT NULL,
    display_name   TEXT,
    address        TEXT,
    created_at     TEXT,
    inventoried_at TEXT NOT NULL,
    send_on_behalf TEXT NOT NULL DEFAULT '[]',  -- JSON list of names (from the mailbox list)
    scanned_at     TEXT,                        -- on-demand check
    last_logon_at  TEXT,
    logon_known    INTEGER NOT NULL DEFAULT 0,  -- 0 = mailbox statistics could not be read
    item_count     INTEGER,
    last_mail_at   TEXT,                        -- newest message to the mailbox in the trace window; NULL = none seen
    traffic_known  INTEGER NOT NULL DEFAULT 0,
    delegates_known INTEGER NOT NULL DEFAULT 0  -- 0 = permissions could not be read
);

-- Who has Full Access / Send As on a mailbox, read on demand with the mailbox check.
CREATE TABLE IF NOT EXISTS mailbox_delegates (
    mailbox_id TEXT NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    trustee    TEXT NOT NULL,
    kind       TEXT NOT NULL CHECK (kind IN ('full_access','send_as')),
    PRIMARY KEY (mailbox_id, trustee, kind)
);

-- Mail flow (transport) rules, from the single rule list read in the inventory.
CREATE TABLE IF NOT EXISTS transport_rules (
    name           TEXT PRIMARY KEY,
    state          TEXT,
    mode           TEXT,
    priority       INTEGER,
    changed_at     TEXT,
    expiry_at      TEXT,
    addresses      TEXT NOT NULL DEFAULT '[]',  -- JSON list of every address the rule mentions
    inventoried_at TEXT NOT NULL
);

-- ------------------------------------------------------------ settings -----
CREATE TABLE IF NOT EXISTS settings (
    name   TEXT PRIMARY KEY,
    value  TEXT NOT NULL            -- JSON-encoded; defaults live in config.py
);
-- names: stale_days_group stale_days_app expiring_days dormant_days_user danger_no_signin_days
--       high_risk_scopes scope_groups scope_apps (pattern text, one per line)

-- ------------------------------------------------- computed flags (cache) --
-- Rebuilt by correlate.py after every inventory/scan; only scanned objects (and users) appear.
CREATE TABLE IF NOT EXISTS flagged_objects (
    object_type  TEXT NOT NULL CHECK (object_type IN ('group','app','user','intune_app','intune_script','guest','member','dl','mailbox','rule','update')),
    object_id    TEXT NOT NULL,
    display_name TEXT,
    risk_level   TEXT NOT NULL CHECK (risk_level IN ('HIGH','MEDIUM','LOW')),
    PRIMARY KEY (object_type, object_id)
);

CREATE TABLE IF NOT EXISTS flags (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    object_type  TEXT NOT NULL,
    object_id    TEXT NOT NULL,
    flag         TEXT NOT NULL,
    explanation  TEXT NOT NULL,
    evidence     TEXT,              -- JSON: dates, scope names, ids behind the flag
    FOREIGN KEY (object_type, object_id)
        REFERENCES flagged_objects(object_type, object_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS ix_flags_obj ON flags(object_type, object_id);

-- ------------------------------------- remediation (v2; unused in v1) ------
CREATE TABLE IF NOT EXISTS remediation_actions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    object_type   TEXT NOT NULL,
    object_id     TEXT NOT NULL,
    action        TEXT NOT NULL,
    status        TEXT NOT NULL CHECK (status IN ('proposed','approved','executed','failed','rolled_back')),
    requested_by  TEXT,
    requested_at  TEXT,
    executed_at   TEXT,
    before_state  TEXT,
    result        TEXT
);

-- ------------------------------------------------------------ accounts -----
-- People who may use Broom365 itself (not Entra users). Kept when the synced data is deleted.
CREATE TABLE IF NOT EXISTS app_users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT,                                        -- NULL/empty = no password yet (only the first admin starts like this)
    role          TEXT NOT NULL CHECK (role IN ('admin','reader')),
    must_change_password INTEGER NOT NULL DEFAULT 1,
    failed_logins INTEGER NOT NULL DEFAULT 0,
    locked_until  TEXT,
    created_at    TEXT NOT NULL,
    last_login_at TEXT
);

-- The Entra app connection (tenant, client id, client secret) and the session signing key, edited in Settings. Kept on database reset.
CREATE TABLE IF NOT EXISTS app_config (
    name   TEXT PRIMARY KEY,
    value  TEXT NOT NULL
);
