# Broom365

Source: <https://github.com/yaba/broom365> · MIT licence

A **read-only** visual tool for Microsoft 365 / Entra ID administrators that finds orphaned, stale and risky
objects by **correlating** data that Entra and Intune show separately: groups whose application no longer
exists, apps with expired secrets nobody uses, apps holding dangerous permissions without recent activity,
privileged groups with no owner, privileged users who stopped signing in.

Broom365 never changes your tenant. Every finding is a **candidate for review** or "needs manual review",
never a verdict and never "safe to delete".

- Backend: Python + Flask (app factory, blueprints), MSAL, Microsoft Graph
- Auth: **app-only** by default (uses the Application permissions already granted to your app registration; no
  Microsoft sign-in, no consent prompt). Interactive delegated sign-in is available as an option.
- Frontend: server-rendered Jinja2 + vanilla JS, light/dark aware
- Storage: SQLite by default, or Microsoft SQL Server through `DATABASE_URL` (cache of Graph results, accounts and settings)
- Single tenant

---

## Quick start

### Try it with demo data (no tenant needed)

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt
$env:BROOM_DEMO = "1"
.venv\Scripts\python -m flask --app run run
```

Open <http://localhost:5000>. Demo mode serves a synthetic tenant through the real sync and correlation code,
skips sign-in, and denies the audit-log endpoint on purpose so you can see "signal unavailable" handling.
The demo database lives in `instance/demo.sqlite`; delete `instance/` to reset it.

### Run against your tenant

1. Register the app (below) and grant the permissions.
2. Start Broom365 and open <http://localhost:5000>: `python -m broom365.wsgi` (or the Docker image, below). The first time it shows the **installer**:
   - **Database**: SQL Server (server, port, database, user, password; the database must already exist) or a SQLite file on this machine. It tests the connection before saving anything and says in plain words what is wrong.
   - **Encryption key**: a random one is suggested; it protects the client secret kept in the database. Keep a copy.
   - **Admin password** for the account `admin`.
3. Sign in, and Broom365 asks for the **tenant ID, client ID and client secret** of the app registration, reads the permissions the app really has, and tells you which are missing
   (required ones block, optional ones only switch off some signals). When all is well it opens the dashboard.

There is no environment file to write: the installer saves its choices in `instance/bootstrap.json` (readable only by the app's user), and the Entra connection lives in the database,
editable later in **Settings**. If the database stops answering, Broom365 opens the installer again with the reason, so you can fix the settings from the browser. Until the installation is finished the
installer is open to whoever can reach the port, like any installer: do it right after starting.

There is no Microsoft login: Broom365 gets its own token with the client secret. It reads the permissions that token
actually carries and tells you if any are missing (see *Permission preflight*).

### The dashboard

Each tab starts with its own summary strip; every tile is also a filter (click it to show only those rows, click again to clear). The **Apps** tab lists every
app registration, not only the flagged ones: *App registrations*, *Expired secrets*, *Apps with no owner*, *Older than a year*, *Younger than a month* and
*High-risk Graph permissions*. Secrets and age come with the analysis; owners and permissions exist only for apps you checked in depth, so for the others the tile
shows a dash and the row says "not checked", never a zero.

### Accounts

Broom365 has its own accounts (username and password, kept in the database; passwords are stored as scrypt hashes and
five failed attempts lock an account for five minutes). There are two roles:

- **admin**: everything, including Settings (Entra connection, thresholds, permission lists), the Accounts page and *Delete database*.
- **reader**: sees every finding, exports CSV and runs inventories and checks. Cannot open Settings or Accounts.

Admins create accounts on the **Accounts** page with a temporary password; the person must choose their own at the first
sign-in, and an admin can reset a password the same way. There is always at least one admin. *Delete database* removes the
synced data but keeps the accounts and the saved Entra connection. The installer sets the first admin's password. (When the database comes from
`DATABASE_URL` and has no accounts yet, `admin` starts with an empty password that must be changed at the first sign-in: open the page right after starting.)

The Entra connection is stored in the database. The client secret is **encrypted** with the key chosen in the installer (or the `BROOM_KEY` environment variable, which wins when set);
keep that key, because without it the secret has to be entered again. `TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET` and `SECRET_KEY` in the
environment or `.env` still work as a development fallback; what is saved in Settings wins.

### Docker (one container)

```bash
docker build -t broom365 .        # python:3.11-slim-bookworm + Microsoft ODBC Driver 18 (installed during the build)
docker run -d -p 5000:5000 -v broom-data:/app/instance broom365
```

Open <http://host:5000>: the installer asks where the data goes (SQL Server or SQLite), for the key and the admin password, then the app asks for the Microsoft 365 connection.
**Keep `/app/instance` on a volume**: it holds `bootstrap.json` (database settings and key) and the sessions, and the SQLite file when you choose it. Without a volume the installer comes back after
every re-created container. The database user needs, on that database only, `db_owner` or `db_ddladmin` + `db_datareader` + `db_datawriter` (Broom365 creates its tables and indexes at start, and a second start changes nothing); no server-level rights, and no access to the system catalog views, which hardened servers often deny:

```sql
CREATE LOGIN broom365 WITH PASSWORD = '...';
USE [broom365db];
CREATE USER broom365 FOR LOGIN broom365;
ALTER ROLE db_ddladmin ADD MEMBER broom365;
ALTER ROLE db_datareader ADD MEMBER broom365;
ALTER ROLE db_datawriter ADD MEMBER broom365;
```

If you installed an older version on SQL Server, some key columns are narrower than the current ones (a long directory role assignment id did not fit): open **Settings** and use *Delete database*, which drops and recreates the synced tables with the current widths and keeps the accounts and the Microsoft 365 connection.

Tables are created in the user's default schema, normally `dbo`; give the user `ALTER ON SCHEMA::dbo` if `CREATE TABLE` is refused there.

Environment variables are optional now and win over what the installer saved: `DATABASE_URL` and `BROOM_KEY` (handy for automated deployments). `DATABASE_URL` accepts any ODBC option:
`mssql+pyodbc://user:password@host:1433/database?driver=ODBC+Driver+18+for+SQL+Server&Encrypt=yes&TrustServerCertificate=no`. A named instance is written `host%5Cinstance`; user and password are optional
(`Trusted_Connection=yes`, `Authentication=...`); a complete ODBC string works too: `mssql+pyodbc:///?odbc_connect=DRIVER={ODBC+Driver+18+for+SQL+Server};SERVER=host,1433;DATABASE=db;UID=u;PWD=p`.
Unless the URL sets `Encrypt` or `TrustServerCertificate` (or names a `DSN`) the connection is encrypted but the server's certificate is accepted as is, so a self-signed certificate works with no
configuration; add `Encrypt=yes&TrustServerCertificate=no` to require a trusted certificate. The password may contain special characters (`# / ? @ :`) as typed; only a literal `%` should be written `%25`.

The image contains Microsoft's ODBC driver, which Microsoft's licence does not clearly allow you to redistribute publicly: build it yourself and keep it in a private
registry rather than publishing it. Start from your own base image with `--build-arg BASE_IMAGE=...` (Python 3.11+; the Dockerfile installs the Microsoft ODBC driver when the base lacks it, so building
accepts Microsoft's licence terms for that driver).

`docker-compose.prod.yml` is the minimal stack for production (for example in Portainer): only Broom365 and one volume; set `BROOM_IMAGE` to the image to run, or write the image name in the file.
`docker compose up --build` (`docker-compose.yml`) builds and runs it for trying it out. To try SQL Server without having one, add `--profile mssql` and `MSSQL_SA_PASSWORD`
(`MSSQL_SA_PASSWORD='...' docker compose --profile mssql up --build`), then use server `mssql`, port 1433, database `broom365`, user `sa` in the installer.
The image runs one Gunicorn worker with threads, because a sync job runs in-process, one at a time. The Python test suite also passes inside the image (Python 3.11).

`FLASK_DEBUG=1` enables auto-reload when using `python run.py`; leave it off anywhere else.

**Environment variables** (all optional; when set they win over what the installer saved):

| Variable | Meaning |
|---|---|
| `DATABASE_URL` | The SQL Server connection, as described above. If unset, the installer's choice is used (SQL Server or the SQLite file) |
| `BROOM_KEY` | The encryption key for the client secret stored in the database (the installer saves one otherwise) |
| `DATABASE_PATH` | The SQLite file (default `instance/broom365.sqlite`); `bootstrap.json` and the sessions live in the same folder |
| `TENANT_ID`, `CLIENT_ID`, `CLIENT_SECRET` | Development fallback for the Microsoft 365 connection (normally entered on the Connect page or in Settings) |
| `SECRET_KEY` | The session signing key. If unset, one is generated once and kept in the database |
| `AUTH_MODE` | `app` (default, app-only) or `delegated` (interactive user sign-in) |
| `REDIRECT_URI` | `delegated` mode only; must match the registered redirect URI, e.g. `http://localhost:5000/auth/callback` |
| `HOST`, `PORT` | For `python -m broom365.wsgi` only (default `127.0.0.1:5000`) |

---

## Entra app registration

Broom365 needs an app registration with a **client secret** and these **Application** permissions (Microsoft Graph),
with admin consent granted. If your existing registration already has them, there is nothing else to do.

| Application permission | Required | Used for |
|---|---|---|
| `Group.Read.All` | Yes | Groups, owners, members, group-to-app assignments |
| `Application.Read.All` | Yes | App registrations, service principals, credentials, permissions |
| `Directory.Read.All` | Yes | Directory objects, users, deleted items |
| `RoleManagement.Read.Directory` | No | Privileged role assignments (privileged-orphan and dormant-admin signals) |
| `AuditLog.Read.All` | No | Sign-in activity and audit logs (stale/abandoned apps, dormant users, group staleness) |
| `Policy.Read.All` | No | Conditional Access policies that include/exclude a group |
| `DeviceManagementApps.Read.All` | No | Intune app assignments to groups |
| `DeviceManagementConfiguration.Read.All` | No | Intune configuration profiles, compliance policies, settings-catalog policies, administrative templates and scripts assigned to groups |

All of them require admin consent. All are read-only. No redirect URI is needed in app mode.

**Permission preflight.** Broom365 acquires its token and compares the `roles` it carries with this table. Missing
*required* permissions block the app and `/permissions` lists them, with the fix and an admin consent link. Missing
*optional* permissions let you continue, and each affected signal is shown as unavailable. A broader permission
(for example `Directory.ReadWrite.All`) also satisfies a narrower read requirement. After granting a permission, use
**Re-check** on that page; it takes effect without signing in again. A wrong tenant ID or an expired secret is
reported there too, with Microsoft's error text.

If your permissions are **Delegated** rather than Application, they do not apply in app mode: add them as
Application permissions, or use delegated mode below.

### Delegated mode (optional)

Set `AUTH_MODE=delegated` and `REDIRECT_URI` to sign in interactively; Broom365 then reads only what the signed-in
person can read (sign in with at least Global Reader). Register a **Web** redirect URI
(`http://localhost:5000/auth/callback`) and grant the same permissions as **Delegated** (plus `User.Read`, which
needs no admin consent; `offline_access` is requested automatically by MSAL). The same preflight applies, using the
scopes in the token response.

---

## How it works: count, analyse a tab, check in detail

Tenants can have thousands of groups and hundreds of apps and scripts, and you rarely want to look at all of it at once. So Broom365 works on demand, one tab at a time:

1. **Count objects** (the inventory) only counts: how many groups, apps, internal users and guests the tenant has. A few cheap calls, a few seconds, nothing is read in
   detail and nothing is evaluated, so no findings appear yet. Intune and Exchange cannot be counted cheaply: those tabs show their total once analysed.
2. **Analyse a tab** reads only what that tab needs and evaluates only that kind of object. Analysing the apps never touches the groups, and the other way round. Each tab says before
   you start what it will read. The result is kept, with when it was analysed; analyse again when you want fresh data.

   | Tab | Analysing reads | Evaluates |
   |---|---|---|
   | Groups | the groups, who uses them (Conditional Access, Intune), the directory roles; then owners, members and audit activity of the groups the **patterns** select | groups (and the privileged users that come with the roles) |
   | Apps | app registrations with secrets and age, sign-in activity, delegated permissions | expired or expiring secrets, stale and abandoned apps; owners and permissions are *not* guessed |
   | Users | who holds a directory role, and their sign-in | dormant, disabled or external privileged users |
   | Intune apps, Scripts, Updates | their own list with assignments | unassigned, uninstall-only, old, update-policy findings |
   | Guests, Internal users | their own list, licences and sign-in | stale and pending guests, stale or leftover accounts |
   | Distribution lists, Mail flow rules | the Exchange lists and rules (one read for both) | unused lists, dead rules |
   | Shared mailboxes | the mailbox list from Exchange | (the detail check below reads each mailbox) |

3. **Check in detail** the objects you pick, with name patterns, for what is too expensive to read for everything. This is the per-object read:

   | Tab | What a check reads | Needed for |
   |---|---|---|
   | Groups | owners, member count, nesting, audit activity, app assignments | `EMPTY_GROUP`, `NO_OWNER`, `STALE`, `UNKNOWN_USE`, `ORPHANED_APP_ASSIGNMENT` |
   | Apps | owners, application permissions | `NO_OWNER`, high-risk permission and risk-without-usage flags |
   | Intune apps | dependency and supersedence links | telling an unused app from an old version or a dependency (`UNASSIGNED_APP`) |
   | Scripts | run results (success / error counts, last run) | `FAILING_SCRIPT`, `IDLE_REMEDIATION` |
   | Guests | the groups and Teams each guest belongs to, nested groups included (1 call per guest) | what access a stale or pending guest still has |

   The job runs in the server: you can leave the page, and a bar at the top of every page shows its progress. Only one job runs at a time.

   Patterns, one per line:

   | Pattern | Meaning |
   |---|---|
   | `win10-app-deployment*` | `*` matches any characters |
   | `sales-emea-0?` | `?` matches exactly one character |
   | `Finance Team` | no wildcard means exact name |
   | `!win10-app-deployment-test*` | leading `!` excludes |
   | `# note` | comment; blank lines ignored |

   Matching is case-insensitive on the display name (for guests also on the e-mail and the company domain: `partner.com` selects a whole company, `*@partner.com` matches e-mails). Exclusions alone select nothing. A live preview shows how many inventoried objects match before
   you check. To check one object, use its exact name.

   Checks **accumulate**: checking `win10-app-deployment*` and later `sw-*` keeps both. Analysing a tab again preserves everything already checked
   and removes objects that disappeared from the tenant (with their checked data). If a list cannot be read, what is stored is kept, not wiped.
   Groups that hold a directory role are always included in group checks so privileged-orphan detection never depends on remembering them.

Whatever has not been checked produces **no flag that depends on that check**: it has not been evaluated, which is different from being clean. The UI
always shows "checked N of M", and a tab that was not analysed shows only its total.

### Is this group really unused?

An empty group with no owner can still be the target of an Intune app assignment, excluded from a Conditional Access
policy, hold a licence, or sit inside another group. Broom365 therefore looks for use in these places and names what it
finds on the group page (**Where this group is used**):

- Conditional Access policies (include and exclude, with the policy name and state)
- Intune: apps (with intent: required / available / uninstall), device configuration profiles, compliance policies,
  settings-catalog policies, administrative templates, PowerShell scripts, macOS shell scripts, remediations
- Group-based licensing, Entra directory roles, Entra enterprise app assignments
- Membership in other groups (nesting)

Each row is **In use** (with the names), **None found**, or **Not checked** (with the reason, for example a missing
permission). A group that is still referenced is never reported as "likely orphaned": a HIGH that came only from
*empty + no owner* drops to MEDIUM and the references are named. A group whose only references are Intune *uninstall*
assignments is called out as such.

**"None found" is not proof.** Places Broom365 does not look at are listed on every group page (Exchange, SharePoint/Teams
permissions, Azure RBAC, access packages, other Intune areas, administrative units, third-party systems). Verify those by
hand before deleting anything. Each page also has *Open in Intune* / *Open in Entra* buttons that jump to the object in the portal.

An object that has not been scanned produces **no flags** (it has not been evaluated, which is different from
being clean). The UI always shows "scanned N of M".

---

## What gets flagged

Flags are computed by pure functions in `broom365/services/correlate.py` (groups) and
`broom365/services/extended_signals.py` (apps, users, privileged objects). Both are unit-tested without Graph access.

### Groups

| Flag | Meaning |
|---|---|
| `ORPHANED_APP_ASSIGNMENT` | Assigned to an app whose service principal is gone (with the deletion date when known) or disabled |
| `EMPTY_GROUP` | Zero members. A signal only: it may carry licenses or policies |
| `NO_OWNER` | No owners |
| `STALE` | No member/owner change within N days (default 180); falls back to creation date when audit data is unavailable, and says so |
| `UNKNOWN_USE` | Has members but no app assignment, license, policy binding or role detected: needs manual review |

Risk: **HIGH** = `ORPHANED_APP_ASSIGNMENT`, or `NO_OWNER` + `EMPTY_GROUP`. **MEDIUM** = `STALE` + `EMPTY_GROUP`, or
`UNKNOWN_USE`. **LOW** = everything else.

### Apps, users and privileged objects

| Flag | Meaning | Risk |
|---|---|---|
| `EXPIRED_SECRET` | A secret/certificate ended in the past (days since expiry shown) | MEDIUM, LOW if another credential is still valid (likely rotation leftover) |
| `EXPIRING_SECRET` | Ends within N days (default 30) | LOW |
| `STALE_APP` | No sign-in for N days (default 180) | LOW |
| `DANGEROUS_PERMISSION` | Holds a scope from the high-risk list (tier 1); the scope is named. HIGH if held as an *application* permission (tenant-wide), MEDIUM if only delegated | HIGH / MEDIUM |
| `BROAD_READ_PERMISSION` | Holds a broad directory read (tier 2: `Directory.Read.All`, `User.Read.All`, `Group.Read.All`, `AuditLog.Read.All`...): to review, not dangerous. MEDIUM as application, LOW as delegated | MEDIUM / LOW |
| `STALE_MEMBER` | Enabled **internal** account with no sign-in for N days (default 180), or created longer ago and never signed in. MEDIUM with a paid licence, else LOW | MEDIUM / LOW |
| `DISABLED_LICENSED_MEMBER` | Disabled internal account that still holds a **paid** licence (free ones do not count) | MEDIUM |
| `LIKELY_ABANDONED_APP` | Correlation: expired secret + no sign-in beyond the stale threshold | HIGH |
| `RISK_WITHOUT_USAGE` | Correlation: high-risk permission + no sign-in for N days (default 90) | HIGH |
| `PRIVILEGED_ORPHAN_GROUP` | Group with a directory role and (no owner, or empty and stale): orphaned admin power | HIGH |
| `DORMANT_PRIVILEGED_USER` | Enabled user with a directory role and no sign-in for N days (default 60) | HIGH |
| `DISABLED_PRIVILEGED_USER` | **Disabled** account that still holds a directory role: it cannot sign in, so the assignment is a leftover (reported whether or not it is also dormant) | MEDIUM |
| `EXTERNAL_PRIVILEGED_USER` | A guest (external) account holds a directory role: confirm it is intended | MEDIUM |
| `STALE_GUEST` | External user with no sign-in for N days (default 365), or added more than N days ago and never signed in; LOW if the account is disabled | MEDIUM / LOW |
| `PENDING_GUEST` | External invitation never accepted after N days (default 90) | LOW |
| `UNINSTALL_ONLY_APP` | **Intune** app whose include-assignments are all `uninstall`: it is no longer deployed, only removed | MEDIUM |
| `UNASSIGNED_APP` | **Intune** app with no assignment that no other app depends on; an old version superseded by a newer app is MEDIUM | LOW / MEDIUM |
| `UNASSIGNED_SCRIPT` | Intune script or remediation with no assignment | LOW |
| `STALE_SCRIPT` | Not modified for N days (default 730) | LOW |
| `EMPTY_TARGETS_SCRIPT` | Every target group is empty (needs the groups to have been scanned) | MEDIUM |
| `FAILING_SCRIPT` | PowerShell / macOS shell script that failed and has never succeeded | MEDIUM |
| `IDLE_REMEDIATION` | Assigned remediation that has not run on any device for N days (default 90) | MEDIUM |
| `LIKELY_OBSOLETE_SCRIPT` | Correlation: stale AND (unassigned OR empty targets OR failing OR idle) | MEDIUM |

### Intune cleanup candidates (apps)

The **Intune apps** tab lists apps that look like leftovers.

- **Uninstall-only** (`UNINSTALL_ONLY_APP`): at least one assignment and *only* `uninstall` ones, no `required` / `available`. The app is no longer
  deployed; once devices have finished uninstalling, its assignments and target groups are candidates for review. The explanation names the target
  groups with their member counts (known once a group has been scanned; otherwise shown as unknown, never guessed). Exclusion targets are ignored even
  though Graph gives them an intent, and uninstall to *All licensed users* counts as a target.
- **Unassigned** (`UNASSIGNED_APP`): no assignment at all. Because most false positives live in dependency and supersedence links, an unassigned app
  is only flagged once you have **checked its relations** (patterns on the tab, one request per app): an app that **another app depends on is not flagged**; an app **superseded by a newer one** is called out as an old version
  (MEDIUM) with a warning that deleting it removes the supersedence link, so devices still on that version would no longer be upgraded through it;
  anything else is LOW. If the links cannot be read, the finding says so and stays LOW. Unchecked unassigned apps are not flagged; the app's
  notes say it still has to be checked.

### Intune scripts and remediations

The **Scripts** tab covers PowerShell scripts, macOS shell scripts and Remediations (proactive remediations). Besides age, it uses what Intune knows.
Unassigned, empty-target and old come straight from the analysis; failing and idle need the **run results**, which you read on demand for the scripts you choose:

- **Unassigned**: it runs on no device.
- **Empty targets**: every target group is empty (the groups must have been scanned to know this).
- **Failing**: the run summary shows failures and not a single success.
- **Idle remediation**: assigned, but its last run on any device was more than N days ago, or never.
- **Old** (`stale_days_script`, default 730): not modified for that long. Old alone is only LOW; **old plus any other signal** is `LIKELY_OBSOLETE_SCRIPT`,
  with the numbers in the explanation (for example "last modified 825 days ago and failed 998 times, never succeeded").

Broom365 is read-only: it points at candidates, it does not delete anything. The groups these scripts target also count as *used* on each group page.

### Windows update policies (Intune)

The **Updates** tab lists every update ring (`windowsUpdateForBusinessConfiguration`), feature update profile, expedite (quality update) profile and driver update
profile, with what each sets and who it reaches. They come with the tab's analysis (no check needed), through the same `DeviceManagementConfiguration.Read.All` read as
the other Intune profiles. Devices are not read: this is about the policies. Everything is a candidate for review, and the checks stick to what Microsoft documents or to
what the policy itself reports:

- `UPDATE_UNASSIGNED` (LOW): assigned to nobody, so it changes nothing. `UPDATE_EMPTY_TARGETS` (MEDIUM): every target group is empty (the groups must have been scanned).
- `UPDATE_OVERLAP` (MEDIUM): another policy of the same kind includes the same group (or everybody) and neither excludes it, so a device may get two sets of settings.
- `UPDATE_NO_DEADLINE` (MEDIUM): a ring with no quality or no feature update deadline. Microsoft's recommended experience is to set deadlines.
- `UPDATE_PAUSED`: a ring pausing quality or feature updates (MEDIUM); LOW when the pause already ended, because a pause lasts at most 35 days and should be cleared.
- `UPDATE_FEATURE_ENDING`: the Windows version of a feature update profile is out of support (HIGH) or ends within `eos_warning_days` (default 180, MEDIUM). The end-of-support
  date is the one Intune stores in the profile, so Broom365 keeps no lifecycle table of its own.
- `UPDATE_DRIVERS_WAITING` (LOW): a driver profile with manual approval and new driver updates waiting.
- `UPDATE_STALE_EXPEDITE` (LOW): an expedite profile not modified for `stale_days_expedite` days (default 90); it covers one release.

Not read yet: update rings made with the Settings catalog, Windows Autopatch groups, Microsoft 365 Apps update channels, and whether devices actually follow the policy.
The groups these policies target also count as *used* on each group page.

### External (guest) users

The **Guests** tab separates external identities from internal ones. External users are invited once, often for a project, and many never come back
while still keeping an access path into the tenant. Analysing the tab reads **all** guests as one paged list, with their last sign-in (about 120 per
request), and flags two things:

- **Stale** (`STALE_GUEST`): no sign-in for longer than `stale_days_guest` (default 365), or added longer ago than that and never signed in. A guest
  used once four years ago and never back is exactly this. An enabled guest is MEDIUM; one that is already disabled is only LOW (inert clutter).
- **Pending** (`PENDING_GUEST`): the invitation was never accepted after `pending_days_guest` (default 90). A pending guest never signed in, so it gets
  this flag and not also the stale one.

Each row shows the guest's e-mail, a *Disabled* / *Invite pending* tag, and the company domain in the explanation. **Company chips** above the table
list the domains with the most flagged guests; one click filters the table so a whole partner can be reviewed at once. The same distinction applies to
administrators: on the Users tab, external accounts carry an *External* tag.

**What access is still open.** Stale and pending findings are more useful when you know what the guest can still reach. On the Guests tab you can
check, on demand, the groups and Teams of the guests you select (by name, e-mail or company domain; about 0.15 s per guest, 25 guests in under 4 seconds).
The explanation then lists the memberships, Teams first, and keeps two kinds apart: memberships **by assignment** (a Team, an assigned group), which are
deliberate access, and **dynamic (rule-based) groups** such as `All Users`, which catch nearly every guest automatically. A guest whose only memberships are
dynamic is reported as having no deliberate group access to lose; a guest in no group at all says so. Guests that have not been checked are flagged as before,
with a note that their memberships are still unknown. What you checked survives analysing the tab again, and the guest CSV gains the membership columns.

**Permissions, in two tiers.** The built-in list has 114 Microsoft Graph permissions (in `broom365/config.py`), split in two lists, both editable in Settings:

- **High-risk (tier 1, 105):** every write permission (`*.ReadWrite.*`, `*.Send`, `Sites.FullControl.All`, `Directory.AccessAsUser.All`...) and the reads of
  *content* (`Mail.Read`, `Files.Read.All`, `Chat.Read.All`, `Sites.Read.All`, `Calendars.Read`...). Flag: `DANGEROUS_PERMISSION`.
- **Broad directory reads (tier 2, 9):** `Directory.Read.All`, `User.Read.All`, `Group.Read.All`, `GroupMember.Read.All`, `AuditLog.Read.All`,
  `DeviceManagementManagedDevices.Read.All`, `IdentityRiskEvent.Read.All`, `Member.Read.Hidden`, `ThreatHunting.Read.All`. They expose a lot of directory metadata
  but not mail, files or chats, and many legitimate products need them, so they are "to review": `BROAD_READ_PERMISSION`. A permission on both lists counts as tier 1.

The **kind of permission matters**: an *application* permission acts on its own across the whole tenant, a *delegated* one is limited to what the signed-in user can
do. So `DANGEROUS_PERMISSION` is HIGH when any tier-1 permission is held as an application permission and MEDIUM when only delegated; `BROAD_READ_PERMISSION` is MEDIUM
as application and LOW as delegated. Matching is by exact name. On a real tenant of about 120 app registrations the 114-permission list raised the apps with a
flagged permission from 10 (old 7-permission list) to 32.

Both lists are editable in Settings and saved with the database, and they are the factory defaults, so **Delete database** (or the *Restore the built-in list*
buttons) brings them back. Broom365 never calls a permission "unnecessary".

### Internal users

The **Internal users** tab covers ordinary (non-guest) accounts, read by the analysis as one paged list with their licences and last sign-in (about 120 per
request; 2,900 users in about 15 seconds). It reports two things:

- **Disabled with licences** (`DISABLED_LICENSED_MEMBER`): the account cannot be used but still holds a **paid** licence, so you pay for nothing. Free licences
  (Power Automate free, Power BI free...) are ignored.
- **Stale** (`STALE_MEMBER`): an enabled account with no sign-in for `stale_days_member` (default 180) or created longer ago and never signed in. The latest of the
  interactive, non-interactive and successful sign-ins is used, so a service account that only signs in non-interactively is not reported. MEDIUM if it holds a paid
  licence, otherwise LOW.

Accounts synced from on-premises Active Directory are labelled *AD* and the explanation says they must be changed there. Service and shared accounts may not sign in
interactively, so review before acting. Disabled accounts **without** a licence are only flagged (`DISABLED_MEMBER`, LOW, *leftover account*) after you press
**Read mailbox types** on the Internal users panel (one Exchange read, about 40 s on 2,900 users): shared, room and equipment
mailboxes are disabled by design and are then left out. Until then they are listed as "not checked", never guessed.
Privileged accounts stay on the Users tab.

### Distribution lists (Exchange)

Analysing the tab reads all lists, dynamic lists, transport rules and the tenant's mail domains in four calls (needs `Exchange.ManageAsApp` plus an Entra role such as Global Reader on the
app). Members and mail traffic are per-list reads, so you pick lists by name or address pattern (same syntax as the other tabs) and press *Check*. Traffic is
a message trace over the last 89 days (the longest Exchange keeps), about 4 s per list without mail.

- `DL_NO_OWNER` (LOW): no owner. Known from the analysis.
- `DL_EMPTY` (MEDIUM): checked, no members.
- `DL_NO_MAIL` (MEDIUM): checked, no mail addressed to it in 89 days.
- `LIKELY_UNUSED_DL` (MEDIUM): no mail, empty or ownerless, and no transport rule mentions it.

If transport rules or the trace cannot be read, the verdict is withheld and the gap is shown.

### Shared, room and equipment mailboxes (Exchange)

These accounts cannot sign in with a password, so they are not "stale users"; what matters is whether anyone still uses them. Press **Read mailbox list**
(one Exchange read, about 30-40 s on 1,700 mailboxes) on the *Shared mailboxes* tab: that list is what the tab analyses (it also separates mailboxes
from leftover accounts on the Internal users tab). Then pick mailboxes by name or address pattern and press *Check mailboxes* (about 3-7 s each): Broom365 reads
the last sign-in and item count (`Get-MailboxStatistics`), who has Full Access (`Get-MailboxPermission`) and Send As (`Get-RecipientPermission`), and asks message
trace for mail received in the last 89 days. Holders are matched against the internal users: a bare SID is a **deleted** account, a disabled account is **disabled**.

- `MAILBOX_NO_ACTIVITY` (MEDIUM): no sign-in for `stale_days_mailbox` days (default 180, or never) and no mail in 89 days.
- `MAILBOX_NO_DELEGATES` (MEDIUM, shared only): no enabled account has Full Access. Rooms and equipment are booked through the calendar, so they are not judged this way.
- `MAILBOX_ORPHAN_DELEGATES` (LOW): Full Access or Send As held by deleted or disabled accounts.
- `LIKELY_UNUSED_MAILBOX` (MEDIUM): no activity, and (room/equipment, or nobody who could use a shared one: no enabled Full Access or Send As holder).

A service or app sending as the mailbox, or a forwarding rule, leaves no trace Broom365 can see, so every finding is a candidate for review.

### Mail flow (transport) rules

Rules come with the analysis (one list), so the *Mail flow rules* tab needs no check:

- `RULE_DISABLED`, `RULE_EXPIRED` (expiry date passed), `RULE_NOT_ENFORCING` (mode is not Enforce: it only tests or audits): all LOW.
- `RULE_DEAD_REFERENCE` (LOW): the rule names an address of this tenant (one of the accepted domains) that matches no distribution list, mailbox, user
  (aliases included) or group. It needs the mailbox list to have been read; mail contacts and public folders are not known, so confirm it in Exchange.

Exchange does not report how often a rule matched, so Broom365 cannot say a rule is unused.

"No sign-in on record" counts as inactive and is described in those words. If sign-in data cannot be read, the
sign-in based flags are **skipped and reported as unavailable**, not guessed.

---

## What Broom365 can and cannot do

**It can**

- Read your tenant with read-only Microsoft Graph calls and never change anything.
- List, in about 30 seconds on a tenant of 2,200 groups, 4,900 users and 350 Intune apps: groups, privileged users, app registrations, Intune apps, scripts and
  remediations, external guests, and the places that reference a group.
- Check on demand, for the objects you choose, what needs a per-object read: group owners/members/nesting, app permissions, Intune app relations,
  script run results, guest memberships.
- Correlate: a group that looks empty but is an Intune uninstall target; an app with an expired secret and no sign-ins; a disabled or external account that
  holds an admin role; a guest idle for years who is still in a Team; an old script that has failed on hundreds of devices.
- Explain each finding in plain language with the dates, names and scopes behind it, say what could **not** be checked, and export it as CSV (everything, or
  one file per tab) with a link to the object in the Intune / Entra portal.
- Tell you exactly which Graph permission is missing (Settings, *Validate permissions*), and degrade gracefully when a signal is unavailable.

**It cannot**

- Change, disable, delete or remove anything. Every finding is a *candidate for review*; remediation is a later milestone.
- **Prove that something is unused.** "None found" only covers the places listed on each group page. It does not look at shared mailbox and calendar
  permissions, membership of other lists, SharePoint or Teams permissions, Azure RBAC, entitlement management and access reviews,
  other Intune areas (app protection, enrollment restrictions, Autopilot, filters, scope tags), administrative units, PIM for Groups, or
  third-party and on-premises systems that read a group.
- Judge whether a script's *content* is still relevant. It uses metadata and run results (age, assignment, failures, last run), not what the script does.
- See further back than the audit log keeps (about 30 days; about 7 without Entra ID P1/P2), so group staleness is a weak signal.
- Read what needs a licence or a beta API you do not have: sign-in activity needs Entra ID P1/P2.
- Cover everything in a tenant. Not covered yet: devices, Teams and SharePoint sites, licence usage beyond disabled accounts, third-party enterprise apps,
  PIM-eligible role assignments, Conditional Access policy hygiene, personal mailboxes and OneDrive. Exchange is covered for distribution lists, shared / room /
  equipment mailboxes and mail flow rules (read with `Get-*` cmdlets, via `Exchange.ManageAsApp`); not covered: calendar permissions, public folders, mail contacts,
  retention and compliance settings.
- Serve several tenants, or several people at once: it is single-tenant, and app-only mode gives whoever opens the page tenant-wide read access (it accepts
  Broom365 accounts).

## Screens

| Route | What it shows |
|---|---|
| `/` | Summary cards, then one **tab per type**: **Groups**, **Apps**, **Users** (`/?tab=apps`, `/?tab=users`). Groups and Apps each have their own scan scope and table; Users lists every privileged account |
| `/groups/<id>` | Metadata, owners, app assignments with target state, **where the group is used** (and what could not be checked), every flag explained with evidence, links to the portal |
| `/apps/<id>` | Credentials with status, permissions (high-risk highlighted), owners, last sign-in, groups assigned to the app |
| `/users/<id>` | Roles, last sign-in, flags |
| `/settings` | Connection and permission status, **Validate permissions** (see below), data freshness, editable thresholds and high-risk list, signal availability with reasons, inventory re-sync |
| `/?tab=intune` | Intune apps that are uninstall-only or unassigned (see above), with a link to each app in the Intune admin center |
| `/?tab=members` | Internal users that are disabled but still licensed, or enabled and stale, with AD / Disabled tags |
| `/?tab=guests` | External (guest) users that are stale or never accepted their invitation, with company chips to filter by organisation |
| `/?tab=scripts` | Intune scripts and remediations that look obsolete (see above) |
| `/export` | One CSV with **every** flagged object of every type (risk, flags, explanations) |
| `/export/<tab>` | One CSV per tab: `groups`, `apps`, `users`, `intune`, `scripts`, `guests`, `members`. Each has the columns that fit its objects (members and what references a group; secrets and permissions of an app; account type and roles of a user; assignments with intent for an Intune app; run results of a script; company domain and invitation state of a guest) plus a link to the object in the portal. Every row of the tab is exported, regardless of the on-page filters; the Users file lists all privileged accounts, flagged or not |
| `/permissions` | Preflight result with fix instructions |

**Validate permissions** (Settings) re-reads the permissions granted to the app, then makes one small real call to every data
source. For each failure it gives the exact permission name to add, or says when the permission is granted and the cause is
something else (a licence, or Graph rejecting the request).

Users are scoped by directory role rather than by pattern: every user holding a role is evaluated automatically.

Every page has an **Export this tab (CSV)** button next to the filters, and the top bar keeps **Export all (CSV)**. All cells are made safe against spreadsheet formula injection, since names come from the tenant.

Saving settings recomputes flags from stored data; nothing is read from Graph.

**Delete database** (Settings, bottom) removes everything stored locally: totals, analyses, scans, flags, saved thresholds and
scope patterns. Type `DELETE` to confirm; it is refused while a sync runs. The tenant is never touched, and counting the objects and
analysing the tabs again rebuilds it. There are no data migrations: after upgrading, delete the database if the app complains about
a missing column.

---

## Known limitations

- **Audit retention.** Directory audit logs keep about 30 days (about 7 without Entra ID P1/P2), far less than the
  default 180-day `STALE` threshold, and Graph rejects older start dates. Broom365 asks for at most the last 29 days
  (6 if the tenant keeps less). A group with no event in that window falls back to its creation date, which can
  over-flag a group changed 30 to 180 days ago, and the finding says so. Treat `STALE` as a weak signal.
- **Usage coverage** is limited to the places listed under *Is this group really unused?*. Intune assignments are read
  from a fixed set of endpoints (apps, device configuration, compliance, settings catalog, administrative templates,
  scripts); other Intune areas are not. Several of these are beta endpoints, and an unreadable one is shown as
  *Not checked*, never as *None found*.
- **Scope of apps**: app registrations of this tenant only; third-party enterprise apps are not evaluated.
- **Roles**: only active assignments are read, not PIM-eligible ones.
- **Beta endpoints**: service principal sign-in (`/beta/reports/servicePrincipalSignInActivities`) and user
  `signInActivity` are beta APIs; user sign-in needs Entra ID P1/P2. The service principal report path was written
  from documentation and should be verified against your tenant.
- **Speed**: Graph calls are sequential. On a real tenant with about 2,200 groups, 120 app registrations and 350 Intune
  apps and 2,000 guests, the inventory took about 30 seconds. A group check costs about 4 calls per group, an Intune app check 1 call per app (about 90 seconds for all
  354), a script check 1 call per script (about 15 seconds for all 55). A deep scan of thousands of objects is slow; scope it with patterns.
  `$batch` is a planned optimisation.
- **App-only sees the whole tenant** within the permissions granted to the registration; there is no per-user
  filtering. Delegated mode limits what you see to the signed-in account's own permissions.

## Production notes

This is built for a single tenant and a single instance.

- **Who can open the UI.** The app holds tenant-wide read access, so every page needs a Broom365 account (see *Accounts*).
  Put it behind HTTPS. Passwords are the only factor; there is no MFA, so keep it on an internal network.

- **Sessions** are stored in server-side filesystem files (`sessions/` next to the database settings, in `instance/`). App mode keeps its Graph token only
  in memory. In delegated mode the MSAL token cache is also kept in the session, so production needs a proper
  shared, encrypted cache (for example Redis, or an encrypted table) keyed per user.
- Serve over **HTTPS** and set `SESSION_COOKIE_SECURE=True`. The session signing key is generated once and kept in the database (`SECRET_KEY` overrides it).
- State-changing requests are CSRF-protected (per-session token). Cookies are `HttpOnly` and `SameSite=Lax`.
- Never commit `.env` or `instance/`. Rotate the client secret before it expires.
- Use a production WSGI server (the Docker image runs Gunicorn with `broom365.wsgi:application`) rather than the Flask development server.
- Only one sync job runs at a time, in-process. Multiple workers would need an external lock.

## Project layout

```
run.py               development entry point (flask --app run run); production uses broom365/wsgi.py
broom365/
  __init__.py        app factory
  wsgi.py            production entry point: the installer first, the application once configured
  bootstrap.py       the installer's saved settings (bootstrap.json), the encryption key, the database URL builder
  installer/         the installer pages (database, key, admin password, Test connection)
  connect/           the step after sign-in: Microsoft 365 connection and permission check
  config.py          optional environment values + default thresholds and scope list
  database.py        SQLite or SQL Server connections (ODBC string, SQL translation)
  db.py              per-request connection, schema, settings store
  runtime.py         the Microsoft 365 connection in effect
  security.py        CSRF
  templating.py      Jinja filters
  demo.py            synthetic tenant (BROOM_DEMO=1)
  auth/              accounts sign-in, MSAL, preflight, token provider for background jobs
  dashboard/ groups/ apps/ users/ settings/ accounts/ export/    blueprints (routes only)
  models/            schema.sql, domain dataclasses (types.py)
  services/
    graph.py         typed Graph helpers, paging, 429/5xx backoff
    exchange.py      read-only Exchange Online client
    sync.py          inventory and scan, signal availability
    scope.py         pattern matching (pure)
    correlate.py     group flags + risk (pure)
    extended_signals.py, intune.py, updates.py, guests.py, members.py, exchange_*.py   the checks (pure)
    permissions.py   scope preflight (pure)
    accounts.py, appconfig.py    Broom365 accounts; the Microsoft 365 connection and its encryption
    repository.py    database <-> domain types, flag persistence
    sync_runner.py   background job runner
  templates/ static/
tests/               unit tests with fixtures; page tests against demo data
```

## Tests

```powershell
.venv\Scripts\python -m pytest
```

The correlation, scope-pattern and permission logic are pure and tested without Graph; sync is tested end to end
with a fake Graph client, including denied endpoints and missing scopes.

## Roadmap

v1 is read-only. The `remediation_actions` table (status lifecycle, before-state snapshot for rollback) exists but
is unused, so later milestones can add disable / revoke / remove-assignment with approval and audit without a
schema refactor.

## Security

Broom365 is meant for an internal network. It holds tenant-wide read access to your Microsoft 365 tenant, so treat the server like any other admin tool.

- The installer is open to whoever can reach the port until it is finished, and it sets the `admin` password: install right after starting, and do not expose a fresh instance to an untrusted network.
- Passwords are the only factor (no MFA). Put it behind HTTPS and your own network controls (VPN, reverse proxy with SSO, IP allow-list).
- The Entra client secret is encrypted in the database with the key chosen in the installer, which is kept in `instance/bootstrap.json` (readable only by the app's user). Keep a copy of the key; without it the secret has to be entered again.
- Give the Entra app registration only the **read** permissions listed above. Broom365 never writes to the tenant.
- No tenant data, credentials or session files belong in a clone of this repository: `.env` and `instance/` are ignored by git and by the Docker build.

To report a vulnerability, please open a private security advisory on the repository rather than a public issue.

## License

[MIT](LICENSE). You may use, modify and redistribute Broom365, including commercially, as long as the copyright notice and the licence text are kept in
copies of the software. It is provided as is, without warranty; check every finding in your own tenant before acting on it.
