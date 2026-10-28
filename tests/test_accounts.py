"""Broom365 accounts: first admin, forced password change, roles, lockout, the Entra connection kept in the database."""
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from broom365 import create_app
from broom365.auth import AppAuthState, AppOnlyTokens
from broom365.config import Config
from broom365.services import accounts, appconfig
from broom365.services.permissions import check_permissions

NOW = datetime(2026, 10, 26, tzinfo=timezone.utc)
SCHEMA = Path(__file__).parents[1] / "broom365" / "models" / "schema.sql"
GOOD = "correct horse battery"
ROLES = ["Group.Read.All", "Application.Read.All", "Directory.Read.All", "RoleManagement.Read.Directory", "AuditLog.Read.All",
         "Policy.Read.All", "DeviceManagementApps.Read.All", "DeviceManagementConfiguration.Read.All", "Exchange.ManageAsApp"]


@pytest.fixture()
def conn():
    c = sqlite3.connect(":memory:")
    c.row_factory = sqlite3.Row
    c.executescript(SCHEMA.read_text(encoding="utf-8"))
    return c


# ------------------------------------------------------------- service -------
def test_first_admin_has_no_password_and_is_created_once(conn):
    assert accounts.ensure_admin(conn, NOW) is True and accounts.ensure_admin(conn, NOW) is False
    (a,) = accounts.list_accounts(conn)
    assert a.username == "admin" and a.is_admin and not a.has_password and a.must_change_password


def test_empty_password_works_only_while_no_password_is_set(conn):
    accounts.ensure_admin(conn, NOW)
    acc, err = accounts.authenticate(conn, "admin", "", NOW)
    assert acc is not None and err is None
    accounts.set_password(conn, acc.id, GOOD)
    assert accounts.authenticate(conn, "admin", "", NOW)[0] is None
    assert accounts.authenticate(conn, "ADMIN ", GOOD, NOW)[0] is not None   # username is trimmed and case-insensitive


def test_wrong_user_and_wrong_password_give_the_same_message(conn):
    accounts.ensure_admin(conn, NOW)
    accounts.set_password(conn, 1, GOOD)
    assert accounts.authenticate(conn, "nobody", "x", NOW)[1] == accounts.authenticate(conn, "admin", "x", NOW)[1] == "Wrong username or password."


def test_five_failures_lock_the_account_for_a_few_minutes(conn):
    accounts.ensure_admin(conn, NOW)
    accounts.set_password(conn, 1, GOOD)
    for _ in range(accounts.MAX_FAILURES):
        accounts.authenticate(conn, "admin", "bad", NOW)
    acc, err = accounts.authenticate(conn, "admin", GOOD, NOW)
    assert acc is None and "Too many" in err                      # even the right password is refused while locked
    assert accounts.authenticate(conn, "admin", GOOD, NOW + timedelta(minutes=accounts.LOCK_MINUTES + 1))[0] is not None


def test_password_rules():
    assert accounts.validate_password("short") and accounts.validate_password("admin12345", "admin12345")
    assert accounts.validate_password(" leading space 1") and accounts.validate_password(GOOD) is None


def test_create_validates_and_rejects_duplicates(conn):
    assert accounts.create(conn, "Ana", GOOD, "reader", NOW) is None
    assert accounts.create(conn, "ana", GOOD, "reader", NOW) == "That username already exists."
    assert accounts.create(conn, "x", GOOD, "reader", NOW) and accounts.create(conn, "bob", "short", "reader", NOW)
    assert accounts.create(conn, "bob", GOOD, "boss", NOW) == "Unknown role."
    (a,) = accounts.list_accounts(conn)
    assert a.username == "ana" and a.must_change_password and a.has_password


def test_the_last_admin_cannot_be_deleted_or_demoted(conn):
    accounts.ensure_admin(conn, NOW)
    assert accounts.delete(conn, 1) and accounts.set_role(conn, 1, "reader")
    accounts.create(conn, "boss", GOOD, "admin", NOW)
    assert accounts.set_role(conn, 1, "reader") is None and accounts.delete(conn, 2) and accounts.delete(conn, 1) is None


# -------------------------------------------------------------- routes -------
def csrf(client, path="/login"):
    return re.search(r'name="csrf_token" value="([^"]+)"', client.get(path).get_data(as_text=True)).group(1)


def sign_in(client, username, password):
    return client.post("/login", data={"username": username, "password": password, "csrf_token": csrf(client)})


def choose_password(client, new=GOOD, current=None):
    data = {"new_password": new, "confirm_password": new, "csrf_token": csrf(client, "/account/password")}
    if current:
        data["current_password"] = current
    return client.post("/account/password", data=data)


@pytest.fixture()
def cfg(tmp_path):
    return Config(database_path=tmp_path / "db.sqlite")


@pytest.fixture()
def make(monkeypatch, cfg):
    monkeypatch.delenv("BROOM_DEMO", raising=False)
    monkeypatch.delenv("SECRET_KEY", raising=False)
    monkeypatch.setattr(AppOnlyTokens, "state", lambda self, force=False: AppAuthState(check_permissions(ROLES, app_only=True), tuple(ROLES), None, 0.0))
    monkeypatch.setattr(AppOnlyTokens, "token", lambda self: "fake-token")
    monkeypatch.setattr("broom365.auth.time.sleep", lambda s: None)
    return lambda: create_app(cfg).test_client()


@pytest.fixture()
def admin(make):
    c = make()
    sign_in(c, "admin", "")
    choose_password(c)
    return c


def test_everything_needs_a_sign_in(make):
    c = make()
    for path in ("/", "/settings", "/accounts", "/export", "/groups/x"):
        assert c.get(path).headers["Location"].endswith("/login"), path
    assert c.post("/sync/inventory").status_code == 400          # no CSRF token without a session


def test_first_start_explains_how_to_sign_in_and_forces_a_password(make):
    c = make()
    assert "First start" in c.get("/login").get_data(as_text=True)
    r = sign_in(c, "admin", "")
    assert r.status_code == 302 and r.headers["Location"].endswith("/account/password")
    for path in ("/", "/settings", "/accounts"):                  # nothing else opens until a password is chosen
        assert c.get(path).headers["Location"].endswith("/account/password"), path
    assert choose_password(c, "short").status_code == 400
    assert choose_password(c, GOOD).status_code == 302
    assert c.get("/").headers["Location"].endswith("/connect")           # next: connect to Microsoft 365
    assert c.get("/connect").status_code == 200 and "First start" not in make().get("/login").get_data(as_text=True)


def test_the_two_new_passwords_must_match(make):
    c = make()
    sign_in(c, "admin", "")
    r = c.post("/account/password", data={"new_password": GOOD, "confirm_password": GOOD + "x", "csrf_token": csrf(c, "/account/password")})
    assert r.status_code == 400 and "different" in r.get_data(as_text=True)


def test_wrong_password_is_refused_and_logout_closes_the_session(admin, make):
    other = make()
    assert sign_in(other, "admin", "nope").status_code == 401
    assert other.get("/").status_code == 302
    admin.get("/logout")
    assert admin.get("/").status_code == 302
    assert sign_in(admin, "admin", GOOD).headers["Location"].endswith("/")


def test_changing_your_password_needs_the_current_one(admin):
    assert choose_password(admin, "another long password", current="wrong").status_code == 400
    assert choose_password(admin, "another long password", current=GOOD).status_code == 302
    admin.get("/logout")
    assert sign_in(admin, "admin", GOOD).status_code == 401 and sign_in(admin, "admin", "another long password").status_code == 302


def test_admin_creates_a_reader_who_must_change_the_temporary_password(admin, make):
    connect(admin)                                   # readers only get in once the Microsoft 365 connection exists
    r = admin.post("/accounts/add", data={"username": "ana", "password": "temporary-pass-1", "role": "reader", "csrf_token": csrf(admin, "/accounts")})
    assert r.status_code == 302
    reader = make()
    assert sign_in(reader, "ana", "temporary-pass-1").headers["Location"].endswith("/account/password")
    assert reader.get("/").headers["Location"].endswith("/account/password")
    assert choose_password(reader, "ana's own password", current="temporary-pass-1").status_code == 302
    assert reader.get("/").status_code == 200


def test_a_reader_can_view_and_run_checks_but_not_administer(admin, make):
    connect(admin)                                   # readers only get in once the Microsoft 365 connection exists
    admin.post("/accounts/add", data={"username": "ana", "password": "temporary-pass-1", "role": "reader", "csrf_token": csrf(admin, "/accounts")})
    reader = make()
    sign_in(reader, "ana", "temporary-pass-1")
    choose_password(reader, "ana's own password", current="temporary-pass-1")
    tok = csrf(reader, "/account/password")
    assert reader.get("/").status_code == 200 and reader.get("/export").status_code == 200
    html = reader.get("/").get_data(as_text=True)
    assert 'href="/settings"' not in html and 'href="/accounts"' not in html and "ana (reader)" in html
    for path in ("/settings", "/accounts"):
        assert reader.get(path).status_code == 403
    assert reader.post("/settings/reset", data={"confirm": "DELETE", "csrf_token": tok}).status_code == 403
    assert reader.post("/accounts/add", data={"username": "eve", "password": "temporary-pass-1", "role": "admin", "csrf_token": tok}).status_code == 403
    assert reader.post("/sync/inventory", headers={"X-CSRF-Token": tok}).status_code == 200      # may run inventories


def test_admin_screens_show_accounts_and_enforce_the_last_admin_rule(admin):
    tok = csrf(admin, "/accounts")
    html = admin.get("/accounts").get_data(as_text=True)
    assert "admin" in html and "you" in html
    assert admin.post("/accounts/1/delete", data={"csrf_token": tok}).status_code == 400          # own account
    assert admin.post("/accounts/1/role", data={"role": "reader", "csrf_token": tok}).status_code == 400
    assert admin.post("/accounts/add", data={"username": "ANA", "password": "x", "role": "reader", "csrf_token": tok}).status_code == 400


def test_admin_resets_a_password_and_deletes_an_account(admin, make):
    tok = csrf(admin, "/accounts")
    admin.post("/accounts/add", data={"username": "ana", "password": "temporary-pass-1", "role": "reader", "csrf_token": tok})
    assert admin.post("/accounts/2/reset", data={"password": "short", "csrf_token": tok}).status_code == 400
    assert admin.post("/accounts/2/reset", data={"password": "temporary-pass-2", "csrf_token": tok}).status_code == 302
    assert sign_in(make(), "ana", "temporary-pass-2").status_code == 302
    assert admin.post("/accounts/2/delete", data={"csrf_token": tok}).status_code == 302
    assert sign_in(make(), "ana", "temporary-pass-2").status_code == 401


def test_the_session_key_is_generated_once_and_kept_in_the_database(make, cfg):
    make()
    c = sqlite3.connect(cfg.database_path)
    first = c.execute("SELECT value FROM app_config WHERE name = 'session_key'").fetchone()[0]
    make()
    assert c.execute("SELECT value FROM app_config WHERE name = 'session_key'").fetchone()[0] == first and len(first) == 64


# ------------------------------------------------ Entra connection in the DB ---
TENANT, CLIENT = "11111111-2222-3333-4444-555555555555", "99999999-8888-7777-6666-555555555555"


def connect(client, **over):
    data = {"tenant_id": TENANT, "client_id": CLIENT, "client_secret": "the-secret", "csrf_token": csrf(client, "/accounts")}
    data.update(over)
    return client.post("/settings/connection", data=data, follow_redirects=True)


def stored(cfg, name):
    r = sqlite3.connect(cfg.database_path).execute("SELECT value FROM app_config WHERE name = ?", (name,)).fetchone()
    return r and r[0]


def test_connection_is_validated_and_saved_in_the_database(admin, cfg, monkeypatch):
    monkeypatch.delenv("BROOM_KEY", raising=False)
    assert "Tenant ID must be" in connect(admin, tenant_id="nope").get_data(as_text=True)
    assert "Client ID must be" in connect(admin, client_id="nope").get_data(as_text=True)
    assert "Enter the client secret" in connect(admin, client_secret="").get_data(as_text=True)
    assert stored(cfg, "azure_tenant_id") is None
    html = connect(admin).get_data(as_text=True)
    assert "Connection saved" in html and TENANT in html and CLIENT in html and "the-secret" not in html
    assert stored(cfg, "azure_tenant_id") == TENANT and stored(cfg, "azure_client_secret") == "plain:the-secret"
    assert "stored as plain text" in html


def test_a_blank_secret_keeps_the_stored_one(admin, cfg):
    connect(admin)
    connect(admin, client_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", client_secret="")
    assert stored(cfg, "azure_client_id") == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee" and stored(cfg, "azure_client_secret") == "plain:the-secret"


def test_with_broom_key_the_secret_is_encrypted_and_readable_only_with_that_key(admin, cfg, monkeypatch):
    monkeypatch.setenv("BROOM_KEY", "k1")
    html = connect(admin).get_data(as_text=True)
    raw = stored(cfg, "azure_client_secret")
    assert raw.startswith("enc:") and "the-secret" not in raw and "encrypted with" in html
    c = sqlite3.connect(cfg.database_path)
    c.row_factory = sqlite3.Row
    assert appconfig.load_credentials(c).client_secret == "the-secret"
    monkeypatch.setenv("BROOM_KEY", "other")
    got = appconfig.load_credentials(c)
    assert got.client_secret == "" and got.secret_unreadable
    monkeypatch.delenv("BROOM_KEY")
    assert appconfig.load_credentials(c).secret_unreadable


def test_database_values_override_the_environment_and_new_tokens_are_built(admin, cfg, monkeypatch):
    from broom365 import auth
    built = []
    monkeypatch.setattr(auth, "AppOnlyTokens", lambda c: built.append((c.tenant_id, c.client_id, c.client_secret)) or object())
    with admin.application.test_request_context("/"):
        auth._tokens()
    connect(admin)
    with admin.application.test_request_context("/"):
        auth._tokens()
        auth._tokens()
    assert built[-1] == (TENANT, CLIENT, "the-secret") and len(built) == 2     # rebuilt once after the change, then reused


def test_without_a_connection_the_dashboard_explains_what_to_do(monkeypatch, cfg):
    monkeypatch.delenv("BROOM_DEMO", raising=False)
    monkeypatch.undo()
    monkeypatch.delenv("BROOM_DEMO", raising=False)
    monkeypatch.setattr("broom365.auth.time.sleep", lambda s: None)
    c = create_app(cfg).test_client()
    sign_in(c, "admin", "")
    choose_password(c)
    r = c.get("/")
    assert r.headers["Location"].endswith("/connect")
    page = c.get("/connect").get_data(as_text=True)
    assert "Connect to Microsoft 365" in page and "Permissions" not in page      # nothing to check before a connection exists
    assert "not configured yet" in c.get("/permissions").get_data(as_text=True)
    assert c.get("/settings").status_code == 200                      # Settings stays reachable to fix it


def test_deleting_the_database_keeps_accounts_and_the_connection(admin, cfg):
    connect(admin)
    admin.post("/accounts/add", data={"username": "ana", "password": "temporary-pass-1", "role": "reader", "csrf_token": csrf(admin, "/accounts")})
    admin.post("/settings/reset", data={"confirm": "DELETE", "csrf_token": csrf(admin, "/accounts")})
    c = sqlite3.connect(cfg.database_path)
    assert c.execute("SELECT COUNT(*) FROM app_users").fetchone()[0] == 2 and stored(cfg, "azure_tenant_id") == TENANT
    assert admin.get("/").status_code == 200


def test_readers_wait_for_an_admin_to_finish_the_setup(admin, make):
    admin.post("/accounts/add", data={"username": "ana", "password": "temporary-pass-1", "role": "reader", "csrf_token": csrf(admin, "/accounts")})
    reader = make()
    sign_in(reader, "ana", "temporary-pass-1")
    choose_password(reader, "ana's own password", current="temporary-pass-1")
    r = reader.get("/")
    assert r.status_code == 503 and "an admin has to connect Broom365" in r.get_data(as_text=True)
    connect(admin)
    assert reader.get("/").status_code == 200
