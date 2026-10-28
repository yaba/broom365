"""The installer (first start / broken database settings) and the connect step that follows it."""
import json
import re
from pathlib import Path

import pytest
from werkzeug.test import Client
from werkzeug.wrappers import Response

from broom365 import bootstrap
from broom365.auth import AppAuthState, AppOnlyTokens
from broom365.database import odbc_connection_string
from broom365.installer import create_setup_app
from broom365.services import appconfig
from broom365.services.permissions import check_permissions
from broom365.wsgi import Switch
from tests.test_accounts import GOOD, ROLES, admin, cfg, choose_password, connect, csrf, make, sign_in  # noqa: F401 (fixtures)


@pytest.fixture()
def home(tmp_path, monkeypatch):
    """A clean working folder: no environment settings, no .env, no key left over from another test."""
    monkeypatch.chdir(tmp_path)
    for name in ("DATABASE_URL", "BROOM_KEY", "SECRET_KEY", "BROOM_DEMO", "TENANT_ID", "CLIENT_ID", "CLIENT_SECRET", "AUTH_MODE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "instance" / "broom365.sqlite"))
    monkeypatch.setattr("broom365.bootstrap.load_dotenv", lambda *a, **k: None)
    monkeypatch.setattr("broom365.config.load_dotenv", lambda *a, **k: None)
    monkeypatch.setattr("broom365.auth.time.sleep", lambda s: None)
    bootstrap.use_key("")
    yield tmp_path
    bootstrap.use_key("")


def token(client, path="/"):
    return re.search(r'name="csrf_token" value="([^"]+)"', client.get(path).get_data(as_text=True)).group(1)


SQLITE_FORM = {"storage": "sqlite", "key": "k" * 24, "admin_password": GOOD, "admin_password2": GOOD}


# ----------------------------------------------------------- pure helpers ----
def test_the_url_built_from_the_form_reads_back_exactly():
    url = bootstrap.build_database_url("sql01\\PROD", "1981", "my db", "svc", "p@ss/w#rd?%;=:x", "trust", "ApplicationIntent=ReadOnly\nConnection Timeout=15")
    s = odbc_connection_string(url)
    assert s == ("DRIVER={ODBC Driver 18 for SQL Server};SERVER=sql01\\PROD,1981;DATABASE=my db;UID=svc;PWD={p@ss/w#rd?%;=:x};"
                 "ApplicationIntent=ReadOnly;Connection Timeout=15;TrustServerCertificate=yes")


@pytest.mark.parametrize("mode,expected", [("verify", "Encrypt=yes;TrustServerCertificate=no"), ("off", "Encrypt=no"), ("trust", "TrustServerCertificate=yes")])
def test_each_encryption_choice_becomes_the_matching_options(mode, expected):
    assert odbc_connection_string(bootstrap.build_database_url("h", "", "d", "u", "p", mode)).endswith(expected)


def test_windows_or_azure_authentication_needs_no_user_name():
    assert bootstrap.needs_user("") and not bootstrap.needs_user("Trusted_Connection=yes") and not bootstrap.needs_user("Authentication=ActiveDirectoryMsi")


@pytest.mark.parametrize("text,fragment", [
    ("('HYT00', '[HYT00] [Microsoft][ODBC Driver 18 for SQL Server]Login timeout expired (0)')", "did not answer in time"),
    ("('08001', 'SSL Provider: certificate verify failed:self-signed certificate')", "certificate was refused"),
    ("('28000', 'Login failed for user x (18456)')", "refused the user name or password"),
    ("('42000', 'Cannot open database \"x\" requested by the login (4060)')", "database does not exist"),
    ("('IM002', 'Data source name not found')", "ODBC driver"),
])
def test_database_errors_are_explained_in_plain_language(text, fragment):
    assert fragment in bootstrap.explain_db_error(RuntimeError(text))


def test_the_saved_file_round_trips_and_decides_whether_setup_is_needed(home):
    assert bootstrap.needs_setup() and bootstrap.load() == {}
    bootstrap.save("", "key-key-key-key-key")
    assert bootstrap.load() == {"database_url": "", "key": "key-key-key-key-key"} and not bootstrap.needs_setup()
    bootstrap.path().unlink()
    assert bootstrap.needs_setup()
    bootstrap.data_path().parent.mkdir(parents=True, exist_ok=True)
    bootstrap.data_path().write_text("")                         # an existing SQLite file counts as an installation
    assert not bootstrap.needs_setup()


def test_the_environment_wins_over_the_saved_settings(home, monkeypatch):
    bootstrap.save("sqlite-from-file", "file-key-file-key-1")
    monkeypatch.setenv("DATABASE_URL", "mssql+pyodbc://env")
    monkeypatch.setenv("BROOM_KEY", "env-key")
    from broom365.config import Config
    assert Config.from_env().database_url == "mssql+pyodbc://env" and not bootstrap.needs_setup()
    bootstrap.use_saved_key()
    assert bootstrap.encryption_key() == "env-key"
    monkeypatch.delenv("BROOM_KEY")
    assert bootstrap.encryption_key() == "file-key-file-key-1"


# --------------------------------------------------------- the installer ------
def test_first_start_installs_with_sqlite_and_leads_to_the_admin_sign_in(home):
    c = Client(Switch(), Response)
    page = c.get("/").get_data(as_text=True)
    assert "<h2>Install</h2>" in page and "SQL Server" in page and 'name="key"' in page
    assert c.get("/login").status_code == 302 and c.get("/login").headers["Location"].endswith("/")      # every other address leads here
    key = re.search(r'name="key" value="([^"]+)"', page).group(1)
    assert len(key) >= bootstrap.MIN_KEY                                                                # a random key is suggested

    assert c.post("/", data={**SQLITE_FORM}).status_code == 400                                         # no CSRF token
    t = token(c)
    mismatch = c.post("/", data={**SQLITE_FORM, "admin_password2": GOOD + "x", "csrf_token": t})
    assert mismatch.status_code == 400 and "different" in mismatch.get_data(as_text=True) and not bootstrap.path().exists()
    weak = c.post("/", data={**SQLITE_FORM, "admin_password": "short", "admin_password2": "short", "csrf_token": t})
    assert weak.status_code == 400 and "at least 10" in weak.get_data(as_text=True)

    done = c.post("/", data={**SQLITE_FORM, "csrf_token": t})
    assert done.status_code == 302
    assert json.loads(bootstrap.path().read_text()) == {"database_url": "", "key": "k" * 24}

    login = c.get("/login")                                          # the real application answers now, in the same process
    assert login.status_code == 200 and "Username" in login.get_data(as_text=True)
    r = c.post("/login", data={"username": "admin", "password": GOOD, "csrf_token": token(c, "/login")})
    assert r.status_code == 302 and r.headers["Location"].endswith("/")        # no forced password change: it was chosen in the installer
    assert c.get("/").headers["Location"].endswith("/connect")                   # next step: connect to Microsoft 365


def test_a_second_start_goes_straight_to_the_application(home):
    c = Client(Switch(), Response)
    c.post("/", data={**SQLITE_FORM, "csrf_token": token(c)})
    again = Client(Switch(), Response)                                # a new process
    assert "Username" in again.get("/login").get_data(as_text=True)
    assert bootstrap.encryption_key() == "k" * 24                       # the saved key encrypts the Microsoft 365 secret


def test_sql_server_settings_are_tested_before_anything_is_saved(home, monkeypatch):
    def refuse(url):
        raise RuntimeError("('HYT00', '[HYT00] [Microsoft][ODBC Driver 18 for SQL Server]Login timeout expired (0)')")
    monkeypatch.setattr("broom365.installer._test", refuse)
    c = Client(create_setup_app(lambda: None), Response)
    form = {"storage": "mssql", "server": "sql01", "port": "1981", "database": "broom", "user": "svc", "db_password": "Sup3r-Secret!",
            "encryption": "trust", "key": "k" * 24, "admin_password": GOOD, "admin_password2": GOOD}
    r = c.post("/", data={**form, "csrf_token": token(c)})
    html = r.get_data(as_text=True)
    assert r.status_code == 400 and "did not answer in time" in html
    assert "Sup3r-Secret!" not in html and not bootstrap.path().exists()
    assert 'value="sql01"' in html                                          # what was typed (except passwords) is kept


def test_sql_server_settings_are_saved_with_the_password_encoded(home, monkeypatch):
    seen = {}
    monkeypatch.setattr("broom365.installer._test", lambda url: seen.setdefault("url", url))
    monkeypatch.setattr("broom365.installer._first_admin", lambda url, password: seen.setdefault("admin", password))
    c = Client(create_setup_app(lambda: seen.setdefault("started", True)), Response)
    form = {"storage": "mssql", "server": "sql01", "port": "", "database": "broom", "user": "svc", "db_password": "p#1/x?@y",
            "encryption": "off", "key": "k" * 24, "admin_password": GOOD, "admin_password2": GOOD}
    assert c.post("/", data={**form, "csrf_token": token(c)}).status_code == 302
    saved = bootstrap.load()
    assert saved["database_url"] == seen["url"] and "p%231%2Fx%3F%40y" in saved["database_url"] and saved["key"] == "k" * 24
    assert seen["started"] and seen["admin"] == GOOD
    assert "UID=svc;PWD={p#1/x?@y}" in odbc_connection_string(saved["database_url"])


@pytest.mark.parametrize("field,value,message", [("server", "", "SQL Server name"), ("port", "70000", "port"), ("database", "", "name of the database"),
                                                 ("user", "", "user name"), ("key", "short", "at least 16")])
def test_incomplete_sql_server_fields_are_explained(home, monkeypatch, field, value, message):
    monkeypatch.setattr("broom365.installer._test", lambda url: pytest.fail("must not connect with invalid fields"))
    c = Client(create_setup_app(lambda: None), Response)
    form = {"storage": "mssql", "server": "sql01", "port": "1433", "database": "broom", "user": "svc", "db_password": "x", "encryption": "trust",
            "key": "k" * 24, "admin_password": GOOD, "admin_password2": GOOD, field: value}
    r = c.post("/", data={**form, "csrf_token": token(c)})
    assert r.status_code == 400 and message in r.get_data(as_text=True)


def test_broken_saved_settings_open_the_installer_in_repair_mode_and_can_be_fixed(home, monkeypatch):
    bootstrap.save("mssql+pyodbc://u:SECRETPW@127.0.0.1:1/db", "saved-key-saved-key-1")
    import broom365.wsgi as wsgi
    real = wsgi.create_app
    calls = []

    def flaky(*a, **k):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("('HYT00', '[HYT00] Login timeout expired (0)')")
        return real(*a, **k)
    monkeypatch.setattr(wsgi, "create_app", flaky)
    c = Client(Switch(), Response)
    page = c.get("/").get_data(as_text=True)
    assert "does not work" in page and "did not answer in time" in page
    assert "SECRETPW" not in page and 'value="saved-key-saved-key-1"' in page      # the key is kept, the password never shown
    assert "Admin password" not in page                                         # accounts live in the database: nothing to choose
    r = c.post("/", data={"storage": "sqlite", "key": "saved-key-saved-key-1", "csrf_token": token(c)})
    assert r.status_code == 302
    assert bootstrap.load() == {"database_url": "", "key": "saved-key-saved-key-1"}
    assert "Username" in c.get("/login").get_data(as_text=True)


def test_the_installer_page_never_asks_twice_for_a_working_installation(home):
    c = Client(Switch(), Response)
    c.post("/", data={**SQLITE_FORM, "csrf_token": token(c)})
    assert "Install" not in c.get("/login").get_data(as_text=True)


# ------------------------------------------------------ the connect step ------
def test_connect_is_where_an_admin_lands_and_it_checks_the_permissions(admin, cfg):
    r = admin.get("/")
    assert r.status_code == 302 and r.headers["Location"].endswith("/connect")
    page = admin.get("/connect").get_data(as_text=True)
    assert "Connect to Microsoft 365" in page and "<h2>Permissions</h2>" not in page
    bad = admin.post("/connect", data={"tenant_id": "nope", "client_id": "x", "client_secret": "", "csrf_token": csrf(admin, "/connect")})
    assert bad.status_code == 400 and "Tenant ID must be" in bad.get_data(as_text=True)
    ok = admin.post("/connect", data={"tenant_id": "contoso.onmicrosoft.com", "client_id": "11111111-2222-3333-4444-555555555555",
                                      "client_secret": "the-secret", "csrf_token": csrf(admin, "/connect")})
    html = ok.get_data(as_text=True)
    assert ok.status_code == 200 and "All good" in html and "the-secret" not in html and 'href="/"' in html
    assert admin.get("/").status_code == 200                                       # connected: the dashboard opens


def test_connect_lists_what_is_missing_and_can_continue_when_only_optional_ones_are(admin, monkeypatch):
    few = [r for r in ROLES if r != "AuditLog.Read.All"]
    monkeypatch.setattr(AppOnlyTokens, "state", lambda self, force=False: AppAuthState(check_permissions(few, app_only=True), tuple(few), None, 0.0))
    connect(admin)
    html = admin.get("/connect").get_data(as_text=True)
    assert "AuditLog.Read.All" in html and "Grant admin consent" in html
    assert ("Continue with the signals that are available" in html) == (check_permissions(few, app_only=True).status == "degraded")


def test_connect_shows_the_token_error_without_leaking_the_secret(admin, monkeypatch):
    err = "invalid_client: AADSTS7000215: Invalid client secret provided."
    monkeypatch.setattr(AppOnlyTokens, "state", lambda self, force=False: AppAuthState(check_permissions([], app_only=True), (), err, 0.0))
    html = connect(admin).get_data(as_text=True)
    assert "could not get a token" not in html or "AADSTS7000215" in html
    page = admin.get("/connect").get_data(as_text=True)
    assert "AADSTS7000215" in page and "the-secret" not in page


def test_the_installer_key_encrypts_the_saved_client_secret(home):
    bootstrap.use_key("installer-key-installer-key")
    sealed = appconfig.seal("s3cret")
    assert sealed.startswith("enc:") and "s3cret" not in sealed and appconfig.unseal(sealed) == "s3cret"
    bootstrap.use_key("another-key-another-key-1")
    assert appconfig.unseal(sealed) is None


# ------------------------------------------------------- the Test button ------
MSSQL_FIELDS = {"storage": "mssql", "server": "sql01", "port": "1981", "database": "broom", "user": "svc", "db_password": "Sup3r-Secret!", "encryption": "trust"}


def test_the_test_button_reports_success_without_saving_anything(home, monkeypatch):
    monkeypatch.setattr("broom365.installer._test", lambda url: "database broom on SQL Server 16.0.1000")
    c = Client(create_setup_app(lambda: pytest.fail("testing must not start the application")), Response)
    r = c.post("/test", data=MSSQL_FIELDS, headers={"X-CSRF-Token": token(c)})
    assert r.get_json() == {"ok": True, "message": "The connection works: database broom on SQL Server 16.0.1000."}
    assert not bootstrap.path().exists() and not bootstrap.data_path().exists()


def test_the_test_button_explains_a_failure_and_never_echoes_the_password(home, monkeypatch):
    def refuse(url):
        raise RuntimeError("('28000', '[28000] Login failed for user svc (18456)')")
    monkeypatch.setattr("broom365.installer._test", refuse)
    c = Client(create_setup_app(lambda: None), Response)
    body = c.post("/test", data=MSSQL_FIELDS, headers={"X-CSRF-Token": token(c)}).get_data(as_text=True)
    assert '"ok":false' in body.replace(" ", "") and "refused the user name or password" in body and "Sup3r-Secret!" not in body


def test_the_test_button_checks_the_fields_first_and_needs_the_csrf_token(home, monkeypatch):
    monkeypatch.setattr("broom365.installer._test", lambda url: pytest.fail("incomplete settings must not be tried"))
    c = Client(create_setup_app(lambda: None), Response)
    r = c.post("/test", data={**MSSQL_FIELDS, "server": "", "database": ""}, headers={"X-CSRF-Token": token(c)})
    assert r.get_json()["ok"] is False and "SQL Server name" in r.get_json()["message"] and "name of the database" in r.get_json()["message"]
    assert c.post("/test", data=MSSQL_FIELDS).status_code == 400


def test_the_test_button_also_checks_that_the_sqlite_folder_can_be_written(home):
    c = Client(create_setup_app(lambda: None), Response)
    d = c.post("/test", data={"storage": "sqlite"}, headers={"X-CSRF-Token": token(c)}).get_json()
    assert d["ok"] is True and "can be written" in d["message"] and not bootstrap.path().exists()
    assert 'id="test"' in c.get("/").get_data(as_text=True)
