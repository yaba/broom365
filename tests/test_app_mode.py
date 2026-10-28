import base64
import json
import re

import pytest

from broom365 import auth, create_app
from broom365.auth import AppAuthState, AppOnlyTokens
from broom365.config import Config, ConfigError
from broom365.services.permissions import check_permissions, scopes_from_access_token

ALL_ROLES = ["Group.Read.All", "Application.Read.All", "Directory.Read.All", "RoleManagement.Read.Directory",
             "AuditLog.Read.All", "Policy.Read.All", "DeviceManagementApps.Read.All", "DeviceManagementConfiguration.Read.All",
             "Exchange.ManageAsApp"]


def jwt(**claims) -> str:
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")  # noqa: E731
    return f"{enc({'alg': 'RS256'})}.{enc(claims)}.sig"


# ------------------------------------------------------------- pure helpers --
def test_scopes_from_access_token_reads_roles_and_scp():
    assert scopes_from_access_token(jwt(roles=["Group.Read.All"], scp="User.Read Mail.Read")) == [
        "Group.Read.All", "User.Read", "Mail.Read"]


@pytest.mark.parametrize("bad", ["", "abc", "a.b.c", "a.!!!.c"])
def test_scopes_from_access_token_tolerates_garbage(bad):
    assert scopes_from_access_token(bad) == []


def test_app_only_does_not_require_user_read():
    assert check_permissions(ALL_ROLES, app_only=True).status == "ok"
    assert check_permissions(ALL_ROLES).status == "blocked"  # delegated mode still needs User.Read


# ---------------------------------------------------------- AppOnlyTokens -----
class FakeMsal:
    def __init__(self, result, exchange=None):
        self.result, self.calls, self.exchange_calls = result, 0, 0
        self.exchange = exchange or {"error": "invalid_resource", "error_description": "no Exchange access"}

    def acquire_token_for_client(self, scopes):
        if "outlook.office365.com" in scopes[0]:
            self.exchange_calls += 1
            return self.exchange
        self.calls += 1
        return self.result


@pytest.fixture()
def cfg(tmp_path):
    return Config(tenant_id="t", client_id="c", client_secret="s", secret_key="k", database_path=tmp_path / "db.sqlite")


def tokens_with(monkeypatch, cfg, result, exchange=None):
    built = []
    monkeypatch.setattr(auth, "_build_app", lambda cache=None, cfg=None: built.append(FakeMsal(result, exchange)) or built[-1])
    return AppOnlyTokens(cfg), built


def test_state_ok_when_all_roles_granted(monkeypatch, cfg):
    t, _ = tokens_with(monkeypatch, cfg, {"access_token": jwt(roles=ALL_ROLES)})
    s = t.state()
    assert s.report.status == "ok" and s.error is None and set(s.granted) == set(ALL_ROLES)


def test_state_degraded_when_optional_missing(monkeypatch, cfg):
    t, _ = tokens_with(monkeypatch, cfg, {"access_token": jwt(roles=ALL_ROLES[:3])})
    s = t.state()
    assert s.report.status == "degraded" and "AuditLog.Read.All" in s.report.missing_scopes


def test_state_blocked_with_error_when_no_token(monkeypatch, cfg):
    t, _ = tokens_with(monkeypatch, cfg, {"error": "invalid_client", "error_description": "AADSTS7000215: bad secret"})
    s = t.state()
    assert s.report.status == "blocked" and "AADSTS7000215" in s.error and t.token() is None


def test_state_is_cached_and_force_rebuilds_the_msal_app(monkeypatch, cfg):
    t, built = tokens_with(monkeypatch, cfg, {"access_token": jwt(roles=ALL_ROLES)})
    t.state(); t.state()
    assert built[0].calls == 1  # cached within the TTL
    t.state(force=True)
    assert len(built) == 2 and built[1].calls == 1  # fresh app, so newly granted roles are seen


# ------------------------------------------------------------------- routes ---
def state_of(roles, error=None):
    return AppAuthState(check_permissions(roles, app_only=True), tuple(roles), error, 0.0)


def make_client(monkeypatch, cfg, roles=ALL_ROLES, error=None):
    monkeypatch.delenv("BROOM_DEMO", raising=False)
    monkeypatch.setattr(AppOnlyTokens, "state", lambda self, force=False: state_of(roles, error))
    monkeypatch.setattr(AppOnlyTokens, "token", lambda self: "fake-token")
    client = create_app(cfg).test_client()
    sign_in_admin(client)
    return client


PASSWORD = "correct horse battery"


def csrf(client, path="/login"):
    return re.search(r'name="csrf_token" value="([^"]+)"', client.get(path).get_data(as_text=True)).group(1)


def sign_in_admin(client):
    """The first start: sign in as admin with no password, then choose one."""
    client.post("/login", data={"username": "admin", "password": "", "csrf_token": csrf(client)})
    client.post("/account/password", data={"new_password": PASSWORD, "confirm_password": PASSWORD,
                                           "csrf_token": csrf(client, "/account/password")})


def test_signed_in_admin_needs_no_microsoft_login_or_consent(monkeypatch, cfg):
    r = make_client(monkeypatch, cfg).get("/")
    assert r.status_code == 200 and "No inventory yet" in r.get_data(as_text=True)
    assert "App-only" in r.get_data(as_text=True)


def test_blocked_permissions_redirect_to_fix_page(monkeypatch, cfg):
    c = make_client(monkeypatch, cfg, roles=["Group.Read.All"])
    assert c.get("/").headers["Location"].endswith("/permissions")
    html = c.get("/permissions").get_data(as_text=True)
    assert "cannot run" in html and "Application.Read.All" in html and "Application permissions" in html
    assert "Continue with reduced signals" not in html


def test_token_error_is_shown(monkeypatch, cfg):
    c = make_client(monkeypatch, cfg, roles=[], error="invalid_client: AADSTS7000215 bad secret")
    html = c.get("/permissions").get_data(as_text=True)
    assert "could not get a token" in html and "AADSTS7000215" in html


def test_degraded_can_continue(monkeypatch, cfg):
    c = make_client(monkeypatch, cfg, roles=ALL_ROLES[:4])
    assert c.get("/").headers["Location"].endswith("/permissions")
    html = c.get("/permissions").get_data(as_text=True)
    assert "Continue with reduced signals" in html
    tok = re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)
    assert c.post("/permissions/continue", data={"csrf_token": tok}).status_code == 302
    assert c.get("/").status_code == 200


def test_settings_page_describes_app_only_mode(monkeypatch, cfg):
    html = make_client(monkeypatch, cfg).get("/settings").get_data(as_text=True)
    assert "app-only, no user sign-in" in html and "The application itself" in html
    assert "<code>User.Read</code>" not in html and "Graph permission (application)" in html


def test_graph_token_provider_is_the_app_token(monkeypatch, cfg):
    app = make_client(monkeypatch, cfg).application
    with app.test_request_context("/"):
        assert auth.graph_token_provider()() == "fake-token"
        assert set(auth.granted_scopes()) == set(ALL_ROLES)


# -------------------------------------------------------------- Config.load ---
@pytest.fixture()
def env(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("broom365.config.load_dotenv", lambda *a, **k: False)  # never read a real .env in tests
    for k in ("AUTH_MODE", "REDIRECT_URI"):
        monkeypatch.delenv(k, raising=False)
    for k, v in {"TENANT_ID": "t", "CLIENT_ID": "c", "CLIENT_SECRET": "s", "SECRET_KEY": "k"}.items():
        monkeypatch.setenv(k, v)
    return monkeypatch


def test_config_app_mode_is_default_and_needs_no_redirect_uri(env):
    c = Config.from_env()
    assert c.auth_mode == "app" and c.redirect_uri == ""


def test_config_delegated_requires_redirect_uri(env):
    env.setenv("AUTH_MODE", "delegated")
    with pytest.raises(ConfigError, match="REDIRECT_URI"):
        Config.from_env()
    env.setenv("REDIRECT_URI", "http://localhost:5000/auth/callback")
    assert Config.from_env().auth_mode == "delegated"


def test_config_rejects_unknown_mode(env):
    env.setenv("AUTH_MODE", "magic")
    with pytest.raises(ConfigError, match="AUTH_MODE"):
        Config.from_env()


def test_unresolvable_tenant_becomes_a_blocked_state_not_a_crash(monkeypatch, cfg):
    def boom(cache=None, cfg=None):
        raise ValueError("Unable to get authority configuration for https://login.microsoftonline.com/t")

    monkeypatch.setattr(auth, "_build_app", boom)
    t = AppOnlyTokens(cfg)
    s = t.state()
    assert s.report.status == "blocked" and "authority" in s.error and t.token() is None


# ------------------------------------------------------------- Exchange token ---
def test_exchange_role_lives_in_a_different_token_and_is_added_to_the_granted_list(monkeypatch, cfg):
    t, built = tokens_with(monkeypatch, cfg, {"access_token": jwt(roles=ALL_ROLES[:-1])},
                           exchange={"access_token": jwt(roles=["Exchange.ManageAsApp"])})
    s = t.state()
    assert "Exchange.ManageAsApp" in s.granted and s.report.status == "ok" and built[0].exchange_calls == 1


def test_without_the_exchange_role_everything_else_still_works_and_it_is_reported_missing(monkeypatch, cfg):
    t, _ = tokens_with(monkeypatch, cfg, {"access_token": jwt(roles=ALL_ROLES[:-1])})
    s = t.state()
    assert s.error is None and s.report.status == "degraded" and [r.scope for r in s.report.missing_optional] == ["Exchange.ManageAsApp"]


def test_exchange_token_is_its_own_request_and_none_when_unavailable(monkeypatch, cfg):
    t, built = tokens_with(monkeypatch, cfg, {"access_token": jwt(roles=ALL_ROLES)}, exchange={"access_token": "exchange-token"})
    assert t.exchange_token() == "exchange-token" and built[0].calls == 0 and built[0].exchange_calls == 1
    t2, _ = tokens_with(monkeypatch, cfg, {"access_token": jwt(roles=ALL_ROLES)})
    assert t2.exchange_token() is None


def test_exchange_requirement_does_not_apply_to_delegated_sign_in():
    assert check_permissions(["User.Read", "Group.Read.All", "Application.Read.All", "Directory.Read.All", "RoleManagement.Read.Directory",
                              "AuditLog.Read.All", "Policy.Read.All", "DeviceManagementApps.Read.All",
                              "DeviceManagementConfiguration.Read.All"]).status == "ok"
    assert "Exchange.ManageAsApp" in [r.scope for r in check_permissions(ALL_ROLES[:-1], app_only=True).missing_optional]
