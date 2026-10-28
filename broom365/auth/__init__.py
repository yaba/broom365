"""Auth blueprint. Two modes, chosen with AUTH_MODE:

app (default)  App-only (client credentials). No Microsoft sign-in and no consent prompt: the app
               gets its own Graph token using the client secret and uses the *application*
               permissions already granted to the registration. The web UI itself is protected by
               Broom365 accounts (username + password, roles admin and reader) kept in the database.
delegated      Interactive MSAL authorization-code flow with delegated permissions; reads what the
               signed-in user can read. The token cache lives in the server-side Flask session.

Production needs a proper shared token cache (e.g. Redis or an encrypted table) for delegated mode.
"""
from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from functools import wraps
from typing import Any, Callable, TypeVar
from urllib.parse import urlencode

import msal
from flask import Blueprint, abort, current_app, flash, g, redirect, render_template, request, session, url_for
from werkzeug.wrappers import Response

from ..config import DEMO_PERMISSIONS, Config
from ..db import get_db
from ..runtime import credentials, effective_config
from ..services import accounts
from ..services.exchange import SCOPE as EXCHANGE_SCOPE, ExchangeClient
from ..services.permissions import PermissionReport, check_permissions, scopes_from_access_token

bp = Blueprint("auth", __name__)

F = TypeVar("F", bound=Callable[..., Any])
_CACHE_KEY = "token_cache"


def _cfg() -> Config:
    """The configuration in effect: environment defaults overridden by the connection saved in Settings."""
    return effective_config()


def is_app_mode() -> bool:
    return str(current_app.config["BROOM_CONFIG"].auth_mode) == "app"


def _build_app(cache: msal.SerializableTokenCache | None = None,
               cfg: Config | None = None) -> msal.ConfidentialClientApplication:
    cfg = cfg or _cfg()
    return msal.ConfidentialClientApplication(
        cfg.client_id, authority=cfg.authority, client_credential=cfg.client_secret, token_cache=cache)


# ------------------------------------------------------------- app-only mode --
@dataclass(frozen=True)
class AppAuthState:
    """Result of the permission preflight for the app's own token."""

    report: PermissionReport
    granted: tuple[str, ...]      # application permissions in the token's `roles` claim, original case
    error: str | None             # why no token could be obtained, if so
    checked_at: float


class AppOnlyTokens:
    """Client-credentials tokens for Graph, plus a short-lived cache of the permission preflight.

    Thread-safe: the same instance serves requests and the background sync thread.
    """

    SCOPE = ["https://graph.microsoft.com/.default"]
    TTL = 60.0

    def __init__(self, cfg: Config) -> None:
        self._cfg = cfg
        self._lock = threading.RLock()
        self._msal: msal.ConfidentialClientApplication | None = None  # built lazily: MSAL contacts Entra to validate the tenant
        self._state: AppAuthState | None = None

    def _acquire(self, scope: list[str] | None = None) -> dict[str, Any]:
        """Token result from MSAL; a tenant/authority that cannot be resolved becomes an error result, not an exception."""
        if not (self._cfg.tenant_id and self._cfg.client_id and self._cfg.client_secret):
            return {"error": "not_configured", "error_description": "The Entra app connection (tenant ID, client ID and client secret) "
                                                                   "is not configured yet. An admin can enter it in Settings."}
        try:
            if self._msal is None:
                self._msal = _build_app(None, self._cfg)
            return self._msal.acquire_token_for_client(scopes=scope or self.SCOPE)  # type: ignore[no-any-return]
        except ValueError as exc:
            return {"error": "authority_error", "error_description": str(exc)}

    def token(self) -> str | None:
        """A valid access token (MSAL reuses the cached one until it nears expiry), or None."""
        with self._lock:
            result = self._acquire()
        return str(result["access_token"]) if "access_token" in result else None

    def exchange_token(self) -> str | None:
        """A token for the Exchange Online admin API (needs Exchange.ManageAsApp), or None."""
        with self._lock:
            result = self._acquire([EXCHANGE_SCOPE])
        return str(result["access_token"]) if "access_token" in result else None

    def state(self, force: bool = False) -> AppAuthState:
        """Preflight from the token's granted application permissions; `force` bypasses every cache.

        The token is only read for the `roles` claim to report what was granted; it is not trusted
        for authorization, Microsoft Graph validates it on every call.
        """
        with self._lock:
            if force:
                self._msal = None  # rebuilt with an empty cache, so newly granted roles show up
                self._state = None
            if self._state and time.monotonic() - self._state.checked_at < self.TTL:
                return self._state
            result = self._acquire()
            if "access_token" in result:
                granted = scopes_from_access_token(result["access_token"])
                # The Exchange role lives in a token for a different API; it is optional, so a failure here is not an error.
                exchange = self._acquire([EXCHANGE_SCOPE])
                if "access_token" in exchange:
                    granted += scopes_from_access_token(exchange["access_token"])
                error = None
            else:
                granted = []
                error = f"{result.get('error', 'error')}: {result.get('error_description', 'no details')}"
            self._state = AppAuthState(check_permissions(granted, app_only=True), tuple(granted), error, time.monotonic())
            return self._state


def _tokens() -> AppOnlyTokens:
    """The token source for the connection in effect; replaced when the connection is changed in Settings."""
    ext = current_app.extensions
    c = credentials()
    key = (c.tenant_id, c.client_id, c.client_secret)
    if ext.get("broom_tokens_key") != key:
        ext["broom_tokens"], ext["broom_tokens_key"] = AppOnlyTokens(_cfg()), key
    return ext["broom_tokens"]  # type: ignore[no-any-return]


def current_account() -> accounts.Account | None:
    """The signed-in Broom365 account (a synthetic admin in demo mode), looked up once per request."""
    if current_app.config.get("DEMO"):
        return accounts.Account(0, "demo", "admin", False, True)
    if "account" not in g:
        uid = session.get("uid")
        g.account = accounts.get(get_db(), int(uid)) if uid else None
    return g.account  # type: ignore[no-any-return]


def _access_gate() -> Response | None:
    """App mode: require a signed-in account. Returns a response to send instead of the page, or None to proceed."""
    acc = current_account()
    if acc is None:
        return redirect(url_for("auth.login"))
    if acc.must_change_password and request.endpoint not in ("auth.change_password", "auth.logout"):
        return redirect(url_for("auth.change_password"))
    return None


# -------------------------------------------------- shared helpers for routes --
def graph_token_provider() -> Callable[[], str | None]:
    """Token getter for GraphClient that also works from the background sync thread."""
    if current_app.config.get("DEMO") or is_app_mode():
        return _tokens().token
    return token_provider_snapshot()


def exchange_client() -> Any:
    """Read-only Exchange Online client for the current mode (usable from the background sync thread), or None."""
    if current_app.config.get("DEMO"):
        from ..demo import DemoExchange
        return DemoExchange()
    if not is_app_mode():
        return None   # Exchange.ManageAsApp is an application role: delegated sign-in cannot use it
    return ExchangeClient(_tokens().exchange_token, _cfg().tenant_id)


def granted_scopes() -> list[str]:
    """Permissions currently granted to Broom365, for the sync job and the settings page."""
    if current_app.config.get("DEMO"):
        return list(DEMO_PERMISSIONS)
    if is_app_mode():
        return list(_tokens().state().granted)
    return list(session.get("granted_scopes", []))


def refresh_granted_scopes() -> tuple[list[str], str | None]:
    """Re-read the granted permissions, bypassing caches. Returns (permissions, token error or None).

    App mode gets a fresh token, so newly granted permissions show up. Delegated mode can only report what the
    current sign-in carries; picking up new consent needs a new sign-in.
    """
    if is_app_mode():
        state = _tokens().state(force=True)
        return list(state.granted), state.error
    return list(session.get("granted_scopes", [])), None


# ------------------------------------------------------------ delegated mode --
def _load_cache() -> msal.SerializableTokenCache:
    cache = msal.SerializableTokenCache()
    if blob := session.get(_CACHE_KEY):
        cache.deserialize(blob)
    return cache


def _save_cache(cache: msal.SerializableTokenCache) -> None:
    if cache.has_state_changed:
        session[_CACHE_KEY] = cache.serialize()


def token_provider_snapshot() -> Callable[[], str | None]:
    """Delegated mode: a token getter that works outside the request (e.g. a background sync thread).

    Copies the session's MSAL cache so the thread can keep refreshing silently on its own.
    """
    cfg = _cfg()
    cache = msal.SerializableTokenCache()
    if blob := session.get(_CACHE_KEY):
        cache.deserialize(blob)
    app = _build_app(cache, cfg)

    def provider() -> str | None:
        accounts = app.get_accounts()
        if not accounts:
            return None
        result = app.acquire_token_silent(list(cfg.scopes), account=accounts[0])
        return str(result["access_token"]) if result and "access_token" in result else None

    return provider


def login_required(view: F) -> F:
    """Gate a page: local/password access plus the permission preflight (app mode), or sign-in (delegated)."""

    @wraps(view)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        if current_app.config.get("DEMO"):
            return view(*args, **kwargs)
        if is_app_mode():
            if (gate := _access_gate()) is not None:
                return gate
            if not credentials().complete:
                acc = current_account()
                if acc is not None and acc.is_admin:
                    return redirect(url_for("connect.show"))
                abort(503, "Setup is not finished: an admin has to connect Broom365 to Microsoft 365 first.")
            status = _tokens().state().report.status
        else:
            if "user" not in session:
                return redirect(url_for("auth.login"))
            status = session.get("perm_status")
        if status == "blocked" or (status == "degraded" and not session.get("perm_ack")):
            return redirect(url_for("auth.permissions"))
        return view(*args, **kwargs)

    return wrapped  # type: ignore[return-value]


def account_required(view: F) -> F:
    """Gate a page that must stay reachable while the Entra connection is not working (Settings, Accounts): sign-in only."""

    @wraps(view)
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        if current_app.config.get("DEMO"):
            return view(*args, **kwargs)
        if is_app_mode():
            if (gate := _access_gate()) is not None:
                return gate
        elif "user" not in session:
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)

    return wrapped  # type: ignore[return-value]


def admin_required(view: F) -> F:
    """Like account_required, and the account must be an admin."""

    @wraps(view)
    @account_required
    def wrapped(*args: Any, **kwargs: Any) -> Any:
        acc = current_account()
        if is_app_mode() and not current_app.config.get("DEMO") and (acc is None or not acc.is_admin):
            abort(403, "Only an admin can do this.")
        return view(*args, **kwargs)

    return wrapped  # type: ignore[return-value]


@bp.route("/login", methods=["GET", "POST"])
def login() -> Response | tuple[str, int] | str:
    """App mode: Broom365 account sign-in. Delegated mode: start the Microsoft auth-code flow."""
    if is_app_mode():
        conn = get_db()
        accounts.ensure_admin(conn)
        if current_account() is not None:
            return redirect(url_for("dashboard.index"))
        if request.method == "POST":
            acc, error = accounts.authenticate(conn, request.form.get("username", ""), request.form.get("password", ""))
            if acc is not None:
                session.clear()  # new session on privilege change
                session["uid"] = acc.id
                return redirect(url_for("auth.change_password" if acc.must_change_password else "dashboard.index"))
            time.sleep(0.5)  # slow down guessing
            return render_template("login.html", error=error, first_run=_first_run(conn)), 401
        return render_template("login.html", error=None, first_run=_first_run(conn))
    flow = _build_app().initiate_auth_code_flow(list(_cfg().scopes), redirect_uri=_cfg().redirect_uri)
    session["auth_flow"] = flow
    return redirect(flow["auth_uri"])


def _first_run(conn: Any) -> bool:
    """True while the initial admin still has no password (the sign-in page then explains how to start)."""
    return bool(conn.execute("SELECT COUNT(*) FROM app_users WHERE password_hash IS NULL OR password_hash = ''").fetchone()[0])


@bp.route("/account/password", methods=["GET", "POST"])
@account_required
def change_password() -> Response | tuple[str, int] | str:
    """Change your own password. Required before anything else after the first sign-in or an admin reset."""
    acc = current_account()
    if acc is None or not is_app_mode() or current_app.config.get("DEMO"):
        return redirect(url_for("dashboard.index"))
    error = None
    if request.method == "POST":
        conn = get_db()
        new, again = request.form.get("new_password", ""), request.form.get("confirm_password", "")
        if acc.has_password and accounts.authenticate(conn, acc.username, request.form.get("current_password", ""))[0] is None:
            error = "The current password is wrong."
        elif new != again:
            error = "The two new passwords are different."
        elif error := accounts.validate_password(new, acc.username):
            pass
        else:
            accounts.set_password(conn, acc.id, new, must_change=False)
            flash("Password changed.")
            return redirect(url_for("dashboard.index"))
        return render_template("password.html", error=error, account=acc), 400
    return render_template("password.html", error=None, account=acc)


@bp.get("/auth/callback")
def callback() -> Response | tuple[str, int]:
    """Delegated mode: complete the auth-code flow and store the token cache + basic identity."""
    if is_app_mode():
        return redirect(url_for("dashboard.index"))
    flow = session.pop("auth_flow", None)
    if flow is None:
        return redirect(url_for("auth.login"))
    cache = _load_cache()
    result = _build_app(cache).acquire_token_by_auth_code_flow(flow, request.args.to_dict())
    if "error" in result:
        return (f"Sign-in failed: {result.get('error')}: {result.get('error_description')}\n\n"
                f"If this is a consent error, an admin can grant consent here: {_admin_consent_url(_cfg().scopes)}"), 400
    session["user"] = result.get("id_token_claims", {})
    report = check_permissions(_granted_scopes(result))
    session["granted_scopes"] = list(report.granted)
    session["perm_status"] = report.status
    session["perm_ack"] = False
    _save_cache(cache)
    if report.status != "ok":
        return redirect(url_for("auth.permissions"))
    return redirect(url_for("dashboard.index"))


@bp.get("/logout")
def logout() -> Response:
    """Clear the local session. (Does not sign out of Entra.)"""
    session.clear()
    return redirect(url_for("auth.login"))


def _granted_scopes(result: dict[str, Any]) -> list[str]:
    """Normalise the token response's `scope` (str or list, possibly Graph-URI prefixed)."""
    raw = result.get("scope") or []
    items = raw.split() if isinstance(raw, str) else list(raw)
    return [i.removeprefix("https://graph.microsoft.com/") for i in items]


def _admin_consent_url(scopes: tuple[str, ...] | list[str], app_only: bool = False) -> str:
    """Admin consent URL. App-only: grants what the registration lists; delegated: the given Graph scopes."""
    cfg = _cfg()
    if app_only:
        return f"https://login.microsoftonline.com/{cfg.tenant_id}/adminconsent?{urlencode({'client_id': cfg.client_id})}"
    query = urlencode({
        "client_id": cfg.client_id,
        "scope": " ".join(f"https://graph.microsoft.com/{s}" for s in scopes),
        "redirect_uri": cfg.redirect_uri,
    })
    return f"https://login.microsoftonline.com/{cfg.tenant_id}/v2.0/adminconsent?{query}"


@bp.get("/permissions")
def permissions() -> Response | str:
    """Preflight result: lists missing Graph permissions and how to fix them. `?recheck=1` re-reads them."""
    error: str | None = None
    if is_app_mode():
        if (gate := _access_gate()) is not None:
            return gate
        state = _tokens().state(force=bool(request.args.get("recheck")))
        report, error = state.report, state.error
    else:
        if "user" not in session:
            return redirect(url_for("auth.login"))
        report = check_permissions(session.get("granted_scopes", []))
    if report.status == "ok":
        return redirect(url_for("dashboard.index"))
    return render_template(
        "permissions.html", report=report, tenant_id=_cfg().tenant_id, client_id=_cfg().client_id,
        mode=_cfg().auth_mode, error=error,
        consent_url=_admin_consent_url(report.missing_scopes, app_only=is_app_mode()))


@bp.post("/permissions/continue")
def permissions_continue() -> Response:
    """Proceed in degraded mode. Refused when a required permission is missing."""
    if is_app_mode():
        if (gate := _access_gate()) is not None:
            return gate
        status = _tokens().state().report.status
    else:
        status = session.get("perm_status")
    if status == "degraded":
        session["perm_ack"] = True
        return redirect(url_for("dashboard.index"))
    return redirect(url_for("auth.permissions"))
