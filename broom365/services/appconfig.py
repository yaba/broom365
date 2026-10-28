"""The Entra app connection and the session key, stored in the database (table app_config) and edited in Settings.

The client secret is encrypted with the key from the installer (bootstrap.json) or `BROOM_KEY` (environment variable) when one is set; without it the secret is stored as plain text and
the Settings page says so. Environment variables TENANT_ID, CLIENT_ID and CLIENT_SECRET still work as a fallback for development.
"""
from __future__ import annotations

import base64
import hashlib
import os
import re
import secrets
from dataclasses import dataclass
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from .. import bootstrap

_ENC, _PLAIN = "enc:", "plain:"
TENANT, CLIENT, SECRET = "azure_tenant_id", "azure_client_id", "azure_client_secret"


def _fernet() -> Fernet | None:
    key = bootstrap.encryption_key()
    if not key:
        return None
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(key.encode()).digest()))


def encryption_enabled() -> bool:
    return _fernet() is not None


def seal(value: str) -> str:
    """Encrypt a value for storage (plain text with a marker when no BROOM_KEY is set)."""
    f = _fernet()
    return _ENC + f.encrypt(value.encode()).decode() if f else _PLAIN + value


def unseal(stored: str) -> str | None:
    """The original value, or None when it is encrypted and BROOM_KEY is missing or different."""
    if stored.startswith(_PLAIN):
        return stored[len(_PLAIN):]
    if stored.startswith(_ENC):
        f = _fernet()
        try:
            return f.decrypt(stored[len(_ENC):].encode()).decode() if f else None
        except InvalidToken:
            return None
    return stored


def get(conn: Any, name: str) -> str | None:
    r = conn.execute("SELECT value FROM app_config WHERE name = ?", (name,)).fetchone()
    return None if r is None else str(r["value"])


def put(conn: Any, name: str, value: str) -> None:
    conn.execute("INSERT INTO app_config (name, value) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET value = excluded.value", (name, value))
    conn.commit()


@dataclass(frozen=True)
class Credentials:
    tenant_id: str = ""
    client_id: str = ""
    client_secret: str = ""
    secret_unreadable: bool = False   # a secret is stored but cannot be decrypted (BROOM_KEY missing or changed)

    @property
    def complete(self) -> bool:
        return bool(self.tenant_id and self.client_id and self.client_secret)


def load_credentials(conn: Any, env: Credentials | None = None) -> Credentials:
    """Credentials from the database, field by field, falling back to the environment ones."""
    env = env or Credentials()
    raw = get(conn, SECRET)
    secret, unreadable = env.client_secret, False
    if raw:
        opened = unseal(raw)
        secret, unreadable = (opened or ""), opened is None
    return Credentials(get(conn, TENANT) or env.tenant_id, get(conn, CLIENT) or env.client_id, secret, unreadable)


def save_credentials(conn: Any, tenant_id: str, client_id: str, client_secret: str | None) -> None:
    """Store the connection; a blank `client_secret` keeps the stored one."""
    put(conn, TENANT, tenant_id.strip())
    put(conn, CLIENT, client_id.strip())
    if client_secret:
        put(conn, SECRET, seal(client_secret.strip()))


_GUID = re.compile(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")
_DOMAIN = re.compile(r"^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


def validate_connection(tenant: str, client: str, secret: str, have_secret: bool) -> list[str]:
    """What is wrong with the values typed for the Entra connection (empty list = fine). A blank secret is fine when one is stored."""
    problems = []
    if not (_GUID.match(tenant) or _DOMAIN.match(tenant)):
        problems.append("Tenant ID must be a GUID or a domain such as contoso.onmicrosoft.com.")
    if not _GUID.match(client):
        problems.append("Client ID must be a GUID (Application (client) ID of the app registration).")
    if not secret and not have_secret:
        problems.append("Enter the client secret (its Value, not its ID).")
    return problems


def session_key(conn: Any) -> str:
    """The Flask signing key: SECRET_KEY from the environment if set, otherwise one generated once and kept in the database."""
    env = os.environ.get("SECRET_KEY", "").strip()
    if env:
        return env
    found = get(conn, "session_key")
    if found:
        return found
    conn.execute("INSERT OR IGNORE INTO app_config (name, value) VALUES ('session_key', ?)", (secrets.token_hex(32),))
    conn.commit()
    return get(conn, "session_key") or ""  # re-read: another worker may have inserted its own first
