"""First-run configuration kept in a file next to the data (`instance/bootstrap.json`), so a container needs no environment variables.

It holds the two things that cannot live in the database itself: how to reach the database (`database_url`, empty = the SQLite file) and the
encryption key (`key`) that protects the Entra client secret stored there. The installer writes it; `DATABASE_URL` and `BROOM_KEY` in the
environment still win when they are set.
"""
from __future__ import annotations

import json
import os
import re
import secrets
from pathlib import Path
from urllib.parse import quote, urlencode

from dotenv import load_dotenv

MIN_KEY = 16
_runtime_key = ""


def data_path() -> Path:
    """The SQLite file location (also the folder that holds bootstrap.json and the sessions)."""
    return Path(os.environ.get("DATABASE_PATH", "instance/broom365.sqlite"))


def path() -> Path:
    return data_path().parent / "bootstrap.json"


def load() -> dict[str, str]:
    """The saved settings, or {} when there are none (or the file is unreadable)."""
    try:
        data = json.loads(path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return {k: str(v) for k, v in data.items() if k in ("database_url", "key")} if isinstance(data, dict) else {}


def save(database_url: str, key: str) -> None:
    """Write the file atomically, readable by the app's user only."""
    p = path()
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps({"database_url": database_url, "key": key}), encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass  # not supported on every file system
    os.replace(tmp, p)


def needs_setup() -> bool:
    """True when nothing says where the data lives yet: no DATABASE_URL, no saved settings and no existing SQLite file."""
    load_dotenv()
    if os.environ.get("DATABASE_URL", "").strip():
        return False
    return not (path().exists() or data_path().exists())


def use_key(key: str) -> None:
    """Make `key` the encryption key of this process when BROOM_KEY is not set in the environment."""
    global _runtime_key
    _runtime_key = key.strip()


def use_saved_key() -> None:
    use_key(load().get("key", ""))


def encryption_key() -> str:
    return os.environ.get("BROOM_KEY", "").strip() or _runtime_key


def new_key() -> str:
    return secrets.token_urlsafe(32)


ENCRYPTION_MODES = {
    "trust": "Encrypted; accept the server's certificate (no certificate needed)",
    "verify": "Encrypted; require a certificate the server trusts",
    "off": "Not encrypted",
}
_EXTRA_NEEDS_NO_USER = re.compile(r"(trusted_connection|authentication)\s*=", re.I)


def parse_extra(text: str) -> list[tuple[str, str]]:
    """`Option=value` pairs, one per line or separated by `;` or `&`."""
    pairs = []
    for item in re.split(r"[;&\n]", text):
        name, eq, value = item.strip().partition("=")
        if eq and name.strip():
            pairs.append((name.strip(), value.strip()))
    return pairs


def needs_user(extra: str) -> bool:
    """A user name is required unless the extra options bring their own authentication (Windows or Azure AD)."""
    return not _EXTRA_NEEDS_NO_USER.search(extra)


def build_database_url(server: str, port: str, database: str, user: str, password: str, encryption: str = "trust",
                       extra: str = "", driver: str = "ODBC Driver 18 for SQL Server") -> str:
    """A `mssql+pyodbc://` URL from the installer's fields; user, password and instance are percent-encoded."""
    auth = ""
    if user:
        auth = quote(user, safe="") + (":" + quote(password, safe="") if password else "") + "@"
    pairs: list[tuple[str, str]] = [("driver", driver)]
    if encryption == "verify":
        pairs += [("Encrypt", "yes"), ("TrustServerCertificate", "no")]
    elif encryption == "off":
        pairs.append(("Encrypt", "no"))
    pairs += parse_extra(extra)
    host = quote(server.strip(), safe="")
    return f"mssql+pyodbc://{auth}{host}{':' + port.strip() if port.strip() else ''}/{quote(database.strip(), safe='')}?{urlencode(pairs, quote_via=quote)}"


def explain_db_error(exc: BaseException) -> str:
    """A plain-language reason for a failed database connection. Never repeats the connection string (it holds the password)."""
    text = str(exc)
    low = text.lower()
    if "hyt00" in low or "timeout expired" in low or ("08001" in low and "network" in low):
        return ("The SQL Server did not answer in time. Check the server name and port, that the server accepts TCP/IP connections, and that nothing "
                "blocks the way (firewall). Inside a container the server name may not resolve: try its IP address.")
    if "certificate" in low:
        return ("The server's certificate was refused. Choose \"Encrypted; accept the server's certificate\" (or \"Not encrypted\") for the encryption.")
    if "4060" in low:
        return "The server is reachable, but that database does not exist or this user cannot open it. Create it first and give the user access."
    if "18456" in low or "28000" in low or "login failed" in low:
        return "The server refused the user name or password (or this user may not sign in with SQL Server authentication)."
    if "im002" in low or "data source name not found" in low or "can't open lib" in low:
        return "The Microsoft ODBC driver for SQL Server was not found on this machine."
    first = text.replace("\n", " ").strip()
    return (first[:300] + "...") if len(first) > 300 else first or type(exc).__name__
