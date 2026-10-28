"""Database connections: SQLite (development, tests) or Microsoft SQL Server (production, `DATABASE_URL`).

The application is written against the sqlite3 API and SQLite's SQL. For SQL Server this module wraps a pyodbc connection in an object
with the same surface (`execute`, `executemany`, `executescript`, `commit`, rows readable by name or position) and translates the few
SQLite-only constructs the code uses: `INSERT OR IGNORE/REPLACE`, `ON CONFLICT ... DO UPDATE` (-> MERGE), `LIMIT`, `COLLATE NOCASE`,
`substr`, `PRAGMA`, `CREATE TABLE IF NOT EXISTS` and the column types of schema.sql. The translation is textual and pure, so it is unit tested
without a server.

DATABASE_URL examples:
  sqlite:///instance/broom365.sqlite
  mssql+pyodbc://user:password@host:1433/broom365?driver=ODBC+Driver+18+for+SQL+Server&TrustServerCertificate=yes
  mssql+pyodbc:///?odbc_connect=DRIVER%3D%7BODBC+Driver+18+for+SQL+Server%7D%3BSERVER%3D...
"""
from __future__ import annotations

import re
import sqlite3
from typing import Any, Iterable, Iterator, Sequence
from urllib.parse import parse_qsl, unquote, urlsplit

# --------------------------------------------------------------------- URL ---


def is_mssql(url: str | None) -> bool:
    return bool(url) and url.lower().startswith(("mssql", "sqlserver"))  # type: ignore[union-attr]


def sqlite_path(url: str) -> str:
    """`sqlite:///relative.db` -> relative.db, `sqlite:////abs/path.db` -> /abs/path.db, a bare path is returned unchanged."""
    if url.lower().startswith("sqlite:///"):
        return url[len("sqlite:///"):]
    return url


_ENCRYPTION_OPTION = re.compile(r"(^|;)\s*(encrypt|trustservercertificate|dsn|filedsn)\s*=", re.I)


def _default_trust(connection_string: str) -> str:
    """Driver 18 encrypts by default and rejects a self-signed server certificate. Unless the connection string already says how to
    treat encryption (`Encrypt` or `TrustServerCertificate`) or points to a data source (`DSN`, which carries its own settings),
    keep the connection encrypted but accept the server's certificate, so no certificate has to be configured.
    Write `Encrypt=yes;TrustServerCertificate=no` to require a trusted certificate, or `Encrypt=no` to turn encryption off."""
    if _ENCRYPTION_OPTION.search(connection_string):
        return connection_string
    return connection_string.rstrip(";") + ";TrustServerCertificate=yes"


def _braced(value: str) -> str:
    """An ODBC value that contains `;` (or a stray brace) must be wrapped in braces, with `}` doubled; an already braced value is kept."""
    if value.startswith("{") and value.endswith("}"):
        return value
    return "{" + value.replace("}", "}}") + "}" if any(c in value for c in ";{}") else value


_URL_TAIL = re.compile(r"([^/?#]*)(/[^?#]*)?(\?.*)?$", re.S)


def odbc_connection_string(url: str) -> str:
    """Turn a SQLAlchemy-style `mssql+pyodbc://` URL into an ODBC connection string. Any ODBC option can be given:

    * `mssql+pyodbc://user:password@host[:port][/database][?Option=value&...]`: every query option is passed through as written
      (`driver=...` picks the driver, `Encrypt`, `TrustServerCertificate`, `ApplicationIntent`, `MultiSubnetFailover`, `Authentication`,
      `Trusted_Connection`...); an option with the name of a generated part (`Server`, `Database`, `UID`, `PWD`) replaces it. The host may be
      `host\\instance` (written `host%5Cinstance`), and the user and password are optional (`Trusted_Connection=yes`, `Authentication=...`).
    * `mssql+pyodbc:///?odbc_connect=<a complete ODBC connection string>`: used as is.

    The credentials end at the LAST `@`, so a password may contain `@`, `/`, `?`, `#` or `:` even when it is not percent-encoded
    (percent-encoded characters are decoded). Errors never repeat any part of the URL, because it holds the password.
    """
    scheme, sep, rest = url.partition("://")
    if not sep:
        raise ValueError("DATABASE_URL must look like mssql+pyodbc://user:password@host:1433/database?driver=...")
    raw_query = rest.partition("?")[2] if "odbc_connect=" in rest.lower() else ""
    for key, value in parse_qsl(raw_query, keep_blank_values=True):
        if key.lower() == "odbc_connect":
            return _default_trust(value)
    userinfo, at, tail = rest.rpartition("@")
    if not at:
        userinfo, tail = "", rest
    m = _URL_TAIL.match(tail)
    hostport, path, query_text = (m.group(1), m.group(2) or "", (m.group(3) or "")[1:]) if m else ("", "", "")
    host, colon, port = hostport.rpartition(":")
    if not colon or "]" in port:
        host, port = hostport, ""
    elif not port.isdigit():
        raise ValueError("DATABASE_URL has a port that is not a number (check the host part; a password with special characters "
                         "such as # / ? @ : % is fine, but a literal % must be written %25)")
    host = unquote(host) or "localhost"
    parts: dict[str, str] = {"DRIVER": "{ODBC Driver 18 for SQL Server}", "SERVER": f"{host},{port}" if port else host}
    if path.strip("/"):
        parts["DATABASE"] = _braced(unquote(path.strip("/")))
    if at:
        user, _, password = userinfo.partition(":")
        parts["UID"] = _braced(unquote(user))
        parts["PWD"] = "{" + unquote(password).replace("}", "}}") + "}"        # braces keep ; and = in a password safe
    shown = {k: k for k in parts}                  # option name as it is written in the result: generated ones in capitals, the rest as given
    for key, value in parse_qsl(query_text, keep_blank_values=True):
        name = key.upper()
        shown.setdefault(name, key)
        parts[name] = "{" + value + "}" if name == "DRIVER" and not value.startswith("{") else _braced(value)
    return _default_trust(";".join(f"{shown[k]}={v}" for k, v in parts.items()))


# --------------------------------------------------------------- DDL --------
_KEY_WIDTH = {"scope": 128, "rule_name": 128, "signal": 128, "name": 128, "username": 128, "trustee": 256}
_INDEXED_DISPLAY_NAME = 450
# Identifiers come from Microsoft: GUIDs (36), but also longer ones (a directory role assignment id is over 64 characters). A key may not exceed
# 450 characters in all (900 bytes), and the widest key below (ids of 128 plus short words) stays within it.
_ID_WIDTH = 128


def _is_id(column: str) -> bool:
    return column == "id" or column.endswith("_id")


def _strip_comments(sql: str) -> str:
    return re.sub(r"--[^\n]*", "", sql)


def _split_top(text: str, sep: str = ",") -> list[str]:
    """Split on `sep` outside parentheses and quotes."""
    parts, depth, cur, quote = [], 0, [], None
    for ch in text:
        if quote:
            cur.append(ch)
            quote = None if ch == quote else quote
        elif ch in "'\"":
            quote = ch
            cur.append(ch)
        elif ch == "(":
            depth += 1
            cur.append(ch)
        elif ch == ")":
            depth -= 1
            cur.append(ch)
        elif ch == sep and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if "".join(cur).strip():
        parts.append("".join(cur).strip())
    return parts


def _names(cols: str) -> list[str]:
    return [c.strip().split()[0].strip('"[]') for c in cols.split(",") if c.strip()]


class Schema:
    """What the translator needs to know about the tables: their primary keys."""

    def __init__(self) -> None:
        self.pk: dict[str, list[str]] = {}
        self.identity: set[str] = set()  # tables with an auto-increment id (lastrowid is available for them)
        self.statements: list[str] = []
        self.tables: list[str] = []      # in creation order: a table is created after the ones it references


def translate_schema(sql: str) -> Schema:
    """SQLite schema.sql -> T-SQL statements, plus the primary key of every table."""
    out = Schema()
    stmts = [s.strip() for s in _strip_comments(sql).split(";") if s.strip()]
    stmts = [s for s in stmts if not s.upper().startswith("PRAGMA")]
    tables: dict[str, dict[str, Any]] = {}
    indexes: list[tuple[str, str, list[str]]] = []
    for s in stmts:
        m = re.match(r"CREATE TABLE IF NOT EXISTS (\w+)\s*\((.*)\)\s*$", s, re.S | re.I)
        if m:
            name, body = m.group(1), m.group(2)
            items = _split_top(body)
            pks: list[str] = []
            bounded: set[str] = set()
            for it in items:
                up = it.upper()
                if up.startswith("PRIMARY KEY"):
                    pks = _names(re.search(r"\((.*)\)", it, re.S).group(1))  # type: ignore[union-attr]
                elif up.startswith("FOREIGN KEY"):
                    bounded.update(_names(re.search(r"\((.*?)\)", it, re.S).group(1)))  # type: ignore[union-attr]
                elif up.startswith(("UNIQUE", "CHECK", "CONSTRAINT")):
                    pass
                else:
                    col = it.split()[0]
                    if "PRIMARY KEY" in up and "AUTOINCREMENT" not in up:
                        pks = [col]
                    if "REFERENCES" in up or " UNIQUE" in up:
                        bounded.add(col)
            if any("AUTOINCREMENT" in i.upper() for i in items):
                out.identity.add(name)
            tables[name] = {"items": items, "pk": pks, "bounded": bounded | set(pks)}
            out.pk[name] = pks
            continue
        m = re.match(r"CREATE INDEX IF NOT EXISTS (\w+) ON (\w+)\s*\((.*)\)", s, re.S | re.I)
        if m:
            cols = _names(re.sub(r"COLLATE NOCASE", "", m.group(3), flags=re.I))
            indexes.append((m.group(1), m.group(2), cols))
            tables[m.group(2)]["bounded"].update(cols)
            continue
        raise ValueError(f"unsupported statement in schema: {s[:60]!r}")

    def column(table: str, item: str) -> str:
        toks = item.split(None, 2)
        name, typ = toks[0], toks[1].upper() if len(toks) > 1 else ""
        rest = toks[2] if len(toks) > 2 else ""
        if typ == "INTEGER":
            if "AUTOINCREMENT" in rest.upper():
                return f"[{name}] INT IDENTITY(1,1) PRIMARY KEY"
            typ = "INT"
        elif typ == "TEXT":
            if name in tables[table]["bounded"]:
                width = _KEY_WIDTH.get(name, _INDEXED_DISPLAY_NAME if name == "display_name" else _ID_WIDTH if _is_id(name) else 64)
                typ = f"NVARCHAR({width})"
            else:
                typ = "NVARCHAR(MAX)"
        rest = re.sub(r"\bCOLLATE NOCASE\b", "", rest, flags=re.I)
        rest = re.sub(r"REFERENCES (\w+)\((\w+)\)", r"REFERENCES [\1]([\2])", rest)
        return f"[{name}] {typ} {rest}".strip()

    for name, t in tables.items():
        cols = []
        for it in t["items"]:
            up = it.upper()
            if up.startswith("PRIMARY KEY"):
                cols.append("PRIMARY KEY (" + ", ".join(f"[{c}]" for c in t["pk"]) + ")")
            elif up.startswith("FOREIGN KEY"):
                m = re.match(r"FOREIGN KEY\s*\((.*?)\)\s*REFERENCES\s+(\w+)\s*\((.*?)\)(.*)", it, re.S | re.I)
                fk, ref, rc, tail = m.groups()  # type: ignore[union-attr]
                cols.append(f"FOREIGN KEY ({', '.join(f'[{c}]' for c in _names(fk))}) REFERENCES [{ref}] "
                            f"({', '.join(f'[{c}]' for c in _names(rc))}){tail}")
            elif up.startswith(("UNIQUE", "CHECK", "CONSTRAINT")):
                cols.append(it)
            else:
                cols.append(column(name, it))
        # "already exists" (2714) is expected on every start after the first: it is caught instead of looked up in the catalog views, because a
        # hardened server may deny them to the database user. Any other error is raised.
        out.statements.append(f"BEGIN TRY CREATE TABLE [{name}] (\n  " + ",\n  ".join(cols)
                              + "\n) END TRY BEGIN CATCH IF ERROR_NUMBER() <> 2714 THROW; END CATCH")
        out.tables.append(name)
    for ix, table, cols in indexes:
        out.statements.append(f"BEGIN TRY CREATE INDEX [{ix}] ON [{table}] ({', '.join(f'[{c}]' for c in cols)}) END TRY "
                              "BEGIN CATCH IF ERROR_NUMBER() <> 1913 THROW; END CATCH")     # 1913: the index already exists
    return out


# ------------------------------------------------------------------ DML -----
_INSERT = re.compile(
    r"^\s*INSERT(?:\s+OR\s+(IGNORE|REPLACE))?\s+INTO\s+(\w+)\s*\(([^)]*)\)\s*VALUES\s*\((.*?)\)\s*"
    r"(?:ON\s+CONFLICT\s*\(([^)]*)\)\s*DO\s+(NOTHING|UPDATE\s+SET\s+(.*?)))?\s*;?\s*$", re.S | re.I)


def _merge(table: str, cols: list[str], values: list[str], keys: list[str], update: list[str] | None) -> str:
    using = ", ".join(f"{v} AS [{c}]" for c, v in zip(cols, values))
    on = " AND ".join(f"tgt.[{k}] = src.[{k}]" for k in keys)
    sql = f"MERGE INTO [{table}] WITH (HOLDLOCK) AS tgt USING (SELECT {using}) AS src ON {on}"
    if update:
        sql += " WHEN MATCHED THEN UPDATE SET " + ", ".join(f"tgt.[{c}] = src.[{c}]" for c in update)
    sql += f" WHEN NOT MATCHED THEN INSERT ({', '.join(f'[{c}]' for c in cols)}) VALUES ({', '.join(f'src.[{c}]' for c in cols)});"
    return sql


def translate_sql(sql: str, pk: dict[str, list[str]]) -> str:
    """One SQLite statement -> T-SQL (see module docstring)."""
    m = _INSERT.match(sql)
    if m and (m.group(1) or m.group(5)):
        mode, table, cols, vals, conflict, action, sets = m.groups()
        cols_l, vals_l = _names(cols), _split_top(vals)
        if len(cols_l) != len(vals_l):
            raise ValueError(f"column/value count mismatch in {sql[:80]!r}")
        if conflict:
            keys = _names(conflict)
            if action.upper() == "NOTHING":
                update = None
            else:
                update = [c for c in (p.split("=")[0].strip() for p in _split_top(sets)) if c not in keys]
        else:
            keys = pk[table]
            update = None if mode.upper() == "IGNORE" else [c for c in cols_l if c not in keys]
        return _merge(table, cols_l, vals_l, keys, update)
    s = re.sub(r"\s+COLLATE\s+NOCASE", "", sql, flags=re.I)
    s = re.sub(r"\bsubstr\(", "SUBSTRING(", s, flags=re.I)
    s = re.sub(r"\s+LIMIT\s+(\?|\d+)(?=\s*(?:\)|;|$))",
               lambda lm: ("" if re.search(r"\bORDER\s+BY\b", s, re.I) else " ORDER BY (SELECT NULL)") + f" OFFSET 0 ROWS FETCH NEXT {lm.group(1)} ROWS ONLY", s,
               flags=re.I)
    return s


# -------------------------------------------------------------- rows --------
class Row(tuple):  # type: ignore[type-arg]
    """A result row readable by position or column name, like sqlite3.Row."""

    _names: tuple[str, ...] = ()

    def __new__(cls, names: Sequence[str], values: Iterable[Any]) -> "Row":
        row = super().__new__(cls, values)
        row._names = tuple(names)
        return row

    def __getitem__(self, key: Any) -> Any:
        if isinstance(key, str):
            try:
                return super().__getitem__(self._names.index(key))
            except ValueError:
                for i, n in enumerate(self._names):  # column names are case-insensitive in SQL Server
                    if n.lower() == key.lower():
                        return super().__getitem__(i)
                raise IndexError(f"No item with that key: {key!r}") from None
        return super().__getitem__(key)

    def keys(self) -> list[str]:
        return list(self._names)


class Cursor:
    """Fully fetched result set: several can be open at once on one connection, as with sqlite3."""

    def __init__(self, rows: list[Row], rowcount: int = -1, lastrowid: int | None = None) -> None:
        self._rows, self._i = rows, 0
        self.rowcount, self.lastrowid = rowcount, lastrowid

    def fetchone(self) -> Row | None:
        if self._i >= len(self._rows):
            return None
        self._i += 1
        return self._rows[self._i - 1]

    def fetchall(self) -> list[Row]:
        rest, self._i = self._rows[self._i:], len(self._rows)
        return rest

    def __iter__(self) -> Iterator[Row]:
        return iter(self.fetchall())


class MssqlConnection:
    """pyodbc connection with the sqlite3 surface the application uses."""

    row_factory: Any = None  # accepted and ignored: rows always support names

    def __init__(self, odbc: str, schema: Schema | None = None) -> None:
        import pyodbc
        self._c = pyodbc.connect(odbc, autocommit=False)
        self._schema = schema or translate_schema(_schema_text())

    def execute(self, sql: str, params: Sequence[Any] = ()) -> Cursor:
        if sql.lstrip().upper().startswith("PRAGMA"):
            return Cursor([])
        t = translate_sql(sql, self._schema.pk)
        cur = self._c.cursor()
        cur.execute(t, tuple(params))
        if cur.description:
            names = [d[0] for d in cur.description]
            return Cursor([Row(names, r) for r in cur.fetchall()])
        rowcount, last = cur.rowcount, None
        into = re.match(r"\s*INSERT\s+INTO\s+\[?(\w+)", t, re.I)
        if into and into.group(1) in self._schema.identity:
            cur.execute("SELECT @@IDENTITY")
            v = cur.fetchone()
            last = int(v[0]) if v and v[0] is not None else None
        return Cursor([], rowcount, last)

    def executemany(self, sql: str, rows: Iterable[Sequence[Any]]) -> Cursor:
        data = [tuple(r) for r in rows]
        if not data:
            return Cursor([], 0)
        t = translate_sql(sql, self._schema.pk)
        cur = self._c.cursor()
        try:
            cur.fast_executemany = True  # one round trip per batch instead of one per row
            cur.executemany(t, data)
        except Exception:  # pyodbc cannot always infer NULL/long-text parameter types in bulk: fall back to row by row
            cur = self._c.cursor()
            for r in data:
                cur.execute(t, r)
        return Cursor([], len(data))

    def executescript(self, script: str) -> None:
        self._ddl(translate_schema(script).statements)

    def _ddl(self, statements: Iterable[str]) -> None:
        """Run DDL one statement at a time, each in its own transaction: an "already exists" error that the statement catches would otherwise
        leave an open transaction uncommittable."""
        self._c.commit()
        self._c.autocommit = True
        try:
            for stmt in statements:
                self._c.execute(stmt)
        finally:
            self._c.autocommit = False

    def commit(self) -> None:
        self._c.commit()

    def rollback(self) -> None:
        self._c.rollback()

    def close(self) -> None:
        self._c.close()

    def drop_all(self, keep: Sequence[str] = ()) -> None:
        """Drop every table of the schema except those in `keep` (children before the tables they reference, no catalog views needed)."""
        self._ddl(f"BEGIN TRY DROP TABLE [{name}] END TRY BEGIN CATCH IF ERROR_NUMBER() <> 3701 THROW; END CATCH"     # 3701: it does not exist
                  for name in reversed(self._schema.tables) if name not in keep)


def _schema_text() -> str:
    from pathlib import Path
    return (Path(__file__).parent / "models" / "schema.sql").read_text(encoding="utf-8")


# ----------------------------------------------------------------- open -----
Connection = sqlite3.Connection | MssqlConnection


def open_connection(url: str | None, sqlite_file: str) -> Any:
    """A new connection: SQL Server when `url` is an mssql URL, otherwise the SQLite file (or `sqlite:///` URL)."""
    if is_mssql(url):
        return MssqlConnection(odbc_connection_string(url))  # type: ignore[arg-type]
    conn = sqlite3.connect(sqlite_path(url) if url else sqlite_file)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn
