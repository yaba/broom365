"""SQL Server support: URL parsing and the SQLite -> T-SQL translation (pure, no server needed), plus an opt-in integration test."""
import os
import re
from pathlib import Path

import pytest

from broom365.database import (Row, Cursor, is_mssql, odbc_connection_string, open_connection, sqlite_path, translate_schema,
                               translate_sql)

SCHEMA = (Path(__file__).parents[1] / "broom365" / "models" / "schema.sql").read_text(encoding="utf-8")
PK = translate_schema(SCHEMA).pk


def test_url_kinds():
    assert is_mssql("mssql+pyodbc://u:p@h/db") and not is_mssql("sqlite:///x.db") and not is_mssql("") and not is_mssql(None)
    assert sqlite_path("sqlite:///instance/x.db") == "instance/x.db" and sqlite_path("instance/x.db") == "instance/x.db"


def test_odbc_connection_string_from_a_url():
    s = odbc_connection_string("mssql+pyodbc://app:s3cr;et@db.local:1433/broom?driver=ODBC+Driver+18+for+SQL+Server&TrustServerCertificate=yes")
    assert s == "DRIVER={ODBC Driver 18 for SQL Server};SERVER=db.local,1433;DATABASE=broom;UID=app;PWD={s3cr;et};TrustServerCertificate=yes"


def test_odbc_connect_passthrough_and_url_encoded_password():
    assert odbc_connection_string("mssql+pyodbc:///?odbc_connect=DRIVER%3D%7BX%7D%3BSERVER%3Dh%3BEncrypt%3Dno") == "DRIVER={X};SERVER=h;Encrypt=no"
    assert "PWD={p@ss}" in odbc_connection_string("mssql+pyodbc://u:p%40ss@h/db")


def test_every_table_is_translated_with_bounded_key_columns():
    sc = translate_schema(SCHEMA)
    assert len(re.findall(r"CREATE TABLE", SCHEMA)) == sum("CREATE TABLE" in s for s in sc.statements)
    text = "\n".join(sc.statements)
    assert "AUTOINCREMENT" not in text and "COLLATE" not in text and "IF NOT EXISTS (SELECT 1 FROM sys.indexes" in text
    assert "[username] NVARCHAR(128) NOT NULL UNIQUE" in text   # a unique column cannot be NVARCHAR(MAX)
    assert "[id] INT IDENTITY(1,1) PRIMARY KEY" in text and sc.identity == {"sync_runs", "flags", "remediation_actions", "app_users"}
    # a key column can never be NVARCHAR(MAX): SQL Server cannot index it
    for table, cols in sc.pk.items():
        for c in cols:
            assert re.search(rf"\[{c}\] NVARCHAR\((?!MAX)\d+\)", next(s for s in sc.statements if f"CREATE TABLE [{table}]" in s)), (table, c)


def test_upsert_becomes_a_merge_that_updates_everything_but_the_key():
    sql = translate_sql("INSERT INTO settings (name, value) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET value = excluded.value", PK)
    assert sql.startswith("MERGE INTO [settings] WITH (HOLDLOCK)") and "SELECT ? AS [name], ? AS [value]" in sql
    assert "WHEN MATCHED THEN UPDATE SET tgt.[value] = src.[value]" in sql and "tgt.[name] = src.[name]" in sql and sql.endswith(";")


def test_insert_or_ignore_only_inserts_missing_rows_using_the_primary_key():
    sql = translate_sql("INSERT OR IGNORE INTO group_owners (group_id, owner_id, owner_type, display_name) VALUES (?,?,?,?)", PK)
    assert "MATCHED THEN UPDATE" not in sql.replace("NOT MATCHED", "") and "tgt.[group_id] = src.[group_id] AND tgt.[owner_id] = src.[owner_id]" in sql


def test_insert_or_replace_updates_the_non_key_columns():
    sql = translate_sql("INSERT OR REPLACE INTO sign_in_activity (object_id, object_type, last_sign_in_at) VALUES (?,?,?)", PK)
    assert "WHEN MATCHED THEN UPDATE SET tgt.[last_sign_in_at] = src.[last_sign_in_at]" in sql and "SET tgt.[object_id]" not in sql


def test_literals_in_values_are_kept():
    sql = translate_sql("INSERT OR IGNORE INTO users (id, display_name, user_principal_name, account_enabled, user_type) VALUES (?, ?, ?, 1, 'Member')", PK)
    assert "1 AS [account_enabled]" in sql and "'Member' AS [user_type]" in sql


def test_limit_collate_and_substr_are_translated():
    assert translate_sql("SELECT * FROM sync_runs ORDER BY id DESC LIMIT 1", PK) == "SELECT * FROM sync_runs ORDER BY id DESC OFFSET 0 ROWS FETCH NEXT 1 ROWS ONLY"
    assert translate_sql("DELETE FROM sync_runs WHERE id NOT IN (SELECT id FROM sync_runs ORDER BY id DESC LIMIT ?)", PK).endswith("FETCH NEXT ? ROWS ONLY)")
    assert translate_sql("SELECT * FROM groups ORDER BY display_name COLLATE NOCASE", PK) == "SELECT * FROM groups ORDER BY display_name"
    assert "SUBSTRING(end_at, 1, 19)" in translate_sql("SELECT substr(end_at, 1, 19) FROM app_credentials", PK)


def test_every_statement_in_the_code_base_translates():
    """No SQL string in the package may use a construct the translator cannot turn into a MERGE."""
    for f in (Path(__file__).parents[1] / "broom365").rglob("*.py"):
        for m in re.finditer(r'"(INSERT (?:OR \w+ )?INTO [^"]*)"((?:\s*"[^"]*")*)', f.read_text(encoding="utf-8")):
            text = m.group(1) + "".join(re.findall(r'"([^"]*)"', m.group(2)))
            if "{" in text:
                continue
            translate_sql(text, PK)


def test_row_reads_by_name_position_and_case_insensitively():
    r = Row(["Id", "name"], ["a", "b"])
    assert r["Id"] == "a" and r["id"] == "a" and r[1] == "b" and tuple(r) == ("a", "b") and dict(zip(r.keys(), r)) == {"Id": "a", "name": "b"}
    with pytest.raises(IndexError):
        r["nope"]


def test_cursor_behaves_like_a_sqlite_cursor():
    c = Cursor([Row(["x"], [1]), Row(["x"], [2])])
    assert c.fetchone()[0] == 1 and [r[0] for r in c] == [2] and c.fetchone() is None


@pytest.mark.skipif(not os.environ.get("BROOM_TEST_MSSQL_URL"), reason="set BROOM_TEST_MSSQL_URL to a scratch SQL Server database to run")
def test_demo_pipeline_gives_the_same_flags_on_sql_server_as_on_sqlite(tmp_path, monkeypatch):
    from broom365 import create_app
    url = os.environ["BROOM_TEST_MSSQL_URL"]
    c = open_connection(url, "")
    c.drop_all()
    c.close()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("BROOM_DEMO", "1")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    create_app()
    lite = open_connection("", str(tmp_path / "instance" / "demo.sqlite"))
    expected = sorted((r[0], r[1], r[2]) for r in lite.execute("SELECT object_type, object_id, flag FROM flags"))
    monkeypatch.setenv("DATABASE_URL", url)
    create_app()
    ms = open_connection(url, "")
    assert sorted((r[0], r[1], r[2]) for r in ms.execute("SELECT object_type, object_id, flag FROM flags")) == expected
    from broom365.db import reset_database
    reset_database(ms)
    assert ms.execute("SELECT COUNT(*) FROM groups").fetchone()[0] == 0


def test_a_password_with_url_special_characters_works_without_encoding():
    raw = odbc_connection_string("mssql+pyodbc://sa:VaSS0uRa#x/y?z:w@v@db.local:1433/broom?driver=ODBC+Driver+18+for+SQL+Server&TrustServerCertificate=yes")
    assert raw == ("DRIVER={ODBC Driver 18 for SQL Server};SERVER=db.local,1433;DATABASE=broom;UID=sa;PWD={VaSS0uRa#x/y?z:w@v};"
                   "TrustServerCertificate=yes")
    assert "PWD={a%b}" in odbc_connection_string("mssql+pyodbc://u:a%b@h/db")            # a stray % stays as typed
    assert "PWD={a%b}" in odbc_connection_string("mssql+pyodbc://u:a%25b@h/db")          # an encoded one is decoded
    assert odbc_connection_string("mssql+pyodbc://u:p@h").startswith("DRIVER={ODBC Driver 18 for SQL Server};SERVER=h;UID=u")
    assert "SERVER=db.local,1433;" in odbc_connection_string("mssql+pyodbc://u:p@db.local:1433/x")


def test_a_bad_url_error_never_repeats_the_password():
    for bad in ("mssql+pyodbc://sa:SECRETpw@host:notaport/db", "no-scheme-at-all-SECRETpw"):
        with pytest.raises(ValueError) as e:
            odbc_connection_string(bad)
        assert "SECRETpw" not in str(e.value)


def test_without_encryption_options_the_server_certificate_is_accepted_so_no_certificate_is_needed():
    assert odbc_connection_string("mssql+pyodbc://u:p@h:1433/db").endswith(";TrustServerCertificate=yes")
    assert odbc_connection_string("mssql+pyodbc:///?odbc_connect=DRIVER%3D%7BX%7D%3BSERVER%3Dh").endswith("SERVER=h;TrustServerCertificate=yes")
    assert odbc_connection_string("mssql+pyodbc:///?odbc_connect=DRIVER={X};SERVER=h;PWD=p;").endswith("PWD=p;TrustServerCertificate=yes")
    # an explicit choice is never overridden
    assert "TrustServerCertificate=no" in odbc_connection_string("mssql+pyodbc://u:p@h/db?Encrypt=yes&TrustServerCertificate=no")
    assert "Encrypt=no" in odbc_connection_string("mssql+pyodbc://u:p@h/db?Encrypt=no") and "TrustServerCertificate" not in odbc_connection_string("mssql+pyodbc://u:p@h/db?Encrypt=no")
    assert odbc_connection_string("mssql+pyodbc:///?odbc_connect=DRIVER={X};SERVER=h;encrypt=no").endswith("encrypt=no")


def test_any_odbc_option_can_be_given_and_overrides_the_generated_parts():
    s = odbc_connection_string("mssql+pyodbc://u:p@db.local:1433/broom?driver=ODBC+Driver+17+for+SQL+Server&Encrypt=yes&TrustServerCertificate=no"
                               "&ApplicationIntent=ReadOnly&MultiSubnetFailover=Yes&Connection+Timeout=15")
    assert s == ("DRIVER={ODBC Driver 17 for SQL Server};SERVER=db.local,1433;DATABASE=broom;UID=u;PWD={p};Encrypt=yes;"
                 "TrustServerCertificate=no;ApplicationIntent=ReadOnly;MultiSubnetFailover=Yes;Connection Timeout=15")
    assert odbc_connection_string("mssql+pyodbc://u:p@h/db?Driver=FreeTDS").startswith("DRIVER={FreeTDS};")
    assert "SERVER=other,1444" in odbc_connection_string("mssql+pyodbc://u:p@h/db?Server=other,1444")        # an option replaces a generated part


def test_instances_windows_authentication_and_azure_ad_need_no_user_or_password():
    s = odbc_connection_string("mssql+pyodbc://sqlhost%5CSQLEXPRESS/db?Trusted_Connection=yes")
    assert "SERVER=sqlhost\\SQLEXPRESS;" in s and "UID" not in s and "PWD" not in s and "Trusted_Connection=yes" in s
    s = odbc_connection_string("mssql+pyodbc://app%40tenant.com:pw@x.database.windows.net:1433/db?Authentication=ActiveDirectoryPassword&Encrypt=yes")
    assert "UID=app@tenant.com;PWD={pw};Authentication=ActiveDirectoryPassword;Encrypt=yes" in s and "TrustServerCertificate" not in s


def test_values_with_semicolons_are_braced_and_a_dsn_keeps_its_own_encryption_settings():
    assert "WSID={a;b}" in odbc_connection_string("mssql+pyodbc://u:p@h/db?WSID=a%3Bb")
    assert odbc_connection_string("mssql+pyodbc:///?odbc_connect=DSN=prod;UID=u;PWD=p") == "DSN=prod;UID=u;PWD=p"
    assert "TrustServerCertificate" not in odbc_connection_string("mssql+pyodbc:///?odbc_connect=DSN%3Dprod")
    raw = odbc_connection_string("mssql+pyodbc:///?odbc_connect=DRIVER={ODBC+Driver+18+for+SQL+Server};SERVER=h,1981;DATABASE=d;UID=u;PWD=p#1;Encrypt=no")
    assert raw == "DRIVER={ODBC Driver 18 for SQL Server};SERVER=h,1981;DATABASE=d;UID=u;PWD=p#1;Encrypt=no"      # '#' is not cut off
