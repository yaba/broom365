import sqlite3

from flask import Flask

from broom365.db import init_db


def test_database_from_an_older_version_gets_the_new_columns(tmp_path):
    path = tmp_path / "old.sqlite"
    c = sqlite3.connect(path)
    c.execute("CREATE TABLE groups (id TEXT PRIMARY KEY, display_name TEXT, inventoried_at TEXT NOT NULL)")
    c.execute("INSERT INTO groups VALUES ('g1', 'Old group', '2026-01-01')")
    c.commit()
    c.close()
    app = Flask(__name__)
    app.config["DATABASE_PATH"] = str(path)
    init_db(app)
    init_db(app)  # idempotent
    c = sqlite3.connect(path)
    cols = {r[1] for r in c.execute("PRAGMA table_info(groups)")}
    assert {"group_types", "parent_count"} <= cols
    assert c.execute("SELECT display_name FROM groups").fetchone()[0] == "Old group"
    assert c.execute("SELECT COUNT(*) FROM group_usages").fetchone()[0] == 0  # new tables exist too
