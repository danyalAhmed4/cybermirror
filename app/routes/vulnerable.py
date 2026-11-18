"""
Lab-only intentionally vulnerable SQL injection target.

Uses isolated SQLite (lab_vuln.db) with fake data only.
Must never connect to MySQL.
"""
from __future__ import annotations

import sqlite3

from flask import Blueprint, current_app, render_template, request

from app.lab_vuln_db import LAB_VULN_DB_PATH, ensure_lab_db
from app.monitoring.store import get_store

vulnerable_bp = Blueprint("vulnerable", __name__)


def _run_vulnerable_search(query: str):
    """
    Build SQL by joining strings on purpose so students can inject.

    Returns (rows, columns, error_message, sql_used).
    """
    # Intentionally vulnerable — do not "fix" this for the lab target.
    sql = (
        "SELECT id, name, category, price FROM products "
        f"WHERE name LIKE '%{query}%' OR category LIKE '%{query}%'"
    )

    ensure_lab_db(LAB_VULN_DB_PATH)
    conn = None
    try:
        # sqlite3 only — never mysql.connector
        conn = sqlite3.connect(LAB_VULN_DB_PATH)
        conn.row_factory = sqlite3.Row
        cur = conn.execute(sql)
        rows = cur.fetchall()
        columns = [desc[0] for desc in cur.description] if cur.description else []
        return rows, columns, None, sql
    except sqlite3.Error as exc:
        return [], [], str(exc), sql
    finally:
        if conn is not None:
            conn.close()


def _vulnerable_enabled() -> bool:
    default = bool(current_app.config.get("ENABLE_VULNERABLE_PAGE", False))
    return get_store().is_vulnerable_page_enabled(default=default)


@vulnerable_bp.route("/search", methods=["GET"])
def search():
    """GET /search?q=... — lab SQLi sink with fake SQLite data."""
    if not _vulnerable_enabled():
        return ("Vulnerable lab page is disabled.", 404)

    q = request.args.get("q", "")
    rows, columns, error, sql_used = ([], [], None, None)
    if q != "":
        rows, columns, error, sql_used = _run_vulnerable_search(q)

    return render_template(
        "search.html",
        q=q,
        rows=rows,
        columns=columns,
        error=error,
        sql_used=sql_used,
    )
