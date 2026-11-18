"""
Isolated SQLite lab database for the intentional SQLi target page.

This module must never import or call MySQL code.
Fake demo data only — not real credentials or production records.
"""
from __future__ import annotations

import os
import sqlite3
from typing import Optional

_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LAB_VULN_DB_PATH = os.path.join(_PROJECT_ROOT, "lab_vuln.db")

# Made-up lab identities only
FAKE_USERS = [
    (1, "lab_alice", "alice.lab@example.com", "user"),
    (2, "lab_bob", "bob.lab@example.com", "user"),
    (3, "lab_carol", "carol.lab@example.com", "analyst"),
    (4, "lab_dave", "dave.lab@example.com", "user"),
    (5, "lab_erin", "erin.lab@example.com", "user"),
    (6, "lab_frank", "frank.lab@example.com", "moderator"),
    (7, "lab_grace", "grace.lab@example.com", "user"),
    (8, "lab_heidi", "heidi.lab@example.com", "user"),
    (9, "lab_ivan", "ivan.lab@example.com", "user"),
    (10, "lab_judy", "judy.lab@example.com", "admin"),
]

FAKE_PRODUCTS = [
    (1, "Nebula CI Runner", "devops", 49.00),
    (2, "VaultGate SSO", "identity", 129.00),
    (3, "PacketLens Pro", "analytics", 89.00),
    (4, "Orbit Object Store", "storage", 39.00),
    (5, "ShieldKey Secrets", "security", 79.00),
    (6, "Flux Queue Workers", "devops", 59.00),
    (7, "Atlas API Gateway", "networking", 149.00),
    (8, "Lumen Log Drain", "analytics", 45.00),
    (9, "Harbor Container Registry", "devops", 69.00),
    (10, "Pulse Uptime Checks", "monitoring", 29.00),
]


def connect(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Open the lab SQLite file (never MySQL)."""
    path = db_path or LAB_VULN_DB_PATH
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def reset_lab_db(db_path: Optional[str] = None) -> str:
    """Delete and recreate lab_vuln.db with fake seed data. Returns the path used."""
    path = db_path or LAB_VULN_DB_PATH
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    if os.path.exists(path):
        os.remove(path)

    conn = sqlite3.connect(path)
    try:
        conn.executescript(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT NOT NULL
            );

            CREATE TABLE products (
                id INTEGER PRIMARY KEY,
                name TEXT NOT NULL,
                category TEXT NOT NULL,
                price REAL NOT NULL
            );
            """
        )
        conn.executemany(
            "INSERT INTO users (id, username, email, role) VALUES (?, ?, ?, ?)",
            FAKE_USERS,
        )
        conn.executemany(
            "INSERT INTO products (id, name, category, price) VALUES (?, ?, ?, ?)",
            FAKE_PRODUCTS,
        )
        conn.commit()
    finally:
        conn.close()
    return path


def ensure_lab_db(db_path: Optional[str] = None) -> str:
    """Create the lab DB from scratch if the file is missing."""
    path = db_path or LAB_VULN_DB_PATH
    if not os.path.exists(path):
        return reset_lab_db(path)
    return path
