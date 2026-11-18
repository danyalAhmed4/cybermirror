#!/usr/bin/env python3
"""Recreate lab_vuln.db from scratch with fake seed data only."""
from __future__ import annotations

import argparse
import os
import sys

# Allow `python scripts/reset_lab_db.py` from the repo root
_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from app.lab_vuln_db import LAB_VULN_DB_PATH, reset_lab_db  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Delete and recreate the CyberMirror lab SQLite DB (fake data only)."
    )
    parser.add_argument(
        "--path",
        default=LAB_VULN_DB_PATH,
        help=f"SQLite file path (default: {LAB_VULN_DB_PATH})",
    )
    args = parser.parse_args()
    path = reset_lab_db(args.path)
    print(f"Recreated lab DB at: {path}")
    print("Tables: users (~10 fake rows), products (fake catalog).")
    print("This file is isolated from MySQL.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
