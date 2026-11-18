#!/usr/bin/env python3
"""
Export live OrbitMart session feature vectors from monitor.db for retraining.

Writes training/live_session_features.csv with APP_FEATURE_ORDER columns plus
Label / Binary Label derived from requests.true_label (majority vote per session).

Usage:
  python export_live_session_features.py
  python export_live_session_features.py --db ../app/monitoring/monitor.db --min-requests 3
"""
from __future__ import annotations

import argparse
import os
import sys
from collections import Counter

import pandas as pd

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from app.monitoring.features_session import APP_FEATURE_ORDER, build_session_features
from app.monitoring.store import get_store

LABEL_MAP = {
    "normal": "Normal",
    "cookie_replay": "Cookie_Replay",
    "sidejacking": "Sidejacking",
    "session_fixation": "Session_Fixation",
    "session_prediction": "Session_Prediction",
}


def _norm(label: str) -> str:
    return (label or "").strip().lower().replace("-", "_").replace(" ", "_")


def export(db_path: str, out_csv: str, *, min_requests: int = 3) -> int:
    store = get_store(db_path)
    # Discover session hashes from requests table
    import sqlite3

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    sessions = conn.execute(
        """
        SELECT session_hash, true_label, COUNT(*) AS n
        FROM requests
        WHERE session_hash IS NOT NULL AND TRIM(session_hash) != ''
        GROUP BY session_hash, true_label
        """
    ).fetchall()
    conn.close()

    by_hash: dict[str, Counter] = {}
    for row in sessions:
        sh = row["session_hash"]
        by_hash.setdefault(sh, Counter())[row["true_label"] or "unlabeled"] += int(
            row["n"]
        )

    records = []
    for session_hash, label_counts in by_hash.items():
        rows = store.fetch_requests_for_session(session_hash)
        if len(rows) < min_requests:
            continue
        # Majority true_label (skip unlabeled if anything else present)
        usable = Counter(
            {
                k: v
                for k, v in label_counts.items()
                if _norm(k) not in {"", "unlabeled"}
            }
        )
        if not usable:
            continue
        raw_label = usable.most_common(1)[0][0]
        mapped = LABEL_MAP.get(_norm(raw_label))
        if not mapped:
            continue

        ips = {r.get("source_ip") for r in rows if r.get("source_ip")}
        vector = build_session_features(
            rows,
            session_hash=session_hash,
            is_https=1,
            secure_cookie_flag=1,
            concurrent_ips_in_window=len(ips),
            sids_tried_per_min=0.0,
        )
        rec = {name: float(vector[i]) for i, name in enumerate(APP_FEATURE_ORDER)}
        rec["Label"] = mapped
        rec["Binary Label"] = "Normal" if mapped == "Normal" else "Hijacked"
        rec["session_hash"] = session_hash[:24]
        records.append(rec)

    os.makedirs(os.path.dirname(out_csv) or ".", exist_ok=True)
    df = pd.DataFrame(records)
    df.to_csv(out_csv, index=False)
    print(f"Wrote {len(df)} sessions → {out_csv}")
    if len(df):
        print(df["Label"].value_counts().to_string())
    return len(df)


def main() -> int:
    p = argparse.ArgumentParser(description="Export live session features for retrain")
    p.add_argument(
        "--db",
        default=os.path.join(_ROOT, "app", "monitoring", "monitor.db"),
    )
    p.add_argument(
        "--out",
        default=os.path.join(os.path.dirname(__file__), "live_session_features.csv"),
    )
    p.add_argument("--min-requests", type=int, default=3)
    args = p.parse_args()
    export(args.db, args.out, min_requests=args.min_requests)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
