#!/usr/bin/env python3
"""
Export labeled train/test rows using the same splits as the training scripts
(test_size=0.2, random_state=42, stratify=y) and report overlap.

Outputs under training/splits/:
  sqli_train.csv / sqli_test.csv / sqli_all_labeled.csv
  session_train.csv / session_test.csv / session_all_labeled.csv
  xss_* if Data_66_featurs.csv is present

Usage:
  python training/export_train_test_splits.py
"""
from __future__ import annotations

import os
import sys

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "splits")
RANDOM_STATE = 42
TEST_SIZE = 0.2


def _write(df: pd.DataFrame, name: str) -> str:
    path = os.path.join(OUT, name)
    df.to_csv(path, index=False)
    return path


def export_sqli() -> None:
    path = os.path.join(HERE, "Modified_SQL_Dataset.csv")
    df = pd.read_csv(path, encoding="utf-8")
    df = df.dropna(subset=["Query", "Label"]).copy()
    df["Query"] = df["Query"].astype(str).str.strip()
    before = len(df)
    df = df.drop_duplicates(subset=["Query"]).reset_index(drop=True)
    print(f"\n=== SQLi ===")
    print(f"Rows after Query dedupe: {len(df)} (removed {before - len(df)})")

    idx = np.arange(len(df))
    y = df["Label"].astype(int)
    train_idx, test_idx = train_test_split(
        idx, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    split = np.full(len(df), "train", dtype=object)
    split[test_idx] = "test"
    labeled = df.copy()
    labeled.insert(0, "split", split)

    train_df = labeled.loc[labeled["split"] == "train"].copy()
    test_df = labeled.loc[labeled["split"] == "test"].copy()

    train_q = set(train_df["Query"])
    test_q = set(test_df["Query"])
    overlap = train_q & test_q

    print(f"Train: {len(train_df)}  Test: {len(test_df)}")
    print(f"Exact Query overlap train∩test: {len(overlap)}")
    print(
        f"Test queries also in train: "
        f"{100.0 * len(overlap) / max(len(test_q), 1):.2f}% of test"
    )
    print(
        f"Train queries also in test: "
        f"{100.0 * len(overlap) / max(len(train_q), 1):.2f}% of train"
    )

    _write(train_df, "sqli_train.csv")
    _write(test_df, "sqli_test.csv")
    _write(labeled, "sqli_all_labeled.csv")
    print(f"Wrote training/splits/sqli_{{train,test,all_labeled}}.csv")


def export_session() -> None:
    path = os.path.join(HERE, "SessionHijacking.csv")
    data = pd.read_csv(path)
    print(f"\n=== Session ===")
    print(f"Rows: {len(data)}")

    # Match session_hijacking.py stratify target (binary Normal vs Hijacked)
    y = (data["Label"] != "Normal").astype(int)
    idx = np.arange(len(data))
    train_idx, test_idx = train_test_split(
        idx, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    split = np.full(len(data), "train", dtype=object)
    split[test_idx] = "test"
    labeled = data.copy()
    labeled.insert(0, "split", split)
    labeled.insert(1, "row_id", idx)

    train_df = labeled.loc[labeled["split"] == "train"].copy()
    test_df = labeled.loc[labeled["split"] == "test"].copy()

    # Feature-space overlap (same columns the model uses after ID drops)
    drop = [
        "Flow ID",
        "Timestamp",
        "Source IP",
        "Destination IP",
        "Session ID",
        "User ID",
        "Source Port",
        "logs",
        "Label",
        "Binary Label",
        "User Agent",
        "Endpoint",
        "HTTP Method",
        "split",
        "row_id",
    ]
    feat_cols = [
        c
        for c in labeled.columns
        if c not in drop and pd.api.types.is_numeric_dtype(labeled[c])
    ]
    # Round to reduce float noise for set comparison
    def _keys(frame: pd.DataFrame) -> set[tuple]:
        sub = frame[feat_cols].fillna(0).round(6)
        return set(map(tuple, sub.to_numpy()))

    train_keys = _keys(train_df)
    test_keys = _keys(test_df)
    overlap = train_keys & test_keys

    print(f"Train: {len(train_df)}  Test: {len(test_df)}")
    print(f"Exact feature-row overlap train∩test: {len(overlap)}")
    print(
        f"Test feature-rows also in train: "
        f"{100.0 * len(overlap) / max(len(test_keys), 1):.2f}% of test"
    )

    _write(train_df, "session_train.csv")
    _write(test_df, "session_test.csv")
    _write(labeled, "session_all_labeled.csv")
    print(f"Wrote training/splits/session_{{train,test,all_labeled}}.csv")


def export_xss() -> None:
    path = os.path.join(HERE, "Data_66_featurs.csv")
    print(f"\n=== XSS ===")
    if not os.path.isfile(path):
        print(f"SKIP — missing {path}")
        return
    df = pd.read_csv(path)
    if "Label" not in df.columns and "label" in df.columns:
        df = df.rename(columns={"label": "Label"})
    # Match xss_attack_detection.py: drop_duplicates then split
    before = len(df)
    df = df.drop_duplicates().reset_index(drop=True)
    print(f"Rows after dedupe: {len(df)} (removed {before - len(df)})")
    y = df["Label"]
    idx = np.arange(len(df))
    train_idx, test_idx = train_test_split(
        idx, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    split = np.full(len(df), "train", dtype=object)
    split[test_idx] = "test"
    labeled = df.copy()
    labeled.insert(0, "split", split)
    train_df = labeled.loc[labeled["split"] == "train"].copy()
    test_df = labeled.loc[labeled["split"] == "test"].copy()

    # Overlap on full feature tuples excluding Label/split
    feat = [c for c in labeled.columns if c not in {"split", "Label"}]
    def _keys(frame: pd.DataFrame) -> set[tuple]:
        sub = frame[feat].copy()
        for c in sub.columns:
            if sub[c].dtype == object:
                sub[c] = sub[c].astype(str)
            else:
                sub[c] = pd.to_numeric(sub[c], errors="coerce").fillna(0).round(6)
        return set(map(tuple, sub.to_numpy()))

    train_keys = _keys(train_df)
    test_keys = _keys(test_df)
    overlap = train_keys & test_keys
    print(f"Train: {len(train_df)}  Test: {len(test_df)}")
    print(f"Exact row overlap train∩test: {len(overlap)}")
    print(
        f"Test rows also in train: "
        f"{100.0 * len(overlap) / max(len(test_keys), 1):.2f}% of test"
    )
    _write(train_df, "xss_train.csv")
    _write(test_df, "xss_test.csv")
    _write(labeled, "xss_all_labeled.csv")
    print(f"Wrote training/splits/xss_{{train,test,all_labeled}}.csv")


def main() -> int:
    os.makedirs(OUT, exist_ok=True)
    print(
        "Exporting splits with test_size=0.2, random_state=42 "
        "(same as training scripts)."
    )
    export_sqli()
    export_session()
    export_xss()
    print(
        "\nNote: Dataset score on the Evaluation page is holdout accuracy from "
        "these splits. Live Run attacks sample SQLi from the FULL CSV (train+test), "
        "so lab recall is not the same as this holdout accuracy."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
