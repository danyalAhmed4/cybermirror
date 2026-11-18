"""Load live lab payloads from the training CSV so OrbitMart traffic matches the models."""
from __future__ import annotations

import os
import random
from typing import Optional

import pandas as pd

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_CSV = os.path.join(_ROOT, "training", "Modified_SQL_Dataset.csv")

_SQLI_HINTS = (
    " or ",
    " union ",
    "select",
    "sleep",
    "drop ",
    "waitfor",
    "--",
    "#",
    "/*",
    "1=1",
    "'1'='1",
)


def _load_df(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path, encoding="utf-8")
    df = df.dropna(subset=["Query", "Label"]).copy()
    df["Query"] = df["Query"].astype(str).str.strip()
    df = df[df["Query"] != ""]
    df["Label"] = df["Label"].astype(int)
    return df.drop_duplicates(subset=["Query"])


def load_sqli_attack_payloads(
    csv_path: Optional[str] = None,
    *,
    limit: int = 24,
    seed: int = 42,
) -> list[str]:
    """
    Pick Label=1 rows that look like the training distribution the SQLi model saw.

    Prefers mid-length queries with classic SQLi markers (not one-char junk).
    """
    path = csv_path or DEFAULT_CSV
    df = _load_df(path)
    attacks = df[df["Label"] == 1].copy()
    attacks["q"] = attacks["Query"].astype(str)
    attacks["n"] = attacks["q"].str.len()
    attacks = attacks[(attacks["n"] >= 8) & (attacks["n"] <= 220)]

    def scored(row) -> int:
        text = f" {row['q'].lower()} "
        return sum(1 for h in _SQLI_HINTS if h in text)

    attacks["score"] = attacks.apply(scored, axis=1)
    attacks = attacks[attacks["score"] >= 1]
    attacks = attacks.sort_values(["score", "n"], ascending=[False, True])

    # Diversify: take top scored, then sample remainder
    top = attacks.head(max(limit * 3, limit)).copy()
    rng = random.Random(seed)
    picks = list(dict.fromkeys(top["q"].tolist()))  # preserve order, unique
    if len(picks) > limit:
        head = picks[: limit // 2]
        rest = picks[limit // 2 :]
        rng.shuffle(rest)
        picks = head + rest[: limit - len(head)]
    return picks[:limit]


def load_sqli_normal_queries(
    csv_path: Optional[str] = None,
    *,
    limit: int = 16,
    seed: int = 42,
) -> list[str]:
    """Pick short Label=0 queries so normals also match training distribution."""
    path = csv_path or DEFAULT_CSV
    df = _load_df(path)
    normals = df[df["Label"] == 0].copy()
    normals["q"] = normals["Query"].astype(str)
    normals["n"] = normals["q"].str.len()
    # Prefer searchable-length benign strings (avoid huge SQL dumps labeled 0)
    normals = normals[(normals["n"] >= 3) & (normals["n"] <= 64)]
    # Drop anything that still looks attacky / DDL-ish (noisy Label=0 rows exist)
    bad = (
        " union ",
        " select ",
        " from ",
        " where ",
        " sleep",
        " drop ",
        " delete ",
        " insert ",
        " update ",
        "1=1",
        "--",
        "#",
        "/*",
        "xp_",
        "waitfor",
        " information_schema",
    )
    mask = ~normals["q"].str.lower().apply(
        lambda t: any(h in f" {t} " for h in bad)
    )
    normals = normals[mask]
    # Prefer mostly alphanumeric / spaces (catalog-like), allow light punctuation
    normals = normals[
        normals["q"].str.match(r"^[A-Za-z0-9][A-Za-z0-9 .,_'\-]{1,62}$", na=False)
    ]
    rng = random.Random(seed)
    picks = normals["q"].drop_duplicates().tolist()
    rng.shuffle(picks)
    return picks[:limit]
