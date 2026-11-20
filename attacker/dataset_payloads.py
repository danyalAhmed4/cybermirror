"""Load live lab payloads from the SQLi CSV with an explicit train/test/OOD policy.

Default is the held-out test split (same 80/20, random_state=42 as training) so
lab Evaluation is not biased by attacking with training-row payloads.
Use split="ood" for obfuscated payloads outside the CSV distribution.
"""
from __future__ import annotations

import os
import random
from typing import Literal, Optional

import pandas as pd
from sklearn.model_selection import train_test_split

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DEFAULT_CSV = os.path.join(_ROOT, "training", "Modified_SQL_Dataset.csv")

SplitName = Literal["test", "train", "all", "ood"]

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

# Out-of-distribution / obfuscated shapes not taken from Modified_SQL_Dataset.csv
OOD_SQLI_PAYLOADS = [
    "1'/**/OR/**/1=1--",
    "1'%09OR%091=1--",
    "1' UnIoN SeLeCt NULL,NULL--",
    "1'||(SELECT '')||'",
    "admin' AND 1=CONVERT(int,(SELECT @@version))--",
    "1;EXEC xp_cmdshell('whoami')--",
    "1' AND SLEEP(0)--",
    "1') OR ('1'='1",
    "%27%20OR%20%271%27%3D%271",
    "1' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION()))--",
    "1' AND (SELECT * FROM (SELECT(SLEEP(0)))a)--",
    "\" OR \"\"=\"",
    "1' UNION ALL SELECT NULL,LOAD_FILE('/etc/passwd')--",
    "1' OR 1=1 LIMIT 1--",
    "1' OR '1'='1' /*",
    "1'\\\" OR \\\"1\\\"=\\\"1",
    "1 AND 1=1 UNION SELECT table_name FROM information_schema.tables--",
    "0x3127204f52202731273d2731",
    "1' OR HEX('a')=HEX('a')--",
    "1'/*!50000OR*/1=1--",
    "1' OR 1 GROUP BY CONCAT(version(),FLOOR(RAND(0)*2)) HAVING MIN(0)--",
    "'; DROP TABLE users--",
    "1' OR EXISTS(SELECT * FROM users)--",
    "1' UNION SELECT CHAR(65),CHAR(66)--",
]

OOD_NORMAL_QUERIES = [
    "wireless earbuds",
    "standing desk",
    "USB-C hub",
    "notebook 15",
    "office lamp",
    "mechanical keyboard",
    "monitor arm",
    "webcam 1080p",
    "laptop sleeve",
    "ethernet cable",
    "power bank",
    "desk mat",
]


def _load_df(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path, encoding="utf-8")
    df = df.dropna(subset=["Query", "Label"]).copy()
    df["Query"] = df["Query"].astype(str).str.strip()
    df = df[df["Query"] != ""]
    df["Label"] = df["Label"].astype(int)
    return df.drop_duplicates(subset=["Query"]).reset_index(drop=True)


def _split_frame(
    df: pd.DataFrame, *, split: SplitName, seed: int = 42
) -> pd.DataFrame:
    """Return rows for split using the same policy as sql_injection_detection.py."""
    if split == "all":
        return df
    if split == "ood":
        raise ValueError("OOD payloads are not CSV rows; use load_* with split='ood'")
    idx = list(range(len(df)))
    y = df["Label"].astype(int)
    train_idx, test_idx = train_test_split(
        idx, test_size=0.2, random_state=seed, stratify=y
    )
    keep = test_idx if split == "test" else train_idx
    return df.iloc[keep].reset_index(drop=True)


def load_sqli_attack_payloads(
    csv_path: Optional[str] = None,
    *,
    limit: int = 24,
    seed: int = 42,
    split: SplitName = "test",
) -> list[str]:
    """
    Pick Label=1 payloads.

    split:
      test — held-out 20% (default; fairer lab eval)
      train — training 80% (optimistic / leakage demo)
      all — full CSV (old biased lab behaviour)
      ood — obfuscated payloads outside the CSV
    """
    if split == "ood":
        rng = random.Random(seed)
        picks = list(OOD_SQLI_PAYLOADS)
        rng.shuffle(picks)
        return picks[:limit]

    path = csv_path or DEFAULT_CSV
    df = _split_frame(_load_df(path), split=split, seed=seed)
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

    top = attacks.head(max(limit * 3, limit)).copy()
    rng = random.Random(seed)
    picks = list(dict.fromkeys(top["q"].tolist()))
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
    split: SplitName = "test",
) -> list[str]:
    """Pick Label=0 queries from the same split policy (or OOD catalog-like strings)."""
    if split == "ood":
        rng = random.Random(seed)
        picks = list(OOD_NORMAL_QUERIES)
        rng.shuffle(picks)
        return picks[:limit]

    path = csv_path or DEFAULT_CSV
    df = _split_frame(_load_df(path), split=split, seed=seed)
    normals = df[df["Label"] == 0].copy()
    normals["q"] = normals["Query"].astype(str)
    normals["n"] = normals["q"].str.len()
    normals = normals[(normals["n"] >= 3) & (normals["n"] <= 64)]
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
    normals = normals[
        normals["q"].str.match(r"^[A-Za-z0-9][A-Za-z0-9 .,_'\-]{1,62}$", na=False)
    ]
    rng = random.Random(seed)
    picks = normals["q"].drop_duplicates().tolist()
    rng.shuffle(picks)
    return picks[:limit]
