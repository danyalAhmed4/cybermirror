"""Generate benign lab traffic against a local CyberMirror instance."""
from __future__ import annotations

import argparse
import ipaddress
import random
import sys
import time
from collections import Counter
from typing import Optional
from urllib.parse import urlparse

import requests

try:
    from attacker.events import (
        add_events_arg,
        close_events,
        configure_events,
        emit,
        vuln_for,
    )
except ImportError:
    from events import (  # type: ignore
        add_events_arg,
        close_events,
        configure_events,
        emit,
        vuln_for,
    )

DEFAULT_BASE_URL = "http://127.0.0.1:5000"
DEFAULT_COUNT = 500
TEST_LABEL = "normal"

# ~20 fake users with realistic-looking identities
FAKE_USERS = [
    {"username": "alice.wong", "email": "alice.wong@example.com"},
    {"username": "brian.okonkwo", "email": "brian.okonkwo@example.com"},
    {"username": "carla.mendez", "email": "carla.mendez@example.net"},
    {"username": "daniel.hurst", "email": "daniel.hurst@example.org"},
    {"username": "elena.petrov", "email": "elena.petrov@example.com"},
    {"username": "farah.khan", "email": "farah.khan@example.co.uk"},
    {"username": "gabriel.rossi", "email": "gabriel.rossi@example.it"},
    {"username": "hana.suzuki", "email": "hana.suzuki@example.jp"},
    {"username": "ivan.novak", "email": "ivan.novak@example.cz"},
    {"username": "julia.brandt", "email": "julia.brandt@example.de"},
    {"username": "kevin.oconnor", "email": "kevin.oconnor@example.ie"},
    {"username": "lena.bergstrom", "email": "lena.bergstrom@example.se"},
    {"username": "marco.silva", "email": "marco.silva@example.br"},
    {"username": "nina.patel", "email": "nina.patel@example.in"},
    {"username": "omar.hadid", "email": "omar.hadid@example.ae"},
    {"username": "priya.nair", "email": "priya.nair@example.com"},
    {"username": "quentin.blake", "email": "quentin.blake@example.net"},
    {"username": "rosa.delgado", "email": "rosa.delgado@example.es"},
    {"username": "samir.ali", "email": "samir.ali@example.org"},
    {"username": "tina.chen", "email": "tina.chen@example.com"},
]

NORMAL_PASSWORD = "NormalPass123!"

SEARCH_TERMS = [
    "vault",
    "devops",
    "analytics",
    "sso",
    "gateway",
    "registry",
    "monitoring",
    "storage",
    "runner",
    "secrets",
]

USER_AGENTS = [
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    ),
    (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) "
        "Version/17.2 Safari/605.1.15"
    ),
    (
        "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) "
        "Gecko/20100101 Firefox/121.0"
    ),
    (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) "
        "Gecko/20100101 Firefox/121.0"
    ),
    (
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) "
        "AppleWebKit/605.1.15 (KHTML, like Gecko) "
        "Version/17.2 Mobile/15E148 Safari/604.1"
    ),
]


def _is_allowed_host(host: str) -> bool:
    """Allow only localhost or RFC1918 / private addresses."""
    raw = (host or "").strip().lower()
    if raw.startswith("[") and raw.endswith("]"):
        raw = raw[1:-1]
    # Strip optional zone index (e.g. fe80::1%eth0)
    if "%" in raw:
        raw = raw.split("%", 1)[0]

    if raw in {"localhost", "127.0.0.1", "::1"}:
        return True

    try:
        ip = ipaddress.ip_address(raw)
    except ValueError:
        return False

    return bool(ip.is_loopback or ip.is_private)


def assert_safe_base_url(base_url: str) -> None:
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"}:
        raise SystemExit(f"Refusing to run: unsupported scheme in {base_url!r}")
    host = parsed.hostname
    if not host or not _is_allowed_host(host):
        raise SystemExit(
            "Refusing to run: --base-url host must be localhost or a private IP "
            f"(10.x, 172.16-31.x, 192.168.x). Got host={host!r}"
        )


def _short_delay() -> None:
    time.sleep(random.uniform(0.05, 0.35))


class TrafficClient:
    """Session wrapper that labels every request and tracks status codes."""

    def __init__(self, base_url: str, user_agent: str, budget: int):
        self.base_url = base_url.rstrip("/")
        self.budget = budget
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": user_agent,
                "X-Test-Label": TEST_LABEL,
            }
        )
        self.status_counts: Counter[int] = Counter()
        self.sent = 0

    @property
    def remaining(self) -> int:
        return max(0, self.budget - self.sent)

    def request(self, method: str, path: str, **kwargs) -> Optional[requests.Response]:
        if self.remaining <= 0:
            return None

        url = f"{self.base_url}{path}"
        kwargs.setdefault("allow_redirects", False)
        kwargs.setdefault("timeout", 15)
        t0 = time.perf_counter()
        response = self.session.request(method, url, **kwargs)
        duration_ms = (time.perf_counter() - t0) * 1000.0
        self.status_counts[response.status_code] += 1
        self.sent += 1
        emit(
            "result",
            command=f"{method} {path}",
            action=f"Benign {method} {path}",
            log=f"{method} {path} → {response.status_code}",
            result={
                "method": method,
                "url": url,
                "status_code": response.status_code,
                "label": TEST_LABEL,
            },
            vulnerability=vuln_for("normal"),
            edge={"from": "attacker", "to": "orbitmart", "label": "normal"},
            status="ok" if response.status_code < 500 else "error",
            duration_ms=round(duration_ms, 2),
        )

        # Follow one redirect so register/login cookies still apply
        if (
            self.remaining > 0
            and response.is_redirect
            and response.headers.get("Location")
        ):
            location = response.headers["Location"]
            next_url = (
                location
                if location.startswith("http")
                else f"{self.base_url}{location}"
            )
            followed = self.session.get(next_url, timeout=15, allow_redirects=False)
            self.status_counts[followed.status_code] += 1
            self.sent += 1
            _short_delay()
            return followed

        _short_delay()
        return response


def run_user_session(client: TrafficClient, user: dict) -> int:
    """Register → login → browse /home → a few searches → logout."""
    before = client.sent
    username = user["username"]
    email = user["email"]

    # Register (conflicts are fine if the user already exists)
    client.request(
        "POST",
        "/register",
        data={
            "username": username,
            "email": email,
            "password": NORMAL_PASSWORD,
        },
    )
    client.request(
        "POST",
        "/login",
        data={"username": username, "password": NORMAL_PASSWORD},
    )

    for _ in range(random.randint(1, 3)):
        if client.remaining <= 0:
            break
        client.request("GET", "/home")

    terms = random.sample(SEARCH_TERMS, k=min(random.randint(2, 4), len(SEARCH_TERMS)))
    for term in terms:
        if client.remaining <= 0:
            break
        client.request("GET", "/search", params={"q": term})

    client.request("GET", "/logout")
    return client.sent - before


def simulate(base_url: str, count: int) -> Counter[int]:
    assert_safe_base_url(base_url)
    totals: Counter[int] = Counter()
    sent = 0
    users = FAKE_USERS.copy()
    random.shuffle(users)

    print(f"Target: {base_url}")
    print(f"Label:  X-Test-Label: {TEST_LABEL}")
    print(f"Goal:   {count} requests across ~{len(FAKE_USERS)} users")
    print()
    emit(
        "log",
        log=f"Target={base_url}; label={TEST_LABEL}; goal={count} requests",
        vulnerability=vuln_for("normal"),
    )

    user_index = 0
    while sent < count:
        user = users[user_index % len(users)]
        user_index += 1
        ua = random.choice(USER_AGENTS)
        client = TrafficClient(base_url, ua, budget=count - sent)
        used = run_user_session(client, user)
        totals.update(client.status_counts)
        sent += used
        line = (
            f"[{sent}/{count}] session user={user['username']} "
            f"ua={ua.split(')')[0].split('(')[-1].strip()[:24]!r} "
            f"requests={used}"
        )
        print(line)
        emit(
            "action",
            action=f"User session {user['username']}",
            log=line,
            vulnerability=vuln_for("normal"),
            result={"user": user["username"], "requests": used, "sent": sent},
        )

    return totals


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Simulate normal (benign) CyberMirror user traffic."
    )
    parser.add_argument(
        "--base-url",
        default=DEFAULT_BASE_URL,
        help=f"CyberMirror base URL (default: {DEFAULT_BASE_URL})",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=DEFAULT_COUNT,
        help=f"Approximate number of HTTP requests to send (default: {DEFAULT_COUNT})",
    )
    add_events_arg(parser)
    args = parser.parse_args(argv)
    if args.count < 1:
        parser.error("--count must be >= 1")
    return args


def main(argv: Optional[list[str]] = None) -> int:
    args = parse_args(argv)
    configure_events(
        args.events_file,
        suite="normal",
        base_url=args.base_url,
        meta={"cli": "python -m attacker.normal_traffic", "count": args.count},
    )
    emit(
        "command",
        command=(
            f"python -m attacker.normal_traffic --base-url {args.base_url} "
            f"--count {args.count}"
        ),
        action="Launch benign traffic simulation",
        vulnerability=vuln_for("normal"),
    )
    try:
        status_counts = simulate(args.base_url, args.count)
    except requests.RequestException as exc:
        print(f"Request failed: {exc}", file=sys.stderr)
        close_events(status="failed", score={"error": str(exc)})
        return 1

    total = sum(status_counts.values())
    print()
    print("=== Summary ===")
    print(f"Requests sent: {total}")
    print("Status codes:")
    for code in sorted(status_counts):
        print(f"  {code}: {status_counts[code]}")

    score = {
        "requests": total,
        "status_codes": dict(status_counts),
        "outcome": "traffic_sent",
    }
    emit("score", score=score, action="Normal traffic summary", status="completed")
    close_events(status="completed", score=score)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
