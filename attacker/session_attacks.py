"""
Lab session-hijacking traffic against CyberMirror.

Requires LAB_TRUST_FORWARDED_FOR=True so X-Forwarded-For can simulate
different client IPs from one laptop. Session fixation needs
SESSION_REGENERATE_ON_LOGIN=False.
"""
from __future__ import annotations

import argparse
import random
import string
import sys
import time
from collections import Counter
from typing import Optional

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

SENSITIVE_PATHS = ["/home", "/search", "/logout"]


def _delay() -> None:
    time.sleep(random.uniform(0.05, 0.25))


def _send(
    session: requests.Session,
    method: str,
    url: str,
    *,
    label: str,
    counts: Counter,
    forwarded_for: Optional[str] = None,
    user_agent: Optional[str] = None,
    action: Optional[str] = None,
    command: Optional[str] = None,
    **kwargs,
) -> requests.Response:
    headers = dict(kwargs.pop("headers", {}) or {})
    headers["X-Test-Label"] = label
    if forwarded_for:
        headers["X-Forwarded-For"] = forwarded_for
    if user_agent:
        headers["User-Agent"] = user_agent
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
            "forwarded_for": forwarded_for,
        },
        vulnerability=vuln_for(label),
        edge={"from": "attacker", "to": "orbitmart", "label": label},
        status="ok" if response.status_code < 500 else "error",
        duration_ms=round(duration_ms, 2),
    )
    _delay()
    return response


def _register_and_login(
    base: str,
    username: str,
    password: str,
    *,
    label: str,
    counts: Counter,
    session: Optional[requests.Session] = None,
    forwarded_for: str = "10.0.0.10",
    user_agent: str = "Mozilla/5.0 (SessionLab/Normal)",
) -> requests.Session:
    sess = session or requests.Session()
    email = f"{username}@example.com"
    _send(
        sess,
        "POST",
        f"{base}/register",
        label=label,
        counts=counts,
        forwarded_for=forwarded_for,
        user_agent=user_agent,
        data={"username": username, "email": email, "password": password},
    )
    _send(
        sess,
        "POST",
        f"{base}/login",
        label=label,
        counts=counts,
        forwarded_for=forwarded_for,
        user_agent=user_agent,
        data={"username": username, "password": password},
    )
    return sess


def attack_cookie_replay(base: str, counts: Counter) -> None:
    """Log in normally, then replay the cookie with a different UA + IP."""
    label = "cookie_replay"
    print(f"[{label}] login as victim")
    emit(
        "command",
        command="session: cookie_replay",
        action="Cookie replay attack",
        log=f"[{label}] login as victim",
        vulnerability=vuln_for(label),
        edge={"from": "victim", "to": "orbitmart", "label": "login"},
    )
    victim = _register_and_login(
        base,
        f"replay_user_{random.randint(1000, 9999)}",
        "ReplayPass123!",
        label=label,
        counts=counts,
        forwarded_for="10.10.1.1",
        user_agent="Mozilla/5.0 (Windows NT 10.0; VictimBrowser)",
    )
    # Browse enough that SESSION_DETECT_MIN_REQUESTS is met before replay
    for _ in range(4):
        _send(
            victim,
            "GET",
            f"{base}/home",
            label=label,
            counts=counts,
            forwarded_for="10.10.1.1",
            user_agent="Mozilla/5.0 (Windows NT 10.0; VictimBrowser)",
        )

    print(f"[{label}] replay cookie from attacker IP/UA")
    emit(
        "action",
        action="Replay stolen session cookie",
        log=f"[{label}] replay cookie from attacker IP/UA",
        vulnerability=vuln_for(label),
        edge={"from": "attacker", "to": "orbitmart", "label": "replay"},
    )
    attacker = requests.Session()
    attacker.cookies.update(victim.cookies)
    for path in ("/home", "/search?q=laptop", "/home", "/home"):
        _send(
            attacker,
            "GET",
            f"{base}{path}" if not path.startswith("/search") else f"{base}/search",
            label=label,
            counts=counts,
            forwarded_for="10.10.9.9",
            user_agent="python-requests/2.31 (cookie-replay)",
            params={"q": "laptop"} if path.startswith("/search") else None,
        )


def attack_sidejacking(base: str, counts: Counter) -> None:
    """Same cookie from a second client hitting sensitive endpoints."""
    label = "sidejacking"
    print(f"[{label}] victim session")
    emit(
        "command",
        command="session: sidejacking",
        action="Sidejacking attack",
        log=f"[{label}] victim session",
        vulnerability=vuln_for(label),
    )
    victim = _register_and_login(
        base,
        f"sidejack_{random.randint(1000, 9999)}",
        "SidejackPass123!",
        label=label,
        counts=counts,
        forwarded_for="10.20.1.1",
        user_agent="Mozilla/5.0 (VictimSidejack)",
    )
    for _ in range(3):
        _send(
            victim,
            "GET",
            f"{base}/home",
            label=label,
            counts=counts,
            forwarded_for="10.20.1.1",
            user_agent="Mozilla/5.0 (VictimSidejack)",
        )

    print(f"[{label}] second client uses stolen cookie on sensitive paths")
    emit(
        "action",
        action="Use stolen cookie on sensitive paths",
        log=f"[{label}] second client uses stolen cookie on sensitive paths",
        vulnerability=vuln_for(label),
        edge={"from": "attacker", "to": "orbitmart", "label": "sidejack"},
    )
    thief = requests.Session()
    thief.cookies.update(victim.cookies)
    for path in list(SENSITIVE_PATHS) + ["/home"]:
        if path == "/search":
            _send(
                thief,
                "GET",
                f"{base}/search",
                label=label,
                counts=counts,
                forwarded_for="10.20.8.8",
                user_agent="curl/8.0 sidejack",
                params={"q": "secrets"},
            )
        else:
            _send(
                thief,
                "GET",
                f"{base}{path}",
                label=label,
                counts=counts,
                forwarded_for="10.20.8.8",
                user_agent="curl/8.0 sidejack",
            )


def attack_session_fixation(base: str, counts: Counter) -> None:
    """
    Attacker obtains a valid anonymous session, victim logs in with that cookie
    from a different IP (SESSION_REGENERATE_ON_LOGIN=False).
    """
    label = "session_fixation"
    print(f"[{label}] attacker plants anonymous session cookie")
    emit(
        "command",
        command="session: session_fixation",
        action="Session fixation attack",
        log=f"[{label}] attacker plants anonymous session cookie",
        vulnerability=vuln_for(label),
    )
    attacker = requests.Session()
    attacker_ip = "10.30.9.9"
    victim_ip = "10.30.1.1"
    ua_attacker = "Mozilla/5.0 (FixationAttacker)"
    ua_victim = "Mozilla/5.0 (FixationVictim)"
    # Valid signed cookie from the app (not a forged raw string)
    _send(
        attacker,
        "GET",
        f"{base}/login",
        label=label,
        counts=counts,
        forwarded_for=attacker_ip,
        user_agent=ua_attacker,
    )
    planted = attacker.cookies.get("session")
    username = f"fix_{random.randint(1000, 9999)}"
    password = "FixationPass123!"

    # Victim registers (own session), then switches to planted cookie for login
    victim = requests.Session()
    _send(
        victim,
        "POST",
        f"{base}/register",
        label=label,
        counts=counts,
        forwarded_for=victim_ip,
        user_agent=ua_victim,
        data={
            "username": username,
            "email": f"{username}@example.com",
            "password": password,
        },
    )
    if planted:
        victim.cookies.clear()
        victim.cookies.set("session", planted)
    print(f"[{label}] victim logs in with planted cookie")
    emit(
        "action",
        action="Victim authenticates with planted session",
        log=f"[{label}] victim logs in with planted cookie",
        vulnerability=vuln_for(label),
        edge={"from": "victim", "to": "orbitmart", "label": "fixed-login"},
    )
    _send(
        victim,
        "POST",
        f"{base}/login",
        label=label,
        counts=counts,
        forwarded_for=victim_ip,
        user_agent=ua_victim,
        data={"username": username, "password": password},
    )
    for _ in range(4):
        _send(
            victim,
            "GET",
            f"{base}/home",
            label=label,
            counts=counts,
            forwarded_for=victim_ip,
            user_agent=ua_victim,
        )


def attack_session_prediction(base: str, counts: Counter) -> None:
    """Send many guessed session IDs per minute."""
    label = "session_prediction"
    print(f"[{label}] spray guessed session cookies")
    emit(
        "command",
        command="session: session_prediction",
        action="Session ID spray / prediction",
        log=f"[{label}] spray guessed session cookies",
        vulnerability=vuln_for(label),
        edge={"from": "attacker", "to": "orbitmart", "label": "spray"},
    )
    ua = "CyberMirror-SessionPredict/1.0"
    for i in range(40):
        guess = requests.Session()
        token = "PRED" + "".join(random.choices(string.hexdigits, k=32))
        guess.cookies.set("session", token)
        _send(
            guess,
            "GET",
            f"{base}/home",
            label=label,
            counts=counts,
            forwarded_for="10.40.1.1",
            user_agent=ua,
        )


def normal_sessions(base: str, counts: Counter, n_users: int = 3) -> None:
    label = "normal"
    print(f"[{label}] benign multi-request sessions")
    emit(
        "command",
        command="session: normal baseline",
        action="Benign multi-request sessions",
        log=f"[{label}] benign multi-request sessions",
        vulnerability=vuln_for(label),
    )
    for i in range(n_users):
        ua = f"Mozilla/5.0 (NormalUser/{i})"
        ip = f"10.50.0.{10 + i}"
        sess = _register_and_login(
            base,
            f"normal_sess_{random.randint(1000, 9999)}",
            "NormalPass123!",
            label=label,
            counts=counts,
            forwarded_for=ip,
            user_agent=ua,
        )
        for path in ("/home", "/search", "/home"):
            if path == "/search":
                _send(
                    sess,
                    "GET",
                    f"{base}/search",
                    label=label,
                    counts=counts,
                    forwarded_for=ip,
                    user_agent=ua,
                    params={"q": "laptop"},
                )
            else:
                _send(
                    sess,
                    "GET",
                    f"{base}{path}",
                    label=label,
                    counts=counts,
                    forwarded_for=ip,
                    user_agent=ua,
                )
        _send(
            sess,
            "GET",
            f"{base}/logout",
            label=label,
            counts=counts,
            forwarded_for=ip,
            user_agent=ua,
        )


def run(base_url: str) -> Counter:
    assert_safe_base_url(base_url)
    base = base_url.rstrip("/")
    counts: Counter = Counter()
    print(f"Target: {base}")
    print("Note: set LAB_TRUST_FORWARDED_FOR=True")
    print("Note: session_fixation needs SESSION_REGENERATE_ON_LOGIN=False")
    print()
    emit(
        "log",
        log=(
            f"Target={base}; LAB_TRUST_FORWARDED_FOR=True recommended; "
            "session_fixation needs SESSION_REGENERATE_ON_LOGIN=False"
        ),
    )

    normal_sessions(base, counts)
    attack_cookie_replay(base, counts)
    attack_sidejacking(base, counts)
    attack_session_fixation(base, counts)
    attack_session_prediction(base, counts)
    return counts


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Lab session-hijack traffic generator.")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    add_events_arg(parser)
    args = parser.parse_args(argv)
    configure_events(
        args.events_file,
        suite="session",
        base_url=args.base_url,
        meta={"cli": "python -m attacker.session_attacks"},
    )
    emit(
        "command",
        command=f"python -m attacker.session_attacks --base-url {args.base_url}",
        action="Launch session-hijack suite",
        vulnerability=vuln_for("cookie_replay"),
    )
    try:
        counts = run(args.base_url)
    except requests.RequestException as exc:
        print(f"Request failed: {exc}", file=sys.stderr)
        close_events(status="failed", score={"error": str(exc)})
        return 1

    print()
    print("=== Summary ===")
    print(f"Requests sent: {sum(counts.values())}")
    for code in sorted(counts):
        print(f"  {code}: {counts[code]}")

    score = {
        "requests": sum(counts.values()),
        "status_codes": dict(counts),
        "outcome": "traffic_sent",
    }
    emit("score", score=score, action="Session suite summary", status="completed")
    close_events(status="completed", score=score)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
