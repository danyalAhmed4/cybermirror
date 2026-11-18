#!/usr/bin/env python3
"""Generate offline sample JSONL runs for /viz (no live attacks)."""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timedelta, timezone

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from attacker.events import VULN_CATALOG, mitigation_for_mode  # noqa: E402

SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "sample_runs")


def _ts(start: datetime, seconds: float) -> str:
    return (start + timedelta(seconds=seconds)).isoformat()


def _write(name: str, events: list[dict]) -> str:
    os.makedirs(SAMPLE_DIR, exist_ok=True)
    path = os.path.join(SAMPLE_DIR, name)
    with open(path, "w", encoding="utf-8") as fh:
        for ev in events:
            fh.write(json.dumps(ev, ensure_ascii=False) + "\n")
    return path


def _base_nodes(extra=None):
    nodes = [
        {"id": "attacker", "label": "Attacker CLI", "kind": "client"},
        {"id": "orbitmart", "label": "OrbitMart", "kind": "app"},
        {"id": "detector", "label": "Detectors", "kind": "defense"},
        {"id": "monitor", "label": "monitor.db", "kind": "store"},
        {"id": "lab_db", "label": "lab_vuln.db", "kind": "store"},
    ]
    if extra:
        nodes.extend(extra)
    return nodes


def sample_sqli() -> str:
    start = datetime(2026, 11, 16, 12, 0, 0, tzinfo=timezone.utc)
    run_id = "sample_sqli_demo"
    v = VULN_CATALOG["sqli"]
    vl = VULN_CATALOG["sqli_login"]
    vn = VULN_CATALOG["normal"]
    events = []
    step = 0

    def add(event, **kw):
        nonlocal step
        step += 1
        row = {
            "ts": _ts(start, step * 0.4),
            "run_id": run_id,
            "step_id": step,
            "event": event,
            "suite": "sqli",
            **kw,
        }
        events.append(row)

    add(
        "run_start",
        action="Start sqli simulation",
        log="Sample recorded run (offline demo)",
        result={"suite": "sqli", "base_url": "http://127.0.0.1:5000", "sample": True},
        nodes=_base_nodes(),
    )
    add(
        "command",
        command="python -m attacker.sqli_attack --base-url http://127.0.0.1:5000",
        action="Launch SQLi attack suite",
        vulnerability=v,
    )
    add(
        "log",
        log="Target=http://127.0.0.1:5000; payloads=3 unique → 6 compact/padded; normals=2",
        vulnerability=v,
    )

    payloads = [
        ("compact", "admin' OR '1'='1' --"),
        ("padded", "admin' OR '1' = '1' --"),
        ("compact", "1' UNION SELECT null,null,null,null--"),
        ("padded", "1' UNION SELECT null , null , null , null --"),
    ]
    for style, payload in payloads:
        add(
            "command",
            command=f"GET /search?q={payload!r}",
            action=f"SQLi catalog search ({style})",
            log=f"[sqli/{style}] search q={payload!r}",
            vulnerability=v,
            edge={"from": "attacker", "to": "lab_db", "label": "inject"},
        )
        add(
            "result",
            command=f"GET /search?q={payload!r}",
            action=f"SQLi catalog search ({style})",
            log=f"GET http://127.0.0.1:5000/search → 200 (label=sqli_{style})",
            result={
                "method": "GET",
                "url": "http://127.0.0.1:5000/search",
                "status_code": 200,
                "label": f"sqli_{style}",
            },
            vulnerability=v,
            edge={"from": "attacker", "to": "orbitmart", "label": f"sqli_{style}"},
            status="ok",
            duration_ms=42.0,
        )
        add(
            "command",
            command=f"POST /login username={payload!r}",
            action=f"SQLi-shaped login username ({style})",
            log=f"[sqli/{style}] login username={payload!r}",
            vulnerability=vl,
        )
        add(
            "result",
            command=f"POST /login username={payload!r}",
            action=f"SQLi-shaped login username ({style})",
            log="POST http://127.0.0.1:5000/login → 401 (label=sqli_" + style + ")",
            result={
                "method": "POST",
                "url": "http://127.0.0.1:5000/login",
                "status_code": 401,
                "label": f"sqli_{style}",
            },
            vulnerability=vl,
            status="ok",
            duration_ms=38.0,
        )

    for term in ("select version", "user profile"):
        add(
            "command",
            command=f"GET /search?q={term!r}",
            action="Benign catalog search",
            log=f"[normal] search q={term!r}",
            vulnerability=vn,
        )
        add(
            "result",
            command=f"GET /search?q={term!r}",
            action="Benign catalog search",
            log="GET http://127.0.0.1:5000/search → 200 (label=normal)",
            result={
                "method": "GET",
                "url": "http://127.0.0.1:5000/search",
                "status_code": 200,
                "label": "normal",
            },
            vulnerability=vn,
            status="ok",
            duration_ms=31.0,
        )

    score = {
        "attack_requests": 8,
        "normal_requests": 2,
        "attack_status_codes": {"200": 4, "401": 4},
        "normal_status_codes": {"200": 2},
        "outcome": "traffic_sent",
        "sample": True,
    }
    add("score", score=score, action="SQLi suite summary", status="completed")
    add(
        "run_end",
        action="Simulation finished",
        status="completed",
        score=score,
        log=f"Run {run_id} completed",
    )
    return _write("sqli_demo.jsonl", events)


def sample_xss() -> str:
    start = datetime(2026, 11, 16, 12, 10, 0, tzinfo=timezone.utc)
    run_id = "sample_xss_demo"
    v = VULN_CATALOG["xss"]
    vn = VULN_CATALOG["normal"]
    events = []
    step = 0

    def add(event, **kw):
        nonlocal step
        step += 1
        events.append(
            {
                "ts": _ts(start, step * 0.35),
                "run_id": run_id,
                "step_id": step,
                "event": event,
                "suite": "xss",
                **kw,
            }
        )

    add(
        "run_start",
        action="Start xss simulation",
        log="Sample recorded run (offline demo)",
        result={"suite": "xss", "sample": True},
        nodes=_base_nodes(),
    )
    add(
        "command",
        command="python -m attacker.xss_attack --base-url http://127.0.0.1:5000",
        action="Launch XSS attack suite",
        vulnerability=v,
    )
    for payload in (
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
    ):
        add(
            "command",
            command=f"GET /search?q={payload!r}",
            action="XSS catalog search",
            log=f"[xss] search q={payload!r}",
            vulnerability=v,
            edge={"from": "attacker", "to": "orbitmart", "label": "xss"},
        )
        add(
            "result",
            command=f"GET /search?q={payload!r}",
            action="XSS catalog search",
            log="GET /search → 200 (label=xss)",
            result={"method": "GET", "status_code": 200, "label": "xss"},
            vulnerability=v,
            status="ok",
            duration_ms=33.0,
        )
        add(
            "command",
            command="POST /register (username|email XSS)",
            action="XSS in register fields",
            log="[xss] register username/email payload",
            vulnerability=v,
        )
        add(
            "result",
            action="XSS in register username",
            log="POST /register → 200 (label=xss)",
            result={"method": "POST", "status_code": 200, "label": "xss"},
            vulnerability=v,
            status="ok",
            duration_ms=40.0,
        )
    add(
        "command",
        command="GET /search?q='laptop'",
        action="Benign search/register",
        log="[normal] search/register 'laptop'",
        vulnerability=vn,
    )
    add(
        "result",
        action="Benign catalog search",
        log="GET /search → 200 (label=normal)",
        result={"status_code": 200, "label": "normal"},
        vulnerability=vn,
        status="ok",
        duration_ms=28.0,
    )
    score = {
        "attack_requests": 6,
        "normal_requests": 1,
        "outcome": "traffic_sent",
        "sample": True,
    }
    add("score", score=score, action="XSS suite summary", status="completed")
    add("run_end", action="Simulation finished", status="completed", score=score)
    return _write("xss_demo.jsonl", events)


def sample_session() -> str:
    start = datetime(2026, 11, 16, 12, 20, 0, tzinfo=timezone.utc)
    run_id = "sample_session_demo"
    events = []
    step = 0

    def add(event, **kw):
        nonlocal step
        step += 1
        events.append(
            {
                "ts": _ts(start, step * 0.5),
                "run_id": run_id,
                "step_id": step,
                "event": event,
                "suite": "session",
                **kw,
            }
        )

    add(
        "run_start",
        action="Start session simulation",
        log="Sample recorded run (offline demo)",
        result={"suite": "session", "sample": True},
        nodes=_base_nodes(
            [{"id": "victim", "label": "Victim browser", "kind": "client"}]
        ),
    )
    add(
        "command",
        command="python -m attacker.session_attacks --base-url http://127.0.0.1:5000",
        action="Launch session-hijack suite",
        vulnerability=VULN_CATALOG["cookie_replay"],
    )
    add(
        "log",
        log="LAB_TRUST_FORWARDED_FOR=True; SESSION_REGENERATE_ON_LOGIN=False for fixation",
    )

    phases = [
        ("normal", "Benign multi-request sessions", "normal"),
        ("cookie_replay", "Cookie replay attack", "cookie_replay"),
        ("sidejacking", "Sidejacking attack", "sidejacking"),
        ("session_fixation", "Session fixation attack", "session_fixation"),
        ("session_prediction", "Session ID spray / prediction", "session_prediction"),
    ]
    for label, action, key in phases:
        add(
            "command",
            command=f"session: {label}",
            action=action,
            log=f"[{label}] begin",
            vulnerability=VULN_CATALOG[key],
        )
        add(
            "action",
            action=action,
            log=f"[{label}] execute labeled requests",
            vulnerability=VULN_CATALOG[key],
            edge={"from": "attacker", "to": "orbitmart", "label": label},
        )
        add(
            "result",
            action=action,
            log=f"GET /home → 200 (label={label})",
            result={"status_code": 200, "label": label},
            vulnerability=VULN_CATALOG[key],
            status="ok",
            duration_ms=45.0,
        )

    score = {"requests": 85, "outcome": "traffic_sent", "sample": True}
    add("score", score=score, action="Session suite summary", status="completed")
    add("run_end", action="Simulation finished", status="completed", score=score)
    return _write("session_demo.jsonl", events)


def sample_experiment() -> str:
    """Vulnerable (OFF) vs mitigated (MONITOR/BLOCK) comparison sample."""
    start = datetime(2026, 11, 16, 13, 0, 0, tzinfo=timezone.utc)
    run_id = "sample_experiment_demo"
    events = []
    step = 0

    def add(event, **kw):
        nonlocal step
        step += 1
        events.append(
            {
                "ts": _ts(start, step * 0.6),
                "run_id": run_id,
                "step_id": step,
                "event": event,
                "suite": "experiment",
                **kw,
            }
        )

    add(
        "run_start",
        action="Start experiment simulation",
        log="Sample OFF → MONITOR → BLOCK comparison (offline demo)",
        result={"suite": "experiment", "sample": True},
        nodes=_base_nodes([{"id": "soc", "label": "SOC Console", "kind": "ops"}]),
    )
    add(
        "command",
        command="python -m evaluation.evaluate --run-experiment",
        action="Launch evaluation experiment",
    )

    mode_scores = {
        "OFF": {
            "false_alarm_rate": 0.0,
            "alerts": 0,
            "sqli_recall": 0.0,
            "xss_recall": 0.0,
            "session_prediction_recall": 0.0,
        },
        "MONITOR": {
            "false_alarm_rate": 0.0,
            "alerts": 48,
            "sqli_recall": 0.94,
            "xss_recall": 0.88,
            "session_prediction_recall": 0.22,
        },
        "BLOCK": {
            "false_alarm_rate": 0.02,
            "alerts": 51,
            "sqli_recall": 0.96,
            "xss_recall": 0.90,
            "session_prediction_recall": 0.25,
        },
    }

    for mode, scores in mode_scores.items():
        add(
            "mode",
            mode=mode,
            action=f"Switch detection mode → {mode}",
            command=f"set_detection_mode({mode})",
            log=f"===== MODE {mode} =====",
            vulnerability=VULN_CATALOG["sqli"],
            mitigation=mitigation_for_mode(mode),
            edge={"from": "soc", "to": "detector", "label": mode},
        )
        if mode == "OFF":
            add(
                "result",
                action="Vulnerable /search probe (OFF)",
                log="vuln probe: injection returned rows (detectors idle)",
                result={
                    "status_code": 200,
                    "succeeded": True,
                    "blocked": False,
                    "payload": "admin' OR '1'='1' --",
                },
                vulnerability=VULN_CATALOG["sqli"],
                mitigation=mitigation_for_mode("OFF"),
                edge={"from": "attacker", "to": "lab_db", "label": "probe"},
            )
        add(
            "command",
            command="replay labeled attack suites",
            action=f"Replay traffic under {mode}",
            log=f"Running traffic suite in mode {mode}",
            mitigation=mitigation_for_mode(mode),
        )
        add(
            "action",
            action=f"SQLi + XSS + session suites ({mode})",
            log=f"Attack traffic completed under {mode}",
            mitigation=mitigation_for_mode(mode),
            edge={"from": "attacker", "to": "detector", "label": mode},
        )
        if mode == "BLOCK":
            add(
                "result",
                action="Blocked malicious request",
                log="GET /search → 403 (BLOCK)",
                result={"status_code": 403, "blocked": True, "label": "sqli_compact"},
                vulnerability=VULN_CATALOG["sqli"],
                mitigation=mitigation_for_mode("BLOCK"),
                status="blocked",
                duration_ms=22.0,
            )
        add(
            "score",
            mode=mode,
            action=f"Score mode {mode}",
            score={"mode": mode, **scores},
            mitigation=mitigation_for_mode(mode),
            status="completed",
        )

    final = {
        "primary_mode": "MONITOR",
        "false_alarm_rate": 0.0,
        "mode_summary": mode_scores,
        "dataset_scores": {
            "sqli": 0.9971,
            "xss": 0.9938,
            "session_binary": 0.9932,
            "session_multiclass": 0.983,
        },
        "outcome": "evaluated",
        "sample": True,
        "comparison": {
            "vulnerable": "OFF — attacks reach sinks, no alerts",
            "observed": "MONITOR — attacks reach sinks, alerts logged",
            "mitigated": "BLOCK — matching requests return 403",
        },
    }
    add("score", score=final, action="Evaluation complete", status="completed")
    add("run_end", action="Simulation finished", status="completed", score=final)
    return _write("experiment_demo.jsonl", events)


def main() -> int:
    paths = [
        sample_sqli(),
        sample_xss(),
        sample_session(),
        sample_experiment(),
    ]
    for p in paths:
        print(f"Wrote {p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
