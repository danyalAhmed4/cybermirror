#!/usr/bin/env python3
"""
Evaluate CyberMirror detectors using labeled traffic in monitor.db.

Joins requests.true_label with alerts by request_id, computes per-attack
precision/recall, false-alarm rate on normal traffic, SQLi compact vs padded
detection rates, and (optionally) repeats a live experiment in OFF / MONITOR /
BLOCK modes.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import sqlite3
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Optional
from urllib.parse import urlparse

import requests

_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from app.monitoring.store import get_store  # noqa: E402
from attacker.events import (  # noqa: E402
    add_events_arg,
    close_events,
    configure_events,
    emit,
    mitigation_for_mode,
    vuln_for,
)

RESULTS_DIR = os.path.join(_ROOT, "results")
RUNS_DIR = os.path.join(RESULTS_DIR, "runs")
DEFAULT_DB = os.path.join(_ROOT, "app", "monitoring", "monitor.db")
EVAL_CSV = os.path.join(RESULTS_DIR, "evaluation.csv")
EVAL_JSON = os.path.join(RESULTS_DIR, "evaluation.json")
MISSES_SQLI = os.path.join(RESULTS_DIR, "misses_sqli.csv")
MISSES_XSS = os.path.join(RESULTS_DIR, "misses_xss.csv")
MISSES_SESSION = os.path.join(RESULTS_DIR, "misses_session.csv")

ATTACK_TYPES = [
    "sqli",
    "xss",
    "cookie_replay",
    "sidejacking",
    "session_fixation",
    "session_prediction",
]

MISS_CSV_FIELDS = [
    "request_id",
    "true_label",
    "path",
    "payload_snippet",
    "caught",
]

DATASET_SCORES = {
    "sqli": 0.9971,
    "xss": 0.9938,
    "session_binary": 0.9932,
    "session_multiclass": 0.9830,
}

SESSION_TYPES = {
    "cookie_replay",
    "sidejacking",
    "session_fixation",
    "session_prediction",
}


def _norm_label(value: Optional[str]) -> str:
    if not value:
        return ""
    return (
        str(value)
        .strip()
        .lower()
        .replace("-", "_")
        .replace(" ", "_")
    )


def _family(true_label: str) -> str:
    """Map true_label to evaluation family (sqli_compact -> sqli)."""
    lab = _norm_label(true_label)
    if lab.startswith("sqli"):
        return "sqli"
    if lab.startswith("xss"):
        return "xss"
    if lab in SESSION_TYPES:
        return lab
    if lab == "normal":
        return "normal"
    return lab or "unlabeled"


def _alert_family(attack_type: str) -> str:
    lab = _norm_label(attack_type)
    if lab.startswith("sqli"):
        return "sqli"
    if lab.startswith("xss"):
        return "xss"
    # Multiclass session models emit Cookie_Replay etc.
    if lab in SESSION_TYPES:
        return lab
    if lab in {"hijacked"}:
        return "hijacked"
    return lab


def _safe_div(num: float, den: float) -> Optional[float]:
    if den <= 0:
        return None
    return num / den


def _payload_snippet(req: dict[str, Any], *, limit: int = 160) -> str:
    """Short payload view from query string or form values for miss CSVs."""
    blob = (req.get("query_string") or "").strip()
    if not blob:
        blob = (req.get("form_values") or "").strip()
    blob = " ".join(blob.split())
    if len(blob) > limit:
        return blob[: limit - 3] + "..."
    return blob


def _session_alert_counts(fam: str, attack: str) -> bool:
    """Session multiclass often confuses subtypes; any hijack family counts."""
    if fam == attack or fam == "hijacked":
        return True
    return attack in SESSION_TYPES and fam in SESSION_TYPES


def _request_caught(
    req: dict[str, Any],
    attack: str,
    alerts_by_request: dict[int, list[dict[str, Any]]],
    session_alerts: dict[str, list[dict[str, Any]]],
) -> bool:
    """Same catch rules as per-type recall (including session_hash fallback)."""
    rid = int(req["id"])
    for a in alerts_by_request.get(rid, []):
        fam = _alert_family(a.get("attack_type") or "")
        if fam == attack:
            return True
        if attack in SESSION_TYPES and _session_alert_counts(fam, attack):
            return True
    if attack in SESSION_TYPES and req.get("session_hash"):
        for a in session_alerts.get(str(req["session_hash"]), []):
            fam = _alert_family(a.get("attack_type") or "")
            if _session_alert_counts(fam, attack):
                return True
    return False


def _load_joined(db_path: str) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        requests_rows = [dict(r) for r in conn.execute("SELECT * FROM requests").fetchall()]
        alerts = [dict(r) for r in conn.execute("SELECT * FROM alerts").fetchall()]
    finally:
        conn.close()
    return requests_rows, alerts


def evaluate_db(db_path: str, *, mode: Optional[str] = None) -> dict[str, Any]:
    """Compute metrics from a monitor.db snapshot."""
    requests_rows, alerts = _load_joined(db_path)

    alerts_by_request: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for a in alerts:
        rid = a.get("request_id")
        if rid is not None:
            alerts_by_request[int(rid)].append(a)

    # Index session_hash -> alerts (via linked requests)
    req_by_id = {int(r["id"]): r for r in requests_rows if r.get("id") is not None}
    session_alerts: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for a in alerts:
        rid = a.get("request_id")
        if rid is None:
            continue
        req = req_by_id.get(int(rid))
        if req and req.get("session_hash"):
            session_alerts[str(req["session_hash"])].append(a)

    misses: dict[str, list[dict[str, Any]]] = {
        "sqli": [],
        "xss": [],
        "session": [],
    }
    per_type: dict[str, dict[str, Any]] = {}
    for attack in ATTACK_TYPES:
        labeled = [
            r
            for r in requests_rows
            if _family(r.get("true_label") or "") == attack
        ]
        attacks_sent = len(labeled)
        caught = 0
        for r in labeled:
            matched = _request_caught(r, attack, alerts_by_request, session_alerts)
            if matched:
                caught += 1
            else:
                miss_row = {
                    "request_id": int(r["id"]),
                    "true_label": r.get("true_label") or "",
                    "path": r.get("path") or "",
                    "payload_snippet": _payload_snippet(r),
                    "caught": 0,
                }
                if attack == "sqli":
                    misses["sqli"].append(miss_row)
                elif attack == "xss":
                    misses["xss"].append(miss_row)
                elif attack in SESSION_TYPES:
                    misses["session"].append(miss_row)

        missed = max(attacks_sent - caught, 0)

        # Precision: alerts of this family whose request true_label family matches
        type_alerts = [
            a for a in alerts if _alert_family(a.get("attack_type") or "") == attack
            or (attack in SESSION_TYPES and _alert_family(a.get("attack_type") or "") == "hijacked")
        ]
        # For hijacked binary alerts, attribute precision only when computing session_* aggregate later
        if attack in SESSION_TYPES:
            type_alerts = [
                a for a in alerts if _alert_family(a.get("attack_type") or "") == attack
            ]

        tp_alerts = 0
        for a in type_alerts:
            rid = a.get("request_id")
            if rid is None:
                continue
            req = req_by_id.get(int(rid))
            if not req:
                continue
            if _family(req.get("true_label") or "") == attack:
                tp_alerts += 1
            elif attack in SESSION_TYPES and _family(req.get("true_label") or "") in SESSION_TYPES:
                # session alert on a session-labeled request of same family only
                if _family(req.get("true_label") or "") == attack:
                    tp_alerts += 1

        precision = _safe_div(tp_alerts, len(type_alerts))
        recall = _safe_div(caught, attacks_sent)

        per_type[attack] = {
            "attack_type": attack,
            "attacks_sent": attacks_sent,
            "caught": caught,
            "missed": missed,
            "alerts_raised": len(type_alerts),
            "recall": recall,
            "precision": precision,
        }

    # Normal false alarms
    normal_reqs = [r for r in requests_rows if _family(r.get("true_label") or "") == "normal"]
    normal_with_alert = 0
    for r in normal_reqs:
        if alerts_by_request.get(int(r["id"])):
            normal_with_alert += 1
    false_alarm_rate = _safe_div(normal_with_alert, len(normal_reqs))

    # SQLi compact vs padded
    def _sqli_style_rate(style: str) -> dict[str, Any]:
        label = f"sqli_{style}"
        rows = [r for r in requests_rows if _norm_label(r.get("true_label")) == label]
        # Also accept true_label == style embedded in query if old data used plain sqli
        if not rows and style in {"compact", "padded"}:
            # Heuristic: padded payloads contain " OR " / " = " with spaces
            sqli_rows = [r for r in requests_rows if _family(r.get("true_label") or "") == "sqli"]
            rows = []
            for r in sqli_rows:
                blob = f"{r.get('query_string') or ''} {r.get('form_values') or ''}"
                is_padded = (" OR " in blob) or (" = " in blob) or ("( " in blob) or (" )" in blob)
                if style == "padded" and is_padded:
                    rows.append(r)
                if style == "compact" and not is_padded:
                    rows.append(r)
        caught = 0
        for r in rows:
            for a in alerts_by_request.get(int(r["id"]), []):
                if _alert_family(a.get("attack_type") or "") == "sqli":
                    caught += 1
                    break
        return {
            "style": style,
            "sent": len(rows),
            "caught": caught,
            "detection_rate": _safe_div(caught, len(rows)),
        }

    sqli_styles = {
        "compact": _sqli_style_rate("compact"),
        "padded": _sqli_style_rate("padded"),
    }

    # Confusion matrix: actual family vs predicted (primary alert family or benign)
    labels = ["normal"] + ATTACK_TYPES + ["other"]
    index = {name: i for i, name in enumerate(labels)}
    matrix = [[0 for _ in labels] for _ in labels]
    for r in requests_rows:
        actual = _family(r.get("true_label") or "")
        if actual not in index:
            actual = "other" if actual not in {"unlabeled", ""} else "other"
        if actual == "unlabeled":
            continue
        if actual not in index:
            actual = "other"
        al = alerts_by_request.get(int(r["id"]), [])
        if not al:
            pred = "normal"  # treated as benign prediction
        else:
            # Prefer first non-benign family
            pred = _alert_family(al[0].get("attack_type") or "") or "other"
            if pred == "hijacked":
                # map binary hijack onto cookie_replay bucket for display stability
                pred = "cookie_replay"
            if pred not in index:
                pred = "other"
        matrix[index[actual]][index[pred]] += 1

    # OFF-mode vuln success (when status_code present on labeled sqli /search)
    vuln_success = {"tested": 0, "succeeded": 0, "blocked": 0}
    for r in requests_rows:
        if _family(r.get("true_label") or "") != "sqli":
            continue
        if (r.get("path") or "") != "/search":
            continue
        vuln_success["tested"] += 1
        code = int(r.get("status_code") or 0)
        if code == 403:
            vuln_success["blocked"] += 1
        elif 200 <= code < 400:
            vuln_success["succeeded"] += 1

    return {
        "mode": mode,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "db_path": db_path,
        "totals": {
            "requests": len(requests_rows),
            "alerts": len(alerts),
            "normal_requests": len(normal_reqs),
            "normal_with_alert": normal_with_alert,
            "false_alarm_rate": false_alarm_rate,
        },
        "per_attack_type": per_type,
        "sqli_compact_vs_padded": sqli_styles,
        "vuln_page_outcomes": vuln_success,
        "confusion_matrix": {
            "labels": labels,
            "matrix": matrix,
        },
        "dataset_scores": DATASET_SCORES,
        "misses": misses,
    }


def _probe_vuln_page(base_url: str) -> dict[str, Any]:
    """In OFF mode, show SQLi still succeeds on the lab /search page."""
    base = base_url.rstrip("/")
    payload = "' OR '1'='1"
    try:
        r = requests.get(
            f"{base}/search",
            params={"q": payload},
            headers={"X-Test-Label": "sqli_compact"},
            timeout=15,
            allow_redirects=False,
        )
        body = r.text.lower()
        succeeded = r.status_code == 200 and (
            "aurora" in body or "results" in body or "<table" in body
        )
        blocked = r.status_code == 403 or "blocked" in body
        return {
            "status_code": r.status_code,
            "succeeded": bool(succeeded),
            "blocked": bool(blocked),
            "payload": payload,
        }
    except requests.RequestException as exc:
        return {"error": str(exc), "succeeded": False, "blocked": False}


def _run_traffic(base_url: str, *, quick: bool = True) -> None:
    """Send a labeled evaluation suite (imports attacker modules)."""
    # Local imports keep evaluate usable --from-db without requests attackers
    from attacker import sqli_attack, xss_attack, session_attacks, normal_traffic

    print("  → normal traffic (sample)")
    normal_traffic.simulate(base_url, 20 if quick else 40)

    print("  → SQLi attack suite")
    sqli_attack.run_attacks(base_url)

    print("  → XSS attack suite")
    xss_attack.run(base_url)

    print("  → session attack suite")
    session_attacks.run(base_url)


def run_experiment(base_url: str, db_path: str, *, quick: bool = True) -> dict[str, Any]:
    store = get_store(db_path)
    modes = ["OFF", "MONITOR", "BLOCK"]
    by_mode: dict[str, Any] = {}

    for mode in modes:
        print(f"\n===== MODE {mode} =====")
        emit(
            "mode",
            mode=mode,
            action=f"Switch detection mode → {mode}",
            command=f"set_detection_mode({mode})",
            log=f"===== MODE {mode} =====",
            vulnerability=vuln_for("sqli"),
            mitigation=mitigation_for_mode(mode),
            edge={"from": "soc", "to": "detector", "label": mode},
        )
        store.set_detection_mode(mode)
        store.clear_logs()
        time.sleep(0.3)

        vuln_probe = None
        if mode == "OFF":
            vuln_probe = _probe_vuln_page(base_url)
            print(f"  vuln probe: {vuln_probe}")
            emit(
                "result",
                action="Vulnerable /search probe (OFF)",
                log=f"vuln probe: {vuln_probe}",
                result=vuln_probe,
                vulnerability=vuln_for("sqli"),
                mitigation=mitigation_for_mode("OFF"),
                edge={"from": "attacker", "to": "lab_db", "label": "probe"},
            )

        emit(
            "command",
            command="replay labeled attack suites",
            action=f"Replay traffic under {mode}",
            log=f"Running traffic suite in mode {mode}",
            mitigation=mitigation_for_mode(mode),
        )
        _run_traffic(base_url, quick=quick)
        time.sleep(0.5)

        metrics = evaluate_db(db_path, mode=mode)
        if vuln_probe is not None:
            metrics["off_mode_vuln_probe"] = vuln_probe
            if mode == "OFF":
                metrics["note"] = (
                    "OFF mode: detectors idle; vulnerable /search should still "
                    "execute injected SQL against lab_vuln.db."
                )
        by_mode[mode] = metrics
        emit(
            "score",
            mode=mode,
            action=f"Score mode {mode}",
            score={
                "mode": mode,
                "false_alarm_rate": metrics["totals"].get("false_alarm_rate"),
                "alerts": metrics["totals"].get("alerts"),
                "sqli_recall": (metrics["per_attack_type"].get("sqli") or {}).get(
                    "recall"
                ),
                "xss_recall": (metrics["per_attack_type"].get("xss") or {}).get(
                    "recall"
                ),
            },
            mitigation=mitigation_for_mode(mode),
            status="completed",
        )

    monitor_block = by_mode.get("MONITOR", {})
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "base_url": base_url,
        "db_path": db_path,
        "dataset_scores": DATASET_SCORES,
        "modes": by_mode,
        # Convenience: prefer MONITOR snapshot for dashboard tables
        "primary_mode": "MONITOR",
        "per_attack_type": monitor_block.get("per_attack_type", {}),
        "totals": monitor_block.get("totals", {}),
        "sqli_compact_vs_padded": monitor_block.get("sqli_compact_vs_padded", {}),
        "confusion_matrix": monitor_block.get("confusion_matrix", {}),
        "misses": monitor_block.get("misses")
        or {"sqli": [], "xss": [], "session": []},
        "mode_summary": {
            m: {
                "false_alarm_rate": by_mode[m]["totals"].get("false_alarm_rate"),
                "total_alerts": by_mode[m]["totals"].get("alerts"),
                "sqli_recall": (by_mode[m]["per_attack_type"].get("sqli") or {}).get(
                    "recall"
                ),
                "xss_recall": (by_mode[m]["per_attack_type"].get("xss") or {}).get(
                    "recall"
                ),
                "vuln_probe": by_mode[m].get("off_mode_vuln_probe"),
                "vuln_page_outcomes": by_mode[m].get("vuln_page_outcomes"),
            }
            for m in modes
        },
    }


def flatten_csv_rows(report: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    modes = report.get("modes")
    if modes:
        for mode, block in modes.items():
            for attack, stats in (block.get("per_attack_type") or {}).items():
                rows.append(
                    {
                        "mode": mode,
                        "attack_type": attack,
                        "attacks_sent": stats.get("attacks_sent"),
                        "caught": stats.get("caught"),
                        "missed": stats.get("missed"),
                        "recall": stats.get("recall"),
                        "precision": stats.get("precision"),
                        "false_alarm_rate": (block.get("totals") or {}).get(
                            "false_alarm_rate"
                        ),
                        "dataset_score_ref": DATASET_SCORES.get(
                            "sqli"
                            if attack == "sqli"
                            else "xss"
                            if attack == "xss"
                            else "session_multiclass"
                            if attack in SESSION_TYPES
                            else ""
                        ),
                    }
                )
            for style, st in (block.get("sqli_compact_vs_padded") or {}).items():
                rows.append(
                    {
                        "mode": mode,
                        "attack_type": f"sqli_{style}",
                        "attacks_sent": st.get("sent"),
                        "caught": st.get("caught"),
                        "missed": (st.get("sent") or 0) - (st.get("caught") or 0),
                        "recall": st.get("detection_rate"),
                        "precision": "",
                        "false_alarm_rate": "",
                        "dataset_score_ref": DATASET_SCORES["sqli"],
                    }
                )
        return rows

    # Single-mode / from-db report
    mode = report.get("mode") or "current"
    for attack, stats in (report.get("per_attack_type") or {}).items():
        rows.append(
            {
                "mode": mode,
                "attack_type": attack,
                "attacks_sent": stats.get("attacks_sent"),
                "caught": stats.get("caught"),
                "missed": stats.get("missed"),
                "recall": stats.get("recall"),
                "precision": stats.get("precision"),
                "false_alarm_rate": (report.get("totals") or {}).get(
                    "false_alarm_rate"
                ),
                "dataset_score_ref": DATASET_SCORES.get(
                    "sqli"
                    if attack == "sqli"
                    else "xss"
                    if attack == "xss"
                    else "session_multiclass"
                    if attack in SESSION_TYPES
                    else ""
                ),
            }
        )
    return rows


def _collect_misses(report: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    """Prefer primary/MONITOR misses; fall back to any mode block that has them."""
    empty: dict[str, list[dict[str, Any]]] = {
        "sqli": [],
        "xss": [],
        "session": [],
    }
    if report.get("misses"):
        return report["misses"]  # type: ignore[return-value]
    modes = report.get("modes") or {}
    primary = report.get("primary_mode") or "MONITOR"
    if primary in modes and modes[primary].get("misses"):
        return modes[primary]["misses"]
    for block in modes.values():
        if block.get("misses"):
            return block["misses"]
    return empty


def write_miss_csvs(report: dict[str, Any]) -> dict[str, str]:
    """Write results/misses_{sqli,xss,session}.csv for the Insights → Retrain loop."""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    misses = _collect_misses(report)
    paths = {
        "sqli": MISSES_SQLI,
        "xss": MISSES_XSS,
        "session": MISSES_SESSION,
    }
    written: dict[str, str] = {}
    for key, path in paths.items():
        rows = misses.get(key) or []
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=MISS_CSV_FIELDS)
            writer.writeheader()
            for row in rows:
                writer.writerow({k: row.get(k, "") for k in MISS_CSV_FIELDS})
        written[key] = path
    return written


def save_report(report: dict[str, Any]) -> tuple[str, str]:
    os.makedirs(RESULTS_DIR, exist_ok=True)
    # Keep miss lists in JSON for debugging, but strip nested duplicates under modes
    # is fine — full report is useful.
    with open(EVAL_JSON, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)

    rows = flatten_csv_rows(report)
    fieldnames = [
        "mode",
        "attack_type",
        "attacks_sent",
        "caught",
        "missed",
        "recall",
        "precision",
        "false_alarm_rate",
        "dataset_score_ref",
    ]
    with open(EVAL_CSV, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    write_miss_csvs(report)
    return EVAL_CSV, EVAL_JSON


def load_saved_report() -> Optional[dict[str, Any]]:
    if not os.path.isfile(EVAL_JSON):
        return None
    with open(EVAL_JSON, encoding="utf-8") as fh:
        return json.load(fh)


def parse_args(argv: Optional[list[str]] = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Evaluate CyberMirror detection quality.")
    p.add_argument("--db", default=DEFAULT_DB, help="Path to monitor.db")
    p.add_argument(
        "--from-db",
        action="store_true",
        help="Evaluate existing DB only (no live traffic).",
    )
    p.add_argument(
        "--run-experiment",
        action="store_true",
        help="Clear logs and replay attacks in OFF/MONITOR/BLOCK.",
    )
    p.add_argument("--base-url", default="http://127.0.0.1:5000")
    p.add_argument(
        "--quick",
        action="store_true",
        default=True,
        help="Smaller normal-traffic sample (default on).",
    )
    add_events_arg(p)
    return p.parse_args(argv)


def main(argv: Optional[list[str]] = None) -> int:
    # Fix accidental bad import if store lacks LAB_VULN_DB_PATH
    args = parse_args(argv)
    os.makedirs(RESULTS_DIR, exist_ok=True)
    os.makedirs(RUNS_DIR, exist_ok=True)

    events_path = args.events_file
    if events_path is None and args.run_experiment:
        # Auto-record experiment runs for /viz history when flag omitted? No —
        # keep CLI quiet unless --events-file is set (acceptance: unchanged default).
        pass

    suite = "experiment" if args.run_experiment else "evaluate_db"
    configure_events(
        events_path,
        suite=suite,
        base_url=getattr(args, "base_url", ""),
        meta={"cli": "python -m evaluation.evaluate"},
    )
    if events_path:
        emit(
            "command",
            command=(
                "python -m evaluation.evaluate "
                + ("--run-experiment" if args.run_experiment else "--from-db")
            ),
            action="Launch evaluation",
        )

    if args.run_experiment:
        host = urlparse(args.base_url).hostname
        if host not in {"127.0.0.1", "localhost"} and not (
            host and (host.startswith("10.") or host.startswith("192.168.") or host.startswith("172."))
        ):
            # Soft check; attackers also enforce
            pass
        report = run_experiment(args.base_url, args.db, quick=args.quick)
    else:
        # Default: evaluate current DB
        mode = None
        try:
            mode = get_store(args.db).get_detection_mode()
        except Exception:
            mode = None
        single = evaluate_db(args.db, mode=mode)
        report = {
            "generated_at": single["generated_at"],
            "db_path": args.db,
            "dataset_scores": DATASET_SCORES,
            "primary_mode": mode or "current",
            "mode": mode or "current",
            "per_attack_type": single["per_attack_type"],
            "totals": single["totals"],
            "sqli_compact_vs_padded": single["sqli_compact_vs_padded"],
            "confusion_matrix": single["confusion_matrix"],
            "vuln_page_outcomes": single["vuln_page_outcomes"],
            "misses": single.get("misses") or {"sqli": [], "xss": [], "session": []},
            "modes": {mode or "current": single},
            "mode_summary": {
                mode or "current": {
                    "false_alarm_rate": single["totals"].get("false_alarm_rate"),
                    "total_alerts": single["totals"].get("alerts"),
                    "sqli_recall": (single["per_attack_type"].get("sqli") or {}).get(
                        "recall"
                    ),
                    "xss_recall": (single["per_attack_type"].get("xss") or {}).get(
                        "recall"
                    ),
                    "vuln_page_outcomes": single.get("vuln_page_outcomes"),
                }
            },
        }

    # For experiment runs, surface MONITOR misses at top level for CSV writers
    if "misses" not in report:
        report["misses"] = _collect_misses(report)

    csv_path, json_path = save_report(report)
    print("\n=== Evaluation summary (primary) ===")
    primary = report.get("per_attack_type") or {}
    for attack in ATTACK_TYPES:
        stats = primary.get(attack) or {}
        print(
            f"{attack:20s} sent={stats.get('attacks_sent', 0):4} "
            f"caught={stats.get('caught', 0):4} missed={stats.get('missed', 0):4} "
            f"recall={stats.get('recall')} precision={stats.get('precision')}"
        )
    totals = report.get("totals") or {}
    print(f"\nFalse alarm rate (normal): {totals.get('false_alarm_rate')}")
    print("SQLi compact vs padded:", report.get("sqli_compact_vs_padded"))
    print("Dataset reference scores:", DATASET_SCORES)
    print(f"\nWrote {csv_path}")
    print(f"Wrote {json_path}")
    misses = report.get("misses") or {}
    print(
        f"Wrote miss lists: "
        f"sqli={len(misses.get('sqli') or [])} "
        f"xss={len(misses.get('xss') or [])} "
        f"session={len(misses.get('session') or [])}"
    )
    print(f"  {MISSES_SQLI}")
    print(f"  {MISSES_XSS}")
    print(f"  {MISSES_SESSION}")

    score = {
        "primary_mode": report.get("primary_mode"),
        "false_alarm_rate": (report.get("totals") or {}).get("false_alarm_rate"),
        "mode_summary": report.get("mode_summary"),
        "dataset_scores": report.get("dataset_scores"),
        "outcome": "evaluated",
        "paths": {"csv": csv_path, "json": json_path},
    }
    emit("score", score=score, action="Evaluation complete", status="completed")
    close_events(status="completed", score=score)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
