"""Built-in CyberMirror monitoring dashboard (admin-protected)."""
from __future__ import annotations

import csv
import io
import json
import os
import subprocess
import sys
import threading
import time
from functools import wraps

from flask import (
    Blueprint,
    Response,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from app.monitoring.store import get_store

dashboard_bp = Blueprint("dashboard", __name__, url_prefix="/dashboard")

_attack_lock = threading.Lock()
_attack_running = False


def admin_required(view):
    """Require dashboard admin session."""

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin_logged_in"):
            if request.path.startswith("/dashboard/api/"):
                return jsonify({"error": "unauthorized"}), 401
            return redirect(url_for("dashboard.login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def _vulnerable_enabled() -> bool:
    store = get_store()
    default = bool(current_app.config.get("ENABLE_VULNERABLE_PAGE", False))
    return store.is_vulnerable_page_enabled(default=default)


@dashboard_bp.route("/login", methods=["GET", "POST"])
def login():
    if session.get("admin_logged_in"):
        return redirect(url_for("dashboard.overview"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        expected_user = current_app.config.get("ADMIN_USERNAME", "admin")
        expected_pass = current_app.config.get("ADMIN_PASSWORD", "admin")
        if username == expected_user and password == expected_pass:
            session["admin_logged_in"] = True
            session["admin_username"] = username
            nxt = request.args.get("next") or url_for("dashboard.overview")
            if not str(nxt).startswith("/dashboard"):
                nxt = url_for("dashboard.overview")
            return redirect(nxt)
        flash("Invalid admin credentials.", "error")
        return render_template("dashboard/login.html"), 401

    return render_template("dashboard/login.html")


@dashboard_bp.route("/logout")
def logout():
    session.pop("admin_logged_in", None)
    session.pop("admin_username", None)
    flash("Signed out of console.", "success")
    return redirect(url_for("dashboard.login"))


@dashboard_bp.route("/")
@admin_required
def overview():
    return render_template("dashboard/overview.html", active="overview")


@dashboard_bp.route("/alerts")
@admin_required
def alerts_page():
    return render_template("dashboard/alerts.html", active="alerts")


@dashboard_bp.route("/sessions")
@admin_required
def sessions_page():
    return render_template("dashboard/sessions.html", active="sessions")


@dashboard_bp.route("/control")
@admin_required
def control_page():
    store = get_store()
    return render_template(
        "dashboard/control.html",
        active="control",
        mode=store.get_detection_mode(),
        vulnerable_enabled=_vulnerable_enabled(),
    )


@dashboard_bp.route("/evaluation")
@admin_required
def evaluation_page():
    return render_template("dashboard/evaluation.html", active="evaluation")


@dashboard_bp.route("/api/evaluation")
@admin_required
def api_evaluation():
    """Serve the latest results/evaluation.json for the Evaluation page."""
    root = os.path.abspath(os.path.join(current_app.root_path, ".."))
    path = os.path.join(root, "results", "evaluation.json")
    if not os.path.isfile(path):
        return jsonify({"ok": False, "error": "missing", "path": path}), 404
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    return jsonify({"ok": True, "path": path, "report": data})


# ---- JSON APIs (polled every 5s) ----


@dashboard_bp.route("/api/overview")
@admin_required
def api_overview():
    store = get_store()
    avg_ms = store.average_detection_ms()
    return jsonify(
        {
            "total_requests": store.count_requests(),
            "total_alerts": store.count_alerts(),
            "mode": store.get_detection_mode(),
            "avg_detection_ms": None if avg_ms is None else round(avg_ms, 2),
            "timeseries": store.timeseries_requests_alerts(limit_buckets=48),
            "alerts_by_type": store.alerts_by_type(),
            "vulnerable_enabled": _vulnerable_enabled(),
        }
    )


@dashboard_bp.route("/api/alerts")
@admin_required
def api_alerts():
    store = get_store()
    attack_type = (request.args.get("type") or "").strip() or None
    sort = (request.args.get("sort") or "desc").strip().lower()
    rows = store.list_alerts(attack_type=attack_type, sort=sort, limit=300)
    return jsonify({"alerts": rows, "types": store.list_alert_types()})


@dashboard_bp.route("/api/sessions")
@admin_required
def api_sessions():
    store = get_store()
    return jsonify({"sessions": store.list_sessions(limit=300)})


@dashboard_bp.route("/api/control", methods=["GET"])
@admin_required
def api_control_get():
    store = get_store()
    return jsonify(
        {
            "mode": store.get_detection_mode(),
            "vulnerable_enabled": _vulnerable_enabled(),
            "total_requests": store.count_requests(),
            "total_alerts": store.count_alerts(),
        }
    )


@dashboard_bp.route("/api/mode", methods=["POST"])
@admin_required
def api_set_mode():
    store = get_store()
    payload = request.get_json(silent=True) or {}
    mode = payload.get("mode") or request.form.get("mode")
    try:
        saved = store.set_detection_mode(str(mode))
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    return jsonify({"ok": True, "mode": saved})


@dashboard_bp.route("/api/vulnerable", methods=["POST"])
@admin_required
def api_set_vulnerable():
    store = get_store()
    payload = request.get_json(silent=True) or {}
    enabled = payload.get("enabled")
    if enabled is None:
        enabled = request.form.get("enabled")
    if isinstance(enabled, str):
        enabled = enabled.strip().lower() in ("1", "true", "yes", "on")
    saved = store.set_vulnerable_page_enabled(bool(enabled))
    # Keep Flask config in sync for templates that read config directly
    current_app.config["ENABLE_VULNERABLE_PAGE"] = saved
    return jsonify({"ok": True, "vulnerable_enabled": saved})


@dashboard_bp.route("/api/clear", methods=["POST"])
@admin_required
def api_clear_logs():
    store = get_store()
    store.clear_logs()
    return jsonify({"ok": True})


@dashboard_bp.route("/api/run-attacks", methods=["POST"])
@admin_required
def api_run_attacks():
    """
    Run the standard local lab attack suite against this Flask instance only.

    Equivalent to:
      python -m attacker.normal_traffic --count 40 --events-file …
      python -m attacker.sqli_attack --events-file …
      python -m attacker.xss_attack --events-file …
      python -m attacker.session_attacks --events-file …
      python -m evaluation.evaluate --from-db

    Each attacker step writes a JSONL under results/runs/ for Attack Viz replay.
    """
    global _attack_running

    if not _attack_lock.acquire(blocking=False):
        return jsonify({"ok": False, "error": "Attack suite already running"}), 409
    if _attack_running:
        _attack_lock.release()
        return jsonify({"ok": False, "error": "Attack suite already running"}), 409
    _attack_running = True

    port = int(current_app.config.get("FLASK_PORT") or 5000)
    base_url = f"http://127.0.0.1:{port}"
    root = os.path.abspath(os.path.join(current_app.root_path, ".."))
    py = sys.executable
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    runs_dir = os.path.join(root, "results", "runs")
    os.makedirs(runs_dir, exist_ok=True)
    # Keep only this suite's recordings — drop older Viz JSONL files.
    for name in os.listdir(runs_dir):
        if name.endswith(".jsonl"):
            try:
                os.remove(os.path.join(runs_dir, name))
            except OSError:
                pass

    def _events_path(label: str) -> str:
        return os.path.join(runs_dir, f"control_{stamp}_{label}.jsonl")

    viz_runs = {
        "normal_traffic": _events_path("normal"),
        "sqli_attack": _events_path("sqli"),
        "xss_attack": _events_path("xss"),
        "session_attacks": _events_path("session"),
    }

    steps = [
        (
            "normal_traffic",
            [
                py,
                "-m",
                "attacker.normal_traffic",
                "--base-url",
                base_url,
                "--count",
                "40",
                "--events-file",
                viz_runs["normal_traffic"],
            ],
        ),
        (
            "sqli_attack",
            [
                py,
                "-m",
                "attacker.sqli_attack",
                "--base-url",
                base_url,
                "--payload-source",
                "test",
                "--events-file",
                viz_runs["sqli_attack"],
            ],
        ),
        (
            "xss_attack",
            [
                py,
                "-m",
                "attacker.xss_attack",
                "--base-url",
                base_url,
                "--events-file",
                viz_runs["xss_attack"],
            ],
        ),
        (
            "session_attacks",
            [
                py,
                "-m",
                "attacker.session_attacks",
                "--base-url",
                base_url,
                "--events-file",
                viz_runs["session_attacks"],
            ],
        ),
    ]

    results = []
    started = time.time()
    try:
        for name, cmd in steps:
            step_started = time.time()
            try:
                proc = subprocess.run(
                    cmd,
                    cwd=root,
                    capture_output=True,
                    text=True,
                    timeout=600,
                    check=False,
                )
                entry = {
                    "step": name,
                    "ok": proc.returncode == 0,
                    "returncode": proc.returncode,
                    "seconds": round(time.time() - step_started, 1),
                    "stderr_tail": (proc.stderr or "")[-400:],
                }
                if name in viz_runs:
                    entry["events_file"] = os.path.relpath(viz_runs[name], root)
                results.append(entry)
                if proc.returncode != 0:
                    return jsonify(
                        {
                            "ok": False,
                            "error": f"{name} exited with code {proc.returncode}",
                            "base_url": base_url,
                            "elapsed_seconds": round(time.time() - started, 1),
                            "results": results,
                            "viz_runs": {
                                k: os.path.relpath(v, root) for k, v in viz_runs.items()
                            },
                        }
                    ), 500
            except subprocess.TimeoutExpired:
                results.append(
                    {
                        "step": name,
                        "ok": False,
                        "returncode": None,
                        "seconds": round(time.time() - step_started, 1),
                        "stderr_tail": "timeout",
                    }
                )
                return jsonify(
                    {
                        "ok": False,
                        "error": f"{name} timed out",
                        "base_url": base_url,
                        "elapsed_seconds": round(time.time() - started, 1),
                        "results": results,
                        "viz_runs": {
                            k: os.path.relpath(v, root) for k, v in viz_runs.items()
                        },
                    }
                ), 500

        # Score the labeled traffic just written to monitor.db
        eval_started = time.time()
        db_path = get_store().db_path
        eval_cmd = [
            py,
            "-m",
            "evaluation.evaluate",
            "--from-db",
            "--db",
            db_path,
        ]
        eval_proc = subprocess.run(
            eval_cmd,
            cwd=root,
            capture_output=True,
            text=True,
            timeout=180,
            check=False,
        )
        results.append(
            {
                "step": "evaluate",
                "ok": eval_proc.returncode == 0,
                "returncode": eval_proc.returncode,
                "seconds": round(time.time() - eval_started, 1),
                "stderr_tail": (eval_proc.stderr or "")[-400:],
            }
        )
        if eval_proc.returncode != 0:
            return jsonify(
                {
                    "ok": False,
                    "error": "Attack suite finished, but evaluation failed",
                    "base_url": base_url,
                    "elapsed_seconds": round(time.time() - started, 1),
                    "results": results,
                    "evaluated": False,
                    "viz_runs": {
                        k: os.path.relpath(v, root) for k, v in viz_runs.items()
                    },
                }
            ), 500
    finally:
        _attack_running = False
        _attack_lock.release()

    viz_rel = {k: os.path.relpath(v, root) for k, v in viz_runs.items()}
    return jsonify(
        {
            "ok": True,
            "base_url": base_url,
            "elapsed_seconds": round(time.time() - started, 1),
            "results": results,
            "evaluated": True,
            "viz_runs": viz_rel,
            "message": (
                "Attack suite + evaluation finished. "
                "Check Alerts, Evaluation, and Attack Viz (new control_* runs)."
            ),
        }
    )


@dashboard_bp.route("/api/export")
@admin_required
def api_export_csv():
    store = get_store()
    rows = store.export_requests_csv_rows()
    fieldnames = [
        "id",
        "timestamp",
        "source_ip",
        "user_agent",
        "method",
        "path",
        "query_string",
        "form_values",
        "session_hash",
        "status_code",
        "true_label",
        "detection_ms",
        "referer",
    ]
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=fieldnames, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({k: row.get(k) for k in fieldnames})
    data = buf.getvalue()
    return Response(
        data,
        mimetype="text/csv",
        headers={
            "Content-Disposition": "attachment; filename=cybermirror_requests.csv"
        },
    )
