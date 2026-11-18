"""Built-in CyberMirror monitoring dashboard (admin-protected)."""
from __future__ import annotations

import csv
import io
import json
import os
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
