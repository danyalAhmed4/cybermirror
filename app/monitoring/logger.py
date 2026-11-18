"""Flask request logging hooks for CyberMirror."""
from __future__ import annotations

import hashlib
import logging
import secrets
from typing import Any, Mapping, MutableMapping, Optional

from flask import Flask, current_app, g, has_request_context, request, session

from app.monitoring.store import get_store

logger = logging.getLogger(__name__)

_SKIP_PREFIXES = ("/static", "/dashboard")
_PASSWORD_FIELD_NAMES = frozenset({"password", "pass", "pwd"})


def _should_skip(path: str) -> bool:
    return any(path == prefix or path.startswith(prefix + "/") for prefix in _SKIP_PREFIXES)


def mask_form_values(form: Mapping[str, Any]) -> dict[str, Any]:
    """Copy form fields, masking password-like keys as '***'."""
    masked: dict[str, Any] = {}
    for key, value in form.items():
        if str(key).strip().lower() in _PASSWORD_FIELD_NAMES:
            masked[key] = "***"
        else:
            masked[key] = value
    return masked


def hash_session_id(session_id: Optional[str]) -> Optional[str]:
    """
    Store the session cookie only as SHA-256 plus the first 6 characters.

    Format: ``<sha256_hex>:<first6>``
    """
    if not session_id:
        return None
    digest = hashlib.sha256(session_id.encode("utf-8")).hexdigest()
    return f"{digest}:{session_id[:6]}"


def ensure_lab_session_sid() -> Optional[str]:
    """
    Stable lab session id stored inside the Flask session.

    Flask signed-cookie sessions change bytes whenever content changes, which
    breaks SID-unchanged / fixation signals. ``_cm_sid`` survives login when
    ``SESSION_REGENERATE_ON_LOGIN`` is False.
    """
    if not has_request_context():
        return None
    try:
        sid = session.get("_cm_sid")
        if not sid:
            sid = secrets.token_hex(16)
            session["_cm_sid"] = sid
            session.modified = True
        return str(sid)
    except Exception:
        return None


def resolve_session_hash(raw_cookie: Optional[str] = None) -> Optional[str]:
    """Prefer stable ``_cm_sid``; fall back to hashing the raw cookie value."""
    lab_sid = ensure_lab_session_sid()
    if lab_sid:
        return hash_session_id(lab_sid)
    return hash_session_id(raw_cookie)


def resolve_source_ip() -> Optional[str]:
    """
    Resolve client IP. ``X-Forwarded-For`` is trusted only when
    ``LAB_TRUST_FORWARDED_FOR`` is True (lab attack scripts).
    """
    remote = request.remote_addr
    try:
        trust = bool(current_app.config.get("LAB_TRUST_FORWARDED_FOR", False))
    except Exception:
        trust = False
    if trust:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            # First hop in the chain
            return forwarded.split(",")[0].strip() or remote
    return remote


def _collect_form_values() -> dict[str, Any]:
    """Capture POST/PUT/PATCH form bodies with password fields masked."""
    if request.method not in ("POST", "PUT", "PATCH"):
        return {}
    try:
        raw: MutableMapping[str, Any] = {}
        for key in request.form.keys():
            values = request.form.getlist(key)
            raw[key] = values[0] if len(values) == 1 else values
        return mask_form_values(raw)
    except Exception:
        return {}


def init_request_logging(app: Flask, db_path: Optional[str] = None) -> None:
    """Register before/after request hooks that persist every eligible request."""
    store = get_store(db_path)

    @app.before_request
    def _capture_request_meta():
        g.monitor_skip = _should_skip(request.path)
        if g.monitor_skip:
            return

        cookie_name = app.config.get("SESSION_COOKIE_NAME", "session")
        raw_session = request.cookies.get(cookie_name)

        # true_label is evaluation-only. Detection code must never read X-Test-Label.
        true_label = request.headers.get("X-Test-Label") or "unlabeled"

        g.monitor_meta = {
            "source_ip": resolve_source_ip(),
            "user_agent": request.headers.get("User-Agent"),
            "method": request.method,
            "path": request.path,
            "query_string": request.query_string.decode("utf-8", errors="replace"),
            "form_values": _collect_form_values(),
            "session_hash": resolve_session_hash(raw_session),
            "true_label": true_label,
            "referer": request.headers.get("Referer") or request.headers.get("Referrer"),
        }

    @app.after_request
    def _persist_request(response):
        if getattr(g, "monitor_skip", False):
            return response

        meta = getattr(g, "monitor_meta", None)
        if not meta:
            return response

        detection = getattr(g, "detection_result", None)
        detection_ms = getattr(detection, "detection_ms", None) if detection else None

        try:
            request_id = store.insert_request(
                source_ip=meta.get("source_ip"),
                user_agent=meta.get("user_agent"),
                method=meta.get("method"),
                path=meta.get("path"),
                query_string=meta.get("query_string"),
                form_values=meta.get("form_values") or {},
                session_hash=meta.get("session_hash"),
                status_code=response.status_code,
                true_label=meta.get("true_label") or "unlabeled",
                detection_ms=detection_ms,
                referer=meta.get("referer"),
            )
        except Exception:
            logger.exception("Failed to persist request log")
            return response

        pending = list(getattr(g, "pending_alerts", None) or [])
        for alert in pending:
            try:
                store.insert_alert(
                    request_id=request_id,
                    source_ip=meta.get("source_ip"),
                    attack_type=alert.get("attack_type"),
                    field=alert.get("field"),
                    probability=float(alert.get("probability") or 0.0),
                    action=alert.get("action") or "alert",
                )
            except Exception:
                logger.exception("Failed to persist alert")

        return response
