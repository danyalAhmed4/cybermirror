"""
Runtime attack detection for CyberMirror.

Loads .joblib models once at startup. Detection must never read X-Test-Label
or true_label — those exist only for offline evaluation.
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import joblib
from flask import Flask, g, render_template, request

from app.monitoring.features_session import (
    APP_FEATURE_ORDER,
    build_session_features,
    predict_session,
)
from app.monitoring.features_xss import predict_xss
from app.monitoring.logger import _PASSWORD_FIELD_NAMES, _should_skip
from app.monitoring.store import MonitorStore, get_store

logger = logging.getLogger(__name__)

VALID_MODES = frozenset({"OFF", "MONITOR", "BLOCK"})

# Identity-like fields: only run XSS if the value looks payload-ish
_IDENTITY_FIELD_TOKENS = frozenset(
    {"username", "user", "email", "mail", "name", "firstname", "lastname"}
)
_XSS_HINT_MARKERS = (
    "<",
    ">",
    "javascript:",
    "onerror",
    "onload",
    "onclick",
    "<script",
    "%3c",
    "&#",
    "svg",
    "iframe",
    "x3c",
    "\\x3c",
    "alert(",
    "prompt(",
)

# Prefer app-retrained session models when present
_MODEL_FILES = {
    "sqli": "sqli_detector.joblib",
    "xss": "xss_detector.joblib",
    "session_binary": "session_app_binary_detector.joblib",
    "session_multiclass": "session_app_multiclass_detector.joblib",
    # Fallbacks if app models are missing
    "session_binary_legacy": "session_binary_detector.joblib",
    "session_multiclass_legacy": "session_multiclass_detector.joblib",
}


@dataclass
class DetectionHit:
    attack_type: str
    field: str
    probability: float


@dataclass
class DetectionResult:
    mode: str = "OFF"
    detection_ms: float = 0.0
    hits: list[DetectionHit] = field(default_factory=list)

    @property
    def should_block(self) -> bool:
        return self.mode == "BLOCK" and bool(self.hits)


class AttackDetector:
    """Holds loaded models and runs per-request / per-session checks."""

    def __init__(self, models_dir: str, store: MonitorStore, app: Optional[Flask] = None):
        self.models_dir = models_dir
        self.store = store
        self.app = app
        self.models: dict[str, Any] = {}
        self._load_models()

    def _load_models(self) -> None:
        for name, filename in _MODEL_FILES.items():
            path = os.path.join(self.models_dir, filename)
            if not os.path.isfile(path):
                logger.warning("Model not found, skipping: %s", path)
                continue
            try:
                self.models[name] = joblib.load(path)
                logger.info("Loaded model %s from %s", name, path)
            except Exception:
                logger.exception("Failed to load model %s from %s", name, path)

        # Use legacy session models only when app-specific ones are absent
        if "session_binary" not in self.models and "session_binary_legacy" in self.models:
            self.models["session_binary"] = self.models["session_binary_legacy"]
        if (
            "session_multiclass" not in self.models
            and "session_multiclass_legacy" in self.models
        ):
            self.models["session_multiclass"] = self.models["session_multiclass_legacy"]

    def get_mode(self) -> str:
        try:
            mode = self.store.get_detection_mode()
        except Exception:
            logger.exception("Failed to read detection_mode; defaulting to OFF")
            return "OFF"
        return mode if mode in VALID_MODES else "OFF"

    def _cfg_float(self, key: str, default: float) -> float:
        if self.app is None:
            return default
        try:
            return float(self.app.config.get(key, default))
        except Exception:
            return default

    def _cfg_int(self, key: str, default: int) -> int:
        if self.app is None:
            return default
        try:
            return int(self.app.config.get(key, default))
        except Exception:
            return default

    @staticmethod
    def _field_base(field_name: str) -> str:
        # "query.q" / "form.username" -> last segment
        return str(field_name).rsplit(".", 1)[-1].strip().lower()

    def _should_score_xss(self, field_name: str, text: str) -> bool:
        """Skip short / marker-free values that inflate XSS false alarms."""
        sample = str(text or "")
        min_len = self._cfg_int("XSS_MIN_TEXT_LEN", 4)
        if len(sample.strip()) < min_len:
            return False
        lowered = sample.lower()
        has_marker = any(marker in lowered for marker in _XSS_HINT_MARKERS)
        # Identity fields and plain catalog terms: only score when payload-like
        base = self._field_base(field_name)
        if base in _IDENTITY_FIELD_TOKENS or not has_marker:
            return has_marker
        return True

    @staticmethod
    def _passes_threshold(
        label: Optional[int],
        proba: Optional[float],
        min_proba: float,
    ) -> bool:
        """Alert when confidence clears the floor (fallback to label if no proba)."""
        if proba is not None:
            return float(proba) >= float(min_proba)
        return label == 1

    def set_mode(self, mode: str) -> str:
        return self.store.set_detection_mode(mode)

    def _session_min_requests(self) -> int:
        if self.app is not None:
            try:
                return int(self.app.config.get("SESSION_DETECT_MIN_REQUESTS", 5))
            except Exception:
                return 5
        return 5

    def _predict_sqli(self, text: str) -> tuple[Optional[int], Optional[float]]:
        model = self.models.get("sqli")
        if model is None or text is None:
            return None, None
        # Match training/sql_injection_detection.py cleaning
        sample = str(text).strip()
        if sample == "":
            return None, None
        try:
            label = int(model.predict([sample])[0])
            proba = None
            if hasattr(model, "predict_proba"):
                proba = float(model.predict_proba([sample])[0][1])
            return label, proba
        except Exception:
            logger.exception("SQLi model inference failed")
            return None, None


    def _predict_xss_field(
        self, field_name: str, text: str, request_url: str
    ) -> tuple[Optional[int], Optional[float]]:
        bundle = self.models.get("xss")
        if bundle is None or not text or not str(text).strip():
            return None, None
        try:
            # Score the field both as URL content and as a form value
            label, proba, _ = predict_xss(
                request_url or text,
                {field_name: text},
                response_html=None,
                bundle=bundle if isinstance(bundle, dict) else None,
            )
            return label, proba
        except Exception:
            logger.exception("XSS model inference failed")
            return None, None

    def _iter_inspectable_fields(self) -> list[tuple[str, str]]:
        fields: list[tuple[str, str]] = []
        try:
            for key in request.args.keys():
                if str(key).strip().lower() in _PASSWORD_FIELD_NAMES:
                    continue
                for value in request.args.getlist(key):
                    if value is None:
                        continue
                    fields.append((f"query.{key}", str(value)))
        except Exception:
            logger.exception("Failed to read query parameters for detection")

        try:
            if request.method in ("POST", "PUT", "PATCH"):
                for key in request.form.keys():
                    if str(key).strip().lower() in _PASSWORD_FIELD_NAMES:
                        continue
                    for value in request.form.getlist(key):
                        if value is None:
                            continue
                        fields.append((f"form.{key}", str(value)))
        except Exception:
            logger.exception("Failed to read form values for detection")
        return fields

    def inspect_request(self) -> DetectionResult:
        """Run SQLi + XSS detectors for the current Flask request."""
        mode = self.get_mode()
        result = DetectionResult(mode=mode)
        if mode == "OFF":
            return result

        t0 = time.perf_counter()
        sqli_min = self._cfg_float("SQLI_MIN_PROBA", 0.65)
        xss_min = self._cfg_float("XSS_MIN_PROBA", 0.85)
        try:
            request_url = request.url
            for field_name, text in self._iter_inspectable_fields():
                # SQLi — require confidence floor to reduce borderline FPs
                label, proba = self._predict_sqli(text)
                if self._passes_threshold(label, proba, sqli_min):
                    result.hits.append(
                        DetectionHit(
                            attack_type="sqli",
                            field=field_name,
                            probability=float(proba if proba is not None else 1.0),
                        )
                    )

                # XSS — skip benign identity fields; require higher confidence
                if self._should_score_xss(field_name, text):
                    x_label, x_proba = self._predict_xss_field(
                        field_name, text, request_url
                    )
                    if self._passes_threshold(x_label, x_proba, xss_min):
                        result.hits.append(
                            DetectionHit(
                                attack_type="xss",
                                field=field_name,
                                probability=float(
                                    x_proba if x_proba is not None else 1.0
                                ),
                            )
                        )

            # Session check — include the in-flight request (logging is after_request)
            try:
                cookie_name = (
                    self.app.config.get("SESSION_COOKIE_NAME", "session")
                    if self.app is not None
                    else "session"
                )
                raw_sid = request.cookies.get(cookie_name)
                from app.monitoring.logger import resolve_session_hash, resolve_source_ip

                session_hash = resolve_session_hash(raw_sid)
                if session_hash:
                    source_ip = resolve_source_ip()
                    current_row = {
                        "timestamp": datetime.now(timezone.utc).strftime(
                            "%Y-%m-%d %H:%M:%S"
                        ),
                        "source_ip": source_ip,
                        "user_agent": request.headers.get("User-Agent"),
                        "method": request.method,
                        "path": request.path,
                        "query_string": request.query_string.decode(
                            "utf-8", errors="replace"
                        ),
                        "status_code": 0,
                        "referer": request.headers.get("Referer")
                        or request.headers.get("Referrer"),
                        "session_hash": session_hash,
                    }
                    result.hits.extend(
                        self.inspect_session(
                            session_hash,
                            source_ip=source_ip,
                            current_request=current_row,
                        )
                    )
            except Exception:
                logger.exception("Inline session check failed")
        except Exception:
            logger.exception("Unexpected error during request inspection")
        finally:
            result.detection_ms = (time.perf_counter() - t0) * 1000.0
        return result

    def inspect_session(
        self,
        session_hash: Optional[str],
        *,
        source_ip: Optional[str] = None,
        request_id: Optional[int] = None,
        current_request: Optional[dict[str, Any]] = None,
    ) -> list[DetectionHit]:
        """
        Run session detector when the session has at least N requests
        (logged history + optional in-flight request from before_request).

        Session-prediction sprays are allowed earlier when many distinct SIDs
        are seen from the same IP in the last minute.
        """
        hits: list[DetectionHit] = []
        if not session_hash:
            return hits
        if self.get_mode() == "OFF":
            return hits

        multi = self.models.get("session_multiclass")
        binary = self.models.get("session_binary")
        bundle = multi if isinstance(multi, dict) else None
        if bundle is None and isinstance(binary, dict):
            bundle = binary
        if bundle is None:
            return hits

        try:
            rows = list(self.store.fetch_requests_for_session(session_hash))
            if current_request:
                rows.append(current_request)

            now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            window_start = (
                datetime.now(timezone.utc) - timedelta(seconds=120)
            ).strftime("%Y-%m-%d %H:%M:%S")
            concurrent = self.store.count_distinct_ips_for_session(
                session_hash, since_ts=window_start
            )
            if current_request and current_request.get("source_ip"):
                # Count the in-flight IP toward concurrent reuse
                prior_ips = {
                    (r.get("source_ip") if isinstance(r, dict) else None)
                    for r in rows[:-1]
                }
                prior_ips.discard(None)
                if current_request["source_ip"] not in prior_ips:
                    concurrent = max(concurrent, len(prior_ips) + 1)

            sids_per_min = 0.0
            if source_ip:
                sids_per_min = self.store.count_sids_for_ip_last_minute(
                    source_ip, now_ts=now
                )
                # In-flight SID is not in DB yet — count it once if new
                prior_only = rows[:-1] if current_request else rows
                already_logged = any(
                    (r.get("session_hash") if isinstance(r, dict) else None)
                    == session_hash
                    for r in prior_only
                )
                if not already_logged:
                    sids_per_min += 1.0

            min_req = self._session_min_requests()
            # SID spray: enough distinct tokens from one IP → score immediately
            spray_hit = sids_per_min >= max(float(min_req), 5.0)
            if len(rows) < min_req and not spray_hit:
                return hits

            # Dataset was HTTPS-heavy; lab twin is HTTP. Keep channel flags at 1
            # so unused TLS features do not dominate live scores.
            is_https = 1
            secure_flag = 1
            if self.app is not None and self.app.config.get("SESSION_COOKIE_SECURE"):
                is_https = 1
                secure_flag = 1

            vector = build_session_features(
                rows,
                session_hash=session_hash,
                is_https=is_https,
                secure_cookie_flag=secure_flag,
                concurrent_ips_in_window=concurrent,
                sids_tried_per_min=sids_per_min,
            )
            feat_names = bundle.get("features") or APP_FEATURE_ORDER
            if len(vector) != len(feat_names):
                current = {
                    name: float(vector[i]) if i < len(vector) else 0.0
                    for i, name in enumerate(APP_FEATURE_ORDER)
                }
                aligned = [float(current.get(name, 0.0)) for name in feat_names]
                vector = __import__("numpy").array(aligned, dtype=float)

            feat_map = {
                name: float(vector[i]) if i < len(vector) else 0.0
                for i, name in enumerate(feat_names)
            }
            sid_unchanged = feat_map.get("SID Unchanged After Login", 0.0) >= 1.0
            ip_changed = feat_map.get("IP Changes In Session", 0.0) >= 1.0
            ua_changed = feat_map.get("User Agent Changed", 0.0) >= 1.0
            ua_script = feat_map.get("UA_Is_Script", 0.0) >= 1.0
            cookie_reuse = feat_map.get("Cookie Reuse Count", 0.0)
            # Cookie/IP/UA reuse — not SID-spray alone (many lab users share 127.0.0.1)
            strong_reuse = (
                ip_changed
                or ua_changed
                or (sid_unchanged and ip_changed)
                or cookie_reuse >= 2.0
            )

            label, proba = predict_session(bundle, vector)

            def _norm_atk(value: Optional[str]) -> str:
                return (value or "").lower().replace("-", "_").replace(" ", "_")

            atk = _norm_atk(str(label) if label else "")

            # Fixation from the model requires unchanged SID (spray must not unlock it)
            if atk == "session_fixation" and not sid_unchanged:
                label, proba, atk = None, None, ""

            # Prediction: lab spray uses scripted UAs. Many OrbitMart users on
            # one NAT (127.0.0.1) look like SID spray to the dataset model.
            if atk == "session_prediction" and not ua_script:
                label, proba, atk = None, None, ""

            # Fall back to binary when multiclass is Normal / gated away
            if (not label or atk in {"", "normal", "0"}) and isinstance(binary, dict):
                blabel, bproba = predict_session(binary, vector)
                if blabel and _norm_atk(str(blabel)) not in {"normal", "0"}:
                    if strong_reuse:
                        label, proba = blabel, bproba
                        atk = _norm_atk(str(blabel))

            # Lab twin: fixation = stable SID across login AND other-IP reuse
            if sid_unchanged and ip_changed and len(rows) >= min_req:
                if atk in {"", "normal", "0", "session_fixation"}:
                    label = "Session_Fixation"
                    proba = max(float(proba or 0.0), 0.85)
                    atk = "session_fixation"

            # SID-spray path: only Session_Prediction (or scripted UA) may alert
            if spray_hit and len(rows) < min_req:
                if atk not in {"session_prediction"} and not (
                    ua_script and atk in {"hijacked", "session_prediction"}
                ):
                    if atk != "session_prediction":
                        label, proba, atk = None, None, ""

            if not label:
                return hits
            atk = _norm_atk(str(label))
            if atk in {"normal", "0", ""}:
                return hits
            # Final gates (re-check after all promotions)
            if atk == "session_prediction" and not ua_script:
                return hits
            if atk == "session_fixation" and not (sid_unchanged and ip_changed):
                return hits

            session_min = self._cfg_float("SESSION_MIN_PROBA", 0.70)
            conf = float(proba if proba is not None else 0.0)
            if proba is not None and conf < session_min:
                return hits

            hits.append(
                DetectionHit(
                    attack_type=str(label),
                    field=f"session:{session_hash[:18]}",
                    probability=float(proba if proba is not None else 1.0),
                )
            )
        except Exception:
            logger.exception("Session inspection failed (request_id=%s)", request_id)
        return hits


_detector: Optional[AttackDetector] = None


def get_detector() -> Optional[AttackDetector]:
    return _detector


def init_detector(app: Flask, store: Optional[MonitorStore] = None) -> AttackDetector:
    """Load models once and register before_request detection hooks."""
    global _detector

    models_dir = app.config.get("MODELS_DIR") or os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
        "models",
    )
    monitor_store = store or get_store()

    config_mode = str(app.config.get("DETECTION_MODE", "OFF")).strip().upper()
    if config_mode in VALID_MODES and monitor_store.get_detection_mode() == "OFF":
        if config_mode != "OFF":
            monitor_store.set_detection_mode(config_mode)

    _detector = AttackDetector(models_dir=models_dir, store=monitor_store, app=app)

    @app.before_request
    def _run_detection():
        g.detection_result = DetectionResult(mode="OFF")
        g.pending_alerts = []
        if _should_skip(request.path):
            return None
        if _detector is None:
            return None

        try:
            result = _detector.inspect_request()
        except Exception:
            logger.exception("Detector inspect_request crashed")
            result = DetectionResult(mode="OFF")

        g.detection_result = result
        action = "block" if result.should_block else "alert"
        g.pending_alerts = [
            {
                "attack_type": hit.attack_type,
                "field": hit.field,
                "probability": hit.probability,
                "action": action if result.mode != "OFF" else "none",
            }
            for hit in result.hits
        ]

        if result.should_block:
            top = result.hits[0] if result.hits else None
            try:
                return (
                    render_template(
                        "blocked.html",
                        attack_type=top.attack_type if top else "unknown",
                        probability=top.probability if top else None,
                        mode=result.mode,
                    ),
                    403,
                )
            except Exception:
                logger.exception("Failed to render blocked page")
                return (
                    "<h1>Request blocked</h1><p>This request was blocked by "
                    "CyberMirror detection.</p>",
                    403,
                    {"Content-Type": "text/html; charset=utf-8"},
                )
        return None

    return _detector
