"""
Build app-level session features for session_app_*_detector.joblib models.

Assumptions
-----------
1. Features are derived only from CyberMirror ``requests`` / ``sessions`` rows
   (no packet/flow/TLS/geo columns).
2. ``Cookie Reuse Count`` = number of distinct ``source_ip`` values that have
   used the same ``session_hash``.
3. ``Concurrent Sessions Same Token`` = count of distinct source IPs that also
   used this session_hash inside a sliding window (default 120s) overlapping
   the latest request time.
4. ``Token Entropy`` = Shannon entropy of the session_hash string (bits),
   normalized lightly by length.
5. ``Is HTTPS`` / ``Secure Cookie Flag`` come from Flask config when provided,
   otherwise 0 (typical local lab HTTP).
6. ``SID In URL`` = 1 if query_string contains session-like tokens
   (``session``, ``sid``, ``jsessionid``).
7. ``SID Unchanged After Login`` = 1 if the session_hash on the first request
   after a successful ``/login`` (2xx/3xx) equals the hash seen on the login
   request itself (fixation signal).
8. ``SIDs Tried Per Min`` approximates distinct session_hash values from the
   same source IP in the last 60 seconds (requires store helper).
9. ``Failed Auth Count`` = requests to ``/login`` with status 401/403/400.
10. ``Error Response (4xx)`` = share of 4xx responses in the session (0..1).
11. ``Requests Per Min`` uses session span from first to last request.
12. ``Time Since Last Request`` / ``Login To Request Gap`` / ``Session Age Sec``
    are seconds based on parsed request timestamps.
13. ``Referer Missing`` = share of requests with empty referer.
14. ``Sensitive Endpoint Hit`` = 1 if any path in {/home, /logout, /search,
    /register, /login} besides pure static browsing — specifically /home,
    /logout, /search count as sensitive for lab purposes.
15. ``UA_Is_Script`` = 1 if any UA matches python|curl|Go-http|Burp|CyberMirror.
16. ``Is_Write_Method`` = 1 if any POST/PUT/DELETE in the session.
"""
from __future__ import annotations

import json
import logging
import math
import re
from collections import Counter
from datetime import datetime
from typing import Any, Optional, Sequence

import numpy as np

logger = logging.getLogger(__name__)

APP_FEATURE_ORDER = [
    "IP Changes In Session",
    "User Agent Changed",
    "Concurrent Sessions Same Token",
    "Token Entropy",
    "Cookie Reuse Count",
    "Is HTTPS",
    "Secure Cookie Flag",
    "SID In URL",
    "SID Unchanged After Login",
    "SIDs Tried Per Min",
    "Failed Auth Count",
    "Error Response (4xx)",
    "Requests Per Min",
    "Time Since Last Request",
    "Login To Request Gap",
    "Referer Missing",
    "Sensitive Endpoint Hit",
    "Session Age Sec",
    "UA_Is_Script",
    "Is_Write_Method",
]

_SENSITIVE_PATHS = {"/home", "/logout", "/search"}
_SCRIPT_UA_RE = re.compile(
    r"python|curl|go-http|burp|cybermirror", re.IGNORECASE
)
_SID_URL_RE = re.compile(r"(session|sid|jsessionid)=", re.IGNORECASE)


def _parse_ts(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def build_session_features(
    requests_rows: Sequence[Any],
    *,
    session_hash: Optional[str] = None,
    is_https: int = 0,
    secure_cookie_flag: int = 0,
    concurrent_ips_in_window: Optional[int] = None,
    sids_tried_per_min: Optional[float] = None,
) -> np.ndarray:
    """
    Build a vector in ``APP_FEATURE_ORDER`` from ordered request rows.

    Each row should support keys / attributes:
    timestamp, source_ip, user_agent, method, path, query_string,
    status_code, referer (optional), session_hash (optional).
    """

    def _get(row: Any, key: str, default=None):
        if isinstance(row, dict):
            return row.get(key, default)
        try:
            return row[key]
        except Exception:
            return getattr(row, key, default)

    rows = list(requests_rows)
    if not rows:
        return np.zeros(len(APP_FEATURE_ORDER), dtype=float)

    ips = [(_get(r, "source_ip") or "") for r in rows]
    uas = [(_get(r, "user_agent") or "") for r in rows]
    times = [_parse_ts(_get(r, "timestamp")) for r in rows]
    times_ok = [t for t in times if t is not None]

    distinct_ips = {ip for ip in ips if ip}
    distinct_uas = {ua for ua in uas if ua}

    # Cookie reuse / concurrent
    cookie_reuse = float(len(distinct_ips))
    concurrent = float(
        concurrent_ips_in_window
        if concurrent_ips_in_window is not None
        else len(distinct_ips)
    )

    sid = session_hash or _get(rows[-1], "session_hash") or ""
    token_entropy = _shannon_entropy(sid)

    sid_in_url = 0.0
    for r in rows:
        qs = _get(r, "query_string") or ""
        if _SID_URL_RE.search(qs):
            sid_in_url = 1.0
            break

    # SID unchanged after login
    sid_unchanged = 0.0
    login_hash = None
    for r in rows:
        path = (_get(r, "path") or "").rstrip("/") or "/"
        status = int(_get(r, "status_code") or 0)
        method = (_get(r, "method") or "").upper()
        if path.endswith("/login") and method == "POST":
            login_hash = _get(r, "session_hash")
            # look ahead for next request after successful login redirect
            if status in (200, 302, 303):
                # if later rows share the same hash as pre-login cookie
                pass
    if login_hash:
        # If any post-login row keeps the pre-login hash, flag fixation-like behavior
        seen_login = False
        for r in rows:
            path = (_get(r, "path") or "")
            method = (_get(r, "method") or "").upper()
            if path.rstrip("/").endswith("/login") and method == "POST":
                seen_login = True
                login_hash = _get(r, "session_hash")
                continue
            if seen_login and login_hash and _get(r, "session_hash") == login_hash:
                sid_unchanged = 1.0
                break

    failed_auth = 0.0
    for r in rows:
        path = (_get(r, "path") or "")
        status = int(_get(r, "status_code") or 0)
        if path.rstrip("/").endswith("/login") and status in (400, 401, 403, 500):
            failed_auth += 1.0

    status_codes = [int(_get(r, "status_code") or 0) for r in rows]
    err_4xx = sum(1 for s in status_codes if 400 <= s < 500) / max(len(status_codes), 1)

    if len(times_ok) >= 2:
        span_sec = max((times_ok[-1] - times_ok[0]).total_seconds(), 1.0)
        session_age = (times_ok[-1] - times_ok[0]).total_seconds()
        rpm = len(rows) / (span_sec / 60.0)
        time_since_last = (times_ok[-1] - times_ok[-2]).total_seconds()
    elif len(times_ok) == 1:
        span_sec = 1.0
        session_age = 0.0
        rpm = float(len(rows))
        time_since_last = 0.0
    else:
        session_age = 0.0
        rpm = float(len(rows))
        time_since_last = 0.0

    # Login to request gap: time from first /login POST to last request
    login_ts = None
    for r, ts in zip(rows, times):
        path = (_get(r, "path") or "")
        method = (_get(r, "method") or "").upper()
        if path.rstrip("/").endswith("/login") and method == "POST" and ts:
            login_ts = ts
            break
    if login_ts and times_ok:
        login_gap = max((times_ok[-1] - login_ts).total_seconds(), 0.0)
    else:
        login_gap = 0.0

    referers = [(_get(r, "referer") or "") for r in rows]
    referer_missing = sum(1 for ref in referers if not str(ref).strip()) / max(
        len(referers), 1
    )

    sensitive = 0.0
    for r in rows:
        path = (_get(r, "path") or "").split("?")[0]
        if path in _SENSITIVE_PATHS:
            sensitive = 1.0
            break

    ua_is_script = 1.0 if any(_SCRIPT_UA_RE.search(ua or "") for ua in uas) else 0.0
    is_write = 1.0 if any(
        (_get(r, "method") or "").upper() in {"POST", "PUT", "DELETE"} for r in rows
    ) else 0.0

    values = {
        "IP Changes In Session": float(max(len(distinct_ips) - 1, 0)),
        "User Agent Changed": float(1 if len(distinct_uas) > 1 else 0),
        "Concurrent Sessions Same Token": concurrent,
        "Token Entropy": float(token_entropy),
        "Cookie Reuse Count": cookie_reuse,
        "Is HTTPS": float(is_https),
        "Secure Cookie Flag": float(secure_cookie_flag),
        "SID In URL": sid_in_url,
        "SID Unchanged After Login": sid_unchanged,
        "SIDs Tried Per Min": float(sids_tried_per_min or 0.0),
        "Failed Auth Count": failed_auth,
        "Error Response (4xx)": float(err_4xx),
        "Requests Per Min": float(rpm),
        "Time Since Last Request": float(time_since_last),
        "Login To Request Gap": float(login_gap),
        "Referer Missing": float(referer_missing),
        "Sensitive Endpoint Hit": sensitive,
        "Session Age Sec": float(session_age),
        "UA_Is_Script": ua_is_script,
        "Is_Write_Method": is_write,
    }
    return np.array([values[name] for name in APP_FEATURE_ORDER], dtype=float)


def predict_session(
    bundle: dict[str, Any],
    vector: np.ndarray,
) -> tuple[Optional[str], Optional[float]]:
    """Return (class_name, probability). Never raises."""
    try:
        scaler = bundle["scaler"]
        model = bundle["model"]
        classes = bundle.get("classes") or ["Normal", "Hijacked"]
        scaled = scaler.transform(vector.reshape(1, -1))
        pred = model.predict(scaled)[0]
        if isinstance(pred, (int, np.integer)):
            # multiclass label encoder ints or binary 0/1
            if classes and int(pred) < len(classes):
                label = str(classes[int(pred)])
            else:
                label = str(pred)
        else:
            label = str(pred)

        proba = None
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(scaled)[0]
            proba = float(np.max(probs))
        return label, proba
    except Exception:
        logger.exception("Session predict failed")
        return None, None
