"""
Structured simulation events for CyberMirror attack CLIs.

Opt-in via --events-file. Default CLI stdout behavior is unchanged.
Events are JSON Lines (one object per line) for the /viz replay UI.
"""
from __future__ import annotations

import json
import os
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Optional, TextIO

_lock = threading.Lock()
_emitter: Optional["EventEmitter"] = None

EVENT_TYPES = frozenset(
    {
        "run_start",
        "command",
        "action",
        "log",
        "result",
        "score",
        "mode",
        "run_end",
    }
)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_run_id(prefix: str = "run") -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{prefix}_{stamp}_{uuid.uuid4().hex[:8]}"


class EventEmitter:
    """Append-only JSONL writer for one simulation run."""

    def __init__(
        self,
        path: str,
        *,
        run_id: str,
        suite: str,
        base_url: str = "",
        meta: Optional[dict[str, Any]] = None,
    ) -> None:
        self.path = os.path.abspath(path)
        self.run_id = run_id
        self.suite = suite
        self.base_url = base_url
        self.meta = dict(meta or {})
        self._step = 0
        self._fh: Optional[TextIO] = None
        parent = os.path.dirname(self.path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._fh = open(self.path, "w", encoding="utf-8")
        self.emit(
            "run_start",
            action=f"Start {suite} simulation",
            log=f"Recording events → {self.path}",
            result={"suite": suite, "base_url": base_url, **self.meta},
            nodes=_default_nodes(suite),
        )

    @property
    def step_id(self) -> int:
        return self._step

    def emit(
        self,
        event: str,
        *,
        command: Optional[str] = None,
        action: Optional[str] = None,
        log: Optional[str] = None,
        result: Any = None,
        score: Any = None,
        vulnerability: Optional[dict[str, Any]] = None,
        mitigation: Optional[dict[str, Any]] = None,
        nodes: Optional[list[dict[str, Any]]] = None,
        edge: Optional[dict[str, Any]] = None,
        status: Optional[str] = None,
        mode: Optional[str] = None,
        duration_ms: Optional[float] = None,
        extra: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        if event not in EVENT_TYPES:
            raise ValueError(f"Unknown event type: {event}")
        self._step += 1
        payload: dict[str, Any] = {
            "ts": utc_now(),
            "run_id": self.run_id,
            "step_id": self._step,
            "event": event,
            "suite": self.suite,
        }
        if command is not None:
            payload["command"] = command
        if action is not None:
            payload["action"] = action
        if log is not None:
            payload["log"] = log
        if result is not None:
            payload["result"] = result
        if score is not None:
            payload["score"] = score
        if vulnerability is not None:
            payload["vulnerability"] = vulnerability
        if mitigation is not None:
            payload["mitigation"] = mitigation
        if nodes is not None:
            payload["nodes"] = nodes
        if edge is not None:
            payload["edge"] = edge
        if status is not None:
            payload["status"] = status
        if mode is not None:
            payload["mode"] = mode
        if duration_ms is not None:
            payload["duration_ms"] = duration_ms
        if extra:
            payload.update(extra)

        line = json.dumps(payload, ensure_ascii=False, default=str)
        with _lock:
            if self._fh is None:
                raise RuntimeError("EventEmitter is closed")
            self._fh.write(line + "\n")
            self._fh.flush()
        return payload

    def close(self, *, status: str = "completed", score: Any = None) -> None:
        if self._fh is None:
            return
        self.emit(
            "run_end",
            action="Simulation finished",
            status=status,
            score=score,
            log=f"Run {self.run_id} {status}",
        )
        with _lock:
            if self._fh is not None:
                self._fh.close()
                self._fh = None


def get_emitter() -> Optional[EventEmitter]:
    return _emitter


def configure_events(
    path: Optional[str],
    *,
    suite: str,
    base_url: str = "",
    run_id: Optional[str] = None,
    meta: Optional[dict[str, Any]] = None,
) -> Optional[EventEmitter]:
    """Activate a process-wide emitter when path is provided."""
    global _emitter
    if _emitter is not None:
        _emitter.close(status="replaced")
        _emitter = None
    if not path:
        return None
    _emitter = EventEmitter(
        path,
        run_id=run_id or new_run_id(suite),
        suite=suite,
        base_url=base_url,
        meta=meta,
    )
    return _emitter


def close_events(*, status: str = "completed", score: Any = None) -> None:
    global _emitter
    if _emitter is None:
        return
    _emitter.close(status=status, score=score)
    _emitter = None


def emit(event: str, **kwargs: Any) -> Optional[dict[str, Any]]:
    em = _emitter
    if em is None:
        return None
    return em.emit(event, **kwargs)


def add_events_arg(parser) -> None:
    """Attach --events-file to an argparse parser."""
    parser.add_argument(
        "--events-file",
        default=None,
        metavar="PATH",
        help=(
            "Optional JSONL path for structured simulation events "
            "(for /viz replay). Default: stdout-only, unchanged."
        ),
    )


def _default_nodes(suite: str) -> list[dict[str, Any]]:
    base = [
        {"id": "attacker", "label": "Attacker CLI", "kind": "client"},
        {"id": "orbitmart", "label": "OrbitMart", "kind": "app"},
        {"id": "detector", "label": "Detectors", "kind": "defense"},
        {"id": "monitor", "label": "monitor.db", "kind": "store"},
        {"id": "lab_db", "label": "lab_vuln.db", "kind": "store"},
    ]
    if suite.startswith("session"):
        base.append({"id": "victim", "label": "Victim browser", "kind": "client"})
    if suite.startswith("eval") or suite == "experiment":
        base.append({"id": "soc", "label": "SOC Console", "kind": "ops"})
    return base


# Vulnerability explanations (why each step works) — educational metadata only.
VULN_CATALOG: dict[str, dict[str, Any]] = {
    "sqli": {
        "id": "sqli-string-concat",
        "title": "SQL injection via string-concatenated query",
        "weakness": (
            "GET /search builds SQL with f-string interpolation of user input "
            "instead of parameterized queries."
        ),
        "sink": "app/routes/vulnerable.py → _run_vulnerable_search",
        "mitigation": (
            "Use parameterized queries / bound parameters; keep detection mode "
            "MONITOR or BLOCK; disable the lab catalog when not demonstrating."
        ),
        "cwe": "CWE-89",
    },
    "sqli_login": {
        "id": "sqli-auth-field",
        "title": "SQLi-shaped payload in login username",
        "weakness": (
            "Login accepts arbitrary username strings; detectors score the field "
            "even though MySQL auth itself is parameterized."
        ),
        "sink": "POST /login (username field inspected by SQLi detector)",
        "mitigation": "Input validation + detector BLOCK mode; never concatenate SQL.",
        "cwe": "CWE-89",
    },
    "xss": {
        "id": "xss-reflected-fields",
        "title": "Cross-site scripting (textbook reflected patterns)",
        "weakness": (
            "Untrusted script-like strings are submitted in search / register "
            "fields; detectors classify XSS feature patterns."
        ),
        "sink": "GET /search, POST /register (username/email)",
        "mitigation": "Output encoding, CSP, detector MONITOR/BLOCK; never trust raw HTML.",
        "cwe": "CWE-79",
    },
    "cookie_replay": {
        "id": "session-cookie-replay",
        "title": "Session cookie replay from a new client",
        "weakness": (
            "Session cookie alone authenticates; replaying it from another IP/UA "
            "is accepted unless detectors flag the anomaly."
        ),
        "sink": "Flask session cookie + /home",
        "mitigation": (
            "Bind sessions to client signals; regenerate IDs; enable session detector "
            "BLOCK; use HTTPS + Secure cookies in production."
        ),
        "cwe": "CWE-384",
    },
    "sidejacking": {
        "id": "session-sidejack",
        "title": "Sidejacking (stolen cookie on sensitive paths)",
        "weakness": "A second client reuses a captured session cookie on /home|/search|/logout.",
        "sink": "Stolen session cookie",
        "mitigation": "TLS everywhere, HttpOnly+Secure cookies, anomaly detection on IP/UA change.",
        "cwe": "CWE-294",
    },
    "session_fixation": {
        "id": "session-fixation",
        "title": "Session fixation",
        "weakness": (
            "If SESSION_REGENERATE_ON_LOGIN=False, a pre-planted session ID survives login "
            "so the attacker who knows that ID inherits the authenticated session."
        ),
        "sink": "Login without rotating _cm_sid / session cookie",
        "mitigation": "Always regenerate session ID on privilege change (default True).",
        "cwe": "CWE-384",
    },
    "session_prediction": {
        "id": "session-prediction",
        "title": "Session ID spraying / prediction",
        "weakness": "High rate of guessed session cookies against authenticated paths.",
        "sink": "Cookie spray → GET /home",
        "mitigation": "Cryptographically random session IDs + rate limits + session detector.",
        "cwe": "CWE-330",
    },
    "normal": {
        "id": "benign-baseline",
        "title": "Benign baseline traffic",
        "weakness": "None — establishes false-alarm baseline for detectors.",
        "sink": "OrbitMart register/login/search/logout",
        "mitigation": "N/A",
        "cwe": None,
    },
    "detection_off": {
        "id": "mode-off",
        "title": "Detection OFF (vulnerable posture)",
        "weakness": "Detectors do not raise alerts or block; attacks reach the sink unchecked.",
        "sink": "AttackDetector mode OFF",
        "mitigation": "Switch to MONITOR or BLOCK in SOC Control.",
        "cwe": None,
    },
    "detection_monitor": {
        "id": "mode-monitor",
        "title": "Detection MONITOR (observe)",
        "weakness": "Attacks still reach the app, but alerts are logged to monitor.db.",
        "sink": "AttackDetector mode MONITOR",
        "mitigation": "Use BLOCK for prevention; tune thresholds via .env.",
        "cwe": None,
    },
    "detection_block": {
        "id": "mode-block",
        "title": "Detection BLOCK (mitigated posture)",
        "weakness": "Mitigated — matching requests receive HTTP 403 blocked.html.",
        "sink": "AttackDetector mode BLOCK",
        "mitigation": "Already mitigated for detected payloads.",
        "cwe": None,
    },
}


def vuln_for(label: str) -> dict[str, Any]:
    """Map X-Test-Label / attack family to catalog entry."""
    lab = (label or "").strip().lower().replace("-", "_")
    if lab.startswith("sqli"):
        return VULN_CATALOG["sqli"]
    if lab.startswith("xss"):
        return VULN_CATALOG["xss"]
    if lab in VULN_CATALOG:
        return VULN_CATALOG[lab]
    if lab == "normal":
        return VULN_CATALOG["normal"]
    return {
        "id": lab or "unknown",
        "title": label or "Unknown",
        "weakness": "See lab documentation.",
        "sink": "",
        "mitigation": "",
        "cwe": None,
    }


def mitigation_for_mode(mode: str) -> dict[str, Any]:
    m = (mode or "").strip().upper()
    key = {
        "OFF": "detection_off",
        "MONITOR": "detection_monitor",
        "BLOCK": "detection_block",
    }.get(m, "detection_monitor")
    return VULN_CATALOG[key]
