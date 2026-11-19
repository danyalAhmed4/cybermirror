"""
Visualization blueprint: replay structured attack-simulation JSONL events.

Serves recorded runs under results/runs/ — no live attack execution from the UI.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime
from typing import Any

from flask import Blueprint, abort, jsonify, render_template, request

_VIZ_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.abspath(os.path.join(_VIZ_DIR, ".."))
RUNS_DIR = os.path.join(_ROOT, "results", "runs")

viz_bp = Blueprint(
    "viz",
    __name__,
    url_prefix="/viz",
    template_folder=os.path.join(_VIZ_DIR, "templates"),
    static_folder=os.path.join(_VIZ_DIR, "static"),
    static_url_path="/viz-static",
)

_SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")


def _ensure_dirs() -> None:
    os.makedirs(RUNS_DIR, exist_ok=True)


def _list_jsonl(directory: str, *, source: str) -> list[dict[str, Any]]:
    _ensure_dirs()
    if not os.path.isdir(directory):
        return []
    items: list[dict[str, Any]] = []
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".jsonl"):
            continue
        path = os.path.join(directory, name)
        if not os.path.isfile(path):
            continue
        meta = _peek_run(path)
        items.append(
            {
                "id": f"{source}:{name}",
                "source": source,
                "filename": name,
                "title": meta.get("title") or name.replace(".jsonl", "").replace("_", " "),
                "suite": meta.get("suite"),
                "run_id": meta.get("run_id"),
                "started_at": meta.get("started_at"),
                "status": meta.get("status"),
                "steps": meta.get("steps", 0),
                "sample": bool(meta.get("sample")),
            }
        )
    # newest first when timestamps exist
    items.sort(key=lambda x: x.get("started_at") or "", reverse=True)
    return items


def _peek_run(path: str) -> dict[str, Any]:
    meta: dict[str, Any] = {"steps": 0}
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                meta["steps"] = max(meta.get("steps", 0), int(ev.get("step_id") or 0))
                if not meta.get("run_id"):
                    meta["run_id"] = ev.get("run_id")
                if not meta.get("suite"):
                    meta["suite"] = ev.get("suite")
                if not meta.get("started_at") and ev.get("ts"):
                    meta["started_at"] = ev.get("ts")
                if ev.get("event") == "run_start":
                    result = ev.get("result") or {}
                    meta["sample"] = result.get("sample")
                    meta["title"] = ev.get("action") or meta.get("title")
                if ev.get("event") == "run_end":
                    meta["status"] = ev.get("status") or "completed"
                    if ev.get("score") and isinstance(ev["score"], dict):
                        meta["final_score"] = ev["score"]
    except OSError:
        pass
    return meta


def _resolve_run(run_id: str) -> tuple[str, str]:
    """Return (absolute_path, source) for recorded:filename or bare filename."""
    _ensure_dirs()
    source = "recorded"
    name = run_id
    if ":" in run_id:
        source, name = run_id.split(":", 1)
    if not _SAFE_NAME.match(name) or not name.endswith(".jsonl"):
        abort(400, description="Invalid run id")
    if source != "recorded":
        abort(404, description="Only recorded runs are available")
    path = os.path.join(RUNS_DIR, name)
    if not os.path.isfile(path):
        abort(404)
    return path, source


def _load_events(path: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def _summarize(events: list[dict[str, Any]]) -> dict[str, Any]:
    if not events:
        return {
            "steps": 0,
            "duration_ms": 0,
            "score": None,
            "status": "empty",
            "modes": [],
            "commands": 0,
            "results": 0,
        }
    first_ts = events[0].get("ts")
    last_ts = events[-1].get("ts")
    duration_ms = 0.0
    try:
        if first_ts and last_ts:
            t0 = datetime.fromisoformat(first_ts.replace("Z", "+00:00"))
            t1 = datetime.fromisoformat(last_ts.replace("Z", "+00:00"))
            duration_ms = max(0.0, (t1 - t0).total_seconds() * 1000.0)
    except ValueError:
        pass

    score = None
    status = "completed"
    modes: list[str] = []
    for ev in events:
        if ev.get("event") == "score":
            score = ev.get("score")
        if ev.get("event") == "run_end":
            status = ev.get("status") or status
            if ev.get("score") is not None:
                score = ev.get("score")
        if ev.get("mode"):
            m = str(ev["mode"]).upper()
            if m not in modes:
                modes.append(m)
        if isinstance(ev.get("duration_ms"), (int, float)):
            pass

    step_durations = [
        float(ev["duration_ms"])
        for ev in events
        if isinstance(ev.get("duration_ms"), (int, float))
    ]
    return {
        "steps": len(events),
        "duration_ms": round(duration_ms, 1),
        "avg_step_ms": round(sum(step_durations) / len(step_durations), 1)
        if step_durations
        else None,
        "score": score,
        "status": status,
        "modes": modes,
        "commands": sum(1 for e in events if e.get("event") == "command"),
        "results": sum(1 for e in events if e.get("event") == "result"),
        "suite": events[0].get("suite"),
        "run_id": events[0].get("run_id"),
        "comparison_ready": len(modes) >= 2,
    }


@viz_bp.route("/")
def index():
    """Main visualization console."""
    return render_template("viz/index.html")


@viz_bp.route("/api/runs")
def api_runs():
    recorded = _list_jsonl(RUNS_DIR, source="recorded")
    return jsonify({"samples": [], "recorded": recorded, "all": recorded})


@viz_bp.route("/api/runs/<path:run_id>")
def api_run(run_id: str):
    path, source = _resolve_run(run_id)
    events = _load_events(path)
    return jsonify(
        {
            "id": f"{source}:{os.path.basename(path)}",
            "source": source,
            "filename": os.path.basename(path),
            "events": events,
            "summary": _summarize(events),
        }
    )


@viz_bp.route("/api/compare")
def api_compare():
    """Return mode-level scores from an experiment-style run for side-by-side view."""
    run_id = request.args.get("run")
    if not run_id:
        recorded = _list_jsonl(RUNS_DIR, source="recorded")
        if not recorded:
            return jsonify({"run": None, "modes": {}, "summary": _summarize([])})
        run_id = recorded[0]["id"]
    path, source = _resolve_run(run_id)
    events = _load_events(path)
    by_mode: dict[str, Any] = {}
    for ev in events:
        mode = (ev.get("mode") or "").upper()
        if not mode:
            continue
        if ev.get("event") == "score" and isinstance(ev.get("score"), dict):
            by_mode[mode] = ev["score"]
        if ev.get("event") == "mode":
            by_mode.setdefault(mode, {})
            by_mode[mode]["mitigation"] = ev.get("mitigation")
            by_mode[mode]["vulnerability"] = ev.get("vulnerability")
    # Final nested mode_summary if present
    for ev in reversed(events):
        if ev.get("event") == "score" and isinstance(ev.get("score"), dict):
            ms = ev["score"].get("mode_summary")
            if isinstance(ms, dict):
                for m, block in ms.items():
                    by_mode.setdefault(m.upper() if isinstance(m, str) else m, {})
                    if isinstance(block, dict):
                        by_mode[m.upper() if isinstance(m, str) else str(m)].update(block)
            break
    return jsonify(
        {
            "run": f"{source}:{os.path.basename(path)}",
            "modes": by_mode,
            "summary": _summarize(events),
        }
    )
