/* CyberMirror Attack Viz — timeline replay of JSONL simulation events */
(() => {
  "use strict";

  const state = {
    runId: null,
    events: [],
    index: -1,
    playing: false,
    speed: 1,
    timer: null,
    nodes: [],
    activeEdge: null,
  };

  const NODE_LAYOUT = {
    attacker: { x: 90, y: 70 },
    victim: { x: 90, y: 200 },
    orbitmart: { x: 320, y: 135 },
    detector: { x: 480, y: 70 },
    monitor: { x: 580, y: 70 },
    lab_db: { x: 480, y: 210 },
    soc: { x: 320, y: 40 },
  };

  const $ = (id) => document.getElementById(id);

  function fmtDuration(ms) {
    if (ms == null || Number.isNaN(ms)) return "—";
    if (ms < 1000) return `${Math.round(ms)} ms`;
    return `${(ms / 1000).toFixed(1)} s`;
  }

  function pretty(val) {
    if (val == null || val === "") return "—";
    if (typeof val === "string") return val;
    try {
      return JSON.stringify(val, null, 2);
    } catch {
      return String(val);
    }
  }

  async function fetchJSON(url) {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`${res.status} ${url}`);
    return res.json();
  }

  function renderRunLists(data) {
    const sampleList = $("sampleList");
    const recordedList = $("recordedList");
    sampleList.innerHTML = "";
    recordedList.innerHTML = "";

    const makeItem = (run) => {
      const li = document.createElement("li");
      const btn = document.createElement("button");
      btn.type = "button";
      btn.dataset.runId = run.id;
      btn.innerHTML = `${escapeHtml(run.title)}<span class="run-meta">${escapeHtml(
        [run.suite, run.steps ? `${run.steps} steps` : null, run.sample ? "sample" : null]
          .filter(Boolean)
          .join(" · ")
      )}</span>`;
      btn.addEventListener("click", () => loadRun(run.id));
      li.appendChild(btn);
      return li;
    };

    (data.samples || []).forEach((r) => sampleList.appendChild(makeItem(r)));
    if ((data.recorded || []).length === 0) {
      recordedList.innerHTML = '<li class="muted empty-hint">None yet — use --events-file</li>';
    } else {
      data.recorded.forEach((r) => recordedList.appendChild(makeItem(r)));
    }
  }

  function escapeHtml(s) {
    return String(s)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  function markActiveRun(runId) {
    document.querySelectorAll(".viz-run-list button").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.runId === runId);
    });
  }

  async function loadRun(runId) {
    stopPlayback();
    const data = await fetchJSON(`/viz/api/runs/${encodeURIComponent(runId)}`);
    state.runId = data.id;
    state.events = data.events || [];
    state.index = state.events.length ? 0 : -1;
    state.nodes = extractNodes(state.events);
    state.activeEdge = null;

    $("runTitle").textContent = data.filename.replace(/\.jsonl$/, "").replace(/_/g, " ");
    $("runSub").textContent = `run_id=${data.summary.run_id || "—"} · ${data.source}`;
    $("suitePill").textContent = `SUITE ${ (data.summary.suite || "—").toUpperCase() }`;
    $("statusPill").textContent = (data.summary.status || "loaded").toUpperCase();
    $("statusPill").classList.add("pill-accent");

    $("sumSteps").textContent = String(data.summary.steps ?? 0);
    $("sumDuration").textContent = fmtDuration(data.summary.duration_ms);
    $("sumCommands").textContent = String(data.summary.commands ?? 0);
    $("sumOutcome").textContent =
      (data.summary.score && data.summary.score.outcome) || data.summary.status || "—";
    $("sumScore").textContent = pretty(data.summary.score);

    $("progressRange").max = Math.max(0, state.events.length - 1);
    $("progressRange").value = Math.max(0, state.index);
    markActiveRun(runId);
    renderGraph();
    renderLogs();
    showStep(state.index);
    await loadCompare(runId);
  }

  function extractNodes(events) {
    for (const ev of events) {
      if (Array.isArray(ev.nodes) && ev.nodes.length) return ev.nodes;
    }
    return [
      { id: "attacker", label: "Attacker CLI", kind: "client" },
      { id: "orbitmart", label: "OrbitMart", kind: "app" },
      { id: "detector", label: "Detectors", kind: "defense" },
      { id: "monitor", label: "monitor.db", kind: "store" },
      { id: "lab_db", label: "lab_vuln.db", kind: "store" },
    ];
  }

  function renderGraph() {
    const svg = $("graphSvg");
    const nodes = state.nodes;
    const positions = {};
    nodes.forEach((n) => {
      positions[n.id] = NODE_LAYOUT[n.id] || {
        x: 200 + Math.random() * 200,
        y: 80 + Math.random() * 120,
      };
    });

    const defaults = [
      ["attacker", "orbitmart"],
      ["victim", "orbitmart"],
      ["orbitmart", "detector"],
      ["detector", "monitor"],
      ["orbitmart", "lab_db"],
      ["soc", "detector"],
    ];

    let edgesHtml = "";
    defaults.forEach(([a, b]) => {
      if (!positions[a] || !positions[b]) return;
      const id = `${a}->${b}`;
      edgesHtml += `<path class="edge-line" id="edge-${cssId(id)}" d="M${positions[a].x},${positions[a].y} L${positions[b].x},${positions[b].y}" />`;
    });

    let nodesHtml = "";
    nodes.forEach((n) => {
      const p = positions[n.id];
      nodesHtml += `
        <g data-node="${escapeHtml(n.id)}">
          <circle class="node-circle" id="node-${cssId(n.id)}" cx="${p.x}" cy="${p.y}" r="28" />
          <text class="node-label" x="${p.x}" y="${p.y + 44}">${escapeHtml(n.label)}</text>
        </g>`;
    });

    svg.innerHTML = edgesHtml + nodesHtml;
    state._positions = positions;
  }

  function cssId(s) {
    return String(s).replace(/[^A-Za-z0-9_-]/g, "_");
  }

  function highlightGraph(ev) {
    document.querySelectorAll(".node-circle").forEach((el) => {
      el.classList.remove("active", "hit");
    });
    document.querySelectorAll(".edge-line").forEach((el) => {
      el.classList.remove("active", "attack");
    });

    const edge = ev && ev.edge;
    if (edge && edge.from && edge.to) {
      const fromEl = document.getElementById(`node-${cssId(edge.from)}`);
      const toEl = document.getElementById(`node-${cssId(edge.to)}`);
      if (fromEl) fromEl.classList.add("active");
      if (toEl) {
        const attackish =
          (edge.label || "").match(/sqli|xss|replay|sidejack|spray|inject|fixation|probe/i) ||
          ev.status === "blocked";
        toEl.classList.add(attackish ? "hit" : "active");
      }
      const edgeEl = document.getElementById(`edge-${cssId(`${edge.from}->${edge.to}`)}`);
      if (edgeEl) {
        edgeEl.classList.add(
          (edge.label || "").match(/sqli|xss|replay|sidejack|spray|inject|fixation|probe/i)
            ? "attack"
            : "active"
        );
      }
      $("edgeLabel").textContent = `${edge.from} → ${edge.to}${
        edge.label ? ` (${edge.label})` : ""
      }`;
    } else {
      $("edgeLabel").textContent = "—";
    }

    // Soft-highlight detector/monitor on score/mode
    if (ev && (ev.event === "score" || ev.event === "mode")) {
      const det = document.getElementById("node-detector");
      const mon = document.getElementById("node-monitor");
      if (det) det.classList.add("active");
      if (mon) mon.classList.add("active");
    }
  }

  function showStep(index) {
    if (!state.events.length) {
      $("progressLabel").textContent = "0 / 0";
      return;
    }
    state.index = Math.max(0, Math.min(index, state.events.length - 1));
    $("progressRange").value = String(state.index);
    $("progressLabel").textContent = `${state.index + 1} / ${state.events.length}`;

    const ev = state.events[state.index];
    $("eventPill").textContent = ev.event || "—";
    $("stepCommand").textContent = ev.command || "—";
    $("stepAction").textContent = ev.action || "—";
    $("stepResult").textContent = pretty(ev.result != null ? ev.result : ev.score);

    const vuln = ev.vulnerability || ev.mitigation;
    if (vuln) {
      $("vulnTitle").textContent = vuln.title || "Weakness";
      $("vulnWeakness").textContent = vuln.weakness || "—";
      $("vulnSink").textContent = vuln.sink ? `Sink: ${vuln.sink}` : "";
      $("vulnMitigation").textContent = vuln.mitigation
        ? `Mitigation: ${vuln.mitigation}`
        : "";
      $("vulnCwe").textContent = vuln.cwe || "";
    } else {
      $("vulnTitle").textContent = "Weakness";
      $("vulnWeakness").textContent = "No vulnerability metadata on this step.";
      $("vulnSink").textContent = "";
      $("vulnMitigation").textContent = "";
      $("vulnCwe").textContent = "";
    }

    highlightGraph(ev);
    renderLogs();
  }

  function logText(ev) {
    return (
      ev.log ||
      ev.action ||
      ev.command ||
      (ev.score ? `score ${pretty(ev.score)}` : "") ||
      ev.event ||
      ""
    );
  }

  function renderLogs() {
    const panel = $("logPanel");
    const q = ($("logSearch").value || "").trim().toLowerCase();
    const filter = $("logFilter").value;
    panel.innerHTML = "";

    state.events.forEach((ev, i) => {
      if (filter !== "all" && ev.event !== filter) return;
      const text = logText(ev);
      if (q && !`${ev.event} ${text}`.toLowerCase().includes(q)) return;

      const row = document.createElement("div");
      row.className = "log-row" + (i === state.index ? " current" : "");
      row.innerHTML = `<span class="step">#${ev.step_id ?? i + 1}</span><span class="etype">${escapeHtml(
        ev.event || ""
      )}</span><span class="etext">${escapeHtml(text)}</span>`;
      row.addEventListener("click", () => {
        stopPlayback();
        showStep(i);
      });
      panel.appendChild(row);
    });

    const current = panel.querySelector(".log-row.current");
    if (current) current.scrollIntoView({ block: "nearest" });
  }

  async function loadCompare(runId) {
    const grid = $("compareGrid");
    try {
      const data = await fetchJSON(`/viz/api/compare?run=${encodeURIComponent(runId)}`);
      const modes = data.modes || {};
      const order = ["OFF", "MONITOR", "BLOCK"];
      const present = order.filter((m) => modes[m]);
      if (!present.length) {
        grid.innerHTML =
          '<p class="muted">This run has no mode comparison. Load <strong>experiment demo</strong> for vulnerable vs mitigated.</p>';
        return;
      }
      grid.innerHTML = present
        .map((m) => {
          const block = modes[m] || {};
          const cls = m.toLowerCase();
          const blurb =
            m === "OFF"
              ? "Vulnerable posture — detectors idle"
              : m === "MONITOR"
                ? "Observe — alerts, traffic continues"
                : "Mitigated — matching requests blocked";
          return `<article class="compare-card ${cls}">
            <h3>${m}</h3>
            <p>${blurb}</p>
            <pre>${escapeHtml(pretty(block))}</pre>
          </article>`;
        })
        .join("");
    } catch {
      grid.innerHTML = '<p class="muted">Comparison unavailable for this run.</p>';
    }
  }

  function stopPlayback() {
    state.playing = false;
    $("btnPlay").textContent = "Play";
    if (state.timer) {
      clearTimeout(state.timer);
      state.timer = null;
    }
  }

  function tick() {
    if (!state.playing) return;
    if (state.index >= state.events.length - 1) {
      stopPlayback();
      return;
    }
    showStep(state.index + 1);
    const base = 650;
    state.timer = setTimeout(tick, base / state.speed);
  }

  function startPlayback() {
    if (!state.events.length) return;
    state.playing = true;
    $("btnPlay").textContent = "Pause";
    if (state.index >= state.events.length - 1) showStep(0);
    tick();
  }

  function bindControls() {
    $("btnPlay").addEventListener("click", () => {
      if (state.playing) stopPlayback();
      else startPlayback();
    });
    $("btnBack").addEventListener("click", () => {
      stopPlayback();
      showStep(state.index - 1);
    });
    $("btnFwd").addEventListener("click", () => {
      stopPlayback();
      showStep(state.index + 1);
    });
    $("btnReset").addEventListener("click", () => {
      stopPlayback();
      showStep(0);
    });
    $("speedRange").addEventListener("input", (e) => {
      state.speed = parseFloat(e.target.value) || 1;
      $("speedLabel").textContent = `${state.speed}×`;
    });
    $("progressRange").addEventListener("input", (e) => {
      stopPlayback();
      showStep(parseInt(e.target.value, 10) || 0);
    });
    $("logSearch").addEventListener("input", renderLogs);
    $("logFilter").addEventListener("change", renderLogs);
  }

  async function init() {
    bindControls();
    try {
      const data = await fetchJSON("/viz/api/runs");
      renderRunLists(data);
      const first =
        (data.samples || []).find((r) => r.filename === "experiment_demo.jsonl") ||
        (data.samples || [])[0];
      if (first) await loadRun(first.id);
    } catch (err) {
      $("runSub").textContent = `Failed to load runs: ${err.message}`;
    }
  }

  document.addEventListener("DOMContentLoaded", init);
})();
