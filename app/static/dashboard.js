(() => {
  const NAVY = "#FF8A3D";
  const BLUE_GREY = "#5B8CFF";
  const BLUE_GREY_2 = "#FF5C5C";
  const REFRESH_MS = 5000;
  const CHART_TICK = "#9AA6B8";
  const CHART_GRID = "rgba(42, 49, 64, 0.9)";

  function $(sel, root = document) {
    return root.querySelector(sel);
  }

  function esc(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;");
  }

  /** Format ISO timestamps for display in Pakistan Standard Time. */
  function formatPkt(iso) {
    if (!iso) return "—";
    const d = new Date(iso);
    if (Number.isNaN(d.getTime())) return String(iso);
    try {
      return (
        new Intl.DateTimeFormat("en-PK", {
          timeZone: "Asia/Karachi",
          year: "numeric",
          month: "short",
          day: "2-digit",
          hour: "2-digit",
          minute: "2-digit",
          second: "2-digit",
          hour12: true,
        }).format(d) + " PKT"
      );
    } catch (_) {
      return String(iso);
    }
  }

  async function getJson(url) {
    const res = await fetch(url, { credentials: "same-origin" });
    if (res.status === 401 || res.redirected) {
      window.location.href = "/dashboard/login";
      throw new Error("unauthorized");
    }
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return res.json();
  }

  async function postJson(url, body) {
    const res = await fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || `HTTP ${res.status}`);
    }
    return res.json();
  }

  function setModePill(mode) {
    const pill = $("#modePill");
    if (!pill) return;
    const next = mode || "—";
    const prev = pill.getAttribute("data-mode") || "";
    pill.textContent = `MODE ${next}`;
    pill.setAttribute("data-mode", next);
    pill.classList.remove("mode-off", "mode-monitor", "mode-block");
    const key = String(next).toUpperCase();
    if (key === "OFF") pill.classList.add("mode-off");
    else if (key === "MONITOR") pill.classList.add("mode-monitor");
    else if (key === "BLOCK") pill.classList.add("mode-block");
    if (prev && prev !== next) {
      pill.classList.add("pill-flash");
      window.setTimeout(() => pill.classList.remove("pill-flash"), 600);
    }
  }

  function pulseLive() {
    const hint = $("#refreshHint");
    if (!hint) return;
    hint.classList.add("is-refreshing");
    window.setTimeout(() => hint.classList.remove("is-refreshing"), 450);
  }

  /* ---------- Overview ---------- */
  let timelineChart = null;
  let typeChart = null;

  function ensureCharts() {
    if (typeof Chart === "undefined") return false;
    const tl = $("#chartTimeline");
    const ty = $("#chartByType");
    if (!tl || !ty) return false;

    if (!timelineChart) {
      timelineChart = new Chart(tl, {
        type: "line",
        data: {
          labels: [],
          datasets: [
            {
              label: "Requests",
              data: [],
              borderColor: BLUE_GREY,
              backgroundColor: "rgba(91, 140, 255, 0.18)",
              tension: 0.25,
              fill: true,
            },
            {
              label: "Alerts",
              data: [],
              borderColor: NAVY,
              backgroundColor: "rgba(255, 138, 61, 0.18)",
              tension: 0.25,
              fill: true,
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: "bottom",
              labels: { color: CHART_TICK },
            },
          },
          scales: {
            x: {
              ticks: {
                maxRotation: 0,
                autoSkip: true,
                maxTicksLimit: 8,
                color: CHART_TICK,
              },
              grid: { color: CHART_GRID },
            },
            y: {
              beginAtZero: true,
              ticks: { precision: 0, color: CHART_TICK },
              grid: { color: CHART_GRID },
            },
          },
        },
      });
    }

    if (!typeChart) {
      typeChart = new Chart(ty, {
        type: "bar",
        data: {
          labels: [],
          datasets: [
            {
              label: "Alerts",
              data: [],
              backgroundColor: [NAVY, BLUE_GREY, BLUE_GREY_2, "#3DDC97", "#FFB078"],
            },
          ],
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { ticks: { color: CHART_TICK }, grid: { color: CHART_GRID } },
            y: {
              beginAtZero: true,
              ticks: { precision: 0, color: CHART_TICK },
              grid: { color: CHART_GRID },
            },
          },
        },
      });
    }
    return true;
  }

  async function refreshOverview() {
    const data = await getJson("/dashboard/api/overview");
    $("#statRequests").textContent = data.total_requests;
    $("#statAlerts").textContent = data.total_alerts;
    $("#statMode").textContent = data.mode;
    $("#statDetectMs").textContent =
      data.avg_detection_ms == null ? "—" : `${data.avg_detection_ms} ms`;
    setModePill(data.mode);
    pulseLive();

    const empty = $("#overviewEmpty");
    if (empty) {
      empty.hidden = Number(data.total_requests || 0) > 0;
    }

    if (!ensureCharts()) return;
    const series = data.timeseries || [];
    timelineChart.data.labels = series.map((r) => r.bucket);
    timelineChart.data.datasets[0].data = series.map((r) => r.requests);
    timelineChart.data.datasets[1].data = series.map((r) => r.alerts);
    timelineChart.update("none");

    const byType = data.alerts_by_type || [];
    typeChart.data.labels = byType.map((r) => r.attack_type);
    typeChart.data.datasets[0].data = byType.map((r) => r.count);
    typeChart.update("none");
  }

  /* ---------- Alerts ---------- */
  async function refreshAlerts() {
    const type = $("#alertTypeFilter")?.value || "";
    const sort = $("#alertSort")?.value || "desc";
    const qs = new URLSearchParams();
    if (type) qs.set("type", type);
    qs.set("sort", sort);
    const data = await getJson(`/dashboard/api/alerts?${qs.toString()}`);

    const filter = $("#alertTypeFilter");
    if (filter && filter.options.length <= 1) {
      (data.types || []).forEach((t) => {
        const opt = document.createElement("option");
        opt.value = t;
        opt.textContent = t;
        filter.appendChild(opt);
      });
    }

    const tbody = $("#alertsTable tbody");
    if (!tbody) return;
    const rows = data.alerts || [];
    if (!rows.length) {
      tbody.innerHTML = `<tr><td colspan="6"><div class="empty-guide compact">
        <strong>No alerts yet</strong>
        <p class="muted">Set MONITOR or BLOCK, enable the OrbitMart catalog, then send traffic. New detections appear here as SOC alerts.</p>
      </div></td></tr>`;
      return;
    }
    const prevIds = new Set(
      Array.from(tbody.querySelectorAll("tr[data-alert-id]")).map((tr) =>
        tr.getAttribute("data-alert-id")
      )
    );
    tbody.innerHTML = rows
      .map((r) => {
        const id = String(r.id ?? "");
        const isNew = id && !prevIds.has(id) && prevIds.size > 0;
        return `<tr data-alert-id="${esc(id)}" class="${isNew ? "row-flash" : ""}">
        <td>${esc(r.timestamp)}</td>
        <td>${esc(r.source_ip)}</td>
        <td>${esc(r.attack_type)}</td>
        <td>${esc(r.field)}</td>
        <td>${r.probability == null ? "—" : Number(r.probability).toFixed(3)}</td>
        <td>${esc(r.action)}</td>
      </tr>`;
      })
      .join("");
    pulseLive();
  }

  /* ---------- Sessions ---------- */
  async function refreshSessions() {
    const data = await getJson("/dashboard/api/sessions");
    const tbody = $("#sessionsTable tbody");
    if (!tbody) return;
    const rows = data.sessions || [];
    if (!rows.length) {
      tbody.innerHTML = `<tr><td colspan="6"><div class="empty-guide compact">
        <strong>No sessions yet</strong>
        <p class="muted">Browse or login on the twin so session features can accumulate, then check for hijack-class predictions.</p>
      </div></td></tr>`;
      return;
    }
    tbody.innerHTML = rows
      .map((r) => {
        const shortHash = String(r.session_hash || "").slice(0, 22);
        const ips = Array.isArray(r.ips) ? r.ips.join(", ") : "";
        return `<tr>
          <td title="${esc(r.session_hash)}">${esc(shortHash)}…</td>
          <td>${esc(r.request_count)}</td>
          <td>${esc(ips || "—")}</td>
          <td>${esc(r.first_seen)}</td>
          <td>${esc(r.last_seen)}</td>
          <td>${esc(r.predicted_class || "—")}</td>
        </tr>`;
      })
      .join("");
  }

  /* ---------- Control ---------- */
  function wireControl() {
    const modeSwitch = $("#modeSwitch");
    if (modeSwitch) {
      modeSwitch.addEventListener("click", async (ev) => {
        const btn = ev.target.closest("[data-mode]");
        if (!btn) return;
        const mode = btn.getAttribute("data-mode");
        try {
          const data = await postJson("/dashboard/api/mode", { mode });
          modeSwitch.querySelectorAll(".mode-btn").forEach((b) => {
            b.classList.toggle("active", b.getAttribute("data-mode") === data.mode);
          });
          $("#modeStatus").innerHTML = `Current: <strong>${esc(data.mode)}</strong>`;
          setModePill(data.mode);
        } catch (err) {
          $("#modeStatus").textContent = `Error: ${err.message}`;
        }
      });
    }

    const vulnToggle = $("#vulnToggle");
    if (vulnToggle) {
      vulnToggle.addEventListener("change", async () => {
        try {
          const data = await postJson("/dashboard/api/vulnerable", {
            enabled: vulnToggle.checked,
          });
          $("#vulnStatus").textContent = data.vulnerable_enabled
            ? "Enabled"
            : "Disabled";
        } catch (err) {
          $("#vulnStatus").textContent = `Error: ${err.message}`;
        }
      });
    }

    const clearBtn = $("#clearLogsBtn");
    if (clearBtn) {
      clearBtn.addEventListener("click", async () => {
        if (!window.confirm("Clear all requests, alerts, and sessions?")) return;
        try {
          await postJson("/dashboard/api/clear", {});
          $("#dataStatus").textContent = "Logs cleared.";
        } catch (err) {
          $("#dataStatus").textContent = `Error: ${err.message}`;
        }
      });
    }

    const runAttacksBtn = $("#runAttacksBtn");
    if (runAttacksBtn) {
      runAttacksBtn.addEventListener("click", async () => {
        if (
          !window.confirm(
            "Run local lab attack suite against this server?\n\n" +
              "normal ×40 → SQLi → XSS → session → evaluate\n" +
              "Also records Attack Viz JSONL under results/runs/.\n" +
              "This takes about 1–3 minutes."
          )
        ) {
          return;
        }
        const status = $("#attackStatus");
        runAttacksBtn.disabled = true;
        if (status) {
          status.textContent =
            "Running attacks + evaluation + Viz recording… leave this tab open.";
        }
        try {
          const data = await postJson("/dashboard/api/run-attacks", {});
          const steps = (data.results || [])
            .map((r) => `${r.step}${r.ok ? "✓" : "✗"}`)
            .join(" · ");
          const vizCount = data.viz_runs
            ? Object.keys(data.viz_runs).length
            : 0;
          if (status) {
            status.textContent =
              data.message ||
              `Done in ${data.elapsed_seconds || "?"}s — ${steps}.`;
            if (vizCount) {
              status.textContent += ` · ${vizCount} Viz run file(s) → /viz/`;
            }
          }
        } catch (err) {
          if (status) status.textContent = `Error: ${err.message}`;
        } finally {
          runAttacksBtn.disabled = false;
        }
      });
    }
  }

  async function refreshControl() {
    const data = await getJson("/dashboard/api/control");
    setModePill(data.mode);
    const modeSwitch = $("#modeSwitch");
    if (modeSwitch) {
      modeSwitch.querySelectorAll(".mode-btn").forEach((b) => {
        b.classList.toggle("active", b.getAttribute("data-mode") === data.mode);
      });
      $("#modeStatus").innerHTML = `Current: <strong>${esc(data.mode)}</strong>`;
    }
    const vulnToggle = $("#vulnToggle");
    if (vulnToggle) {
      vulnToggle.checked = !!data.vulnerable_enabled;
      $("#vulnStatus").textContent = data.vulnerable_enabled ? "Enabled" : "Disabled";
    }
  }

  function wireSidebar() {
    const btn = $("#dashMenuBtn");
    const sidebar = $("#dashSidebar");
    if (!btn || !sidebar) return;
    btn.addEventListener("click", () => sidebar.classList.toggle("open"));
  }

  /* ---------- Evaluation ---------- */
  let confusionChart = null;
  const ATTACK_ORDER = [
    "sqli",
    "xss",
    "cookie_replay",
    "sidejacking",
    "session_fixation",
    "session_prediction",
  ];

  function fmtRate(v) {
    if (v == null || v === "") return "—";
    const n = Number(v);
    if (Number.isNaN(n)) return "—";
    return `${(n * 100).toFixed(1)}%`;
  }

  function datasetRefFor(attack, report) {
    const scores = report.dataset_scores || {};
    if (attack === "sqli") return scores.sqli;
    if (attack === "xss") return scores.xss;
    if (
      ["cookie_replay", "sidejacking", "session_fixation", "session_prediction"].includes(
        attack
      )
    ) {
      return scores.session_multiclass;
    }
    return null;
  }

  function renderConfusion(cm) {
    if (typeof Chart === "undefined") return;
    const canvas = $("#chartConfusion");
    if (!canvas || !cm || !cm.labels || !cm.matrix) return;
    const labels = cm.labels;
    const matrix = cm.matrix;
    // Chart.js matrix-like: one dataset per predicted class (stacked bars by actual)
    const palette = [NAVY, BLUE_GREY, BLUE_GREY_2, "#3d4f63", "#6f7f90", "#9aa8b5", "#c5ced6"];
    const datasets = labels.map((pred, j) => ({
      label: pred,
      data: matrix.map((row) => row[j] || 0),
      backgroundColor: palette[j % palette.length],
      stack: "cm",
    }));
    if (confusionChart) confusionChart.destroy();
    confusionChart = new Chart(canvas, {
      type: "bar",
      data: { labels, datasets },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: "bottom" },
          title: { display: true, text: "True label (x) vs predicted (stacked)" },
        },
        scales: {
          x: { stacked: true, title: { display: true, text: "True label" } },
          y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } },
        },
      },
    });
  }

  async function refreshEvaluation() {
    const meta = $("#evalMeta");
    let payload;
    try {
      payload = await getJson("/dashboard/api/evaluation");
    } catch (err) {
      if (meta) {
        meta.innerHTML =
          "No evaluation report yet. After a labeled traffic run, execute <code>python -m evaluation.evaluate --from-db</code> to close Phase 4.";
      }
      return;
    }
    const report = payload.report || {};
    if (meta) {
      meta.textContent = `Generated ${formatPkt(report.generated_at)} · primary mode ${
        report.primary_mode || report.mode || "—"
      }`;
    }

    const per = report.per_attack_type || {};
    const tbody = $("#evalMetricsTable tbody");
    if (tbody) {
      tbody.innerHTML = ATTACK_ORDER.map((attack) => {
        const s = per[attack] || {};
        const ref = datasetRefFor(attack, report);
        return `<tr>
          <td>${esc(attack)}</td>
          <td>${esc(s.attacks_sent ?? 0)}</td>
          <td>${esc(s.caught ?? 0)}</td>
          <td>${esc(s.missed ?? 0)}</td>
          <td>${fmtRate(s.recall)}</td>
          <td>${fmtRate(s.precision)}</td>
          <td>${ref == null ? "—" : Number(ref).toFixed(4)}</td>
        </tr>`;
      }).join("");
    }

    const side = $("#evalSideStats");
    if (side) {
      const totals = report.totals || {};
      const styles = report.sqli_compact_vs_padded || {};
      const compact = styles.compact || {};
      const padded = styles.padded || {};
      const ds = report.dataset_scores || {};
      side.innerHTML = `
        <li>False alarm rate (normal): <strong>${fmtRate(totals.false_alarm_rate)}</strong>
          (${esc(totals.normal_with_alert ?? 0)} / ${esc(totals.normal_requests ?? 0)})</li>
        <li>SQLi compact detection: <strong>${fmtRate(compact.detection_rate)}</strong>
          (${esc(compact.caught ?? 0)} / ${esc(compact.sent ?? 0)})</li>
        <li>SQLi padded detection: <strong>${fmtRate(padded.detection_rate)}</strong>
          (${esc(padded.caught ?? 0)} / ${esc(padded.sent ?? 0)})</li>
        <li>Dataset refs — SQLi ${esc(ds.sqli)}, XSS ${esc(ds.xss)},
          session binary ${esc(ds.session_binary)}, multiclass ${esc(ds.session_multiclass)}</li>
      `;
    }

    const modeBody = $("#evalModeTable tbody");
    const summary = report.mode_summary || {};
    if (modeBody) {
      const keys = Object.keys(summary);
      if (!keys.length) {
        modeBody.innerHTML = `<tr><td colspan="6" class="muted">Single-DB evaluation (no multi-mode run).</td></tr>`;
      } else {
        modeBody.innerHTML = keys
          .map((mode) => {
            const m = summary[mode] || {};
            let note = "—";
            if (mode === "OFF" && m.vuln_probe) {
              note = m.vuln_probe.succeeded
                ? "Vuln page still exploitable"
                : m.vuln_probe.blocked
                  ? "Unexpectedly blocked"
                  : "Probe inconclusive";
            } else if (mode === "OFF") {
              note = "Detectors idle";
            }
            return `<tr>
              <td>${esc(mode)}</td>
              <td>${esc(m.total_alerts ?? "—")}</td>
              <td>${fmtRate(m.false_alarm_rate)}</td>
              <td>${fmtRate(m.sqli_recall)}</td>
              <td>${fmtRate(m.xss_recall)}</td>
              <td>${esc(note)}</td>
            </tr>`;
          })
          .join("");
      }
    }

    renderConfusion(report.confusion_matrix);
  }

  document.addEventListener("DOMContentLoaded", () => {
    wireSidebar();
    const page = document.querySelector("[data-dashboard-page]");
    if (!page) return;
    const name = page.getAttribute("data-dashboard-page");

    const runners = {
      overview: refreshOverview,
      alerts: refreshAlerts,
      sessions: refreshSessions,
      control: refreshControl,
      evaluation: refreshEvaluation,
    };

    if (name === "control") wireControl();
    if (name === "alerts") {
      $("#alertTypeFilter")?.addEventListener("change", () => refreshAlerts().catch(() => {}));
      $("#alertSort")?.addEventListener("change", () => refreshAlerts().catch(() => {}));
    }
    if (name === "evaluation") {
      $("#evalRefreshBtn")?.addEventListener("click", () =>
        refreshEvaluation().catch(() => {})
      );
    }

    const run = runners[name];
    if (!run) return;

    const tick = () => run().catch((err) => console.warn("dashboard refresh", err));
    // Charts may load after defer; retry briefly
    setTimeout(tick, 50);
    // Evaluation is file-based; refresh less aggressively
    setInterval(tick, name === "evaluation" ? 15000 : REFRESH_MS);
  });
})();
