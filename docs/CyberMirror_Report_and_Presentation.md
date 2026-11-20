# CyberMirror — Project Report & Presentation Content  
**(≈ 4–5 pages · use as report body or slide script)**

---

## Slide / Section 1 — Title & Problem

**Title:** CyberMirror: An AI-Assisted Local Web-Attack Detection Lab  
**Subtitle:** Twin application · ML detectors · SOC evaluation loop  

**Problem.** Modern web apps face SQL injection (SQLi), cross-site scripting (XSS), and session hijacking, but students and small teams rarely have a **safe, end-to-end place** to attack, detect, measure, and improve models. Production systems cannot be used for live exploitation practice.

**Solution.** CyberMirror is a **local AI web-attack laboratory** with two faces of the same system:

| Face | Role |
|------|------|
| **OrbitMart** (`/`) | User-facing “cloud tools” storefront (register, login, catalog search) — the *attack surface* |
| **CyberMirror SOC Console** (`/dashboard`) | Operator console — overview, alerts, sessions, control, evaluation |
| **Attack Viz** (`/viz`) | Replay of recorded attack runs for teaching and demos |

All traffic stays on localhost / private lab IPs. The lab is **not** a claim of a full enterprise IDS, firewall stack, or automated remediation product.

---

## Slide / Section 2 — Objectives & Scope

**Objectives**

1. Build a **vulnerable-by-design but sandboxed** web twin for controlled attacks.  
2. Train and deploy **ML detectors** for SQLi, XSS, and session abuse.  
3. Simulate labeled attack and benign traffic; capture detections in a monitor store.  
4. Measure quality with **recall, precision, false-alarm rate**, and a feedback loop (miss lists → retrain).  
5. Demonstrate **OFF / MONITOR / BLOCK** operational modes and visual attack storytelling.

**In scope:** local Flask app, MySQL auth, SQLite lab catalog (`lab_vuln.db`), joblib models, attacker CLIs, SOC UI, evaluation, Viz replay.  

**Out of scope:** network firewall virtualization, MITRE/CVE pipelines, phishing/malware/DDoS, automated patch engines.

---

## Slide / Section 3 — System Architecture

**High-level flow**

```
Attacker CLI / browser
        ↓
   OrbitMart (Flask)
        ↓
   Detectors (joblib)  ← mode: OFF | MONITOR | BLOCK
        ↓
   monitor.db (requests + alerts)
        ↓
   SOC Console + Evaluation + Attack Viz
```

**Stack (short)**

- Python / Flask storefront + SOC templates  
- MySQL + bcrypt for OrbitMart users  
- SQLite `monitor.db` for request/alert telemetry  
- scikit-learn / XGBoost models in `models/*.joblib`  
- Chart.js dashboard; JSONL event files for Viz  

**Detection modes**

| Mode | Behaviour |
|------|-----------|
| **OFF** | Detectors idle; lab can still show exploitable catalog behaviour |
| **MONITOR** | Score traffic, write alerts, allow requests |
| **BLOCK** | Score traffic, write alerts, return **HTTP 403** on hits |

---

## Slide / Section 4 — Models & Training

### Algorithms compared (same family across tasks)

For each detection task we trained and compared:

| Algorithm | Library / notes |
|-----------|-----------------|
| **Logistic Regression** | scikit-learn (`LogisticRegression`) |
| **Random Forest** | scikit-learn (`RandomForestClassifier`) |
| **Gradient Boosting** | SQLi/XSS: `GradientBoostingClassifier` · Session: `HistGradientBoostingClassifier` |
| **XGBoost** | `XGBClassifier` (tree booster, `hist` where used) |

**Protocol (shared idea):** load CSV → clean/dedupe → **80/20 stratified** `train_test_split` (`random_state=42`) → (XSS/session: **SMOTE on train only**) → fit candidates → pick **best by holdout F1/accuracy** → save `models/*.joblib`.

### Deployed models in CyberMirror (what the live app loads)

| Task | Features | Candidates trained | **Selected / deployed** | Artifact | Holdout reference |
|------|----------|--------------------|-------------------------|----------|-------------------|
| **SQLi** | Char **TF‑IDF** (2–5 grams) → classifier pipeline | LR, RF, GB, XGBoost | **Random Forest** (best pipeline on holdout) | `models/sqli_detector.joblib` | ~**0.9971** Acc |
| **XSS** | Tabular features + **StandardScaler** | LR, RF, GB, XGBoost (+ grid search on RF/GB) | **XGBoost** | `models/xss_detector.joblib` | ~**0.9938** Acc |
| **Session binary** (Normal vs Hijacked) | App-aligned numeric + UA/method flags, scaled | LR, RF, HistGB, XGBoost | **XGBoost** | `models/session_app_binary_detector.joblib` | ~**0.9932** Acc |
| **Session multiclass** (Normal / Cookie_Replay / Sidejacking / Fixation / Prediction, …) | Same feature family, multiclass XGB | LR, RF, HistGB, XGBoost | **XGBoost** | `models/session_app_multiclass_detector.joblib` | ~**0.983** Acc |

Legacy full-flow session joblibs (`session_binary_detector.joblib`, `session_multiclass_detector.joblib`) were also **XGBoost**-best on the original SessionHijacking comparison tables; the **app** prefers the `session_app_*` pair so features match Flask live telemetry.

### Example session comparison (original CSV training run)

**Binary:** XGBoost 0.9933 → HistGB 0.9931 → RF 0.9923 → LR 0.9908  
**Multiclass:** XGBoost 0.983 → HistGB 0.980 → RF 0.978 → LR 0.969  

After deduplication, **train∩test exact overlap = 0%** for exported SQLi/session splits.

**Important honesty point for the report:**  
- **Dataset score** = performance on the CSV holdout (same distribution as training).  
- **Lab Evaluation recall** = performance on live labeled requests during Run attacks.  
- Earlier lab runs sampled SQLi from the **full** CSV (train+test mixed) → **optimistic bias**.  
- The lab now defaults SQLi payloads to the **held-out test split**; optional **`ood`** payloads stress obfuscated / out-of-distribution attacks closer to “real world ≠ dataset.”

Real-world attacks are not guaranteed to look like the training CSV; high lab recall is a **demo of the twin**, not a proof of universal detection.

---

## Slide / Section 5 — Attack Simulation & Labeling

**Attacker modules** (Control → **Run attacks**, or CLI):

1. `normal_traffic` — benign multi-user browsing  
2. `sqli_attack` — compact/padded SQLi on search + login-shaped fields  
3. `xss_attack` — reflected XSS-style payloads  
4. `session_attacks` — cookie replay, sidejacking, fixation, prediction  

Each request can carry **`X-Test-Label`** (e.g. `sqli_compact`, `xss`, `cookie_replay`). Labels are **ground truth for Evaluation only**; detectors **must not** read them to decide alerts (fair scoring).

After the suite, Evaluation runs (`evaluate --from-db`) and Viz can record **latest-only** JSONL runs under `results/runs/`.

---

## Slide / Section 6 — Evaluation Metrics (How to Read the Dashboard)

| Metric | Meaning |
|--------|---------|
| **Sent** | Labeled attack requests of that family in `monitor.db` |
| **Caught** | Those requests that also produced a matching **detector alert** |
| **Missed** | Sent − Caught |
| **Recall** | Caught / Sent — “of attacks we sent, how many did we notice?” |
| **Precision** | Of alerts of that type, how many matched the true label |
| **FAR** | Fraction of **normal**-labeled requests that still got an alert |
| **Dataset score** | Offline model reference — **not** the live run |

**Caught is real model output**, not auto-credited from the label. Evaluation joins `true_label` ↔ `alerts`.

**Illustrative MONITOR lab result** (order of magnitude; re-run for exact figures):

- SQLi recall often very high on classic / test-split payloads  
- XSS high but not perfect  
- Session subtypes mixed; **session_prediction** typically weakest  
- FAR non-zero when normals include edge cases or stacked suite noise  

**BLOCK** preserves detection quality while returning **403** on SQLi hits (vuln catalog probes blocked).

---

## Slide / Section 7 — Insights Loop & Viz

**Insights → improve**

1. Run attacks → view Alerts / Sessions  
2. Evaluation writes `results/evaluation.json` and `misses_*.csv`  
3. Inspect misses → adjust thresholds (`.env`) or retrain → clear logs → repeat  

**Attack Viz**

- Replays **recorded** runs (not a live camera)  
- Control Run attacks writes a fresh `control_*` suite and **replaces** older recordings  
- “Vulnerable vs mitigated” needs a multi-mode **experiment** recording (OFF/MONITOR/BLOCK), not a single SQLi/XSS file  

---

## Slide / Section 8 — Results Summary & Limitations

**Achieved**

- Working twin (OrbitMart + SOC) with OFF/MONITOR/BLOCK  
- Deployed SQLi, XSS, and session detectors  
- One-button lab suite + auto-evaluate + Viz recording  
- Transparent metrics and miss lists for a retrain loop  
- Clearer SQLi payload policy: **test** by default; **ood** for harder checks  

**Limitations**

- Local lab only; not production security assurance  
- Models tied to training distributions; OOD / novel attacks may evade  
- Session prediction remains challenging  
- Evaluation quality depends on clean logs (clear before scored runs)  
- XSS training CSV may be environment-specific  

---

## Slide / Section 9 — Conclusion & Future Work

**Conclusion.** CyberMirror shows a complete student-scale pipeline: **vulnerable twin → ML detection → labeled simulation → SOC metrics → feedback**. It teaches that “100% lab recall” and “holdout dataset score” are different claims, and that real attacks may diverge from any fixed CSV.

**Future work**

- Expand OOD / red-team payload packs for SQLi and XSS  
- Stronger session-prediction features and thresholds  
- Optional fair eval mode that scores the **full** holdout set, not only 24 sampled payloads  
- Richer multi-mode experiment Viz from Control  
- Documented CI job for train → evaluate → publish metrics  

---

## Presentation timing guide (≈ 8–10 minutes)

| Min | Talk track |
|-----|------------|
| 0–1 | Problem + twin idea (OrbitMart vs SOC) |
| 1–3 | Architecture + modes OFF/MONITOR/BLOCK |
| 3–5 | Models, train/test honesty, bias fix |
| 5–7 | Live demo: Run attacks → Alerts → Evaluation → Viz |
| 7–9 | Metrics table, limitations, conclusion |

**Demo checklist:** Flask up → Control MONITOR → Clear logs → Run attacks → Evaluation (PKT time) → Viz recorded run → optional BLOCK SQLi 403.

---

## One-paragraph abstract (for report cover)

CyberMirror is a localhost AI web-attack laboratory pairing a user-facing OrbitMart storefront with a CyberMirror SOC console. Machine-learning detectors for SQL injection, XSS, and session hijacking score live traffic under OFF, MONITOR, or BLOCK modes. Labeled attacker suites populate a monitor database; evaluation computes recall, precision, and false-alarm rate, and miss lists support retraining. Attack Viz replays recorded runs for instruction. The project emphasizes fair labeling, train/test awareness, and the gap between dataset holdout accuracy and real-world or out-of-distribution attacks.

---

*Document length target: ~4–5 printed pages at standard academic formatting (11–12 pt, 1.15–1.5 spacing). Expand tables with your latest Evaluation screenshot numbers before submission.*
