# CyberMirror

Local **AI web-attack lab** with two faces:

- **OrbitMart** (`/`) — user-facing cloud-tools marketplace (register, login, catalog search)
- **CyberMirror SOC Console** (`/dashboard`) — dark operator console (overview, alerts, sessions, control, evaluation)

Traffic stays on localhost / private lab IPs.

## What this project covers

| Phase | What it means | Implemented today |
|-------|---------------|-------------------|
| **1. Lab environment** | Stand up a safe local app you can attack and monitor | OrbitMart + MySQL auth + catalog SQLi target (`lab_vuln.db`), OFF / MONITOR / BLOCK |
| **2. Train models** | Collect data, train AI/ML | `training/` scripts → `models/*.joblib` (SQLi, XSS, session) |
| **3. Simulate & assess** | Execute attacks, capture impact | `attacker/` scripts + live detectors → `monitor.db` |
| **4. Insights & loop** | Measure quality, remediate, retrain | SOC console + `evaluation/evaluate.py` → `results/` |

Not claimed as built: full network firewall/IDS virtualization, MITRE/CVE pipelines, phishing/malware/DDoS, automated remediation engines.

## Stack

- **Storefront:** OrbitMart templates + `orbitmart.css`
- **SOC console:** dark Chart.js dashboard (`dashboard.css`)
- **Auth:** local MySQL (`users` table) + bcrypt passwords
- **Monitoring:** SQLite `app/monitoring/monitor.db`
- **Detectors:** joblib models (scikit-learn / XGBoost)
- **Lab target:** intentional SQLi catalog search on isolated SQLite only

## Prerequisites

- Python 3.11+ recommended
- Local MySQL with a database (default name `SecureX`) and a `users` table for OrbitMart register/login
- A local `.env` in the project root (not committed; copy values from the example below)

### `.env` (local only)

```env
SECRET_KEY=change-me-to-a-long-random-lab-secret
FLASK_HOST=0.0.0.0
FLASK_PORT=5000
SESSION_REGENERATE_ON_LOGIN=True
ENABLE_VULNERABLE_PAGE=True
DETECTION_MODE=MONITOR
SESSION_DETECT_MIN_REQUESTS=3
LAB_TRUST_FORWARDED_FOR=True
SQLI_MIN_PROBA=0.50
XSS_MIN_PROBA=0.85
SESSION_MIN_PROBA=0.70
ADMIN_USERNAME=admin
ADMIN_PASSWORD=test123
MYSQL_HOST=127.0.0.1
MYSQL_USER=root
MYSQL_PASSWORD=
MYSQL_DATABASE=SecureX
```

## Quick start — run the app & open the dashboard

```powershell
git clone https://github.com/danyalAhmed4/cybermirror.git
cd cybermirror
pip install -r requirements.txt
# create a local .env (see example above), then:
python -m app.app
```

The server starts with **debug off** and **no reloader** (avoids stale detector code). Default port: **5000**.

### SOC Console (dashboard)

| Page | URL |
|------|-----|
| Login | http://127.0.0.1:5000/dashboard/login |
| Overview | http://127.0.0.1:5000/dashboard/ |
| Alerts | http://127.0.0.1:5000/dashboard/alerts |
| Sessions | http://127.0.0.1:5000/dashboard/sessions |
| Control | http://127.0.0.1:5000/dashboard/control |
| Evaluation | http://127.0.0.1:5000/dashboard/evaluation |

**Dashboard credentials:** `admin` / `test123`  
(from `ADMIN_USERNAME` / `ADMIN_PASSWORD` in `.env`)

On **Control**: set detection mode to **MONITOR**, enable the OrbitMart catalog if you want `/search` SQLi demos, and use **Clear logs** for a clean slate.

### OrbitMart (storefront)

| Page | URL |
|------|-----|
| Home | http://127.0.0.1:5000/ |
| Register | http://127.0.0.1:5000/register |
| Login | http://127.0.0.1:5000/login |
| Catalog search | http://127.0.0.1:5000/search |

Register a normal user in MySQL via `/register`, then log in. This is separate from the SOC dashboard admin account.

## 60-second demo

1. **Lab environment** — start the app; Console → Control → **MONITOR**; enable OrbitMart catalog  
2. **Train** — models already in `models/`  
3. **Simulate** — browse OrbitMart `/search` or run (second terminal):
   ```powershell
   python -m attacker.normal_traffic --count 40
   python -m attacker.sqli_attack
   python -m attacker.xss_attack
   python -m attacker.session_attacks
   ```
4. **Insights** — Console → Alerts / Sessions / Evaluation · or open **Attack Viz** at `/viz`  
5. **Feedback** — clear logs, tweak thresholds in `.env`, or retrain — then repeat

```powershell
python -m evaluation.evaluate --from-db
```

Evaluation also writes miss lists under `results/misses_*.csv` for the retrain loop.

## Attack Viz (simulation replay)

Visual timeline of sandboxed attack simulations. The CLI still works unchanged; pass `--events-file` to also record structured JSON Lines for replay.

### Demo without running attacks

```powershell
python -m app.app
# open http://127.0.0.1:5000/viz   (or :8080 if FLASK_PORT unset)
```

Sample runs ship under `viz/sample_runs/` (SQLi, XSS, session, OFF/MONITOR/BLOCK experiment). Regenerate with:

```powershell
python viz/generate_samples.py
```

### Record a live lab run

```powershell
python -m attacker.sqli_attack --events-file results/runs/sqli_live.jsonl
python -m attacker.xss_attack --events-file results/runs/xss_live.jsonl
python -m attacker.session_attacks --events-file results/runs/session_live.jsonl
python -m evaluation.evaluate --run-experiment --events-file results/runs/experiment_live.jsonl
```

Then open **Attack Viz** → Recorded runs. Each event includes command, action, log, result, score, and the weakness / mitigation callout for that step. Experiment runs unlock the **Vulnerable vs mitigated** panel (OFF vs MONITOR vs BLOCK).

### Viz layout

```
viz/
  routes.py            /viz blueprint + JSON APIs
  static/              viz.css / viz.js
  templates/viz/       replay UI
  sample_runs/         offline demo JSONL
  generate_samples.py  rebuild sample datasets
```

## Project layout

```
cybermirror/
  app/                 Flask app + monitoring + console
  models/              Saved .joblib detectors
  training/            Offline training scripts + datasets
  attacker/            Normal + attack traffic generators (+ optional --events-file)
  evaluation/          Score labeled runs → results/
  viz/                 Attack simulation replay UI (/viz)
  results/             evaluation.csv / evaluation.json / misses_*.csv / runs/
  .env                 Local secrets (never commit)
```

## Safety

- Attack traffic must stay on **localhost / private lab IPs**
- Demo search uses **fake SQLite data only** — not MySQL
- Detectors never read `X-Test-Label` (labels are for evaluation only)

## License

See [LICENSE](LICENSE).
