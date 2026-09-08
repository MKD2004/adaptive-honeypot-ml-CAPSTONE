# 🛡️ Adaptive Honeypot ML System (CAPSTONE)

An intelligent, self-evolving cybersecurity system that detects, deceives, and adapts to real-world attacks using Machine Learning and threat intelligence.

**Pipeline:** `Traffic → Gateway → Cowrie → 128 Features → MT3 → Adaptive Config → Logger → Dashboard`

---

# 🎬 FULL PIPELINE DEMO — copy-paste these

> Runs the complete end-to-end system with three simulated attacker sessions.
> **No network, no live attacker, no Cowrie instance required.** Takes ~37 seconds.

### Terminal 1 — start the system (leave it running)

```powershell
cd C:\Users\mahit\OneDrive\Desktop\adaptive-honeypot-ml-CAPSTONE
.\honeypot_dataset\venv\Scripts\python.exe -m traffic_gateway.run_pipeline
```

Wait ~13 seconds for the `Pipeline ready:` banner:

```
  ==============================================================
  Pipeline ready:
    MT3 model:  loaded (3,759,510 params, cuda, val macro-F1 0.9599)
    Semantic:   yes
    KEV cache:  1,675 CVEs loaded
    Watching:   honeypot_dataset\cowrie\logs  (poll 30s)
    Dashboard:  http://localhost:5000/pipeline
    API:        http://localhost:5000/api/live-feed
  ==============================================================
```

### Browser — open this and leave it on screen

```
http://localhost:5000/pipeline
```

It starts **empty**. That is intentional — the panel watches it fill up live.

### Terminal 2 — run the demo

```powershell
cd C:\Users\mahit\OneDrive\Desktop\adaptive-honeypot-ml-CAPSTONE
.\honeypot_dataset\venv\Scripts\python.exe demo\simulate_attack.py --reset-config
```

### Expected result

```
  #  scenario                       gw     MT3 micro-state     conf   ph  interaction  config
  1  Reconnaissance + Brute Force   1.000  ACCESS_BRUTE_SSH    0.775  1   low          -
  2  Execution + Discovery          0.480  DISC_PROC_ENUM      0.996  3   medium       CHANGED
  3  Privilege Escalation+Persist   0.700  EVASION_HIST_ERASE  0.569  6   high         CHANGED
```

The honeypot escalates **low → medium → high** as the attacker moves down the kill chain,
each change logged with its cause, e.g.
`"Phase 3->6, interaction medium->high: EVASION_HIST_ERASE detected"`.

---

## ⚠️ Demo gotchas (read before presenting)

| Gotcha | Why it matters |
|---|---|
| **Always pass `--reset-config`** | Without it the honeypot is still HIGH from the last run, every scenario prints "No change", and the escalation story disappears. This is the #1 way to fluff the demo. |
| **Use the full `.\honeypot_dataset\venv\Scripts\python.exe` path** | Plain `python` is 3.14 on PATH with no torch — it fails instantly. |
| **Do NOT start `dashboard/backend.py`** | It also claims port 5000 and will collide. `run_pipeline` already serves both pages. |
| **Two terminals, not one** | Terminal 1 blocks on the log watcher by design. |

### If the dashboard dies mid-demo

The demo **does not need the API** — it loads its own MT3 and writes results regardless.
Keep narrating Terminal 2's timeline (it prints all 6 stages per scenario); the dashboard
will show everything as soon as you restart it.

### Useful variations

```powershell
# Re-run one scenario only (~15s), e.g. for a follow-up question
.\honeypot_dataset\venv\Scripts\python.exe demo\simulate_attack.py --scenario 2 --reset-config

# Slow it down to narrate each stage
.\honeypot_dataset\venv\Scripts\python.exe demo\simulate_attack.py --reset-config --pause 1.5

# Instant, no pauses
.\honeypot_dataset\venv\Scripts\python.exe demo\simulate_attack.py --reset-config --pause 0

# Terminal shows escape-code garbage instead of colour
.\honeypot_dataset\venv\Scripts\python.exe demo\simulate_attack.py --reset-config --no-color
```

### Reset to a clean slate between practice runs

```powershell
cd C:\Users\mahit\OneDrive\Desktop\adaptive-honeypot-ml-CAPSTONE
Remove-Item logs\pipeline_results.jsonl,logs\honeypot_config_changes.jsonl -ErrorAction SilentlyContinue
.\honeypot_dataset\venv\Scripts\python.exe -c "from adaptive_honeypot.configurator import configurator; configurator.reset()"
```

### Port 5000 already in use

```powershell
Get-NetTCPConnection -LocalPort 5000 -State Listen | Select-Object OwningProcess
Stop-Process -Id <PID_FROM_ABOVE>
```

---

## ❓ The question the panel will ask

Scenario 3's confidence (0.57) is visibly lower than scenario 2's (0.996).

**The honest answer is the strong one:** `EVASION_*` and `PERSIST_*` are among the nine
micro-states with **no real-data anchor**. Genuinely real data is CIC-IDS2017 + UNSW-NB15
only, which anchor **13 of 45** classes — all network-flow. The honeypot-command classes
are synthetic (see `DECISIONS.md`, 2026-08-28). Low confidence there is the model
correctly reflecting where the data is weak, and the `top-3` line on screen shows it
spreading probability across neighbouring evasion states rather than over-committing.
The phase decision (6 → high interaction) is right either way.

---

# 🧩 What the pipeline actually does

| Stage | Module | Behaviour |
|---|---|---|
| 1. Pre-filter | `traffic_gateway/traffic_classifier.py` | Scores each connection on IP reputation (blacklist/whitelist/geo/JA3), behaviour (conn rate, port scan, failed auth) and payload statistics → `MALICIOUS` / `SUSPICIOUS` / `BENIGN` → `ENGAGE` / `DECOY` / `LOG_ONLY` |
| 2. Capture | Cowrie | Writes the session's event stream to a JSON log |
| 3. Parse | `honeypot_dataset/src/parsers/cowrie_parser.py` | Collapses events into one session record — **byte-identical to notebook 01** (verified on 1,795 sessions × 11 fields, 0 mismatches) |
| 4. Features | `honeypot_dataset/src/extractors/` | 128 features in 6 groups: A temporal (24), B network (28), C payload (24), D semantic (30, DistilBERT+PCA), E threat intel (14, live KEV/EPSS), F TLS/host (8) |
| 5. Classify | `ml_analytics/artifacts/mt3_full_d256/best.pt` | MT3 (3.76M params) → one of 45 MITRE-mapped micro-states + kill-chain phase + confidence |
| 6. Adapt | `adaptive_honeypot/configurator.py` | Phase → interaction level; trending-CVE banner overlay; writes `active_config.json` |
| 7. Log | `logs/pipeline_results.jsonl` | One structured JSON line per session |
| 8. Show | `dashboard/static/pipeline.html` | Live feed, phase distribution, active config, blacklist/whitelist controls |

**Adaptive behaviour by kill-chain phase:**

| Phase | Interaction | What the attacker sees |
|---|---|---|
| 0–1 Recon / Initial Access | `low` | Minimal fake filesystem, 1200 ms responses — waste their time, fingerprint the tool |
| 2–3 Execution / Discovery | `medium` | Richer filesystem, fake credentials visible — let them reveal their tooling |
| 4–6 PrivEsc / Persistence / Evasion | `high` | Full fake system, fake `/etc/shadow`, plantable SSH keys — capture the full toolkit |
| 7–8 Lateral / Exfiltration | `maximum` | All of the above **+ external alert armed** — they believe they succeeded |

---

# 📁 Project Structure

```
adaptive-honeypot-ml-CAPSTONE/
│
├── traffic_gateway/            # Proxy, IP classification, rate limiting + THE PIPELINE
│   ├── inspection_gateway.py   #   async TCP gateway (run separately)
│   ├── traffic_classifier.py   #   pre-MT3 filter (3 signal families)
│   ├── feature_bridge.py       #   128 features -> scaler -> MT3 inference
│   ├── post_session_pipeline.py#   Cowrie log watcher -> MT3 -> config -> JSONL
│   ├── api.py                  #   Flask API + dashboard (port 5000)
│   └── run_pipeline.py         #   ORCHESTRATOR - starts everything
│
├── adaptive_honeypot/
│   └── configurator.py         # MT3 prediction -> live honeypot config
│
├── demo/
│   └── simulate_attack.py      # 3-scenario panel demo (no network needed)
│
├── honeypot_dataset/           # Dataset pipeline (HoneySynth-960k) - DO NOT RUN
│   ├── configs/schema.py       #   45 micro-states, 128 features, kill-chain DAG
│   ├── src/extractors/         #   the 6 feature extractors
│   ├── src/parsers/            #   cowrie_parser.py (extracted from notebook 01)
│   └── notebooks/              #   01-05, frozen
│
├── ml_analytics/               # MT3 + CNN-LSTM baseline + trained artifacts
├── cve_intelligence/           # NVD / EPSS / CISA-KEV / ExploitDB clients
├── dashboard/static/           # index.html (gateway events) + pipeline.html (MT3)
├── response_mitigation/        # Firewall / IP blocking (scaffolding)
└── logs/                       # pipeline_results.jsonl (generated)
```

---

# 📊 Model Results

Same frozen splits, macro-F1 over the 21 classes present in `test_real`:

| model | params | val macro-F1 | test_real (clean) | test_synth |
|---|---|---|---|---|
| linear probe | 5,805 | 0.9376 | 0.7551 | 0.9373 |
| CNN-LSTM baseline | 189,581 | 0.9621 | 0.7976 | 0.9610 |
| **MT3 (d=256, 4 layers)** | **3,759,510** | **0.9599** | **0.8187** | 0.9589 |

**Headline finding:** on `test_real` the two models **tie** (McNemar p = 0.617), so MT3's
Transformer fusion does not beat concatenation + MLP at 20× the parameters. Quote the
**clean** column — 29.74% of `test_real` rows are byte-identical to training rows.
See `STATUS.md` and `DECISIONS.md`.

---

# ⚙️ Setup (first time on a new machine)

```bash
git clone https://github.com/MKD2004/adaptive-honeypot-ml-CAPSTONE.git
cd adaptive-honeypot-ml-CAPSTONE
pip install -r requirements.txt
pip install flask flask-cors watchdog
```

The pipeline needs, in addition to the dataset venv's ML stack:
`flask`, `flask-cors`, `watchdog`.

**Required artifacts** (not in git — large files):
* `ml_analytics/artifacts/mt3_full_d256/best.pt` — the trained MT3 checkpoint
* `honeypot_dataset/data/final/feature_scaler.pkl` — the frozen scaler
* `honeypot_dataset/data/processed/semantic_pca.pkl` — the fitted PCA

Without `semantic_pca.pkl` the pipeline still runs, but Group D (30 of 128 features)
is zero-filled and the banner reports `Semantic: NO`.

---

# 🚦 Module 1 Demo: Traffic Gateway only (Stage 1, legacy)

The original network-level demo. Independent of the ML pipeline above.

**Step 1 — fake honeypot**
```bash
python fake_web.py
```

**Step 2 — traffic gateway**
```bash
python -m traffic_gateway.inspection_gateway
```

**Step 3 — legacy dashboard** (use a port other than 5000 if the pipeline is running)
```bash
python dashboard/backend.py --host 0.0.0.0 --port 5001
```

**Step 4 — send traffic**
```bash
curl http://localhost:8080/
```

**Step 5 — LAN demo**: find your IP with `ipconfig`, then from other laptops:
```bash
curl http://192.168.1.5:8080/
```

**Step 6 — trigger rate limiting**
```bat
for /l %i in (1,1,30) do curl http://192.168.1.5:8080/
```

**Backup — dashboard demo mode**
```bash
python dashboard/backend.py --demo --port 5001
```

---

# 📖 Reference Docs

| File | Contents |
|---|---|
| `CLAUDE.md` | Repo layout, schema summary, conventions, current status |
| `SCHEMA.md` | Full 45 micro-state / 128-feature reference |
| `DECISIONS.md` | Why things were built a certain way — **read before rewriting anything** |
| `ERRORS.md` | Bugs already hit and fixed — check before re-debugging |
| `STATUS.md` | Live pipeline stage, machine-tagged |
| `TEAMMATES.md` | Hard rules for collaborators (do not run the notebooks) |

---

# 📈 Future Enhancements

* Real CRF over `KILL_CHAIN_DAG` (MT3 currently has none — see `DECISIONS.md`)
* Genuinely real Cowrie logs to anchor the 9 synthetic-only micro-states
* Reinforcement learning for adaptive defence
* Distributed honeypot network + SIEM integration
