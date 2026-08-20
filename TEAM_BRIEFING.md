# TEAM BRIEFING — Adaptive Honeypot and ML Threat Gateway
### HoneySynth-1M Capstone Project
**PES University · Team UE23CS320A · B.Tech CSE 2023–2027**  
**Last Updated:** 2026-08-06 (status audited against repo — see §8) ·
Status: Dataset pipeline has a class-coverage bug, fixed at the real-data
layer but not yet propagated through TabSyn (rerun needed on college
machine); MT3 architecture written; baseline model, training script, and
React dashboard described below are not yet present in this repo

---

## 1. What We Are Building

An **Adaptive Honeypot Gateway** — a system that sits at the network boundary,
intercepts incoming connections, classifies them using a trained ML model, and
routes them to the most appropriate honeypot decoy. The model learns from a
large, richly-labeled dataset of attack sessions to recognize 45 distinct
attack micro-states across the full kill chain, then deploys the right
deception environment in real time.

```
Attacker
   ↓
Traffic Gateway (Python asyncio TCP proxy)
   ↓
MT3 Model (MITRE-Aware Temporal Threat Transformer)
   ↓ classifies micro-state (45 classes) + honeypot target (4 classes)
   ↓
Route to: SSH_HONEYPOT / WEB_HONEYPOT / DB_HONEYPOT / AUTH_HONEYPOT
   ↓
Log everything → Dashboard → CVE Intelligence → Adapt
```

The paper's novel contributions are:
1. **HoneySynth-1M** — a 1.2M session dataset fusing live threat intelligence
   (CVSS, EPSS, CISA KEV) directly into network session features
2. **MT3 architecture** — a transformer with kill-chain phase positional
   encoding and CRF decoding that guarantees operationally valid predictions
3. **EPSS temporal drift injection** — simulating how exploit probability
   scores evolve when a CVE enters the CISA KEV catalog (no existing dataset does this)

---

## 2. Repository Structure

**Reconciled against the actual repo on 2026-08-06.** Items that don't
exist are marked `[MISSING]` rather than removed from the tree, so the
diagram still communicates the intended design — just be aware these paths
will 404 until someone builds them.

```
adaptive-honeypot-ml-CAPSTONE/
│
├── honeypot_dataset/                 ← DATASET PIPELINE (Mahith)
│   ├── configs/
│   │   └── schema.py                 ← READ THIS FIRST — all 45 labels,
│   │                                    128 features, kill-chain DAG
│   ├── src/
│   │   ├── extractors/               ← 6 feature group extractors
│   │   │   ├── temporal.py           ← Group A: 24 features → LSTM
│   │   │   ├── network.py            ← Group B: 28 features → CNN
│   │   │   ├── payload.py            ← Group C: 24 features → CNN
│   │   │   ├── semantic.py           ← Group D: 30 features → DistilBERT
│   │   │   ├── threat_intel.py       ← Group E: 14 features → CNN+LSTM
│   │   │   ├── tls_host.py           ← Group F:  8 features → CNN
│   │   │   └── pipeline.py           ← orchestrates all 6
│   │   ├── generators/
│   │   │   ├── kill_chain_simulator.py ← Markov DAG simulator + KCVR
│   │   │   ├── fill_missing_classes.py ← rule-based sessions for the 35
│   │   │   │                             classes real data never covers
│   │   │   └── epss_drift.py           ← temporal EPSS drift (novel)
│   │   └── validators/
│   │       └── quality_checks.py     ← Wasserstein, adversarial AUC, TSTR
│   ├── notebooks/
│   │   ├── 01_process_real_data.ipynb     ← parse Cowrie + CIC/UNSW ✅
│   │   ├── 02_feature_extraction.ipynb    ← extract all 128 features ✅
│   │   ├── 03_tabsyn_generation.ipynb     ← 🔴 needs rerun — its output
│   │   │                                    (tabsyn/data/honeypot_sessions/)
│   │   │                                    still reflects the stale
│   │   │                                    10-class data; see §8
│   │   ├── 04_great_generation.ipynb      ← GReaT 240k ⬜ pending
│   │   └── 05_assembly_validation.ipynb   ← final merge + splits ⬜
│   ├── data/
│   │   ├── raw/                      ← CIC/UNSW CSVs + Cowrie logs go here
│   │   ├── processed/                ← X_real.npy, y_real.npy — now 45/45
│   │   │                                classes after fill_missing_classes.py
│   │   ├── backup_processed/         ← pre-fix snapshot (10/45 classes),
│   │   │                                keep until the 45-class merge is
│   │   │                                validated on the college retrain
│   │   └── synthetic/                [MISSING] — not created; TabSyn/GReaT
│   │                                    output currently lives at repo-root
│   │                                    data/synthetic/ and tabsyn/data/
│   │                                    instead (see below)
│   └── README_DATASET.md             [MISSING] — not found anywhere in repo
│
├── models/                           ← ML MODELS
│   ├── mt3/
│   │   └── architecture.py           ← MT3 (main contribution) ✅ confirmed:
│   │                                    CRF head, FeatureGroupTokenizer,
│   │                                    KillChainPhaseEncoding, MT3 module
│   └── baselines/                    [MISSING] — directory doesn't exist.
│       └── cnn_lstm_distilbert.py    [MISSING] — the closest same-named
│                                        file, ml_analytics/models/cnn_lstm.py,
│                                        is a 0-byte stub, not this baseline
│
├── training/                         [MISSING] — directory doesn't exist,
│   ├── train.py                        not even in git history. Nothing to
│   └── configs/                        run "python training/train.py" against
│       ├── laptop.yaml                 yet — needs to be written.
│       └── college.yaml
│
├── cve_intelligence/                 ← CVE PIPELINE — ✅ confirmed present,
│   ├── pipeline.py                     with live output data already on
│   ├── config.py                       disk (cve_intelligence/data/
│   ├── clients/                        trending_profiles.json,
│   │   ├── nvd.py                      cve_priority_results.csv)
│   │   ├── cisa.py
│   │   ├── cveorg.py
│   │   ├── exploitdb.py
│   │   └── mitre.py
│   ├── analyzers.py
│   └── config_generator.py
│
├── honeypot-dashboard/               [MISSING] — this React+Vite frontend
│   └── src/                            doesn't exist. What exists instead:
│       ├── pages/                      dashboard/backend.py (Flask) +
│       └── components/                 dashboard/static/index.html
│
├── CLAUDE.md                         ← Claude Code project context (read auto)
├── README_DATASET.md                 [MISSING] — not found anywhere in repo
└── TEAM_BRIEFING.md                  ← this file
```

---

## 3. The Dataset — HoneySynth-1M

### Composition

| Source | Sessions | % | Status |
|---|---|---|---|
| Cowrie SSH honeypot (real) | 180,000 | 15% | ⬜ Pending deployment |
| CIC-IDS2017 + UNSW-NB15 (real, transfer) | 60,000 | 5% | ✅ Processed |
| TabSyn synthetic (VAE + diffusion) | 720,000 | 60% | 🔄 VAE training |
| GReaT synthetic (fine-tuned GPT-2) | 240,000 | 20% | ⬜ Pending |
| **Total** | **1,200,000** | 100% | |

### Why Mostly Synthetic

Real honeypot logs are heavily imbalanced — 90%+ of Cowrie sessions are
SSH brute-force and port scans. Rare but critical states like
`EXFIL_DNS_TUNNEL`, `PRIVESC_CONTAINER_ESC`, `PERSIST_SYSTEMD_SVC` may
appear fewer than 10 times in months of real logs. The synthetic generators
(TabSyn + GReaT) are trained on real sessions and learn to reproduce their
statistical structure, then generate balanced samples across all 45 classes.

Two generators are used deliberately — if a model trained on TabSyn output
transfers to GReaT output AND to real held-out Cowrie sessions, it learned
genuine attack patterns, not one generator's artifacts.

### 128 Feature Groups

Every session becomes a 128-dimensional vector:

| Group | Cols | Features | Fed To |
|---|---|---|---|
| A Temporal | 0–23 | IAT timing, bursts, session rhythm | LSTM |
| B Network | 24–51 | Bytes, packets, TCP flags, ports | CNN |
| C Payload | 52–75 | Entropy, obfuscation, encoding signals | CNN |
| D Semantic | 76–105 | DistilBERT CLS → PCA(30) of command text | DistilBERT branch |
| E Threat Intel | 106–119 | CVSS, EPSS, KEV, CVE age, exploit signals | CNN+LSTM |
| F TLS/Host | 120–127 | JA3 fingerprint, TLS version, geo risk | CNN |

**Group E is the dataset's defining novelty.** No existing public honeypot
dataset fuses live threat intelligence scores into per-session features.

### 45 Micro-States — MITRE ATT&CK Mapped

| Phase | States | IDs |
|---|---|---|
| 0 Reconnaissance | 6 | 0–5 |
| 1 Initial Access | 6 | 6–11 |
| 2 Execution | 6 | 12–17 |
| 3 Discovery | 5 | 18–22 |
| 4 Privilege Escalation | 4 | 23–26 |
| 5 Persistence | 5 | 27–31 |
| 6 Defense Evasion | 5 | 32–36 |
| 7 Lateral Movement | 3 | 37–39 |
| 8 Exfiltration | 5 | 40–44 |

Full label list with MITRE IDs: `configs/schema.py → MICRO_STATES`

### Secondary Label — honeypot_target

Each session also has a 4-class deployment label:
- `SSH_HONEYPOT` — shell-based attack stages (majority)
- `WEB_HONEYPOT` — HTTP/HTTPS exfil or web attacks
- `DB_HONEYPOT` — database-targeting sessions (port-derived)
- `AUTH_HONEYPOT` — credential-stuffing and auth-bypass

This enables MT3's multi-task head: one forward pass produces both
the micro-state prediction AND the deployment recommendation.

### Metadata Fields (Not in Training Features)

Stored in `metadata_*.parquet`, row-aligned with `X_*.npy`:

| Field | Description |
|---|---|
| session_id | Unique per session |
| campaign_id | Groups sessions from same attacker in same time window |
| attacker_id | Stable fingerprint from JA3 hash (survives IP rotation) |
| timestamp | Session start UTC |
| source | cowrie_real / cic_transfer / tabsyn_synthetic / great_synthetic |
| honeypot_target | SSH / WEB / DB / AUTH deployment recommendation |

---

## 4. The Kill-Chain DAG

Every attack state has a set of valid next states. This DAG is enforced
in two places:

1. **`kill_chain_simulator.py`** — generates synthetic sessions that only
   follow valid transitions (RECON → ACCESS → EXEC, never backwards)
2. **MT3's CRF head** — at inference time, Viterbi decoding guarantees
   the predicted sequence is DAG-valid. CNN-LSTM baseline uses plain
   softmax and can produce invalid sequences.

**Kill-Chain Violation Rate (KCVR)** is a key paper metric:
- CNN-LSTM baseline: ~4–8% KCVR (softmax is unconstrained)
- MT3 with CRF: 0.00% KCVR (guaranteed by construction)

Full DAG: `configs/schema.py → KILL_CHAIN_DAG`

---

## 5. The ML Models

### Model 1 — CNN-LSTM-DistilBERT (Strong Baseline)

**[MISSING] — this is a design spec, not implemented code.** Confirmed
2026-08-06: `models/baselines/` doesn't exist anywhere in the repo, and
`ml_analytics/models/cnn_lstm.py` (the closest same-named file) is a 0-byte
stub from the original scaffold, unrelated to this design. The architecture
below still describes the intended model — someone needs to write it.

Three parallel branches consuming different feature groups:

```
Input x (B, 128)
     │
     ├── CNN branch    x[:,24:76]  (52 dims, Groups B+C)
     │   Conv1D → ResBlock → Pool → Conv1D → Pool
     │   Output: spatial_features (B, 256)
     │
     ├── LSTM branch   x[:,0:24] + x[:,106:128]  (46 dims, Groups A+E+F)
     │   BiLSTM → LSTM → TemporalAttention
     │   Output: temporal_features (B, 256)
     │
     └── Semantic branch  x[:,76:106]  (30 dims, Group D)
         Linear(30→128) → GELU
         Output: semantic_features (B, 128)
         
Fusion: concat → (B, 640)
        Linear(640→256) → BN → GELU → Dropout
        Linear(256→128) → BN → GELU → Dropout
        Linear(128→45)  → LogSoftmax

Output: logits (B, 45) — no kill-chain guarantee
```

File (to be written): `models/baselines/cnn_lstm_distilbert.py`

### Model 2 — MT3: MITRE-Aware Temporal Threat Transformer (Main Contribution)

```
Input x (B, 128)
     │
     └── split_features() → 6 group tensors
          │
          ├── FeatureGroupTokenizer
          │   6 × Linear(group_size → 256) → LayerNorm → GELU
          │   → stack → (B, 6, 256)  [6 tokens, one per feature group]
          │
          ├── + GroupTypeEmbedding(6, 256)   [which group is this?]
          ├── + KillChainPhaseEncoding(9, 256) [what kill-chain phase?]
          │
          ├── TransformerEncoder
          │   Pre-LN, 4 layers, 8 heads, d_model=256
          │   → (B, 6, 256)
          │
          └── flatten → (B, 1536)
               │
               ├── ClassifierHead → emissions (B, 45)
               │   Linear(1536→512)→LN→GELU→Dropout
               │   Linear(512→256)→LN→GELU→Dropout
               │   Linear(256→45)
               │
               ├── CRF head
               │   Training: -crf(emissions, labels) = NLL loss
               │   Inference: crf.decode() = Viterbi → valid sequence
               │
               └── HoneypotHead → logits (B, 4)
                   Linear(1536→128)→GELU→Dropout→Linear(128→4)

Multi-task loss = CRF_NLL + 0.3 × CrossEntropy(honeypot_logits)
```

File: `models/mt3/architecture.py` — ✅ confirmed present and matches this
spec (CRF, FeatureGroupTokenizer, KillChainPhaseEncoding, ClassifierHead,
HoneypotHead, MT3 module all found in the file, 2026-08-06).

**Three architectural novelties vs. baseline:**
1. Feature group tokenization — each group becomes a separate transformer token,
   learning cross-group attention (how TI features modulate temporal patterns)
2. Kill-chain phase positional encoding — model knows where in the attack
   lifecycle the current session sits
3. CRF decoding — KCVR=0.00% guaranteed at inference

### Training Script

**[MISSING] — `training/train.py` does not exist**, and neither does
`training/` itself (confirmed 2026-08-06, not even in git history). The
commands below describe the intended interface, not something that runs
today. Writing this script is a prerequisite for any of the model-training
or ablation items in §8's NEXT list.

```powershell
# Laptop (dev mode — fast iteration, subsampled)
python training/train.py --hardware laptop --model mt3 --debug

# College system (full training)
python training/train.py --hardware college --model mt3
python training/train.py --hardware college --model cnn_lstm
```

---

## 6. The CVE Intelligence Pipeline

Runs on a schedule and outputs `cve_intelligence/data/trending_profiles.json`
which the Traffic Gateway uses to configure honeypot service profiles.

```
CISA KEV catalog (primary) ← real-time active exploitation list
        ↓
NVD API v2.0 (secondary)   ← CVSS score enrichment per CVE
        ↓
EPSS API (FIRST.org)       ← daily exploitation probability
        ↓
ExploitDB CSV (GitLab)     ← public exploit availability
        ↓
Priority scoring:
  score = 0.40×cvss_norm + 0.35×epss_score + 0.25×is_kev
        ↓
Honeypot config generation ← which emulator to deploy per attack type
        ↓
trending_profiles.json      ← read by Traffic Gateway
```

**IMPORTANT — NVD Backlog (April 2026):**
NIST formally stopped enriching most CVEs. Only KEV/federal/EO14028-critical
CVEs receive CVSS within one business day. Our pipeline now treats CISA KEV
as the PRIMARY source. KEV-confirmed CVEs without CVSS get a floor score of
`cvss_norm=0.85` — KEV membership proves active exploitation regardless of
whether NIST has scored it yet. See `cve_intelligence/docs/nvd_backlog_note.md`.

Run the pipeline:
```powershell
python -m cve_intelligence.pipeline --days 7
```

---

## 7. The React Dashboard

A multi-page live monitoring dashboard built in React + Vite + Tailwind.
Light enterprise theme. All animations implemented natively (no extra libs).

Pages:
- **Overview** — KPI cards with counter animation, threat level gauge
- **IP Matrix** — per-IP cards with risk score bars, border glow on high-risk IPs
- **Live Feed** — terminal-style event log with slide-in animation,
  scrambled-text effect on ML SCORE events
- **Analytics** — Recharts line + donut charts, connection rate over time
- **Gateway Health** — service status, model uptime

Run locally:
```powershell
cd honeypot-dashboard
npm install
npm run dev
# → http://localhost:5173
```

---

## 8. Current Status — What's Done and What's Next

**This section was audited against the actual repo contents on 2026-08-06 —**
**see the note at the end for what was and wasn't re-checked.**

```
✅ COMPLETE (verified present and working in the repo)
   Schema design (45 micro-states, 128 features, kill-chain DAG)
     honeypot_dataset/configs/schema.py — internally consistent
   Notebook 01 — real data processed (CIC-IDS2017 + UNSW-NB15)
   Notebook 02 — all 128 features extracted and validated (original run):
     • Shape (717,810 × 128) ✓
     • Zero NaN/Inf ✓
     • All 6 feature groups active ✓
     • 66% unique semantic vectors (Group D fix applied) ✓
     • Raw bytes_out heavy-tailed by design; log twin well-behaved ✓
   fill_missing_classes.py (new) — generates rule-based sessions for the
     35 classes real data never covered, merges into X_real.npy/y_real.npy.
     Already run once: X_real.npy now 892,810 rows, all 45 classes present
     (verified directly). Pre-fix data kept at data/backup_processed/.
   MT3 architecture written — models/mt3/architecture.py (22KB), confirmed:
     CRF head, FeatureGroupTokenizer, KillChainPhaseEncoding, ClassifierHead,
     HoneypotHead, MT3 module all present and structured as designed.
   TabSyn VAE training completed 500/500 epochs, converged cleanly, no
     divergence (data/synthetic/tabsyn_status.txt) — mechanically sound,
     but trained on the pre-fix 10-class data (see BROKEN section below).

🔴 BROKEN / MUST BE REDONE (found and fixed at the data layer this session,
   TabSyn side still needs a rerun — do this on the college machine)
   Root cause of "35 classes never generated": Notebook 03 builds TabSyn's
     train/test CSVs directly from X_real.npy/y_real.npy and only resamples
     classes already present — it never injects the missing ones. Since it
     was run before fill_missing_classes.py existed, tabsyn/data/
     honeypot_sessions/train.csv still contains only 10/45 classes today
     (verified directly), even though the source X_real.npy has been fixed.
     info.json in that folder was hand-edited to claim 45 classes but its
     row counts match neither the old nor the new data — don't trust it.
   TabSyn diffusion training collapsed at epoch 120/2000: loss stable and
     decreasing to epoch 119 (0.0805), then jumped to 0.70 and never
     recovered — stuck there until early stopping kicked in around epoch
     618. All three saved checkpoints (200/400/600) were written after the
     collapse and were unusable; they and the stale 10-class sample CSV
     have been deleted (~3GB reclaimed) so nothing broken gets mistaken for
     real output later.

⬜ NOT YET IMPLEMENTED (previously marked ✅ in this doc — corrected)
   training/train.py + training/configs/{laptop,college}.yaml — does not
     exist anywhere in the repo or in git history. Never created.
   models/baselines/cnn_lstm_distilbert.py — does not exist.
     ml_analytics/models/cnn_lstm.py exists but is a 0-byte stub from the
     original project scaffold, unrelated to this design.
   honeypot-dashboard/ (React + Vite, 5 pages) — does not exist. Only
     dashboard/ exists (Flask backend.py + one static HTML page).

⬜ NEXT (this week)
   Rerun Notebook 03 on the college machine from the corrected, 45-class
     X_real.npy/y_real.npy so it regenerates train.csv/test.csv/info.json
     from scratch (don't hand-edit info.json again).
   Retrain TabSyn VAE (mandatory — the existing run only ever saw 10
     classes) and diffusion (watch for a repeat of the epoch-120 collapse;
     consider gradient clipping / a lower LR if it recurs).
   Run GReaT fine-tuning and sampling (Notebook 04, college system)
   Notebook 05 — assemble final 1.2M dataset
   Write training/train.py and models/baselines/cnn_lstm_distilbert.py —
     both are prerequisites for "run all 7 models" below and don't exist yet
   Run all 7 models for paper Table 2 (college system)
   Run 3 ablation studies for paper Table 3

⬜ LATER (not re-verified this session — status as previously documented)
   Cowrie honeypot deployment (Docker on cloud VM) — deployment files exist
     at honeypot_dataset/cowrie/, not yet run; data/raw/cowrie_logs/ has a
     small cowrie.json but not the target 180k sessions
   MT3 full training on college system (RTX 4500 Ada)
   honeypot-dashboard/ React frontend — build from scratch, doesn't exist
   Paper write-up (Tables 1–4, architecture figure, results)

Not re-checked in this audit: cve_intelligence/, traffic_gateway/,
adaptive_honeypot/, response_mitigation/, monitoring/. Their status lines
elsewhere in this doc are carried over unverified — confirm before relying
on them for the paper or a demo.
```

---

## 9. Hardware Guide — What Runs Where

**Note (2026-08-06):** the `training/train.py` commands below are the
intended interface — the script doesn't exist yet (see §5), so these won't
run today. The hardware split itself (laptop for dev/smoke-tests, college
machine for real training runs) is still the right plan and applies equally
to whatever ends up training MT3/the baseline, and to the TabSyn rerun.

### Mahith's Laptop — RTX 3050 (4GB VRAM)
Use for: code writing, debugging, quick smoke tests, Notebook 01-02,
dashboard development, anything that fits in 4GB VRAM with fp16.

```powershell
# Dev mode — always subsample first to catch bugs fast
python training/train.py --hardware laptop --model mt3 --debug
# 5 epochs on 500 rows, takes ~2 minutes, confirms no crashes
```

**Never run full training on the laptop.** It either OOMs or takes 10x longer.
The laptop is also where the TabSyn diffusion run collapsed at epoch 120/2000
(see §8) — worth keeping in mind if VRAM-related instability is a suspect.

### College System — RTX 4500 Ada (24GB VRAM, 128GB RAM, i9 13th Gen)
Use for: Notebook 03 (TabSyn — rerun needed on the corrected 45-class data),
Notebook 04 (GReaT), Notebook 05 (assembly), all 7 model training runs,
ablation studies.

```powershell
python training/train.py --hardware college --model mt3
# Full 100 epochs on 1.2M sessions, ~8-10 hours
```

### TabSyn — Specific Setup Required

TabSyn is NOT on PyPI. Must be cloned separately:
```powershell
git clone https://github.com/amazon-science/tabsyn.git
cd tabsyn
pip install -r requirements.txt
```

Six patches were supposedly applied to make it work on 4GB VRAM, documented
at `honeypot_dataset/docs/tabsyn_patches.md` — **that file doesn't exist**
(confirmed 2026-08-06; `honeypot_dataset/docs/` isn't present at all, only
the unrelated root-level `docs/` with architecture diagrams). Either the
patches were never written up, or the notes live somewhere outside this
repo — track them down or re-document them before the college retrain, so
whoever runs it isn't rediscovering the same fixes from scratch.

---

## 10. Environment Setup (New Team Member)

```powershell
# 1. Clone the repo
git clone https://github.com/YOUR_USERNAME/adaptive-honeypot-ml-CAPSTONE.git
cd adaptive-honeypot-ml-CAPSTONE\honeypot_dataset

# 2. Create virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# If Activate.ps1 blocked by policy:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# 3. Install dependencies
pip install -r requirements.txt
pip install python-dotenv

# 4. Set up environment variables
cp .env.example .env
notepad .env
# Add: NVD_API_KEY=your_key (get from nvd.nist.gov/developers/request-an-api-key)

# 5. Place real data files
# data/raw/cic_ids2017/ ← 8 CSV files (MachineLearningCSV.zip from UNB)
# data/raw/unsw_nb15/  ← UNSW_NB15_training-set.csv + testing-set.csv

# 6. Verify everything imports
python -c "
import sys; sys.path.insert(0, '.')
from configs.schema import MICRO_STATES, N_CLASSES, N_FEATURES
from src.extractors.temporal import extract_temporal
from src.generators.kill_chain_simulator import generate_session_sequence
import random
seq = generate_session_sequence(random.Random(42), min_len=3)
print(f'Schema OK: {N_CLASSES} classes, {N_FEATURES} features')
print(f'Kill-chain seq: {seq}')
print('Setup verified')
"

# 7. Launch Jupyter
jupyter notebook
```

---

## 11. Claude Code Setup

Every team member with Claude Pro should set up Claude Code so the
project context loads automatically:

```powershell
npm install -g @anthropic-ai/claude-code
cd C:\path\to\adaptive-honeypot-ml-CAPSTONE
claude
```

Claude Code reads `CLAUDE.md` automatically on every session start.
You don't need to re-explain the schema, feature groups, or architecture
— it already knows the project.

If Claude Code seems to have forgotten context mid-session:
```
Read CLAUDE.md and SESSION_NOTES.md to restore project context,
then confirm you understand the 128-feature schema and 45 micro-states.
```

**Model selection:**
- Use **Sonnet 4.6** for everything until model training begins
  (code edits, debugging, notebook fixes, pipeline work)
- Reserve **Opus** for: MT3 architecture debugging, GReaT fine-tuning
  issues, training loss not converging, paper writing and ablation design

---

## 12. Key Decisions and Why — Reference for Viva

| Decision | What we chose | Why |
|---|---|---|
| Generative model | TabSyn + GReaT (two generators) | Cross-generator validation proves model learned real patterns not generator artifacts |
| 500 VAE epochs | 500 (not 300) | 50-epoch diagnostic showed loss still decreasing at epoch 49 with active beta decay cycles |
| Feature groups | 6 groups mapped to 3 architectures | Each sub-network specializes in what it's best at: CNN=spatial, LSTM=sequential, DistilBERT=semantic |
| MITRE ATT&CK labels | All 45 map to documented technique IDs | Industry-standard taxonomy — output immediately interpretable by any SOC team |
| CRF decoding head | CRF on MT3, plain softmax on baseline | CRF guarantees KCVR=0%; this is quantifiable, concrete advantage over baseline |
| KEV-first pipeline | CISA KEV primary, NVD secondary | NVD stopped enriching most CVEs in April 2026; KEV is the only reliable real-time source |
| 66% unique semantic vectors | Accepted as valid | CIC/UNSW flow descriptions differ by protocol/port/duration — some collision expected for similar flows |
| Group B heavy-tail | No clipping | 173 rows (0.024%) are real DDoS flows, not noise. Log twin feature (col 27) is well-behaved. |
| Two-night TabSyn split | VAE tonight, diffusion tomorrow | VAE at 500 epochs = ~16hrs alone. Running both in one night requires cutting epochs based on time not convergence. |

---

## 13. Team Task Allocation

Fill in your team's names and owned modules here.
Status column re-verified against the repo on 2026-08-06 where marked (*);
unmarked rows are carried over from before and haven't been re-checked.

| Module | Owner | Status |
|---|---|---|
| Dataset pipeline (Notebooks 01-05) | Mahith | 🔄 In progress — Notebook 03 needs a rerun on corrected data (*) |
| MT3 model architecture | Mahith | ✅ Written — models/mt3/architecture.py confirmed (*) |
| CNN-LSTM baseline | Mahith | ❌ Not in repo — models/baselines/ doesn't exist; ml_analytics/models/cnn_lstm.py is an empty stub (*) |
| Training script | Mahith | ❌ Not in repo — training/train.py doesn't exist, not even in git history (*) |
| CVE intelligence pipeline | Mahith | ✅ Fixed (unverified this pass) |
| React dashboard | — | ❌ Not in repo — only dashboard/ (Flask + static HTML) exists (*) |
| Cowrie honeypot deployment | — | ⬜ Pending (deployment files exist at honeypot_dataset/cowrie/, not yet run) |
| Traffic Gateway (asyncio proxy) | — | ⬜ Pending (unverified this pass) |
| Model training + evaluation | — | ⬜ Pending — blocked on training script above |
| Paper writing | All | ⬜ Pending |
| Presentation / viva prep | All | ⬜ Pending |

---

## 14. Paper Structure (Target Conference: IEEE S&P / NDSS / USENIX Security)

```
Title: "HoneySynth-1M: A Differentially Private, Threat-Intelligence-
        Augmented Synthetic Network Dataset for Kill-Chain-Aware Intrusion Detection"

Section 1: Introduction
Section 2: Related Work
Section 3: Dataset Construction (your methodology)
Section 4: MT3 Architecture
Section 5: Evaluation
  Table 1: Dataset statistics
  Table 2: Model comparison (7 models, accuracy/macro-F1/KCVR/TSTR)
  Table 3: Ablation study (remove one feature group at a time)
  Table 4: Kill-Chain Violation Rate comparison
  Figure 3: Attention heatmaps (which feature groups MT3 attends to per attack phase)
  Figure 4: Learning curve (dataset size vs F1)
Section 6: Discussion and Limitations
Section 7: Conclusion
```

---

## 15. Required Citations

All must appear in the final paper:

| What | Citation |
|---|---|
| CIC-IDS2017 | Sharafaldin et al., ICISSP 2018 |
| UNSW-NB15 | Moustafa & Slay, MilCIS 2015 + Info Security Journal 2016 |
| TabSyn | Zhang et al., ICLR 2024 |
| GReaT | Borisov et al., ICLR 2023 |
| MITRE ATT&CK | MITRE Corp, attack.mitre.org |
| DistilBERT | Sanh et al., NeurIPS 2019 Workshop |
| CISA KEV | CISA, cisa.gov/known-exploited-vulnerabilities |
| Cowrie | Oosterhof, github.com/cowrie/cowrie |

---

*This document was generated from the full Claude conversation log covering
the complete design and implementation of the HoneySynth-1M dataset pipeline,
MT3 model architecture, and CVE intelligence module. For the most current
version, check the repo — this file is updated at major milestones.*
