# Adaptive Honeypot Gateway (Capstone)

ML-driven honeypot that classifies attacker sessions into 45 MITRE ATT&CK-mapped micro-states across 9 kill-chain phases, then adapts honeypot behavior in real time.

## Repository Layout

```
honeypot_dataset/          Dataset pipeline (HoneySynth-1M)
  configs/schema.py        Central schema: 128 features, 45 micro-states, kill-chain DAG
  src/extractors/          6 feature extractors + pipeline orchestrator
  src/generators/          Kill-chain simulator, EPSS drift
  src/validators/          Quality checks (Table 1 metrics)
  venv/                    Python venv (not committed)

adaptive_honeypot/         Honeypot emulators (SSH, HTTP, DB, web app) + orchestrator
traffic_gateway/           Proxy, IP classification, rate limiting, reputation scoring
ml_analytics/              CNN-LSTM model, feature extraction, training pipeline
response_mitigation/       Firewall API, IP blocker, rate limiter, session isolator
cve_intelligence/          NVD/EPSS/CISA-KEV/ExploitDB clients + analysis pipeline
monitoring/                Dashboard + alerting
dashboard/                 Backend API
data/                      Raw datasets (not committed)
  raw/cic_ids2017/         8 CSVs from CIC-IDS2017
  raw/unsw_nb15/           2 CSVs from UNSW-NB15
tabsyn/                    TabSyn synthetic data generator (external)
```

## 128-Feature Schema (configs/schema.py)

| Group | Indices | Size | Arch Branch | Extractor |
|-------|---------|------|-------------|-----------|
| A_temporal | 0-23 | 24 | LSTM | `src/extractors/temporal.py` — IAT stats, burst detection, calendar context |
| B_network | 24-51 | 28 | CNN | `src/extractors/network.py` — byte/packet flows, port/protocol encoding, TCP flags |
| C_payload | 52-75 | 24 | CNN | `src/extractors/payload.py` — entropy, byte distributions, n-gram stats, shell token analysis |
| D_semantic | 76-105 | 30 | DistilBERT | `src/extractors/semantic.py` — DistilBERT CLS → PCA(30) projections of command text |
| E_threat_intel | 106-119 | 14 | CNN+LSTM | `src/extractors/threat_intel.py` — CVSS, EPSS, CISA KEV, exploit counts (live API calls) |
| F_tls_host | 120-127 | 8 | CNN | `src/extractors/tls_host.py` — JA3 fingerprint, TLS version, geo risk |

## 45 Micro-States (9 Kill-Chain Phases)

0: Reconnaissance (6) | 1: Initial Access (6) | 2: Execution (6) | 3: Discovery (5) | 4: Privilege Escalation (4) | 5: Persistence (5) | 6: Defense Evasion (5) | 7: Lateral Movement (3) | 8: Exfiltration (5)

Transitions are constrained by `KILL_CHAIN_DAG` in schema.py.

## Dataset Targets

**Original plan** (1.2M): 180k real Cowrie, 60k real transfer (CIC-IDS2017 +
UNSW-NB15), 720k TabSyn synthetic, 240k GReaT synthetic. Minimum 2,000 per class.

**What was actually built** — `HoneySynth-960k`, frozen 2026-08-27 in `data/final/`:
240k real-derived + 720k TabSyn, GReaT deferred. 7,410-226,999 per class.

**Provenance (corrected 2026-08-28 — read `DECISIONS.md` before writing any paper text):**
the 15,000 Cowrie sessions are **synthetic** (teammate-generated), not real. Genuinely
real data is **CIC-IDS2017 + UNSW-NB15 only**, anchoring **13 of 45** micro-states, all
network-flow classes. There is no real honeypot data in the project. Describe the
dataset as "real network-intrusion data anchoring 13 kill-chain classes, augmented with
synthetic honeypot sessions + TabSyn to cover the full 45-class MITRE taxonomy" — never
as 22 real classes.

## Key Commands

```bash
# Dataset pipeline runs from honeypot_dataset/
cd honeypot_dataset
pip install -r ../requirements.txt
python -m src.extractors.pipeline      # feature extraction
python -m src.generators.kill_chain_simulator  # synthetic session generation
python -m src.validators.quality_checks        # dataset validation
```

## Conventions

- All extractors return `np.ndarray` of the exact size for their feature group, with `nan_to_num` applied
- Session data is passed as `dict` with documented expected keys per extractor
- Threat intel extractor makes live API calls (NVD, EPSS, CISA KEV) with caching to `data/processed/ti_cache.json`
- Semantic extractor requires a pre-fitted PCA model at `data/processed/semantic_pca.pkl`
- `pipeline.py:extract_all()` orchestrates all 6 extractors into a single 128-d vector
- `pipeline.py:build_feature_matrix()` converts a DataFrame into `(X, y)` arrays ready for training

When asked to "run notebook X", always execute the existing .ipynb file
in place using `jupyter nbconvert --to notebook --execute --inplace`.
Never create a new .py script or a copy of the notebook as a substitute.
If a notebook execution fails, fix the cells inside the original .ipynb
file directly rather than creating a workaround file.

Use the venv interpreter explicitly for all commands in `honeypot_dataset/`:
`honeypot_dataset/venv/Scripts/python.exe`. The system `python` (3.14, on PATH)
does not have pandas/torch/jupyter installed — only the venv does.

## Reference Docs

Reference material at repo root. As of 2026-08-27 these ARE committed (they sync
project state/rules across machines):

**Shared / identical on every machine** (never fork locally; change once + push):
- `SCHEMA.md` — full 45 micro-state / 128-feature reference for writing prompts fast
- `DECISIONS.md` — why things were built a certain way; check before redoing something
- `ERRORS.md` — bugs already hit and fixed; check before re-debugging the same crash
- `TEAMMATES.md` — HARD RULES for collaborators + any AI assistant (do NOT run/edit
  the dataset pipeline, notebooks, or `tabsyn/`; stay in your assigned module)

**System-specific** (each machine has/uses its own — do not follow another
machine's copy):
- `STATUS.md` — current pipeline stage; entries are machine-tagged. Update at end of session.
- `HARDWARE.md` — per-machine GPU/VRAM/venv specs + config/batch-size implications
- `SETUP.md` — per-machine environment setup (OS/GPU-dependent)
- `ASUS.md` / `DGX.md` / `<MACHINE>.md` — that machine's role + work log

## Multi-machine sync (read before working)

**GitHub `main` is the single source of truth.** Every Claude Code on every machine
(ASUS/Dell laptops, DGX server) MUST `git pull` before working and push its changes
back. The code and the shared docs above are byte-identical everywhere; only the
system-specific files differ per machine. Read this machine's `<MACHINE>.md` for its
role. Do not edit shared files locally without pushing — that is how sessions drift.

## Current Status (2026-09-01)

**`STATUS.md` is the live, detailed source — this is only a coarse snapshot.**

**Dataset: FROZEN.** `data/final/` holds HoneySynth-960k — 756,000 train / 84,000 val /
60,000 `test_real` / 60,000 `test_synth`, 128 features, 45 classes (`test_real` has 21).
Notebooks 01, 02, 03 (TabSyn VAE + diffusion + 720k sampling) and 05 are **done**;
04 (GReaT) stays **deferred**. Do not regenerate — every model below is trained on
these exact rows.

**Two traps when loading `data/final/` — see `ERRORS.md`, top two entries.** The arrays
are ALREADY SCALED (never call `scaler.transform` on them) and `feature_scaler.pkl` is a
joblib dump (`pickle.load` raises). Both corrupt silently.

**Models trained and compared** (same splits, same scaler, macro-F1 over the 21 classes
present in `test_real`):

| model | params | val macro-F1 | test_real | test_real (clean) | test_synth |
|---|---|---|---|---|---|
| linear probe | 5,805 | 0.9376 | 0.7681 | **0.7551** | 0.9373 |
| CNN-LSTM baseline | 189,581 | 0.9621 | 0.8093 | **0.7976** | 0.9610 |
| MT3 (d=256, 4 layers) | 3,759,510 | 0.9599 | 0.8276 | **0.8187** | 0.9589 |

Headline finding: **on `test_real` the two models tie** (McNemar p = 0.617 clean), so
MT3's Transformer fusion does not beat concatenation + MLP at 20x the parameters; the
CNN-LSTM wins `test_synth` significantly (p = 0.00064). A 5,805-parameter linear probe
reaching 0.7681 is the floor any result must clear.

**Quote the clean column.** 29.74% of `test_real` rows are byte-identical to rows in
`X_train` (notebook 05 splits disjointly by index, not by value, and real network flows
genuinely repeat). The clean subset is 41,785 rows; `test_synth` is unaffected (0.00%).

Known and deliberately not fixed before the review: MT3 has **no CRF** despite the
naming, and `KILL_CHAIN_DAG` never enters training — measured, both models' errors are
at or below chance for DAG legality on `test_synth`. See `DECISIONS.md`.
