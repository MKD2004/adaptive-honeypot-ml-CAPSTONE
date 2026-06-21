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

- 1.2M total sessions: 180k real Cowrie, 60k real transfer (CIC-IDS2017 + UNSW-NB15), 720k TabSyn synthetic, 240k GReaT synthetic
- Minimum 2,000 samples per class
- Cowrie honeypot logs to be integrated as a third real data source

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

echo "
When asked to run notebook X, always execute the existing .ipynb file 
in place using jupyter nbconvert --to notebook --execute --inplace. 
Never create a new .py script or copy of the notebook as a substitute." >> CLAUDE.md