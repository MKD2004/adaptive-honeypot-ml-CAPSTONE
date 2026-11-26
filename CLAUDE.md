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

adaptive_honeypot/         configurator.py — MT3 prediction -> honeypot config +
                           adaptive honeyfs (writes active_config.json). Other
                           files (orchestrator, emulators) are empty scaffolding.
traffic_gateway/           Proxy + IP classification + rate limiting, AND the live
                           pipeline: traffic_classifier (pre-MT3 filter),
                           feature_bridge (128 feats -> MT3), post_session_pipeline
                           (Cowrie log watcher -> MT3 -> config), api.py (Flask,
                           :5000), run_pipeline.py (orchestrator), peer_attribution
ml_analytics/              MT3 + CNN-LSTM models, mt3_pipeline, trained artifacts
demo/                      live_demo.py (one-command full stack), real_server.py +
                           ssh_honeypot.py (demo PROPS, not honeypots),
                           attack_client.py / brute_force.py (peer simulators),
                           reset_demo.py, simulate_attack.py (scripted 3-scenario)
response_mitigation/       Firewall API, IP blocker (scaffolding; auto-blacklist
                           currently lives in post_session_pipeline)
cve_intelligence/          NVD/EPSS/CISA-KEV/ExploitDB clients + analysis pipeline
monitoring/                Dashboard + alerting
dashboard/static/          index.html (gateway events) + pipeline.html (MT3 feed) +
                           live.html (live access control); backend.py (legacy SSE)
data/                      Raw datasets (not committed)
  raw/cic_ids2017/         8 CSVs from CIC-IDS2017
  raw/unsw_nb15/           2 CSVs from UNSW-NB15
honeypot_dataset/
  src/parsers/cowrie_parser.py   Cowrie log parser (extracted from notebook 01)
  cowrie/                  REAL Cowrie 3.0.13 Docker deployment (compose, cfg,
                           userdb, adaptive honeyfs) — this is the genuine honeypot
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
**This describes `data/final/` (FROZEN, superseded).** The current build is
`data/final_v2/` — 1,556,809 rows, TabSyn excluded, see the provenance table
below and `DATA_INTEGRITY.md` §§8-14.

**Provenance (re-measured 2026-11-24 — read `DATA_INTEGRITY.md` §14 before writing any
paper text).** This replaces the 2026-08-28 note, which said real data was
"CIC-IDS2017 + UNSW-NB15 only, anchoring 13 of 45" and that there was no real
honeypot data. Both were true when written and are now wrong.

There IS real honeypot data now: **114,490 Cowrie sessions**, 1,071 source IPs,
13 days (2026-11-01 to 11-14), 754,029 events, captured on the Oracle VM. It
replaced the 15,000 teammate-generated sessions that were previously mislabelled
as real.

Composition of `data/final_v2/` (1,749,809 rows pre-split):

| tier | rows | share |
|---|---|---|
| real honeypot (Cowrie SSH) | 114,490 | 6.5% |
| real netflow (CIC-IDS2017) | 657,646 | 37.6% |
| real netflow (UNSW-NB15) | 257,673 | 14.7% |
| synthetic (`cowrie_simulator`, NOT TabSyn) | 720,000 | 41.1% |
| **measured, any real source** | **1,029,809** | **58.9%** |
| **real honeypot only** | **114,490** | **6.5%** |

Class anchoring, 46 labels (45 micro-states + BENIGN):

| anchoring | classes |
|---|---|
| real honeypot **+** netflow | **4** — `ACCESS_BRUTE_SSH`, `DISC_ENV_PROBE`, `EXEC_SHELL_OPEN`, `RECON_IP_SCAN` |
| trace honeypot only (<300 sessions) | 4 — `DISC_PROC_ENUM` (1), `EVASION_HIST_ERASE` (6), `EXFIL_SCP_DATA` (36), `EXEC_WGET_EXEC` (100) |
| real netflow only | 10 |
| **synthetic only, no real evidence** | **28** |

**Heralding adds two (2026-11-26, measured but NOT incorporated — §24).** An
11-day credential-honeypot capture (40,565 attacker sessions, 3,078 IPs) gives
`ACCESS_DEFAULT_CRED` 4,800 and `ACCESS_CRED_STUFF` 234 real sessions. Both had
**zero** real rows of any kind, and both are classes MT3 confuses
`ACCESS_BRUTE_SSH` with — 1,328 of its 1,657 missed sessions. So anchoring is
**20 of 46 with some real evidence, 26 synthetic-only**, once it is used.

It is not merged, for two reasons in §24e/24f: a Heralding session populates
only **43 of 128 features** (no shell, no commands, no byte counts, duration
fixed at Heralding's 30 s timeout), so its rows are identifiable by their
constant signature and a Heralding-only class would be learnable from its source
— §19a's BENIGN-is-netflow trap again. And 24,083 telnet/VNC sessions would be
labelled `ACCESS_BRUTE_SSH` as "nearest available", which needs a naming
decision first.

So **18 of 46 classes have some real evidence and only 4 have enough honeypot
data to train on**, not the 13 stated previously. Four classes hold 99.87% of the
honeypot capture. Collecting longer does not help: 2.5x more capture added zero
new classes (`DATA_INTEGRITY.md` §3d).

Describe it as: "a 13-day real SSH honeypot capture (114,490 sessions) anchoring
4 trainable kill-chain classes, plus real network-intrusion flows anchoring 10
more, augmented with calibrated synthetic sessions to cover the 45-class MITRE
taxonomy — 28 classes rest on synthetic data alone." Never as 22 real classes,
and never imply the honeypot capture covers the taxonomy.

## Key Commands

```bash
# Dataset pipeline runs from honeypot_dataset/
cd honeypot_dataset
pip install -r ../requirements.txt
python -m src.extractors.pipeline      # feature extraction
python -m src.generators.cowrie_simulator      # synthetic sessions (Cowrie events)
#   kill_chain_simulator is SUPERSEDED for dataset building: it writes summary
#   rows, not event streams. Kept byte-compatible for the frozen data/final/
#   build and its tests. See DATA_INTEGRITY.md section 8.
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

## Live Pipeline / System (added 2026-09-29)

Beyond the dataset/ML work, the runnable end-to-end system:

```
traffic -> gateway (routes benign->real server, hostile->honeypot)
        -> Cowrie honeypot captures the session
        -> post_session_pipeline: parse -> 128 features -> MT3 classify (45 states)
        -> configurator adapts the honeypot (interaction level + honeyfs bait)
        -> auto-blacklist the source -> dashboard shows it all
```

**Timing (important):** MT3 classifies a session only when it CLOSES
(`cowrie.session.closed`) — it needs the full session for the temporal/sequence
features, so it cannot classify mid-attack. The honeypot reconfigures right
after, and the change applies to the NEXT session, not the one just classified.
The gateway's `traffic_classifier` (IP rep / rate / payload signals) runs at
connection time and only decides routing — it is not MT3.

**Two honeypots:** `honeypot_dataset/cowrie/` is the REAL one (Cowrie 3.0.13 in
Docker, adaptive honeyfs via `contents_path`). `demo/ssh_honeypot.py` +
`demo/real_server.py` are offline PROPS for the demo — never call them honeypots
in the paper.

**Run it:** `python -m traffic_gateway.run_pipeline` (scripted), or
`python demo/live_demo.py` (full two-laptop stack; auto-starts Cowrie in Docker,
falls back to the python prop if Docker is down). See `docs/DEMORUN.md` (local,
gitignored) for the recording script. Uses `honeypot_dataset/venv` + Flask /
flask-cors / watchdog / paramiko.

**Config knobs** (traffic_gateway/config.py): `CLASSIFIER_ROUTING` (env
`GATEWAY_CLASSIFIER_ROUTING`) enables benign->real routing; whitelisted IPs get
`RATE_LIMIT_TRUSTED_MAX_CONN` (100/min) not an exemption; `MT3_AUTO_BLACKLIST`
blacklists a source once MT3 classifies it as phase >= 1.

## Reference Docs

**All documentation lives in `docs/` as of 2026-11-04** — there were 22 markdown
files at the repo root, which made it unreadable. Only `README.md` and this file
stay at the top level (this one because it is loaded from the repo root).

`docs/README.md` is the index: what to read first, what each file is for, and
which ones are machine-specific. Docstrings throughout the code cite these by
bare filename ("see `DECISIONS.md`"), which still resolves by search -- the names
are unique, so keep them that way.

Paths below are relative to `docs/`. As of 2026-08-27 these ARE committed (they
sync project state/rules across machines):

**Shared / identical on every machine** (never fork locally; change once + push):
- `SCHEMA.md` — full 45 micro-state / 128-feature reference for writing prompts fast
- `DECISIONS.md` — why things were built a certain way; check before redoing something
- `ERRORS.md` — bugs already hit and fixed; check before re-debugging the same crash
- `ROADMAP.md` — capstone -> research-paper plan: contribution, novelty positioning
  (literature survey), the A/B experiment, milestones. Read before paper decisions.
- `MULTI_HONEYPOT.md` — the plan for growing from one honeypot (Cowrie SSH) to four
  (+ auth portal, web app, database). Expansion of ROADMAP M4. Read before adding
  a honeypot or claiming the system has more than one.
- `TEAMMATES.md` — HARD RULES for collaborators + any AI assistant (do NOT run/edit
  the dataset pipeline, notebooks, or `tabsyn/`; stay in your assigned module)

**System-specific** (each machine has/uses its own — do not follow another
machine's copy):
- `STATUS.md` — current pipeline stage; entries are machine-tagged. Update at end of session.
- `HARDWARE.md` — per-machine GPU/VRAM/venv specs + config/batch-size implications
- `SETUP.md` — per-machine environment setup (OS/GPU-dependent)
- `ASUS.md` / `DGX.md` / `<MACHINE>.md` — that machine's role + work log

## Communication Style

Explain things in a plain-English, easy-to-understand tone.

- Use simple, everyday words.
- Avoid heavy technical jargon unless necessary. If you use a technical term, explain it briefly.
- Prefer short sentences. One idea per sentence.
- Explain what happened, why it matters, and what we should do next.

## Multi-machine sync (read before working)

**GitHub `main` is the single source of truth.** Every Claude Code on every machine
(ASUS/Dell laptops, DGX server) MUST `git pull` before working and push its changes
back. The code and the shared docs above are byte-identical everywhere; only the
system-specific files differ per machine. Read this machine's `<MACHINE>.md` for its
role. Do not edit shared files locally without pushing — that is how sessions drift.

## Current Status (2026-11-24)

**`STATUS.md` is the live, detailed source — this is only a coarse snapshot.**

**System since 2026-09-01:** the full live pipeline was built and connected (see
"Live Pipeline / System" above) — traffic gateway -> real Cowrie honeypot -> MT3
classification -> adaptive reconfiguration -> dashboard, plus the two-laptop live
demo and the recording tooling. Next phase is the research paper — see
`ROADMAP.md`; the A/B intelligence-yield study (section 5) is the contribution,
not the dataset.

**Dataset: `data/final_v2/` is the current build.** 1,556,809 rows —
1,293,128 train / 143,681 val / 60,000 `test_real` / 60,000 `test_synth`, 128
features, 46 labels (45 micro-states + BENIGN), min train class 13,199. The
pipeline is notebooks **01 → 02 → 05**: TabSyn (03, 03b) and GReaT (04) are
DELETED, Part 2 formally dropped (`DATA_INTEGRITY.md` §11a). Each split also
ships provenance metadata — `M_*` (measured/imputed mask), `prov_*` (temporal
provenance), `gen_*` (which source produced the row), `donor_*` (how the timing
was obtained) — plus `imputation_manifest.json`.

**`data/final/` (HoneySynth-960k) is RETIRED, not merely frozen.** The arrays are
untouched on disk, but `ml_analytics/mt3_pipeline/data.py:load_split()` now
RAISES on them: 60.3% of its train rows and 97.9% of `test_real` carry a
fabricated temporal block (`DATA_INTEGRITY.md` §11b). `integrity="warn"` or
`MT3_ALLOW_UNVALIDATED=1` is the deliberately loud escape hatch for reproducing
old numbers.

**Every model number measured before 2026-11-24 is retired with it.** MT3
`test_real` 0.8276, CNN-LSTM 0.8093, the 5,805-parameter linear-probe floor
0.7681, the 29.74% `test_real` duplication and the "~83 informative features"
count were all measured on `data/final/`. Do not quote them. `final_v2` has
**101 informative features of 128** (27 dead, all triaged DROP).

**Models trained on `final_v2`** (2026-11-25, one protocol, value-disjoint
split, 46 labels). `test_real` = 59,784 real sessions, 16 labels present:

| model | params | macro-F1 | macro-F1 @n>=97 | weighted F1 | accuracy | phase acc |
|---|---|---|---|---|---|---|
| linear probe | 5,934 | 0.3835 | 0.5339 | — | 0.7482 | — |
| CNN-LSTM | 189,710 | 0.4413 | 0.6118 | — | 0.8194 | — |
| **MT3** | 3,759,767 | **0.5507** | **0.7387** | **0.9082** | **0.8908** | **0.9366** |

**Quote these four, in this order: phase accuracy 0.9366, weighted F1 0.9082,
macro-F1 over the 10 classes with n>=97 real sessions 0.7387 (99.6% coverage),
macro-F1 over all 16 observed classes 0.5507.** Plain macro-F1 is dominated by
9 classes holding 1.1% of rows — see `DATA_INTEGRITY.md` §23 for the threshold's
derivation and the four rules for reporting it.

MT3's Transformer fusion now **earns** its 20x parameters: the floor-to-ceiling
spread is 0.167 against 0.064 on `data/final/`, where the three models were a
statistical tie (p=0.617) because that data was close to linearly separable — a
5,805-parameter probe reached 0.9930 accuracy on it. Results are also reported
per `donor_origin` (§22): `per_event` timing costs the probe 0.197 mean recall
and MT3 only 0.036.

**Read `DATA_INTEGRITY.md` §§8-23 before quoting any dataset number.** It is the
self-contained handoff: what was wrong, what is fixed (synthetic sessions are now
generated as Cowrie log events and parsed by the real extractors; a feature that
cannot be measured is NaN, not zero; donor pools are class-aware; the integrity
gate runs at the training entry point), and what is not (54.5% of generated
sessions fall back to per-event timing, and 28 of 46 classes still rest on
synthetic data alone).

**Two traps when loading either build — see `ERRORS.md`.** The arrays are ALREADY
SCALED (never call `scaler.transform` on them) and `feature_scaler.pkl` is a
joblib dump (`pickle.load` raises). Both corrupt silently.

Known and deliberately not fixed: MT3 has **no CRF** despite the naming, and
`KILL_CHAIN_DAG` never enters training — measured, both models' errors were at or
below chance for DAG legality on `test_synth`. See `DECISIONS.md`.
