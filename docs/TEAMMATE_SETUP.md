# TEAMMATE_SETUP — running this project from a fresh clone

Read `TEAMMATES.md` first. Its hard rule stands: **do not run the dataset
pipeline or the notebooks.** You do not need to. This file is how you get
working without them.

---

## What a clone gives you, and what it cannot

| | size | in git? |
|---|---|---|
| all code, notebooks, docs, `setup.sh` / `setup.ps1`, `requirements.txt` | — | yes |
| `honeypot_dataset/data/processed/semantic_pca.pkl` | 95 KB | yes (deliberate exception) |
| `honeypot_dataset/data/final_v2/` — the dataset | **4.4 GB** | **no** |
| `ml_analytics/artifacts/` — the trained models | 91 MB | **no** |

The dataset and the checkpoints are gitignored because of their size. Someone
has to hand them to you. Which one you need depends on what you are doing.

## THE ONE THING THAT WILL SILENTLY RUIN YOUR RESULTS

**A checkpoint and a scaler are a matched pair.** `best.pt` was trained on
`final_v2`'s already-scaled arrays. Pair it with the retired `data/final/`
scaler — or pair the old `mt3_full_d256` checkpoint with `final_v2` — and
predictions come out plausible and wrong, raising nothing. Same family as the
"arrays are already scaled" trap at the top of `ERRORS.md`.

Two protections exist. `load_split()` **raises** on `data/final/` by design, and
`MT3Inference.load()` refuses a checkpoint whose output count disagrees with the
label schema. Do not work around either.

Second trap, from the same file: **the shipped arrays are ALREADY SCALED.**
Never call `scaler.transform()` on them. And `feature_scaler.pkl` is a joblib
dump — `pickle.load()` raises on it.

---

## Path A — ML work on a laptop (most people)

You want the **pilot**: a class-balanced ~200k-row subset, both test splits
byte-identical to the full build so everyone scores on the same rows, the real
scaler, and all the provenance arrays. **75 MB zipped** (843 MB unpacked).

Ask whoever holds the dataset to run:

```bash
python -m ml_analytics.mt3_pipeline.make_pilot \
    --src honeypot_dataset/data/final_v2 --zip
```

Then, on your machine:

```bash
git clone <repo> && cd adaptive-honeypot-ml-CAPSTONE
./setup.sh                      # setup.ps1 on Windows
unzip honeysynth_pilot_200k.zip -d ml_analytics/data/pilot_200k/

# does my setup actually work? 10 checks, ~25s, CPU-friendly
python -m ml_analytics.mt3_pipeline.smoke_test --data-dir ml_analytics/data/pilot_200k
```

`smoke_test` is the gate — 10 checks, about 25 seconds. It covers the things
that corrupt results silently rather than crash: scaler provenance, "the splits
are already scaled", schema parity between `mt3.py` and `schema.py`, loss
parity, that the model can overfit one batch, and both CLIs end to end. A clean
run looks like `10/10 checks passed`. **If it fails, stop and ask. Do not
train.**

Then anything below works (`--help` on each):

```bash
python -m ml_analytics.mt3_pipeline.train_baseline --model linear   --data-dir <dir>
python -m ml_analytics.mt3_pipeline.train_baseline --model cnn_lstm --data-dir <dir>
python -m ml_analytics.mt3_pipeline.train_mt3 --data-dir <dir> --out-dir <dir>
python -m ml_analytics.mt3_pipeline.report_donor          # results per donor_origin
python -m src.validators.source_separability              # from honeypot_dataset/
python -m src.validators.transition_agreement             # from honeypot_dataset/
```

**A pilot number is not a headline number.** 200k balanced train rows is not the
1.47M-row build, so quote pilot results as pilot results.

## Path B — reproduce the published numbers

You need the full `honeypot_dataset/data/final_v2/` (4.4 GB) and
`ml_analytics/artifacts/mt3_final_v2_d256/` (91 MB). Copy both, by rsync or a
shared drive — not git. Keep them together; see the matched-pair warning above.

The numbers to expect are in `CLAUDE.md` under Current Status, and
`DATA_INTEGRITY.md` §21d and §23 explain which to quote and why.

## Path C — run the live system end to end

Needs **Docker** (real Cowrie 3.0.13 runs in a container) plus the checkpoint
from Path B.

```bash
python demo/live_demo.py              # full stack, auto-starts Cowrie in Docker
python -m traffic_gateway.run_pipeline # scripted, no demo props
```

The gateway reads the checkpoint at `ml_analytics/artifacts/mt3_final_v2_d256/`
and the scaler from `honeypot_dataset/data/final_v2/`, so Path C needs Path B's
files. `docs/DEMORUN.md` is gitignored, so the recording script does not travel
with the clone — ask for it.

Timing to expect, measured 2026-11-25: 68 s one-off startup (DistilBERT + PCA
load), then **16 ms per session** for features + MT3 + reconfiguration.

---

## Two things about the model that will confuse you

**It has 46 outputs, not 45.** 45 kill-chain micro-states plus `BENIGN` at index
45. BENIGN has no MITRE technique, no phase and no DAG edges, so
`MT3Inference.predict()` reports `phase: -1` and `is_benign: true` for it.

**-1 is deliberate.** Every downstream rule is `phase >= threshold`, so -1
clears nothing and a benign verdict cannot trigger a block even if a caller
forgets to check the label. Do not "fix" it to 0 — phase 0 is Reconnaissance,
and `02-11-2026 FINDINGS.md` finding #1 is a real benign session that got
auto-blacklisted.

## Where to read what

| question | file |
|---|---|
| what is wrong with the data and what was fixed | `DATA_INTEGRITY.md` §§8-23 |
| which numbers to quote, and which are retired | `CLAUDE.md` Current Status, §21d, §23 |
| why something was built this way | `DECISIONS.md` |
| this crash has happened before | `ERRORS.md` |
| what we are doing next | `STATUS.md`, `ROADMAP.md` |
| what I am allowed to touch | `TEAMMATES.md` |
