# TEAMMATE_SETUP — get this project running from a fresh clone

Read `TEAMMATES.md` first. Its hard rule stands: **do not run the dataset
pipeline or the notebooks.** You do not need to, and this file is how you work
without them.

Follow it top to bottom. Every command is meant to be copy-pasted, and every
step says what a correct result looks like.

---

## 0. What you need from the dataset owner

A clone gives you all the code. It cannot give you the data or the models —
they are gitignored because of their size.

| | size | in git? | how you get it |
|---|---|---|---|
| all code, notebooks, docs | — | yes | `git clone` |
| `semantic_pca.pkl` | 95 KB | yes | `git clone` |
| **`honeysynth_pilot_200k.zip`** | **75 MB** | no | **ask — this is what you want** |
| `data/final_v2/` (full dataset) | 4.4 GB | no | only to reproduce headline numbers |
| `artifacts/mt3_final_v2_d256/` (trained model) | 91 MB | no | only if you need the model |

**Most people need only the 75 MB pilot zip.** Ask for it before you start.

---

## 1. Clone and install

```bash
git clone https://github.com/MKD2004/adaptive-honeypot-ml-CAPSTONE.git
cd adaptive-honeypot-ml-CAPSTONE
```

**Linux / macOS:**
```bash
./setup.sh
```

**Windows (PowerShell):**
```powershell
.\setup.ps1
```

This builds a virtual environment at **`venv/` in the repo root** and installs
both `requirements.txt` and `honeypot_dataset/requirements.txt` into it. Safe
to re-run.

### Which python to use — read this or nothing will work

After setup, your interpreter is:

```bash
venv/bin/python                  # Linux / macOS
venv\Scripts\python.exe          # Windows
```

`CLAUDE.md` and some docs say `honeypot_dataset/venv/Scripts/python.exe`. That
is the **dataset owner's machine**, where the venv was built by hand somewhere
else. Both work. Use whichever exists for you, and always use it explicitly —
the system `python` does not have torch or pandas.

Everything below writes `python`, meaning *your venv's python*.

Two notes on `setup.sh`: it also clones `tabsyn/`, which the project **dropped**
(`DATA_INTEGRITY.md` §11a) — harmless, ignore that directory. And if the torch
install fails it is almost always the CUDA wheel; re-run with
`TORCH_INDEX_URL=https://download.pytorch.org/whl/cpu ./setup.sh` for a
CPU-only install, which is enough for everything in this file except the live
demo.

---

## 2. Unpack the pilot dataset

```bash
unzip honeysynth_pilot_200k.zip -d ml_analytics/data/pilot_200k/
ls ml_analytics/data/pilot_200k/ | wc -l        # expect 31
```

What is inside:

```
train       200,000 rows   46 labels   class-balanced subsample
val          23,000 rows   46 labels   class-balanced subsample
test_real    59,784 rows   16 labels   IDENTICAL to the full build
test_synth   60,005 rows   45 labels   IDENTICAL to the full build
```

The **test splits are byte-identical to the full 1.47M-row build**, so your
`test_real` score is directly comparable to anyone else's. Only train and val
are subsampled. `manifest.json` carries a sha256 for all 29 arrays and the seed.

Besides `X_` and `y_`, every split ships `M_` (which features were measured
rather than imputed), `prov_` (temporal provenance), `gen_` (which generator
produced the row), `donor_` (how its timing was obtained) and `seq_` (the
micro-state walk). You need `donor_` for the per-origin reporting in §22.

---

## 3. Verify your setup before training anything

```bash
python -m ml_analytics.mt3_pipeline.smoke_test --data-dir ml_analytics/data/pilot_200k
```

**Correct result: `10/10 checks passed`**, about 25 seconds.

It checks the things that corrupt results silently instead of crashing: scaler
provenance, that the splits are already scaled, schema parity between `mt3.py`
and `schema.py`, loss parity, that the model can overfit a single batch, and
both CLIs end to end.

**If it is not 10/10, stop and ask.** Do not train on a setup that fails this —
the results will look plausible and be wrong.

---

## 4. What you can run

```bash
# the floor: one linear layer, 5,934 parameters, under a minute
python -m ml_analytics.mt3_pipeline.train_baseline --model linear \
    --data-dir ml_analytics/data/pilot_200k \
    --out-dir ml_analytics/artifacts/my_probe

# the baseline: CNN-LSTM, 189,710 parameters, ~15 s/epoch on a laptop GPU
python -m ml_analytics.mt3_pipeline.train_baseline --model cnn_lstm \
    --data-dir ml_analytics/data/pilot_200k \
    --out-dir ml_analytics/artifacts/my_cnn_lstm

# MT3 itself, 3.76M parameters
python -m ml_analytics.mt3_pipeline.train_mt3 \
    --data-dir ml_analytics/data/pilot_200k \
    --out-dir ml_analytics/artifacts/my_mt3 \
    --epochs 20 --batch-size 1024 --lr 3e-4 --amp

# results split by how each session's timing was produced
python -m ml_analytics.mt3_pipeline.report_donor \
    --artifacts ml_analytics/artifacts/my_mt3 \
    --data-dir ml_analytics/data/pilot_200k
```

These two need the **full** dataset, not the pilot, and run from inside
`honeypot_dataset/`:

```bash
cd honeypot_dataset
../venv/bin/python -m src.validators.source_separability   # real vs generated
../venv/bin/python -m src.validators.transition_agreement  # observed vs the DAG
cd ..
```

Every command takes `--help`.

### A pilot number is not a headline number

200,000 balanced training rows is not the 1,466,849-row build. Your MT3 will
score **below** the published 0.5507 macro-F1, and that is expected rather than
a setup problem. Label pilot results as pilot results.

Published numbers for reference (`CLAUDE.md` Current Status):

```
model          params      macro-F1   macro-F1@n>=97   accuracy   phase acc
linear probe    5,934        0.3835       0.5339        0.7482        —
CNN-LSTM      189,710        0.4413       0.6118        0.8194        —
MT3         3,759,767        0.5507       0.7387        0.8908       0.9366
```

---

## 5. Which number to quote

In this order:

```
phase accuracy                       0.9366     what the system acts on
weighted F1                          0.9082
macro-F1 over 10 classes with n>=97  0.7387     covers 99.6% of real sessions
macro-F1 over all 16 classes         0.5507     the strict number
```

Plain macro-F1 looks low because 9 of the 16 classes hold just 652 of 59,784
rows (1.1%) and yet carry 56% of the average — one class has 2 rows.
`DATA_INTEGRITY.md` §23 derives the n≥97 threshold from a confidence interval
and gives four rules for reporting it. **Never quote a subset score without its
coverage figure beside it.**

Numbers that are **retired** — do not use them anywhere: MT3 0.8276, CNN-LSTM
0.8093, linear probe 0.7681, "~83 informative features", 29.74% duplication.
All were measured on `data/final/`, which carried fabricated temporal features
in 60% of its training rows.

---

## 6. Full dataset, and the live demo

**Full dataset** — ask for `data/final_v2/` (4.4 GB) and, if you need the
trained model, `artifacts/mt3_final_v2_d256/` (91 MB). Put them at exactly those
paths. **Take both or neither** — see the first trap below.

**Live demo** — needs Docker, because real Cowrie 3.0.13 runs in a container,
plus the full dataset and the model:

```bash
python demo/live_demo.py                 # full stack, starts Cowrie in Docker
python -m traffic_gateway.run_pipeline   # scripted, no demo props
```

Expect 68 s of one-off startup (DistilBERT and the PCA loading), then **16 ms
per session** for features, MT3 and reconfiguration. `docs/DEMORUN.md` is
gitignored — ask for it if you are recording.

---

## 7. The traps, in the order you will meet them

**A checkpoint and a scaler are a matched pair.** `best.pt` was trained on
`final_v2`'s already-scaled arrays. Pair it with the retired `data/final/`
scaler and predictions come out plausible and wrong, raising nothing. Keep the
dataset folder and the checkpoint together. `MT3Inference.load()` refuses a
checkpoint whose output count disagrees with the schema — do not work around it.

**The shipped arrays are ALREADY SCALED.** Never call `scaler.transform()` on
them; it double-scales in silence. Load the scaler only for new raw data.

**`feature_scaler.pkl` is a joblib dump.** `pickle.load()` raises
`invalid load key`. Use `joblib.load()`.

**The model has 46 outputs, not 45** — 45 kill-chain micro-states plus `BENIGN`
at index 45. BENIGN has no MITRE technique and no phase, so its predictions
carry `phase: -1` and `is_benign: true`. **Do not "fix" -1 to 0.** Phase 0 is
Reconnaissance, every rule in the gateway is `phase >= threshold`, and -1 is
what stops a benign session being blocked.

**`load_split()` raises on `data/final/` on purpose** — that build is 60.3%
fabricated temporal features in train. To reproduce an old number anyway,
`integrity="warn"` or `MT3_ALLOW_UNVALIDATED=1` downgrades the gate and prints
the reason every time.

| error you see | what it means |
|---|---|
| `ModuleNotFoundError: torch` | you used the system python, not the venv |
| `invalid load key` on a `.pkl` | use `joblib.load`, not `pickle.load` |
| `DataError: ... fabricated` | you pointed at `data/final/`; use `final_v2` or the pilot |
| `checkpoint ... has 45 outputs but 46 labels` | old checkpoint; get `mt3_final_v2_d256` |
| `semantic PCA missing` | 30 of 128 features zero-fill; `git pull` for `semantic_pca.pkl` |
| smoke test below 10/10 | stop and ask; do not train |

---

## 8. Where to read what

| question | file |
|---|---|
| what was wrong with the data, and what is fixed | `DATA_INTEGRITY.md` §§8-23 |
| which numbers to quote, which are retired | `CLAUDE.md` Current Status; §21d, §23 |
| why something was built this way | `DECISIONS.md` |
| this crash has happened before | `ERRORS.md` |
| what we are doing next | `STATUS.md`, `ROADMAP.md` |
| what am I allowed to touch | `TEAMMATES.md` |
| the 45 micro-states and 128 features | `SCHEMA.md` |
