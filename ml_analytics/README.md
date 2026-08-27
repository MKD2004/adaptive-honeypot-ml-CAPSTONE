# ml_analytics — CNN-LSTM + DistilBERT baseline

This module holds the **baseline classifier** for the capstone: a multi-branch
CNN-LSTM-DistilBERT that classifies attacker sessions into the 45 MITRE-mapped
micro-states. It is compared against the **MT3** model (owner's work — see rules).

**Before working here, read `TEAMMATES.md` and `CLAUDE.md` at the repo root and
`git pull origin main` first.** Use "Prompt A" from `TEAMMATES.md` to start a Claude
Code session, with your role set to *"CNN-LSTM + DistilBERT baseline in ml_analytics/"*.

---

## Scope — what you own vs what is off-limits

**You build/edit (in `ml_analytics/` only):**
- `models/cnn_lstm.py` — the multi-branch model (scaffold already present).
- `models/model_trainer.py`, `models/threat_classifier.py` — training/eval pipeline.
- `feature_extraction/` — only if you need helper hooks; the features already exist (below).

**Off-limits (hard rules from `TEAMMATES.md`):**
- `models/mt3.py` — the owner's MT3 model. **Do not touch.**
- `honeypot_dataset/` (the dataset pipeline), any notebook (`01`–`05`, `03b`), and
  `tabsyn/`. **Never run a notebook.** Consume the produced arrays; never regenerate them.

---

## Data — TRAIN ON `data/final/` (the frozen assembled dataset)

**The dataset is assembled and frozen (2026-08-28). Train on the splits in
`honeypot_dataset/data/final/` — NOT on `X_real.npy`.** Everything is already
feature-extracted; do NOT re-run any notebook.

Transferred to the DGX as **`honeysynth_final.zip`** → unzip to
`honeypot_dataset/data/final/` (see `DGX.md` transfer manifest).

| File | Shape | Use |
|---|---|---|
| `data/final/X_train.npy` / `y_train.npy` | (756000, 128) / (756000,) | **train** (45 classes) |
| `data/final/X_val.npy` / `y_val.npy` | (84000, 128) | **validation** |
| `data/final/X_test_real.npy` / `y_test_real.npy` | (60000, 128) | **headline test — real holdout (21 classes)** |
| `data/final/X_test_synth.npy` / `y_test_synth.npy` | (60000, 128) | test — full 45-class behavior |
| `data/final/feature_scaler.pkl` | — | **load this exact scaler; do NOT re-fit** (MT3 uses the same) |

Composition: 960k sessions = 240k real (25%) + 720k TabSyn synthetic (75%).

**Data provenance (read this — corrected 2026-08-28):** the genuinely-real data is
**CIC-IDS2017 + UNSW-NB15 only** (network flows, 13/45 classes). The "Cowrie
honeypot" data is **synthetic** (teammate-generated), not a real capture — do not
describe it as real. There is no real honeypot data. The synthetic has a known
fidelity fingerprint (adversarial AUC ~0.998) but strong utility (TSTR macro-F1
0.99 on real network classes) — see `FIDELITY_ANALYSIS.md` and `DECISIONS.md`.

`X_real.npy` / `y_real.npy` (22-class real+synthetic-Cowrie, pre-assembly) are
kept only for GReaT (notebook 04) and as a fallback — **not** the baseline training
target. All these files are git-ignored (transferred, not pulled); load read-only.

Read `honeypot_dataset/configs/schema.py` (read-only) for `FEATURE_GROUPS`,
`N_FEATURES` (128), `N_CLASSES` (45), and `IDX_TO_LABEL`.

---

## Model architecture — multi-branch over the 128-d vector

Each feature group is a slice of the 128-d input and feeds a branch:

| Branch | Group | Columns | Notes |
|---|---|---|---|
| **LSTM** | A_temporal | `[0:24]` | IAT stats, bursts, calendar context |
| **CNN** | B_network | `[24:52]` | byte/packet flows, ports, TCP flags |
| **CNN** | C_payload | `[52:76]` | entropy, byte dist, n-grams, shell tokens |
| **DistilBERT** | D_semantic | `[76:106]` | **already the DistilBERT→PCA(30) projection** |
| **CNN+LSTM** | E_threat_intel | `[106:120]` | CVSS/EPSS/KEV (all-zero for real data — no CVEs) |
| **CNN** | F_tls_host | `[120:128]` | JA3, TLS version, geo risk |

**Critical:** the `D_semantic` block (cols 76–105) is **already** the DistilBERT CLS
→ PCA(30) output, computed in notebook 02. The "DistilBERT" branch **consumes those
30 features directly — it does NOT re-run a transformer.** If you want a live
end-to-end DistilBERT branch (raw `command_text` → transformer), that is a different
design that needs the parquet — **agree with the owner first**, do not assume it.

Slice branch inputs from `FEATURE_GROUPS` rather than hardcoding indices, so it stays
correct if the schema ever changes.

---

## Class handling

- `data/final/` covers **all 45 classes** and is already balanced (min ~7,410 /
  max ~227,000 per class). Still use a **class-weighted or focal loss** — the split
  isn't perfectly uniform, and the real-anchored classes dominate.
- The splits are pre-stratified; use them as-is (don't re-split `X_train`).

---

## Evaluation protocol — MUST match MT3 for a fair comparison

The whole point is baseline-vs-MT3, so both models must be judged identically:

1. **Same splits (already fixed).** Both CNN-LSTM and MT3 train on
   `data/final/X_train` (+ `X_val` for tuning) and evaluate on the **same**
   `data/final/X_test_*`. Do not make your own split.
2. **Same scaler.** Load `data/final/feature_scaler.pkl` — do NOT re-fit; MT3 uses
   the identical one.
3. **Headline metric = `X_test_real`** (60k, 21 real classes) — real-world
   performance. Also report `X_test_synth` (60k, 45 classes) for full-taxonomy
   behavior.
4. **Same metrics:** macro-F1 (primary), per-class F1, accuracy, confusion matrix.
   **Save your predictions** so the two models are compared on identical test rows.

---

## Where to run

Train on the **DGX (GB10)**, launched **detached** (`tmux` / `screen` / `nohup`) so
the job survives your laptop disconnecting. See `DGX.md`. The laptop is only a client;
compute is server-side.

## Quick start checklist

1. `git pull origin main`; read `CLAUDE.md`, `TEAMMATES.md`, `DGX.md`, `SCHEMA.md`.
2. Get **`honeysynth_final.zip`** from the owner; unzip to
   `honeypot_dataset/data/final/` (git-ignored — transferred, not pulled).
3. Load `data/final/X_train.npy` + `y_train.npy` and `feature_scaler.pkl`.
4. Build the branch model in `models/cnn_lstm.py` per the architecture table above
   (slice branch inputs via `FEATURE_GROUPS`).
5. Train via `models/model_trainer.py` with a class-weighted/focal loss.
6. Evaluate on `X_test_real` (headline) + `X_test_synth`; report macro-F1 +
   per-class F1 + confusion matrix; **save predictions** for the MT3 comparison.
