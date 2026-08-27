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

## Data — the real Cowrie + CIC + UNSW dataset (already processed)

The real dataset is **already feature-extracted** — do NOT re-run notebooks 01/02.

| File | Shape | What it is |
|---|---|---|
| `honeypot_dataset/data/processed/X_real.npy` | (737319, 128) float32 | Real sessions: Cowrie SSH (15k) + CIC-IDS2017 (557k) + UNSW-NB15 (164k) |
| `honeypot_dataset/data/processed/y_real.npy` | (737319,) int64 | Micro-state labels — **22 of 45 classes present** in real data |
| `honeypot_dataset/data/processed/real_sessions_combined.parquet` | 737319 rows | Raw session metadata incl. `command_text` (only if you need live text) |

**These `.npy`/`.parquet` files are git-ignored** — they will NOT arrive via
`git pull`. The dataset owner transfers them to your machine / the DGX. Load them
read-only; never overwrite or regenerate them.

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

- Real-only data has **22/45 classes** (the other 23 are all-zero — they come from
  TabSyn synthetic later). Train/evaluate on the present classes for now; when the
  frozen **real + TabSyn** dataset lands (45 classes, **identical 128-d format**),
  just swap the data path — no architecture change.
- Heavy imbalance (e.g. `DISC_ENV_PROBE` ~277k vs `PERSIST_SSH_KEY_ADD` ~13). Use a
  **stratified split** and a **class-weighted or focal loss**.

---

## Evaluation protocol — MUST match MT3 for a fair comparison

The whole point is baseline-vs-MT3, so both models must be judged identically:

1. **Same split, same seed.**
   - *Now (prototyping):* split `X_real`/`y_real` with a fixed seed (e.g. 42),
     stratified, to build and debug the pipeline.
   - *For the review comparison:* use the canonical splits that **notebook 05**
     produces from the frozen real+TabSyn dataset. Both CNN-LSTM and MT3 train/eval
     on those exact splits.
2. **Same metrics:** macro-F1 (primary), per-class F1, accuracy, and a confusion
   matrix. Save predictions so the two models can be compared on identical test rows.
3. Agree the split + metric definitions with the owner up front.

---

## Where to run

Train on the **DGX (GB10)**, launched **detached** (`tmux` / `screen` / `nohup`) so
the job survives your laptop disconnecting. See `DGX.md`. The laptop is only a client;
compute is server-side.

## Quick start checklist

1. `git pull origin main`; read `CLAUDE.md`, `TEAMMATES.md`, `DGX.md`, `SCHEMA.md`.
2. Get `X_real.npy` + `y_real.npy` from the owner (they are git-ignored).
3. Build the branch model in `models/cnn_lstm.py` per the table above (slice via
   `FEATURE_GROUPS`).
4. Stratified split + class-weighted loss; train via `models/model_trainer.py`.
5. Report macro-F1 + per-class F1 + confusion matrix; save predictions.
6. When the frozen 45-class dataset arrives, swap the data path and re-run.
