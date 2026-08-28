# MT3_PROMPT.md — session prompt for building the MT3 train/eval pipeline

**Purpose:** copy-paste starter prompt for a **fresh Claude Code session** (owner-driven only —
MT3 is Mahith's task; teammates must not touch `mt3.py`). The MT3 *model* is already written
(`ml_analytics/models/mt3.py`); the work this prompt kicks off is the **training + evaluation
pipeline** on the frozen dataset, matching the CNN-LSTM baseline's protocol exactly so the
baseline-vs-MT3 comparison is fair.

System-specific file? No — this is a shared reference doc (like SCHEMA.md). Keep it identical
on every machine; change once and push.

---

## The prompt (copy everything in the block)

```
You are working on the Adaptive Honeypot Gateway capstone. I am Mahith (the dataset/model
owner). Your job this session: build the TRAINING + EVALUATION pipeline for the MT3 model
so it can be compared head-to-head against the CNN-LSTM baseline. MT3 is MY task — you are
authorized to work on it (unlike teammates, who must not touch mt3.py).

STEP 1 — READ THESE BEFORE WRITING ANY CODE (in this order):
  1. CLAUDE.md                       — project brief, schema, conventions, current status
  2. TEAMMATES.md                    — hard rules (which I own vs teammates); MT3 is mine
  3. DECISIONS.md                    — why the dataset is frozen at real+TabSyn; provenance
  4. FIDELITY_ANALYSIS.md            — the real-vs-synth AUC story + TSTR utility (for framing results)
  5. DGX.md                          — where training runs (GB10, launch detached) + transfer manifest
  6. SCHEMA.md                       — 45 micro-states / 128 features / kill-chain phases
  7. ml_analytics/README.md          — DATA location, splits, scaler, and the EVALUATION PROTOCOL
                                        that MT3 MUST match for a fair baseline comparison
  8. ml_analytics/models/mt3.py      — the MT3 model (already written — read, do NOT rewrite it)
  9. ml_analytics/models/cnn_lstm.py — the baseline, so MT3's train/eval mirrors it exactly
  10. honeypot_dataset/configs/schema.py (read-only) — FEATURE_GROUPS, N_FEATURES=128,
      N_CLASSES=45, IDX_TO_LABEL, IDX_TO_PHASE
  11. ml_analytics/models/model_trainer.py — existing trainer scaffold; extend/reuse, don't fork

Then `git pull origin main` and summarize back to me: what MT3 already does, what the eval
protocol requires, and what's missing — BEFORE writing code.

DATA (do NOT regenerate — it's frozen, git-ignored, transferred not pulled):
  Train on honeypot_dataset/data/final/  (unzip honeysynth_final.zip there if absent):
    X_train.npy (756000,128) / y_train.npy   — train, 45 classes
    X_val.npy   (84000,128)                  — validation
    X_test_real.npy  (60000,128, 21 real classes)  — HEADLINE metric
    X_test_synth.npy (60000,128, 45 classes)       — full-taxonomy behavior
    feature_scaler.pkl  — LOAD THIS EXACT SCALER, do NOT re-fit (baseline uses the same one)

HARD RULES:
  - Model architecture in mt3.py is done. Do NOT change it without asking me. Your work is the
    train/eval loop, loss weighting, checkpointing, metrics, and the comparison report.
  - MT3.forward(x, labels) already returns (emissions, hp_logits, loss) with the phase-aux loss
    built in — feed it the 45-way label; it derives the 9-way phase target itself.
  - Match the baseline's protocol: SAME splits, SAME scaler, SAME metrics (macro-F1 primary,
    per-class F1, accuracy, confusion matrix). SAVE predictions on X_test_real and X_test_synth
    so MT3 vs CNN-LSTM is compared on identical rows.
  - Use a class-weighted / focal loss (split is balanced but not uniform).
  - Do NOT run any notebook (01-05), do NOT touch honeypot_dataset/ pipeline or tabsyn/.
  - Train on the DGX (GB10), launched detached (tmux/screen) — see DGX.md. Laptop is client-only.
  - Stay in ml_analytics/. Push only ml_analytics/ files to main; pull before you start.

Deliverable: a runnable MT3 train+eval that reports macro-F1 on X_test_real (headline) and
X_test_synth, saves predictions, and prints a baseline-vs-MT3 comparison table.
```

---

## Notes for whoever runs this

- **The model is done; the pipeline is the gap.** `mt3.py` is complete and self-contained
  (per-group branch encoders → Transformer fusion over the 6 branch embeddings → dual heads,
  with the phase-auxiliary loss already wired into `forward`). Do not rewrite it.
- **The scaler rule is the one that makes-or-breaks the comparison.** If MT3 re-fits its own
  scaler, its numbers are not on the same footing as the baseline. Load
  `honeypot_dataset/data/final/feature_scaler.pkl` — do not re-fit.
- **Headline metric = `X_test_real`** (60k, 21 real classes); also report `X_test_synth`
  (60k, 45 classes). Same splits + same scaler for both models = a fair baseline-vs-MT3
  comparison. Save predictions so both are judged on identical rows.
