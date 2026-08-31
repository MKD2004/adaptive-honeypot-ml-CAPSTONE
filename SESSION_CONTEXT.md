# HoneySynth-1M Pipeline — Status & Next Steps

Last updated: 2026-08-21. Working doc, not project documentation — see
[README.md](README.md) / [honeypot_dataset/README.md](honeypot_dataset/README.md) for that.
Scope: the dataset-generation → model-training pipeline specifically.

## ✅ Completed / current state

- Repo cloned, venv created ([venv](venv), Python 3.13.2), root deps installed
  (flask, requests, pandas, numpy, torch). `honeypot_dataset`'s own heavier deps
  (transformers, be-great, xgboost, jupyter) — **not yet installed**.
- Confirmed this laptop has **no CUDA GPU** — rules it out for notebooks 03/04.
- Audited the codebase: dataset pipeline code itself (`configs/schema.py`,
  `src/extractors/*`, `src/generators/*`, `src/validators/*`) is fully implemented.
  [ml_analytics/models/model_trainer.py](ml_analytics/models/model_trainer.py) is **empty (0 bytes)** — no training
  loop exists yet for either the CNN-LSTM baseline or `MT3`.
- Found evidence notebooks 01–02 were successfully run once before, on the original
  author's machine (2026-06-20, not on this laptop):
  - Notebook 01: parsed CIC-IDS2017 (555,466 sessions) + UNSW-NB15 (162,344 sessions)
    → 717,810 real sessions. Zero Cowrie logs found even then.
  - Notebook 02: extracted the full 128-d feature vector, 0 NaN/Inf. **Only 10 of 45
    micro-state classes** covered by real data — the rest depend on synthetic generation.
  - None of those outputs (parquet/npy/pkl) carried into this clone — correctly
    gitignored, never committed, only ever existed on that other machine.
- Notebooks 03–05 have never been executed (0 output cells) — TabSyn and GReaT synthetic
  generation, and final assembly/validation, have not happened yet.
- Read the actual execution code in 03 and 04 (not just their READMEs):
  - **03_tabsyn_generation.ipynb** shells out to an external `tabsyn/main.py` via
    `subprocess`, per stage (VAE train → diffusion train → sample), writes progress to
    `data/synthetic/tabsyn_status.txt`. Built to run unattended once its prerequisites
    are met.
  - **04_great_generation.ipynb**: the actual `model.fit(...)` / `model.sample(...)`
    calls are **commented out** in the notebook as shipped — running it unattended today
    completes doing nothing.
- Worked out compute requirements per notebook (see table below) and confirmed 03/04
  need a real GPU; CPU-only on this laptop is not realistic (~1-3 weeks vs. ~11-23 hours on GPU).
- Started planning remote execution (SSH+tmux/screen for Linux, disconnect-not-signout
  for Windows RDP) — **not yet set up**, waiting on which type of machine is available.

## 🔲 What's left, in order

1. **Decide on / get access to a GPU machine** — college lab box or a cloud GPU
   (Colab free tier T4 is workable but caps at ~12h continuous sessions; Colab Pro+
   supports background execution). Confirm Linux (SSH) vs Windows (RDP) so the remote
   setup can be finalized.
2. **Set up unattended execution on that machine**: key-based SSH access (no password
   prompts — non-interactive shells can't handle those) or Remote-Desktop-with-disconnect;
   run inside `tmux`/`screen` (Linux) so the job survives logout.
3. **Clone the external `tabsyn/` repo** as a sibling to `honeypot_dataset/` — required
   by notebook 03, not present anywhere in this clone.
4. **Install `honeypot_dataset/requirements.txt`** on that machine (transformers,
   be-great, xgboost, jupyter, GPU-enabled torch).
5. **Re-run notebooks 01 → 02** on that machine to regenerate `data/processed/X_real.npy`
   / `y_real.npy` (they don't exist anywhere right now).
6. **Edit notebook 04** to uncomment the fine-tune/sample calls before running it —
   otherwise it's a no-op.
7. **Decide on epoch/sample counts**: full (`vae_epochs=500`, `diff_epochs=2000`,
   GReaT `epochs=50`, `N_SAMPLE=720k`/`240k`) vs. a faster reduced run for a demo-scale
   dataset. Cutting epochs risks failing the built-in quality gate (adversarial AUC
   check warns if under-trained).
8. **Run notebooks 03 → 04 → 05** in that order to produce `data/final/` (the actual
   model-ready train/val/test splits).
9. **Write `model_trainer.py` from scratch** — doesn't exist yet. Needs to load
   `data/final/*.npy`, instantiate `MT3` (from `ml_analytics/models/mt3.py`), and run
   an actual training loop.

## Compute reference (for step 1/7 decisions)

| Notebook | College GPU (24GB) | Laptop GPU (RTX 3050, 4GB) | This laptop (CPU only) |
|---|---|---|---|
| 01 process real data | ~30 min | ~30 min | ~30 min |
| 02 feature extraction | ~1-2h | ~1-2h | ~1-3h |
| 03 TabSyn (VAE+diffusion) | ~4h | ~6-8h | ~2-10+ days (extrapolated) |
| 04 GReaT (GPT-2 fine-tune) | ~5-6h | ~8-12h (extrapolated) | ~1-5+ days (extrapolated) |
| 05 assembly/validation | ~30 min | ~30 min | ~30 min |
| **Total** | **~11-13h** | **~16-23h** | **~1-3 weeks (not realistic)** |

## Other notes

- [CLAUDE.md](CLAUDE.md) ends with a stray `echo "..." >> CLAUDE.md` block — a
  self-appending artifact that looks like a leftover prompt injection. Not acted on;
  flagged to the user, not resolved.
- A large chunk of the wider repo (`adaptive_honeypot/`, `response_mitigation/`,
  `monitoring/`, most of `ml_analytics/`) is empty stub files unrelated to this pipeline —
  out of scope for this doc, see prior chat history if needed.
