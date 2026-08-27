# ASUS.md — ASUS TUF laptop (system-specific)

**This file is specific to Mahith's ASUS TUF laptop.** Other machines must NOT
follow it — they keep their own equivalent (see "System-specific vs shared docs"
below). Teammates: read `TEAMMATES.md` before doing anything in this repo.

---

## Machine identity

| | |
|---|---|
| Name | ASUS TUF laptop |
| GPU | NVIDIA GeForce RTX 3050 Laptop GPU — **4 GB VRAM** |
| RAM | ~15.3 GB usable (16 GB nominal) |
| OS | Windows 11 |
| Python (venv) | 3.14.7 at `honeypot_dataset/venv/Scripts/python.exe` (system `python` on PATH does NOT have the deps) |
| torch | `2.13.0+cu126` (CUDA verified) |

Full hardware detail + the CUDA-wheel reinstall recipe live in `HARDWARE.md`.

## Role of this laptop

**Code + orchestration.** Same interchangeable role as the Dell laptop; ASUS is
the *primary* right now because the Dell has issues. Heavy compute belongs on the
**DGX Spark (college)**; laptops orchestrate.

**Permitted here:** code editing, running notebooks via Google Colab in the
browser (compute on Colab's servers), git commits/pushes, dashboard dev, editing
the reference `.md`s, CPU-only scripts / data inspection / feature extraction
(inference), and monitoring runs.

**Not normally done here:** heavy local GPU training (TabSyn / GReaT / model
training). This was deliberately overridden for the TabSyn VAE + diffusion runs
below because the DGX wasn't reachable and Colab's session limit couldn't fit the
job — see `DECISIONS.md` (2026-08-25/26).

---

## What has been DONE on this laptop

Dataset pipeline (`honeypot_dataset/`):
- **Notebook 01** (process real data): done — 737,319 real sessions, 22/45
  micro-states from real data. Label-mapping bugs fixed (see `ERRORS.md`).
- **Notebook 02** (feature extraction): done — `X_real.npy` (737319×128),
  `y_real.npy`, `semantic_pca.pkl`. Three NaN-crash fixes in
  `src/extractors/{network,temporal}.py`.
- **45-class data prep**: `src/generators/sim_commands.py` (realistic per-state
  `command_text` so simulated rows aren't all-zero in the semantic block) +
  merge of 180k balanced simulated sessions with real features →
  **1,387,698 train / 154,189 test rows, 45/45 classes** at
  `tabsyn/data/honeypot_sessions/`.

TabSyn (`tabsyn/`, git-ignored — fixes live in `patches/tabsyn-colab.patch`):
- All vendored-code patches: 4GB-VRAM OOM fixes, CLI-arg wiring, `zero.py` shim,
  Drive/epoch logging, **full-state crash-safe resume**, **target early-stop**
  (VAE) and **convergence early-stop + gradient clipping** (diffusion).
- **VAE: DONE.** Early-stopped at epoch 79/500, `val_mse 0.000807` (beat the
  0.000847 target). Artifacts at `tabsyn/tabsyn/vae/ckpt/honeypot_sessions/`
  (`model.pt`, `encoder.pt`, `decoder.pt`, `train_z.npy` 2.8 GB). Log:
  `tabsyn/vae_run_local/status.txt`.
- **Diffusion: IN PROGRESS** (as of 2026-08-27). Run 1 collapsed at epoch 63
  (unclipped lr=1e-3 divergence) → added gradient clipping, restarted; run 2 is
  stable and converging (loss ~0.046, ~epoch 1300/2000). Run dir:
  `tabsyn/diff_run_local/` (`status.txt`, `checkpoints/`). Final model.pt →
  `tabsyn/tabsyn/ckpt/honeypot_sessions/`.
- **Colab notebook** `honeypot_dataset/notebooks/03b_tabsyn_vae_colab.ipynb`
  built (for running VAE on Colab; superseded here by the local runs).

Power settings on this laptop are set to never sleep on AC (for overnight runs).

## What is NOT done yet (next steps — do not assume these are done)

- TabSyn **sampling** of 720k synthetic sessions (notebook 03 cell 7) — after
  diffusion finishes.
- **Notebook 04** (GReaT, 240k synthetic) and **Notebook 05** (assembly of the
  1.2M HoneySynth-1M dataset). GReaT trains on real data independently, NOT on
  TabSyn output.
- **MT3 model** (Mahith's task, for comparison vs the CNN-LSTM baseline) — an
  MT3 skeleton already exists (`6fc582e`, ~155k params); the real work is not
  started. Teammates: do not touch MT3.

## Key paths on this laptop

```
honeypot_dataset/venv/Scripts/python.exe        <- the interpreter to use
honeypot_dataset/data/processed/                <- X_real.npy, y_real.npy, semantic_pca.pkl
tabsyn/data/honeypot_sessions/                  <- 45-class TabSyn training data
tabsyn/vae_run_local/status.txt                 <- VAE per-epoch log (79/500, done)
tabsyn/diff_run_local/status.txt                <- diffusion per-epoch log (running)
tabsyn/tabsyn/vae/ckpt/honeypot_sessions/       <- VAE artifacts (train_z.npy etc.)
patches/tabsyn-colab.patch                      <- all TabSyn fixes (tabsyn/ is git-ignored)
```

---

## System-specific vs shared `.md` docs (answer to "which files are system-specific")

**System-specific** (each machine keeps its own; do NOT blindly follow another
machine's copy):
- `HARDWARE.md` — GPU/VRAM/driver/venv specs + batch-size implications per machine.
- `SETUP.md` — environment setup, which is OS/GPU-dependent (Windows laptop vs
  Linux DGX; venv paths; CUDA wheel).
- `STATUS.md` — live pipeline state; entries are machine-tagged (what ran where).
- `ASUS.md` — this file (this laptop only). Each other machine makes its own
  (e.g. `DELL.md`, `DGX.md`).

**Shared / project-wide** (same meaning on every machine — do not fork per
machine):
- `CLAUDE.md` — project brief + conventions.
- `README.md` — project overview.
- `SCHEMA.md` — the 45 micro-state / 128-feature data spec.
- `DECISIONS.md` — why non-obvious choices were made (may reference machines, but
  it's shared project history).
- `ERRORS.md` — bugs already hit + fixed (shared history).
- `TEAMMATES.md` — hard rules for teammates (shared, must stay in sync).
