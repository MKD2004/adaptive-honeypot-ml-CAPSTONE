# DGX.md — College DGX Spark (GB10) server (system-specific, shared machine)

**This file is specific to the college DGX Spark (GB10) server.** It is the
**heavy-compute machine** — the sanctioned place to train models. Unlike the
laptops (code/orchestration only), real training runs here. Multiple people share
this machine, so coordinate (see "Shared-machine etiquette" below).

Read the shared rules first: `CLAUDE.md` (project brief) and `TEAMMATES.md` (hard
rules) apply here exactly as on every other machine.

---

## Machine identity

| | |
|---|---|
| Name | College DGX Spark |
| Compute | NVIDIA **GB10** (Grace-Blackwell) |
| OS | Linux |
| Access | remote client from any laptop (SSH / notebook) — **all compute is server-side**, the laptop is just a terminal |

**Verify real specs on first login** and record them here — do NOT trust the old
`HARDWARE.md` "college = RTX 4500 Ada, 24 GB (unverified)" line, which predates the
switch to the GB10:

```bash
nvidia-smi --query-gpu=name,memory.total,driver_version --format=csv
python -c "import torch; print(torch.__version__, torch.cuda.is_available(), torch.cuda.get_device_name(0))"
```

## Role of this machine

Heavy training. This is where the following run (per DECISIONS.md 2026-08-27):
- **CNN-LSTM + DistilBERT baseline** — teammates' deliverable (in `ml_analytics/`).
- **MT3 model** — Mahith's (for baseline comparison). Do not touch unless you are Mahith.
- **GReaT** (notebook 04, ~6-7h) — deferred; run here only if there's time before the review.
- Optionally **TabSyn diffusion/sampling** if not finished on the laptop.

## Setup (first time)

Follow `SETUP.md` end-to-end (it was written for the college Linux machine): clone
the repo, build a **fresh** venv (never copy the Windows venv), install deps, and
re-apply the TabSyn fixes.

- **TabSyn fixes are NOT in the repo** (`tabsyn/` is git-ignored). Clone upstream
  TabSyn, `git checkout cb5ac0f`, then `git apply patches/tabsyn-colab.patch`.
  That gives you every fix: VRAM batching, CLI wiring, `zero.py` shim, resume,
  early-stop, gradient clipping, batched sampling.
- The dataset artifacts below are git-ignored — they will NOT arrive via
  `git pull`. Transfer the zips from the laptop and unzip to the paths in the
  manifest.

## Transfer manifest (what to copy from the laptop and where to put it)

`git clone` gets all the CODE (notebooks, `configs/`, `src/`, `patches/`,
`ml_analytics/`, the `.md` docs). Only the **data** must be transferred manually.
All destination paths are **relative to the repo root** on the DGX.

| Transfer this (from laptop repo root) | Unzip / place at (DGX, repo-relative) | Needed for |
|---|---|---|
| **`honeysynth_final.zip`** | `honeypot_dataset/data/final/` | **CNN-LSTM baseline + MT3 training — the PRIMARY artifact.** Frozen splits + scaler. |
| `real_dataset_Xy.zip` (`X_real.npy`, `y_real.npy`) | `honeypot_dataset/data/processed/` | GReaT (notebook 04) later; also the 22-class real-only fallback |
| `honeypot_dataset/data/processed/semantic_pca.pkl` | `honeypot_dataset/data/processed/` | only if re-extracting features / GReaT semantic branch |

**Unzip commands (from the repo root on the DGX):**
```bash
mkdir -p honeypot_dataset/data/final honeypot_dataset/data/processed
unzip honeysynth_final.zip -d honeypot_dataset/data/final/
unzip real_dataset_Xy.zip  -d honeypot_dataset/data/processed/   # if doing GReaT / fallback
```

**What the models train on:** everything in `honeypot_dataset/data/final/` —
```
X_train.npy (756k) / X_val.npy / X_test_synth.npy / X_test_real.npy  + matching y_*.npy
feature_scaler.pkl   <- BOTH CNN-LSTM and MT3 must load this same scaler (do not re-fit)
dataset_card.json / quality_report.json
```
Evaluate on **`X_test_real`** (60k, 21 real classes) as the headline metric;
`X_test_synth` (60k, 45 classes) shows full-taxonomy behavior. Same splits + same
scaler for both models = a fair baseline-vs-MT3 comparison.

**Only needed if you also run TabSyn/GReaT here** (not for the baseline): apply the
patch (`git checkout cb5ac0f` + `git apply patches/tabsyn-colab.patch` in a fresh
tabsyn clone), and transfer `tabsyn/tabsyn/vae/ckpt/honeypot_sessions/train_z.npy`
(2.8 GB) + `tabsyn/data/honeypot_sessions/` only if re-sampling TabSyn.

## Running jobs here — ALWAYS launch detached

Your laptop is just a client; if you close it or drop SSH, a **foreground** job
dies. Launch long jobs under `tmux` / `screen` (or `nohup ... &`) so they survive
disconnection:

```bash
tmux new -s train            # start a persistent session
# ... launch training inside it ...
# detach with Ctrl-b then d ; reattach later with: tmux attach -t train
```

The training scripts honor the same committed env-var interface as on the laptop
(so behavior is identical): `TABSYN_RESUME`, `TABSYN_CONVERGE_PATIENCE`,
`TABSYN_GRAD_CLIP`, `TABSYN_CKPT_EVERY`, `TABSYN_EPOCH_LOG`, `TABSYN_SAMPLE_BATCH`,
`TABSYN_N_SAMPLE`. On the GB10's larger memory you can raise batch sizes vs the
4 GB laptop.

## Shared-machine etiquette (multiple people + multiple Claude Codes here)

- **`git pull` before you start; push only your own module's files.** Never edit
  shared files (schema, extractors, notebooks, `CLAUDE.md`, `SCHEMA.md`, …) locally
  without agreeing first — that is how machines drift out of sync.
- **Stay in your lane:** teammates → `ml_analytics/` (CNN-LSTM). Owner → dataset
  pipeline / TabSyn / GReaT / MT3. `TEAMMATES.md` rule 1 (do not run/edit the
  dataset pipeline or notebooks) applies here too.
- **Don't run two heavy jobs that collide on the GPU** without checking `nvidia-smi`
  first — coordinate who's training when.
- **Any AI assistant (Claude Code) on this box follows `CLAUDE.md` + `TEAMMATES.md`.**
  It must refuse to run/edit the dataset notebooks or `tabsyn/` unless the person
  driving it is the dataset owner.

---

## How every machine stays in sync (the answer to "I don't want different versions")

**GitHub `main` is the single source of truth. Every Claude Code on every machine
pulls `main` before working and pushes its changes back.** That keeps the *code*
and the *shared docs* byte-identical everywhere. The ONLY things that legitimately
differ per machine are the **system-specific** files:

- System-specific (each machine has/uses its own): `HARDWARE.md`, `SETUP.md`,
  `STATUS.md`, and the per-machine files `ASUS.md`, `DGX.md`, `DELL.md`, …
- Shared / identical everywhere (never fork locally): `CLAUDE.md`, `README.md`,
  `SCHEMA.md`, `DECISIONS.md`, `ERRORS.md`, `TEAMMATES.md`.

So there is no "different version of the project" — only different per-machine
notes. If a shared file needs changing, change it once and push, so everyone pulls
the same thing.
