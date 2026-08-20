# College PC Setup Guide

Machine setup for the Adaptive Honeypot / HoneySynth-1M project — covers
two different situations, pick the one that matches what you're actually
doing:

- **Your own laptop, already cloned** (e.g. the new laptop you're
  bringing to college) — you mostly need Step 0 + Step 1B (pull) +
  Step 2, not a fresh clone.
- **A machine with nothing on it yet** (a college lab PC you get
  allocated, or a laptop that's never had this repo) — the full Step 0
  → Step 1A (clone) → Step 2 flow.

Covers **both Windows and Ubuntu** since college lab machines can be
either — read the OS-specific section that matches your machine, everything
else is shared.

Repo: `https://github.com/MKD2004/adaptive-honeypot-ml-CAPSTONE`
Branch to use: `feature/ml-analytics` (this is where all current work
lives — MT3 architecture, the class-coverage fix, the setup scripts).

---

## Step 0 — Do this on YOUR laptop before you leave

Two things are currently sitting on this laptop only, not in GitHub.
Skip either one and the college PC setup breaks or silently uses stale
data.

### 0.1 — Code that has to be pushed

Without these committed and pushed, getting the code onto the target
machine (by clone *or* pull) gets you the *old* environment — no setup
script, no VRAM patch, no record of the class-coverage fix.

**Status: done.** Committed as `83c63d4` and pushed to
`origin/feature/ml-analytics` already — this step doesn't need repeating
unless you make further local changes on this laptop before transferring.
Record of what's now safely on GitHub:

```
setup.sh
setup.ps1
honeypot_dataset/docs/tabsyn_patches.md
honeypot_dataset/docs/tabsyn_patches.patch
honeypot_dataset/src/generators/fill_missing_classes.py
.gitignore                                    (fix to the logs/ pattern)
TEAM_BRIEFING.md
SESSION_NOTES.md
SETUP_GUIDE.md
```

`INTERVIEW_PREP.md` and `PANEL_REVIEW_UPDATE.md` were deliberately left
out of that commit — personal/local reference only, not for the repo.
`data/synthetic/` and `tabsyn/` were also left out — build output and a
third-party clone respectively, both correctly gitignored/untracked.

### 0.2 — Data that git will never carry

`.gitignore` deliberately excludes `*.npy`, `*.pkl`, `*.parquet`, and all
of `honeypot_dataset/data/` — correct, since these are large binaries
that don't belong in git. But it means **`git clone` alone will not give
you the corrected dataset.** You need to move these files separately:

| Path | Size | Why you need it |
|---|---|---|
| `honeypot_dataset/data/processed/X_real.npy` | ~460 MB | **The corrected 45-class data** — this is the whole point of the college rerun |
| `honeypot_dataset/data/processed/y_real.npy` | ~7 MB | labels for the above |
| `honeypot_dataset/data/processed/real_sessions_combined.parquet` | ~18 MB | |
| `honeypot_dataset/data/processed/real_meta.parquet` | ~4 MB | |
| `honeypot_dataset/data/processed/sim_meta.parquet` | ~6 MB | metadata for the injected classes |
| `honeypot_dataset/data/processed/semantic_pca.pkl` | ~100 KB | fitted PCA — needed by `fill_missing_classes.py` / semantic extractor |
| `honeypot_dataset/data/processed/ti_cache.json` | ~30 KB | cached NVD/EPSS API responses |
| `honeypot_dataset/data/raw/cic_ids2017/` | ~844 MB | raw source CSVs, only needed if you plan to re-run Notebook 01 |
| `honeypot_dataset/data/raw/unsw_nb15/` | ~46 MB | same |
| `.env` | <1 KB | your `NVD_API_KEY` — never committed, copy by hand |

`honeypot_dataset/data/backup_processed/` (the pre-fix 10-class snapshot,
~378 MB) is optional — only bring it if you want a side-by-side
comparison; it's not needed for the rerun itself.

**Two ways to move this, pick based on your situation:**

**A. Same Microsoft account, OneDrive sync (easiest).** This project
already lives under `OneDrive\Desktop\...` on this laptop. If you sign
into the *same* Microsoft account on the college PC and it's set up to
sync that OneDrive, these files can just... be there once sync catches
up. Caveats: (1) large files may show as "cloud-only" placeholders that
need "Always keep on this device" toggled before Python can read them
without a re-download delay; (2) don't rely on this if the college PC
uses a shared/lab account that isn't tied to your Microsoft login.

**B. USB drive / manual transfer (works everywhere).** Total to move is
roughly ~1.3 GB if you skip the raw CSVs and backup snapshot (just
`processed/` + `.env`), or ~2.2 GB if you bring everything in the table.
Copy the files preserving the exact relative paths shown in the table —
the notebooks and scripts expect them at those locations, not wherever
is convenient.

---

## Step 1 — Get the code onto the target machine

Pick 1A or 1B depending on whether the machine already has the repo.
Either way, **Step 0.2's data transfer still applies afterward** — `git`
never carries the data files, whether you clone fresh or pull an
existing checkout.

### 1A — Fresh machine, nothing cloned yet

```bash
git clone https://github.com/MKD2004/adaptive-honeypot-ml-CAPSTONE.git
cd adaptive-honeypot-ml-CAPSTONE
git checkout feature/ml-analytics
```

### 1B — Already cloned (e.g. your own laptop from an earlier setup)

Check for local changes before pulling — don't pull over uncommitted
work you don't recognize:

```powershell
cd path\to\adaptive-honeypot-ml-CAPSTONE
git status
```

If that's clean (or anything shown is safe to stash), fetch and sync to
the branch with the current work:

```powershell
git fetch origin
git checkout feature/ml-analytics   # skip if already on this branch
git pull origin feature/ml-analytics
```

If `git status` showed changes you don't want to lose:
`git stash` first, pull, then `git stash pop` to bring them back —
don't discard anything blind.

**Either way, then:** drop in the data files from Step 0.2 at their exact
paths, and copy your `.env` file into the repo root. If the machine
already has some of these files from an earlier sync, don't assume
they're current — re-run the Step 3 verification below on them rather
than trusting an old copy, especially `y_real.npy` (an old copy may only
have 10/45 classes).

---

## Step 2A — Windows

```powershell
# If PowerShell blocks the script:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

.\setup.ps1
```

What it does, in order: checks for Python 3.11 (via `py -3.11`), creates
`honeypot_dataset\venv` if missing, installs CUDA PyTorch (cu121),
installs `honeypot_dataset\requirements.txt`, installs
`python-dotenv`/`jupyter`/`xgboost`/`be-great`, clones TabSyn fresh into
`tabsyn\` **and applies the 4GB-VRAM patch automatically**, installs
TabSyn's own requirements, runs a smoke test (schema + full MT3 forward
pass), and prints a summary (GPU name/VRAM, CUDA availability, per-package
status).

If Python 3.11 isn't already on the machine, install it from
python.org first — the script fails fast with a clear message rather
than silently using the wrong version.

## Step 2B — Ubuntu

Two things Ubuntu needs that Windows doesn't, both common enough to
handle upfront:

1. **Python 3.11 may not be the system default.** Ubuntu 22.04 ships
   3.10, 24.04 ships 3.12. If `python3.11 --version` fails:
   ```bash
   sudo add-apt-repository ppa:deadsnakes/ppa
   sudo apt update
   sudo apt install python3.11 python3.11-venv
   ```
   (skip this if the lab image already has 3.11 — check first.)

2. **The venv module is a separate package on Debian/Ubuntu.** Even with
   Python 3.11 installed, `python3.11 -m venv` can fail without
   `python3.11-venv` explicitly installed (the command above covers it).

Then:

```bash
chmod +x setup.sh
./setup.sh
```

Same 10 steps as the Windows version, same automatic TabSyn clone + VRAM
patch. If `nvidia-smi` isn't found, the summary will say "no GPU
detected" — flag that to lab staff before doing anything else, since the
whole point of the college machine is the RTX 4500 Ada's 24GB VRAM.

---

## Step 3 — Verify before doing anything else

The script's own smoke test is your first signal, but check these
explicitly against what the summary prints:

- **GPU detected**: should read something like
  `NVIDIA RTX 4500 Ada Generation, 24564 MiB` — not the 4GB laptop card.
- **torch CUDA available: True**.
- **Schema OK: 45 classes, 128 features** — printed by the smoke test.
- **MT3 smoke test PASSED** with a params count (~4.3M) and
  `dag_constraint loaded from schema: True`.

Then confirm the data actually landed correctly:

```bash
python -c "
import numpy as np
y = np.load('honeypot_dataset/data/processed/y_real.npy')
u = np.unique(y)
print(f'{len(u)} classes present, {len(y)} total rows')
assert len(u) == 45, 'Data transfer incomplete or wrong file — expected 45 classes'
print('OK — this is the corrected dataset')
"
```

If that prints `10 classes present` instead of 45, you copied the wrong
file (likely from `backup_processed/` or an old sync) — go back to
Step 0.2.

---

## Step 4 — What to actually run once verified

This guide only covers getting the *environment* right. The actual
rerun plan (Notebook 03 → TabSyn VAE → TabSyn diffusion, and why each
step is needed) is in `PANEL_REVIEW_UPDATE.md` §4 — read that before
kicking off a multi-hour training run so you're not surprised by
anything, in particular:

- Notebook 03 needs to run **from the top** so it re-exports
  `tabsyn/data/honeypot_sessions/` from the corrected 45-class data
  (the old export only ever saw 10 classes).
- Set `--ckpt_every 50` (not 200) on both VAE and diffusion training —
  this is a lesson from the earlier collapsed run, not a VRAM
  consideration, and it now applies regardless of how much headroom the
  24GB card gives you. See `honeypot_dataset/docs/tabsyn_patches.md`
  patch #5 for the exact command-line flags.

---

## One more thing worth flagging

`honeypot_dataset/.env.example` currently has what looks like a real NVD
API key value checked into the *public* GitHub repo, not a placeholder
like `your_key_here`. Worth confirming whether that key is still active
and rotating it at nvd.nist.gov if so — an API key with no cost/PII
exposure isn't a severe leak, but it shouldn't be sitting in a public
repo's example file either way.

---

## Troubleshooting quick-reference

| Symptom | Likely cause | Fix |
|---|---|---|
| `setup.ps1` won't run at all | execution policy | `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser` |
| `python3.11: command not found` (Ubuntu) | not installed / no deadsnakes PPA | see Step 2B item 1 |
| `python3.11 -m venv` fails with an "ensurepip" error (Ubuntu) | missing `python3.11-venv` | `sudo apt install python3.11-venv` |
| GPU detected: none | wrong machine, or drivers not loaded | check with lab staff before troubleshooting further |
| smoke test schema import fails | data files not copied to the right relative path | re-check Step 0.2 paths exactly |
| `y_real.npy` shows 10 classes not 45 | copied `backup_processed/` or a stale sync instead of `processed/` | re-copy from Step 0.2 |
| TabSyn patch step warns "could not verify VRAM patch state" | someone hand-edited `tabsyn/` files outside the patch | inspect `git -C tabsyn status`, resolve manually, see `tabsyn_patches.md` |
