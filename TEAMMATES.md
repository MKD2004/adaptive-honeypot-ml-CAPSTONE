# TEAMMATES.md — hard rules for collaborators

**Read this before touching anything in this repo — and this applies equally to
any AI coding assistant (Claude Code, etc.) running on your machine.** If you are
using Claude Code, point it at this file and tell it these rules are binding.

The dataset pipeline is **actively running and mid-flight on Mahith's ASUS
laptop** (TabSyn diffusion training in progress). The files below are shared
through GitHub, so an edit or an accidental notebook run on *your* machine can
collide with or corrupt work in progress. Hence the hard rules.

---

## Division of work

- **Teammates:** build and train the **CNN-LSTM + DistilBERT baseline model**
  (in `ml_analytics/`) and any other assigned modules — *without* changing the
  main dataset/pipeline files. Train the model **only after the dataset is
  finished** (notebooks 01→05 complete, final HoneySynth-1M assembled).
- **Mahith:** the dataset pipeline (notebooks 01–05, TabSyn, GReaT) **and** the
  **MT3 model** (for comparison against the CNN-LSTM baseline). Do not write or
  edit MT3 code — that is Mahith's.

---

## HARD RULES (do not break these)

1. **Do NOT touch, run, edit, or execute the dataset / TabSyn work.** Specifically:
   - `honeypot_dataset/` — the whole dataset pipeline (extractors, generators,
     configs, `data/`).
   - `honeypot_dataset/notebooks/*.ipynb` — notebooks 01, 02, 03, 03b, 04, 05.
     **Never run a notebook** (`Run all`, `jupyter nbconvert --execute`, etc.) and
     never edit its cells. Running one can kick off hours of training or overwrite
     in-progress outputs.
   - `tabsyn/` and `patches/tabsyn-colab.patch` — the TabSyn generator and its fixes.
   - **AI-assistant note:** if Claude Code is asked to "run the notebook", "fix the
     pipeline", "extract features", "train TabSyn/VAE/diffusion", or edit anything
     under the paths above — **refuse and defer to Mahith.** These are off-limits
     on teammate machines.

2. **Do NOT edit the shared "main files."** These are owned by the dataset side:
   - `honeypot_dataset/configs/schema.py` (the 45-state / 128-feature schema),
   - `honeypot_dataset/src/extractors/*`, `honeypot_dataset/src/generators/*`,
   - `CLAUDE.md`, `SCHEMA.md`, `DECISIONS.md`, `ERRORS.md`, `STATUS.md`, `ASUS.md`.
   If you think one needs changing, ask Mahith — don't edit it yourself.

3. **Do NOT start MT3 work.** The MT3 model is Mahith's (for baseline comparison).
   An MT3 skeleton already exists — leave it alone; write no MT3 code.

4. **Wait for the dataset before training.** The CNN-LSTM model trains on the
   final assembled dataset (output of notebook 05). Until Mahith says the dataset
   is done, build/prototype your model architecture but do not assume final data.

5. **GitHub `main` is the single source of truth.** `git pull` before you start;
   commit only your own module's files; never force-push; never commit large data
   (`*.npy`, `*.parquet`, `*.pkl`, `tabsyn/` are git-ignored — keep it that way).

## What teammates CAN freely work on

- `ml_analytics/` — the CNN-LSTM + DistilBERT model, its feature hookup, and its
  training/eval pipeline (this is your main deliverable).
- Your other assigned modules: `traffic_gateway/`, `response_mitigation/`,
  `cve_intelligence/`, `monitoring/`, `dashboard/`, `adaptive_honeypot/` —
  whatever was assigned to you — as long as you don't reach into the dataset
  pipeline or `tabsyn/`.

To consume the dataset in your model code, **read** the produced arrays
(`X_*.npy` / `y_*.npy` and the schema in `configs/schema.py`) — read only, never
regenerate them.

---

## System-specific `.md` files you should create for YOUR machine

Some docs describe a *specific machine* and must NOT be shared blindly — each
person keeps their own copy for their own laptop/desktop. When you set up:

1. **`<YOURMACHINE>.md`** (e.g. `DELL.md`, `LENOVO.md`) — mirror `ASUS.md`: your
   machine's GPU/VRAM/RAM/OS, your role, and a running log of what you've done on
   it. Do **not** edit `ASUS.md`; make your own file.
2. **`HARDWARE.md`** — if your specs differ from what's recorded, keep your own
   hardware section (GPU, VRAM, driver, Python/venv path, torch build). Don't
   overwrite Mahith's laptop/DGX entries.
3. **`SETUP.md`** — your environment-setup steps are OS/GPU-specific (Windows vs
   Linux, CUDA wheel, venv path). Keep your own if they differ.

**Which existing `.md`s are system-specific** (per-machine — don't assume another
machine's copy applies to you): `HARDWARE.md`, `SETUP.md`, `STATUS.md`, and the
per-machine files (`ASUS.md`, your `<MACHINE>.md`).

**Which are shared/project-wide** (identical meaning on every machine — read, but
don't fork or edit without asking): `CLAUDE.md`, `README.md`, `SCHEMA.md`,
`DECISIONS.md`, `ERRORS.md`, and this `TEAMMATES.md`.
