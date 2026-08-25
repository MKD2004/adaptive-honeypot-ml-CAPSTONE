# STATUS

Reference only — not committed. Update this at the end of every session: what's
done, what's running, what's next. Keep it short — this is a snapshot, not a log
(that's DECISIONS.md / ERRORS.md).

---

## Last updated: 2026-08-25 (session 2, ASUS TUF)

### Session 2 summary (2026-08-25)
Built the Colab overnight VAE pipeline on the ASUS TUF (code/orchestration only —
no local GPU training). Decision reversed to 45-class TabSyn (see DECISIONS.md).

- **New:** `honeypot_dataset/notebooks/03b_tabsyn_vae_colab.ipynb` — mounts Drive,
  clones repo + TabSyn (pinned `cb5ac0f` + `patches/tabsyn-colab.patch`), merges
  180k balanced simulated sessions with real features, **asserts 45/45 classes**,
  trains VAE only (batch 4096, 500 epochs), checkpoints every 50 epochs + logs
  every epoch to `Drive/.../tabsyn_status.txt`. Does NOT start diffusion.
- **New:** `src/generators/sim_commands.py` — realistic per-micro-state
  `command_text` so simulated rows populate the semantic block (leak fix).
  Validated locally: 45/45 classes, semantic block non-zero for all rows, 0 NaN/Inf.
- **New:** `patches/tabsyn-colab.patch` — the vendored-TabSyn fixes as a git-appliable
  patch (tabsyn/ is git-ignored, so this is how Colab gets them). Now also includes
  the env-var-driven Drive checkpoint/epoch-log hook. Verified applies clean to cb5ac0f.
- Committed + pushed to `main` (`dbafc90`): notebook, sim_commands, patch, the two
  extractor NaN fixes, `.gitattributes` LF rule for *.patch.
- ASUS power locked for overnight: AC sleep/monitor = never, lid-close = do nothing.

**Training status: NOT yet started.** The notebook is built, validated, and pushed,
but running it is a browser action on Colab (needs data uploaded to Drive first —
see "Immediate next step"). Do not report VAE training as started until the user has
run 03b and `tabsyn_status.txt` shows a START line.

---

## (session 1) 2026-08-11

## Pipeline stage

| Notebook | Status | Notes |
|---|---|---|
| 01_process_real_data | ✅ Done | 737,319 real sessions saved to `data/processed/real_sessions_combined.parquet`. 22/45 micro-states covered from real data (see SCHEMA.md for which). |
| 02_feature_extraction | ✅ Done | Ran clean on attempt #4 (3 crash bugs fixed first, see ERRORS.md). `X_real.npy`/`y_real.npy` saved, shape (737319, 128) / (737319,), 0 NaN / 0 Inf. Classes covered: 22/45 (matches SCHEMA.md prediction exactly). Semantic PCA fitted (98.4% variance) and saved to `data/processed/semantic_pca.pkl`. Total wall time ~21 min (much faster than the notebook's own 180k-session benchmark implied). |
| 03_tabsyn_generation (data prep, cell 3.1) | ✅ Done | `tabsyn/data/honeypot_sessions/` prepared: 886,549 train / 98,506 test rows. Only 22/45 classes present (same gap as notebook 01/02 — cell 3's oversampling loop only touches classes present in the data). `info.json` still says `n_classes: 45` but the model's actual `category_embeddings` are sized `[22, 4]`. **Open question, see DECISIONS.md — not yet resolved.** |
| 03_tabsyn_generation (VAE timing test) | ✅ Done | 3-epoch test run on this laptop (RTX 3050, batch 512): **~140 sec/epoch measured**. Hit and fixed 5 real bugs in the vendored `tabsyn/` code along the way (missing deps, ignored CLI args, 3x unbatched-forward-pass OOM, torch version-skew crash) — see ERRORS.md. Extrapolated full-run estimates: 500 epochs ≈ **19.4 hours**, 1000 ≈ 38.9h, 4000 (the old broken hardcoded default) ≈ 155h. |
| 03_tabsyn_generation (real VAE run, 500 epochs) | ⏳ Deferred to college | 22/45-class scope confirmed correct by design (see DECISIONS.md) — no data-prep changes needed. Laptop run would be ~19.4h; user decided to run VAE on the college RTX 4500 Ada instead. All 5 bug fixes from today are in the vendored `tabsyn/` code itself, so they carry over — should NOT need rediscovering at college. |
| 03_tabsyn_generation (diffusion) | ⏳ Deferred to college | Same session as VAE now. Diffusion also had the hardcoded-epoch bug (was always 10,001 epochs, not the notebook's intended 2,000) — now fixed, same pattern as VAE. Its own unbatched-eval-OOM risk has NOT been explicitly checked/fixed (lower priority since college has 24GB, but worth a quick look before a real run there). |
| 04_great_generation | ⏳ Not started | |
| 05_assembly_validation | ⏳ Not started | |

## Environment

- venv at `honeypot_dataset/venv/` has torch `2.13.0+cu126` (CUDA-enabled, verified working — see HARDWARE.md). System Python 3.14 does NOT have the project deps; always use the venv interpreter.
- Raw data present: Cowrie (`data/raw/cowrie_logs/cowrie.json`, 15,000 sessions), CIC-IDS2017 (8/8 CSVs), UNSW-NB15 (both files).

## Immediate next step (2026-08-25)

**To start the overnight Colab VAE run from ASUS TUF:**
1. Upload to a Google Drive folder `MyDrive/capstone/` (the notebook's `DRIVE_PROJECT`):
   `X_real.npy`, `y_real.npy`, `semantic_pca.pkl` (all in `honeypot_dataset/data/processed/`).
   `real_sessions_combined.parquet` is optional (the notebook reuses the extracted
   `X_real.npy` for the real side, so it is not required).
2. Open `honeypot_dataset/notebooks/03b_tabsyn_vae_colab.ipynb` in Colab (GitHub →
   the pushed `main`), set Runtime → GPU, Run all.
3. Watch cell 5 assert 45/45, then cell 7 stream VAE epochs. Paste the keep-alive
   snippet in the browser console; leave the tab open overnight.
4. Morning check: `Drive/capstone/tabsyn_vae_run/tabsyn_status.txt` — epoch 500
   reached, final val MSE < 0.000847, 10 checkpoints in `checkpoints/`, no OOM,
   45-class assert line present.

---

## Prior next step (2026-08-11, superseded by 03b for the VAE stage)

Laptop-side work for today is done. At the college system: run notebook 03
cell 5 (now works correctly — CLI-arg-wiring bug fixed, so `vae_batch=4096`/
`vae_epochs=500` and `diff_batch=4096`/`diff_epochs=2000` will actually take
effect) or invoke `tabsyn/main.py --method vae`/`--method tabsyn --mode train`
directly. Before a real run there: worth a quick check that diffusion
(`tabsyn/tabsyn/main.py`) doesn't have its own unbatched-eval-OOM issue like
VAE did (untested — see STATUS.md pipeline table). The 1.8GB `train_z.npy` /
`model.pt` / `encoder.pt` / `decoder.pt` at
`tabsyn/tabsyn/vae/ckpt/honeypot_sessions/` right now are from the 3-epoch
laptop *test* run only — not a real trained model, will be overwritten by the
actual college run, safe to delete for disk space if wanted.

## Known gaps (not bugs, just not done yet)

- 23/45 micro-states have zero real-data coverage (expected — real traffic doesn't
  naturally produce every APT technique). These need TabSyn/GReaT synthetic coverage.
  Full list in SCHEMA.md.
- `EVENT_MAP` dead code in notebook 01 (cowrie.direct-tcpip.request events silently
  ignored) — not fixed, low priority since LATERAL_SSH_SPREAD is still reachable via
  UNSW's Worms category. See ERRORS.md.
