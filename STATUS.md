# STATUS

Shared reference — **committed**, machine-tagged. Update at the end of every
session: what's done, what's running, what's next. Keep it short — this is a
snapshot, not a log (that's DECISIONS.md / ERRORS.md).

---

## Last updated: 2026-09-01 (session 3, ASUS TUF)

### Session 3 summary (2026-08-28 → 2026-09-01) — DATASET FROZEN, BOTH MODELS TRAINED

The pipeline is finished and the review comparison is done. Nothing in
`data/final/` may be regenerated — both models are trained on those exact rows.

**Dataset — HoneySynth-960k, frozen 2026-08-27.** TabSyn sampling (720k) completed,
notebook 05 assembled real+TabSyn (GReaT-optional path), splits written to
`honeypot_dataset/data/final/`: 756,000 train / 84,000 val / 60,000 `test_real` /
60,000 `test_synth`; 128 features; 45 classes in train/val/test_synth, **21** in
`test_real`. Train imbalance 28.7x (6,055 → 173,722 per class).

**PROVENANCE CORRECTION (2026-08-28)** — see DECISIONS.md. The 15,000 Cowrie
sessions are **synthetic** (teammate-confirmed), not real. Genuinely real data is
**CIC-IDS2017 + UNSW-NB15 only**, anchoring **13 of 45** classes, all network-flow.
Real class coverage 22 → 13. The 22-class figure in the session-1 table below is
superseded; it is a count of *labelled* classes, not real-anchored ones.

**MT3 pipeline built** (`ml_analytics/mt3_pipeline/`, `0178f58`): data loading with
scaler-provenance checks, class-weighted/focal loss, metrics, train/eval/compare
CLIs, `make_pilot.py`, and a 10-step smoke test. `models/mt3.py` untouched.

**Two dataset traps found and logged in ERRORS.md (top two entries).** Both corrupt
silently, neither crashes: (1) the `data/final/` arrays are ALREADY SCALED —
notebook 05 saved `scaler.transform(X)`, so re-transforming shifts column means
0.002 → 4.8; (2) `feature_scaler.pkl` is a **joblib** dump, `pickle.load` raises.
`data.check_scaling()` now refuses to train if the arrays stop looking pre-scaled.

**Models — all on the identical frozen splits, macro-F1 over the 21 classes present
in `test_real`:**

| model | params | val macro-F1 | test_real | test_real (clean) | test_synth |
|---|---|---|---|---|---|
| linear probe (128→45) | 5,805 | 0.9376 | 0.7681 | — | 0.9373 |
| CNN-LSTM baseline | 189,581 | 0.9621 | 0.8093 | **0.7976** | 0.9610 |
| MT3 (d=256, 4 layers) | 3,759,510 | 0.9599 | 0.8276 | **0.8187** | 0.9589 |

MT3 ran on the ASUS (RTX 3050 4GB, bf16 AMP, batch 1024, `--cache-on-device`):
~40 s/epoch, early-stopped at epoch 35, best epoch 29. CNN-LSTM ran on Colab
(~7 s/epoch, early stop epoch 67, best epoch 52).

**Headline result: on `test_real` the two models TIE** — McNemar p = 0.617 (clean),
p = 0.569 (contaminated). MT3's Transformer fusion does not beat concatenation +
MLP at 20x the parameters. The CNN-LSTM wins `test_synth` significantly
(p = 0.00064) and edges MT3 on val macro-F1. Because the baseline deliberately
reuses MT3's branch encoders, this is a clean ablation of the fusion step.
A 5,805-parameter linear probe at 0.7681 is the floor any result must clear.

**TRAIN/TEST CONTAMINATION — quote the clean column.** 17,843 of the 60,000
`test_real` rows (**29.74%**) are byte-identical to rows in `X_train` with the same
label; another 20.11% duplicate `X_val`. Cause: notebook 05's `train_test_split` is
disjoint **by index, not by value**, and real CIC/UNSW flows genuinely repeat. Clean
subset = **41,785** rows, all 21 classes survive; mask at
`test_real_clean_mask.npz` (local, gitignored). `test_synth` unaffected (0.00%).
Worst class: EXEC_SHELL_OPEN, 94.7% duplicated, F1 ~0.99 → ~0.82 once cleaned.
Both models score ~1.0 on the leaked rows, so the *gap* barely moves (+0.0183 →
+0.0210) — but the absolute numbers are inflated and must not be reported as-is.

**Architecture audit — MT3 has no CRF.** No `CRF`/`viterbi`/transition matrix in
`mt3.py`; the "hp_logits" head is a 9-way phase auxiliary, and `KILL_CHAIN_DAG`
never enters training. Measured 2026-09-01: on `test_synth` all three models' errors
are at or **below** chance for DAG legality (0.380 / 0.391 / 0.357 vs 0.412 chance)
— no model has learned kill-chain structure. Adding a real CRF needs per-event
features `data/final/` does not carry. Deferred, not hidden.

**CNN-LSTM branch merged** into `main` (`8087d26`, local — review before pushing).
`SESSION_CONTEXT.md` excluded from the merge and gitignored (stale 2026-08-21
working doc; same rule as ASUS.md / HARDWARE.md / SETUP.md).

**Next:** teammate to confirm the clean 0.7976 independently; report clean numbers
in the paper with the 29.74% disclosed; post-review, rebuild the split
deduplicated-by-value. GReaT (04) still deferred.

---

## Session 2: 2026-08-25 (ASUS TUF)

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

**Update (2026-08-25 ~21:52): VAE training is now RUNNING LOCALLY on the ASUS.**
The Colab run crashed at ~5h/epoch 111 (checkpoint saved at epoch 100 only). Because
TabSyn's checkpoints were weights-only (no beta/optimizer state), that run could not
be cleanly resumed — the beta-annealing schedule that drove the loss down was lost.
Decision (user's call): run a FRESH VAE on the ASUS laptop itself (secondary to DGX,
which wasn't reachable). Before launching, added full-state crash-safe checkpoint/
resume to `vae/main.py` (model+optimizer+scheduler+beta+patience+epoch), validated
by a 2→4 epoch resume test, and folded into `patches/tabsyn-colab.patch`.

- Data: prepared the 45-class merged set LOCALLY (same seeds as Colab): 1,387,698
  train / 154,189 test rows at `tabsyn/data/honeypot_sessions/`. `category_embeddings`
  is `[45, 4]` (confirmed 45-class, not the old `[22, 4]`).
- Run: `main.py --method vae --epochs 500 --training_batch_size 512`, detached
  (PID in `tabsyn/vae_run_local/train.pid`), logging to
  `tabsyn/vae_run_local/status.txt`, checkpoints (every 50 + `resume_state.pt` every
  epoch) in `tabsyn/vae_run_local/checkpoints/`.
- Measured: **215.9 s/epoch** at batch 512 (no OOM) → ~30h for 500 epochs. At batch
  512 there are 2711 steps/epoch (vs Colab's 339 at 4096), so it optimizes ~8x faster
  per epoch — epoch 1 val_mse 0.006 already beats Colab's epoch-1 0.036. Likely hits
  the 0.000847 target well before epoch 500.
- If interrupted: just relaunch the same command — it auto-resumes from
  `resume_state.pt`. Does NOT auto-start diffusion.

**Update (2026-08-26 02:47): VAE training COMPLETE — target met, auto-stopped.**
Early-stopped at epoch 79/500 (val_mse 0.000807 <= target 0.000847 for 3
consecutive epochs; best val_mse 0.000722 at epoch 77). beta annealed
0.010 -> 0.007 -> 0.0049 -> 0.00343. ~5h wall on ASUS at batch 512 (vs ~30h for a
full 500). Process exited clean. Final artifacts saved to
`tabsyn/tabsyn/vae/ckpt/honeypot_sessions/`: model.pt, encoder.pt, decoder.pt,
train_z.npy (2.8GB). Periodic/resume checkpoints in `tabsyn/vae_run_local/`
(model_epoch0050.pt, resume_state.pt) + full per-epoch log in
`vae_run_local/status.txt`. Diffusion was NOT started (by design).

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
| 03_tabsyn_generation (VAE, real run) | ✅ DONE (2026-08-26, ASUS) | 45-class VAE early-stopped at epoch 79, val_mse 0.000807 (< 0.000847 target). Artifacts at `tabsyn/tabsyn/vae/ckpt/honeypot_sessions/`. See the 2026-08-26 update below. |
| 03_tabsyn_generation (diffusion) | ✅ DONE (2026-08-27, ASUS) | Completed full 2000/2000 epochs, best_loss 0.042314. Run 1 collapsed at epoch 63 (unclipped lr=1e-3) → added gradient clipping, restarted; run 2 stable start to finish. Survived 3 accidental laptop sleeps via the crash-safe resume. `model.pt` at `tabsyn/tabsyn/ckpt/honeypot_sessions/`. Next: SAMPLING. |
| 03 sampling (720k) | ✅ DONE (2026-08-27, ASUS) | 720,000 synthetic rows sampled; batching (`TABSYN_SAMPLE_BATCH`/`TABSYN_N_SAMPLE`) kept it inside the 4GB card. Fed straight into notebook 05. |
| 04_great_generation | ⏸️ DEFERRED (review-freeze) | Skipped for the 2-day review; add later only if time. Runs on DGX (GB10), ~6-7h. See DECISIONS.md 2026-08-27. |
| 05_assembly_validation | ✅ DONE (2026-08-27) | Made **GReaT-optional** (cells 3/5/7 auto-detect `X_great.npy`; assemble real+TabSyn when absent). Output: HoneySynth-960k in `data/final/`. **Known defect: splits are disjoint by index, not by value → 29.74% of `test_real` duplicates `X_train`.** See session 3. |
| CNN-LSTM baseline | ✅ DONE (2026-08-31, Colab) | 189,581 params, val macro-F1 0.9621, test_real 0.7976 clean. Teammate deliverable, merged `8087d26`. |
| MT3 | ✅ DONE (2026-08-30, ASUS) | d=256/4 layers, 3,759,510 params, val macro-F1 0.9599, test_real 0.8187 clean. Ties the baseline (p=0.617). |

## Environment

- venv at `honeypot_dataset/venv/` has torch `2.13.0+cu126` (CUDA-enabled, verified working — see HARDWARE.md). System Python 3.14 does NOT have the project deps; always use the venv interpreter.
- Raw data present: Cowrie (`data/raw/cowrie_logs/cowrie.json`, 15,000 sessions), CIC-IDS2017 (8/8 CSVs), UNSW-NB15 (both files).

## Review plan (2026-08-27, ~2-day deadline)

Freeze dataset at **real + TabSyn** (skip GReaT); train CNN-LSTM baseline + MT3 on
the **DGX (GB10)** and compare. Steps: diffusion finishes → TabSyn sampling (720k)
→ notebook 05 (real+TabSyn, GReaT-optional) → transfer frozen dataset to DGX →
train both models. Fallback if TabSyn fails: real-only `X_real.npy` (22 classes),
already on disk. GReaT deferred. See DECISIONS.md 2026-08-27. **MT3 is unwritten =
the real critical path** — do not block on GReaT.

## Superseded: immediate next step as of 2026-08-25 (Colab VAE run — done, see session 3)

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
