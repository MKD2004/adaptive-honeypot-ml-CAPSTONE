# mt3_pipeline — MT3 training + evaluation

Owner: Mahith. MT3 is **not** a teammate deliverable (`TEAMMATES.md` rule 3).
The architecture in `ml_analytics/models/mt3.py` is **read-only** here — this
package is only the train/eval loop, loss weighting, checkpointing, metrics, and
the baseline-vs-MT3 comparison.

```
data.py        frozen-split loading, scaler provenance checks, batching
losses.py      class-weighted CE / focal + the phase-auxiliary objective
metrics.py     macro-F1 (primary), per-class F1, accuracy, confusion matrix
train_mt3.py   training CLI  (checkpoint, early stop, auto-eval)
evaluate.py    checkpoint -> predictions + metrics on the frozen test splits
compare.py     baseline-vs-MT3 table on identical test rows
smoke_test.py  10-step end-to-end self-check
run_dgx.sh     detached tmux launcher for the DGX (GB10)
```

Artifacts land in `ml_analytics/artifacts/mt3/` (git-ignored).

---

## Quick start

```bash
git pull origin main
# data/final/ is git-ignored: unzip honeysynth_final.zip there first (DGX.md)

python -m ml_analytics.mt3_pipeline.smoke_test          # ~30s, verifies everything
./ml_analytics/mt3_pipeline/run_dgx.sh                  # real run, detached (DGX)

python -m ml_analytics.mt3_pipeline.compare \
    --mt3-dir ml_analytics/artifacts/mt3 \
    --baseline-dir ml_analytics/artifacts/cnn_lstm
```

On Windows use the venv interpreter explicitly:
`honeypot_dataset/venv/Scripts/python.exe -m ml_analytics.mt3_pipeline.smoke_test`

---

## Two dataset facts that are easy to get wrong

**1. `feature_scaler.pkl` is a joblib dump, not a plain pickle.**
`pickle.load()` on it raises `UnpicklingError: invalid load key, '\x0a'` — the
file carries joblib's `NDArrayWrapper` sub-pickles. Use `joblib.load`, or
`data.load_scaler()`.

**2. The arrays in `data/final/` are ALREADY SCALED — do not transform them again.**
Notebook 05 fits the scaler on raw `X_train`, saves `X_train_s = scaler.transform(X_train)`
as `X_train.npy`, and dumps the fitted scaler next to it. Empirically:
`X_train` column means average `0.0018` while `scaler.mean_` averages `137`.
Calling `scaler.transform()` on the frozen splits shifts the column means to
`~4.8` and destroys the data.

So "load this exact scaler, do NOT re-fit" is satisfied by:
* loading it (`data.load_scaler`) and recording it in every checkpoint's provenance,
* using it for **raw** sessions at inference time (`data.transform_raw`),
* **not** re-applying it to the frozen splits.

`data.check_scaling()` asserts this at every load and refuses to train if the
arrays ever stop looking pre-scaled. `smoke_test` step 3 additionally proves that
re-applying the scaler *would* corrupt the data, so a regression is loud.

---

## The loss: why it is not `MT3.forward`'s built-in one

`MT3.forward(x, labels)` returns

```
loss = CE(emissions, labels) + aux_loss_weight * CE(hp_logits, phase(labels))
```

which is **unweighted**. The train split runs 6,055 → 173,722 samples per class
(≈29×) and the headline metric is macro-F1, so the trainer calls `forward(x)`
**without** labels and rebuilds the same two-term objective in `losses.py` with a
weighted / focal state term. The 9-way phase target is still derived from the
45-way label using the model's own `idx_to_phase` buffer — nothing about the
architecture changes.

`--loss ce` reproduces `MT3.forward`'s loss exactly; `smoke_test` step 5 asserts
the two agree to 1e-6.

| flag | effect |
|---|---|
| `--loss weighted_ce` (default) | CE with per-class weights |
| `--loss focal --focal-gamma 1.5` | focal loss, optionally class-weighted |
| `--loss ce` | plain CE — matches the model's built-in loss |
| `--class-weight balanced\|inv_sqrt\|effective\|none` | weighting scheme (default `balanced`) |

---

## Evaluation protocol (must match the CNN-LSTM baseline)

From `ml_analytics/README.md`, enforced in code:

1. **Same splits** — `data/final/` as-is, never re-split.
2. **Same scaler** — loaded, never re-fit (see above).
3. **Headline = `X_test_real`** (60k, **21** classes present); `X_test_synth`
   (60k, 45 classes) reported alongside.
4. **Same metrics** — macro-F1 primary, plus per-class F1, accuracy, confusion matrix.
5. **Predictions saved** — `preds_test_real.npz` / `preds_test_synth.npz` hold
   `y_true`, `y_pred`, `phase_pred`, `y_prob`, so both models are scored on
   identical rows. `compare.py` aborts if the two `y_true` arrays differ.

### Two macro-F1 numbers, and which one to quote

`X_test_real` contains only 21 of the 45 micro-states. Averaging F1 over all 45
would divide by 45 and penalise every model for 24 classes the split never asks
about. So the pipeline reports both:

* **`macro_f1`** — averaged over the classes present in `y_true`. **Quote this.**
* `macro_f1_all45` — averaged over all 45 (absent classes contribute 0).

Both models must quote the same one; `compare.py` prints both side by side.

Also reported: balanced accuracy, weighted-F1, and a 9-way **kill-chain phase**
macro-F1 derived from the micro-state predictions (MT3's auxiliary head is
evaluated on its own terms too).

---

## Baseline comparison

`compare.py` reads both models' prediction files, verifies row identity, and
prints the headline table, per-class F1 deltas, and **McNemar's test** on the
discordant predictions (so an accuracy gap is reported with a p-value rather
than asserted).

The CNN-LSTM baseline is a teammate deliverable and
`ml_analytics/models/cnn_lstm.py` is still **empty on `main`**. Until it lands,
`compare.py` runs with the MT3 column alone and prints an explicit "no
comparison is being claimed" note — it never fabricates a baseline row.

To slot the baseline in, have it write the same npz format to
`ml_analytics/artifacts/cnn_lstm/preds_test_{real,synth}.npz`:

```python
np.savez_compressed(path, y_true=y_true, y_pred=y_pred,
                    phase_pred=phase_pred, model=np.array("cnn_lstm"),
                    split=np.array("test_real"))
```

or simply reuse `evaluate.evaluate_split()`.

---

## Checkpoints

`best.pt` (best val macro-F1) and `last.pt` (every epoch, atomic write) carry
**full state** — model, optimizer, scheduler, AMP scaler, epoch, history, RNG
state, config, and the scaler-provenance record. `--resume` continues from
`last.pt` at the next epoch.

Full state rather than weights-only is deliberate: `DECISIONS.md` (2026-08-25)
records a ~5h run lost because only weights had been saved and the LR/β schedule
could not be restored.

---

## Run on the DGX, not the laptop

`run_dgx.sh` launches under `tmux` (falls back to `nohup`), tees to
`artifacts/mt3/train.log`, refuses to start if `data/final/` is missing or the
tmux session already exists, and prints current GPU usage first (shared machine —
`DGX.md` etiquette). Tunables via env: `EPOCHS`, `BATCH_SIZE`, `LR`, `LOSS`,
`CLASS_WEIGHT`, `SEED`, `OUT_DIR`, `PY`, `EXTRA`.

`--cache-on-device` parks the whole train split in GPU memory (~390 MB for 756k
rows) and removes the host→device copy from the step loop. Safe on the GB10;
leave it off on a 4 GB laptop.

---

## Smoke test

`python -m ml_analytics.mt3_pipeline.smoke_test [--fast] [--keep]`

| # | check |
|---|---|
| 1 | `mt3.py` constants == `schema.py` (groups tile 0..127, phase map, sizes) |
| 2 | dataset files, shapes, dtypes, label range, finiteness, class counts |
| 3 | scaler joblib-loads; splits are pre-scaled; re-applying it *would* corrupt |
| 4 | forward/backward shapes, finiteness, eval-mode determinism, shape guard |
| 5 | `MT3Objective(--loss ce)` == `MT3.forward`'s built-in loss to 1e-6 |
| 6 | class weights finite, mean 1, zero for absent classes, rare ≥ common |
| 7 | the model can overfit a single 64-row batch (wiring sanity) |
| 8 | train CLI: checkpoints, history, provenance flags, `--resume` continuity |
| 9 | evaluate CLI: saved `y_true` matches disk, probs sum to 1, metrics well-formed |
| 10 | compare CLI: MT3-only path, 2-model path, and abort on mismatched rows |
