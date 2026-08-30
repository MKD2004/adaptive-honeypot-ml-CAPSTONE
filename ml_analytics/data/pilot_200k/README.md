# HoneySynth pilot (200k)

Preliminary/pilot subset of the frozen HoneySynth dataset, for running MT3 and
the CNN-LSTM baseline end-to-end before committing to the full 756k train split.

**Nothing here was regenerated.** These are rows notebook 05 already produced,
subsampled with seed 42. Rebuild it byte-identically with:

```
python -m ml_analytics.mt3_pipeline.make_pilot --n 200000 \
    --val-per-class 500 --scheme balanced --seed 42
```

| file | rows | classes | how |
|---|---|---|---|
| `X_train.npy` / `y_train.npy` | 200,000 | 45 | balanced subsample |
| `X_val.npy` / `y_val.npy` | 22,500 | 45 | balanced subsample |
| `X_test_real.npy` / `y_test_real.npy` | 60,000 | 21 | copied unchanged |
| `X_test_synth.npy` / `y_test_synth.npy` | 60,000 | 45 | copied unchanged |

## Two rules (same as `data/final/`)

1. **These arrays are ALREADY SCALED.** `feature_scaler.pkl` is the scaler that
   produced them (notebook 05 saves `scaler.transform(X)`). Load it for
   provenance / for raw sessions at inference, but **never call
   `scaler.transform()` on these files** -- it double-scales and silently
   corrupts the input. See `ERRORS.md`.
2. **`feature_scaler.pkl` is a joblib dump.** `pickle.load()` raises
   `invalid load key`; use `joblib.load()`.

## Train split is class-BALANCED

4,444-4,445 rows per class (1.0x), drawn without
replacement from the full train split (which is 28.7x imbalanced). No duplicated
rows. Val is balanced the same way (500/class).

Because train is balanced, `--class-weight balanced` is close to a no-op here --
that is expected. The class prior of train no longer matches the test splits, so
expect accuracy to read slightly lower and macro-F1 slightly higher than a
prior-matched run would.

## Test splits are the OFFICIAL ones, unchanged

`X_test_real` (60,000 rows, 21 classes -- **headline metric**) and
`X_test_synth` (60,000 rows, 45 classes) are byte-identical copies of
`data/final/`. Every model -- pilot MT3, pilot CNN-LSTM, and the eventual
full-scale runs -- is therefore scored on identical rows.

## Use it

Both trainers take `--data-dir`, so nothing else changes:

```
python -m ml_analytics.mt3_pipeline.train_mt3 \
    --data-dir ml_analytics/data/pilot_200k \
    --out-dir  ml_analytics/artifacts/mt3_pilot
```

Report macro-F1 on `X_test_real` (headline) and `X_test_synth`, and **save
predictions** so MT3 and CNN-LSTM can be compared on identical rows:
`ml_analytics/mt3_pipeline/compare.py` expects
`preds_test_real.npz` / `preds_test_synth.npz` with `y_true`, `y_pred`.
