# Session Notes

## Notebook 02 — Feature Extraction (Validated)

`data/processed/X_real.npy` (717,810 x 128) and `y_real.npy` (717,810,) pass all 6 quality checks:

1. Shape match between X and y
2. No NaN/Inf values
3. Label range within 0-44 (45 micro-states)
4. All 6 feature groups populated (non-zero variance)
5. Semantic features (Group D) have meaningful variance after DistilBERT+PCA refit
6. Value range — PASS after bytes_out outlier investigation (col 25, 173/717k rows >1M; acceptable)

Sources: CIC-IDS2017 (555,466) + UNSW-NB15 (162,344) = 717,810 sessions covering 10/45 classes.

## TabSyn Training Plan

### Phase 1: VAE (overnight)

| Parameter         | Value   |
|-------------------|---------|
| batch_size        | 512     |
| epochs            | 500     |
| estimated time    | ~1.9 min/epoch x 500 = ~16 hours |
| checkpoint freq   | every 50 epochs to `data/synthetic/tabsyn_checkpoints/` |
| loss log          | every epoch to `data/synthetic/tabsyn_status.txt` |
| auto-diffusion    | NO — stop after VAE completes |

**Why 500 epochs (do not reduce):**
- 50-epoch diagnostic confirmed loss still actively decreasing at epoch 49 (val MSE = 0.000847)
- Beta annealing schedule has 3 decay cycles (0.01 -> 0.007 -> 0.0049)
- Only 2 decay cycles visible in 50 epochs — 500 needed to capture all decay-driven improvements
- Cutting to 300 would likely catch the model mid-decay cycle

### Phase 2: Diffusion (next night, after manual VAE review)

| Parameter         | Value   |
|-------------------|---------|
| batch_size        | 4096    |
| epochs            | 2000    |
| estimated time    | ~17 sec/epoch x 2000 = ~9.4 hours |
| early stopping    | patience 500 epochs |

Starts only after reviewing the VAE 500-epoch loss curve and confirming convergence.

### Data Location

TabSyn-formatted data is prepped at `tabsyn/data/honeypot_sessions/` (train/test CSVs, X_num/X_cat npy files, info.json).

## Pending

- **NVD/KEV pipeline fix:** Threat intel extractor (`honeypot_dataset/src/extractors/threat_intel.py`) live API calls need error handling / caching improvements. Not yet started.
