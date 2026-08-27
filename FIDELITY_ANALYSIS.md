# FIDELITY ANALYSIS — HoneySynth (real + TabSyn)

Shared reference for the write-up. Records why the synthetic data's adversarial
AUC is ~0.998, where the fingerprint comes from, and why it does not hurt
downstream utility. Dated 2026-08-28 (ASUS). Related: `DECISIONS.md` (2026-08-28
provenance correction), dataset in `honeypot_dataset/data/final/`.

---

## TL;DR

- Adversarial AUC ≈ **0.998** (real vs TabSyn) is a **genuine generator
  fingerprint**, confirmed by a calibration control (real-vs-real = 0.50).
- It is **not** caused by the synthetic-Cowrie contamination — CIC/UNSW-only gives
  the same ~0.998.
- The fingerprint is stamped at **both the VAE and the diffusion stage** (each in
  isolation gives AUC ≈ 1.0), VAE-first.
- It lives in **fine joint structure**, not marginals or class-discriminative
  structure — so downstream utility is strong: **TSTR macro-F1 0.99** on real
  network-flow classes. **Distinguishable ≠ not useful.**

## Methodology

- **Adversarial AUC**: XGBoost (200 trees, depth 5) trained to tell real from
  synthetic on the 128 features (or 516-d latents); AUC on a 30% holdout. 0.5 =
  indistinguishable, 1.0 = trivially separable.
- **TSTR** (Train-on-Synthetic, Test-on-Real): RandomForest trained on synthetic,
  evaluated on real; macro / weighted / per-class F1.
- Row alignment between `X_real.npy` and `real_sessions_combined.parquet` (for the
  `source` split) was verified (`y_real == parquet-derived labels`: True).

## Results

### Adversarial AUC — calibration controls first
| Comparison | AUC |
|---|---|
| **Control:** real vs real (X_real, disjoint halves) | **0.5000** |
| **Control:** real CIC/UNSW vs real CIC/UNSW | **0.5021** |
| real (22-cls) vs TabSyn (45-cls) | 0.998 |
| real (22 shared cls) vs TabSyn (same 22) | 0.9976 |
| real CIC/UNSW only vs TabSyn (same 13 cls) | 0.9979 |

The controls returning 0.50 prove the metric is **calibrated** — the ~0.998 values
are real signal, not a high-dimensional artifact.

### Stage attribution
| Stage test | AUC | Reading |
|---|---|---|
| Diffusion latents vs real latents (`train_z`) | **1.0** | diffusion latents distinguishable from real latents |
| VAE round-trip: decode(encode(real)) vs real | **1.0** | the VAE alone makes real data detectable, before diffusion |

Both stages contribute; the VAE round-trip is already 1.0, so the **VAE decoder is a
primary source** and diffusion adds on top.

### The apparent paradox (and its resolution)
- Diffusion latents match real latents **on marginals almost perfectly**: overall
  std 0.269 vs 0.274; per-dim means differ by avg 0.003 (max 0.037); per-dim std
  0.181 vs 0.184. Yet AUC = 1.0.
- VAE reconstruction MSE is **0.0008** (tiny). Yet round-trip AUC = 1.0.

**Resolution:** the fingerprint is a *systematic* difference in joint/correlation
structure, not in the marginals or magnitudes. VAEs produce slightly-smoothed
reconstructions — minuscule error but consistent in direction, so a classifier
catches every sample; diffusion nails the marginals but its 516-d correlation
structure differs just enough to be caught. Neither shows up in per-feature stats.

### TSTR (downstream utility)
| Cut | classes | TSTR macro-F1 | TSTR weighted-F1 |
|---|---|---|---|
| Full real (22 cls) | 22 | 0.705 | 0.995 |
| **CIC/UNSW only (real)** | 13 | **0.9934** | 0.9998 |

The full-set macro-F1 (0.705) is dragged down entirely by rare Cowrie-derived
classes with 3–28 real test samples (statistically unreliable at that n, and those
classes are themselves synthetic — see provenance note). On the genuinely-real
network-flow classes, a synthetic-trained model classifies **real** attacks at
macro-F1 0.99, all 13 classes ≥ 0.97.

## Interpretation

The synthetic is **distributionally distinguishable but functionally faithful**.
The adversarial AUC measures "can a dedicated classifier find *any* systematic
difference" — and in high dimensions the answer is yes, for a subtle
pipeline-induced fingerprint. TSTR measures "does the synthetic teach the real task"
— and the answer is strongly yes. For training/augmentation (the actual use), TSTR
is the metric that matters.

## Sentence for the review / paper

> "Our synthetic data is distributionally distinguishable from real (adversarial AUC
> ≈ 0.998; the metric is calibrated — real-vs-real gives 0.50). The fingerprint is a
> systematic artifact of the VAE→diffusion pipeline, present already at the VAE
> reconstruction stage, and is unrelated to data source. Crucially it resides in
> fine joint structure rather than class-discriminative structure: downstream
> utility is strong (TSTR macro-F1 0.99 on real network-flow classes).
> Distinguishable ≠ not useful."

## Caveats / provenance
- The "real Cowrie" honeypot data is **synthetic** (teammate-confirmed); genuinely
  real = CIC-IDS2017 + UNSW-NB15 (13/45 classes). See `DECISIONS.md` 2026-08-28.
- Numbers use 15k-per-side subsamples (seeded); expect ±small variation on re-run.
