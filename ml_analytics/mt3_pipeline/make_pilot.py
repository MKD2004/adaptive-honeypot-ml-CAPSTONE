"""
Build a smaller PILOT dataset from the frozen HoneySynth splits.

Purpose: run MT3 and the CNN-LSTM baseline end-to-end on ~200k sessions before
committing to the full 756k train split -- a preliminary experiment that fits on
a laptop GPU, and a self-contained package teammates can train the baseline on.

What it does NOT do: it never regenerates, re-splits, re-scales or re-labels
anything. It only SUBSAMPLES rows that notebook 05 already produced, and copies
the scaler and both test splits through untouched.

Design
------
train  class-BALANCED subsample of data/final/X_train.npy.
       The rarest of the 45 micro-states has 6,055 train rows, so 200,000 / 45
       = 4,444 per class is reachable WITHOUT replacement -- no duplicated rows,
       no class dominating. (The full train split is 28.7x imbalanced.)
val    class-balanced subsample of data/final/X_val.npy, 500 per class
       (rarest val class has 673 rows), = 22,500.
test   data/final/X_test_real.npy and X_test_synth.npy are copied UNCHANGED,
       same rows in the same order. That is deliberate: the headline metric
       stays comparable between the pilot, the eventual full run, and the
       CNN-LSTM baseline, all scored on identical rows.
scaler feature_scaler.pkl copied byte-for-byte. The arrays are ALREADY scaled by
       it (see data.py) -- do not apply it again.

Output file names mirror data/final/ exactly, so the trainers need no changes:

    python -m ml_analytics.mt3_pipeline.train_mt3 \
        --data-dir ml_analytics/data/pilot_200k ...

Usage:
    python -m ml_analytics.mt3_pipeline.make_pilot                # 200k, seed 42
    python -m ml_analytics.mt3_pipeline.make_pilot --zip          # + shareable zip
    python -m ml_analytics.mt3_pipeline.make_pilot --n 100000 --scheme proportional
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Sequence

import numpy as np

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    __package__ = "ml_analytics.mt3_pipeline"

from .data import DEFAULT_DATA_DIR, N_CLASSES, REPO_ROOT, load_label_names  # noqa: E402

DEFAULT_OUT_DIR = REPO_ROOT / "ml_analytics" / "data" / "pilot_200k"
SCHEMES = ("balanced", "proportional", "sqrt")


def allocate(counts: np.ndarray, total: int, scheme: str) -> np.ndarray:
    """How many rows to draw from each class, capped by availability.

    balanced      uniform across present classes
    proportional  keeps the original class prior
    sqrt          tempered -- between the two

    Shortfall from classes that cannot supply their quota is redistributed to
    classes that still have spare rows, so the total is met exactly when possible.
    """
    present = counts > 0
    k = int(present.sum())
    if scheme == "balanced":
        weight = present.astype(np.float64)
    elif scheme == "proportional":
        weight = counts.astype(np.float64)
    elif scheme == "sqrt":
        weight = np.sqrt(counts.astype(np.float64))
    else:
        raise ValueError(f"unknown scheme {scheme!r}, expected {SCHEMES}")
    weight = weight / weight.sum()

    take = np.floor(weight * total).astype(np.int64)
    take = np.minimum(take, counts)

    # largest-remainder top-up, then redistribute any shortfall
    for _ in range(1000):
        deficit = total - int(take.sum())
        if deficit <= 0:
            break
        spare = counts - take
        eligible = np.flatnonzero(spare > 0)
        if eligible.size == 0:
            break
        # hand out one row at a time to the classes furthest below their quota
        order = eligible[np.argsort(-spare[eligible])]
        for c in order[:deficit]:
            take[c] += 1

    if int(take.sum()) != total:
        print(f"[pilot] note: requested {total:,} rows, {int(take.sum()):,} available "
              f"under scheme={scheme} across {k} classes")
    return take


def subsample(y: np.ndarray, total: int, scheme: str, seed: int) -> np.ndarray:
    """Row indices for a class-controlled subsample, sorted (cheap fancy-indexing)."""
    counts = np.bincount(y, minlength=N_CLASSES)
    take = allocate(counts, total, scheme)
    rng = np.random.default_rng(seed)
    keep: List[np.ndarray] = []
    for c in range(N_CLASSES):
        if take[c] == 0:
            continue
        pool = np.flatnonzero(y == c)
        keep.append(rng.choice(pool, size=int(take[c]), replace=False))
    idx = np.concatenate(keep)
    rng.shuffle(idx)          # break class ordering
    return np.sort(idx)       # then sort for fast row gather


def sha256(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        while True:
            b = fh.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def build(
    src: Path = DEFAULT_DATA_DIR,
    out: Path = DEFAULT_OUT_DIR,
    n_train: int = 200_000,
    val_per_class: int = 500,
    scheme: str = "balanced",
    seed: int = 42,
    copy_tests: bool = True,
    make_zip: bool = False,
) -> Dict[str, object]:
    src, out = Path(src), Path(out)
    if not (src / "X_train.npy").exists():
        raise SystemExit(f"[pilot] {src}/X_train.npy not found -- unzip honeysynth_final.zip there")
    out.mkdir(parents=True, exist_ok=True)
    labels = load_label_names()

    manifest: Dict[str, object] = {
        "name": f"HoneySynth pilot ({n_train // 1000}k)",
        "pilot": True,
        "source": str(src),
        "built_from": "notebook 05 frozen splits -- SUBSAMPLED only, never regenerated",
        "scheme": scheme,
        "seed": seed,
        "already_scaled": True,
        "scaler": "feature_scaler.pkl (joblib) -- the splits are ALREADY transformed by it; "
                  "load it, never re-fit it, never re-apply it to these arrays",
        "splits": {},
    }

    # ---- train / val: subsampled ------------------------------------------ #
    for split, total in (("train", n_train), ("val", val_per_class * N_CLASSES)):
        y = np.load(src / f"y_{split}.npy")
        idx = subsample(y, total, scheme, seed)
        X = np.load(src / f"X_{split}.npy", mmap_mode="r")
        Xs = np.ascontiguousarray(X[idx])
        ys = y[idx]
        np.save(out / f"X_{split}.npy", Xs)
        np.save(out / f"y_{split}.npy", ys)
        c = np.bincount(ys, minlength=N_CLASSES)
        present = c > 0
        manifest["splits"][split] = {
            "rows": int(len(ys)),
            "classes": int(present.sum()),
            "per_class_min": int(c[present].min()),
            "per_class_max": int(c.max()),
            "imbalance_ratio": round(float(c.max() / c[present].min()), 3),
            "subsampled_from": int(len(y)),
        }
        print(f"[pilot] {split:5s} {len(ys):>7,} rows  {int(present.sum())}/45 classes  "
              f"per-class {c[present].min():,}-{c.max():,}  "
              f"(imbalance {c.max() / c[present].min():.2f}x)")

    # ---- test splits: copied unchanged ------------------------------------ #
    if copy_tests:
        for split in ("test_real", "test_synth"):
            for pre in ("X", "y"):
                shutil.copy2(src / f"{pre}_{split}.npy", out / f"{pre}_{split}.npy")
            y = np.load(out / f"y_{split}.npy")
            c = np.bincount(y, minlength=N_CLASSES)
            manifest["splits"][split] = {
                "rows": int(len(y)),
                "classes": int((c > 0).sum()),
                "per_class_min": int(c[c > 0].min()),
                "per_class_max": int(c.max()),
                "copied_unchanged": True,
            }
            print(f"[pilot] {split:11s} {len(y):>6,} rows  {(c > 0).sum()}/45 classes  "
                  f"(copied UNCHANGED -- identical rows for every model)")

    shutil.copy2(src / "feature_scaler.pkl", out / "feature_scaler.pkl")

    # ---- class table ------------------------------------------------------- #
    ytr = np.load(out / "y_train.npy")
    ctr = np.bincount(ytr, minlength=N_CLASSES)
    manifest["per_class_train"] = {labels[i]: int(ctr[i]) for i in range(N_CLASSES)}

    files = sorted(p for p in out.iterdir() if p.suffix in (".npy", ".pkl"))
    manifest["files"] = {
        p.name: {"bytes": p.stat().st_size, "sha256": sha256(p)[:16]} for p in files
    }
    total_bytes = sum(p.stat().st_size for p in files)
    manifest["total_bytes"] = total_bytes

    (out / "manifest.json").write_text(json.dumps(manifest, indent=2))
    _write_readme(out, manifest, n_train, val_per_class, scheme, seed)
    print(f"[pilot] wrote {len(files)} arrays ({total_bytes / 1e6:.0f} MB) to {out}")

    if make_zip:
        zpath = out.parent / f"honeysynth_pilot_{n_train // 1000}k.zip"
        with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
            for p in sorted(out.iterdir()):
                if p.is_file():
                    z.write(p, p.name)
        print(f"[pilot] zipped -> {zpath} ({zpath.stat().st_size / 1e6:.0f} MB)")
        manifest["zip"] = str(zpath)

    return manifest


def _write_readme(out: Path, manifest, n_train, val_per_class, scheme, seed) -> None:
    s = manifest["splits"]
    tr, va = s["train"], s["val"]
    rows = "\n".join(
        f"| `X_{k}.npy` / `y_{k}.npy` | {v['rows']:,} | {v['classes']} | "
        f"{'copied unchanged' if v.get('copied_unchanged') else f'{scheme} subsample'} |"
        for k, v in s.items()
    )
    (out / "README.md").write_text(f"""# HoneySynth pilot ({n_train // 1000}k)

Preliminary/pilot subset of the frozen HoneySynth dataset, for running MT3 and
the CNN-LSTM baseline end-to-end before committing to the full 756k train split.

**Nothing here was regenerated.** These are rows notebook 05 already produced,
subsampled with seed {seed}. Rebuild it byte-identically with:

```
python -m ml_analytics.mt3_pipeline.make_pilot --n {n_train} \\
    --val-per-class {val_per_class} --scheme {scheme} --seed {seed}
```

| file | rows | classes | how |
|---|---|---|---|
{rows}

## Two rules (same as `data/final/`)

1. **These arrays are ALREADY SCALED.** `feature_scaler.pkl` is the scaler that
   produced them (notebook 05 saves `scaler.transform(X)`). Load it for
   provenance / for raw sessions at inference, but **never call
   `scaler.transform()` on these files** -- it double-scales and silently
   corrupts the input. See `ERRORS.md`.
2. **`feature_scaler.pkl` is a joblib dump.** `pickle.load()` raises
   `invalid load key`; use `joblib.load()`.

## Train split is class-BALANCED

{tr['per_class_min']:,}-{tr['per_class_max']:,} rows per class ({tr['imbalance_ratio']}x), drawn without
replacement from the full train split (which is 28.7x imbalanced). No duplicated
rows. Val is balanced the same way ({val_per_class}/class).

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
python -m ml_analytics.mt3_pipeline.train_mt3 \\
    --data-dir ml_analytics/data/pilot_200k \\
    --out-dir  ml_analytics/artifacts/mt3_pilot
```

Report macro-F1 on `X_test_real` (headline) and `X_test_synth`, and **save
predictions** so MT3 and CNN-LSTM can be compared on identical rows:
`ml_analytics/mt3_pipeline/compare.py` expects
`preds_test_real.npz` / `preds_test_synth.npz` with `y_true`, `y_pred`.
""")


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Build a pilot subset of the frozen dataset")
    p.add_argument("--src", type=Path, default=DEFAULT_DATA_DIR)
    p.add_argument("--out", type=Path, default=DEFAULT_OUT_DIR)
    p.add_argument("--n", type=int, default=200_000, help="train rows")
    p.add_argument("--val-per-class", type=int, default=500)
    p.add_argument("--scheme", choices=SCHEMES, default="balanced")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--no-tests", action="store_true", help="skip copying the test splits")
    p.add_argument("--zip", action="store_true", help="also write a shareable zip")
    a = p.parse_args(argv)
    build(a.src, a.out, a.n, a.val_per_class, a.scheme, a.seed,
          copy_tests=not a.no_tests, make_zip=a.zip)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
