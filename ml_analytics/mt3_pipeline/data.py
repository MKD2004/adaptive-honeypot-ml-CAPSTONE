"""
Frozen-dataset loading for MT3 training/eval.

HARD CONSTRAINTS (ml_analytics/README.md, DGX.md, MT3_PROMPT.md):
  * Train/evaluate on honeypot_dataset/data/final/ ONLY. Never regenerate it,
    never re-split it, never run a notebook.
  * Use the shipped feature_scaler.pkl; never fit a new scaler.

IMPORTANT -- the splits on disk are ALREADY SCALED.
    notebook 05 (cell 11) does:   scaler.fit(X_train)
                                  X_train_s = scaler.transform(X_train)
    and (cell 13) saves the *_s arrays as X_train.npy / X_val.npy / X_test_*.npy,
    then joblib-dumps the fitted scaler alongside them.
So feature_scaler.pkl is the scaler that PRODUCED these arrays. Applying it
again would double-scale the data. check_scaling() below verifies this
empirically at load time and refuses to guess. The scaler is still loaded (and
required to exist) because it is the object any *raw* session must pass through
at inference time, and because both models must agree on it.

Note: feature_scaler.pkl is a joblib dump, NOT a plain pickle -- pickle.load on
it raises UnpicklingError (invalid load key). Always joblib.load.
"""
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

import numpy as np

# repo root = .../adaptive-honeypot-ml-CAPSTONE
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATA_DIR = REPO_ROOT / "honeypot_dataset" / "data" / "final"

N_FEATURES = 128
N_CLASSES = 45
N_PHASES = 9

SPLITS = ("train", "val", "test_real", "test_synth")

_EXPECTED_ROWS = {
    "train": 756_000,
    "val": 84_000,
    "test_real": 60_000,
    "test_synth": 60_000,
}


class DataError(RuntimeError):
    """Raised when the frozen dataset is missing or fails an integrity check."""


# --------------------------------------------------------------------------- #
# label metadata
# --------------------------------------------------------------------------- #

# micro-state id -> kill-chain phase (0-8); mirrors schema.py IDX_TO_PHASE and
# ml_analytics/models/mt3.py DEFAULT_IDX_TO_PHASE (parity asserted in smoke_test).
IDX_TO_PHASE: List[int] = (
    [0] * 6 + [1] * 6 + [2] * 6 + [3] * 5 + [4] * 4
    + [5] * 5 + [6] * 5 + [7] * 3 + [8] * 5
)

PHASE_NAMES = [
    "Reconnaissance", "Initial Access", "Execution", "Discovery",
    "Privilege Escalation", "Persistence", "Defense Evasion",
    "Lateral Movement", "Exfiltration",
]


def load_label_names() -> List[str]:
    """Micro-state names from honeypot_dataset/configs/schema.py (READ-ONLY import).

    Falls back to generic names if the dataset package is not importable (e.g.
    ml_analytics shipped standalone). Never mutates anything under honeypot_dataset/.
    """
    import sys

    ds_root = REPO_ROOT / "honeypot_dataset"
    added = False
    try:
        if str(ds_root) not in sys.path:
            sys.path.insert(0, str(ds_root))
            added = True
        from configs import schema  # type: ignore

        idx_to_label = schema.IDX_TO_LABEL
        return [idx_to_label[i] for i in range(N_CLASSES)]
    except Exception:
        return [f"class_{i:02d}" for i in range(N_CLASSES)]
    finally:
        if added:
            try:
                sys.path.remove(str(ds_root))
            except ValueError:
                pass


# --------------------------------------------------------------------------- #
# scaler
# --------------------------------------------------------------------------- #

def load_scaler(data_dir: Path = DEFAULT_DATA_DIR):
    """Load the frozen StandardScaler (joblib format). Never re-fit it."""
    import joblib

    path = Path(data_dir) / "feature_scaler.pkl"
    if not path.exists():
        raise DataError(f"missing scaler: {path} (unzip honeysynth_final.zip here)")
    try:
        scaler = joblib.load(path)
    except Exception as exc:  # pragma: no cover - surfaced verbatim to the user
        raise DataError(
            f"could not joblib.load {path}: {exc}. "
            "Note this file is a joblib dump; plain pickle.load fails on it."
        ) from exc
    n_in = getattr(scaler, "n_features_in_", None)
    if n_in is not None and int(n_in) != N_FEATURES:
        raise DataError(f"scaler expects {n_in} features, schema says {N_FEATURES}")
    return scaler


def transform_raw(X_raw: np.ndarray, data_dir: Path = DEFAULT_DATA_DIR) -> np.ndarray:
    """Apply the frozen scaler to RAW (unscaled) 128-d features.

    This is the inference path for live sessions coming out of the extractor
    pipeline. It is NOT used on the data/final/ splits, which are pre-scaled.
    """
    scaler = load_scaler(data_dir)
    return scaler.transform(np.asarray(X_raw, dtype=np.float64)).astype(np.float32)


def check_scaling(X: np.ndarray, scaler, sample: int = 20_000) -> Dict[str, object]:
    """Decide empirically whether X is already scaler-transformed.

    Returns a provenance dict. Raises if X looks RAW (which would mean the
    dataset on disk is not what notebook 05 produced) so we never silently train
    on inconsistently-scaled data.
    """
    n = min(sample, len(X))
    S = np.asarray(X[:n], dtype=np.float64)
    col_mean_abs = float(np.abs(S.mean(axis=0)).mean())
    col_std_mean = float(S.std(axis=0).mean())
    scaler_mean_abs = float(np.abs(getattr(scaler, "mean_")).mean())

    already_scaled = col_mean_abs < 0.5 and scaler_mean_abs > 1.0
    info = {
        "col_mean_abs": round(col_mean_abs, 6),
        "col_std_mean": round(col_std_mean, 6),
        "scaler_mean_abs": round(scaler_mean_abs, 6),
        "already_scaled": already_scaled,
    }
    if not already_scaled:
        raise DataError(
            "data/final/ arrays do not look pre-scaled "
            f"(col |mean| {col_mean_abs:.4f}, scaler |mean_| {scaler_mean_abs:.4f}). "
            "Notebook 05 saves scaler.transform(X); if that changed, the "
            "baseline-vs-MT3 comparison is no longer on identical inputs. Stop "
            "and check with the dataset owner rather than re-scaling here."
        )
    return info


# --------------------------------------------------------------------------- #
# splits
# --------------------------------------------------------------------------- #

@dataclass
class Split:
    name: str
    X: np.ndarray
    y: np.ndarray

    def __len__(self) -> int:
        return len(self.y)

    @property
    def classes_present(self) -> np.ndarray:
        return np.unique(self.y)


# ── Part 3: the integrity gate at the training entry point ──────────────────
# DATA_INTEGRITY.md section 4 Part 3: "Make it a gate at the TRAINING ENTRY
# POINT, not an optional notebook cell. A report nobody runs is how this
# survived three months."
#
# `load_split` is that entry point -- every training, evaluation and comparison
# script in this package goes through it -- so the checks run here and RAISE.
#
# WHAT IS CHECKED, and why each one exists:
#
#   NaN             `extract_temporal` returns NaN for features a session cannot
#                   support. Notebook 05 imputes them and ships a mask, so a
#                   split reaching training with NaN means the imputation step
#                   was skipped. Training on it silently produces NaN loss.
#   fabricated IAT  a degenerate inter-arrival block across more than two events
#                   -- the Part 0 defect. Arithmetically consistent, which is
#                   exactly why nothing caught it before.
#   arithmetic      the 97 invariant checks in `feature_integrity`.
#   provenance      if `prov_<split>.npy` is present, every row's NaN pattern
#                   must match what its provenance level permits.
#
# THRESHOLDS ARE MEASURED, NOT GUESSED. The two datasets that exist separate
# very widely on both axes, so there is no judgement call hiding in these
# numbers:
#
#                        arithmetic failures   fabricated-IAT rows
#   data/final/    X_train      17 / 97              60.3%
#                  X_test_real   0 / 97              98.0%
#   data/final_v2/ X_train       3 / 97               0.21%
#                  X_test_synth  0 / 97               0.00%
#
# So 8/97 and 5% sit in empty space between a clean dataset and a defective one.
# The 3/97 floor on final_v2 is float32 storage noise, verified at the record
# level: 0 genuine violations in 40,000 freshly computed records.
#
# ESCAPE HATCH, deliberately loud. Reproducing the pre-rebuild numbers requires
# loading data/final/, which fails this gate by design. Pass
# `integrity="warn"` or set MT3_ALLOW_UNVALIDATED=1, and the reason is printed
# every time so it cannot become the silent default.
MAX_ARITHMETIC_FAILURES = 8
MAX_FABRICATED_FRACTION = 0.05


class IntegrityGateError(DataError):
    """A split failed the integrity gate at the training entry point."""


def check_integrity(X, y, name: str, data_dir: Path,
                    mode: str = "raise") -> Dict[str, object]:
    """Gate one split. `mode` is "raise", "warn" or "off"."""
    import numpy as _np

    if mode == "off":
        return {"split": name, "mode": "off", "checked": False}

    repo = Path(__file__).resolve().parents[2]
    hp = repo / "honeypot_dataset"
    if str(hp) not in sys.path:
        sys.path.insert(0, str(hp))
    try:
        from src.validators.feature_integrity import (  # noqa: E402
            fabricated_iat_mask, provenance_from_nan, validate,
            validate_provenance)
    except Exception as exc:                        # pragma: no cover
        print(f"[warn] integrity gate unavailable ({exc}); split {name} unchecked")
        return {"split": name, "mode": mode, "checked": False, "error": str(exc)}

    Xa = _np.asarray(X[: min(len(X), 300_000)], dtype=_np.float64)
    problems: List[str] = []

    n_nan = int(_np.isnan(Xa).sum())
    if n_nan:
        rows = int(_np.isnan(Xa).any(axis=1).sum())
        problems.append(
            f"{rows:,} rows carry NaN ({n_nan:,} cells). Notebook 05 imputes "
            f"the temporal block and ships M_*.npy; this split skipped it.")

    # un-scale so the invariants see real units, and so tolerances can track
    # each column's magnitude (a flat epsilon cries wolf -- DATA_INTEGRITY 3b)
    try:
        scaler = load_scaler(data_dir)
        Xu = Xa * scaler.scale_ + scaler.mean_
    except Exception:
        scaler, Xu = None, Xa

    rep = validate(Xu, scaler=scaler) if scaler is not None else validate(Xu)
    n_arith = len([v for v in rep.violations if v.kind == "arithmetic"])
    if n_arith > MAX_ARITHMETIC_FAILURES:
        failed = ", ".join(v.detail.split(":")[0]
                           for v in rep.violations if v.kind == "arithmetic")[:200]
        problems.append(f"{n_arith} of 97 arithmetic invariants fail ({failed})")

    fab = fabricated_iat_mask(Xu)
    frac = float(fab.mean())
    if frac > MAX_FABRICATED_FRACTION:
        problems.append(
            f"{frac*100:.1f}% of rows have a degenerate inter-arrival block "
            f"across >2 events -- fabricated temporal features (Part 0)")

    # Provenance, checked against whichever record of absence the split carries.
    #
    # There are two legitimate states and the gate must not confuse them:
    #
    #   pre-imputation   the feature is NaN. `validate_provenance` applies: a
    #                    NUMBER where the level forbids one is fabrication.
    #   post-imputation  the feature holds a median fill and `M_<split>.npy`
    #                    records mask == 0. The value is expected; what must
    #                    hold is that the MASK agrees with the provenance level.
    #
    # Demanding NaN after imputation failed `final_v2` on all 39 imputed
    # features, which would have blocked the only clean dataset in the repo. The
    # distinction being enforced is "undocumented absence" versus "documented
    # absence", not "absent" versus "present".
    prov_path = Path(data_dir) / f"prov_{name}.npy"
    mask_path = Path(data_dir) / f"M_{name}.npy"
    prov_checked = False
    if prov_path.exists():
        prov = _np.load(prov_path)[: len(Xa)]
        if len(prov) == len(Xa):
            prov_checked = True
            if mask_path.exists():
                from src.extractors.temporal import (  # noqa: E402
                    TEMPORAL_FEATURE_NAMES, unavailable_features)
                M = _np.asarray(_np.load(mask_path, mmap_mode="r")[: len(Xa)])
                mismatched = 0
                for level in _np.unique(prov):
                    sel = prov == level
                    want_absent = unavailable_features(str(level))
                    for j, fname in enumerate(TEMPORAL_FEATURE_NAMES):
                        expect = 0 if fname in want_absent else 1
                        mismatched += int((M[sel, j] != expect).sum())
                if mismatched:
                    problems.append(
                        f"{mismatched:,} mask cells disagree with the row's "
                        f"provenance level -- M_{name}.npy does not describe "
                        f"which temporal features were measured")
            else:
                prep = validate_provenance(Xu, prov)
                bad = [v for v in prep.violations if v.kind == "fabricated"]
                if bad:
                    problems.append(
                        f"{len(bad)} temporal features carry a value where the "
                        f"row's provenance cannot support one, and no "
                        f"M_{name}.npy documents the fill")

    info = {"split": name, "mode": mode, "checked": True, "rows": int(len(Xa)),
            "nan_cells": n_nan, "arithmetic_failures": n_arith,
            "fabricated_fraction": round(frac, 6),
            "provenance_checked": prov_checked, "problems": problems}

    if problems:
        _nl = chr(10)
        msg = ("integrity gate FAILED for split %r in %s:%s  - %s"
               % (name, data_dir, _nl, (_nl + "  - ").join(problems)))
        if mode == "raise":
            raise IntegrityGateError(
                msg + _nl + _nl
                + "This is the Part 3 gate. If you are deliberately "
                + "reproducing pre-rebuild numbers on data/final/, pass "
                + "integrity='warn' or set MT3_ALLOW_UNVALIDATED=1.")
        print(f"[INTEGRITY WARNING] {msg}")
    return info


def _integrity_mode(explicit: Optional[str]) -> str:
    if explicit is not None:
        return explicit
    if os.environ.get("MT3_ALLOW_UNVALIDATED") == "1":
        print("[integrity] MT3_ALLOW_UNVALIDATED=1 -- gate downgraded to warnings")
        return "warn"
    return "raise"


def load_split(
    name: str,
    data_dir: Path = DEFAULT_DATA_DIR,
    limit: Optional[int] = None,
    mmap: bool = False,
    seed: int = 0,
    integrity: Optional[str] = None,
) -> Split:
    """Load one frozen split. limit takes a class-stratified subsample (smoke tests).

    `integrity` gates the split before anything can train on it: "raise"
    (default), "warn" or "off". See `check_integrity` -- data/final/ fails by
    design, which is the point of Part 3.
    """
    if name not in SPLITS:
        raise DataError(f"unknown split {name!r}; expected one of {SPLITS}")
    data_dir = Path(data_dir)
    xp, yp = data_dir / f"X_{name}.npy", data_dir / f"y_{name}.npy"
    for p in (xp, yp):
        if not p.exists():
            raise DataError(f"missing {p} (unzip honeysynth_final.zip into {data_dir})")

    X = np.load(xp, mmap_mode="r" if mmap else None)
    y = np.load(yp)

    if X.ndim != 2 or X.shape[1] != N_FEATURES:
        raise DataError(f"{xp.name}: expected (n, {N_FEATURES}), got {X.shape}")
    if len(X) != len(y):
        raise DataError(f"{name}: X has {len(X)} rows, y has {len(y)}")
    # row-count expectations apply to the canonical frozen dataset only; a pilot
    # subset (make_pilot.py) legitimately has fewer rows and marks itself as such
    is_canonical = data_dir.resolve() == DEFAULT_DATA_DIR.resolve()
    exp = _EXPECTED_ROWS.get(name)
    if is_canonical and exp is not None and len(y) != exp:
        print(f"[warn] {name}: expected {exp:,} rows, found {len(y):,}")
    if y.min() < 0 or y.max() >= N_CLASSES:
        raise DataError(
            f"{name}: labels out of range [0,{N_CLASSES}): [{y.min()}, {y.max()}]"
        )

    if limit is not None and limit < len(y):
        idx = _stratified_subsample(y, limit, seed)
        X = X[idx]
        y = y[idx]

    X = np.ascontiguousarray(np.asarray(X, dtype=np.float32))
    y = np.asarray(y, dtype=np.int64)
    check_integrity(X, y, name, data_dir, _integrity_mode(integrity))

    return Split(name=name, X=X, y=y)


def _stratified_subsample(y: np.ndarray, limit: int, seed: int) -> np.ndarray:
    """At-least-one-per-present-class subsample, otherwise proportional."""
    rng = np.random.default_rng(seed)
    classes, counts = np.unique(y, return_counts=True)
    take = np.maximum(1, np.floor(counts / counts.sum() * limit).astype(int))
    take = np.minimum(take, counts)
    keep: List[np.ndarray] = []
    for c, k in zip(classes, take):
        pool = np.flatnonzero(y == c)
        keep.append(rng.choice(pool, size=int(k), replace=False))
    idx = np.concatenate(keep)
    rng.shuffle(idx)
    return np.sort(idx[:limit])


def load_dataset(
    data_dir: Path = DEFAULT_DATA_DIR,
    splits: Tuple[str, ...] = SPLITS,
    limits: Optional[Dict[str, int]] = None,
    verify_scaling: bool = True,
    verbose: bool = True,
) -> Tuple[Dict[str, Split], Dict[str, object]]:
    """Load the frozen splits + a scaler-provenance record."""
    data_dir = Path(data_dir)
    limits = limits or {}
    scaler = load_scaler(data_dir)

    out: Dict[str, Split] = {}
    for name in splits:
        out[name] = load_split(name, data_dir, limit=limits.get(name))

    provenance: Dict[str, object] = {
        "data_dir": str(data_dir),
        "scaler_class": type(scaler).__name__,
        "scaler_n_samples_seen": float(getattr(scaler, "n_samples_seen_", -1)),
        "scaler_refit": False,
        "scaler_reapplied_to_splits": False,
    }
    if verify_scaling:
        ref = out.get("train") or out[next(iter(out))]
        provenance["scaling_check"] = check_scaling(ref.X, scaler)

    card = data_dir / "dataset_card.json"
    if card.exists():
        try:
            provenance["dataset_card"] = json.loads(card.read_text())
        except Exception:
            pass

    if verbose:
        print(f"[data] {data_dir}")
        for name, sp in out.items():
            counts = np.bincount(sp.y, minlength=N_CLASSES)
            present = sp.classes_present
            print(
                f"[data]   {name:11s} X{sp.X.shape} y{sp.y.shape} "
                f"classes={len(present):2d} per-class min/max="
                f"{counts[present].min()}/{counts[present].max()}"
            )
        print(
            f"[data] scaler: {provenance['scaler_class']} fit on "
            f"{provenance['scaler_n_samples_seen']:,.0f} rows -- loaded, NOT re-fit; "
            "splits already transformed by it (not re-applied)"
        )
    return out, provenance


def class_counts(y: np.ndarray, n_classes: int = N_CLASSES) -> np.ndarray:
    return np.bincount(np.asarray(y, dtype=np.int64), minlength=n_classes)


# --------------------------------------------------------------------------- #
# batching
# --------------------------------------------------------------------------- #

class TensorBatcher:
    """Index-shuffling batcher over in-memory tensors.

    Faster than a DataLoader for dense tabular data and free of Windows
    multiprocessing pitfalls. Optionally parks the whole split on the GPU.
    """

    def __init__(
        self,
        X: np.ndarray,
        y: np.ndarray,
        batch_size: int,
        shuffle: bool = False,
        device: str = "cpu",
        cache_on_device: bool = False,
        seed: int = 0,
        drop_last: bool = False,
    ) -> None:
        import torch

        self.batch_size = int(batch_size)
        self.shuffle = shuffle
        self.device = device
        self.drop_last = drop_last
        self._gen = np.random.default_rng(seed)

        self.X = torch.from_numpy(np.ascontiguousarray(X, dtype=np.float32))
        self.y = torch.from_numpy(np.ascontiguousarray(y, dtype=np.int64))
        self.on_device = cache_on_device and device != "cpu"
        if self.on_device:
            self.X = self.X.to(device, non_blocking=True)
            self.y = self.y.to(device, non_blocking=True)
        elif device != "cpu":
            try:
                self.X = self.X.pin_memory()
                self.y = self.y.pin_memory()
            except RuntimeError:  # pinning unavailable on this host
                pass

    def __len__(self) -> int:
        n = len(self.y)
        if self.drop_last:
            return n // self.batch_size
        return (n + self.batch_size - 1) // self.batch_size

    def __iter__(self) -> Iterator[Tuple[object, object]]:
        import torch

        n = len(self.y)
        if self.shuffle:
            order = torch.from_numpy(self._gen.permutation(n))
            if self.on_device:
                order = order.to(self.device)
        else:
            order = None

        for start in range(0, n, self.batch_size):
            end = start + self.batch_size
            if self.drop_last and end > n:
                break
            if order is None:
                xb, yb = self.X[start:end], self.y[start:end]
            else:
                sel = order[start:end]
                xb, yb = self.X[sel], self.y[sel]
            if not self.on_device and self.device != "cpu":
                xb = xb.to(self.device, non_blocking=True)
                yb = yb.to(self.device, non_blocking=True)
            yield xb, yb
