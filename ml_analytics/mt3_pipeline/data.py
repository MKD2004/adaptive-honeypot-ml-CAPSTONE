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


def load_split(
    name: str,
    data_dir: Path = DEFAULT_DATA_DIR,
    limit: Optional[int] = None,
    mmap: bool = False,
    seed: int = 0,
) -> Split:
    """Load one frozen split. limit takes a class-stratified subsample (smoke tests)."""
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
    exp = _EXPECTED_ROWS.get(name)
    if exp is not None and len(y) != exp:
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
