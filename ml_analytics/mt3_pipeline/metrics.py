"""
Evaluation metrics -- the protocol both CNN-LSTM and MT3 must report
(ml_analytics/README.md "Evaluation protocol"):

    macro-F1 (PRIMARY), per-class F1, accuracy, confusion matrix.

Two macro-F1 numbers are reported and they are not interchangeable:

  macro_f1        averaged over the classes PRESENT in y_true. This is the
                  headline number. X_test_real contains only 21 of the 45
                  micro-states, so averaging over all 45 would divide by 45 and
                  score every model against 24 classes it was never asked about.
  macro_f1_all45  averaged over all 45 classes (absent classes score 0).
                  Reported for completeness / comparability with X_test_synth.

Both models must quote the SAME one when compared; compare.py prints both.
"""
from __future__ import annotations

from typing import Dict, List, Optional, Sequence

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_recall_fscore_support,
)

from .data import IDX_TO_PHASE, N_CLASSES, N_PHASES, PHASE_NAMES


def _phase_of(y: np.ndarray) -> np.ndarray:
    lut = np.asarray(IDX_TO_PHASE, dtype=np.int64)
    return lut[np.asarray(y, dtype=np.int64)]


def classification_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    label_names: Optional[Sequence[str]] = None,
    n_classes: int = N_CLASSES,
    include_confusion: bool = True,
) -> Dict[str, object]:
    """Full metric bundle for one split."""
    y_true = np.asarray(y_true, dtype=np.int64)
    y_pred = np.asarray(y_pred, dtype=np.int64)
    present = np.unique(y_true)
    all_labels = np.arange(n_classes)

    prec, rec, f1, sup = precision_recall_fscore_support(
        y_true, y_pred, labels=all_labels, zero_division=0
    )

    out: Dict[str, object] = {
        "n_samples": int(len(y_true)),
        "n_classes_present": int(len(present)),
        "classes_present": present.tolist(),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "balanced_accuracy": float(balanced_accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(y_true, y_pred, labels=present, average="macro", zero_division=0)),
        "macro_f1_all45": float(f1_score(y_true, y_pred, labels=all_labels, average="macro", zero_division=0)),
        "weighted_f1": float(f1_score(y_true, y_pred, average="weighted", zero_division=0)),
        "micro_f1": float(f1_score(y_true, y_pred, average="micro", zero_division=0)),
        "macro_precision": float(np.mean(prec[present])),
        "macro_recall": float(np.mean(rec[present])),
    }

    names = list(label_names) if label_names is not None else [f"class_{i:02d}" for i in range(n_classes)]
    out["per_class"] = {
        names[i]: {
            "idx": int(i),
            "support": int(sup[i]),
            "precision": float(prec[i]),
            "recall": float(rec[i]),
            "f1": float(f1[i]),
            "present_in_y_true": bool(sup[i] > 0),
        }
        for i in range(n_classes)
    }

    # kill-chain phase level (9-way), derived from the micro-state predictions
    pt, pp = _phase_of(y_true), _phase_of(y_pred)
    phase_present = np.unique(pt)
    out["phase"] = {
        "accuracy": float(accuracy_score(pt, pp)),
        "macro_f1": float(f1_score(pt, pp, labels=phase_present, average="macro", zero_division=0)),
        "per_phase_f1": {
            PHASE_NAMES[p]: float(f1_score(pt, pp, labels=[p], average="macro", zero_division=0))
            for p in range(N_PHASES)
        },
    }

    if include_confusion:
        out["confusion_matrix"] = confusion_matrix(y_true, y_pred, labels=all_labels).tolist()
    return out


def top_confusions(
    cm: np.ndarray, label_names: Sequence[str], k: int = 10
) -> List[Dict[str, object]]:
    """The k largest off-diagonal cells of a confusion matrix."""
    cm = np.asarray(cm)
    off = cm.copy()
    np.fill_diagonal(off, 0)
    if off.sum() == 0:
        return []
    flat = np.argsort(off, axis=None)[::-1][:k]
    rows, cols = np.unravel_index(flat, off.shape)
    out = []
    for r, c in zip(rows, cols):
        if off[r, c] == 0:
            break
        support = cm[r].sum()
        out.append(
            {
                "true": label_names[r],
                "pred": label_names[c],
                "count": int(off[r, c]),
                "pct_of_true_class": round(float(off[r, c]) / support * 100, 2) if support else 0.0,
            }
        )
    return out


def format_metrics_line(name: str, m: Dict[str, object]) -> str:
    return (
        f"{name:<14s} n={m['n_samples']:>6,d} cls={m['n_classes_present']:>2d}  "
        f"macroF1={m['macro_f1']:.4f}  macroF1@45={m['macro_f1_all45']:.4f}  "
        f"acc={m['accuracy']:.4f}  wF1={m['weighted_f1']:.4f}  "
        f"phaseF1={m['phase']['macro_f1']:.4f}"
    )


def per_class_table(m: Dict[str, object], only_present: bool = True, top_n: Optional[int] = None) -> str:
    """Readable per-class F1 table, worst-first."""
    rows = [v for v in m["per_class"].values() if (v["present_in_y_true"] or not only_present)]
    rows.sort(key=lambda r: (r["f1"], -r["support"]))
    if top_n:
        rows = rows[:top_n]
    names = {v["idx"]: k for k, v in m["per_class"].items()}
    lines = [f"  {'micro-state':<26s} {'support':>8s} {'prec':>7s} {'rec':>7s} {'f1':>7s}"]
    lines.append("  " + "-" * 60)
    for r in rows:
        lines.append(
            f"  {names[r['idx']]:<26s} {r['support']:>8,d} "
            f"{r['precision']:>7.4f} {r['recall']:>7.4f} {r['f1']:>7.4f}"
        )
    return "\n".join(lines)
