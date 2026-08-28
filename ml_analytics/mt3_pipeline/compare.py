"""
Baseline (CNN-LSTM) vs MT3 comparison on IDENTICAL test rows.

Reads the prediction files written by evaluate.py (preds_test_real.npz /
preds_test_synth.npz) for each model, asserts the two models were scored on the
same y_true (same split, same order), then prints:

  * a headline table   -- macro-F1 / accuracy / weighted-F1 / phase macro-F1
  * a per-class delta  -- where MT3 gains or loses against the baseline
  * McNemar's test     -- whether the accuracy difference is statistically real

The baseline is a teammate deliverable (ml_analytics/models/cnn_lstm.py). Until
it lands, run this with only --mt3-dir and it prints the MT3 column alone plus a
note that the baseline predictions are missing -- it never invents numbers.

Usage:
    python -m ml_analytics.mt3_pipeline.compare \
        --mt3-dir ml_analytics/artifacts/mt3 \
        --baseline-dir ml_analytics/artifacts/cnn_lstm
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

import numpy as np

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    __package__ = "ml_analytics.mt3_pipeline"

from .data import REPO_ROOT, load_label_names  # noqa: E402
from .metrics import classification_metrics  # noqa: E402

TEST_SPLITS = ("test_real", "test_synth")
HEADLINE_SPLIT = "test_real"


def load_preds(pred_dir: Path, split: str) -> Optional[Dict[str, np.ndarray]]:
    path = Path(pred_dir) / f"preds_{split}.npz"
    if not path.exists():
        return None
    with np.load(path, allow_pickle=False) as z:
        return {k: z[k] for k in z.files if k in ("y_true", "y_pred", "phase_pred", "y_prob")}


def mcnemar(y_true: np.ndarray, pred_a: np.ndarray, pred_b: np.ndarray) -> Dict[str, float]:
    """Exact-ish McNemar on the discordant pairs (normal approx with continuity correction)."""
    a_ok, b_ok = pred_a == y_true, pred_b == y_true
    n01 = int(np.sum(a_ok & ~b_ok))   # A right, B wrong
    n10 = int(np.sum(~a_ok & b_ok))   # A wrong, B right
    n = n01 + n10
    if n == 0:
        return {"n01": n01, "n10": n10, "statistic": 0.0, "p_value": 1.0}
    stat = (abs(n01 - n10) - 1) ** 2 / n
    try:
        from scipy.stats import chi2

        p = float(chi2.sf(stat, df=1))
    except Exception:  # scipy optional
        p = float(np.exp(-stat / 2))  # crude upper bound, flagged in output
    return {"n01": n01, "n10": n10, "statistic": float(stat), "p_value": p}


def compare_split(
    split: str,
    models: Dict[str, Dict[str, np.ndarray]],
    label_names: Sequence[str],
) -> Dict[str, object]:
    """Score every available model on one split after verifying row identity."""
    ref_name, ref = next(iter(models.items()))
    y_true = ref["y_true"]
    for name, pr in models.items():
        if len(pr["y_true"]) != len(y_true) or not np.array_equal(pr["y_true"], y_true):
            raise SystemExit(
                f"[compare] ABORT: {name} and {ref_name} were scored on different rows for "
                f"{split}. Both models must evaluate data/final/X_{split}.npy unshuffled."
            )
    out: Dict[str, object] = {"split": split, "n": int(len(y_true)), "models": {}}
    for name, pr in models.items():
        out["models"][name] = classification_metrics(
            y_true, pr["y_pred"], label_names=label_names, include_confusion=False
        )
    return out


def _fmt_row(label: str, values: List[str], width: int = 12) -> str:
    return f"  {label:<22s}" + "".join(f"{v:>{width}s}" for v in values)


def print_report(
    per_split: Dict[str, Dict[str, object]],
    model_order: List[str],
    label_names: Sequence[str],
    top_delta: int = 12,
) -> None:
    print("\n" + "=" * 78)
    print("  BASELINE vs MT3 -- frozen HoneySynth splits, same scaler, same rows")
    print("=" * 78)

    for split, res in per_split.items():
        tag = "  [HEADLINE]" if split == HEADLINE_SPLIT else ""
        m0 = res["models"][model_order[0]]
        print(f"\n{split}  (n={res['n']:,}, {m0['n_classes_present']} classes present){tag}")
        print(_fmt_row("metric", [m for m in model_order]))
        print("  " + "-" * (22 + 12 * len(model_order)))
        rows = [
            ("macro-F1 (present)", lambda m: f"{m['macro_f1']:.4f}"),
            ("macro-F1 (all 45)", lambda m: f"{m['macro_f1_all45']:.4f}"),
            ("accuracy", lambda m: f"{m['accuracy']:.4f}"),
            ("balanced accuracy", lambda m: f"{m['balanced_accuracy']:.4f}"),
            ("weighted-F1", lambda m: f"{m['weighted_f1']:.4f}"),
            ("macro precision", lambda m: f"{m['macro_precision']:.4f}"),
            ("macro recall", lambda m: f"{m['macro_recall']:.4f}"),
            ("phase macro-F1 (9)", lambda m: f"{m['phase']['macro_f1']:.4f}"),
            ("phase accuracy", lambda m: f"{m['phase']['accuracy']:.4f}"),
        ]
        for label, fn in rows:
            print(_fmt_row(label, [fn(res["models"][name]) for name in model_order]))

        if len(model_order) == 2:
            a, b = model_order
            ma, mb = res["models"][a], res["models"][b]
            d = mb["macro_f1"] - ma["macro_f1"]
            print(_fmt_row("delta macro-F1", ["", f"{d:+.4f}"]))
            mc = res.get("mcnemar")
            if mc:
                print(f"  McNemar: {a} only-right={mc['n01']:,}  {b} only-right={mc['n10']:,}  "
                      f"chi2={mc['statistic']:.1f}  p={mc['p_value']:.3g}")

    if len(model_order) == 2:
        a, b = model_order
        for split, res in per_split.items():
            ma, mb = res["models"][a], res["models"][b]
            deltas = []
            for name, va in ma["per_class"].items():
                vb = mb["per_class"][name]
                if not va["present_in_y_true"]:
                    continue
                deltas.append((vb["f1"] - va["f1"], name, va["support"], va["f1"], vb["f1"]))
            deltas.sort()
            print(f"\n{split}: largest per-class F1 shifts ({b} minus {a})")
            print(f"  {'micro-state':<26s} {'support':>8s} {a[:10]:>10s} {b[:10]:>10s} {'delta':>9s}")
            print("  " + "-" * 68)
            head = deltas[:top_delta // 2]
            tail = [d for d in deltas[-(top_delta // 2):] if d not in head]
            for d, name, sup, fa, fb in head + tail:
                print(f"  {name:<26s} {sup:>8,d} {fa:>10.4f} {fb:>10.4f} {d:>+9.4f}")


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Compare CNN-LSTM baseline vs MT3 on identical rows")
    p.add_argument("--mt3-dir", type=Path,
                   default=REPO_ROOT / "ml_analytics" / "artifacts" / "mt3")
    p.add_argument("--baseline-dir", type=Path,
                   default=REPO_ROOT / "ml_analytics" / "artifacts" / "cnn_lstm")
    p.add_argument("--mt3-name", default="MT3")
    p.add_argument("--baseline-name", default="CNN-LSTM")
    p.add_argument("--splits", nargs="+", default=list(TEST_SPLITS))
    p.add_argument("--out", type=Path, default=None, help="write the comparison as JSON")
    a = p.parse_args(argv)

    label_names = load_label_names()
    sources: List[Tuple[str, Path]] = [
        (a.baseline_name, a.baseline_dir),
        (a.mt3_name, a.mt3_dir),
    ]

    per_split: Dict[str, Dict[str, object]] = {}
    model_order: List[str] = []
    missing: List[str] = []

    for split in a.splits:
        models: Dict[str, Dict[str, np.ndarray]] = {}
        for name, d in sources:
            pr = load_preds(d, split)
            if pr is None:
                missing.append(f"{name}: {Path(d) / f'preds_{split}.npz'}")
                continue
            models[name] = pr
        if not models:
            continue
        res = compare_split(split, models, label_names)
        if len(models) == 2:
            names = list(models)
            res["mcnemar"] = mcnemar(
                models[names[0]]["y_true"], models[names[0]]["y_pred"], models[names[1]]["y_pred"]
            )
        per_split[split] = res
        model_order = list(models)

    if not per_split:
        print("[compare] no prediction files found. Train + evaluate first:")
        print("    python -m ml_analytics.mt3_pipeline.train_mt3 --out-dir ml_analytics/artifacts/mt3")
        for m in missing:
            print(f"    missing: {m}")
        return 1

    print_report(per_split, model_order, label_names)

    if missing:
        print("\n[compare] NOTE -- only one model was scored; no comparison is being claimed.")
        for m in sorted(set(missing)):
            print(f"    missing predictions: {m}")
        print("    The CNN-LSTM baseline is a teammate deliverable "
              "(ml_analytics/models/cnn_lstm.py is still empty on main).")

    if a.out:
        payload = {
            split: {
                "n": res["n"],
                "models": {
                    name: {k: v for k, v in m.items() if k != "per_class"}
                    for name, m in res["models"].items()
                },
                "mcnemar": res.get("mcnemar"),
            }
            for split, res in per_split.items()
        }
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(json.dumps(payload, indent=2))
        print(f"\n[compare] JSON written to {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
