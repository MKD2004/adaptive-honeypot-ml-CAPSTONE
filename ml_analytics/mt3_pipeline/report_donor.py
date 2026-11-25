"""
ml_analytics/mt3_pipeline/report_donor.py

Results split by `donor_origin` -- how each generated session's timing was
obtained. DATA_INTEGRITY.md 11a requires every result on this dataset to be
reported per class AND per donor origin; nothing did until now.

Run as:
    python -m ml_analytics.mt3_pipeline.report_donor

    donor_exact    gaps copied from a real session of the SAME class and bucket
    donor_bucket   same bucket, DIFFERENT class -- correlation kept, wrong rhythm
    per_event      no length-matched donor; each gap drawn independently
                   -- marginals right, joint structure gone

Only `test_synth` carries these: `test_real` rows were measured, not generated,
so its donor column is "measured" throughout.

TWO WAYS TO READ IT, AND ONE OF THEM IS WRONG.

A POOLED score per donor group measures CLASS COMPOSITION, not timing quality --
the same trap section 12d documents for adversarial AUC. The groups hold
different classes by construction, because whether an exact donor exists is a
property of the class:

    donor_exact    6 classes   the real-supported ones
    donor_bucket  43 classes
    per_event     44 classes

So the pooled table below is printed with its composition beside it, and the
number to actually use is the PAIRED one: for each class with rows in two donor
groups, the model's RECALL on that class under each. Recall is used rather than
F1 because it is defined per row and does not shift when the subset changes the
negative set. 30 of 45 classes qualify, nearly all `donor_bucket` against
`per_event`; `donor_exact` is confined to 6 classes and cannot be paired broadly.

WHAT SECTION 14e PREDICTS. 54.5% of generated sessions fall back to `per_event`,
which has the same defect class-blind donors had, and on a task where structural
counts cannot separate the classes class-blind timing scored at chance (0.546)
where class-aware reached 0.946. If timing is load-bearing for a class, its
`per_event` rows should be the harder ones. If this report shows no paired
difference, that is evidence the model is not using timing for those classes at
all -- which is a finding, not a null result.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Dict, List, Optional, Sequence

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

DEFAULT_ARTIFACTS = (
    "ml_analytics/artifacts/linear_probe_final_v2",
    "ml_analytics/artifacts/cnn_lstm_final_v2",
    "ml_analytics/artifacts/mt3_final_v2_d256",
)
ORIGINS = ("donor_exact", "donor_bucket", "per_event")
MIN_CLASS_ROWS = 100


def _label_names() -> List[str]:
    from .data import load_label_names

    return load_label_names()


def pooled_by_origin(y_true, y_pred, donor) -> Dict[str, dict]:
    """Per-origin accuracy and macro-F1, WITH the class composition beside it."""
    from sklearn.metrics import f1_score

    out = {}
    for o in ORIGINS:
        m = donor == o
        if not m.any():
            continue
        yt, yp = y_true[m], y_pred[m]
        present = np.unique(yt)
        out[o] = {
            "n": int(m.sum()),
            "n_classes": int(len(present)),
            "accuracy": float((yt == yp).mean()),
            "macro_f1": float(f1_score(yt, yp, labels=present, average="macro",
                                       zero_division=0)),
        }
    return out


def paired_by_class(y_true, y_pred, donor, a="donor_bucket", b="per_event",
                    min_rows: int = MIN_CLASS_ROWS) -> Dict[str, object]:
    """Per-class recall under two donor origins, for classes holding both.

    This is the confound-free comparison: the class is held fixed, so a
    difference is about how the timing was produced and nothing else.
    """
    names = _label_names()
    rows = []
    for c in np.unique(y_true):
        ma = (y_true == c) & (donor == a)
        mb = (y_true == c) & (donor == b)
        if ma.sum() < min_rows or mb.sum() < min_rows:
            continue
        ra = float((y_pred[ma] == c).mean())
        rb = float((y_pred[mb] == c).mean())
        rows.append({
            "class": names[c] if c < len(names) else f"class_{c}",
            "idx": int(c),
            f"n_{a}": int(ma.sum()), f"n_{b}": int(mb.sum()),
            f"recall_{a}": round(ra, 4), f"recall_{b}": round(rb, 4),
            "delta": round(ra - rb, 4),
        })
    rows.sort(key=lambda r: -abs(r["delta"]))
    deltas = np.array([r["delta"] for r in rows], dtype=float)
    summary = {"a": a, "b": b, "n_classes_paired": len(rows)}
    if len(rows):
        wins = int((deltas > 0).sum())
        summary.update({
            "mean_delta": round(float(deltas.mean()), 4),
            "median_delta": round(float(np.median(deltas)), 4),
            f"classes_where_{a}_wins": wins,
            f"classes_where_{b}_wins": int((deltas < 0).sum()),
        })
        try:
            from scipy.stats import wilcoxon

            if len(rows) >= 6 and np.any(deltas != 0):
                summary["wilcoxon_p"] = round(float(wilcoxon(deltas).pvalue), 6)
        except Exception:
            pass
    return {"summary": summary, "per_class": rows}


def report(artifact_dir: Path, data_dir: Path, split: str = "test_synth") -> Optional[dict]:
    preds = artifact_dir / f"preds_{split}.npz"
    donor_f = data_dir / f"donor_{split}.npy"
    if not preds.exists():
        print(f"[donor] {artifact_dir.name}: no preds_{split}.npz -- skipped")
        return None
    if not donor_f.exists():
        raise FileNotFoundError(f"{donor_f} missing; rerun notebooks 02 then 05")

    z = np.load(preds)
    y_true, y_pred = z["y_true"], z["y_pred"]
    donor = np.asarray([str(v) for v in np.load(donor_f)])
    if len(donor) != len(y_true):
        raise ValueError(
            f"{artifact_dir.name}: donor_{split}.npy has {len(donor):,} rows but "
            f"preds has {len(y_true):,} -- the predictions predate the current "
            f"split, so retrain before reporting")

    uniq = sorted(set(donor.tolist()))
    if uniq == ["measured"]:
        print(f"[donor] {artifact_dir.name} / {split}: every row is 'measured' "
              f"(real, not generated) -- no donor breakdown applies")
        return {"split": split, "all_measured": True}

    out = {"split": split, "model": artifact_dir.name,
           "pooled": pooled_by_origin(y_true, y_pred, donor),
           "paired_bucket_vs_per_event": paired_by_class(y_true, y_pred, donor)}

    print(f"\n[donor] {artifact_dir.name} / {split}")
    print(f"  {'origin':14s} {'n':>7s} {'cls':>4s} {'macroF1':>8s} {'acc':>8s}"
          f"   <- POOLED: confounded by class composition")
    for o, d in out["pooled"].items():
        print(f"  {o:14s} {d['n']:>7,} {d['n_classes']:>4d} {d['macro_f1']:>8.4f} "
              f"{d['accuracy']:>8.4f}")

    s = out["paired_bucket_vs_per_event"]["summary"]
    print(f"  PAIRED within class, donor_bucket vs per_event "
          f"({s['n_classes_paired']} classes with >={MIN_CLASS_ROWS} rows in both):")
    if s["n_classes_paired"]:
        print(f"    mean recall delta {s['mean_delta']:+.4f}   median "
              f"{s['median_delta']:+.4f}   bucket wins "
              f"{s['classes_where_donor_bucket_wins']}, per_event wins "
              f"{s['classes_where_per_event_wins']}"
              + (f"   wilcoxon p={s['wilcoxon_p']}" if "wilcoxon_p" in s else ""))
        for r in out["paired_bucket_vs_per_event"]["per_class"][:8]:
            print(f"      {r['class']:24s} bucket {r['recall_donor_bucket']:.4f} "
                  f"(n={r['n_donor_bucket']:,})   per_event "
                  f"{r['recall_per_event']:.4f} (n={r['n_per_event']:,})   "
                  f"delta {r['delta']:+.4f}")
    return out


def main(argv: Optional[Sequence[str]] = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--artifacts", nargs="*", default=list(DEFAULT_ARTIFACTS))
    ap.add_argument("--data-dir", type=Path,
                    default=Path("honeypot_dataset/data/final_v2"))
    ap.add_argument("--splits", nargs="*", default=["test_synth", "test_real"])
    ap.add_argument("--out", type=Path, default=None)
    a = ap.parse_args(argv)

    all_out = {}
    for d in a.artifacts:
        for sp in a.splits:
            r = report(Path(d), a.data_dir, sp)
            if r:
                all_out.setdefault(Path(d).name, {})[sp] = r
    out = a.out or a.data_dir / "donor_origin_report.json"
    out.write_text(json.dumps(all_out, indent=2), encoding="utf-8")
    print(f"\n[donor] saved -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
