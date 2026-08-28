"""
Evaluate an MT3 checkpoint on the frozen test splits and SAVE PREDICTIONS.

Saving predictions is mandatory (MT3_PROMPT.md / ml_analytics/README.md): the
baseline-vs-MT3 comparison must be computed on identical test rows, which
compare.py verifies by checking that both prediction files carry the same
y_true array.

Usage (from the repo root):
    python -m ml_analytics.mt3_pipeline.evaluate \
        --ckpt ml_analytics/artifacts/mt3/best.pt \
        --out-dir ml_analytics/artifacts/mt3
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Dict, Optional, Sequence, Tuple

import numpy as np

if __package__ in (None, ""):  # allow `python ml_analytics/mt3_pipeline/evaluate.py`
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    __package__ = "ml_analytics.mt3_pipeline"

from .data import (  # noqa: E402
    DEFAULT_DATA_DIR,
    N_CLASSES,
    Split,
    load_label_names,
    load_split,
)
from .metrics import (  # noqa: E402
    classification_metrics,
    format_metrics_line,
    per_class_table,
    top_confusions,
)

TEST_SPLITS = ("test_real", "test_synth")


def pick_device(requested: str = "auto") -> str:
    import torch

    if requested != "auto":
        return requested
    return "cuda" if torch.cuda.is_available() else "cpu"


def build_model(model_kwargs: Optional[Dict[str, object]] = None):
    from ml_analytics.models.mt3 import MT3

    return MT3(**(model_kwargs or {}))


def load_model(ckpt_path: Path, device: str = "cpu") -> Tuple[object, Dict[str, object]]:
    """Rebuild MT3 from a checkpoint written by train_mt3.py."""
    import torch

    ckpt = torch.load(str(ckpt_path), map_location=device, weights_only=False)
    model = build_model(ckpt.get("model_kwargs"))
    model.load_state_dict(ckpt["model_state"])
    model.to(device).eval()
    return model, ckpt


@np.errstate(all="ignore")
def predict(
    model,
    X: np.ndarray,
    device: str = "cpu",
    batch_size: int = 4096,
    amp: bool = False,
    return_probs: bool = True,
) -> Dict[str, np.ndarray]:
    """Batched inference -> micro-state preds, phase preds, (optional) probabilities."""
    import torch

    model.eval()
    n = len(X)
    preds = np.empty(n, dtype=np.int64)
    phase_preds = np.empty(n, dtype=np.int64)
    probs = np.empty((n, N_CLASSES), dtype=np.float16) if return_probs else None

    amp_dtype = torch.bfloat16 if (amp and device.startswith("cuda")) else torch.float16
    use_amp = amp and device.startswith("cuda")

    with torch.no_grad():
        for start in range(0, n, batch_size):
            xb = torch.from_numpy(np.ascontiguousarray(X[start : start + batch_size])).to(device)
            if use_amp:
                with torch.autocast(device_type="cuda", dtype=amp_dtype):
                    emissions, hp_logits, _ = model(xb)
            else:
                emissions, hp_logits, _ = model(xb)
            emissions = emissions.float()
            preds[start : start + len(xb)] = emissions.argmax(dim=1).cpu().numpy()
            phase_preds[start : start + len(xb)] = hp_logits.float().argmax(dim=1).cpu().numpy()
            if return_probs:
                probs[start : start + len(xb)] = (
                    torch.softmax(emissions, dim=1).cpu().numpy().astype(np.float16)
                )

    out = {"y_pred": preds, "phase_pred": phase_preds}
    if return_probs:
        out["y_prob"] = probs
    return out


def evaluate_split(
    model,
    split: Split,
    label_names: Sequence[str],
    device: str = "cpu",
    batch_size: int = 4096,
    amp: bool = False,
    out_dir: Optional[Path] = None,
    model_name: str = "mt3",
    save_probs: bool = True,
) -> Dict[str, object]:
    """Predict, score, and persist predictions + metrics for one split."""
    pr = predict(model, split.X, device=device, batch_size=batch_size, amp=amp, return_probs=save_probs)
    m = classification_metrics(split.y, pr["y_pred"], label_names=label_names)
    m["split"] = split.name
    m["model"] = model_name

    if out_dir is not None:
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        payload = {
            "y_true": split.y.astype(np.int64),
            "y_pred": pr["y_pred"].astype(np.int64),
            "phase_pred": pr["phase_pred"].astype(np.int64),
            "model": np.array(model_name),
            "split": np.array(split.name),
        }
        if save_probs:
            payload["y_prob"] = pr["y_prob"]
        np.savez_compressed(out_dir / f"preds_{split.name}.npz", **payload)
        (out_dir / f"metrics_{split.name}.json").write_text(json.dumps(m, indent=2))
    return m


def evaluate_checkpoint(
    ckpt_path: Path,
    data_dir: Path = DEFAULT_DATA_DIR,
    out_dir: Optional[Path] = None,
    splits: Sequence[str] = TEST_SPLITS,
    device: str = "auto",
    batch_size: int = 4096,
    amp: bool = False,
    limits: Optional[Dict[str, int]] = None,
    model_name: str = "mt3",
    verbose: bool = True,
    save_probs: bool = True,
) -> Dict[str, Dict[str, object]]:
    device = pick_device(device)
    model, ckpt = load_model(Path(ckpt_path), device=device)
    label_names = load_label_names()
    limits = limits or {}

    results: Dict[str, Dict[str, object]] = {}
    for name in splits:
        sp = load_split(name, data_dir, limit=limits.get(name))
        m = evaluate_split(
            model, sp, label_names, device=device, batch_size=batch_size, amp=amp,
            out_dir=out_dir, model_name=model_name, save_probs=save_probs,
        )
        results[name] = m
        if verbose:
            headline = " <-- HEADLINE" if name == "test_real" else ""
            print(f"[eval] {format_metrics_line(name, m)}{headline}")

    if verbose:
        for name, m in results.items():
            print(f"\n[eval] {name}: worst per-class F1 (present classes)")
            print(per_class_table(m, top_n=10))
            cm = np.asarray(m["confusion_matrix"])
            tc = top_confusions(cm, label_names, k=5)
            if tc:
                print(f"[eval] {name}: top confusions")
                for r in tc:
                    print(f"    {r['true']:<24s} -> {r['pred']:<24s} {r['count']:>6,d} "
                          f"({r['pct_of_true_class']:.1f}% of true class)")

    if out_dir is not None:
        summary = {
            "model": model_name,
            "checkpoint": str(ckpt_path),
            "epoch": ckpt.get("epoch"),
            "val_macro_f1": ckpt.get("best_val_macro_f1"),
            "results": {
                k: {kk: vv for kk, vv in v.items() if kk not in ("confusion_matrix", "per_class")}
                for k, v in results.items()
            },
        }
        Path(out_dir).mkdir(parents=True, exist_ok=True)
        (Path(out_dir) / "eval_summary.json").write_text(json.dumps(summary, indent=2))
    return results


def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="Evaluate an MT3 checkpoint on the frozen test splits")
    p.add_argument("--ckpt", required=True, type=Path)
    p.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    p.add_argument("--out-dir", type=Path, default=None)
    p.add_argument("--splits", nargs="+", default=list(TEST_SPLITS))
    p.add_argument("--device", default="auto")
    p.add_argument("--batch-size", type=int, default=4096)
    p.add_argument("--amp", action="store_true")
    p.add_argument("--model-name", default="mt3")
    p.add_argument("--no-probs", action="store_true", help="skip saving softmax probabilities")
    a = p.parse_args(argv)

    out_dir = a.out_dir or Path(a.ckpt).parent
    evaluate_checkpoint(
        a.ckpt, data_dir=a.data_dir, out_dir=out_dir, splits=a.splits, device=a.device,
        batch_size=a.batch_size, amp=a.amp, model_name=a.model_name, save_probs=not a.no_probs,
    )
    print(f"\n[eval] predictions + metrics written to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
