"""
ml_analytics/mt3_pipeline/linear_probe.py

One linear layer, 128 -> n_labels. The floor any architecture claim has to clear.

Run as:
    python -m ml_analytics.mt3_pipeline.linear_probe \\
        --data-dir honeypot_dataset/data/final_v2 \\
        --out-dir ml_analytics/artifacts/linear_probe_final_v2

WHY THIS EXISTS. On `data/final/` the three models landed on top of each other:
MT3 (3.76M params) 0.8276 on test_real, CNN-LSTM (190k) 0.8093, and a
5,805-parameter linear probe 0.7681. A probe within 0.06 of a Transformer is not
a result about the Transformer -- it says the task was close to linearly
separable, and that architecture was not the thing being measured. The frozen
build also had a fabricated temporal block in 60.3% of train rows and a group-D
provenance watermark, so some of that separability was artifact.

The probe was run ad hoc then and its code was never committed -- the same
reproducibility gap DATA_INTEGRITY.md 12a records. This is it, written down.

It deliberately matches `train_mt3.py`'s protocol -- same splits, same frozen
scaler, same weighted loss, same class weighting, same metrics -- so the ONLY
difference against MT3 is the model. Anything else and the comparison measures
the protocol.

READ THE EXCLUDE-BENIGN COLUMN. `final_v2` ships BENIGN (label 45) and all
193,000 benign rows are CIC/UNSW netflow, which separates from Cowrie at AUC
1.0000 on source alone (12b). BENIGN is therefore the easiest class in the
dataset for any model, and including it inflates every macro-F1. The report
gives macro-F1 with and without it; the without column is the one that answers
"is the attack taxonomy linearly separable".
"""
from __future__ import annotations

import json
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, Optional

import numpy as np

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from .data import TensorBatcher, load_dataset, load_label_names  # noqa: E402
from .evaluate import pick_device, predict  # noqa: E402
from .losses import build_class_weights, build_state_criterion  # noqa: E402
from .metrics import classification_metrics  # noqa: E402


@dataclass
class ProbeConfig:
    model: str = "linear"
    data_dir: str = "honeypot_dataset/data/final_v2"
    out_dir: str = "ml_analytics/artifacts/linear_probe_final_v2"
    epochs: int = 20
    batch_size: int = 4096
    lr: float = 1e-3
    weight_decay: float = 0.0
    loss: str = "weighted_ce"
    class_weight: str = "balanced"
    seed: int = 42
    device: str = "auto"
    amp: bool = False


def macro_f1_excluding(y_true: np.ndarray, y_pred: np.ndarray, drop: int) -> Dict[str, float]:
    """Macro-F1 over the classes actually present, with one label removed.

    Not the same as deleting a column from the confusion matrix: rows whose TRUE
    label is `drop` are removed entirely, so a model is neither rewarded nor
    punished for how it handles them.
    """
    from sklearn.metrics import f1_score

    keep = y_true != drop
    yt, yp = y_true[keep], y_pred[keep]
    present = np.unique(yt)
    return {
        "n_samples": int(keep.sum()),
        "n_classes_present": int(len(present)),
        "macro_f1": float(f1_score(yt, yp, labels=present, average="macro", zero_division=0)),
        "accuracy": float((yt == yp).mean()),
    }


def run(cfg: ProbeConfig) -> Dict[str, object]:
    import torch
    import torch.nn as nn

    out_dir = Path(cfg.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    device = pick_device(cfg.device)
    torch.manual_seed(cfg.seed)
    np.random.seed(cfg.seed)

    splits, provenance = load_dataset(
        Path(cfg.data_dir), splits=("train", "val", "test_real", "test_synth"),
        verbose=True,
    )
    train_sp, val_sp = splits["train"], splits["val"]
    label_names = load_label_names()

    n_labels = int(max(train_sp.y.max(), val_sp.y.max())) + 1
    n_features = train_sp.X.shape[1]

    if cfg.model == "linear":
        # one linear layer, no hidden units, no nonlinearity: the floor
        model = nn.Linear(n_features, n_labels).to(device)
        desc = f"nn.Linear({n_features}, {n_labels})"
    elif cfg.model == "cnn_lstm":
        from ml_analytics.models.cnn_lstm import CNNLSTM

        # class_weights are deliberately NOT passed: the model would then apply
        # its own internal loss, and this script uses the SAME external
        # criterion as MT3 and the probe. Parity of protocol is the whole point.
        model = CNNLSTM(n_features=n_features, n_classes=n_labels).to(device)
        desc = f"CNNLSTM(n_classes={n_labels})"
    else:
        raise ValueError(f"unknown --model {cfg.model!r}")
    n_params = sum(p.numel() for p in model.parameters())
    print(f"[probe] {cfg.model}: {desc} = {n_params:,} parameters")

    weights = build_class_weights(train_sp.y, n_labels, scheme=cfg.class_weight)
    criterion = build_state_criterion(cfg.loss, weights, device=device)
    opt = torch.optim.AdamW(model.parameters(), lr=cfg.lr, weight_decay=cfg.weight_decay)

    batcher = TensorBatcher(train_sp.X, train_sp.y, cfg.batch_size,
                            shuffle=True, device=device)
    best = {"macro_f1": -1.0, "epoch": -1, "state": None}
    for epoch in range(1, cfg.epochs + 1):
        model.train()
        t0, tot, seen = time.perf_counter(), 0.0, 0
        for xb, yb in batcher:
            opt.zero_grad(set_to_none=True)
            raw = model(xb)
            logits = raw[0] if isinstance(raw, (tuple, list)) else raw
            loss = criterion(logits, yb)
            loss.backward()
            opt.step()
            tot += float(loss) * len(yb); seen += len(yb)
        pr = predict(model, val_sp.X, device=device, batch_size=16384, return_probs=False)
        vm = classification_metrics(val_sp.y, pr["y_pred"], label_names=label_names,
                                    include_confusion=False)
        flag = ""
        if vm["macro_f1"] > best["macro_f1"]:
            best = {"macro_f1": vm["macro_f1"], "epoch": epoch,
                    "state": {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}}
            flag = " *BEST*"
        print(f"[probe] epoch {epoch:3d}/{cfg.epochs} loss={tot / max(seen,1):.4f} "
              f"| val macroF1={vm['macro_f1']:.4f} acc={vm['accuracy']:.4f} "
              f"| {time.perf_counter() - t0:.0f}s{flag}")

    model.load_state_dict(best["state"])
    report: Dict[str, object] = {
        "config": asdict(cfg), "model": cfg.model, "n_params": int(n_params), "n_labels": n_labels,
        "best_val_macro_f1": best["macro_f1"], "best_epoch": best["epoch"],
        "provenance": {k: provenance.get(k) for k in ("scaler_class", "dataset_card")},
        "splits": {},
    }
    benign_idx = n_labels - 1 if n_labels > 45 else None
    for name in ("test_real", "test_synth"):
        sp = splits[name]
        pr = predict(model, sp.X, device=device, batch_size=16384, return_probs=False)
        m = classification_metrics(sp.y, pr["y_pred"], label_names=label_names,
                                   include_confusion=False)
        entry = {
            "n_samples": m["n_samples"],
            "n_classes_present": m["n_classes_present"],
            "macro_f1": m["macro_f1"],
            "macro_f1_all45": m["macro_f1_all45"],
            "accuracy": m["accuracy"],
            "balanced_accuracy": m["balanced_accuracy"],
            "per_class": m["per_class"],
        }
        if benign_idx is not None and (sp.y == benign_idx).any():
            entry["excluding_benign"] = macro_f1_excluding(sp.y, pr["y_pred"], benign_idx)
            entry["benign_f1"] = m["per_class"].get("BENIGN", {}).get("f1")
        report["splits"][name] = entry
        np.savez_compressed(out_dir / f"preds_{name}.npz",
                            y_true=sp.y, y_pred=pr["y_pred"])
        line = (f"[probe] {name:11s} n={entry['n_samples']:,} "
                f"cls={entry['n_classes_present']:2d} macroF1={entry['macro_f1']:.4f} "
                f"acc={entry['accuracy']:.4f}")
        if "excluding_benign" in entry:
            line += (f" | excl BENIGN macroF1={entry['excluding_benign']['macro_f1']:.4f} "
                     f"(BENIGN f1={entry['benign_f1']:.4f})")
        print(line)

    (out_dir / "metrics.json").write_text(json.dumps(report, indent=2, default=str),
                                          encoding="utf-8")
    print(f"[probe] saved -> {out_dir / 'metrics.json'}")
    return report


def main(argv: Optional[list] = None) -> int:
    import argparse

    d = ProbeConfig()
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--model", choices=("linear", "cnn_lstm"), default=d.model)
    p.add_argument("--data-dir", default=d.data_dir)
    p.add_argument("--out-dir", default=d.out_dir)
    p.add_argument("--epochs", type=int, default=d.epochs)
    p.add_argument("--batch-size", type=int, default=d.batch_size)
    p.add_argument("--lr", type=float, default=d.lr)
    p.add_argument("--loss", choices=("ce", "weighted_ce", "focal"), default=d.loss)
    p.add_argument("--class-weight",
                   choices=("none", "balanced", "inv_sqrt", "effective"),
                   default=d.class_weight)
    p.add_argument("--seed", type=int, default=d.seed)
    p.add_argument("--device", default=d.device)
    a = p.parse_args(argv)
    run(ProbeConfig(**vars(a)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
