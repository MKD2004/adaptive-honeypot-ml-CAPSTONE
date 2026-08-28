"""
Train MT3 on the frozen HoneySynth dataset, then evaluate + save predictions.

Protocol (fixed by ml_analytics/README.md so CNN-LSTM and MT3 are comparable):
  * splits   honeypot_dataset/data/final/{X,y}_{train,val,test_real,test_synth}.npy
             -- used as-is, never re-split
  * scaler   data/final/feature_scaler.pkl -- loaded, never re-fit; the splits are
             already transformed by it (see data.py), so it is NOT re-applied
  * metrics  macro-F1 (primary), per-class F1, accuracy, confusion matrix
  * headline X_test_real (60k, 21 real classes); also report X_test_synth (45 cls)
  * predictions saved for both test splits so the two models are compared on
    identical rows

The architecture in ml_analytics/models/mt3.py is read-only here. The loss is
built in losses.py rather than using MT3.forward's built-in (unweighted) loss,
because the prompt requires class-weighted / focal training -- see losses.py.

Typical DGX run (launch detached, see DGX.md):
    tmux new -s mt3
    python -m ml_analytics.mt3_pipeline.train_mt3 \
        --out-dir ml_analytics/artifacts/mt3 \
        --epochs 30 --batch-size 1024 --lr 3e-4 --amp --cache-on-device
    # Ctrl-b d to detach

Smoke run (laptop, seconds):
    python -m ml_analytics.mt3_pipeline.train_mt3 --smoke
"""
from __future__ import annotations

import argparse
import json
import math
import os
import platform
import random
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, List, Optional, Sequence

import numpy as np

if __package__ in (None, ""):  # allow `python ml_analytics/mt3_pipeline/train_mt3.py`
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    __package__ = "ml_analytics.mt3_pipeline"

from .data import (  # noqa: E402
    DEFAULT_DATA_DIR,
    N_CLASSES,
    REPO_ROOT,
    TensorBatcher,
    class_counts,
    load_dataset,
    load_label_names,
)
from .evaluate import evaluate_checkpoint, pick_device, predict  # noqa: E402
from .losses import MT3Objective, build_class_weights, build_state_criterion  # noqa: E402
from .metrics import classification_metrics, format_metrics_line, per_class_table  # noqa: E402

DEFAULT_OUT_DIR = REPO_ROOT / "ml_analytics" / "artifacts" / "mt3"


# --------------------------------------------------------------------------- #
# config
# --------------------------------------------------------------------------- #

@dataclass
class TrainConfig:
    data_dir: str = str(DEFAULT_DATA_DIR)
    out_dir: str = str(DEFAULT_OUT_DIR)
    epochs: int = 30
    batch_size: int = 1024
    eval_batch_size: int = 4096
    lr: float = 3e-4
    weight_decay: float = 0.01
    warmup_frac: float = 0.03
    min_lr_frac: float = 0.05
    grad_clip: float = 1.0
    # model (mt3.MT3 constructor args -- architecture defaults, do not tune silently)
    d_model: int = 64
    nhead: int = 4
    num_fusion_layers: int = 2
    dropout: float = 0.1
    aux_loss_weight: float = 0.3
    # objective
    loss: str = "weighted_ce"
    class_weight: str = "balanced"
    focal_gamma: float = 1.5
    label_smoothing: float = 0.0
    weight_clip: float = 20.0
    # runtime
    device: str = "auto"
    amp: bool = False
    cache_on_device: bool = False
    seed: int = 42
    early_stop_patience: int = 5
    max_steps_per_epoch: int = 0        # 0 = full epoch
    limit_train: int = 0                # 0 = all rows
    limit_val: int = 0
    log_every: int = 100
    resume: bool = False
    eval_after_train: bool = True
    save_probs: bool = True


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def set_seed(seed: int) -> None:
    import torch

    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def _amp_dtype(device: str):
    import torch

    if not device.startswith("cuda"):
        return None
    try:
        if torch.cuda.is_bf16_supported():
            return torch.bfloat16
    except Exception:
        pass
    return torch.float16


def build_scheduler(optimizer, total_steps: int, warmup_frac: float, min_lr_frac: float):
    """Linear warmup -> cosine decay to min_lr_frac * lr."""
    import torch

    warmup = max(1, int(total_steps * warmup_frac))

    def lr_lambda(step: int) -> float:
        if step < warmup:
            return (step + 1) / warmup
        progress = (step - warmup) / max(1, total_steps - warmup)
        progress = min(1.0, progress)
        cosine = 0.5 * (1.0 + math.cos(math.pi * progress))
        return min_lr_frac + (1.0 - min_lr_frac) * cosine

    return torch.optim.lr_scheduler.LambdaLR(optimizer, lr_lambda)


def _model_kwargs(cfg: TrainConfig) -> Dict[str, object]:
    return {
        "d_model": cfg.d_model,
        "nhead": cfg.nhead,
        "num_fusion_layers": cfg.num_fusion_layers,
        "dropout": cfg.dropout,
        "aux_loss_weight": cfg.aux_loss_weight,
    }


def _env_record(device: str) -> Dict[str, object]:
    import torch

    rec = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "torch": torch.__version__,
        "device": device,
        "cuda_available": bool(torch.cuda.is_available()),
    }
    if torch.cuda.is_available():
        try:
            rec["gpu"] = torch.cuda.get_device_name(0)
            rec["gpu_mem_gb"] = round(torch.cuda.get_device_properties(0).total_memory / 1e9, 1)
        except Exception:
            pass
    return rec


# --------------------------------------------------------------------------- #
# train / validate
# --------------------------------------------------------------------------- #

def run_epoch(
    model, batcher, objective, optimizer, scheduler, scaler, cfg: TrainConfig,
    device: str, amp_dtype, epoch: int, max_steps: int = 0,
) -> Dict[str, float]:
    import torch

    model.train()
    tot = tot_state = tot_phase = 0.0
    seen = correct = 0
    t0 = time.time()
    n_batches = len(batcher) if not max_steps else min(len(batcher), max_steps)

    for step, (xb, yb) in enumerate(batcher):
        if max_steps and step >= max_steps:
            break
        optimizer.zero_grad(set_to_none=True)

        if amp_dtype is not None and cfg.amp:
            with torch.autocast(device_type="cuda", dtype=amp_dtype):
                emissions, hp_logits, _ = model(xb)          # labels omitted on purpose
                loss, state_loss, phase_loss = objective(emissions, hp_logits, yb)
        else:
            emissions, hp_logits, _ = model(xb)
            loss, state_loss, phase_loss = objective(emissions, hp_logits, yb)

        if not torch.isfinite(loss):
            raise RuntimeError(f"non-finite loss at epoch {epoch} step {step}: {loss.item()}")

        if scaler is not None and scaler.is_enabled():
            scaler.scale(loss).backward()
            scaler.unscale_(optimizer)
            torch.nn.utils.clip_grad_norm_(model.parameters(), cfg.grad_clip)
            scaler.step(optimizer)
            scaler.update()
        else:
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), cfg.grad_clip)
            optimizer.step()
        scheduler.step()

        bs = yb.shape[0]
        tot += float(loss.detach()) * bs
        tot_state += float(state_loss) * bs
        tot_phase += float(phase_loss) * bs
        correct += int((emissions.detach().argmax(1) == yb).sum())
        seen += bs

        if cfg.log_every and (step + 1) % cfg.log_every == 0:
            print(
                f"[train] epoch {epoch:3d} step {step + 1:5d}/{n_batches} "
                f"loss={tot / seen:.4f} acc={correct / seen:.4f} "
                f"lr={scheduler.get_last_lr()[0]:.2e} "
                f"({seen / max(1e-9, time.time() - t0):,.0f} rows/s)",
                flush=True,
            )

    dt = time.time() - t0
    return {
        "loss": tot / max(1, seen),
        "state_loss": tot_state / max(1, seen),
        "phase_loss": tot_phase / max(1, seen),
        "train_acc": correct / max(1, seen),
        "rows": seen,
        "seconds": round(dt, 1),
        "rows_per_s": round(seen / max(1e-9, dt), 1),
    }


def validate(model, split, label_names, device, cfg: TrainConfig) -> Dict[str, object]:
    pr = predict(
        model, split.X, device=device, batch_size=cfg.eval_batch_size,
        amp=cfg.amp, return_probs=False,
    )
    return classification_metrics(
        split.y, pr["y_pred"], label_names=label_names, include_confusion=False
    )


def save_checkpoint(path: Path, model, optimizer, scheduler, scaler, cfg, epoch,
                    best_val, history, provenance, class_weights) -> None:
    """Full-state checkpoint (model + optimizer + scheduler + AMP scaler + RNG).

    Full state, not weights-only: DECISIONS.md 2026-08-25 records losing a ~5h run
    to a weights-only checkpoint that could not restore the schedule.
    """
    import torch

    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "model_state": model.state_dict(),
        "model_kwargs": _model_kwargs(cfg),
        "optimizer_state": optimizer.state_dict(),
        "scheduler_state": scheduler.state_dict(),
        "amp_scaler_state": scaler.state_dict() if scaler is not None else None,
        "epoch": epoch,
        "best_val_macro_f1": best_val,
        "config": asdict(cfg),
        "history": history,
        "provenance": provenance,
        "class_weights": None if class_weights is None else np.asarray(class_weights).tolist(),
        "rng_state": {
            "python": random.getstate(),
            "numpy": np.random.get_state(),
            "torch": torch.get_rng_state(),
        },
    }
    tmp = path.with_suffix(path.suffix + ".tmp")
    torch.save(payload, str(tmp))
    os.replace(tmp, path)  # atomic


def train(cfg: TrainConfig) -> Dict[str, object]:
    import torch

    out_dir = Path(cfg.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    device = pick_device(cfg.device)
    set_seed(cfg.seed)

    limits: Dict[str, int] = {}
    if cfg.limit_train:
        limits["train"] = cfg.limit_train
    if cfg.limit_val:
        limits["val"] = cfg.limit_val

    splits, provenance = load_dataset(
        Path(cfg.data_dir), splits=("train", "val"), limits=limits, verbose=True
    )
    provenance["env"] = _env_record(device)
    train_sp, val_sp = splits["train"], splits["val"]
    label_names = load_label_names()

    # ---- objective -------------------------------------------------------- #
    weights = build_class_weights(
        train_sp.y, N_CLASSES, scheme=cfg.class_weight, clip=cfg.weight_clip
    )
    state_criterion = build_state_criterion(
        cfg.loss, weights, focal_gamma=cfg.focal_gamma,
        label_smoothing=cfg.label_smoothing, device=device,
    )

    from ml_analytics.models.mt3 import MT3

    model = MT3(**_model_kwargs(cfg)).to(device)
    objective = MT3Objective(
        state_criterion, model.idx_to_phase, aux_loss_weight=cfg.aux_loss_weight, device=device
    ).to(device)

    counts = class_counts(train_sp.y)
    print(f"[model] MT3 d_model={cfg.d_model} heads={cfg.nhead} layers={cfg.num_fusion_layers} "
          f"params={model.count_parameters():,} device={device}")
    print(f"[loss ] {cfg.loss} (class_weight={cfg.class_weight}, aux_weight={cfg.aux_loss_weight}"
          + (f", gamma={cfg.focal_gamma}" if cfg.loss == "focal" else "") + ")")
    print(f"[loss ] train class counts: min={counts[counts > 0].min():,} max={counts.max():,} "
          f"imbalance={counts.max() / max(1, counts[counts > 0].min()):.1f}x"
          + (f"; weights [{weights[weights > 0].min():.3f}, {weights.max():.3f}]" if weights is not None else ""))

    # ---- optimiser / schedule --------------------------------------------- #
    decay, no_decay = [], []
    for name, p in model.named_parameters():
        if not p.requires_grad:
            continue
        (no_decay if p.ndim <= 1 or name.endswith("branch_pos_embed") else decay).append(p)
    optimizer = torch.optim.AdamW(
        [{"params": decay, "weight_decay": cfg.weight_decay},
         {"params": no_decay, "weight_decay": 0.0}],
        lr=cfg.lr, betas=(0.9, 0.999), eps=1e-8,
    )

    train_batcher = TensorBatcher(
        train_sp.X, train_sp.y, cfg.batch_size, shuffle=True, device=device,
        cache_on_device=cfg.cache_on_device, seed=cfg.seed, drop_last=False,
    )
    steps_per_epoch = len(train_batcher) if not cfg.max_steps_per_epoch else min(
        len(train_batcher), cfg.max_steps_per_epoch
    )
    scheduler = build_scheduler(
        optimizer, steps_per_epoch * cfg.epochs, cfg.warmup_frac, cfg.min_lr_frac
    )

    amp_dtype = _amp_dtype(device)
    use_grad_scaler = bool(cfg.amp and amp_dtype is torch.float16)
    scaler = torch.amp.GradScaler("cuda", enabled=use_grad_scaler) if device.startswith("cuda") else None
    if cfg.amp:
        print(f"[amp  ] enabled dtype={amp_dtype} grad_scaler={use_grad_scaler}")

    # ---- resume ------------------------------------------------------------ #
    start_epoch, best_val, best_epoch, history = 1, -1.0, -1, []
    last_path, best_path = out_dir / "last.pt", out_dir / "best.pt"
    if cfg.resume and last_path.exists():
        ck = torch.load(str(last_path), map_location=device, weights_only=False)
        model.load_state_dict(ck["model_state"])
        optimizer.load_state_dict(ck["optimizer_state"])
        scheduler.load_state_dict(ck["scheduler_state"])
        if scaler is not None and ck.get("amp_scaler_state"):
            scaler.load_state_dict(ck["amp_scaler_state"])
        start_epoch = int(ck["epoch"]) + 1
        best_val = float(ck.get("best_val_macro_f1", -1.0))
        history = list(ck.get("history", []))
        print(f"[resume] from {last_path} at epoch {start_epoch} (best val macro-F1 {best_val:.4f})")

    # ---- loop --------------------------------------------------------------- #
    hist_path = out_dir / "history.jsonl"
    epochs_no_improve = 0
    print(f"[train] {len(train_sp):,} train rows, {len(val_sp):,} val rows, "
          f"{steps_per_epoch:,} steps/epoch x {cfg.epochs} epochs")

    for epoch in range(start_epoch, cfg.epochs + 1):
        tr = run_epoch(model, train_batcher, objective, optimizer, scheduler, scaler,
                       cfg, device, amp_dtype, epoch, cfg.max_steps_per_epoch)
        vm = validate(model, val_sp, label_names, device, cfg)
        row = {
            "epoch": epoch,
            **{k: v for k, v in tr.items()},
            "val_macro_f1": vm["macro_f1"],
            "val_macro_f1_all45": vm["macro_f1_all45"],
            "val_acc": vm["accuracy"],
            "val_weighted_f1": vm["weighted_f1"],
            "val_phase_macro_f1": vm["phase"]["macro_f1"],
            "lr": scheduler.get_last_lr()[0],
        }
        history.append(row)
        with hist_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(row) + "\n")

        improved = vm["macro_f1"] > best_val
        print(
            f"[epoch] {epoch:3d}/{cfg.epochs} loss={tr['loss']:.4f} "
            f"(state {tr['state_loss']:.4f} / phase {tr['phase_loss']:.4f}) "
            f"train_acc={tr['train_acc']:.4f} | val macroF1={vm['macro_f1']:.4f} "
            f"acc={vm['accuracy']:.4f} phaseF1={vm['phase']['macro_f1']:.4f} "
            f"| {tr['seconds']:.0f}s {'*BEST*' if improved else ''}",
            flush=True,
        )

        save_checkpoint(last_path, model, optimizer, scheduler, scaler, cfg, epoch,
                        best_val if not improved else vm["macro_f1"], history,
                        provenance, weights)
        if improved:
            best_val, best_epoch, epochs_no_improve = vm["macro_f1"], epoch, 0
            save_checkpoint(best_path, model, optimizer, scheduler, scaler, cfg, epoch,
                            best_val, history, provenance, weights)
        else:
            epochs_no_improve += 1
            if cfg.early_stop_patience and epochs_no_improve >= cfg.early_stop_patience:
                print(f"[train] early stop: no val macro-F1 improvement for "
                      f"{epochs_no_improve} epochs (best {best_val:.4f} @ epoch {best_epoch})")
                break

    print(f"[train] done. best val macro-F1 {best_val:.4f} @ epoch {best_epoch} -> {best_path}")
    summary: Dict[str, object] = {
        "best_val_macro_f1": best_val,
        "best_epoch": best_epoch,
        "epochs_run": history[-1]["epoch"] if history else 0,
        "config": asdict(cfg),
        "provenance": provenance,
    }

    if history:
        final_val = validate(model, val_sp, label_names, device, cfg)
        print("\n[val  ] worst per-class F1 at final epoch")
        print(per_class_table(final_val, top_n=10))

    if cfg.eval_after_train and best_path.exists():
        print("\n[eval ] evaluating BEST checkpoint on the frozen test splits")
        results = evaluate_checkpoint(
            best_path, data_dir=Path(cfg.data_dir), out_dir=out_dir, device=device,
            batch_size=cfg.eval_batch_size, amp=cfg.amp, model_name="mt3",
            save_probs=cfg.save_probs,
        )
        summary["test"] = {
            k: {kk: vv for kk, vv in v.items() if kk not in ("confusion_matrix", "per_class")}
            for k, v in results.items()
        }

    (out_dir / "train_summary.json").write_text(json.dumps(summary, indent=2, default=str))
    return summary


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    d = TrainConfig()
    p = argparse.ArgumentParser(
        description="Train + evaluate MT3 on the frozen HoneySynth splits",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("--data-dir", default=d.data_dir)
    p.add_argument("--out-dir", default=d.out_dir)
    p.add_argument("--epochs", type=int, default=d.epochs)
    p.add_argument("--batch-size", type=int, default=d.batch_size)
    p.add_argument("--eval-batch-size", type=int, default=d.eval_batch_size)
    p.add_argument("--lr", type=float, default=d.lr)
    p.add_argument("--weight-decay", type=float, default=d.weight_decay)
    p.add_argument("--warmup-frac", type=float, default=d.warmup_frac)
    p.add_argument("--grad-clip", type=float, default=d.grad_clip)
    p.add_argument("--d-model", type=int, default=d.d_model)
    p.add_argument("--nhead", type=int, default=d.nhead)
    p.add_argument("--num-fusion-layers", type=int, default=d.num_fusion_layers)
    p.add_argument("--dropout", type=float, default=d.dropout)
    p.add_argument("--aux-loss-weight", type=float, default=d.aux_loss_weight)
    p.add_argument("--loss", choices=("ce", "weighted_ce", "focal"), default=d.loss)
    p.add_argument("--class-weight", choices=("none", "balanced", "inv_sqrt", "effective"),
                   default=d.class_weight)
    p.add_argument("--focal-gamma", type=float, default=d.focal_gamma)
    p.add_argument("--label-smoothing", type=float, default=d.label_smoothing)
    p.add_argument("--device", default=d.device)
    p.add_argument("--amp", action="store_true")
    p.add_argument("--cache-on-device", action="store_true",
                   help="park the whole train split in GPU memory (fast; ~400MB for 756k rows)")
    p.add_argument("--seed", type=int, default=d.seed)
    p.add_argument("--early-stop-patience", type=int, default=d.early_stop_patience)
    p.add_argument("--max-steps-per-epoch", type=int, default=d.max_steps_per_epoch)
    p.add_argument("--limit-train", type=int, default=d.limit_train)
    p.add_argument("--limit-val", type=int, default=d.limit_val)
    p.add_argument("--log-every", type=int, default=d.log_every)
    p.add_argument("--resume", action="store_true")
    p.add_argument("--no-eval", action="store_true", help="skip the post-training test evaluation")
    p.add_argument("--no-probs", action="store_true", help="do not save softmax probabilities")
    p.add_argument("--smoke", action="store_true",
                   help="tiny end-to-end run: 2 epochs on a stratified subsample")
    return p


def cfg_from_args(a: argparse.Namespace) -> TrainConfig:
    cfg = TrainConfig(
        data_dir=a.data_dir, out_dir=a.out_dir, epochs=a.epochs, batch_size=a.batch_size,
        eval_batch_size=a.eval_batch_size, lr=a.lr, weight_decay=a.weight_decay,
        warmup_frac=a.warmup_frac, grad_clip=a.grad_clip, d_model=a.d_model, nhead=a.nhead,
        num_fusion_layers=a.num_fusion_layers, dropout=a.dropout,
        aux_loss_weight=a.aux_loss_weight, loss=a.loss, class_weight=a.class_weight,
        focal_gamma=a.focal_gamma, label_smoothing=a.label_smoothing, device=a.device,
        amp=a.amp, cache_on_device=a.cache_on_device, seed=a.seed,
        early_stop_patience=a.early_stop_patience, max_steps_per_epoch=a.max_steps_per_epoch,
        limit_train=a.limit_train, limit_val=a.limit_val, log_every=a.log_every,
        resume=a.resume, eval_after_train=not a.no_eval, save_probs=not a.no_probs,
    )
    if a.smoke:
        cfg.epochs = 2
        cfg.limit_train = a.limit_train or 20_000
        cfg.limit_val = a.limit_val or 5_000
        cfg.batch_size = 512
        cfg.log_every = 10
        cfg.early_stop_patience = 0
        cfg.out_dir = a.out_dir if a.out_dir != str(DEFAULT_OUT_DIR) else str(
            REPO_ROOT / "ml_analytics" / "artifacts" / "mt3_smoke"
        )
    return cfg


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    cfg = cfg_from_args(args)
    train(cfg)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
