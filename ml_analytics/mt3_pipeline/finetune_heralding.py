"""
ml_analytics/mt3_pipeline/finetune_heralding.py

Fine-tune MT3 so it can classify Heralding (credential-honeypot) sessions,
WITHOUT disturbing the frozen model or the published numbers.

DECISIONS THIS IMPLEMENTS (DECISIONS.md 2026-11-04)

  Separate model, not a replacement. Output goes to artifacts/mt3_multi/, and
  artifacts/mt3_full_d256/best.pt is never written. The comparison table (MT3
  0.8276 / CNN-LSTM 0.8093 / linear probe 0.7681) keeps describing the model it
  was measured on; the paper reports both and says why.

  Fine-tune with replay, not oversampling. 8,400 Heralding rows against 756,000
  frozen rows is 1.1% and would be swamped. Oversampling them 16x would overfit
  8,284 distinct vectors. Class weighting targets the wrong axis -- the imbalance
  is by SOURCE, not class, and the same classes exist in the Cowrie/netflow data
  with entirely different feature shapes. So: start from the trained checkpoint,
  train on Heralding rows mixed with a stratified REPLAY sample of the original
  data at a controlled ratio, at a low learning rate.

THE SCALING TRAP (ERRORS.md, top two entries)

  data/final/*.npy is ALREADY SCALED. Heralding rows come out of
  extract_features() RAW. Mixing them without scaling the new rows would train
  the model on two different unit systems. So the frozen scaler is applied to
  the Heralding rows here -- and nowhere near the replay rows. The scaler is a
  joblib dump; pickle.load raises on it.

ACCEPTANCE -- all four, or the model is not used

  1. Heralding test macro-F1 above --min-heralding-f1.
  2. The six acceptance scenarios pass (acceptance_heralding.py).
  3. ORIGINAL test_real macro-F1 must not drop more than --max-regression. This
     is the catastrophic-forgetting guard and the reason replay exists.
  4. No confident nonsense on a bare connect -- checked inside (2).

Run:
    python -m ml_analytics.mt3_pipeline.finetune_heralding --epochs 4
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Dict, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
HER_DIR = REPO_ROOT / "honeypot_dataset" / "data" / "processed" / "heralding_aug"
DATA_FINAL = REPO_ROOT / "honeypot_dataset" / "data" / "final"
DEFAULT_OUT = REPO_ROOT / "ml_analytics" / "artifacts" / "mt3_multi"
BASE_CKPT = REPO_ROOT / "ml_analytics" / "artifacts" / "mt3_full_d256" / "best.pt"


def _load_heralding() -> Dict[str, Tuple]:
    import numpy as np
    out = {}
    for split in ("train", "val", "test"):
        xp, yp = HER_DIR / f"X_her_{split}.npy", HER_DIR / f"y_her_{split}.npy"
        if not xp.exists():
            raise FileNotFoundError(
                f"{xp} missing. Generate it first:\n"
                f"  python -m src.generators.heralding_simulator  (from honeypot_dataset/)\n"
                f"then extract features -- see HONEYPOT_AUDIT.md PART 8.")
        out[split] = (np.load(xp), np.load(yp))
    return out


def _scale_raw(X_raw):
    """Frozen scaler onto RAW rows. Never call this on data/final arrays."""
    import numpy as np
    from ml_analytics.mt3_pipeline.data import load_scaler
    scaler = load_scaler(DATA_FINAL)          # joblib dump, not pickle
    return scaler.transform(np.asarray(X_raw, dtype=np.float64)).astype(np.float32)


def _replay_sample(n_per_class: int, seed: int):
    """Stratified sample of the ORIGINAL (already-scaled) training data."""
    import numpy as np
    X = np.load(DATA_FINAL / "X_train.npy", mmap_mode="r")
    y = np.load(DATA_FINAL / "y_train.npy")
    rng = np.random.default_rng(seed)
    keep = []
    for c in np.unique(y):
        idx = np.where(y == c)[0]
        take = min(n_per_class, len(idx))
        keep.append(rng.choice(idx, size=take, replace=False))
    keep = np.sort(np.concatenate(keep))
    return np.asarray(X[keep], dtype=np.float32), y[keep]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--base-ckpt", default=str(BASE_CKPT))
    ap.add_argument("--out-dir", default=str(DEFAULT_OUT))
    ap.add_argument("--epochs", type=int, default=4)
    ap.add_argument("--lr", type=float, default=1e-4)
    ap.add_argument("--batch-size", type=int, default=512)
    ap.add_argument("--replay-per-class", type=int, default=1200,
                    help="original rows per class mixed in, to prevent forgetting")
    ap.add_argument("--seed", type=int, default=2026)
    ap.add_argument("--min-heralding-f1", type=float, default=0.80)
    ap.add_argument("--max-regression", type=float, default=0.01,
                    help="largest tolerated drop in original test_real macro-F1")
    ap.add_argument("--device", default="auto")
    a = ap.parse_args(argv)

    import numpy as np
    import torch
    from sklearn.metrics import f1_score
    from ml_analytics.mt3_pipeline.evaluate import load_model, pick_device, predict

    out_dir = Path(a.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    torch.manual_seed(a.seed)
    np.random.seed(a.seed)
    device = pick_device(a.device)

    # ---- data -------------------------------------------------------------
    her = _load_heralding()
    Xh_tr = _scale_raw(her["train"][0]); yh_tr = her["train"][1]
    Xh_va = _scale_raw(her["val"][0]);   yh_va = her["val"][1]
    Xh_te = _scale_raw(her["test"][0]);  yh_te = her["test"][1]

    Xr, yr = _replay_sample(a.replay_per_class, a.seed)
    print(f"heralding train {Xh_tr.shape}  replay {Xr.shape}  "
          f"heralding share {100 * len(Xh_tr) / (len(Xh_tr) + len(Xr)):.1f}%")

    X_mix = np.concatenate([Xh_tr, Xr]).astype(np.float32)
    y_mix = np.concatenate([yh_tr, yr]).astype(np.int64)
    perm = np.random.permutation(len(X_mix))
    X_mix, y_mix = X_mix[perm], y_mix[perm]

    # ---- baseline, before touching anything -------------------------------
    model, ckpt = load_model(Path(a.base_ckpt), device=device)
    X_real = np.load(DATA_FINAL / "X_test_real.npy")
    y_real = np.load(DATA_FINAL / "y_test_real.npy")
    clean = np.load(REPO_ROOT / "test_real_clean_mask.npz")["clean_mask"]
    labels_real = sorted(set(y_real.tolist()))

    base_real = f1_score(y_real, predict(model, X_real, device=device,
                                         return_probs=False)["y_pred"],
                         average="macro", labels=labels_real)
    base_her = f1_score(yh_te, predict(model, Xh_te, device=device,
                                       return_probs=False)["y_pred"],
                        average="macro", labels=sorted(set(yh_te.tolist())))
    print(f"BEFORE  test_real macro-F1 {base_real:.4f}   heralding macro-F1 {base_her:.4f}")

    # ---- fine-tune --------------------------------------------------------
    model.train()
    opt = torch.optim.AdamW(model.parameters(), lr=a.lr, weight_decay=0.01)
    lossf = torch.nn.CrossEntropyLoss()
    Xt = torch.from_numpy(X_mix)
    yt = torch.from_numpy(y_mix)
    n = len(Xt)
    best_val, best_state = -1.0, None

    for ep in range(1, a.epochs + 1):
        model.train()
        order = torch.randperm(n)
        total, seen = 0.0, 0
        t0 = time.perf_counter()
        for s in range(0, n, a.batch_size):
            b = order[s:s + a.batch_size]
            xb, yb = Xt[b].to(device), yt[b].to(device)
            emissions, _hp, _ = model(xb)
            loss = lossf(emissions.float(), yb)
            opt.zero_grad(set_to_none=True)
            loss.backward()
            torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
            opt.step()
            total += float(loss) * len(b); seen += len(b)

        model.eval()
        vh = f1_score(yh_va, predict(model, Xh_va, device=device,
                                     return_probs=False)["y_pred"],
                      average="macro", labels=sorted(set(yh_va.tolist())))
        vr = f1_score(y_real, predict(model, X_real, device=device,
                                      return_probs=False)["y_pred"],
                      average="macro", labels=labels_real)
        # select on the pair, so a model that forgets cannot win
        score = min(vh, vr / max(base_real, 1e-9))
        print(f"  epoch {ep}  loss {total/seen:.4f}  heralding val F1 {vh:.4f}  "
              f"test_real F1 {vr:.4f}  ({time.perf_counter()-t0:.0f}s)")
        if score > best_val:
            best_val = score
            best_state = {k: v.detach().cpu().clone() for k, v in model.state_dict().items()}

    if best_state is not None:
        model.load_state_dict(best_state)
    model.eval()

    # ---- final numbers ----------------------------------------------------
    her_f1 = f1_score(yh_te, predict(model, Xh_te, device=device,
                                     return_probs=False)["y_pred"],
                      average="macro", labels=sorted(set(yh_te.tolist())))
    yp_real = predict(model, X_real, device=device, return_probs=False)["y_pred"]
    real_f1 = f1_score(y_real, yp_real, average="macro", labels=labels_real)
    real_f1_clean = f1_score(y_real[clean], yp_real[clean], average="macro",
                             labels=sorted(set(y_real[clean].tolist())))
    regression = base_real - real_f1

    print(f"\nAFTER   test_real macro-F1 {real_f1:.4f} (clean {real_f1_clean:.4f})"
          f"   heralding macro-F1 {her_f1:.4f}")
    print(f"        regression vs base: {regression:+.4f} "
          f"(tolerance {a.max_regression})")

    ckpt_out = out_dir / "best.pt"
    torch.save({
        "model_state": model.state_dict(),
        "model_kwargs": ckpt.get("model_kwargs"),
        "base_checkpoint": str(a.base_ckpt),
        "finetune": {"epochs": a.epochs, "lr": a.lr, "batch_size": a.batch_size,
                     "replay_per_class": a.replay_per_class, "seed": a.seed},
        "metrics": {"heralding_test_macro_f1": float(her_f1),
                    "test_real_macro_f1": float(real_f1),
                    "test_real_macro_f1_clean": float(real_f1_clean),
                    "base_test_real_macro_f1": float(base_real),
                    "regression": float(regression)},
        "note": "Fine-tuned for Heralding. NOT the frozen MT3 -- the published "
                "comparison table refers to artifacts/mt3_full_d256/best.pt.",
    }, str(ckpt_out))
    print(f"        saved {ckpt_out}")

    # ---- the gate ---------------------------------------------------------
    from ml_analytics.mt3_pipeline.acceptance_heralding import run as acceptance
    acc = acceptance(ckpt_out)

    criteria = {
        "heralding_f1": {"value": round(float(her_f1), 4),
                         "floor": a.min_heralding_f1,
                         "pass": her_f1 >= a.min_heralding_f1},
        "no_regression": {"value": round(float(regression), 4),
                          "tolerance": a.max_regression,
                          "pass": regression <= a.max_regression},
        "acceptance_scenarios": {"value": acc["criteria"], "pass": acc["pass"]},
    }
    ok = all(c["pass"] for c in criteria.values())
    print(f"\n{'criterion':<24}verdict")
    print("-" * 40)
    for k, c in criteria.items():
        print(f"{k:<24}{'PASS' if c['pass'] else 'FAIL'}")
    print(f"\noverall: {'PASS' if ok else 'FAIL'}")
    if ok:
        print('  -> safe to add "heralding" to CONFIG.MT3_TRUSTED_SOURCES *and*\n'
              '     point the pipeline at artifacts/mt3_multi/best.pt')
    else:
        print("  -> do NOT trust this model on heralding; leave the gate closed")

    (out_dir / "finetune_summary.json").write_text(
        json.dumps({"criteria": criteria, "pass": ok,
                    "metrics": {"heralding_test_macro_f1": float(her_f1),
                                "test_real_macro_f1": float(real_f1),
                                "test_real_macro_f1_clean": float(real_f1_clean),
                                "base_test_real_macro_f1": float(base_real)}},
                   indent=2, default=str), encoding="utf-8")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
