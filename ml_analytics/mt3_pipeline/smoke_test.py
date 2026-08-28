"""
End-to-end smoke test for the MT3 train/eval pipeline.

Runs fast (CPU-friendly) and checks the things that would silently corrupt the
baseline-vs-MT3 comparison rather than crash it:

  1  constants parity   mt3.py FEATURE_GROUPS / IDX_TO_PHASE == schema.py
  2  dataset integrity  files, shapes, dtypes, label range, no NaN/Inf
  3  scaler provenance  joblib-loadable, 128 features, splits ALREADY scaled
                        (re-applying it would double-scale -- asserted)
  4  model forward      shapes, finite outputs, branch slicing covers 0..127
  5  loss parity        MT3Objective(--loss ce) == MT3.forward's built-in loss
  6  class weights      finite, mean 1, zero for absent classes
  7  overfit-a-batch    the model can drive one batch to ~0 loss (wiring sane)
  8  train CLI          2 tiny epochs -> checkpoints, history, resume works
  9  evaluate CLI       predictions saved, metrics well-formed, row identity
 10  compare CLI        runs with MT3 only, and against a synthetic 2nd model

Usage (from the repo root):
    python -m ml_analytics.mt3_pipeline.smoke_test           # full
    python -m ml_analytics.mt3_pipeline.smoke_test --fast    # skip step 8's 2nd epoch
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
import traceback
from pathlib import Path
from typing import Callable, List, Optional, Sequence, Tuple

import numpy as np

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    __package__ = "ml_analytics.mt3_pipeline"

from . import data as D  # noqa: E402
from .data import DEFAULT_DATA_DIR, N_CLASSES, N_FEATURES, REPO_ROOT  # noqa: E402

SMOKE_DIR = REPO_ROOT / "ml_analytics" / "artifacts" / "smoke"

_results: List[Tuple[str, bool, str, float]] = []


def check(name: str) -> Callable:
    def deco(fn: Callable) -> Callable:
        fn._check_name = name  # type: ignore[attr-defined]
        return fn

    return deco


def _run(name: str, fn: Callable, *args) -> bool:
    t0 = time.time()
    print(f"\n--- {name} " + "-" * max(0, 60 - len(name)))
    try:
        msg = fn(*args) or "ok"
        _results.append((name, True, str(msg), time.time() - t0))
        print(f"[PASS] {name}: {msg}")
        return True
    except Exception as exc:
        _results.append((name, False, f"{type(exc).__name__}: {exc}", time.time() - t0))
        print(f"[FAIL] {name}: {type(exc).__name__}: {exc}")
        traceback.print_exc()
        return False


# --------------------------------------------------------------------------- #
# 1 constants parity
# --------------------------------------------------------------------------- #

def t_constants(data_dir: Path) -> str:
    from ml_analytics.models.mt3 import (
        DEFAULT_IDX_TO_PHASE,
        FEATURE_GROUPS as MT3_GROUPS,
        N_CLASSES as MT3_NC,
        N_FEATURES as MT3_NF,
        N_PHASES as MT3_NP,
    )

    assert MT3_NF == N_FEATURES == 128, f"n_features mismatch: {MT3_NF}"
    assert MT3_NC == N_CLASSES == 45, f"n_classes mismatch: {MT3_NC}"
    assert MT3_NP == 9
    assert DEFAULT_IDX_TO_PHASE == D.IDX_TO_PHASE, "mt3 phase map != pipeline phase map"

    # branch slices must tile 0..127 exactly, no gap and no overlap
    spans = sorted((int(g["start"]), int(g["end"])) for g in MT3_GROUPS.values())
    cursor = 0
    for s, e in spans:
        assert s == cursor, f"feature-group gap/overlap at {s} (expected {cursor})"
        cursor = e
    assert cursor == N_FEATURES, f"groups cover {cursor} features, expected {N_FEATURES}"

    detail = "mt3 vs pipeline: OK"
    ds_root = REPO_ROOT / "honeypot_dataset"
    if (ds_root / "configs" / "schema.py").exists():
        sys.path.insert(0, str(ds_root))
        try:
            from configs import schema  # type: ignore

            assert schema.N_FEATURES == 128 and schema.N_CLASSES == 45
            sch_phase = [schema.IDX_TO_PHASE[i] for i in range(45)]
            assert sch_phase == DEFAULT_IDX_TO_PHASE, "mt3 phase map != schema.py IDX_TO_PHASE"
            sch_groups = {k: (v["start"], v["end"]) for k, v in schema.FEATURE_GROUPS.items()}
            mt3_groups = {k: (v["start"], v["end"]) for k, v in MT3_GROUPS.items()}
            assert sch_groups == mt3_groups, f"group slices differ:\n{sch_groups}\n{mt3_groups}"
            detail = "mt3 == schema.py (groups, phases, sizes)"
        finally:
            sys.path.remove(str(ds_root))
    return detail


# --------------------------------------------------------------------------- #
# 2 dataset integrity
# --------------------------------------------------------------------------- #

def t_dataset(data_dir: Path) -> str:
    expected = {
        "train": (756_000, 45),
        "val": (84_000, 45),
        "test_real": (60_000, 21),
        "test_synth": (60_000, 45),
    }
    lines = []
    for name, (n_exp, cls_exp) in expected.items():
        sp = D.load_split(name, data_dir, mmap=True)
        assert sp.X.shape[1] == N_FEATURES, f"{name}: {sp.X.shape}"
        assert sp.X.dtype == np.float32, f"{name}: dtype {sp.X.dtype}"
        assert sp.y.dtype == np.int64, f"{name}: y dtype {sp.y.dtype}"
        n_cls = len(sp.classes_present)
        if len(sp) != n_exp:
            lines.append(f"{name}: n={len(sp):,} (expected {n_exp:,})")
        assert n_cls == cls_exp, f"{name}: {n_cls} classes present, expected {cls_exp}"
        chunk = np.asarray(sp.X[: min(50_000, len(sp))])
        assert np.isfinite(chunk).all(), f"{name}: non-finite values in X"
        lines.append(f"{name} n={len(sp):,} cls={n_cls}")
    return "; ".join(lines)


# --------------------------------------------------------------------------- #
# 3 scaler provenance
# --------------------------------------------------------------------------- #

def t_scaler(data_dir: Path) -> str:
    import pickle

    path = Path(data_dir) / "feature_scaler.pkl"
    scaler = D.load_scaler(data_dir)
    assert scaler.n_features_in_ == N_FEATURES

    # documents the joblib-vs-pickle trap so a regression here is loud
    plain_pickle_works = True
    try:
        with open(path, "rb") as fh:
            pickle.load(fh)
    except Exception:
        plain_pickle_works = False

    sp = D.load_split("train", data_dir, limit=20_000)
    info = D.check_scaling(sp.X, scaler)
    assert info["already_scaled"], "splits are not pre-scaled -- see data.check_scaling"

    # prove that re-applying the scaler WOULD corrupt the data (guards the rule)
    double = scaler.transform(np.asarray(sp.X[:2000], dtype=np.float64))
    drift = float(np.abs(double.mean(axis=0)).mean())
    assert drift > info["col_mean_abs"] * 5, (
        "re-applying the scaler barely changed the data -- the pre-scaled "
        "assumption needs re-checking"
    )
    return (
        f"joblib OK (plain pickle works={plain_pickle_works}); splits pre-scaled "
        f"(col |mean|={info['col_mean_abs']:.4f}, re-transform would give {drift:.4f})"
    )


# --------------------------------------------------------------------------- #
# 4 model forward
# --------------------------------------------------------------------------- #

def t_forward(data_dir: Path) -> str:
    import torch
    from ml_analytics.models.mt3 import MT3

    torch.manual_seed(0)
    model = MT3()
    x = torch.randn(8, N_FEATURES)
    y = torch.randint(0, N_CLASSES, (8,))

    # eval mode: dropout off, so the labels-vs-no-labels paths are comparable
    model.eval()
    with torch.no_grad():
        e_eval, h_eval, l_eval = model(x, y)
        e2, h2, l2 = model(x)
    assert e_eval.shape == (8, N_CLASSES), e_eval.shape
    assert h_eval.shape == (8, 9), h_eval.shape
    assert torch.isfinite(e_eval).all() and torch.isfinite(h_eval).all(), "non-finite logits"
    assert l_eval is not None and torch.isfinite(l_eval), "built-in loss missing/non-finite"
    assert l2 is None, "loss must be None when labels are omitted"
    assert torch.allclose(e_eval, e2, atol=1e-6), "logits depend on whether labels were passed"
    assert torch.allclose(h_eval, h2, atol=1e-6), "phase logits depend on labels being passed"

    model.train()
    emissions, hp_logits, loss = model(x, y)
    assert torch.isfinite(loss), "train-mode loss non-finite"
    loss.backward()
    n_grad = sum(1 for p in model.parameters() if p.grad is not None and p.grad.abs().sum() > 0)
    assert n_grad > 0, "no gradients flowed"

    try:
        model(torch.randn(4, 64))
        raise AssertionError("expected a ValueError for the wrong feature count")
    except ValueError:
        pass

    return (f"{model.count_parameters():,} params, {n_grad} tensors with grad, "
            f"shape guard OK, eval-mode determinism OK")


# --------------------------------------------------------------------------- #
# 5 loss parity
# --------------------------------------------------------------------------- #

def t_loss_parity(data_dir: Path) -> str:
    import torch
    from ml_analytics.models.mt3 import MT3

    from .losses import MT3Objective, build_class_weights, build_state_criterion

    torch.manual_seed(1)
    model = MT3().eval()
    x = torch.randn(64, N_FEATURES)
    y = torch.randint(0, N_CLASSES, (64,))

    with torch.no_grad():
        emissions, hp_logits, builtin = model(x, y)
        obj = MT3Objective(build_state_criterion("ce", None), model.idx_to_phase,
                           aux_loss_weight=model.aux_loss_weight)
        ours, state, phase = obj(emissions, hp_logits, y)
    assert torch.allclose(builtin, ours, atol=1e-6), f"{builtin.item()} vs {ours.item()}"

    # phase target derivation must match the model's own buffer
    derived = obj.idx_to_phase[y]
    assert torch.equal(derived, model.idx_to_phase[y])

    # weighted / focal variants must differ from plain CE but stay finite
    w = build_class_weights(y.numpy(), N_CLASSES, "balanced")
    with torch.no_grad():
        wobj = MT3Objective(build_state_criterion("weighted_ce", w), model.idx_to_phase, 0.3)
        fobj = MT3Objective(build_state_criterion("focal", w, focal_gamma=1.5), model.idx_to_phase, 0.3)
        lw = wobj(emissions, hp_logits, y)[0]
        lf = fobj(emissions, hp_logits, y)[0]
    assert torch.isfinite(lw) and torch.isfinite(lf)
    assert lf < lw, "focal should down-weight easy examples relative to weighted CE"
    return (f"ce == MT3.forward ({builtin.item():.6f}); weighted={lw.item():.4f} "
            f"focal={lf.item():.4f}; state={state.item():.4f} phase={phase.item():.4f}")


# --------------------------------------------------------------------------- #
# 6 class weights
# --------------------------------------------------------------------------- #

def t_class_weights(data_dir: Path) -> str:
    sp = D.load_split("train", data_dir, limit=30_000)
    counts = D.class_counts(sp.y)
    out = []
    for scheme in ("balanced", "inv_sqrt", "effective"):
        w = D_weights(sp.y, scheme)
        present = counts > 0
        assert np.isfinite(w).all(), f"{scheme}: non-finite weights"
        assert (w[~present] == 0).all(), f"{scheme}: absent class got a non-zero weight"
        assert abs(w[present].mean() - 1.0) < 0.35, f"{scheme}: mean weight {w[present].mean():.3f}"
        # rarer classes must not be down-weighted relative to common ones
        rare, common = counts[present].argmin(), counts[present].argmax()
        idx = np.flatnonzero(present)
        assert w[idx[rare]] >= w[idx[common]], f"{scheme}: rare class weighted below common"
        out.append(f"{scheme}[{w[present].min():.2f},{w.max():.2f}]")
    from .losses import build_class_weights

    assert build_class_weights(sp.y, N_CLASSES, "none") is None
    return " ".join(out)


def D_weights(y: np.ndarray, scheme: str) -> np.ndarray:
    from .losses import build_class_weights

    w = build_class_weights(y, N_CLASSES, scheme)
    assert w is not None
    return w


# --------------------------------------------------------------------------- #
# 7 overfit a single batch
# --------------------------------------------------------------------------- #

def t_overfit_batch(data_dir: Path) -> str:
    import torch
    from ml_analytics.models.mt3 import MT3

    from .losses import MT3Objective, build_state_criterion

    torch.manual_seed(0)
    sp = D.load_split("train", data_dir, limit=2_000)
    idx = np.arange(64)
    x = torch.from_numpy(sp.X[idx])
    y = torch.from_numpy(sp.y[idx])

    model = MT3()
    obj = MT3Objective(build_state_criterion("ce", None), model.idx_to_phase, 0.3)
    opt = torch.optim.AdamW(model.parameters(), lr=3e-3)

    first = last = None
    for step in range(150):
        opt.zero_grad(set_to_none=True)
        emissions, hp, _ = model(x)
        loss, _, _ = obj(emissions, hp, y)
        loss.backward()
        torch.nn.utils.clip_grad_norm_(model.parameters(), 1.0)
        opt.step()
        if step == 0:
            first = float(loss)
        last = float(loss)
    acc = float((emissions.argmax(1) == y).float().mean())
    assert last < first * 0.5, f"loss barely moved: {first:.4f} -> {last:.4f}"
    assert acc > 0.75, f"cannot overfit 64 rows (acc {acc:.3f}) -- wiring is suspect"
    return f"loss {first:.4f} -> {last:.4f}, batch acc {acc:.3f} in 150 steps"


# --------------------------------------------------------------------------- #
# 8 train CLI + resume
# --------------------------------------------------------------------------- #

def t_train_cli(data_dir: Path, fast: bool = False) -> str:
    from .train_mt3 import main as train_main

    out = SMOKE_DIR / "train"
    if out.exists():
        shutil.rmtree(out)
    argv = [
        "--data-dir", str(data_dir), "--out-dir", str(out),
        "--epochs", "1" if fast else "2",
        "--limit-train", "8000", "--limit-val", "2000",
        "--batch-size", "512", "--lr", "1e-3", "--log-every", "0",
        "--loss", "weighted_ce", "--class-weight", "balanced",
        "--early-stop-patience", "0", "--device", "cpu", "--no-eval", "--seed", "7",
    ]
    assert train_main(argv) == 0

    for f in ("best.pt", "last.pt", "history.jsonl", "train_summary.json"):
        assert (out / f).exists(), f"missing artifact {f}"
    hist = [json.loads(l) for l in (out / "history.jsonl").read_text().splitlines() if l.strip()]
    assert hist, "empty history"
    for row in hist:
        for k in ("epoch", "loss", "val_macro_f1", "val_acc", "lr"):
            assert k in row, f"history row missing {k}"
        assert np.isfinite(row["loss"]), "non-finite training loss"

    import torch

    ck = torch.load(str(out / "best.pt"), map_location="cpu", weights_only=False)
    for k in ("model_state", "model_kwargs", "optimizer_state", "scheduler_state",
              "epoch", "best_val_macro_f1", "config", "provenance"):
        assert k in ck, f"checkpoint missing {k}"
    assert ck["provenance"]["scaler_refit"] is False
    assert ck["provenance"]["scaler_reapplied_to_splits"] is False

    # resume must pick up at the next epoch, not restart
    if not fast:
        assert train_main(argv + ["--resume", "--epochs", "3"]) == 0
        hist2 = [json.loads(l) for l in (out / "history.jsonl").read_text().splitlines() if l.strip()]
        epochs = [r["epoch"] for r in hist2]
        assert epochs == sorted(epochs) and max(epochs) == 3, f"resume produced epochs {epochs}"

    return f"{len(hist)} epoch(s), best val macro-F1 {ck['best_val_macro_f1']:.4f}, resume OK"


# --------------------------------------------------------------------------- #
# 9 evaluate CLI
# --------------------------------------------------------------------------- #

def t_evaluate_cli(data_dir: Path) -> str:
    from .evaluate import main as eval_main

    ckpt = SMOKE_DIR / "train" / "best.pt"
    out = SMOKE_DIR / "mt3"
    assert eval_main([
        "--ckpt", str(ckpt), "--data-dir", str(data_dir), "--out-dir", str(out),
        "--device", "cpu", "--batch-size", "8192",
    ]) == 0

    msgs = []
    for split, n_exp, cls_exp in (("test_real", 60_000, 21), ("test_synth", 60_000, 45)):
        npz = out / f"preds_{split}.npz"
        assert npz.exists(), f"missing {npz}"
        with np.load(npz) as z:
            y_true, y_pred, prob = z["y_true"], z["y_pred"], z["y_prob"]
        truth = D.load_split(split, data_dir)
        assert len(y_true) == n_exp
        assert np.array_equal(y_true, truth.y), f"{split}: saved y_true != on-disk labels"
        assert y_pred.min() >= 0 and y_pred.max() < N_CLASSES
        assert prob.shape == (n_exp, N_CLASSES)
        assert np.allclose(prob.astype(np.float32).sum(1), 1.0, atol=2e-2), "probs do not sum to 1"

        m = json.loads((out / f"metrics_{split}.json").read_text())
        assert m["n_classes_present"] == cls_exp
        assert 0.0 <= m["macro_f1"] <= 1.0 and 0.0 <= m["accuracy"] <= 1.0
        assert len(m["per_class"]) == N_CLASSES
        assert len(m["confusion_matrix"]) == N_CLASSES
        # macro-F1 over present classes must not be lower than the all-45 version
        assert m["macro_f1"] >= m["macro_f1_all45"] - 1e-9
        msgs.append(f"{split}: macroF1={m['macro_f1']:.4f} acc={m['accuracy']:.4f}")
    assert (out / "eval_summary.json").exists()
    return "; ".join(msgs)


# --------------------------------------------------------------------------- #
# 10 compare CLI
# --------------------------------------------------------------------------- #

def t_compare_cli(data_dir: Path) -> str:
    from .compare import main as cmp_main

    mt3_dir = SMOKE_DIR / "mt3"
    fake_dir = SMOKE_DIR / "fake_baseline"
    missing = SMOKE_DIR / "does_not_exist"

    # (a) MT3 only -> must still succeed and say the baseline is missing
    assert cmp_main(["--mt3-dir", str(mt3_dir), "--baseline-dir", str(missing)]) == 0

    # (b) synthetic second model on the SAME rows -> full comparison path
    fake_dir.mkdir(parents=True, exist_ok=True)
    rng = np.random.default_rng(0)
    for split in ("test_real", "test_synth"):
        with np.load(mt3_dir / f"preds_{split}.npz") as z:
            y_true, y_pred = z["y_true"], z["y_pred"]
        noisy = y_pred.copy()
        flip = rng.random(len(noisy)) < 0.3
        noisy[flip] = rng.integers(0, N_CLASSES, flip.sum())
        np.savez_compressed(
            fake_dir / f"preds_{split}.npz",
            y_true=y_true, y_pred=noisy,
            phase_pred=np.asarray(D.IDX_TO_PHASE)[noisy],
            model=np.array("fake"), split=np.array(split),
        )
    out_json = SMOKE_DIR / "comparison.json"
    assert cmp_main([
        "--mt3-dir", str(mt3_dir), "--baseline-dir", str(fake_dir),
        "--baseline-name", "FAKE", "--out", str(out_json),
    ]) == 0
    payload = json.loads(out_json.read_text())
    assert set(payload) == {"test_real", "test_synth"}
    for split, res in payload.items():
        assert set(res["models"]) == {"FAKE", "MT3"}
        assert res["mcnemar"]["p_value"] <= 1.0

    # (c) mismatched rows must ABORT, not silently compare
    bad = SMOKE_DIR / "bad_rows"
    bad.mkdir(parents=True, exist_ok=True)
    with np.load(mt3_dir / "preds_test_real.npz") as z:
        y_true, y_pred = z["y_true"], z["y_pred"]
    perm = rng.permutation(len(y_true))
    np.savez_compressed(bad / "preds_test_real.npz", y_true=y_true[perm], y_pred=y_pred[perm],
                        phase_pred=np.zeros_like(y_pred), model=np.array("bad"),
                        split=np.array("test_real"))
    try:
        cmp_main(["--mt3-dir", str(mt3_dir), "--baseline-dir", str(bad), "--splits", "test_real"])
        raise AssertionError("compare accepted mismatched rows")
    except SystemExit as e:
        assert "different rows" in str(e), f"unexpected SystemExit: {e}"
    return "mt3-only OK, 2-model comparison OK, row-mismatch aborts"


# --------------------------------------------------------------------------- #

def main(argv: Optional[Sequence[str]] = None) -> int:
    p = argparse.ArgumentParser(description="MT3 pipeline smoke test")
    p.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    p.add_argument("--fast", action="store_true", help="shorter training step")
    p.add_argument("--keep", action="store_true", help="keep artifacts/smoke afterwards")
    a = p.parse_args(argv)

    print("=" * 72)
    print("  MT3 PIPELINE SMOKE TEST")
    print(f"  data: {a.data_dir}")
    print("=" * 72)

    steps: List[Tuple[str, Callable]] = [
        ("1 constants parity (mt3 vs schema)", t_constants),
        ("2 dataset integrity", t_dataset),
        ("3 scaler provenance", t_scaler),
        ("4 model forward/backward", t_forward),
        ("5 loss parity vs MT3.forward", t_loss_parity),
        ("6 class weights", t_class_weights),
        ("7 overfit one batch", t_overfit_batch),
        ("8 train CLI + resume", lambda d: t_train_cli(d, a.fast)),
        ("9 evaluate CLI + saved preds", t_evaluate_cli),
        ("10 compare CLI", t_compare_cli),
    ]

    ok = True
    for name, fn in steps:
        passed = _run(name, fn, a.data_dir)
        ok = ok and passed
        if not passed and name.startswith(("1 ", "2 ", "3 ", "8 ")):
            print(f"\n[abort] {name} is a prerequisite for the remaining steps")
            break

    print("\n" + "=" * 72)
    print("  SUMMARY")
    print("=" * 72)
    for name, passed, msg, dt in _results:
        print(f"  [{'PASS' if passed else 'FAIL'}] {name:<38s} {dt:6.1f}s  {msg}")
    n_pass = sum(1 for _, p_, _, _ in _results if p_)
    print(f"\n  {n_pass}/{len(_results)} checks passed")

    if not a.keep and ok and SMOKE_DIR.exists():
        shutil.rmtree(SMOKE_DIR, ignore_errors=True)
        print(f"  (removed {SMOKE_DIR}; pass --keep to inspect)")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
