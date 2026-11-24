"""
src/validators/source_separability.py

Can a classifier tell a REAL honeypot session from a GENERATED one? Run as
`python -m src.validators.source_separability` from `honeypot_dataset/`.

This is the method of DATA_INTEGRITY.md section 12, written down. Those
experiments were run ad hoc and section 12a records the consequence: the
results could not be reproduced from the shipped artifact. The numbers in
sections 12b and 16 come from here now.

It is NOT `quality_checks.adversarial_auc`, which takes the FIRST n rows of each
side, keeps constant columns and never establishes a control. Three differences
matter:

  equal n per side, RANDOM    the splits are not source-balanced, so taking the
                             first n compares different class mixtures
  constant columns dropped    27 of 128 are dead; they cannot separate anything
                             but they change the tree's splits
  a real-vs-real control      a random half-split of real data must land on
                             0.50. Without that line a high AUC elsewhere is
                             uninterpretable -- section 9a spent three months
                             reading 0.998 as poor fidelity when the reference
                             band was never measured.

Two rules for reading the output, both learned the hard way (section 12d):

  * POOLED figures measure class composition and protocol, not provenance.
    Class identity alone scores ~0.97 inside the synthetic data, and two REAL
    netflow datasets separate at 1.0000. Only same-protocol, within-class rows
    mean anything.
  * 0.50 is the standard, not 0.60. The 0.93-1.00 "reference band" of section 9a
    came from STRUCTURED splits and is the lenient reading (section 9g).
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

import numpy as np

log = logging.getLogger(__name__)

REAL_GEN = "cowrie_real"                   # real SSH honeypot sessions
SYNTH_GEN = "simulated_cowrie_events"      # cowrie_simulator output
# the four classes with enough real honeypot support to compare within class
REAL_SUPPORTED = ("ACCESS_BRUTE_SSH", "RECON_IP_SCAN",
                  "DISC_ENV_PROBE", "EXEC_SHELL_OPEN")
MAX_PER_SIDE = 20_000
MIN_PER_SIDE = 200


def separability(X: np.ndarray, idx_a: np.ndarray, idx_b: np.ndarray,
                 cols: np.ndarray, seed: int = 42,
                 cap: int = MAX_PER_SIDE) -> tuple[float | None, int]:
    """AUC for telling rows `idx_a` from rows `idx_b` using `cols`.

    Returns (auc, n_per_side); auc is None when either side is too small to
    measure, which is reported rather than filled with a number.
    """
    from sklearn.ensemble import HistGradientBoostingClassifier
    from sklearn.metrics import roc_auc_score
    from sklearn.model_selection import train_test_split

    n = min(len(idx_a), len(idx_b), cap)
    if n < MIN_PER_SIDE:
        return None, n
    rng = np.random.RandomState(seed)
    a = np.sort(rng.choice(idx_a, n, replace=False))
    b = np.sort(rng.choice(idx_b, n, replace=False))
    Xs = np.vstack([X[a][:, cols], X[b][:, cols]])
    ys = np.r_[np.zeros(n), np.ones(n)]

    keep = Xs.std(axis=0) > 0          # a dead column cannot separate anything
    if not keep.any():
        return None, n
    Xtr, Xte, ytr, yte = train_test_split(
        Xs[:, keep], ys, test_size=0.3, stratify=ys, random_state=seed)
    model = HistGradientBoostingClassifier(max_iter=120, random_state=seed)
    model.fit(Xtr, ytr)
    return float(roc_auc_score(yte, model.predict_proba(Xte)[:, 1])), n


def _halves(idx: np.ndarray, seed: int) -> tuple[np.ndarray, np.ndarray]:
    shuffled = np.random.RandomState(seed).permutation(idx)
    mid = len(shuffled) // 2
    return shuffled[:mid], shuffled[mid:]


# n is held FIXED across every cell of the two breakdowns below, because this
# AUC rises with n on unchanged data (17d) -- a breakdown measured at whatever n
# each cell happens to have is a table of sample sizes.
BREAKDOWN_CAP = 5_000


def per_feature_within_class(X, y, gen, seed: int = 42,
                             cap: int = BREAKDOWN_CAP) -> dict:
    """One feature at a time: which temporal statistic is still separable?

    The point of the breakdown is the comparison with the whole block. If no
    single feature approaches the block's AUC, the marginals are right and what
    is wrong is how they co-vary within a session (section 18a).
    """
    from configs.schema import LABEL_TO_IDX
    from src.extractors.temporal import TEMPORAL_FEATURE_NAMES
    from configs.schema import FEATURE_GROUPS

    start = FEATURE_GROUPS["A_temporal"]["start"]
    real, synth = np.where(gen == REAL_GEN)[0], np.where(gen == SYNTH_GEN)[0]
    out: dict = {}
    for j, fname in enumerate(TEMPORAL_FEATURE_NAMES):
        col = np.array([start + j])
        out[fname] = {}
        for cls in REAL_SUPPORTED:
            c = LABEL_TO_IDX[cls]
            auc, _ = separability(X, real[y[real] == c], synth[y[synth] == c],
                                  col, seed=seed, cap=cap)
            out[fname][cls] = None if auc is None else round(auc, 4)
        worst = [v for v in out[fname].values() if v is not None]
        out[fname]["worst"] = max(worst) if worst else None
        log.info("  %-24s %s", fname,
                 "  ".join(f"{cls[:5]} {out[fname][cls]}" for cls in REAL_SUPPORTED))
    return out


def by_donor_origin(X, y, gen, don, seed: int = 42) -> dict:
    """Does the timing fallback explain the gap? Compare at MATCHED n.

    `donor_exact` copies a real session of the same class; `donor_bucket`
    borrows another class's rhythm; `per_event` draws each gap independently.
    Each fallback group is small in these four classes, so `donor_exact` is
    re-measured at the fallback group's own n rather than at its full size --
    otherwise the comparison is 17d's trap.
    """
    from configs.schema import FEATURE_GROUPS, LABEL_TO_IDX

    A = np.arange(FEATURE_GROUPS["A_temporal"]["start"],
                  FEATURE_GROUPS["A_temporal"]["end"])
    real, synth = np.where(gen == REAL_GEN)[0], np.where(gen == SYNTH_GEN)[0]
    out: dict = {}
    for cls in REAL_SUPPORTED:
        c = LABEL_TO_IDX[cls]
        r = real[y[real] == c]
        exact = synth[(y[synth] == c) & (don[synth] == "donor_exact")]
        out[cls] = {}
        for origin in ("donor_bucket", "per_event"):
            s = synth[(y[synth] == c) & (don[synth] == origin)]
            auc, n = separability(X, r, s, A, seed=seed, cap=len(s))
            if auc is None:
                out[cls][origin] = {"n": int(len(s)), "auc": None,
                                    "donor_exact_at_same_n": None}
                log.info("  %-18s %-13s n=%-6d too few to measure", cls, origin, len(s))
                continue
            base, _ = separability(X, r, exact, A, seed=seed, cap=n)
            out[cls][origin] = {"n": int(n), "auc": round(auc, 4),
                                "donor_exact_at_same_n":
                                    None if base is None else round(base, 4)}
            log.info("  %-18s %-13s n=%-6d %s %.4f   donor_exact %.4f",
                     cls, origin, n, "fallback", auc, base)
    # exposure: the fallback paths concentrate in the classes with no real data
    anchored = np.isin(y[synth], [LABEL_TO_IDX[k] for k in REAL_SUPPORTED])
    out["exposure"] = {}
    for label, mask in (("real_supported_classes", anchored),
                        ("other_classes", ~anchored)):
        sub = don[synth][mask]
        out["exposure"][label] = {"n": int(len(sub)), **{
            o: round(100.0 * float((sub == o).mean()), 1)
            for o in ("donor_exact", "donor_bucket", "per_event")}}
        log.info("  %-24s n=%-8d %s", label, len(sub),
                 "  ".join(f"{o} {out['exposure'][label][o]}%"
                           for o in ("donor_exact", "donor_bucket", "per_event")))
    return out


def temporal_coverage(data_dir: Path) -> dict:
    """Share of train rows where each temporal feature was MEASURED, not filled.

    A feature imputed on half the corpus carries no within-session relationship
    for those rows -- it is the train median (section 18c).
    """
    from src.extractors.temporal import TEMPORAL_FEATURE_NAMES

    M = np.load(data_dir / "M_train.npy")
    out = {name: round(100.0 * float(M[:, j].mean()), 1)
           for j, name in enumerate(TEMPORAL_FEATURE_NAMES)}
    for name, pct in out.items():
        log.info("  %-24s measured in %5.1f%% of train rows", name, pct)
    return out


def run(data_dir: Path, seed: int = 42) -> dict:
    """Every experiment, on the train+val splits of a built dataset."""
    from configs.schema import FEATURE_GROUPS, LABEL_TO_IDX

    X = np.vstack([np.load(data_dir / "X_train.npy", mmap_mode="r"),
                   np.load(data_dir / "X_val.npy", mmap_mode="r")])
    y = np.concatenate([np.load(data_dir / "y_train.npy"),
                        np.load(data_dir / "y_val.npy")])
    gen = np.concatenate([np.load(data_dir / "gen_train.npy", allow_pickle=True),
                          np.load(data_dir / "gen_val.npy", allow_pickle=True)])
    gen = np.asarray([str(v) for v in gen])
    don = np.concatenate([np.load(data_dir / "donor_train.npy", allow_pickle=True),
                          np.load(data_dir / "donor_val.npy", allow_pickle=True)])
    don = np.asarray([str(v) for v in don])
    # train+val are the only splits holding both sides: test_real is source-pure
    # real and test_synth source-pure generated.

    blocks = {g: np.arange(i["start"], i["end"]) for g, i in FEATURE_GROUPS.items()}
    allcols = np.arange(X.shape[1])
    real = np.where(gen == REAL_GEN)[0]
    synth = np.where(gen == SYNTH_GEN)[0]
    out: dict = {"n_real": len(real), "n_synth": len(synth)}

    def record(label: str, bucket: dict, a, b, cols):
        auc, n = separability(X, a, b, cols, seed=seed)
        bucket[label] = None if auc is None else round(auc, 4)
        log.info("  %-34s %s  (n=%s/side)", label,
                 "  n/a" if auc is None else f"{auc:.4f}", f"{n:,}")

    log.info("CONTROL -- a random half-split must land on 0.50")
    out["control"] = {}
    for name, idx in (("real vs real", real), ("synth vs synth", synth)):
        a, b = _halves(idx, seed)
        record(name, out["control"], a, b, allcols)

    log.info("PER BLOCK -- real vs generated, pooled over classes")
    out["per_block_pooled"] = {}
    for name, cols in blocks.items():
        record(name, out["per_block_pooled"], real, synth, cols)

    log.info("LEAVE ONE BLOCK OUT -- real vs generated, pooled")
    out["leave_one_out"] = {}
    record("ALL 128", out["leave_one_out"], real, synth, allcols)
    for name, cols in blocks.items():
        kept = np.setdiff1d(allcols, cols)
        record(f"without {name}", out["leave_one_out"], real, synth, kept)

    log.info("WITHIN CLASS -- the only rows that measure provenance")
    out["within_class"] = {}
    for cls in REAL_SUPPORTED:
        c = LABEL_TO_IDX[cls]
        r, s = real[y[real] == c], synth[y[synth] == c]
        out["within_class"][cls] = {}
        log.info(" %s", cls)
        for name, cols in blocks.items():
            record(name, out["within_class"][cls], r, s, cols)
        record("ALL 128", out["within_class"][cls], r, s, allcols)
        no_d = np.setdiff1d(allcols, blocks["D_semantic"])
        record("ALL minus D_semantic", out["within_class"][cls], r, s, no_d)

    log.info("PER TEMPORAL FEATURE, within class (n=%d/side fixed)", BREAKDOWN_CAP)
    out["per_temporal_feature"] = per_feature_within_class(X, y, gen, seed=seed)

    log.info("BY TIMING ORIGIN -- matched n, donor_exact re-measured alongside")
    out["by_donor_origin"] = by_donor_origin(X, y, gen, don, seed=seed)

    log.info("TEMPORAL COVERAGE -- measured, not imputed")
    out["temporal_coverage"] = temporal_coverage(data_dir)
    return out


def main() -> None:
    import argparse

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data-dir", type=Path, default=Path("data/final_v2"))
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--out", type=Path, default=None,
                    help="write the results as JSON (default: <data-dir>/source_separability.json)")
    args = ap.parse_args()

    report = run(args.data_dir, seed=args.seed)
    out = args.out or args.data_dir / "source_separability.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    log.info("\nSaved -> %s", out)


if __name__ == "__main__":
    main()
