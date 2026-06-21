"""
src/validators/quality_checks.py
Dataset quality validation — produces all numbers for Table 1 of the paper.
Run after every generation step before proceeding to training.
"""
from __future__ import annotations
import logging, json
import numpy as np
import pandas as pd
from pathlib import Path
from collections import Counter

log = logging.getLogger(__name__)


def check_shape(X: np.ndarray, y: np.ndarray,
                expected_features: int = 128,
                expected_classes: int  = 45) -> dict:
    issues = []
    if X.shape[1] != expected_features:
        issues.append(f"Expected {expected_features} features, got {X.shape[1]}")
    if np.isnan(X).any():
        issues.append(f"NaN values: {np.isnan(X).sum()}")
    if np.isinf(X).any():
        issues.append(f"Inf values: {np.isinf(X).sum()}")
    present = len(np.unique(y))
    if present < expected_classes:
        issues.append(f"Only {present}/{expected_classes} classes present")
    result = {"passed": len(issues) == 0, "issues": issues,
              "shape_X": list(X.shape), "n_classes_present": present}
    status = "✓ PASS" if result["passed"] else "✗ FAIL"
    log.info("Shape check %s: %s", status, issues or "all good")
    return result


def check_class_balance(y: np.ndarray,
                        min_samples: int = 2000) -> dict:
    from configs.schema import IDX_TO_LABEL
    counts   = Counter(y.tolist())
    minority = {IDX_TO_LABEL.get(k, str(k)): v
                for k, v in counts.items() if v < min_samples}
    result = {
        "min_count":  min(counts.values()),
        "max_count":  max(counts.values()),
        "mean_count": int(np.mean(list(counts.values()))),
        "imbalance_ratio": round(max(counts.values()) / (min(counts.values()) + 1), 2),
        "classes_below_min": minority,
        "passed": len(minority) == 0,
    }
    status = "✓ PASS" if result["passed"] else f"⚠ WARN — {len(minority)} under-represented classes"
    log.info("Balance check %s | min=%d max=%d ratio=%.1f",
             status, result["min_count"], result["max_count"], result["imbalance_ratio"])
    return result


def wasserstein_by_group(X_real: np.ndarray,
                         X_synth: np.ndarray) -> dict:
    """Per-feature-group Wasserstein distance. Target: mean W < 0.5 per group."""
    from scipy.stats import wasserstein_distance
    from configs.schema import FEATURE_GROUPS

    results = {}
    for grp, info in FEATURE_GROUPS.items():
        s, e  = info["start"], info["end"]
        dists = [wasserstein_distance(X_real[:, i], X_synth[:, i])
                 for i in range(s, e)]
        results[grp] = {
            "mean_W": round(float(np.mean(dists)), 5),
            "max_W":  round(float(np.max(dists)),  5),
            "p90_W":  round(float(np.percentile(dists, 90)), 5),
            "passed": float(np.mean(dists)) < 0.5,
        }
        status = "✓" if results[grp]["passed"] else "⚠"
        log.info("  %s %-20s mean_W=%.4f  max_W=%.4f",
                 status, grp, results[grp]["mean_W"], results[grp]["max_W"])
    return results


def adversarial_auc(X_real: np.ndarray,
                    X_synth: np.ndarray,
                    n_sample: int = 20_000,
                    threshold: float = 0.60) -> dict:
    """
    Train XGBoost to distinguish real vs. synthetic rows.
    AUC < threshold → synthetic is indistinguishable (PASS).
    AUC > threshold → detectable artifacts (FAIL — retrain generator).
    """
    from xgboost import XGBClassifier
    from sklearn.model_selection import StratifiedKFold, cross_val_score

    n = min(len(X_real), len(X_synth), n_sample)
    X = np.vstack([X_real[:n], X_synth[:n]])
    y = np.array([0]*n + [1]*n)

    clf = XGBClassifier(n_estimators=200, max_depth=5,
                        random_state=42, n_jobs=-1,
                        use_label_encoder=False, eval_metric="logloss",
                        verbosity=0)
    cv  = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    auc = float(cross_val_score(clf, X, y, scoring="roc_auc", cv=cv).mean())

    # Feature importance → tells you WHICH group the generator failed on
    clf.fit(X, y)
    imp   = clf.feature_importances_
    top10 = np.argsort(imp)[::-1][:10].tolist()

    result = {
        "adversarial_auc": round(auc, 4),
        "passed":          auc < threshold,
        "threshold":       threshold,
        "top10_leaky_feature_indices": top10,
        "verdict": "PASS — synthetic indistinguishable from real"
                   if auc < threshold else
                   f"FAIL — AUC={auc:.3f}, fix generator for features {top10[:3]}",
    }
    status = "✓ PASS" if result["passed"] else "✗ FAIL"
    log.info("Adversarial AUC %s: %.4f (threshold=%.2f)", status, auc, threshold)
    return result


def tstr_baseline(X_train_synth: np.ndarray, y_train_synth: np.ndarray,
                  X_test_real:   np.ndarray, y_test_real:   np.ndarray) -> dict:
    """
    Train-on-Synthetic Test-on-Real (TSTR) evaluation.
    Key metric for Table 2 of the paper.
    Uses fast RandomForest — not your full CNN-LSTM model.
    """
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics  import f1_score, accuracy_score

    log.info("TSTR: training RandomForest on %d synthetic sessions...", len(X_train_synth))
    clf = RandomForestClassifier(n_estimators=200, max_depth=20,
                                 random_state=42, n_jobs=-1)
    clf.fit(X_train_synth, y_train_synth)
    preds = clf.predict(X_test_real)

    result = {
        "tstr_accuracy":    round(float(accuracy_score(y_test_real, preds)), 4),
        "tstr_macro_f1":    round(float(f1_score(y_test_real, preds, average="macro", zero_division=0)), 4),
        "tstr_weighted_f1": round(float(f1_score(y_test_real, preds, average="weighted", zero_division=0)), 4),
        "n_train_synth":    len(X_train_synth),
        "n_test_real":      len(X_test_real),
    }
    log.info("TSTR: accuracy=%.4f  macro_F1=%.4f",
             result["tstr_accuracy"], result["tstr_macro_f1"])
    return result


def run_full_validation(X_real:  np.ndarray, y_real:  np.ndarray,
                        X_synth: np.ndarray, y_synth: np.ndarray,
                        output_path: Path = Path("data/processed/quality_report.json")
                        ) -> dict:
    """
    Run all quality checks and save a JSON report.
    Call this before committing the dataset.
    """
    log.info("=" * 60)
    log.info("DATASET QUALITY VALIDATION — HoneySynth-1M")
    log.info("=" * 60)

    X_all = np.vstack([X_real, X_synth])
    y_all = np.concatenate([y_real, y_synth])

    report = {
        "shape_check":      check_shape(X_all, y_all),
        "balance_check":    check_class_balance(y_all),
        "wasserstein":      wasserstein_by_group(X_real, X_synth),
        "adversarial_auc":  adversarial_auc(X_real, X_synth),
        "tstr":             tstr_baseline(X_synth, y_synth, X_real, y_real),
    }

    all_passed = all([
        report["shape_check"]["passed"],
        report["balance_check"]["passed"],
        report["adversarial_auc"]["passed"],
        all(g["passed"] for g in report["wasserstein"].values()),
    ])
    report["overall_passed"] = all_passed
    report["verdict"] = "READY FOR TRAINING" if all_passed else "NEEDS FIXES — see issues above"

    log.info("\n%s", "=" * 60)
    log.info("OVERALL: %s", report["verdict"])
    log.info("TSTR macro-F1: %.4f", report["tstr"]["tstr_macro_f1"])
    log.info("Adversarial AUC: %.4f", report["adversarial_auc"]["adversarial_auc"])
    log.info("%s", "=" * 60)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, default=str)
    log.info("Report saved → %s", output_path)
    return report
