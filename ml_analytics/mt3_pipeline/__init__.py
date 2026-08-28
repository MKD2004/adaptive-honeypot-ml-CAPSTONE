"""
ml_analytics/mt3_pipeline — training + evaluation pipeline for the MT3 model.

Owner: Mahith (MT3 is not a teammate deliverable; see TEAMMATES.md rule 3).

The MT3 *architecture* lives in ml_analytics/models/mt3.py and is treated as
read-only here. This package supplies everything around it:

    data.py      frozen-split loading, scaler provenance checks, batching
    losses.py    class-weighted CE / focal + the phase-auxiliary combination
    metrics.py   macro-F1 (primary), per-class F1, accuracy, confusion matrix
    train_mt3.py training CLI (checkpointing, early stop, auto-eval)
    evaluate.py  checkpoint -> predictions + metrics on the frozen test splits
    compare.py   baseline-vs-MT3 comparison table on identical test rows
    smoke_test.py end-to-end self-check

Evaluation protocol is fixed by ml_analytics/README.md so that CNN-LSTM and MT3
are judged identically: same splits, same scaler, same metrics, saved predictions.
"""

__all__ = ["data", "losses", "metrics"]
