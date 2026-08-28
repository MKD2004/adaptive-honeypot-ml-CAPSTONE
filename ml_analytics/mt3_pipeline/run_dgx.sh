#!/usr/bin/env bash
# Launch the MT3 training run on the DGX Spark (GB10), DETACHED.
#
# The laptop is only a client -- a foreground job dies when SSH drops
# (DGX.md, "Running jobs here -- ALWAYS launch detached").
#
#   ./ml_analytics/mt3_pipeline/run_dgx.sh              # start detached
#   tmux attach -t mt3                                  # watch it
#   tail -f ml_analytics/artifacts/mt3/train.log        # or just the log
#
# Prerequisites on the DGX:
#   * git pull origin main
#   * honeysynth_final.zip unzipped into honeypot_dataset/data/final/
#     (git-ignored -- transferred, not pulled; see DGX.md transfer manifest)
#   * a venv with torch + scikit-learn + joblib
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

SESSION="${SESSION:-mt3}"
PY="${PY:-python}"
OUT_DIR="${OUT_DIR:-ml_analytics/artifacts/mt3}"
DATA_DIR="${DATA_DIR:-honeypot_dataset/data/final}"

EPOCHS="${EPOCHS:-30}"
BATCH_SIZE="${BATCH_SIZE:-1024}"
LR="${LR:-3e-4}"
LOSS="${LOSS:-weighted_ce}"
CLASS_WEIGHT="${CLASS_WEIGHT:-balanced}"
SEED="${SEED:-42}"
EXTRA="${EXTRA:-}"

if [[ ! -f "$DATA_DIR/X_train.npy" ]]; then
  echo "ERROR: $DATA_DIR/X_train.npy not found."
  echo "       unzip honeysynth_final.zip -d $DATA_DIR/   (see DGX.md)"
  exit 1
fi

mkdir -p "$OUT_DIR"
LOG="$OUT_DIR/train.log"

CMD="$PY -u -m ml_analytics.mt3_pipeline.train_mt3 \
  --data-dir $DATA_DIR --out-dir $OUT_DIR \
  --epochs $EPOCHS --batch-size $BATCH_SIZE --lr $LR \
  --loss $LOSS --class-weight $CLASS_WEIGHT --seed $SEED \
  --amp --cache-on-device --early-stop-patience 5 $EXTRA"

echo "[run_dgx] repo:    $REPO_ROOT"
echo "[run_dgx] session: $SESSION"
echo "[run_dgx] log:     $LOG"
echo "[run_dgx] cmd:     $CMD"

# check nobody else is mid-run on the GPU (shared machine -- DGX.md etiquette)
if command -v nvidia-smi >/dev/null 2>&1; then
  echo "[run_dgx] current GPU usage:"
  nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv || true
fi

if command -v tmux >/dev/null 2>&1; then
  if tmux has-session -t "$SESSION" 2>/dev/null; then
    echo "[run_dgx] tmux session '$SESSION' already exists -- attach or kill it first:"
    echo "          tmux attach -t $SESSION   /   tmux kill-session -t $SESSION"
    exit 1
  fi
  tmux new-session -d -s "$SESSION" "$CMD 2>&1 | tee $LOG"
  echo "[run_dgx] launched detached. tmux attach -t $SESSION"
else
  nohup bash -c "$CMD" >"$LOG" 2>&1 &
  echo "[run_dgx] tmux not found; launched with nohup (pid $!). tail -f $LOG"
fi
