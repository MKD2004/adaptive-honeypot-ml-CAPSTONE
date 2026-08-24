#!/usr/bin/env bash
# setup.sh — automates the full dev environment setup for
# adaptive-honeypot-ml-CAPSTONE (Linux / college GPU system).
#
# Usage:   ./setup.sh          (or: bash setup.sh)
# To keep the venv active in your current shell afterwards, run:
#   source setup.sh
#
# Idempotent: safe to re-run. Existing venv / satisfied packages / an
# existing tabsyn/ checkout are detected and skipped, not recreated.
#
# Override the TabSyn repo to clone with:
#   TABSYN_REPO_URL=... ./setup.sh
# Override the Python interpreter used to build the venv (default: auto-detect,
# preferring python3.11) with:
#   PYTHON_BIN=python3.12 ./setup.sh
# Override the PyTorch wheel index (default: cu121, built for x86_64 + older
# GPU generations) with:
#   TORCH_INDEX_URL=https://download.pytorch.org/whl/cu128 ./setup.sh
# e.g. on an aarch64 Blackwell/GB10 box (NVIDIA DGX Spark), cu121 has no
# aarch64 wheel and the driver is CUDA 13-class anyway — use cu128 there.
set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_ROOT"

VENV_DIR="$PROJECT_ROOT/venv"
TABSYN_DIR="$PROJECT_ROOT/tabsyn"
TABSYN_REPO_URL="${TABSYN_REPO_URL:-https://github.com/amazon-science/tabsyn.git}"
TORCH_INDEX_URL="${TORCH_INDEX_URL:-https://download.pytorch.org/whl/cu121}"

log()  { printf '\n\033[1;34m[setup]\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33m[setup][warn]\033[0m %s\n' "$1" >&2; }
err()  { printf '\033[1;31m[setup][error]\033[0m %s\n' "$1" >&2; }

fail_step() { err "$1"; exit 1; }

# ── 1. Check Python ──────────────────────────────────────────────────────
PYTHON311=""
if [ -n "${PYTHON_BIN:-}" ]; then
    log "Using PYTHON_BIN override: $PYTHON_BIN"
    if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
        fail_step "PYTHON_BIN=$PYTHON_BIN not found on PATH."
    fi
    PYTHON311="$PYTHON_BIN"
else
    log "Checking for Python 3.11..."
    for candidate in python3.11 python3.11.exe; do
        if command -v "$candidate" >/dev/null 2>&1; then
            PYTHON311="$candidate"
            break
        fi
    done

    if [ -z "$PYTHON311" ] && command -v python3 >/dev/null 2>&1; then
        PY3_MINOR="$(python3 -c 'import sys; print(sys.version_info[1])' 2>/dev/null || echo 0)"
        if [ "$PY3_MINOR" -ge 10 ] 2>/dev/null; then
            warn "python3.11 not found — falling back to $(python3 --version 2>&1) on PATH."
            warn "This project's default torch install targets cu121, which is built for"
            warn "Python 3.11 specifically. If the pip install below fails, pin the wheel"
            warn "index explicitly: TORCH_INDEX_URL=... ./setup.sh (and/or PYTHON_BIN=...)."
            PYTHON311="python3"
        fi
    fi
fi

if [ -z "$PYTHON311" ]; then
    err "No suitable Python found on PATH (looked for python3.11, then python3 >= 3.10)."
    err "CUDA PyTorch wheels aren't published for every Python version —"
    err "this project standardises on 3.11 by default so the GPU build installs cleanly."
    err ""
    err "Install it with one of:"
    err "  Ubuntu/Debian:  sudo add-apt-repository ppa:deadsnakes/ppa && sudo apt update && sudo apt install python3.11 python3.11-venv"
    err "  pyenv:          pyenv install 3.11.9"
    err "Or point at whatever Python 3 you do have: PYTHON_BIN=python3.12 ./setup.sh"
    exit 1
fi
log "Found $("$PYTHON311" --version 2>&1) ($PYTHON311)"

# ── 2. Create venv if missing ────────────────────────────────────────────
if [ -f "$VENV_DIR/bin/activate" ]; then
    log "venv already exists at $VENV_DIR — skipping creation."
else
    log "Creating venv at $VENV_DIR..."
    "$PYTHON311" -m venv "$VENV_DIR" \
        || fail_step "venv creation failed. On Debian/Ubuntu you may need: sudo apt install python3.11-venv"
fi

VENV_PY="$VENV_DIR/bin/python"

# ── 3. Activate venv ─────────────────────────────────────────────────────
log "Activating venv..."
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate" || warn "Could not source activate script — continuing via $VENV_PY directly."

"$VENV_PY" -m pip install --upgrade pip -q || fail_step "pip upgrade failed."

# ── 4. Install CUDA PyTorch ───────────────────────────────────────────────
if "$VENV_PY" -c "
import sys
try:
    import torch
except ImportError:
    sys.exit(1)
sys.exit(0 if torch.cuda.is_available() else 1)
" >/dev/null 2>&1; then
    log "torch with CUDA already available — skipping."
else
    if ! command -v nvidia-smi >/dev/null 2>&1; then
        warn "nvidia-smi not found — no NVIDIA driver detected on this machine."
        warn "Installing the $TORCH_INDEX_URL wheel anyway; it will run CPU-only here."
    fi
    log "Installing CUDA PyTorch ($TORCH_INDEX_URL)..."
    "$VENV_PY" -m pip install torch --index-url "$TORCH_INDEX_URL" -q \
        || fail_step "torch install from $TORCH_INDEX_URL failed. Wrong wheel index for this arch/GPU? Try overriding TORCH_INDEX_URL."
fi

# ── 5. Install all requirements ──────────────────────────────────────────
log "Installing requirements.txt..."
"$VENV_PY" -m pip install -r "$PROJECT_ROOT/requirements.txt" -q \
    || fail_step "requirements.txt install failed."

if [ -f "$PROJECT_ROOT/honeypot_dataset/requirements.txt" ]; then
    log "Installing honeypot_dataset/requirements.txt..."
    "$VENV_PY" -m pip install -r "$PROJECT_ROOT/honeypot_dataset/requirements.txt" -q \
        || fail_step "honeypot_dataset/requirements.txt install failed."
fi

# ── 6. Ensure key extras are present ─────────────────────────────────────
log "Ensuring python-dotenv, jupyter, xgboost, be-great are installed..."
"$VENV_PY" -m pip install -q "python-dotenv>=1.0.0" "jupyter>=1.0.0" "xgboost>=2.0.0" "be-great" \
    || fail_step "extras install failed."

# ── 7. Clone TabSyn if missing ───────────────────────────────────────────
if [ -d "$TABSYN_DIR" ]; then
    log "tabsyn/ already exists — skipping clone."
else
    log "Cloning TabSyn from $TABSYN_REPO_URL..."
    git clone "$TABSYN_REPO_URL" "$TABSYN_DIR" \
        || warn "TabSyn clone failed — check TABSYN_REPO_URL / network access and retry."
fi

# ── 8. Install TabSyn requirements ───────────────────────────────────────
if [ -f "$TABSYN_DIR/requirements.txt" ]; then
    log "Installing tabsyn/requirements.txt..."
    "$VENV_PY" -m pip install -r "$TABSYN_DIR/requirements.txt" -q \
        || warn "tabsyn/requirements.txt install had errors — check output above."
elif [ -d "$TABSYN_DIR" ]; then
    warn "tabsyn/requirements.txt not found — skipping (check the repo's own setup instructions)."
fi

# ── 9. Smoke test: schema + MT3 ──────────────────────────────────────────
log "Running smoke test..."
SMOKE_OK=1

(
    cd "$PROJECT_ROOT/honeypot_dataset" && "$VENV_PY" - <<'PYEOF'
import sys; sys.path.insert(0, '.')
from configs.schema import N_CLASSES, N_FEATURES, KILL_CHAIN_DAG
from src.generators.kill_chain_simulator import generate_session_sequence
import random
seq = generate_session_sequence(random.Random(42), min_len=3)
print(f'Schema: {N_CLASSES} classes, {N_FEATURES} features')
print(f'Kill-chain: {seq}')
PYEOF
) || SMOKE_OK=0

"$VENV_PY" - <<'PYEOF' || SMOKE_OK=0
import sys; sys.path.insert(0, '.')
import torch
from ml_analytics.models.mt3 import MT3
model = MT3()
x = torch.randn(4, 128)
y = torch.randint(0, 45, (4,))
emissions, hp_logits, loss = model(x, labels=y)
print(f'MT3: emissions={emissions.shape} hp={hp_logits.shape} loss={loss.item():.4f}')
print(f'Params: {model.count_parameters():,}')
PYEOF

if [ "$SMOKE_OK" -eq 1 ]; then
    log "Smoke test PASSED."
else
    err "Smoke test FAILED — see output above."
fi

# ── 10. Summary ───────────────────────────────────────────────────────────
log "Summary"
"$VENV_PY" - <<'PYEOF'
import sys
print(f"  Python:       {sys.version.split()[0]}")
try:
    import torch
    print(f"  PyTorch:      {torch.__version__}")
    cuda = torch.cuda.is_available()
    print(f"  GPU detected: {'YES' if cuda else 'NO'}")
    if cuda:
        print(f"  GPU:          {torch.cuda.get_device_name(0)}")
        vram = torch.cuda.get_device_properties(0).total_memory / 1e9
        print(f"  VRAM:         {vram:.1f} GB")
except ImportError as e:
    print(f"  PyTorch:      MISSING ({e})")

for name in ("numpy", "pandas", "scipy", "sklearn", "transformers", "xgboost", "be_great", "jupyter"):
    try:
        mod = __import__(name)
        ver = getattr(mod, "__version__", "OK")
        print(f"  {name:<14}{ver}")
    except ImportError as e:
        print(f"  {name:<14}MISSING ({e})")
PYEOF

if [ "$SMOKE_OK" -eq 1 ]; then
    log "Setup complete."
    exit 0
else
    exit 1
fi
