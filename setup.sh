#!/usr/bin/env bash
# setup.sh — Adaptive Honeypot / HoneySynth-1M environment bootstrap (Linux)
#
# Sets up the venv at honeypot_dataset/venv, installs CUDA PyTorch (cu121),
# project + TabSyn dependencies, clones TabSyn if missing, and runs a smoke
# test of the schema + MT3 architecture.
#
# Idempotent: safe to run repeatedly. Existing venv / already-satisfied
# packages / an already-cloned tabsyn/ are detected and skipped, not redone.
#
# Usage:  ./setup.sh
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$ROOT/honeypot_dataset/venv"
REQS="$ROOT/honeypot_dataset/requirements.txt"
TABSYN_DIR="$ROOT/tabsyn"
TABSYN_REPO="https://github.com/amazon-science/tabsyn.git"

STEP=0
step() { STEP=$((STEP + 1)); echo; echo "== [$STEP/10] $1 =="; }
ok()   { echo "   OK: $1"; }
warn() { echo "   WARN: $1"; }
fail() { echo "   ERROR: $1"; exit 1; }

# ── 1. Check Python 3.11 ──────────────────────────────────────────────────
step "Checking Python 3.11"
PYTHON_BIN=""
if command -v python3.11 >/dev/null 2>&1; then
    PYTHON_BIN="$(command -v python3.11)"
elif command -v python3 >/dev/null 2>&1 && python3 --version 2>&1 | grep -q "3\.11"; then
    PYTHON_BIN="$(command -v python3)"
fi
[ -n "$PYTHON_BIN" ] || fail "Python 3.11 not found. Install it (e.g. 'sudo apt install python3.11 python3.11-venv') and re-run."
ok "$($PYTHON_BIN --version) at $PYTHON_BIN"

# ── 2. Create venv if missing ─────────────────────────────────────────────
step "Virtual environment"
if [ -d "$VENV_DIR" ] && [ -f "$VENV_DIR/bin/activate" ]; then
    ok "venv already exists at $VENV_DIR — skipping creation"
else
    "$PYTHON_BIN" -m venv "$VENV_DIR" || fail "venv creation failed"
    ok "created venv at $VENV_DIR"
fi

# ── 3. Activate venv ──────────────────────────────────────────────────────
step "Activating venv"
# shellcheck disable=SC1091
source "$VENV_DIR/bin/activate" || fail "could not activate venv"
python -m pip install --upgrade pip -q
ok "venv active: $(python --version) at $(command -v python)"

# ── 4. CUDA PyTorch (cu121) ───────────────────────────────────────────────
step "CUDA PyTorch (cu121)"
if python -c "import torch, sys; sys.exit(0 if torch.cuda.is_available() else 1)" >/dev/null 2>&1; then
    ok "torch already installed with CUDA available ($(python -c 'import torch; print(torch.__version__)'))"
else
    warn "installing torch (cu121 build) — this can take a few minutes"
    pip install torch --index-url https://download.pytorch.org/whl/cu121 -q \
        || warn "cu121 install failed (no matching GPU/driver on this machine?) — continuing with whatever torch is present"
fi

# ── 5. Install all requirements ───────────────────────────────────────────
step "Project requirements (honeypot_dataset/requirements.txt)"
if [ -f "$REQS" ]; then
    pip install -r "$REQS" -q || fail "requirements install failed"
    ok "requirements satisfied"
else
    warn "no requirements.txt found at $REQS — skipping"
fi

# ── 6. Extra packages (dotenv, jupyter, xgboost, be-great) ───────────────
step "Extra packages: python-dotenv, jupyter, xgboost, be-great"
ensure_pkg() {
    # $1 = pip package name, $2 = python import name (may differ)
    if python -c "import ${2}" >/dev/null 2>&1; then
        ok "${1} already installed — skipping"
    else
        pip install "${1}" -q || warn "failed to install ${1}"
    fi
}
ensure_pkg "python-dotenv" "dotenv"
ensure_pkg "jupyter" "jupyter_core"
ensure_pkg "xgboost" "xgboost"
ensure_pkg "be-great" "be_great"

# ── 7. Clone TabSyn if missing, apply 4GB-VRAM patch ──────────────────────
step "TabSyn repo (clone + VRAM patch)"
if [ -d "$TABSYN_DIR" ] && [ -d "$TABSYN_DIR/.git" ]; then
    ok "tabsyn/ already present — skipping clone"
else
    command -v git >/dev/null 2>&1 || fail "git not found — cannot clone TabSyn"
    git clone "$TABSYN_REPO" "$TABSYN_DIR" || fail "TabSyn clone failed"
    ok "cloned TabSyn to $TABSYN_DIR"
fi

PATCH_FILE="$ROOT/honeypot_dataset/docs/tabsyn_patches.patch"
if [ -f "$PATCH_FILE" ]; then
    if git -C "$TABSYN_DIR" apply --check "$PATCH_FILE" >/dev/null 2>&1; then
        git -C "$TABSYN_DIR" apply "$PATCH_FILE" \
            && ok "applied 4GB-VRAM patch (tabsyn_patches.patch)" \
            || warn "patch apply failed unexpectedly — see honeypot_dataset/docs/tabsyn_patches.md"
    elif git -C "$TABSYN_DIR" apply --check --reverse "$PATCH_FILE" >/dev/null 2>&1; then
        ok "4GB-VRAM patch already applied — skipping"
    else
        warn "could not verify VRAM patch state (tabsyn/ may have manual edits) — check manually: git -C tabsyn apply --check honeypot_dataset/docs/tabsyn_patches.patch"
    fi
else
    warn "patch file not found at $PATCH_FILE — skipping VRAM patch (TabSyn may OOM on small-VRAM cards)"
fi

# ── 8. TabSyn requirements ────────────────────────────────────────────────
step "TabSyn requirements"
if [ -f "$TABSYN_DIR/requirements.txt" ]; then
    pip install -r "$TABSYN_DIR/requirements.txt" -q || warn "some TabSyn requirements failed to install"
    ok "TabSyn requirements satisfied"
else
    warn "no requirements.txt found in $TABSYN_DIR"
fi

# ── 9. Smoke test: schema + MT3 ───────────────────────────────────────────
step "Smoke test (schema + MT3)"
SMOKE_OK=1
(
    cd "$ROOT/honeypot_dataset" && python -c "
import sys; sys.path.insert(0, '.')
from configs.schema import MICRO_STATES, N_CLASSES, N_FEATURES
from src.extractors.temporal import extract_temporal
from src.generators.kill_chain_simulator import generate_session_sequence
import random
seq = generate_session_sequence(random.Random(42), min_len=3)
assert N_CLASSES == 45 and N_FEATURES == 128
print(f'Schema OK: {N_CLASSES} classes, {N_FEATURES} features')
print(f'Kill-chain seq: {seq}')
"
) || SMOKE_OK=0

(cd "$ROOT" && python -m models.mt3.architecture) || SMOKE_OK=0

if [ "$SMOKE_OK" -eq 1 ]; then
    ok "schema + MT3 smoke test PASSED"
else
    warn "smoke test FAILED — see output above"
fi

# ── 10. Summary ────────────────────────────────────────────────────────────
step "Summary"
if command -v nvidia-smi >/dev/null 2>&1; then
    GPU_INFO="$(nvidia-smi --query-gpu=name,memory.total --format=csv,noheader 2>/dev/null)"
    if [ -n "$GPU_INFO" ]; then
        echo "   GPU detected : $GPU_INFO"
    else
        echo "   GPU detected : nvidia-smi present but returned no data"
    fi
else
    echo "   GPU detected : none (nvidia-smi not found)"
fi
python -c "
import torch
print(f'   torch          : {torch.__version__}  (CUDA available: {torch.cuda.is_available()})')
" 2>/dev/null || echo "   torch          : NOT IMPORTABLE"

for pkg in numpy pandas sklearn transformers xgboost be_great dotenv jupyter_core; do
    python -c "import ${pkg}" >/dev/null 2>&1 && echo "   ${pkg} : OK" || echo "   ${pkg} : MISSING"
done

echo
if [ "$SMOKE_OK" -eq 1 ]; then
    echo "Setup complete — smoke test passed."
else
    echo "Setup finished with warnings — smoke test did not fully pass, see above."
fi
