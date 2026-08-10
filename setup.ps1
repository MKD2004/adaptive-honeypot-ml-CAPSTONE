<#
.SYNOPSIS
    Automates the full dev environment setup for adaptive-honeypot-ml-CAPSTONE
    (Windows laptop).

.DESCRIPTION
    Idempotent: safe to re-run. Existing venv / satisfied packages / an
    existing tabsyn/ checkout are detected and skipped, not recreated.

.EXAMPLE
    .\setup.ps1

    If script execution is blocked, run once in this session first:
        Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

    Override the TabSyn repo to clone with:
        $env:TABSYN_REPO_URL = "..."; .\setup.ps1
#>

$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

$VenvDir   = Join-Path $ProjectRoot "venv"
$TabsynDir = Join-Path $ProjectRoot "tabsyn"
$TabsynRepoUrl = if ($env:TABSYN_REPO_URL) { $env:TABSYN_REPO_URL } else { "https://github.com/amazon-science/tabsyn.git" }

function Write-Log  ($msg) { Write-Host "`n[setup] $msg" -ForegroundColor Cyan }
function Write-Warn2($msg) { Write-Host "[setup][warn] $msg" -ForegroundColor Yellow }
function Write-Err2 ($msg) { Write-Host "[setup][error] $msg" -ForegroundColor Red }

function Assert-Success($msg) {
    if ($LASTEXITCODE -ne 0) {
        Write-Err2 $msg
        exit 1
    }
}

# ── 1. Check Python 3.11 ─────────────────────────────────────────────────
Write-Log "Checking for Python 3.11..."
$PyCmd = $null
$PyPrefixArgs = @()

$pyLauncher = Get-Command py -ErrorAction SilentlyContinue
if ($pyLauncher) {
    & py -3.11 --version | Out-Null
    if ($LASTEXITCODE -eq 0) {
        $PyCmd = "py"
        $PyPrefixArgs = @("-3.11")
    }
}

if (-not $PyCmd) {
    foreach ($candidate in @("python3.11", "python3.11.exe")) {
        $found = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($found) {
            $PyCmd = $candidate
            break
        }
    }
}

if (-not $PyCmd) {
    Write-Err2 "Python 3.11 not found."
    Write-Err2 "CUDA PyTorch (cu121) wheels aren't published for every Python version --"
    Write-Err2 "this project standardises on 3.11 specifically so the GPU build installs cleanly."
    Write-Err2 ""
    Write-Err2 "Install it with:"
    Write-Err2 "  winget install Python.Python.3.11"
    Write-Err2 "  (or download from https://www.python.org/downloads/ -- check 'Add to PATH' and the py launcher option)"
    exit 1
}

$PyVersionText = & $PyCmd @PyPrefixArgs --version
Write-Log "Found $PyVersionText ($PyCmd $($PyPrefixArgs -join ' '))"

# ── 2. Create venv if missing ────────────────────────────────────────────
$VenvPy = Join-Path $VenvDir "Scripts\python.exe"

if (Test-Path $VenvPy) {
    Write-Log "venv already exists at $VenvDir -- skipping creation."
} else {
    Write-Log "Creating venv at $VenvDir..."
    & $PyCmd @PyPrefixArgs -m venv $VenvDir
    if (-not (Test-Path $VenvPy)) {
        Write-Err2 "venv creation failed."
        exit 1
    }
}

# ── 3. Activate venv ─────────────────────────────────────────────────────
Write-Log "Activating venv..."
$ActivateScript = Join-Path $VenvDir "Scripts\Activate.ps1"
try {
    . $ActivateScript
} catch {
    Write-Warn2 "Could not dot-source Activate.ps1 (execution policy?) -- continuing via $VenvPy directly."
    Write-Warn2 "To enable activation: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass"
}

& $VenvPy -m pip install --upgrade pip -q
Assert-Success "pip upgrade failed."

# ── 4. Install CUDA PyTorch (cu121) ──────────────────────────────────────
& $VenvPy -c "
import sys
try:
    import torch
except ImportError:
    sys.exit(1)
sys.exit(0 if torch.cuda.is_available() else 1)
" 2>$null | Out-Null
$CudaOk = ($LASTEXITCODE -eq 0)

if ($CudaOk) {
    Write-Log "torch with CUDA already available -- skipping."
} else {
    $nvidiaSmi = Get-Command nvidia-smi -ErrorAction SilentlyContinue
    if (-not $nvidiaSmi) {
        Write-Warn2 "nvidia-smi not found -- no NVIDIA driver detected on this machine."
        Write-Warn2 "Installing the cu121 wheel anyway; it will run CPU-only here."
    }
    Write-Log "Installing CUDA PyTorch (cu121)..."
    & $VenvPy -m pip install torch --index-url https://download.pytorch.org/whl/cu121 -q
    Assert-Success "torch (cu121) install failed."
}

# ── 5. Install all requirements ──────────────────────────────────────────
Write-Log "Installing requirements.txt..."
& $VenvPy -m pip install -r (Join-Path $ProjectRoot "requirements.txt") -q
Assert-Success "requirements.txt install failed."

$HpReqs = Join-Path $ProjectRoot "honeypot_dataset\requirements.txt"
if (Test-Path $HpReqs) {
    Write-Log "Installing honeypot_dataset/requirements.txt..."
    & $VenvPy -m pip install -r $HpReqs -q
    Assert-Success "honeypot_dataset/requirements.txt install failed."
}

# ── 6. Ensure key extras are present ─────────────────────────────────────
Write-Log "Ensuring python-dotenv, jupyter, xgboost, be-great are installed..."
& $VenvPy -m pip install -q "python-dotenv>=1.0.0" "jupyter>=1.0.0" "xgboost>=2.0.0" "be-great"
Assert-Success "extras install failed."

# ── 7. Clone TabSyn if missing ────────────────────────────────────────────
if (Test-Path $TabsynDir) {
    Write-Log "tabsyn/ already exists -- skipping clone."
} else {
    Write-Log "Cloning TabSyn from $TabsynRepoUrl..."
    git clone $TabsynRepoUrl $TabsynDir
    if ($LASTEXITCODE -ne 0) {
        Write-Warn2 "TabSyn clone failed -- check TABSYN_REPO_URL / network access and retry."
    }
}

# ── 8. Install TabSyn requirements ───────────────────────────────────────
$TabsynReqs = Join-Path $TabsynDir "requirements.txt"
if (Test-Path $TabsynReqs) {
    Write-Log "Installing tabsyn/requirements.txt..."
    & $VenvPy -m pip install -r $TabsynReqs -q
    if ($LASTEXITCODE -ne 0) {
        Write-Warn2 "tabsyn/requirements.txt install had errors -- check output above."
    }
} elseif (Test-Path $TabsynDir) {
    Write-Warn2 "tabsyn/requirements.txt not found -- skipping (check the repo's own setup instructions)."
}

# ── 9. Smoke test: schema + MT3 ──────────────────────────────────────────
Write-Log "Running smoke test..."
$SmokeOk = $true

$SchemaTestFile = Join-Path $env:TEMP "honeypot_schema_smoke_test.py"
@'
import sys; sys.path.insert(0, '.')
from configs.schema import N_CLASSES, N_FEATURES, KILL_CHAIN_DAG
from src.generators.kill_chain_simulator import generate_session_sequence
import random
seq = generate_session_sequence(random.Random(42), min_len=3)
print(f'Schema: {N_CLASSES} classes, {N_FEATURES} features')
print(f'Kill-chain: {seq}')
'@ | Set-Content -Path $SchemaTestFile -Encoding utf8

Push-Location (Join-Path $ProjectRoot "honeypot_dataset")
& $VenvPy $SchemaTestFile
if ($LASTEXITCODE -ne 0) { $SmokeOk = $false }
Pop-Location
Remove-Item $SchemaTestFile -ErrorAction SilentlyContinue

$MT3TestFile = Join-Path $env:TEMP "mt3_smoke_test.py"
@'
import sys; sys.path.insert(0, '.')
import torch
from ml_analytics.models.mt3 import MT3
model = MT3()
x = torch.randn(4, 128)
y = torch.randint(0, 45, (4,))
emissions, hp_logits, loss = model(x, labels=y)
print(f'MT3: emissions={emissions.shape} hp={hp_logits.shape} loss={loss.item():.4f}')
print(f'Params: {model.count_parameters():,}')
'@ | Set-Content -Path $MT3TestFile -Encoding utf8

& $VenvPy $MT3TestFile
if ($LASTEXITCODE -ne 0) { $SmokeOk = $false }
Remove-Item $MT3TestFile -ErrorAction SilentlyContinue

if ($SmokeOk) {
    Write-Log "Smoke test PASSED."
} else {
    Write-Err2 "Smoke test FAILED -- see output above."
}

# ── 10. Summary ────────────────────────────────────────────────────────────
Write-Log "Summary"
$SummaryFile = Join-Path $env:TEMP "env_summary.py"
@'
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
'@ | Set-Content -Path $SummaryFile -Encoding utf8

& $VenvPy $SummaryFile
Remove-Item $SummaryFile -ErrorAction SilentlyContinue

if ($SmokeOk) {
    Write-Log "Setup complete."
    exit 0
} else {
    exit 1
}
