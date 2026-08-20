# setup.ps1 - Adaptive Honeypot / HoneySynth-1M environment bootstrap (Windows)
#
# Sets up the venv at honeypot_dataset\venv, installs CUDA PyTorch (cu121),
# project + TabSyn dependencies, clones TabSyn if missing, and runs a smoke
# test of the schema + MT3 architecture.
#
# Idempotent: safe to run repeatedly. Existing venv / already-satisfied
# packages / an already-cloned tabsyn\ are detected and skipped, not redone.
#
# Usage:  .\setup.ps1
# If blocked by execution policy:
#   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

$ErrorActionPreference = "Continue"

$ROOT        = $PSScriptRoot
$VenvDir     = Join-Path $ROOT "honeypot_dataset\venv"
$ReqsFile    = Join-Path $ROOT "honeypot_dataset\requirements.txt"
$TabsynDir   = Join-Path $ROOT "tabsyn"
$TabsynRepo  = "https://github.com/amazon-science/tabsyn.git"

$Step = 0
function Step($msg)  { $script:Step++; Write-Host ""; Write-Host "== [$($script:Step)/10] $msg ==" }
function Ok($msg)    { Write-Host "   OK: $msg" }
function WarnMsg($msg) { Write-Host "   WARN: $msg" }
function FailMsg($msg) { Write-Host "   ERROR: $msg"; exit 1 }

# -- 1. Check Python 3.11 ---------------------------------------------------
Step "Checking Python 3.11"
$PythonBin = $null
try {
    $pyVersion = & py -3.11 --version 2>$null
    if ($LASTEXITCODE -eq 0 -and $pyVersion -match "3\.11") {
        $PythonBin = "py -3.11"
    }
} catch {}
if (-not $PythonBin) {
    try {
        $pyVersion = & python --version 2>$null
        if ($pyVersion -match "3\.11") { $PythonBin = "python" }
    } catch {}
}
if (-not $PythonBin) {
    FailMsg "Python 3.11 not found. Install it from python.org and re-run (make sure 'py -3.11' or 'python --version' resolves to 3.11)."
}
Ok "$PythonBin -> $(Invoke-Expression "$PythonBin --version")"

# -- 2. Create venv if missing ----------------------------------------------
Step "Virtual environment"
$VenvPython = Join-Path $VenvDir "Scripts\python.exe"
$VenvActivate = Join-Path $VenvDir "Scripts\Activate.ps1"
if ((Test-Path $VenvDir) -and (Test-Path $VenvActivate)) {
    Ok "venv already exists at $VenvDir - skipping creation"
} else {
    Invoke-Expression "$PythonBin -m venv `"$VenvDir`""
    if ($LASTEXITCODE -ne 0) { FailMsg "venv creation failed" }
    Ok "created venv at $VenvDir"
}

# -- 3. Activate venv --------------------------------------------------------
Step "Activating venv"
if (-not (Test-Path $VenvActivate)) { FailMsg "activation script not found at $VenvActivate" }
& $VenvActivate
& $VenvPython -m pip install --upgrade pip -q
Ok "venv active: $(& $VenvPython --version) at $VenvPython"

# -- 4. CUDA PyTorch (cu121) --------------------------------------------------
Step "CUDA PyTorch (cu121)"
& $VenvPython -c "import torch, sys; sys.exit(0 if torch.cuda.is_available() else 1)" 2>$null
if ($LASTEXITCODE -eq 0) {
    $torchVer = & $VenvPython -c "import torch; print(torch.__version__)"
    Ok "torch already installed with CUDA available ($torchVer)"
} else {
    WarnMsg "installing torch (cu121 build) - this can take a few minutes"
    & $VenvPython -m pip install torch --index-url https://download.pytorch.org/whl/cu121 -q
    if ($LASTEXITCODE -ne 0) {
        WarnMsg "cu121 install failed (no matching GPU/driver on this machine?) - continuing with whatever torch is present"
    }
}

# -- 5. Install all requirements ---------------------------------------------
Step "Project requirements (honeypot_dataset\requirements.txt)"
if (Test-Path $ReqsFile) {
    & $VenvPython -m pip install -r $ReqsFile -q
    if ($LASTEXITCODE -ne 0) { FailMsg "requirements install failed" }
    Ok "requirements satisfied"
} else {
    WarnMsg "no requirements.txt found at $ReqsFile - skipping"
}

# -- 6. Extra packages (dotenv, jupyter, xgboost, be-great) ------------------
Step "Extra packages: python-dotenv, jupyter, xgboost, be-great"
function Ensure-Pkg($pipName, $importName) {
    & $VenvPython -c "import $importName" 2>$null
    if ($LASTEXITCODE -eq 0) {
        Ok "$pipName already installed - skipping"
    } else {
        & $VenvPython -m pip install $pipName -q
        if ($LASTEXITCODE -ne 0) { WarnMsg "failed to install $pipName" }
    }
}
Ensure-Pkg "python-dotenv" "dotenv"
Ensure-Pkg "jupyter" "jupyter_core"
Ensure-Pkg "xgboost" "xgboost"
Ensure-Pkg "be-great" "be_great"

# -- 7. Clone TabSyn if missing, apply 4GB-VRAM patch ------------------------
Step "TabSyn repo (clone + VRAM patch)"
if ((Test-Path $TabsynDir) -and (Test-Path (Join-Path $TabsynDir ".git"))) {
    Ok "tabsyn\ already present - skipping clone"
} else {
    if (-not (Get-Command git -ErrorAction SilentlyContinue)) { FailMsg "git not found - cannot clone TabSyn" }
    git clone $TabsynRepo $TabsynDir
    if ($LASTEXITCODE -ne 0) { FailMsg "TabSyn clone failed" }
    Ok "cloned TabSyn to $TabsynDir"
}

$PatchFile = Join-Path $ROOT "honeypot_dataset\docs\tabsyn_patches.patch"
if (Test-Path $PatchFile) {
    git -C $TabsynDir apply --check $PatchFile 2>$null
    if ($LASTEXITCODE -eq 0) {
        git -C $TabsynDir apply $PatchFile
        if ($LASTEXITCODE -eq 0) {
            Ok "applied 4GB-VRAM patch (tabsyn_patches.patch)"
        } else {
            WarnMsg "patch apply failed unexpectedly - see honeypot_dataset\docs\tabsyn_patches.md"
        }
    } else {
        git -C $TabsynDir apply --check --reverse $PatchFile 2>$null
        if ($LASTEXITCODE -eq 0) {
            Ok "4GB-VRAM patch already applied - skipping"
        } else {
            WarnMsg "could not verify VRAM patch state (tabsyn\ may have manual edits) - check manually: git -C tabsyn apply --check honeypot_dataset\docs\tabsyn_patches.patch"
        }
    }
} else {
    WarnMsg "patch file not found at $PatchFile - skipping VRAM patch (TabSyn may OOM on small-VRAM cards)"
}

# -- 8. TabSyn requirements ----------------------------------------------------
Step "TabSyn requirements"
$TabsynReqs = Join-Path $TabsynDir "requirements.txt"
if (Test-Path $TabsynReqs) {
    & $VenvPython -m pip install -r $TabsynReqs -q
    if ($LASTEXITCODE -ne 0) { WarnMsg "some TabSyn requirements failed to install" }
    Ok "TabSyn requirements satisfied"
} else {
    WarnMsg "no requirements.txt found in $TabsynDir"
}

# -- 9. Smoke test: schema + MT3 ----------------------------------------------
Step "Smoke test (schema + MT3)"
$SmokeOk = $true

Push-Location (Join-Path $ROOT "honeypot_dataset")
& $VenvPython -c @"
import sys; sys.path.insert(0, '.')
from configs.schema import MICRO_STATES, N_CLASSES, N_FEATURES
from src.extractors.temporal import extract_temporal
from src.generators.kill_chain_simulator import generate_session_sequence
import random
seq = generate_session_sequence(random.Random(42), min_len=3)
assert N_CLASSES == 45 and N_FEATURES == 128
print(f'Schema OK: {N_CLASSES} classes, {N_FEATURES} features')
print(f'Kill-chain seq: {seq}')
"@
if ($LASTEXITCODE -ne 0) { $SmokeOk = $false }
Pop-Location

Push-Location $ROOT
& $VenvPython -m models.mt3.architecture
if ($LASTEXITCODE -ne 0) { $SmokeOk = $false }
Pop-Location

if ($SmokeOk) { Ok "schema + MT3 smoke test PASSED" } else { WarnMsg "smoke test FAILED - see output above" }

# -- 10. Summary ----------------------------------------------------------------
Step "Summary"
if (Get-Command nvidia-smi -ErrorAction SilentlyContinue) {
    $gpuInfo = & nvidia-smi --query-gpu=name,memory.total --format=csv,noheader 2>$null
    if ($gpuInfo) {
        Write-Host "   GPU detected : $gpuInfo"
    } else {
        Write-Host "   GPU detected : nvidia-smi present but returned no data"
    }
} else {
    Write-Host "   GPU detected : none (nvidia-smi not found)"
}

& $VenvPython -c "import torch; print(f'   torch          : {torch.__version__}  (CUDA available: {torch.cuda.is_available()})')" 2>$null
if ($LASTEXITCODE -ne 0) { Write-Host "   torch          : NOT IMPORTABLE" }

foreach ($pkg in @("numpy","pandas","sklearn","transformers","xgboost","be_great","dotenv","jupyter_core")) {
    & $VenvPython -c "import $pkg" 2>$null
    if ($LASTEXITCODE -eq 0) { Write-Host "   $pkg : OK" } else { Write-Host "   $pkg : MISSING" }
}

Write-Host ""
if ($SmokeOk) {
    Write-Host "Setup complete - smoke test passed."
} else {
    Write-Host "Setup finished with warnings - smoke test did not fully pass, see above."
}
