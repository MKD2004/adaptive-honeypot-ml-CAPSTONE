# collect_logs.ps1 — Copy Cowrie JSON logs to the dataset pipeline
# Run this periodically to sync logs into the dataset directory

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$LogSource = Join-Path $ScriptDir "logs"
$LogDest   = Join-Path $ScriptDir "..\data\raw\cowrie_logs"

if (-not (Test-Path $LogDest)) {
    New-Item -ItemType Directory -Path $LogDest -Force | Out-Null
}

# Copy all cowrie.json* files
$files = Get-ChildItem -Path $LogSource -Filter "cowrie.json*" -ErrorAction SilentlyContinue
if ($files) {
    foreach ($f in $files) {
        Copy-Item $f.FullName -Destination $LogDest -Force
        Write-Host "  Copied: $($f.Name) ($([math]::Round($f.Length/1KB)) KB)"
    }
    Write-Host "`nTotal files copied: $($files.Count)"

    # Quick stats
    $mainLog = Join-Path $LogDest "cowrie.json"
    if (Test-Path $mainLog) {
        $lines = (Get-Content $mainLog | Measure-Object -Line).Lines
        Write-Host "Current cowrie.json: $lines events"
    }
} else {
    Write-Host "No cowrie.json files found in $LogSource"
    Write-Host "Make sure Cowrie is running: docker compose up -d"
}
