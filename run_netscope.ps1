

param(
    [string]$Port = "COM3",
    [switch]$NoTshark,
    [switch]$NoEsp,
    [string]$ExportDir = ".",
    [string]$Interface = ""
)

$ErrorActionPreference = "Stop"

Write-Host "==========================================" -ForegroundColor Cyan
Write-Host "  NETSCOPE — Real-time Network Monitor"     -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

try {
    $pyVersion = python --version 2>&1
    Write-Host "[OK] $pyVersion" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Python not found. Install Python 3.12+ and add to PATH." -ForegroundColor Red
    exit 1
}

try {
    python -c "import textual" 2>$null
    Write-Host "[OK] Textual installed" -ForegroundColor Green
} catch {
    Write-Host "[WARN] Installing textual..." -ForegroundColor Yellow
    pip install textual
}

$cmdArgs = @("-m", "netscope", "--port", $Port, "--export-dir", $ExportDir)

if ($NoTshark) {
    $cmdArgs += "--no-tshark"
}
if ($NoEsp) {
    $cmdArgs += "--no-esp"
}
if ($Interface -ne "") {
    $cmdArgs += @("--interface", $Interface)
}

Write-Host ""
Write-Host "Starting NETSCOPE..." -ForegroundColor Cyan
Write-Host "  Port:      $Port"
Write-Host "  TShark:    $(if ($NoTshark) { 'disabled' } else { 'auto-detect' })"
Write-Host "  ESP32:     $(if ($NoEsp) { 'disabled' } else { 'auto-detect' })"
Write-Host "  Export to: $ExportDir"
Write-Host ""

python @cmdArgs
