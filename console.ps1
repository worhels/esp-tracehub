param([string]$Port = 'COM3')
$ErrorActionPreference = 'Stop'
Write-Host 'ESP-LAB console. Enter: help, status, flash-check 16. Exit: Ctrl+]'
Write-Host 'Opening a USB-UART port may reset the board, depending on its wiring.'
python -m serial.tools.miniterm --dtr 0 --rts 0 --echo --eol LF $Port 115200
if ($LASTEXITCODE -ne 0) {
    Write-Host "Console stopped with error $LASTEXITCODE. Check the cable and port." -ForegroundColor Red
    Read-Host 'Press Enter to close'
    exit $LASTEXITCODE
}
