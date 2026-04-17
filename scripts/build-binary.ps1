Param(
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$python = "C:/Program Files/Python312/python.exe"
if (-not (Test-Path $python)) {
    $python = "python"
}

if ($Clean) {
    if (Test-Path "build") { Remove-Item -Recurse -Force "build" }
    if (Test-Path "dist") { Remove-Item -Recurse -Force "dist" }
    if (Test-Path "packetpulse.spec") { Remove-Item -Force "packetpulse.spec" }
}

& $python -m pip install --upgrade pyinstaller
& $python -m PyInstaller --onefile --name packetpulse packetpulse/cli.py

Write-Host "Binary created at dist/packetpulse(.exe)"
