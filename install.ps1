# Quick installer (Windows / PowerShell) for the API Key Exposure Auditor.
# Downloads the latest source into a folder, then tells you how to load it.
# Usage:  iwr -useb https://raw.githubusercontent.com/hasif5/api-key-exposure-auditor/main/install.ps1 | iex
#   or:   .\install.ps1

$ErrorActionPreference = 'Stop'
$repo = 'hasif5/api-key-exposure-auditor'
$dest = Join-Path $HOME 'api-key-exposure-auditor'
$zip  = Join-Path $env:TEMP 'gakea-src.zip'
$tmp  = Join-Path $env:TEMP 'gakea-extract'

Write-Host "Downloading latest source..." -ForegroundColor Cyan
Invoke-WebRequest "https://github.com/$repo/archive/refs/heads/main.zip" -OutFile $zip

if (Test-Path $tmp)  { Remove-Item $tmp  -Recurse -Force }
if (Test-Path $dest) { Remove-Item $dest -Recurse -Force }
Expand-Archive $zip -DestinationPath $tmp -Force
Move-Item (Join-Path $tmp 'api-key-exposure-auditor-main') $dest -Force
Remove-Item $zip -Force
Remove-Item $tmp -Recurse -Force

Write-Host ""
Write-Host "Installed to: $dest" -ForegroundColor Green
Write-Host ""
Write-Host "Now load it in your browser (one time):" -ForegroundColor Yellow
Write-Host "  1. Open  chrome://extensions   (or  edge://extensions )"
Write-Host "  2. Turn on  Developer mode  (top-right toggle)"
Write-Host "  3. Click  Load unpacked  and select:"
Write-Host "       $dest"
Write-Host ""
Write-Host "To update later, just run this installer again." -ForegroundColor DarkGray
