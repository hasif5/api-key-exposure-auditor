# Build a store-ready zip (Chrome Web Store / Edge Add-ons) — runtime files only.
# Produces forward-slash entry names so the Chrome Web Store accepts it.
# Usage:  .\build.ps1
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.IO.Compression | Out-Null
Add-Type -AssemblyName System.IO.Compression.FileSystem | Out-Null

$root  = (Get-Location).Path
$out   = 'dist'
$name  = 'api-key-exposure-auditor-store.zip'
$items = @('manifest.json', 'background.js', 'content', 'lib', 'popup', 'dashboard', 'collection', 'icons')

New-Item -ItemType Directory -Force $out | Out-Null
$zipPath = Join-Path $out $name
if (Test-Path $zipPath) { Remove-Item $zipPath -Force }

# Collect the files to include.
$files = @()
foreach ($it in $items) {
  $p = Join-Path $root $it
  if (Test-Path $p -PathType Container) { $files += Get-ChildItem $p -Recurse -File }
  elseif (Test-Path $p)                 { $files += Get-Item $p }
}

$zip = [System.IO.Compression.ZipFile]::Open($zipPath, 'Create')
try {
  foreach ($f in $files) {
    $rel = $f.FullName.Substring($root.Length + 1) -replace '\\', '/'
    [void][System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $f.FullName, $rel)
  }
} finally {
  $zip.Dispose()
}

Write-Host "Built $zipPath ($($files.Count) files)" -ForegroundColor Green
Write-Host "Upload this file in the Chrome Web Store / Edge Add-ons developer dashboard."
