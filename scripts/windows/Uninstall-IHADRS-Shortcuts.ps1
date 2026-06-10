[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

$programsDir = Join-Path ([Environment]::GetFolderPath("Programs")) "IHADRS EDR"
$desktopShortcut = Join-Path ([Environment]::GetFolderPath("Desktop")) "IHADRS EDR.lnk"

Remove-Item -Path $desktopShortcut -Force -ErrorAction SilentlyContinue
Remove-Item -Path $programsDir -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Removed IHADRS Desktop and Start Menu shortcuts." -ForegroundColor Green
