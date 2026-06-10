[CmdletBinding()]
param(
    [switch]$NoDesktopShortcut,
    [switch]$SkipDependencyInstall
)

$ErrorActionPreference = "Stop"

function Get-RepoRoot {
    return (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
}

function New-Shortcut {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$TargetPath,
        [Parameter(Mandatory = $true)][string]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$Description,
        [string]$IconLocation
    )

    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut($Path)
    $shortcut.TargetPath = $TargetPath
    $shortcut.Arguments = $Arguments
    $shortcut.WorkingDirectory = $WorkingDirectory
    $shortcut.Description = $Description
    if ($IconLocation) {
        $shortcut.IconLocation = $IconLocation
    }
    $shortcut.Save()
}

function Get-PythonLauncher {
    $candidates = @("py.exe", "python.exe")
    foreach ($candidate in $candidates) {
        $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($cmd) {
            return $cmd.Source
        }
    }
    throw "Python was not found. Install Python 3.11+ or create the venv manually."
}

$repoRoot = Get-RepoRoot
$venvPython = Join-Path $repoRoot "venv\Scripts\python.exe"
$requirements = Join-Path $repoRoot "requirements.txt"
$startScript = Join-Path $repoRoot "scripts\windows\Start-IHADRS.ps1"
$dashboardScript = Join-Path $repoRoot "scripts\windows\Open-IHADRS-Dashboard.ps1"
$stopScript = Join-Path $repoRoot "scripts\windows\Stop-IHADRS.ps1"
$powershell = Join-Path $PSHOME "powershell.exe"
$icon = "$env:SystemRoot\System32\imageres.dll,78"

Write-Host "Installing IHADRS Windows shortcuts..." -ForegroundColor Cyan
Write-Host "Project: $repoRoot"

if (-not (Test-Path $venvPython)) {
    if ($SkipDependencyInstall) {
        throw "venv was not found at $venvPython and dependency installation was skipped."
    }

    $pythonLauncher = Get-PythonLauncher
    Write-Host "Creating Python virtual environment..." -ForegroundColor Cyan
    if ((Split-Path -Leaf $pythonLauncher) -ieq "py.exe") {
        & $pythonLauncher -3.11 -m venv (Join-Path $repoRoot "venv")
    } else {
        & $pythonLauncher -m venv (Join-Path $repoRoot "venv")
    }

    if (-not (Test-Path $venvPython)) {
        throw "Failed to create the IHADRS virtual environment."
    }

    Write-Host "Installing runtime dependencies..." -ForegroundColor Cyan
    & $venvPython -m pip install --upgrade pip
    & $venvPython -m pip install -r $requirements
} else {
    Write-Host "Using existing virtual environment: $venvPython" -ForegroundColor Green
}

$programsDir = Join-Path ([Environment]::GetFolderPath("Programs")) "IHADRS EDR"
New-Item -ItemType Directory -Force -Path $programsDir | Out-Null

$shortcutArgs = @{
    TargetPath = $powershell
    WorkingDirectory = $repoRoot
    IconLocation = $icon
}

New-Shortcut `
    -Path (Join-Path $programsDir "IHADRS EDR.lnk") `
    -Arguments "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$startScript`"" `
    -Description "Start IHADRS EDR and open the dashboard." `
    @shortcutArgs

New-Shortcut `
    -Path (Join-Path $programsDir "IHADRS Dashboard.lnk") `
    -Arguments "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$dashboardScript`"" `
    -Description "Open the IHADRS dashboard." `
    @shortcutArgs

New-Shortcut `
    -Path (Join-Path $programsDir "Stop IHADRS EDR.lnk") `
    -Arguments "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$stopScript`"" `
    -Description "Stop the IHADRS EDR process started by the launcher." `
    @shortcutArgs

if (-not $NoDesktopShortcut) {
    $desktop = [Environment]::GetFolderPath("Desktop")
    New-Shortcut `
        -Path (Join-Path $desktop "IHADRS EDR.lnk") `
        -Arguments "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$startScript`"" `
        -Description "Start IHADRS EDR and open the dashboard." `
        @shortcutArgs
}

Write-Host ""
Write-Host "IHADRS is installed as a clickable Windows app." -ForegroundColor Green
Write-Host "Use the Desktop shortcut or Start Menu > IHADRS EDR > IHADRS EDR."
Write-Host "The first launch will ask for Administrator approval because EDR monitoring needs system access."
