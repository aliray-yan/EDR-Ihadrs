[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$dataDir = Join-Path $repoRoot "data"
$logDir = Join-Path $repoRoot "logs"
$pidFile = Join-Path $dataDir "ihadrs.pid"
$launcherLog = Join-Path $logDir "windows-launcher.log"

New-Item -ItemType Directory -Force -Path $dataDir, $logDir | Out-Null

if (-not (Test-Administrator)) {
    $powershell = Join-Path $PSHOME "powershell.exe"
    Start-Process -FilePath $powershell `
        -ArgumentList "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`"" `
        -Verb RunAs
    exit
}

if (-not (Test-Path $pidFile)) {
    Add-Content -Path $launcherLog -Value "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") No IHADRS PID file was found."
    exit
}

$ihadrsPid = [int](Get-Content $pidFile | Select-Object -First 1)
$process = Get-Process -Id $ihadrsPid -ErrorAction SilentlyContinue
if ($process) {
    Stop-Process -Id $ihadrsPid -Force
    Add-Content -Path $launcherLog -Value "$(Get-Date -Format "yyyy-MM-dd HH:mm:ss") Stopped IHADRS PID $ihadrsPid."
}

Remove-Item -Path $pidFile -Force -ErrorAction SilentlyContinue
