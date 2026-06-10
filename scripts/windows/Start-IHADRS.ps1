[CmdletBinding()]
param(
    [switch]$NoBrowser,
    [string]$DashboardUrl = "http://127.0.0.1:8765/"
)

$ErrorActionPreference = "Stop"

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Test-PortOpen {
    param(
        [string]$HostName,
        [int]$Port
    )

    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $result = $client.BeginConnect($HostName, $Port, $null, $null)
        if (-not $result.AsyncWaitHandle.WaitOne(500, $false)) {
            return $false
        }
        $client.EndConnect($result)
        return $true
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

function Write-LaunchLog {
    param([string]$Message)
    $line = "{0} {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Add-Content -Path $script:LauncherLog -Value $line
}

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$dataDir = Join-Path $repoRoot "data"
$logDir = Join-Path $repoRoot "logs"
New-Item -ItemType Directory -Force -Path $dataDir, $logDir | Out-Null

$script:LauncherLog = Join-Path $logDir "windows-launcher.log"
$stdoutLog = Join-Path $logDir "ihadrs-stdout.log"
$stderrLog = Join-Path $logDir "ihadrs-stderr.log"
$pidFile = Join-Path $dataDir "ihadrs.pid"
$python = Join-Path $repoRoot "venv\Scripts\python.exe"

Set-Location $repoRoot

if (Test-Path $pidFile) {
    $existingPid = (Get-Content $pidFile -ErrorAction SilentlyContinue | Select-Object -First 1)
    if ($existingPid -and (Get-Process -Id ([int]$existingPid) -ErrorAction SilentlyContinue)) {
        Write-LaunchLog "IHADRS is already running with PID $existingPid."
        if (-not $NoBrowser) {
            Start-Process $DashboardUrl
        }
        exit
    }
}

if (Test-PortOpen -HostName "127.0.0.1" -Port 8765) {
    Write-LaunchLog "IHADRS dashboard port is already open."
    if (-not $NoBrowser) {
        Start-Process $DashboardUrl
    }
    exit
}

if (-not (Test-Administrator)) {
    $powershell = Join-Path $PSHOME "powershell.exe"
    $arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`""
    if ($NoBrowser) {
        $arguments += " -NoBrowser"
    }
    if ($DashboardUrl) {
        $arguments += " -DashboardUrl `"$DashboardUrl`""
    }
    Start-Process -FilePath $powershell -ArgumentList $arguments -Verb RunAs
    exit
}

if (-not (Test-Path $python)) {
    throw "IHADRS virtual environment was not found. Run Install IHADRS.cmd first."
}

$env:PYTHONPATH = "src"
$process = Start-Process `
    -FilePath $python `
    -ArgumentList @("-m", "ihadrs", "start") `
    -WorkingDirectory $repoRoot `
    -WindowStyle Hidden `
    -RedirectStandardOutput $stdoutLog `
    -RedirectStandardError $stderrLog `
    -PassThru

Set-Content -Path $pidFile -Value $process.Id
Write-LaunchLog "Started IHADRS with PID $($process.Id)."

for ($attempt = 1; $attempt -le 40; $attempt++) {
    if (Test-PortOpen -HostName "127.0.0.1" -Port 8765) {
        Write-LaunchLog "Dashboard became available at $DashboardUrl."
        if (-not $NoBrowser) {
            Start-Process $DashboardUrl
        }
        exit
    }
    Start-Sleep -Milliseconds 500
}

Write-LaunchLog "IHADRS started, but the dashboard did not become reachable within 20 seconds."
if (-not $NoBrowser) {
    Start-Process $DashboardUrl
}
