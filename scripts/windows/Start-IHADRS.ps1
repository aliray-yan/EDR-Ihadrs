[CmdletBinding()]
param(
    [switch]$NoBrowser,
    [string]$DashboardUrl = "http://127.0.0.1:8765/",
    [string]$StopWhenSignalFile
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

function Get-AppBrowserPath {
    $candidates = @(
        (Join-Path ${env:ProgramFiles(x86)} "Microsoft\Edge\Application\msedge.exe"),
        (Join-Path $env:ProgramFiles "Microsoft\Edge\Application\msedge.exe"),
        (Join-Path $env:LocalAppData "Microsoft\Edge\Application\msedge.exe"),
        (Join-Path $env:ProgramFiles "Google\Chrome\Application\chrome.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Google\Chrome\Application\chrome.exe"),
        (Join-Path $env:LocalAppData "Google\Chrome\Application\chrome.exe")
    )

    foreach ($candidate in $candidates) {
        if ($candidate -and (Test-Path $candidate)) {
            return $candidate
        }
    }

    foreach ($name in @("msedge.exe", "chrome.exe")) {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        if ($command) {
            return $command.Source
        }
    }

    return $null
}

function Get-DashboardBrowserProcesses {
    param([string]$ProfileDir)

    if (-not $ProfileDir) {
        return @()
    }

    return @(
        Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
            Where-Object {
                $_.ProcessId -and
                $_.CommandLine -and
                ($_.Name -in @("msedge.exe", "chrome.exe")) -and
                $_.CommandLine.Contains($ProfileDir)
            }
    )
}

function Start-DashboardAppWindow {
    param(
        [string]$Url,
        [string]$SessionId
    )

    $browser = Get-AppBrowserPath
    if (-not $browser) {
        Write-LaunchLog "No Edge/Chrome app-mode browser found. Falling back to the default browser."
        Start-Process $Url
        return [pscustomobject]@{
            Tracked = $false
            ProfileDir = $null
        }
    }

    $profileDir = Join-Path $script:DataDir "dashboard-browser-profile-$SessionId"
    New-Item -ItemType Directory -Force -Path $profileDir | Out-Null

    $browserArgs = @(
        "--app=`"$Url`"",
        "--user-data-dir=`"$profileDir`"",
        "--no-first-run",
        "--disable-background-mode"
    )

    Start-Process `
        -FilePath $browser `
        -ArgumentList $browserArgs `
        -WorkingDirectory $script:RepoRoot | Out-Null

    for ($attempt = 1; $attempt -le 20; $attempt++) {
        if ((Get-DashboardBrowserProcesses -ProfileDir $profileDir).Count -gt 0) {
            Write-LaunchLog "Opened tracked dashboard app window with profile $profileDir."
            return [pscustomobject]@{
                Tracked = $true
                ProfileDir = $profileDir
            }
        }
        Start-Sleep -Milliseconds 250
    }

    Write-LaunchLog "Dashboard app window opened, but its browser process could not be tracked."
    return [pscustomobject]@{
        Tracked = $false
        ProfileDir = $profileDir
    }
}

function Wait-DashboardAppWindowClosed {
    param([string]$ProfileDir)

    if (-not $ProfileDir) {
        return
    }

    Start-Sleep -Seconds 1
    while ((Get-DashboardBrowserProcesses -ProfileDir $ProfileDir).Count -gt 0) {
        Start-Sleep -Seconds 1
    }

    Write-LaunchLog "Dashboard app window closed."
    Remove-Item -LiteralPath $ProfileDir -Recurse -Force -ErrorAction SilentlyContinue
}

function Wait-DashboardReady {
    for ($attempt = 1; $attempt -le 240; $attempt++) {
        if (Test-PortOpen -HostName "127.0.0.1" -Port 8765) {
            return $true
        }
        Start-Sleep -Milliseconds 500
    }

    return $false
}

function Wait-StopSignal {
    param(
        [string]$SignalFile,
        [int]$IhadrsProcessId
    )

    if (-not $SignalFile) {
        return
    }

    Write-LaunchLog "Waiting for dashboard close signal: $SignalFile"
    while (-not (Test-Path $SignalFile)) {
        if ($IhadrsProcessId -and -not (Get-Process -Id $IhadrsProcessId -ErrorAction SilentlyContinue)) {
            Write-LaunchLog "IHADRS process $IhadrsProcessId exited before the dashboard close signal."
            return
        }
        Start-Sleep -Seconds 1
    }

    Remove-Item -LiteralPath $SignalFile -Force -ErrorAction SilentlyContinue
}

function Stop-IHADRSProcess {
    param([int]$IhadrsProcessId)

    if (-not $IhadrsProcessId) {
        return
    }

    $runningProcess = Get-Process -Id $IhadrsProcessId -ErrorAction SilentlyContinue
    if ($runningProcess) {
        Stop-Process -Id $IhadrsProcessId -Force
        Write-LaunchLog "Stopped IHADRS PID $IhadrsProcessId."
    }

    Remove-Item -LiteralPath $script:PidFile -Force -ErrorAction SilentlyContinue
}

function Open-DashboardAndStopOnClose {
    param([int]$IhadrsProcessId)

    if ($NoBrowser) {
        if ($StopWhenSignalFile) {
            Wait-StopSignal -SignalFile $StopWhenSignalFile -IhadrsProcessId $IhadrsProcessId
            Stop-IHADRSProcess -IhadrsProcessId $IhadrsProcessId
        }
        return
    }

    $sessionId = [guid]::NewGuid().ToString("N")
    $window = Start-DashboardAppWindow -Url $DashboardUrl -SessionId $sessionId
    if ($window.Tracked) {
        Wait-DashboardAppWindowClosed -ProfileDir $window.ProfileDir
        Stop-IHADRSProcess -IhadrsProcessId $IhadrsProcessId
    }
}

$script:RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$script:DataDir = Join-Path $script:RepoRoot "data"
$logDir = Join-Path $script:RepoRoot "logs"
New-Item -ItemType Directory -Force -Path $script:DataDir, $logDir | Out-Null

$script:LauncherLog = Join-Path $logDir "windows-launcher.log"
$stdoutLog = Join-Path $logDir "ihadrs-stdout.log"
$stderrLog = Join-Path $logDir "ihadrs-stderr.log"
$script:PidFile = Join-Path $script:DataDir "ihadrs.pid"
$python = Join-Path $script:RepoRoot "venv\Scripts\python.exe"

Set-Location $script:RepoRoot

if (-not (Test-Administrator)) {
    $powershell = Join-Path $PSHOME "powershell.exe"

    if ($NoBrowser) {
        $arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`" -NoBrowser"
        if ($DashboardUrl) {
            $arguments += " -DashboardUrl `"$DashboardUrl`""
        }
        Start-Process -FilePath $powershell -ArgumentList $arguments -Verb RunAs
        exit
    }

    $sessionId = [guid]::NewGuid().ToString("N")
    $signalFile = Join-Path $script:DataDir "dashboard-session-$sessionId.closed"
    Remove-Item -LiteralPath $signalFile -Force -ErrorAction SilentlyContinue

    $arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$PSCommandPath`" -NoBrowser -DashboardUrl `"$DashboardUrl`" -StopWhenSignalFile `"$signalFile`""
    Start-Process -FilePath $powershell -ArgumentList $arguments -Verb RunAs

    if (Wait-DashboardReady) {
        $window = Start-DashboardAppWindow -Url $DashboardUrl -SessionId $sessionId
        if ($window.Tracked) {
            Wait-DashboardAppWindowClosed -ProfileDir $window.ProfileDir
            Set-Content -Path $signalFile -Value "closed"
        }
    } else {
        Write-LaunchLog "IHADRS did not become reachable after elevation."
        Set-Content -Path $signalFile -Value "closed"
    }
    exit
}

if (Test-Path $script:PidFile) {
    $existingPid = (Get-Content $script:PidFile -ErrorAction SilentlyContinue | Select-Object -First 1)
    if ($existingPid -and (Get-Process -Id ([int]$existingPid) -ErrorAction SilentlyContinue)) {
        Write-LaunchLog "IHADRS is already running with PID $existingPid."
        Open-DashboardAndStopOnClose -IhadrsProcessId ([int]$existingPid)
        exit
    }
}

if (Test-PortOpen -HostName "127.0.0.1" -Port 8765) {
    Write-LaunchLog "IHADRS dashboard port is already open."
    if (-not $NoBrowser) {
        $sessionId = [guid]::NewGuid().ToString("N")
        $window = Start-DashboardAppWindow -Url $DashboardUrl -SessionId $sessionId
        if ($window.Tracked) {
            Wait-DashboardAppWindowClosed -ProfileDir $window.ProfileDir
        }
    }
    exit
}

if (-not (Test-Path $python)) {
    throw "IHADRS virtual environment was not found. Run Install IHADRS.cmd first."
}

$env:PYTHONPATH = "src"
$process = Start-Process `
    -FilePath $python `
    -ArgumentList @("-m", "ihadrs", "start") `
    -WorkingDirectory $script:RepoRoot `
    -WindowStyle Hidden `
    -RedirectStandardOutput $stdoutLog `
    -RedirectStandardError $stderrLog `
    -PassThru

Set-Content -Path $script:PidFile -Value $process.Id
Write-LaunchLog "Started IHADRS with PID $($process.Id)."

if (Wait-DashboardReady) {
    Write-LaunchLog "Dashboard became available at $DashboardUrl."
    Open-DashboardAndStopOnClose -IhadrsProcessId $process.Id
    exit
}

Write-LaunchLog "IHADRS started, but the dashboard did not become reachable within 120 seconds."
Open-DashboardAndStopOnClose -IhadrsProcessId $process.Id
