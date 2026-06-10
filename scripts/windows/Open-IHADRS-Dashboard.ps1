[CmdletBinding()]
param(
    [string]$DashboardUrl = "http://127.0.0.1:8765/"
)

$ErrorActionPreference = "Stop"

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

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$startScript = Join-Path $repoRoot "scripts\windows\Start-IHADRS.ps1"

if (-not (Test-PortOpen -HostName "127.0.0.1" -Port 8765)) {
    & $startScript
    exit
}

Start-Process $DashboardUrl
