param(
    [string]$InstallDirectory = (Join-Path $env:ProgramFiles "DNS Shunt")
)

$ErrorActionPreference = "Stop"
$serviceName = "DnsShunt"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) {
    throw "Run this uninstaller from an elevated PowerShell session."
}

$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($null -ne $service) {
    if ($service.Status -ne "Stopped") {
        Stop-Service -Name $serviceName -Force
        $service.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
    }
    & sc.exe delete $serviceName | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Could not delete the dns-shunt service (sc.exe $LASTEXITCODE)."
    }
}

$loadedDriver = Get-CimInstance Win32_SystemDriver `
    -Filter "Name = 'WinDivert'" -ErrorAction Stop
if ($null -ne $loadedDriver -and $loadedDriver.State -eq "Running") {
    $loadedDriverPath = [Environment]::ExpandEnvironmentVariables(
        $loadedDriver.PathName.Trim('"')
    )
    if ($loadedDriverPath.StartsWith(
        '\??\',
        [StringComparison]::OrdinalIgnoreCase
    )) {
        $loadedDriverPath = $loadedDriverPath.Substring(4)
    }
    $loadedDriverPath = [System.IO.Path]::GetFullPath($loadedDriverPath)
    $installedDriverPath = [System.IO.Path]::GetFullPath(
        (Join-Path $InstallDirectory "WinDivert64.sys")
    )

    if ($loadedDriverPath -eq $installedDriverPath) {
        Write-Output "Stopping the active WinDivert driver before removal."
        & sc.exe stop WinDivert | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw "Could not stop the active WinDivert driver."
        }

        $stopDeadline = [DateTime]::UtcNow.AddSeconds(30)
        do {
            Start-Sleep -Milliseconds 250
            $loadedDriver = Get-CimInstance Win32_SystemDriver `
                -Filter "Name = 'WinDivert'" -ErrorAction Stop
        } while (
            $null -ne $loadedDriver -and
            $loadedDriver.State -ne "Stopped" -and
            [DateTime]::UtcNow -lt $stopDeadline
        )
        if ($null -ne $loadedDriver -and
            $loadedDriver.State -ne "Stopped") {
            throw "Timed out waiting for the WinDivert driver to stop."
        }
    }
}

if (Test-Path -LiteralPath $InstallDirectory) {
    Remove-Item -LiteralPath $InstallDirectory -Recurse -Force
}

Write-Output "dns-shunt service and installed binaries were removed."
Write-Output "ProgramData configuration and rules were preserved."
