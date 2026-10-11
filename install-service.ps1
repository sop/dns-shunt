param(
    [string]$InstallDirectory = (Join-Path $env:ProgramFiles "dns-shunt")
)

$ErrorActionPreference = "Stop"
$serviceName = "DnsShunt"
$eventSource = "Dns-Shunt"
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$releaseDirectory = Join-Path $projectRoot "target\release"
$programDataDirectory = Join-Path $env:ProgramData "dns-shunt"
$exampleConfig = Join-Path $projectRoot "dns-shunt.example.toml"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)) {
    throw "Run this installer from an elevated PowerShell session."
}

$windivertSetup = Join-Path $projectRoot "install-windivert.ps1"
& $windivertSetup

$releaseExecutable = Join-Path $releaseDirectory "dns-shunt.exe"
$releaseDll = Join-Path $releaseDirectory "WinDivert.dll"
$releaseDriver = Join-Path $releaseDirectory "WinDivert64.sys"
foreach ($file in @($releaseExecutable, $releaseDll, $releaseDriver)) {
    if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
        throw "Required release file is missing: $file. Run cargo build --release."
    }
}

New-Item -ItemType Directory -Path $InstallDirectory -Force | Out-Null
New-Item -ItemType Directory -Path $programDataDirectory -Force | Out-Null
Copy-Item -LiteralPath $releaseExecutable -Destination $InstallDirectory -Force
Copy-Item -LiteralPath $releaseDll -Destination $InstallDirectory -Force
Copy-Item -LiteralPath $releaseDriver -Destination $InstallDirectory -Force

$installedExecutable = Join-Path $InstallDirectory "dns-shunt.exe"
$configPath = Join-Path $programDataDirectory "config.toml"
if (-not (Test-Path -LiteralPath $configPath)) {
    Copy-Item -LiteralPath $exampleConfig -Destination $configPath
}

& icacls.exe $programDataDirectory /inheritance:r `
    /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)M" | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw "Could not set SYSTEM/Administrators permissions on ProgramData."
}

& $installedExecutable --config $configPath
if ($LASTEXITCODE -ne 0) {
    throw "Service config validation failed; see $configPath."
}

$eventSourceKey = Join-Path `
    "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application" `
    $eventSource
if (-not (Test-Path -LiteralPath $eventSourceKey)) {
    New-EventLog -LogName Application -Source $eventSource
}

$service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
$binaryPath = "`"$installedExecutable`" --service"
if ($null -eq $service) {
    New-Service -Name $serviceName -BinaryPathName $binaryPath `
        -StartupType Automatic -DisplayName "dns-shunt DNS override service" |
        Out-Null
}
else {
    if ($service.Status -ne "Stopped") {
        Stop-Service -Name $serviceName -Force
        $service.WaitForStatus("Stopped", [TimeSpan]::FromSeconds(30))
    }

    $serviceConfiguration = Get-CimInstance -ClassName Win32_Service `
        -Filter "Name='$serviceName'"
    $changeResult = Invoke-CimMethod -InputObject $serviceConfiguration `
        -MethodName Change -Arguments @{
            PathName = $binaryPath
            StartMode = "Auto"
            StartName = "LocalSystem"
    }
    if ($changeResult.ReturnValue -ne 0) {
        throw "Could not update the dns-shunt service " +
            "(Win32_Service.Change $($changeResult.ReturnValue))."
    }
}

Start-Service -Name $serviceName
(Get-Service -Name $serviceName).WaitForStatus(
    "Running",
    [TimeSpan]::FromSeconds(30)
)
Write-Output "dns-shunt is installed and running as LocalSystem."
Write-Output "Shared configuration and rules: $programDataDirectory"
Write-Output "Service events: Windows Event Viewer, Application log, $eventSource"
