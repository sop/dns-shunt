param(
    [string]$PackageDirectory = (Join-Path $PSScriptRoot "x64\Debug")
)

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell prompt."
}

$inf = Join-Path $PackageDirectory "DnsShuntWfp.inf"
$sys = Join-Path $PackageDirectory "DnsShuntWfp.sys"
$cat = Join-Path $PackageDirectory "DnsShuntWfp.cat"
foreach ($path in @($inf, $sys, $cat)) {
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Missing WDK package file: $path. Build driver\DnsShuntWfp.vcxproj for x64 first."
    }
}

& pnputil.exe /add-driver $inf /install
if ($LASTEXITCODE -ne 0) {
    throw "pnputil failed to install the WFP driver package (exit $LASTEXITCODE)."
}

$systemDriver = Join-Path $env:SystemRoot "System32\drivers\DnsShuntWfp.sys"
Copy-Item -LiteralPath $sys -Destination $systemDriver -Force

$service = Get-Service -Name "DnsShuntWfp" -ErrorAction SilentlyContinue
if ($null -eq $service) {
    & sc.exe create DnsShuntWfp type= kernel start= demand error= normal binPath= "\SystemRoot\System32\drivers\DnsShuntWfp.sys"
    if ($LASTEXITCODE -ne 0) {
        throw "Could not register the DnsShuntWfp kernel service (exit $LASTEXITCODE)."
    }
    $service = Get-Service -Name "DnsShuntWfp"
}
if ($service.Status -ne "Running") {
    & sc.exe start DnsShuntWfp
    if ($LASTEXITCODE -ne 0) {
        throw "Could not start DnsShuntWfp (exit $LASTEXITCODE)."
    }
    $service = Get-Service -Name "DnsShuntWfp"
    $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
}

Write-Output "Installed and started the dns-shunt WFP callout. Use only on a disposable test machine with required test-signing configuration; boot-security settings were not changed."
