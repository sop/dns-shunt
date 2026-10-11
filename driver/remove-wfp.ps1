param(
    [switch]$RemovePackage
)

$ErrorActionPreference = "Stop"

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell prompt."
}

$service = Get-Service -Name "DnsShuntWfp" -ErrorAction SilentlyContinue
if ($null -ne $service -and $service.Status -ne "Stopped") {
    & sc.exe stop DnsShuntWfp
    if ($LASTEXITCODE -ne 0) {
        throw "Could not stop DnsShuntWfp (exit $LASTEXITCODE)."
    }
    $service = Get-Service -Name "DnsShuntWfp"
    $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
}

if ($null -ne $service) {
    & sc.exe delete DnsShuntWfp
    if ($LASTEXITCODE -ne 0) {
        throw "Could not remove DnsShuntWfp service registration (exit $LASTEXITCODE)."
    }
    $systemDriver = Join-Path $env:SystemRoot "System32\drivers\DnsShuntWfp.sys"
    if (Test-Path -LiteralPath $systemDriver) {
        Remove-Item -LiteralPath $systemDriver -Force
    }
}

if ($RemovePackage) {
    $package = Get-WindowsDriver -Online -All | Where-Object { $_.OriginalFileName -like "*DnsShuntWfp.inf" }
    if ($null -ne $package) {
        & pnputil.exe /delete-driver $package.Driver -uninstall
        if ($LASTEXITCODE -ne 0) {
            throw "Could not remove driver package $($package.Driver) (exit $LASTEXITCODE)."
        }
    }
}

Write-Output "Stopped and removed the dns-shunt WFP service. Use -RemovePackage to remove its driver package."
