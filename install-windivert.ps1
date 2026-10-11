param(
    [switch]$Force
)

$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$version = "2.2.2"
$assetName = "WinDivert-$version-A.zip"
$assetUrl = "https://github.com/basil00/WinDivert/releases/download/v$version/$assetName"
$expectedArchiveSize = 405137
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$targetRoot = Join-Path $projectRoot "target"
$assetRoot = Join-Path $targetRoot "windivert"
$archivePath = Join-Path $assetRoot $assetName
$dllPath = Join-Path $assetRoot "WinDivert.dll"
$driverPath = Join-Path $assetRoot "WinDivert64.sys"
$stageRoot = Join-Path $assetRoot "stage"

if (-not [Environment]::Is64BitOperatingSystem) {
    throw "The project and installer currently require 64-bit Windows."
}

New-Item -ItemType Directory -Path $assetRoot -Force | Out-Null

function Test-ValidDriverSignature {
    param([Parameter(Mandatory = $true)][string]$Path)

    $signature = Get-AuthenticodeSignature -FilePath $Path
    if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
        throw "WinDivert driver signature is not valid ($($signature.Status)): $Path"
    }
}

function Copy-ArchiveEntry {
    param(
        [Parameter(Mandatory = $true)]
        [System.IO.Compression.ZipArchiveEntry]$Entry,
        [Parameter(Mandatory = $true)]
        [string]$Destination
    )

    $inputStream = $Entry.Open()
    $outputStream = $null
    try {
        $outputStream = [System.IO.File]::Create($Destination)
        $inputStream.CopyTo($outputStream)
    }
    finally {
        if ($null -ne $outputStream) {
            $outputStream.Dispose()
        }
        $inputStream.Dispose()
    }
}

$haveAssets = (Test-Path -LiteralPath $dllPath) -and
    (Test-Path -LiteralPath $driverPath) -and
    ((Get-Item -LiteralPath $dllPath -ErrorAction SilentlyContinue).Length -gt 0)
if ($Force -or -not $haveAssets) {
    $downloadPath = "$archivePath.download"
    if (Test-Path -LiteralPath $stageRoot) {
        Remove-Item -LiteralPath $stageRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Path $stageRoot -Force | Out-Null

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $assetUrl -OutFile $downloadPath -UseBasicParsing
        $downloadSize = (Get-Item -LiteralPath $downloadPath).Length
        if ($downloadSize -ne $expectedArchiveSize) {
            throw "Unexpected WinDivert archive size: expected $expectedArchiveSize bytes, got $downloadSize."
        }

        $archive = [System.IO.Compression.ZipFile]::OpenRead($downloadPath)
        try {
            $dllEntry = $archive.Entries | Where-Object {
                $_.FullName -match "(^|/)x64/WinDivert\.dll$"
            } | Select-Object -First 1
            $driverEntry = $archive.Entries | Where-Object {
                $_.FullName -match "(^|/)x64/WinDivert64\.sys$"
            } | Select-Object -First 1

            if ($null -eq $dllEntry -or $null -eq $driverEntry) {
                throw "The release archive does not contain the expected x64 runtime files."
            }

            $stagedDll = Join-Path $stageRoot "WinDivert.dll"
            $stagedDriver = Join-Path $stageRoot "WinDivert64.sys"
            Copy-ArchiveEntry -Entry $dllEntry -Destination $stagedDll
            Copy-ArchiveEntry -Entry $driverEntry -Destination $stagedDriver
            Test-ValidDriverSignature -Path $stagedDriver

            Copy-Item -LiteralPath $downloadPath -Destination $archivePath -Force
            Copy-Item -LiteralPath $stagedDll -Destination $dllPath -Force
            Copy-Item -LiteralPath $stagedDriver -Destination $driverPath -Force
        }
        finally {
            if ($null -ne $archive) {
                $archive.Dispose()
            }
        }
    }
    finally {
        if (Test-Path -LiteralPath $downloadPath) {
            Remove-Item -LiteralPath $downloadPath -Force
        }
        if (Test-Path -LiteralPath $stageRoot) {
            Remove-Item -LiteralPath $stageRoot -Recurse -Force
        }
    }
}
else {
    Test-ValidDriverSignature -Path $driverPath
}

$runtimeDirectories = @(
    (Join-Path $targetRoot "debug"),
    (Join-Path $targetRoot "release")
)
foreach ($runtimeDirectory in $runtimeDirectories) {
    New-Item -ItemType Directory -Path $runtimeDirectory -Force | Out-Null
    Copy-Item -LiteralPath $dllPath -Destination $runtimeDirectory -Force
    Copy-Item -LiteralPath $driverPath -Destination $runtimeDirectory -Force
}

Write-Output "Installed WinDivert $version x64 runtime assets under target\debug and target\release."
Write-Output "Run the prototype from an elevated terminal with: cargo run -- --config dns-shunt.example.toml --run"
