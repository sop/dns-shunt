$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $PSScriptRoot
$target = "x86_64-pc-windows-msvc"
$version = "2.2.2"
$archiveName = "WinDivert-$version-A.zip"
$archiveSize = 405137
$archiveSha256 = "63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15"
$assetUrl = "https://github.com/basil00/WinDivert/releases/download/v$version/$archiveName"
$distDirectory = Join-Path $projectRoot "dist"
$cacheDirectory = Join-Path $distDirectory "cache"
$stageDirectory = Join-Path $distDirectory "stage"
$archivePath = Join-Path $cacheDirectory $archiveName
$installerDefinition = Join-Path $projectRoot "installer\dns-shunt.iss"
$releaseExecutable = Join-Path $projectRoot "target\$target\release\dns-shunt.exe"

function Stop-WithError {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "build-installer: $Message"
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

if (-not [Environment]::Is64BitOperatingSystem) {
    Stop-WithError "run this workflow on a Windows x64 build host."
}

$rustc = Get-Command rustc.exe -ErrorAction SilentlyContinue
$cargo = Get-Command cargo.exe -ErrorAction SilentlyContinue
$rustup = Get-Command rustup.exe -ErrorAction SilentlyContinue
if ($null -eq $rustc -or $null -eq $cargo -or $null -eq $rustup) {
    Stop-WithError "Rust, Cargo, and rustup must be available on PATH."
}

$compilerInfo = & $rustc.Source -Vv
if ($LASTEXITCODE -ne 0) {
    Stop-WithError "could not inspect the active Rust toolchain."
}
$hostLine = $compilerInfo | Where-Object { $_ -like "host: *" }
if ($hostLine -ne "host: $target") {
    Stop-WithError "the active Rust host must be $target."
}
$installedTargets = & $rustup.Source target list --installed
if ($LASTEXITCODE -ne 0 -or $installedTargets -notcontains $target) {
    Stop-WithError "install the Rust target with: rustup target add $target"
}

$iscc = Get-Command ISCC.exe -ErrorAction SilentlyContinue
if ($null -ne $iscc) {
    $isccPath = $iscc.Source
}
else {
    $isccCandidates = @(
        (Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 7\ISCC.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Inno Setup 7\ISCC.exe"),
        (Join-Path $env:ProgramFiles "Inno Setup 7\ISCC.exe"),
        (Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"),
        (Join-Path $env:ProgramFiles "Inno Setup 6\ISCC.exe")
    )
    $isccPath = $isccCandidates |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } |
        Select-Object -First 1
}
if ([string]::IsNullOrWhiteSpace($isccPath)) {
    Stop-WithError "Inno Setup 6.3+ or 7 ISCC.exe must be installed or available on PATH."
}

New-Item -ItemType Directory -Path $cacheDirectory -Force | Out-Null
if (-not (Test-Path -LiteralPath $archivePath -PathType Leaf)) {
    $downloadPath = "$archivePath.download"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $assetUrl -OutFile $downloadPath -UseBasicParsing
        $downloaded = Get-Item -LiteralPath $downloadPath
        $downloadHash = (Get-FileHash -LiteralPath $downloadPath `
            -Algorithm SHA256).Hash
        if ($downloaded.Length -ne $archiveSize -or
            $downloadHash -ne $archiveSha256) {
            Stop-WithError "downloaded WinDivert archive failed size or SHA-256 validation."
        }
        Move-Item -LiteralPath $downloadPath -Destination $archivePath -Force
    }
    finally {
        if (Test-Path -LiteralPath $downloadPath) {
            Remove-Item -LiteralPath $downloadPath -Force
        }
    }
}

$archiveItem = Get-Item -LiteralPath $archivePath
if ($archiveItem.Length -ne $archiveSize) {
    Stop-WithError "unexpected WinDivert archive size: $($archiveItem.Length) bytes."
}
$archiveHash = (Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash
if ($archiveHash -ne $archiveSha256) {
    Stop-WithError "WinDivert archive SHA-256 mismatch: $archiveHash"
}

$installerPath = Join-Path $distDirectory "dns-shunt-setup.exe"
if (Test-Path -LiteralPath $installerPath) {
    Remove-Item -LiteralPath $installerPath -Force
}
if (Test-Path -LiteralPath $stageDirectory) {
    Remove-Item -LiteralPath $stageDirectory -Recurse -Force
}

Write-Output "Building $target release executable."
& $cargo.Source build --release --target $target `
    --manifest-path (Join-Path $projectRoot "Cargo.toml")
if ($LASTEXITCODE -ne 0) {
    Stop-WithError "cargo build failed with exit code $LASTEXITCODE."
}
if (-not (Test-Path -LiteralPath $releaseExecutable -PathType Leaf)) {
    Stop-WithError "release executable is missing: $releaseExecutable"
}

New-Item -ItemType Directory -Path $stageDirectory -Force | Out-Null
Copy-Item -LiteralPath $releaseExecutable -Destination $stageDirectory
Copy-Item -LiteralPath (Join-Path $projectRoot "dns-shunt.example.toml") `
    -Destination $stageDirectory

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [System.IO.Compression.ZipFile]::OpenRead($archivePath)
try {
    $dllEntry = $archive.Entries | Where-Object {
        $_.FullName -match "(^|/)x64/WinDivert\.dll$"
    } | Select-Object -First 1
    $driverEntry = $archive.Entries | Where-Object {
        $_.FullName -match "(^|/)x64/WinDivert64\.sys$"
    } | Select-Object -First 1
    if ($null -eq $dllEntry -or $null -eq $driverEntry) {
        Stop-WithError "archive does not contain the expected x64 WinDivert files."
    }

    $dllPath = Join-Path $stageDirectory "WinDivert.dll"
    $driverPath = Join-Path $stageDirectory "WinDivert64.sys"
    Copy-ArchiveEntry -Entry $dllEntry -Destination $dllPath
    Copy-ArchiveEntry -Entry $driverEntry -Destination $driverPath
}
finally {
    $archive.Dispose()
}

$signature = Get-AuthenticodeSignature -FilePath $driverPath
if ($signature.Status -ne [System.Management.Automation.SignatureStatus]::Valid) {
    Stop-WithError "WinDivert driver signature is not valid ($($signature.Status))."
}
foreach ($asset in @(
    "dns-shunt.exe",
    "dns-shunt.example.toml",
    "WinDivert.dll",
    "WinDivert64.sys"
)) {
    $stagedAsset = Join-Path $stageDirectory $asset
    if (-not (Test-Path -LiteralPath $stagedAsset -PathType Leaf) -or
        (Get-Item -LiteralPath $stagedAsset).Length -eq 0) {
        Stop-WithError "staged asset is missing or empty: $asset"
    }
}

Write-Output "Compiling the Inno Setup installer."
& $isccPath "/DSourceDir=$stageDirectory" $installerDefinition
if ($LASTEXITCODE -ne 0) {
    Stop-WithError "Inno Setup compilation failed with exit code $LASTEXITCODE."
}

if (-not (Test-Path -LiteralPath $installerPath -PathType Leaf)) {
    Stop-WithError "Inno Setup did not produce $installerPath"
}
Write-Output "Installer created: $installerPath"
