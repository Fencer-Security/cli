<#
.SYNOPSIS
    Install the Fencer CLI on Windows from GitHub Releases.

.DESCRIPTION
    Downloads the signed release archive for this machine's architecture, verifies it
    against SHA256SUMS, and installs fencer.exe into a user directory.

    Usage:
        irm https://raw.githubusercontent.com/Fencer-Security/cli/main/scripts/install.ps1 | iex

    Optional environment variables:
        FENCER_CLI_VERSION      Version to install (default: latest)
        FENCER_CLI_REPO         GitHub owner/name that hosts releases (default: Fencer-Security/cli)
        FENCER_CLI_DIR          Install directory (default: %LOCALAPPDATA%\Programs\fencer)
        FENCER_CLI_SKIP_VERIFY  Set to 1 to skip checksum verification (not recommended)
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repo = if ($env:FENCER_CLI_REPO) { $env:FENCER_CLI_REPO } else { 'Fencer-Security/cli' }
$version = if ($env:FENCER_CLI_VERSION) { $env:FENCER_CLI_VERSION } else { 'latest' }
$skipVerify = $env:FENCER_CLI_SKIP_VERIFY -eq '1'

function Get-Arch {
    switch ($env:PROCESSOR_ARCHITECTURE) {
        'AMD64' { 'amd64' }
        'ARM64' { 'arm64' }
        default { throw "unsupported architecture: $($env:PROCESSOR_ARCHITECTURE)" }
    }
}

function Invoke-GitHub {
    param([string]$Url, [string]$OutFile)
    $headers = @{ 'Accept' = 'application/vnd.github+json' }
    $token = if ($env:GH_TOKEN) { $env:GH_TOKEN } elseif ($env:GITHUB_TOKEN) { $env:GITHUB_TOKEN } else { $null }
    if ($token) { $headers['Authorization'] = "Bearer $token" }
    if ($OutFile) {
        Invoke-WebRequest -Uri $Url -Headers $headers -OutFile $OutFile -UseBasicParsing
    }
    else {
        Invoke-WebRequest -Uri $Url -Headers $headers -UseBasicParsing
    }
}

$arch = Get-Arch

if ($version -eq 'latest') {
    $release = (Invoke-GitHub "https://api.github.com/repos/$repo/releases/latest").Content | ConvertFrom-Json
    $version = $release.tag_name
}
$version = $version -replace '^v', ''

$archive = "fencer_${version}_windows_${arch}.zip"
$base = "https://github.com/$repo/releases/download/v$version"
$tmp = New-Item -ItemType Directory -Path (Join-Path $env:TEMP ("fencer-" + [System.Guid]::NewGuid()))

try {
    $archivePath = Join-Path $tmp $archive
    $sumsPath = Join-Path $tmp 'SHA256SUMS'
    Invoke-GitHub "$base/$archive" $archivePath
    Invoke-GitHub "$base/SHA256SUMS" $sumsPath

    if (-not $skipVerify) {
        $expected = (Get-Content $sumsPath | Where-Object { $_ -match "\s\Q$archive\E$" } |
            ForEach-Object { ($_ -split '\s+')[0] } | Select-Object -First 1)
        if (-not $expected) { throw "no SHA256SUMS entry for $archive" }
        $actual = (Get-FileHash -Algorithm SHA256 -Path $archivePath).Hash.ToLower()
        if ($expected.ToLower() -ne $actual) {
            throw "checksum mismatch for ${archive}: expected $expected, got $actual"
        }
    }

    Expand-Archive -Path $archivePath -DestinationPath $tmp -Force
    $bin = Join-Path $tmp 'fencer.exe'
    if (-not (Test-Path $bin)) { throw 'archive did not contain fencer.exe' }

    $dest = if ($env:FENCER_CLI_DIR) { $env:FENCER_CLI_DIR } else { Join-Path $env:LOCALAPPDATA 'Programs\fencer' }
    New-Item -ItemType Directory -Force -Path $dest | Out-Null
    Copy-Item -Path $bin -Destination (Join-Path $dest 'fencer.exe') -Force

    Write-Host "Installed fencer $version to $dest\fencer.exe"
    & (Join-Path $dest 'fencer.exe') version

    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if ($userPath -notlike "*$dest*") {
        Write-Host "Add $dest to your PATH to use the fencer command."
    }
}
finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
