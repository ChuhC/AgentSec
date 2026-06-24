# agentSec Windows installer packaging
# Usage: .\scripts\package-win.ps1 [-SkipEngine] [-SkipNpmInstall]
#
# Output: app\release\AgentSec-*-setup.exe (NSIS)
# Note: PyInstaller engine must be built on Windows; use scripts/package-dmg.sh on macOS.

param(
    [switch]$SkipEngine,
    [switch]$SkipNpmInstall
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$App = Join-Path $Root "app"
$Engine = Join-Path $Root "engine"
$EngineBin = Join-Path $Engine "dist_pkg\agentsec-engine\agentsec-engine.exe"
$SetupScript = Join-Path $Root "scripts\setup-engine.ps1"

function Invoke-NpmStep {
    param(
        [string]$Label,
        [string[]]$Args
    )
    Write-Host "==> $Label"
    & npm @Args
    if ($LASTEXITCODE -ne 0) {
        throw "$Label failed with exit code $LASTEXITCODE"
    }
}

if ($env:OS -notmatch "Windows") {
    throw "Run this script on Windows. On macOS use scripts/package-dmg.sh"
}

if (-not $env:GITHUB_ACTIONS) {
    if (-not $env:ELECTRON_MIRROR) {
        $env:ELECTRON_MIRROR = "https://npmmirror.com/mirrors/electron/"
    }
    if (-not $env:ELECTRON_BUILDER_BINARIES_MIRROR) {
        $env:ELECTRON_BUILDER_BINARIES_MIRROR = "https://npmmirror.com/mirrors/electron-builder-binaries/"
    }
}

Write-Host "==> agentSec Windows packaging"
Write-Host "    Root: $Root"

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    throw "node not found on PATH"
}
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    throw "npm not found on PATH"
}

& $SetupScript -WithPyInstaller

Push-Location $App
try {
    if (-not $SkipNpmInstall) {
        if ($env:GITHUB_ACTIONS) {
            Invoke-NpmStep "npm ci (app/)" @("ci")
        } else {
            Invoke-NpmStep "npm install (app/)" @("install")
        }
    } else {
        Write-Host "==> Skipping npm install"
    }

    $iconIco = Join-Path $App "build\icon.ico"
    if (-not (Test-Path $iconIco)) {
        Write-Warning "app/build/icon.ico not found; electron-builder will use icon.png"
    }

    if (-not $SkipEngine) {
        Invoke-NpmStep "Freezing Python engine (PyInstaller)" @("run", "build:engine")
    } else {
        Write-Host "==> Skipping engine freeze"
        if (-not (Test-Path $EngineBin)) {
            throw "Engine binary missing: $EngineBin`nRun a full build first or omit -SkipEngine"
        }
    }

    Invoke-NpmStep "Building frontend + Electron main process" @("run", "build")

    if (-not (Test-Path (Join-Path $App "dist-electron\main.js"))) {
        throw "Missing app/dist-electron/main.js after build; cannot package Electron app"
    }

    Invoke-NpmStep "electron-builder (win nsis)" @("run", "dist:win")
} finally {
    Pop-Location
}

$releaseDir = Join-Path $App "release"
$setup = Get-ChildItem -Path $releaseDir -Filter "*.exe" -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -notmatch '^agentsec-engine(\.exe)?$' -and $_.DirectoryName -eq $releaseDir } |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if ($setup) {
    Write-Host ""
    Write-Host "Done."
    Write-Host "  Installer: $($setup.FullName)"
    Write-Host ("  Size: {0:N2} MB" -f ($setup.Length / 1MB))
} else {
    Write-Host "Release directory contents:" -ForegroundColor Yellow
    Get-ChildItem -Path $releaseDir -Recurse -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_.FullName }
    throw "No NSIS installer .exe found under $releaseDir"
}
