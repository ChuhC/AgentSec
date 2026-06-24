# agentSec Windows installer packaging
# Usage: .\scripts\package-win.ps1 [-SkipEngine] [-SkipNpmInstall]
#
# Output: app\release\AgentSec Setup *.exe (NSIS)
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

if ($env:OS -notmatch "Windows") {
    throw "Run this script on Windows. On macOS use scripts/package-dmg.sh"
}

if (-not $env:ELECTRON_MIRROR) {
    $env:ELECTRON_MIRROR = "https://npmmirror.com/mirrors/electron/"
}
if (-not $env:ELECTRON_BUILDER_BINARIES_MIRROR) {
    $env:ELECTRON_BUILDER_BINARIES_MIRROR = "https://npmmirror.com/mirrors/electron-builder-binaries/"
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

if (-not $SkipNpmInstall) {
    Write-Host "==> npm install (app/)"
    Push-Location $App
    npm install
    Pop-Location
} else {
    Write-Host "==> Skipping npm install"
}

$iconIco = Join-Path $App "build\icon.ico"
if (-not (Test-Path $iconIco)) {
    Write-Warning "app/build/icon.ico not found; electron-builder will use the default icon"
}

Push-Location $App

if (-not $SkipEngine) {
    Write-Host "==> Freezing Python engine (PyInstaller)"
    npm run build:engine
} else {
    Write-Host "==> Skipping engine freeze"
    if (-not (Test-Path $EngineBin)) {
        throw "Engine binary missing: $EngineBin`nRun a full build first or omit -SkipEngine"
    }
}

Write-Host "==> Building frontend + Electron main process"
npm run build

Write-Host "==> electron-builder (win nsis)"
npm run dist:win

Pop-Location

$releaseDir = Join-Path $App "release"
$setup = Get-ChildItem -Path $releaseDir -Filter "*.exe" -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if ($setup) {
    Write-Host ""
    Write-Host "Done."
    Write-Host "  Installer: $($setup.FullName)"
    Write-Host ("  Size: {0:N2} MB" -f ($setup.Length / 1MB))
} else {
    throw "No .exe found under $releaseDir"
}
