# agentSec Windows 安装包一键打包
# 用法: .\scripts\package-win.ps1 [-SkipEngine] [-SkipNpmInstall]
#
# 产物: app\release\AgentSec Setup *.exe (NSIS)
# 注意: PyInstaller 引擎须在 Windows 上构建；macOS 请用 scripts/package-dmg.sh

param(
    [switch]$SkipEngine,
    [switch]$SkipNpmInstall
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$App = Join-Path $Root "app"
$Engine = Join-Path $Root "engine"
$Venv = Join-Path $Engine ".venv"
$VenvPy = Join-Path $Venv "Scripts\python.exe"
$EngineBin = Join-Path $Engine "dist_pkg\agentsec-engine\agentsec-engine.exe"

if ($env:OS -notmatch "Windows") {
    Write-Error "Windows 安装包请在 Windows 上运行本脚本；macOS 请用 scripts/package-dmg.sh"
}

if (-not $env:ELECTRON_MIRROR) {
    $env:ELECTRON_MIRROR = "https://npmmirror.com/mirrors/electron/"
}
if (-not $env:ELECTRON_BUILDER_BINARIES_MIRROR) {
    $env:ELECTRON_BUILDER_BINARIES_MIRROR = "https://npmmirror.com/mirrors/electron-builder-binaries/"
}

Write-Host "==> agentSec Windows 打包"
Write-Host "    根目录: $Root"

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    throw "未找到 node"
}
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    throw "未找到 npm"
}

if (-not (Test-Path $VenvPy)) {
    Write-Host "==> 创建 Python 虚拟环境 ($Venv)"
    python -m venv $Venv
    if (-not (Test-Path $VenvPy)) {
        throw "venv 创建失败，请确认已安装 Python 3.10+ 且 python 在 PATH 中"
    }
}

Write-Host "==> 安装/更新引擎依赖"
& $VenvPy -m pip install -q -e $Engine
& $VenvPy -m pip install -q pyinstaller

if (-not $SkipNpmInstall) {
    Write-Host "==> npm install (app/)"
    Push-Location $App
    npm install
    Pop-Location
} else {
    Write-Host "==> 跳过 npm install"
}

$iconIco = Join-Path $App "build\icon.ico"
if (-not (Test-Path $iconIco)) {
    Write-Warning "未找到 app/build/icon.ico，将使用 electron-builder 默认图标"
}

Push-Location $App

if (-not $SkipEngine) {
    Write-Host "==> 冻结 Python 引擎 (PyInstaller)"
    npm run build:engine
} else {
    Write-Host "==> 跳过引擎冻结"
    if (-not (Test-Path $EngineBin)) {
        throw "引擎二进制不存在: $EngineBin`n请先完整打包或去掉 -SkipEngine"
    }
}

Write-Host "==> 构建前端 + Electron 主进程"
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
    Write-Host "✓ 打包完成"
    Write-Host "  安装包: $($setup.FullName)"
    Write-Host ("  大小: {0:N2} MB" -f ($setup.Length / 1MB))
} else {
    throw "未找到 exe 产物，请检查 $releaseDir"
}
