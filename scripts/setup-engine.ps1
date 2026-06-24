# Configure engine/.venv (Python scan engine dependencies)
# Usage: .\scripts\setup-engine.ps1 [-WithPyInstaller]
param(
    [switch]$WithPyInstaller
)

$ErrorActionPreference = "Stop"

$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$Engine = Join-Path $Root "engine"
$Venv = Join-Path $Engine ".venv"
$VenvPy = Join-Path $Venv "Scripts\python.exe"

function Test-Python310Plus {
    param([string]$Exe)
    if (-not (Test-Path $Exe)) { return $false }
    & $Exe -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)" 2>$null
    return $LASTEXITCODE -eq 0
}

function Find-Python {
    $candidates = @(
        "py -3.12",
        "py -3.11",
        "py -3.10",
        "python3.12",
        "python3.11",
        "python3.10",
        "python3",
        "python"
    )
    foreach ($cmd in $candidates) {
        $parts = $cmd -split " ", 2
        $exe = Get-Command $parts[0] -ErrorAction SilentlyContinue
        if (-not $exe) { continue }
        if ($parts.Count -eq 2) {
            $py = & $parts[0] $parts[1] -c "import sys; print(sys.executable)" 2>$null
        } else {
            $py = & $parts[0] -c "import sys; print(sys.executable)" 2>$null
        }
        if ($py -and (Test-Python310Plus $py.Trim())) {
            return $py.Trim()
        }
    }
    return $null
}

if ((Test-Path $VenvPy) -and (Test-Python310Plus $VenvPy)) {
    $ver = & $VenvPy --version 2>&1
    Write-Host "==> Using existing venv ($Venv, $ver)"
} else {
    if (Test-Path $Venv) {
        Write-Host "==> Removing incompatible venv at $Venv"
        Remove-Item -Recurse -Force $Venv
    }
    $Py = Find-Python
    if (-not $Py) {
        throw "Python 3.10+ required. Install from https://www.python.org/ or use: py -3.11 -m venv ..."
    }
    $ver = & $Py --version 2>&1
    Write-Host "==> Creating venv ($Venv) with $Py ($ver)"
    & $Py -m venv $Venv
    if (-not (Test-Path $VenvPy)) {
        throw "Failed to create venv at $Venv. Ensure Python 3.10+ is on PATH."
    }
}

Write-Host "==> Installing/updating engine dependencies"
& $VenvPy -m pip install -q -U pip
& $VenvPy -m pip install -q -e $Engine

if ($WithPyInstaller) {
    & $VenvPy -m pip install -q pyinstaller
}

Write-Host "==> Engine ready: $VenvPy"
