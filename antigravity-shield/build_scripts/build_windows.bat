@echo off
REM Build script for AntiGravity Shield (Windows)
REM Creates a standalone .exe that can run on any Windows system
REM without requiring Python or dependencies to be installed.

setlocal enabledelayedexpansion

echo ==========================================
echo Building AntiGravity Shield (Windows)
echo ==========================================

REM Get the script directory
set SCRIPT_DIR=%~dp0
set PROJECT_DIR=%SCRIPT_DIR%..

cd /d "%PROJECT_DIR%"

echo [1/5] Checking Python and pip...
python --version
pip --version

echo [2/5] Installing build dependencies...
pip install pyinstaller

echo [3/5] Installing agshield package...
pip install -e .

echo [4/5] Building executable...
pyinstaller build_scripts\agshield_windows.spec ^
    --clean ^
    --noconfirm ^
    --distpath dist ^
    --workpath build

echo [5/5] Verifying build...
if exist "dist\agshield.exe" (
    echo.
    echo ==========================================
    echo BUILD SUCCESSFUL
    echo ==========================================
    echo Executable: %PROJECT_DIR%\dist\agshield.exe
    echo.
    echo Test it:
    echo   dist\agshield.exe --version
    echo   dist\agshield.exe --help
    echo ==========================================
) else (
    echo.
    echo ==========================================
    echo BUILD FAILED
    echo ==========================================
    exit /b 1
)
