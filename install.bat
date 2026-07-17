@echo off
title AntiGravity Shield v3.0 — Installer
echo.
echo  ============================================
echo   AntiGravity Shield v3.0 — Installation
echo  ============================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install Python 3.10+ from python.org
    echo         Make sure to check "Add Python to PATH" during install.
    pause
    exit /b 1
)

echo [1/3] Installing dependencies...
pip install watchdog psutil --quiet
if errorlevel 1 (
    echo [ERROR] Failed to install dependencies.
    pause
    exit /b 1
)

echo [2/3] Copying shield to home directory...
copy /y "%~dp0shield_v3.py" "%USERPROFILE%\shield_v3.py" >nul
copy /y "%~dp0stealth_attack.py" "%USERPROFILE%\stealth_attack.py" >nul

echo [3/3] Creating desktop launcher...
(
echo @echo off
echo title ANTIGRAVITY SHIELD v3.0 - AI POWERED
echo python "%USERPROFILE%\shield_v3.py"
echo pause
) > "%USERPROFILE%\Desktop\Start_Shield_v3.bat"

(
echo @echo off
echo title STEALTH ATTACK AGENT
echo python "%USERPROFILE%\stealth_attack.py"
echo pause
) > "%USERPROFILE%\Desktop\Run_Attack.bat"

echo.
echo  ============================================
echo   Installation Complete!
echo  ============================================
echo.
echo  Files installed:
echo    %USERPROFILE%\shield_v3.py
echo    %USERPROFILE%\stealth_attack.py
echo    %USERPROFILE%\Desktop\Start_Shield_v3.bat
echo    %USERPROFILE%\Desktop\Run_Attack.bat
echo.
echo  To start: Double-click "Start_Shield_v3.bat" on Desktop
echo  To auto-start on boot: python shield_v3.py --install
echo.
pause
