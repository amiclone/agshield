@echo off
REM Installation script for AntiGravity Shield (Windows)
REM Installs the standalone .exe and agent package to standard locations.

setlocal enabledelayedexpansion

set INSTALL_DIR=C:\Program Files\antigravity-shield
set AGENT_DIR=%INSTALL_DIR%\agent_package

echo ==========================================
echo Installing AntiGravity Shield
echo ==========================================

REM Create installation directory
echo [1/4] Creating directories...
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"
if not exist "%AGENT_DIR%" mkdir "%AGENT_DIR%"
if not exist "C:\ProgramData\antigravity" mkdir "C:\ProgramData\antigravity"

REM Copy agent package
echo [2/4] Installing agent package...
xcopy /Y /E "%~dp0..\..\agent_package\*" "%AGENT_DIR%\"

REM Copy executable
echo [3/4] Installing executable...
copy /Y "%~dp0..\dist\agshield.exe" "%INSTALL_DIR%\agshield.exe"

REM Add to PATH for current user
echo [4/4] Adding to PATH...
setx PATH "%PATH%;%INSTALL_DIR%" /M

echo.
echo ==========================================
echo INSTALLATION SUCCESSFUL
echo ==========================================
echo Executable: %INSTALL_DIR%\agshield.exe
echo Agent package: %AGENT_DIR%
echo.
echo Usage:
echo   agshield.exe start --watch C:\Users
echo   agshield.exe status
echo   agshield.exe stop
echo ==========================================
echo.
echo NOTE: Restart your terminal to use the new PATH entry.
