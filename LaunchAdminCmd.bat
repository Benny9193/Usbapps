@echo off
REM Portable Recon Toolkit - elevated command prompt launcher.
REM
REM When invoked (either directly, or via autorun.inf when Windows
REM AutoPlay mounts the drive), this script self-elevates through UAC
REM and drops into an interactive Administrator command prompt rooted
REM at the USB drive, with the toolkit directories prepended to PATH
REM so "Launch.bat", "recon.py", and any bundled portable binaries can
REM be invoked by name.

setlocal enabledelayedexpansion
cd /d "%~dp0"

REM ------------------------------------------------------------------
REM Detect whether we are already running elevated. "net session" only
REM succeeds when the current token has administrator privileges, so
REM it is a reliable portable check that works from XP onward.
REM ------------------------------------------------------------------
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo [+] Portable Recon Toolkit
    echo [+] Requesting administrator privileges via UAC...
    echo.
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" 1>nul 2>nul
    if errorlevel 1 (
        echo [!] Failed to request elevation. Right-click this file and
        echo     choose "Run as administrator" to launch the admin prompt.
        pause
        exit /b 1
    )
    exit /b 0
)

REM ------------------------------------------------------------------
REM We are now running as administrator. Present a short banner and
REM hand the user an interactive cmd.exe session with the toolkit on
REM PATH. "cmd /k" keeps the window open after the initial commands.
REM ------------------------------------------------------------------
title Portable Recon Toolkit [Administrator]
color 0A
cls
echo.
echo ================================================================
echo   Portable Recon Toolkit - Administrator Command Prompt
echo ================================================================
echo.
echo   Toolkit directory : %~dp0
echo   Running as        : %USERDOMAIN%\%USERNAME%  (elevated)
echo.
echo   Available commands:
echo     Launch.bat              - start the dashboard at 127.0.0.1:8787
echo     Launch.bat scan TARGET  - run a port scan
echo     Launch.bat full TARGET  - full DNS / WHOIS / subdomain / nmap
echo     Launch.bat --help       - full CLI reference
echo.
echo   Type "exit" to close this window.
echo ================================================================
echo.

cmd /k "cd /d ""%~dp0"" && set ""PATH=%~dp0;%~dp0bin;%~dp0bin\python;%PATH%"""
endlocal
