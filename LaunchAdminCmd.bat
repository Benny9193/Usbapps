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
REM We are now running as administrator. Before handing the operator
REM an interactive cmd.exe session, gate access behind a two-factor
REM challenge: name, then numeric code. If either is wrong we shout
REM STRANGER DANGER and pop a browser to an appropriately diagnostic
REM Google search, then bail out without ever exposing the shell.
REM ------------------------------------------------------------------
title Portable Recon Toolkit [Administrator]
color 0A
cls
echo.
echo ================================================================
echo   Portable Recon Toolkit - Access Control
echo ================================================================
echo.

set "who="
set /p "who=Identify yourself. What is your name? "
if /i not "%who%"=="Connor" goto :stranger

echo.
echo   Hello, Connor. Prove it.
echo.
set "code="
set /p "code=Enter your access code: "
if not "%code%"=="052393090322" goto :stranger

REM ------------------------------------------------------------------
REM Access granted. Hand over the interactive shell.
REM ------------------------------------------------------------------
cls
echo.
echo ================================================================
echo   Portable Recon Toolkit - Administrator Command Prompt
echo ================================================================
echo.
echo   Access granted. Welcome back, Connor.
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
exit /b 0

REM ------------------------------------------------------------------
REM Failed challenge. Make some noise, open the browser to the
REM diagnostic Google search, and exit without dropping to a shell.
REM %%3F is a literal %3F (URL-encoded '?') - batch eats single %'s.
REM ------------------------------------------------------------------
:stranger
color 0C
cls
echo.
echo ================================================================
echo.
echo                      S T R A N G E R
echo                        D A N G E R
echo.
echo ================================================================
echo.
echo   Nice try. That USB does not belong to you.
echo.
start "" "https://www.google.com/search?q=how+to+tell+if+i+have+retardation%%3F"
timeout /t 4 >nul
endlocal
exit /b 1
