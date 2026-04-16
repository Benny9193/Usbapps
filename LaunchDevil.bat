@echo off
REM Portable Recon Toolkit - "devil" prank launcher.
REM
REM When invoked (either directly, or via autorun.inf when Windows
REM AutoPlay mounts the drive), this script opens an interactive
REM command prompt, prints a short taunting sequence with 2-second
REM pauses between lines, and then opens the target URL in the
REM default browser.
REM
REM No elevation, no access control - this variant is pure theatre.

setlocal enabledelayedexpansion
cd /d "%~dp0"

title Portable Recon Toolkit
color 0C
cls
echo.
echo ================================================================
echo.
echo   Do you know who the devil is?
echo.
echo ================================================================
echo.

timeout /t 2 /nobreak >nul

echo.
echo   Well, I'll show you.
echo.

timeout /t 2 /nobreak >nul

start "" "https://www.facebook.com/share/1FHYsoqFdH/"

endlocal
exit /b 0
