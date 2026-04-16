@echo off
REM ============================================================================
REM  QR Code Maker - double-click launcher for make_qr.py
REM
REM  Prompts you for a URL (or any text), an optional output name, and an
REM  optional title, then runs make_qr.py to produce a PNG, an SVG, and a
REM  printable HTML card in this same folder.
REM ============================================================================

setlocal enabledelayedexpansion
cd /d "%~dp0"

REM --- Locate Python: portable bundled copy first, then system Python -------
set "PY="
if exist "..\bin\python\python.exe" (
    set "PY=%~dp0..\bin\python\python.exe"
    goto :have_py
)

where python >nul 2>nul
if not errorlevel 1 (
    set "PY=python"
    goto :have_py
)

where py >nul 2>nul
if not errorlevel 1 (
    set "PY=py -3"
    goto :have_py
)

echo.
echo [!] Python was not found.
echo     Install Python 3.8+ and make sure "python" is on PATH,
echo     or drop a portable Python distribution into  ..\bin\python\
echo.
pause
exit /b 1

:have_py

REM --- Make sure segno is installed ------------------------------------------
%PY% -c "import segno" >nul 2>nul
if errorlevel 1 (
    echo [+] Installing segno (one-time)...
    %PY% -m pip install --quiet segno
    if errorlevel 1 (
        echo [!] Failed to install segno. Check your internet connection.
        pause
        exit /b 1
    )
)

REM --- Prompt the user -------------------------------------------------------
echo.
echo ============================================
echo             Q R   C O D E   M A K E R
echo ============================================
echo.
echo Enter the URL or text you want the QR to open.
echo (Example: https://example.com)
echo.

set "PAYLOAD="
set /p "PAYLOAD=URL or text: "
if "!PAYLOAD!"=="" (
    echo.
    echo [!] Nothing entered. Nothing to do.
    pause
    exit /b 1
)

set "NAME="
set /p "NAME=Output filename (default: qr): "
if "!NAME!"=="" set "NAME=qr"

set "TITLE="
set /p "TITLE=Card title (default: Scan me): "
if "!TITLE!"=="" set "TITLE=Scan me"

echo.
echo [+] Generating QR code...
echo.

%PY% "%~dp0make_qr.py" "!PAYLOAD!" --name "!NAME!" --title "!TITLE!"
if errorlevel 1 (
    echo.
    echo [!] QR generation failed.
    pause
    exit /b 1
)

echo.
echo [+] Done. Look for these files in this folder:
echo       !NAME!.png
echo       !NAME!.svg
echo       !NAME!-card.html
echo.
pause
endlocal
