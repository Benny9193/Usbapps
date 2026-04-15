@echo off
REM Portable Recon Toolkit launcher (Windows)
REM Drops you straight into the dashboard by default, or forwards
REM command-line arguments to recon.py.

setlocal enabledelayedexpansion
cd /d "%~dp0"

REM Prefer a portable Python bundled under bin\python\, then system Python.
set "PY="
if exist "bin\python\python.exe" (
    set "PY=%~dp0bin\python\python.exe"
    goto :have_py
)
if exist "bin\python\pythonw.exe" (
    set "PY=%~dp0bin\python\python.exe"
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
echo     Either install Python 3.8+ and make sure "python" is on PATH,
echo     or drop a portable Python distribution into  bin\python\
echo.
pause
exit /b 1

:have_py
if "%~1"=="" (
    echo [+] Launching dashboard...
    %PY% "%~dp0recon.py" dashboard
) else (
    %PY% "%~dp0recon.py" %*
)
endlocal
