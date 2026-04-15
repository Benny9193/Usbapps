@echo off
REM Trivia.bat - USB trivia gate.
REM
REM Opens a pink command-prompt window, asks a single trivia question,
REM and opens a secret Google Photos album when the correct answer is
REM given (or when the user gives up and types "no").
REM
REM How to use:
REM   - Double-click Trivia.bat from the USB drive after plugging it in.
REM   - Or, to have it fire automatically via AutoPlay, edit autorun.inf
REM     and replace the "open=" / "shellexecute=" targets with Trivia.bat.

cd /d "%~dp0"

title Trivia
color 0D

set "URL=https://photos.app.goo.gl/7x4LxoZjX67xCTqd6"

:ask
cls
echo.
echo ================================================================
echo.
echo   Who is the most loving and beautiful woman in the world?
echo.
echo ================================================================
echo.
set "ans="
set /p "ans=Your answer: "

if /i "%ans%"=="Coriee"        goto :correct
if /i "%ans%"=="Cord"          goto :correct
if /i "%ans%"=="Connor's wife" goto :correct

echo.
echo   ooo, not even close. woild you like to try again?
echo.
set "retry="
set /p "retry=(yes/no): "
if /i "%retry%"=="no" goto :giveup
goto :ask

:correct
cls
echo.
echo ================================================================
echo.
echo   That's right. Opening the album...
echo.
echo ================================================================
echo.
start "" "%URL%"
timeout /t 2 >nul
exit /b 0

:giveup
cls
echo.
echo ================================================================
echo.
echo   Here's a hint. Opening the album...
echo.
echo ================================================================
echo.
start "" "%URL%"
timeout /t 2 >nul
exit /b 0
