@echo off
REM Convenience wrapper: run_scan.bat <path to scan> [extra options]
setlocal
if "%~1"=="" (
    echo Usage: run_scan.bat ^<path to scan^> [options]
    echo   e.g. run_scan.bat C:\Projects\MyFirmware\src --min-severity High
    exit /b 2
)
python "%~dp0scan_c_code.py" %*
set RESULT=%ERRORLEVEL%
echo.
pause
exit /b %RESULT%
