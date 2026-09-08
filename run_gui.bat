@echo off
REM Start the scanner window (no console).
start "" pythonw "%~dp0cstdscan_gui.py"
if errorlevel 1 start "" python "%~dp0cstdscan_gui.py"
