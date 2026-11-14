@echo off
setlocal

set "TARGET_DIR=%~dp0"
cd /d "%TARGET_DIR%"

:: If standalone EXE exists in dist, run it directly
if exist "dist\OSINTReconStudio\OSINTReconStudio.exe" (
    start "" "dist\OSINTReconStudio\OSINTReconStudio.exe" %*
    exit /b 0
)

:: Otherwise run via virtual environment
if exist ".venv\Scripts\python.exe" (
    set "PYTHONPATH=%TARGET_DIR%src"
    start "" ".venv\Scripts\pythonw.exe" run_app.py %*
    exit /b 0
)

:: Fallback to build script to set up environment first
echo Virtual environment not found. Running build/setup script first...
call build_windows.bat
if exist "dist\OSINTReconStudio\OSINTReconStudio.exe" (
    start "" "dist\OSINTReconStudio\OSINTReconStudio.exe" %*
)
