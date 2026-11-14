@echo off
setlocal

set "TARGET_DIR=%~dp0"
cd /d "%TARGET_DIR%"

echo =====================================================================
echo  Starting OSINT Recon Studio...
echo =====================================================================

:: Option 1: Run compiled standalone executable
if exist "dist\OSINTReconStudio\OSINTReconStudio.exe" (
    echo [*] Launching standalone application: dist\OSINTReconStudio\OSINTReconStudio.exe
    pushd "%TARGET_DIR%dist\OSINTReconStudio"
    start "" "OSINTReconStudio.exe" %*
    popd
    exit /b 0
)

:: Option 2: Run via virtual environment pythonw [silent GUI]
if exist ".venv\Scripts\pythonw.exe" (
    echo [*] Launching via Python virtual environment: pythonw
    set "PYTHONPATH=%TARGET_DIR%src;%PYTHONPATH%"
    start "" ".venv\Scripts\pythonw.exe" "%TARGET_DIR%run_app.py" %*
    exit /b 0
)

:: Option 3: Run via virtual environment python [console fallback]
if exist ".venv\Scripts\python.exe" (
    echo [*] Launching via Python virtual environment: python
    set "PYTHONPATH=%TARGET_DIR%src;%PYTHONPATH%"
    start "" ".venv\Scripts\python.exe" "%TARGET_DIR%run_app.py" %*
    exit /b 0
)

:: Option 4: Run via system Python
python -c "import sys; sys.exit(0)" >nul 2>&1
if not errorlevel 1 (
    echo [*] Launching via system Python
    set "PYTHONPATH=%TARGET_DIR%src;%PYTHONPATH%"
    start "" python "%TARGET_DIR%run_app.py" %*
    exit /b 0
)

echo ERROR: Could not find compiled executable or working Python 3.12+ environment.
echo Please run build_windows.bat to initialize and compile the application.
echo.
pause
exit /b 1
