@echo off
setlocal

echo =====================================================================
echo  OSINT Recon Studio - Native Windows Executable Builder (.exe)
echo =====================================================================
echo.

set "TARGET_DIR=%~dp0"
cd /d "%TARGET_DIR%"

:: 1. Search for a functional Python interpreter
set "PYTHON_EXE="

:: Check existing virtual environment first
if exist ".venv\Scripts\python.exe" (
    ".venv\Scripts\python.exe" -c "import sys; sys.exit(0)" >nul 2>&1
    if not errorlevel 1 (
        set "PYTHON_EXE=%TARGET_DIR%.venv\Scripts\python.exe"
        goto :python_found
    )
)

:: Check .local/bin (uv / local installations)
if exist "%USERPROFILE%\.local\bin\python3.15.exe" (
    "%USERPROFILE%\.local\bin\python3.15.exe" -c "import sys; sys.exit(0)" >nul 2>&1
    if not errorlevel 1 (
        set "PYTHON_EXE=%USERPROFILE%\.local\bin\python3.15.exe"
        goto :python_found
    )
)
if exist "%USERPROFILE%\.local\bin\python.exe" (
    "%USERPROFILE%\.local\bin\python.exe" -c "import sys; sys.exit(0)" >nul 2>&1
    if not errorlevel 1 (
        set "PYTHON_EXE=%USERPROFILE%\.local\bin\python.exe"
        goto :python_found
    )
)

:: Check standard Windows installed Python locations
for %%D in (
    "%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
    "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
    "%ProgramFiles%\Python313\python.exe"
    "%ProgramFiles%\Python312\python.exe"
) do (
    if exist %%D (
        %%D -c "import sys; sys.exit(0)" >nul 2>&1
        if not errorlevel 1 (
            set "PYTHON_EXE=%%~D"
            goto :python_found
        )
    )
)

:: Check py launcher
py -3 -c "import sys; sys.exit(0)" >nul 2>&1
if not errorlevel 1 (
    set "PYTHON_EXE=py -3"
    goto :python_found
)

:: Check python in PATH (verifying it is not a broken WindowsApps stub)
python -c "import sys; sys.exit(0)" >nul 2>&1
if not errorlevel 1 (
    set "PYTHON_EXE=python"
    goto :python_found
)

echo ERROR: No working Python 3.12+ installation detected.
echo Please install Python 3.12 or newer from https://www.python.org/downloads/
echo and ensure Python is added to your system PATH.
pause
exit /b 1

:python_found
echo [*] Found functional Python: %PYTHON_EXE%
"%PYTHON_EXE%" --version
echo.

:: 2. Ensure virtual environment exists
if not exist ".venv\Scripts\python.exe" (
    echo [*] Initializing virtual environment in .venv...
    if exist "%USERPROFILE%\.local\bin\uv.exe" (
        "%USERPROFILE%\.local\bin\uv.exe" venv .venv --python "%PYTHON_EXE%"
    ) else (
        "%PYTHON_EXE%" -m venv .venv
    )
    if errorlevel 1 (
        echo ERROR: Failed to create virtual environment.
        pause
        exit /b 1
    )
)

:: 3. Ensure pip is available
".venv\Scripts\python.exe" -m pip --version >nul 2>&1
if errorlevel 1 (
    echo [*] Bootstrapping pip in virtual environment...
    ".venv\Scripts\python.exe" -m ensurepip --default-pip >nul 2>&1
)

:: 4. Install/Update requirements using virtual environment
echo [*] Verifying and installing required packages...
if exist "%USERPROFILE%\.local\bin\uv.exe" (
    "%USERPROFILE%\.local\bin\uv.exe" pip install -r requirements.txt --python ".venv\Scripts\python.exe"
) else (
    ".venv\Scripts\python.exe" -m pip install -r requirements.txt
)
if errorlevel 1 (
    echo ERROR: Failed to install required packages.
    pause
    exit /b 1
)

:: 5. Terminate any active instance and clean prior builds
echo [*] Cleaning old build artifacts...
taskkill /F /IM OSINTReconStudio.exe >nul 2>&1
ping -n 2 127.0.0.1 >nul 2>&1
if exist "build" rmdir /s /q "build"
if exist "dist" rmdir /s /q "dist"

:: 6. Compile with PyInstaller
echo.
echo [*] Compiling standalone Windows application via PyInstaller...
".venv\Scripts\pyinstaller.exe" --noconsole ^
                               --windowed ^
                               --name "OSINTReconStudio" ^
                               --icon "assets\app_icon.ico" ^
                               --clean ^
                               --noconfirm ^
                               --paths "src" ^
                               --add-data "assets;assets" ^
                               --collect-all "PySide6" ^
                               --collect-all "osint_studio" ^
                               --collect-all "phonenumbers" ^
                               --collect-all "pypdf" ^
                               --collect-all "PIL" ^
                               --collect-data "certifi" ^
                               --collect-submodules "dnspython" ^
                               --collect-submodules "idna" ^
                               --hidden-import "certifi" ^
                               --hidden-import "idna" ^
                               --hidden-import "dns" ^
                               --hidden-import "dns.dnssec" ^
                               --hidden-import "dns.asyncresolver" ^
                               --hidden-import "dns.rdtypes.IN" ^
                               --hidden-import "dns.rdtypes.ANY" ^
                               --hidden-import "httpx" ^
                               --hidden-import "PIL.ExifTags" ^
                               run_app.py

if errorlevel 1 (
    echo ERROR: PyInstaller compilation failed.
    pause
    exit /b 1
)

:: Copy helper shortcut script to dist folder for easy user access
if exist "Create_Desktop_Shortcut.bat" (
    copy /y "Create_Desktop_Shortcut.bat" "dist\OSINTReconStudio\" >nul 2>&1
)

:: 7. Automated Self-Test Verification
echo.
echo [*] Running automated self-test on compiled executable...
if exist "dist\OSINTReconStudio\OSINTReconStudio.exe" (
    "dist\OSINTReconStudio\OSINTReconStudio.exe" --self-test
    if errorlevel 1 (
        echo WARNING: Self-test returned an exit code error. Check crash_log.txt.
    ) else (
        echo [SELF-TEST] PASS: Compiled executable initialized successfully!
    )
)

:: 8. Final Report
echo.
if exist "dist\OSINTReconStudio\OSINTReconStudio.exe" (
    echo =====================================================================
    echo  SUCCESS: Standalone executable created successfully!
    echo  Executable location: dist\OSINTReconStudio\OSINTReconStudio.exe
    echo  Shortcut Creator:   dist\OSINTReconStudio\Create_Desktop_Shortcut.bat
    echo =====================================================================
) else (
    echo Build completed. Check the 'dist' directory.
)

echo.
pause
