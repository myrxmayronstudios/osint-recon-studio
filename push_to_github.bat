@echo off
setlocal enabledelayedexpansion

echo =====================================================================
echo  OSINT Recon Studio - GitHub Repository & Push Assistant
echo =====================================================================
echo.

set "TARGET_DIR=%~dp0"
cd /d "%TARGET_DIR%"

:: 1. Locate Git executable
set "GIT_EXE="
where git >nul 2>&1
if not errorlevel 1 (
    set "GIT_EXE=git"
    goto :git_found
)

:: Search GitHub Desktop bundled Git
for /d %%D in ("%LOCALAPPDATA%\GitHubDesktop\app-*") do (
    if exist "%%~D\resources\app\git\cmd\git.exe" (
        set "GIT_EXE=%%~D\resources\app\git\cmd\git.exe"
        goto :git_found
    )
)

:: Search standard program files
if exist "%ProgramFiles%\Git\cmd\git.exe" (
    set "GIT_EXE=%ProgramFiles%\Git\cmd\git.exe"
    goto :git_found
)
if exist "%LOCALAPPDATA%\Programs\Git\cmd\git.exe" (
    set "GIT_EXE=%LOCALAPPDATA%\Programs\Git\cmd\git.exe"
    goto :git_found
)

echo ERROR: Git is not installed or not in PATH.
echo Please install Git for Windows from: https://git-scm.com/
pause
exit /b 1

:git_found
echo [*] Using Git: %GIT_EXE%
"%GIT_EXE%" --version
echo.

:: 2. Initialize repository if .git doesn't exist
if not exist ".git" (
    echo [*] Initializing Git repository with default branch 'main'...
    "%GIT_EXE%" init -b main
    if errorlevel 1 (
        echo [*] Initializing fallback (legacy git init)...
        "%GIT_EXE%" init
        "%GIT_EXE%" branch -M main >nul 2>&1
    )
)

:: 3. Stage files
echo [*] Staging all files conforming to .gitignore...
"%GIT_EXE%" add .

:: 4. Commit changes
set "COMMIT_MSG=%~1"
if "%COMMIT_MSG%"=="" (
    set "COMMIT_MSG=feat: OSINT Recon Studio v1.3.0 with Personal Privacy exposure auditor, desktop pinning, and PyInstaller launcher"
)

"%GIT_EXE%" status --porcelain | findstr /R "." >nul 2>&1
if not errorlevel 1 (
    echo [*] Committing changes with message:
    echo     "%COMMIT_MSG%"
    "%GIT_EXE%" commit -m "%COMMIT_MSG%"
) else (
    echo [*] Working tree clean - no new changes to commit.
)

echo.
:: 5. Check remote origin
set "HAS_REMOTE="
"%GIT_EXE%" remote get-url origin >nul 2>&1
if not errorlevel 1 (
    set "HAS_REMOTE=1"
    for /f "tokens=*" %%R in ('"%GIT_EXE%" remote get-url origin') do (
        echo [*] Existing remote origin found: %%R
    )
) else (
    echo [!] No remote 'origin' configured yet.
    echo.
    echo Please create a new GitHub repository at: https://github.com/new
    set /p REPO_URL="Enter your GitHub repository URL (e.g. https://github.com/username/osint-recon-studio.git): "
    if not "!REPO_URL!"=="" (
        "%GIT_EXE%" remote add origin "!REPO_URL!"
        set "HAS_REMOTE=1"
    ) else (
        echo [!] Skipped remote addition. You can manually run:
        echo     git remote add origin https://github.com/YOUR_USER/osint-recon-studio.git
        echo     git push -u origin main
        pause
        exit /b 0
    )
)

:: 6. Push to GitHub
if "%HAS_REMOTE%"=="1" (
    echo.
    echo [*] Pushing branch 'main' to GitHub remote origin...
    "%GIT_EXE%" push -u origin main
    if errorlevel 1 (
        echo.
        echo [!] Push failed or authentication needed.
        echo If using personal access token or SSH, please ensure credentials are saved.
    ) else (
        echo.
        echo =====================================================================
        echo  SUCCESS: Code successfully committed and pushed to GitHub!
        echo =====================================================================
    )
)

echo.
pause
