@echo off
setlocal
cd /d "%~dp0"

echo =====================================================================
echo  OSINT Recon Studio - Desktop Shortcut Creator
echo =====================================================================
echo.

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$ws = New-Object -ComObject WScript.Shell;" ^
    "$d = [System.Environment]::GetFolderPath('Desktop');" ^
    "$shortcutPath = Join-Path $d 'OSINT Recon Studio.lnk';" ^
    "$exe = (Resolve-Path 'dist\OSINTReconStudio\OSINTReconStudio.exe' -ErrorAction SilentlyContinue);" ^
    "if (-not $exe) { $exe = (Resolve-Path 'run_app.bat') };" ^
    "$s = $ws.CreateShortcut($shortcutPath);" ^
    "$s.TargetPath = $exe.Path;" ^
    "$s.WorkingDirectory = (Get-Location).Path;" ^
    "$ico = (Resolve-Path 'assets\app_icon.ico' -ErrorAction SilentlyContinue);" ^
    "if ($ico) { $s.IconLocation = \"$($ico.Path),0\" };" ^
    "$s.Description = 'OSINT Recon Studio - Native Windows Passive OSINT & Privacy Studio';" ^
    "$s.Save();" ^
    "Write-Host '[+] Desktop shortcut created successfully at:' $shortcutPath -ForegroundColor Green"

echo.
pause
