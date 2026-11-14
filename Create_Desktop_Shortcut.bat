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
    "$candidates = @(" ^
    "    'dist\OSINTReconStudio\OSINTReconStudio.exe'," ^
    "    'OSINTReconStudio.exe'," ^
    "    'run_app.bat'," ^
    "    '..\run_app.bat'" ^
    ");" ^
    "$targetPath = $null;" ^
    "foreach ($c in $candidates) {" ^
    "    if (Test-Path $c) {" ^
    "        $targetPath = (Resolve-Path $c).Path;" ^
    "        break;" ^
    "    }" ^
    "};" ^
    "if (-not $targetPath) {" ^
    "    Write-Host '[-] Error: Could not locate application target.' -ForegroundColor Red;" ^
    "    exit 1;" ^
    "};" ^
    "$s = $ws.CreateShortcut($shortcutPath);" ^
    "$s.TargetPath = $targetPath;" ^
    "$s.WorkingDirectory = Split-Path -Parent $targetPath;" ^
    "$icoCandidates = @(" ^
    "    'assets\app_icon.ico'," ^
    "    '_internal\assets\app_icon.ico'," ^
    "    '..\assets\app_icon.ico'," ^
    "    '..\..\assets\app_icon.ico'" ^
    ");" ^
    "foreach ($ic in $icoCandidates) {" ^
    "    if (Test-Path $ic) {" ^
    "        $s.IconLocation = \"$((Resolve-Path $ic).Path),0\";" ^
    "        break;" ^
    "    }" ^
    "};" ^
    "$s.Description = 'OSINT Recon Studio - Native Windows Passive OSINT & Privacy Studio';" ^
    "$s.Save();" ^
    "Write-Host '[+] Desktop shortcut created successfully at:' $shortcutPath -ForegroundColor Green"

echo.
pause
