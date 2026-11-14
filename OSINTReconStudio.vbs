Set WshShell = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
strDir = fso.GetParentFolderName(WScript.ScriptFullName)

If fso.FileExists(strDir & "\dist\OSINTReconStudio\OSINTReconStudio.exe") Then
    WshShell.CurrentDirectory = strDir & "\dist\OSINTReconStudio"
    WshShell.Run Chr(34) & strDir & "\dist\OSINTReconStudio\OSINTReconStudio.exe" & Chr(34), 1, False
ElseIf fso.FileExists(strDir & "\.venv\Scripts\pythonw.exe") Then
    WshShell.CurrentDirectory = strDir
    WshShell.Run Chr(34) & strDir & "\.venv\Scripts\pythonw.exe" & Chr(34) & " " & Chr(34) & strDir & "\run_app.py" & Chr(34), 0, False
Else
    WshShell.Run "cmd /c cd /d " & Chr(34) & strDir & Chr(34) & " && run_app.bat", 1, False
End If
