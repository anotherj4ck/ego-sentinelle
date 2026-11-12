@echo off
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0lancer.ps1" %*
set "CODE=%ERRORLEVEL%"
pause
exit /b %CODE%
