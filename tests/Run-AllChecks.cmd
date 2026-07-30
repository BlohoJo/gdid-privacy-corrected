@echo off
setlocal
set "RUNNER=%~dp0Run-AllChecks.ps1"
set "WINDOWS_POWERSHELL=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"

if not exist "%WINDOWS_POWERSHELL%" (
    echo [FAIL] Windows PowerShell 5.1 was not found at:
    echo        %WINDOWS_POWERSHELL%
    exit /b 1
)

"%WINDOWS_POWERSHELL%" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "%RUNNER%" -IncludeStatus -RequirePowerShell7
set "RESULT=%ERRORLEVEL%"

echo.
if "%RESULT%"=="0" (
    echo All validation stages passed.
) else (
    echo One or more validation stages failed.
    echo Attach the newest log from tests\validation-results when reporting a problem.
)
exit /b %RESULT%
