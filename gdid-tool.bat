@echo off
setlocal EnableExtensions DisableDelayedExpansion

set "SCRIPT=%~dp0gdid-tool.ps1"
if not exist "%SCRIPT%" (
    echo [ERROR] Cannot find "%SCRIPT%".
    exit /b 1
)

set "PAUSE_WHEN_DONE=0"
if "%~1"=="" set "PAUSE_WHEN_DONE=1"

set "MODE=%~1"
if not defined MODE set "MODE=status"

if /I "%MODE%"=="install" goto :ensure_admin
if /I "%MODE%"=="uninstall" goto :ensure_admin
goto :run

:ensure_admin
>nul 2>&1 "%SystemRoot%\System32\fltmc.exe"
if not errorlevel 1 goto :run

REM Only install and uninstall enter this branch, so pass the validated mode and
REM script path through environment variables rather than interpolating arbitrary
REM command text into the elevation command.
set "GDID_TOOL_SCRIPT=%SCRIPT%"
set "GDID_TOOL_MODE=%MODE%"
PowerShell.exe -NoLogo -NoProfile -Command ^
  "$ErrorActionPreference='Stop'; try { $q=[char]34; $line='-NoLogo -NoProfile -ExecutionPolicy Bypass -File ' + $q + $env:GDID_TOOL_SCRIPT + $q + ' ' + $env:GDID_TOOL_MODE; $p=Start-Process -FilePath 'PowerShell.exe' -Verb RunAs -ArgumentList $line -Wait -PassThru; exit $p.ExitCode } catch { Write-Error $_; exit 1 }"
set "RC=%errorlevel%"
set "GDID_TOOL_SCRIPT="
set "GDID_TOOL_MODE="
exit /b %RC%

:run
PowerShell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%" %*
set "RC=%errorlevel%"
if "%PAUSE_WHEN_DONE%"=="1" pause
exit /b %RC%
