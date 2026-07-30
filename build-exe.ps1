#Requires -Version 5.1
<#
.SYNOPSIS
    Builds the audited PowerShell script as a visible console EXE using ps2exe.

.DESCRIPTION
    The EXE is intentionally not marked always-elevated. Read-only commands do
    not need elevation; run `gdid-tool.exe install` or `uninstall` from an
    elevated console. The default command remains `status`.
#>

[CmdletBinding()]
param(
    [switch]$InstallDependency
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# Building is a release operation. Refuse to compile until the checked-in
# Windows PowerShell 5.1 + PowerShell 7 gate passes.
$validationRunner = Join-Path $PSScriptRoot 'tests\Run-AllChecks.ps1'
$windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
if (-not (Test-Path -LiteralPath $validationRunner -PathType Leaf)) {
    throw "Cannot find validation runner '$validationRunner'."
}
if (-not (Test-Path -LiteralPath $windowsPowerShell -PathType Leaf)) {
    throw "Cannot find Windows PowerShell 5.1 at '$windowsPowerShell'."
}
& $windowsPowerShell -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass `
    -File $validationRunner -RequirePowerShell7
if ($LASTEXITCODE -ne 0) {
    throw "Dual-engine validation failed with exit code $LASTEXITCODE. The EXE was not built."
}

$minimumPs2ExeVersion = [version]'1.0.18'
$module = Get-Module -ListAvailable -Name ps2exe |
    Sort-Object Version -Descending |
    Select-Object -First 1

if ($null -eq $module -or $module.Version -lt $minimumPs2ExeVersion) {
    if (-not $InstallDependency) {
        $found = if ($null -eq $module) { 'not installed' } else { "version $($module.Version)" }
        throw "ps2exe $minimumPs2ExeVersion or newer is required (found: $found). Re-run with -InstallDependency, or install it explicitly with: Install-Module ps2exe -Scope CurrentUser -MinimumVersion $minimumPs2ExeVersion -Force"
    }
    Install-Module -Name ps2exe -Scope CurrentUser -MinimumVersion $minimumPs2ExeVersion -Force -ErrorAction Stop
    $module = Get-Module -ListAvailable -Name ps2exe |
        Where-Object { $_.Version -ge $minimumPs2ExeVersion } |
        Sort-Object Version -Descending |
        Select-Object -First 1
}

if ($null -eq $module -or $module.Version -lt $minimumPs2ExeVersion) {
    throw "A compatible ps2exe module could not be located after installation. Required: $minimumPs2ExeVersion or newer."
}
Import-Module $module.Path -Force -ErrorAction Stop

$source = Join-Path $PSScriptRoot 'gdid-tool.ps1'
$output = Join-Path $PSScriptRoot 'gdid-tool.exe'
if (-not (Test-Path -LiteralPath $source -PathType Leaf)) {
    throw "Cannot find '$source'."
}

# Do not use -noConsole or -requireAdmin. The tool's interface is console based,
# and only install/uninstall require an elevated process.
Invoke-PS2EXE -InputFile $source -OutputFile $output

if (-not (Test-Path -LiteralPath $output -PathType Leaf)) {
    throw "ps2exe returned without creating '$output'."
}

Write-Host "Built: $output (ps2exe $($module.Version))" -ForegroundColor Green
Write-Host 'Keep gdid-config.json beside the EXE.' -ForegroundColor Yellow
Write-Host 'The default command is status; elevate only for install/uninstall.' -ForegroundColor Yellow
