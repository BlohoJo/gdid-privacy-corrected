#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$IncludeStatus,
    [switch]$RequirePowerShell7,
    [string]$LogPath
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$parseWorker = Join-Path $PSScriptRoot 'Parse-AllPowerShell.ps1'
$validator = Join-Path $PSScriptRoot 'Validate-GDIDTool.ps1'
$main = Join-Path $root 'gdid-tool.ps1'

if ([string]::IsNullOrWhiteSpace($LogPath)) {
    $resultDirectory = Join-Path $PSScriptRoot 'validation-results'
    if (-not (Test-Path -LiteralPath $resultDirectory)) {
        New-Item -ItemType Directory -Path $resultDirectory -Force | Out-Null
    }
    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $LogPath = Join-Path $resultDirectory "validation-$stamp.log"
}

$logDirectory = Split-Path -Parent $LogPath
if ($logDirectory -and -not (Test-Path -LiteralPath $logDirectory)) {
    New-Item -ItemType Directory -Path $logDirectory -Force | Out-Null
}

$script:FailureCount = 0
$script:StepCount = 0

function Write-LogLine {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )

    Write-Host $Text -ForegroundColor $Color
    Add-Content -LiteralPath $LogPath -Value $Text -Encoding UTF8
}

function Invoke-ValidationStep {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$Executable,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    $script:StepCount++
    Write-LogLine "`n===== $Label =====" Cyan
    Write-LogLine ("Executable: {0}" -f $Executable) DarkGray

    try {
        $output = @(& $Executable @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    } catch {
        $script:FailureCount++
        Write-LogLine ("[FAIL] {0} could not be launched: {1}" -f
            $Label,
            $_.Exception.Message) Red
        return $false
    }

    foreach ($line in $output) {
        $text = if ($null -eq $line) { '' } else { [string]$line }
        Write-Host $text
        Add-Content -LiteralPath $LogPath -Value $text -Encoding UTF8
    }

    if ($exitCode -ne 0) {
        $script:FailureCount++
        Write-LogLine ("[FAIL] {0} exited with code {1}." -f $Label, $exitCode) Red
        return $false
    }

    Write-LogLine "[PASS] $Label" Green
    return $true
}

Set-Content -LiteralPath $LogPath -Value @(
    'GDID Privacy Tool validation log',
    "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss K')",
    "Root: $root",
    "Launcher engine: $($PSVersionTable.PSEdition) $($PSVersionTable.PSVersion)",
    "Language mode: $($ExecutionContext.SessionState.LanguageMode)",
    "OS: $([Environment]::OSVersion.VersionString)",
    "64-bit process: $([Environment]::Is64BitProcess)",
    ''
) -Encoding UTF8

$engines = New-Object 'System.Collections.Generic.List[object]'
$windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
if (Test-Path -LiteralPath $windowsPowerShell -PathType Leaf) {
    $engines.Add([pscustomobject]@{
        Name = 'Windows PowerShell 5.1'
        Path = $windowsPowerShell
    })
} else {
    $script:FailureCount++
    Write-LogLine '[FAIL] Windows PowerShell 5.1 was not found.' Red
}

$pwshCommand = Get-Command -Name 'pwsh.exe' -ErrorAction SilentlyContinue
if ($null -eq $pwshCommand) {
    $pwshCommand = Get-Command -Name 'pwsh' -ErrorAction SilentlyContinue
}
if ($null -ne $pwshCommand) {
    $engines.Add([pscustomobject]@{
        Name = 'PowerShell 7'
        Path = [string]$pwshCommand.Path
    })
} elseif ($RequirePowerShell7) {
    $script:FailureCount++
    Write-LogLine '[FAIL] PowerShell 7 (pwsh.exe) was required but was not found.' Red
} else {
    Write-LogLine '[WARN] PowerShell 7 was not found; only Windows PowerShell 5.1 will be checked.' Yellow
}

foreach ($engine in $engines) {
    $common = @('-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass')
    $parsePassed = Invoke-ValidationStep `
        -Label "$($engine.Name): parse every PowerShell file" `
        -Executable $engine.Path `
        -Arguments ($common + @('-File', $parseWorker, '-Root', $root))

    if (-not $parsePassed) {
        Write-LogLine "[SKIP] Remaining $($engine.Name) checks were skipped because parsing failed." Yellow
        continue
    }

    [void](Invoke-ValidationStep `
        -Label "$($engine.Name): package validator" `
        -Executable $engine.Path `
        -Arguments ($common + @('-File', $validator)))

    [void](Invoke-ValidationStep `
        -Label "$($engine.Name): main-script help smoke test" `
        -Executable $engine.Path `
        -Arguments ($common + @('-File', $main, 'help')))

    [void](Invoke-ValidationStep `
        -Label "$($engine.Name): configuration read smoke test" `
        -Executable $engine.Path `
        -Arguments ($common + @('-File', $main, 'config')))

    if ($IncludeStatus) {
        [void](Invoke-ValidationStep `
            -Label "$($engine.Name): read-only status smoke test" `
            -Executable $engine.Path `
            -Arguments ($common + @('-File', $main, 'status')))
    }
}

Write-LogLine "`n===== Summary =====" Cyan
Write-LogLine "Steps attempted: $script:StepCount"
Write-LogLine "Failures:       $script:FailureCount" $(if ($script:FailureCount -eq 0) { 'Green' } else { 'Red' })
Write-LogLine "Log:            $LogPath"

if ($script:FailureCount -gt 0) {
    exit 1
}
exit 0
