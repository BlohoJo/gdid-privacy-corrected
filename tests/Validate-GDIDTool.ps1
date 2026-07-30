#Requires -Version 5.1
[CmdletBinding()]
param()

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$mainPath = Join-Path $root 'gdid-tool.ps1'
$configPath = Join-Path $root 'gdid-config.json'
$failures = New-Object 'System.Collections.Generic.List[string]'
$passes = 0

function Pass([string]$Message) {
    $script:passes++
    Write-Host "[PASS] $Message" -ForegroundColor Green
}
function Fail([string]$Message) {
    $failures.Add($Message)
    Write-Host "[FAIL] $Message" -ForegroundColor Red
}
function Require-Match {
    param([string]$Text, [System.Collections.IDictionary]$Patterns, [string]$Category)
    $before = $failures.Count
    foreach ($item in $Patterns.GetEnumerator()) {
        if ($Text -notmatch [string]$item.Value) { Fail "$Category missing: $($item.Key)" }
    }
    if ($failures.Count -eq $before) { Pass "$Category requirements present" }
}
function Require-Absent {
    param([string]$Text, [System.Collections.IDictionary]$Patterns, [string]$Category)
    $before = $failures.Count
    foreach ($item in $Patterns.GetEnumerator()) {
        if ($Text -match [string]$item.Value) { Fail "$Category prohibited item present: $($item.Key)" }
    }
    if ($failures.Count -eq $before) { Pass "$Category prohibited-item checks passed" }
}

function Get-Sha256Hex {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$LiteralPath
    )

    # Use the .NET base class library directly. This avoids depending on
    # Microsoft.PowerShell.Utility module discovery or command auto-loading in
    # either Windows PowerShell 5.1 or PowerShell 7.
    $stream = $null
    $sha256 = $null
    try {
        $stream = [System.IO.File]::Open(
            $LiteralPath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read
        )
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        if ($null -eq $sha256) {
            throw 'The .NET runtime could not create a SHA-256 implementation.'
        }
        $bytes = $sha256.ComputeHash($stream)
        return [System.BitConverter]::ToString($bytes).Replace('-', '')
    } finally {
        if ($null -ne $stream) { $stream.Dispose() }
        if ($null -ne $sha256) { $sha256.Dispose() }
    }
}

$required = @(
    'gdid-tool.ps1','gdid-config.json','README.md','AUDIT_REPORT.md',
    'REMOVED_FEATURES.md','STATIC_AUDIT_RESULTS.md','TESTING.md',
    'SHA256SUMS.txt','PSScriptAnalyzerSettings.psd1','build-exe.ps1',
    'gdid-tool.bat','tests\WPN_TEST_PLAN.md','tests\TELEMETRY_TEST_PLAN.md',
    'tests\Validate-GDIDTool.ps1','tests\Parse-AllPowerShell.ps1',
    'tests\Run-AllChecks.ps1','tests\Run-AllChecks.cmd',
    '.github\workflows\powershell-validation.yml'
)
foreach ($relative in $required) {
    $path = Join-Path $root $relative
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Fail "Missing package file: $relative" }
}
if ($failures.Count -eq 0) { Pass 'All required package files are present' }

# Parse, but never execute, every packaged PowerShell source/data file.
$asts = @{}
$powerShellFiles = @(Get-ChildItem -LiteralPath $root -File -Recurse | Where-Object {
    $_.Extension.ToLowerInvariant() -in @('.ps1', '.psm1', '.psd1')
} | Select-Object -ExpandProperty FullName)
$parserFailureCountBefore = $failures.Count
foreach ($path in $powerShellFiles) {
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        $path,
        [ref]$tokens,
        [ref]$errors
    )
    $asts[$path] = $ast
    foreach ($error in @($errors)) {
        Fail ("Parser {0}:{1}:{2}: {3}" -f
            $path,
            $error.Extent.StartLineNumber,
            $error.Extent.StartColumnNumber,
            $error.Message)
    }
    foreach ($token in @($tokens | Where-Object {
        $_.Kind -eq [System.Management.Automation.Language.TokenKind]::StringExpandable -or
        $_.Kind -eq [System.Management.Automation.Language.TokenKind]::HereStringExpandable
    })) {
        $matches = [regex]::Matches(
            [string]$token.Text,
            '\$(?!\(|\{)(?!(?:global|script|local|private|using|env|function|variable):)([A-Za-z_][A-Za-z0-9_]*):',
            [Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
        foreach ($match in $matches) {
            Fail ("Unsafe expandable-string interpolation {0}:{1}:{2}: {3}" -f
                $path,
                $token.Extent.StartLineNumber,
                $token.Extent.StartColumnNumber,
                $match.Value)
        }
    }
}
if ($powerShellFiles.Count -gt 0 -and $failures.Count -eq $parserFailureCountBefore) {
    Pass "PowerShell parser/interpolation gate passed for $($powerShellFiles.Count) files"
}

$validatorPath = Join-Path $PSScriptRoot 'Validate-GDIDTool.ps1'
$validatorAst = $asts[$validatorPath]
if ($null -ne $validatorAst) {
    $portableHashHelper = @($validatorAst.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -eq 'Get-Sha256Hex'
    }, $true))
    $moduleHashCalls = @($validatorAst.FindAll({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst] -and
        $node.GetCommandName() -eq ('Get' + '-FileHash')
    }, $true))
    if ($portableHashHelper.Count -ne 1) {
        Fail "Portable SHA-256 helper count is $($portableHashHelper.Count); expected exactly 1."
    }
    if ($moduleHashCalls.Count -gt 0) {
        Fail 'Checksum validation must not depend on the Microsoft.PowerShell.Utility file-hash cmdlet.'
    }
    if ($portableHashHelper.Count -eq 1 -and $moduleHashCalls.Count -eq 0) {
        Pass 'Checksum validator uses the engine-independent .NET SHA-256 helper'
    }
}

if (-not (Test-Path -LiteralPath $mainPath)) { throw 'Main script is missing.' }
$main = Get-Content -LiteralPath $mainPath -Raw
$readme = Get-Content -LiteralPath (Join-Path $root 'README.md') -Raw
$audit = Get-Content -LiteralPath (Join-Path $root 'AUDIT_REPORT.md') -Raw
$mainAst = $asts[$mainPath]
if ($null -ne $mainAst) {
    $funcs = @($mainAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] },$true))
    $dupes = @($funcs | Group-Object { $_.Name.ToLowerInvariant() } | Where-Object Count -gt 1)
    foreach ($dupe in $dupes) { Fail "Duplicate function: $($dupe.Name) ($($dupe.Count))" }
    if ($dupes.Count -eq 0) { Pass "Function names are unique ($($funcs.Count) functions)" }
}

Require-Match $main ([ordered]@{
    'tool version' = '(?m)^\s*\$script:ToolVersion\s*=\s*''3\.7\.2-audited-telemetry''\s*$'
    'config schema 5' = '(?m)^\s*\$script:CurrentConfigSchema\s*=\s*5\s*$'
    'state schema 6' = '(?m)^\s*\$script:CurrentStateSchema\s*=\s*6\s*$'
    'state migration' = '(?m)^function\s+Upgrade-StateToCurrentSchema\b'
}) 'Version/schema'

Require-Match $main ([ordered]@{
    'blockTelemetry default off' = '(?m)^\s*blockTelemetry\s*=\s*\$false\b'
    'delete request default off' = '(?m)^\s*requestDiagnosticDataDelete\s*=\s*\$false\b'
    'strict Boolean conversion' = '(?m)^function\s+ConvertTo-StrictBoolean\b'
    'unknown key rejection' = 'contains unknown key\(s\)'
    'cross-session lock' = '\[IO\.FileShare\]::None'
}) 'Configuration/safety'

Require-Match $main ([ordered]@{
    'platform detection' = '(?m)^function\s+Get-WindowsPlatformProfile\b'
    'edition-aware resolver' = "DesiredValueResolver\s*=\s*'MinimumDiagnosticData'"
    'Pro minimum fallback' = '\$minimum\s*=\s*if\s*\(\$supportsDiagnosticDataOff\)\s*\{\s*0\s*\}\s*else\s*\{\s*1\s*\}'
    'AllowTelemetry policy' = "Id\s*=\s*'Telemetry\.AllowTelemetry'"
    'device name policy' = "Name\s*=\s*'AllowDeviceNameInTelemetry'"
    'enterprise proxy policy' = "Name\s*=\s*'DisableEnterpriseAuthProxy'"
    'OneSettings policy' = "Name\s*=\s*'DisableOneSettingsDownloads'"
    'feedback policy' = "Name\s*=\s*'DoNotShowFeedbackNotifications'"
    'log limit policy' = "Name\s*=\s*'LimitDiagnosticLogCollection'"
    'Analytics policy' = "Id\s*=\s*'Telemetry\.LimitEnhancedDiagnosticDataWindowsAnalytics'"
    'Analytics disabled value zero' = "(?s)Id\s*=\s*'Telemetry\.LimitEnhancedDiagnosticDataWindowsAnalytics'.*?DesiredValue\s*=\s*0"
    'deletion kept available' = "(?s)Id\s*=\s*'Telemetry\.DisableDeviceDelete'.*?DesiredValue\s*=\s*0"
    'opt-in Settings UI lock' = "Name\s*=\s*'DisableTelemetryOptInSettingsUx'"
    'tailored experiences' = "Name\s*=\s*'DisableTailoredExperiencesWithDiagnosticData'"
    'linguistic collection' = "Name\s*=\s*'AllowLinguisticDataCollection'"
    'text restriction' = "Name\s*=\s*'RestrictImplicitTextCollection'"
    'ink restriction' = "Name\s*=\s*'RestrictImplicitInkCollection'"
}) 'Diagnostic policy implementation'

Require-Match $main ([ordered]@{
    'gpupdate helper' = '(?m)^function\s+Invoke-GroupPolicyRefresh\b'
    'gpupdate force wait' = "ArgumentList\s+@\('/force',\s*'/wait:300'\)"
    'post-refresh policy verification' = '(?m)^function\s+Assert-ConfiguredPoliciesReconciled\b'
    'restoration verification' = '(?m)^function\s+Assert-ManagedPoliciesRestored\b'
    'deletion request helper' = '(?m)^function\s+Invoke-DiagnosticDataDeleteRequest\b'
    'current-host cmdlet call' = 'Clear-WindowsDiagnosticData'
    'Windows PowerShell fallback' = 'System32\\WindowsPowerShell\\v1\.0\\powershell\.exe'
    'one-shot flag reset' = 'config\[''requestDiagnosticDataDelete''\]\s*=\s*\$false'
}) 'Group Policy/deletion workflow'

Require-Match $main ([ordered]@{
    'DiagTrack path' = 'SYSTEM\\CurrentControlSet\\Services\\DiagTrack'
    'dmwappush path' = 'SYSTEM\\CurrentControlSet\\Services\\dmwappushservice'
    'telemetry status helper' = '(?m)^function\s+Get-TelemetryBlockStatus\b'
    'telemetry enable helper' = '(?m)^function\s+Enable-TelemetryBlock\b'
    'telemetry restore helper' = '(?m)^function\s+Restore-TelemetryFromState\b'
    'service loop disables through SCM' = 'Set-Service\s+-Name\s+\$item\.Name\s+-StartupType\s+Disabled'
    'live block verification' = 'Diagnostic-data service block verification failed'
    'service baseline verification' = 'Assert-ManagedServicePathsBackedForMutation\s+-State\s+\$State\s+-Family\s+''Telemetry'''
}) 'Telemetry service implementation'

Require-Match $main ([ordered]@{
    'WpnService path' = 'SYSTEM\\CurrentControlSet\\Services\\WpnService'
    'WpnUserService path' = 'SYSTEM\\CurrentControlSet\\Services\\WpnUserService'
    'WPN block helper' = '(?m)^function\s+Enable-WpnBlock\b'
    'WPN restore helper' = '(?m)^function\s+Restore-WpnFromState\b'
    'WPN instance enumeration' = "Get-Service\s+-Name\s+'WpnUserService_\*'"
    'template flags zero' = 'Set-RegistryValue\s+-Path\s+\$script:WpnUserTemplatePath\s+-Name\s+''UserServiceFlags''\s+-Value\s+0'
}) 'WPN implementation'

Require-Match $main ([ordered]@{
    'CDP block helper' = '(?m)^function\s+Enable-CDPBlock\b'
    'CDP restore helper' = '(?m)^function\s+Restore-CDPFromState\b'
    'CDP instance enumeration' = "Get-Service\s+-Name\s+'CDPUserSvc_\*'"
    'mask requires verified CDP' = 'CDP is not fully disabled and stopped'
    'original identity restore' = '(?m)^function\s+Restore-OriginalIdentity\b'
}) 'CDP/identity implementation'

Require-Absent $main ([ordered]@{
    'IP firewall commands' = '\b(New-NetFirewallRule|Set-NetFirewallRule|Remove-NetFirewallRule)\b'
    'legacy firewall refresh command' = "'refreshfw'"
    'AppInit DLL deployment' = '\bAppInit_DLLs\b'
    'CDP cache deletion' = 'ConnectedDevicesPlatform.*Remove-Item|Remove-Item.*ConnectedDevicesPlatform'
    'CDP restart helper' = '(?m)^function\s+Restart-CDP\b'
    'elevated rotation task' = 'New-ScheduledTaskPrincipal[^\r\n]+RunLevel\s+Highest'
    'dynamic expression execution' = '\bInvoke-Expression\b|\biex\b'
    'encoded command' = '-EncodedCommand\b'
}) 'Removed/unsafe mechanisms'

# Validate JSON shape and exact shipped defaults.
try {
    $raw = Get-Content -LiteralPath $configPath -Raw | ConvertFrom-Json
    $expected = [ordered]@{
        schemaVersion = 5; rotationMode = 'onDemand'; timedIntervalMin = 30;
        blockCDP = $true; blockWpn = $false; blockTelemetry = $false;
        requestDiagnosticDataDelete = $false; blockHosts = $true;
        blockAADHost = $false; blockDO = $false; killPhoneLink = $false;
        killOneDrive = $false; killStore = $false; killTimeline = $false;
        hookMethod = 'registry'
    }
    $names = @($raw.PSObject.Properties.Name)
    foreach ($key in $expected.Keys) {
        if ($names -notcontains $key) { Fail "Config missing key: $key"; continue }
        if ([string]$raw.$key -cne [string]$expected[$key]) { Fail "Config $key expected '$($expected[$key])', found '$($raw.$key)'" }
    }
    foreach ($name in $names) { if (-not $expected.Contains($name)) { Fail "Config unknown key: $name" } }
    if (-not ($failures | Where-Object { $_ -like 'Config *' })) { Pass 'Configuration schema, keys, and defaults match' }
} catch { Fail "Configuration JSON: $($_.Exception.Message)" }

Require-Match $readme ([ordered]@{
    'telemetry opt-in warning' = '`blockTelemetry=true` can break or degrade'
    'edition matrix' = 'Windows 10/11 Pro'
    'Analytics value correction' = 'maps to value `0`, not `1`'
    'gpupdate disclosure' = 'gpupdate\.exe /force /wait:300'
    'Registry.pol disclosure' = 'does not edit `Registry\.pol`'
    'deletion is request only' = 'not proof that Microsoft has completed server-side deletion'
    'Intune warning' = 'Intune/MDM'
    'validation first' = 'Run-AllChecks\.cmd'
    'dual parser disclosure' = '(?s)Windows PowerShell 5\.1.*PowerShell 7|PowerShell 7.*Windows PowerShell 5\.1'
}) 'README telemetry/validation disclosure'

Require-Match $audit ([ordered]@{
    'Issue 12 disposition' = 'Issue #12 disposition'
    'telemetry effectiveness matrix' = 'Effectiveness matrix'
    'live test limitation' = 'not Windows'
}) 'Audit documentation'

# Verify every packaged payload listed in the SHA-256 manifest. The manifest
# deliberately does not list itself or generated validation logs.
$manifestPath = Join-Path $root 'SHA256SUMS.txt'
$manifestFailureCountBefore = $failures.Count
$manifestEntryCount = 0
$manifestRelativePaths = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
try {
    foreach ($line in @(Get-Content -LiteralPath $manifestPath)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        $entryMatch = [regex]::Match($line, '^([0-9A-Fa-f]{64})  \./(.+)$')
        if (-not $entryMatch.Success) {
            Fail "Malformed checksum-manifest line: $line"
            continue
        }
        $manifestEntryCount++
        $expectedHash = $entryMatch.Groups[1].Value.ToUpperInvariant()
        $manifestRelativePath = $entryMatch.Groups[2].Value.Replace('\', '/')
        if (-not $manifestRelativePaths.Add($manifestRelativePath)) {
            Fail "Duplicate checksum-manifest target: $manifestRelativePath"
            continue
        }
        $relativePath = $manifestRelativePath -replace '/', [IO.Path]::DirectorySeparatorChar
        $targetPath = Join-Path $root $relativePath
        if (-not (Test-Path -LiteralPath $targetPath -PathType Leaf)) {
            Fail "Checksum target is missing: $manifestRelativePath"
            continue
        }
        $actualHash = Get-Sha256Hex -LiteralPath $targetPath
        if ($actualHash -cne $expectedHash) {
            Fail "Checksum mismatch: $manifestRelativePath"
        }
    }

    $rootPrefix = $root.TrimEnd([char[]]@('\', '/')) + [IO.Path]::DirectorySeparatorChar
    $payloadFiles = @(Get-ChildItem -LiteralPath $root -File -Recurse | Where-Object {
        $_.FullName -ne $manifestPath -and
        $_.Name -ne 'gdid-tool.exe' -and
        $_.FullName -notmatch '[\\/]tests[\\/]validation-results[\\/]' -and
        $_.FullName -notmatch '[\\/]\.git[\\/]'
    })
    foreach ($payloadFile in $payloadFiles) {
        $payloadRelativePath = $payloadFile.FullName.Substring($rootPrefix.Length).Replace('\', '/')
        if (-not $manifestRelativePaths.Contains($payloadRelativePath)) {
            Fail "Package file is not covered by SHA256SUMS.txt: $payloadRelativePath"
        }
    }
} catch {
    Fail "Checksum-manifest validation: $($_.Exception.Message)"
}
if ($manifestEntryCount -gt 0 -and $failures.Count -eq $manifestFailureCountBefore) {
    Pass "SHA-256 manifest verified and covers all payload files ($manifestEntryCount files)"
}

# PSScriptAnalyzer is optional locally and mandatory in CI.
if (Get-Module -ListAvailable -Name PSScriptAnalyzer) {
    $settingsPath = Join-Path $root 'PSScriptAnalyzerSettings.psd1'
    $findings = @(Invoke-ScriptAnalyzer -Path $root -Recurse -Settings $settingsPath)
    foreach ($finding in $findings) {
        Fail "PSScriptAnalyzer $($finding.RuleName): $($finding.ScriptName):$($finding.Line): $($finding.Message)"
    }
    if ($findings.Count -eq 0) {
        Pass 'PSScriptAnalyzer compatibility/safety rules reported no findings'
    }
} else {
    Write-Host '[INFO] PSScriptAnalyzer is not installed; analyzer pass skipped locally. It remains mandatory in CI.' -ForegroundColor Cyan
}

Write-Host "`nPasses: $passes  Failures: $($failures.Count)"
if ($failures.Count -gt 0) { exit 1 }
Write-Host 'All static validation checks passed.' -ForegroundColor Green
exit 0
