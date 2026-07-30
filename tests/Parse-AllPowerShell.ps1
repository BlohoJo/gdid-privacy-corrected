#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Root
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$resolvedRoot = (Resolve-Path -LiteralPath $Root).Path
$extensions = @('.ps1', '.psm1', '.psd1')
$files = @(Get-ChildItem -LiteralPath $resolvedRoot -Recurse -File | Where-Object {
    $extensions -contains $_.Extension.ToLowerInvariant()
} | Sort-Object FullName)

$parseErrors = New-Object 'System.Collections.Generic.List[string]'
$unsafeInterpolations = New-Object 'System.Collections.Generic.List[string]'
[char[]]$trimChars = @([char]'\', [char]'/')

Write-Host ("Engine: {0} {1} (64-bit={2})" -f
    $PSVersionTable.PSEdition,
    $PSVersionTable.PSVersion,
    [Environment]::Is64BitProcess)
Write-Host "Root:   $resolvedRoot"
Write-Host "Files:  $($files.Count)"

foreach ($file in $files) {
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile(
        $file.FullName,
        [ref]$tokens,
        [ref]$errors
    )

    $relative = $file.FullName.Substring($resolvedRoot.Length).TrimStart($trimChars)
    foreach ($error in @($errors)) {
        $message = "{0}:{1}:{2}: {3}" -f
            $relative,
            $error.Extent.StartLineNumber,
            $error.Extent.StartColumnNumber,
            $error.Message
        $parseErrors.Add($message)
        Write-Host "[PARSE ERROR] $message" -ForegroundColor Red
    }

    # Regression gate for the defect that escaped the earlier delimiter-only
    # audit. A plain variable immediately followed by a colon in an expandable
    # string is either invalid or an unintended drive/scope interpretation.
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
            $message = "{0}:{1}:{2}: ambiguous expandable-string variable '{3}'" -f
                $relative,
                $token.Extent.StartLineNumber,
                $token.Extent.StartColumnNumber,
                $match.Value
            $unsafeInterpolations.Add($message)
            Write-Host "[INTERPOLATION ERROR] $message" -ForegroundColor Red
        }
    }
}

if ($parseErrors.Count -gt 0 -or $unsafeInterpolations.Count -gt 0) {
    Write-Host ("FAILED: parser errors={0}; unsafe interpolations={1}" -f
        $parseErrors.Count,
        $unsafeInterpolations.Count) -ForegroundColor Red
    exit 1
}

Write-Host "PASS: all $($files.Count) PowerShell files parsed cleanly and no unsafe variable-colon interpolation was found." -ForegroundColor Green
exit 0
