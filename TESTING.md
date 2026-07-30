# Testing and troubleshooting — mandatory release gate

The main script must not be debugged by repeatedly executing it and fixing only
the first parser message. PowerShell can parse a script without executing it and
return every syntax error in one pass. The project therefore has a two-engine,
parser-first validation gate.

## One-command target-machine check

From either PowerShell or Command Prompt, run this **before invoking
`gdid-tool.ps1` directly**:

```cmd
.\tests\Run-AllChecks.cmd
```

This is non-mutating. It performs the following sequential checks:

1. Parses every packaged `.ps1`, `.psm1`, and `.psd1` file with Windows
   PowerShell 5.1.
2. Repeats the parse with PowerShell 7.
3. Rejects unsafe unbraced variable-plus-colon interpolation even apart from
   normal parser diagnostics.
4. Runs the package validator under both engines.
5. Verifies the manifest with a .NET SHA-256 helper that has no dependency on
   PowerShell module auto-loading, then checks the configuration schema,
   required implementation markers, prohibited mechanisms, and duplicate
   function names.
6. Runs `help`, `config`, and the read-only `status` command under both engines.
7. Writes one complete log to `tests\validation-results`.

No registry, service, HOSTS, policy, scheduled-task, or identity value is
changed by this validation command. PowerShell 7 must be installed because the
project claims support for both engines. A release should not be published when
either engine is missing from the release-validation environment.

## Checksum implementation

The package validator intentionally does not call the `Get-FileHash` cmdlet.
Some otherwise functional Windows PowerShell 5.1 installations cannot discover
that command because of module-path, module-registration, or auto-loading
problems. Manifest verification instead uses
`System.Security.Cryptography.SHA256` and `System.IO.File` directly, which are
available to both supported engines without importing a PowerShell module.

## Parser-only check

To collect all parser errors without running the main script:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\tests\Parse-AllPowerShell.ps1 -Root .

pwsh.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\tests\Parse-AllPowerShell.ps1 -Root .
```

## PSScriptAnalyzer

The package includes `PSScriptAnalyzerSettings.psd1`, with compatible-syntax
checks for PowerShell 5.1 and PowerShell 7. When PSScriptAnalyzer is installed,
the package validator runs it automatically.

```powershell
Install-Module PSScriptAnalyzer -Scope CurrentUser
Invoke-ScriptAnalyzer -Path . -Recurse `
  -Settings .\PSScriptAnalyzerSettings.psd1
```

The real PowerShell parser is the authoritative syntax gate. A hand-written
delimiter scanner, regex scan, or apparent line count must never be reported as
a successful PowerShell parse. PSScriptAnalyzer is an additional layer; it does
not replace execution under each supported engine.

## Release gate

The included GitHub Actions workflow runs the checks on Windows using both
Windows PowerShell and PowerShell 7. `build-exe.ps1` also refuses to build until
the dual-engine gate passes. Release archives and checksums should be generated
only after that Windows workflow succeeds.

## Live integration testing

Syntax and smoke tests cannot prove that Windows accepts every service, policy,
registry, Group Policy, Task Scheduler, or HOSTS operation on every build and
edition. Before deploying mutating commands, use a disposable VM snapshot and
follow:

- `tests/WPN_TEST_PLAN.md`
- `tests/TELEMETRY_TEST_PLAN.md`

Test at minimum on Windows 10 Pro, Windows 10 Enterprise, Windows 11 Pro,
Windows 11 Enterprise, and each supported Windows Server generation. Capture
both installation and exact uninstall restoration results.

## Reporting a failure once

Do not copy only the first error. Attach the newest file from
`tests\validation-results`; it contains results from both engines, every parser
diagnostic, the package validator, analyzer output when available, and all
read-only smoke tests. That gives a maintainer one complete defect set to fix in
a single revision.
