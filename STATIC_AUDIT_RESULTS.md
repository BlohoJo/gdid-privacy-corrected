# Static Audit Results

Audit date: **2026-07-28**

Target package: **GDID Privacy Tool 3.7.2-audited-telemetry**

## Regression fixed

The prior 3.7 package contained eight invalid expandable-string interpolations
where a plain variable was immediately followed by `:`. Windows PowerShell 5.1
and PowerShell 7 rejected the script before execution. All eight known
occurrences remain braced, and the package includes a dedicated regression
gate for that error class. Version 3.7.2 also replaces the checksum validator's
module-dependent file-hash command with a direct .NET SHA-256 implementation.

## Checks completed in this Linux analysis environment

| Check | Result |
|---|---|
| Main script lines | 5,506 |
| Main script functions (lexical count) | 119; no duplicates |
| Configuration JSON | Valid; exact schema-5 shipped defaults |
| Independent lexical delimiter/string/comment scan | Pass |
| Known variable-plus-colon patterns in executable strings | 0 found |
| C0 control characters | 0 |
| Malformed CRCRLF sequences | 0 |
| Trailing whitespace | 0 lines |
| Backtick continuation followed by whitespace | 0 |
| Required CDP/WPN/telemetry/policy markers | Present |
| Removed IP-firewall/AppInit/cache-restart constructs | Absent |
| Configuration/documentation consistency | Pass |
| Portable .NET SHA-256 validator; no file-hash cmdlet dependency | Present |
| Clean archive and SHA-256 manifest | Generated during packaging |

## Mandatory Windows validation not executable here

This environment does not contain Windows PowerShell 5.1, PowerShell 7, the
Windows registry, Service Control Manager, Task Scheduler, or Group Policy
engine. Therefore this report does **not** claim that PowerShell's real parser,
PSScriptAnalyzer, or Windows lifecycle tests passed here. The earlier 3.7 report
was wrong to let a custom lexical scan stand in for the parser gate.

On Windows, the first command after extraction must be:

```cmd
.\tests\Run-AllChecks.cmd
```

It runs the official parser under both supported engines, the package validator,
PSScriptAnalyzer when installed, and read-only `help`, `config`, and `status`
smoke tests. It emits one complete log under `tests\validation-results`. Do not
use a mutating command unless that check exits with code `0`.

Then follow both disposable-VM plans:

- `tests/WPN_TEST_PLAN.md`
- `tests/TELEMETRY_TEST_PLAN.md`
