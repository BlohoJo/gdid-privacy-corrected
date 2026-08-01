# Static Audit Results

Audit date: **2026-07-31**

Target package: **GDID Privacy Tool 3.8.1-audited-hosts**

## Regression history retained

The prior 3.7 package contained eight invalid expandable-string interpolations
where a plain variable was immediately followed by `:`. Windows PowerShell 5.1
and PowerShell 7 rejected the script before execution. All eight known
occurrences remain braced, and the package retains a dedicated regression gate
for that error class.

Version 3.7.2 replaced the validator's module-dependent file-hash command with a
direct .NET SHA-256 implementation. Version 3.7.3 added the repository
line-ending contract: ordinary text is exported as LF, while `.bat` and `.cmd`
launchers are declared `text eol=crlf` and exported as CRLF. The Windows CI
workflow now also validates a `git archive` ZIP so checkout and source-archive
bytes are both covered.

Version 3.8.0 adds the 16 research-derived HOSTS names as four independently
controlled groups, preserves schema-5 behavior during migration, adds a
validated extension list, rejects IP literals and non-hostname input, and
verifies the managed block as an exact IPv4/IPv6 set.


Version 3.8.1 corrects five validator regex literals that used double-quoted
PowerShell strings with `\$...`. Backslash is not PowerShell's escape character,
so the original 3.8.0 validator dereferenced an undefined `$config` variable
under StrictMode and would also have substituted `$true`/`$false` in four
neighboring patterns. All five are now single-quoted. The independent parser
worker rejects this error class before validator execution, and the validator also
checks its own AST as a second layer.

## Checks completed in this Linux analysis environment

| Check | Result |
|---|---|
| Main script lines | 5,845 |
| Main script functions (lexical count) | 123; no duplicates |
| PowerShell-family files | 6 |
| Configuration JSON | Valid; exact schema-6 shipped defaults |
| Built-in HOSTS groups | 5 DDS/CDP + 1 AAD/DDS + 4 Activity + 6 WNS/notify = 16 unique names |
| Fresh default built-in HOSTS set | 9 names; DDS/CDP and Activity enabled |
| Independent PowerShell lexical/token scan | Pass; no lexer error tokens |
| Independent delimiter scan outside strings/comments | Pass |
| Known variable-plus-colon patterns | 0 candidates |
| Custom-domain safeguards | Exact hostname validation, normalization, deduplication, and IP-literal rejection present |
| Exact-set HOSTS diagnostics | Missing, unexpected, duplicate, and malformed IPv4/IPv6 entries covered |
| Runtime DNS discovery for HOSTS list | Absent; configured exact names do not depend on current DNS resolution |
| C0 control characters | 0 |
| Malformed CRCRLF sequences | 0 |
| Trailing whitespace | 0 lines |
| Backtick continuation followed by whitespace | 0 |
| Required CDP/WPN/telemetry/policy markers | Present |
| Removed IP-firewall/AppInit/cache-restart constructs | Absent |
| Configuration/documentation consistency | Pass |
| Portable .NET SHA-256 validator; no file-hash cmdlet dependency | Present |
| Explicit LF/forced-CRLF `.gitattributes` policy and pre-checkout CI configuration | Present |
| Package payloads covered by manifest | 19 files, excluding `SHA256SUMS.txt` itself |
| Working-tree, clone, and `git archive` checksum verification | Performed during final packaging; see release notes |

## Mandatory Windows validation not executable here

This environment does not contain Windows PowerShell 5.1, PowerShell 7, the
Windows registry, Service Control Manager, Task Scheduler, or Group Policy
engine. Therefore this report does **not** claim that PowerShell's real parser,
PSScriptAnalyzer, or Windows lifecycle tests passed here. A custom lexical scan
is not a substitute for the actual PowerShell parser.

On Windows, the first command after extraction must be:

```cmd
.\tests\Run-AllChecks.cmd
```

It runs the official parser under both supported engines, the package validator,
PSScriptAnalyzer when installed, and read-only `help`, `config`, and `status`
smoke tests. It emits one complete log under `tests\validation-results`. Do not
use a mutating command unless that check exits with code `0`.

Then follow all three disposable-VM plans:

- `tests/HOSTS_TEST_PLAN.md`
- `tests/WPN_TEST_PLAN.md`
- `tests/TELEMETRY_TEST_PLAN.md`
