# Audit Report — GDID Privacy Tool 3.7.3, Telemetry/WPN Build

## Scope

This report covers the supplied `gdid-tool.ps1`, its original `README.md`, Issue #12, the complete archive, and the successive audited corrections through tool version `3.7.3-audited-telemetry`.

The current build is intentionally narrower than the original project. It provides reversible local Windows hardening and truthful reporting. It does **not** represent local registry masking as rotation of Microsoft's authoritative Device PUID.

## Executive verdict

The original project did not fully work as advertised. Its former IP-firewall path contained implementation defects and was structurally ineffective against rapidly changing shared addresses. Its `rotate` operation changed local registry copies, not the authoritative DeviceTicket/PUID, and the original value could be restored when CDP ran. Its elevated task design also created an avoidable privilege boundary problem.

The audited build removes or rejects those unsupported mechanisms and adds verified, reversible controls for:

- CDP (`CDPSvc`, `CDPUserSvc`, and current instances);
- Windows Push Notification services (`WpnService`, `WpnUserService`, and current instances);
- Connected User Experiences and Telemetry (`DiagTrack`);
- Device Management WAP Push (`dmwappushservice`);
- edition-aware Windows diagnostic-data policies;
- selected Settings-equivalent privacy policies;
- a one-shot supported diagnostic-data deletion request;
- selected feature policies and exact-name HOSTS entries; and
- local masking of existing current-user identifier registry copies only after CDP is verified disabled.

These controls reduce selected local reporting paths. They do not prove that every Microsoft component or application has stopped communicating, and they do not alter Microsoft's server-side identity record.

## Issue #12 disposition

| Issue | Current disposition |
|---|---|
| Single-address `AddRange()` failure | Removed with the entire IP-firewall feature. |
| Comma-joined `RemoteAddress` | Removed with the entire IP-firewall feature. |
| Failed firewall creation reported as success | Removed with the entire IP-firewall feature. |
| Sinkholed results turned into firewall rules | Removed with the entire IP-firewall feature. |
| Dead/inappropriate domain list | Removed from IP-firewall logic; HOSTS entries are explicit and narrowly scoped. |
| IP rules ineffective against short TTLs | Fixed by removing the feature rather than retaining false protection. |
| CDP restores locally spoofed value | Addressed operationally: masking is refused unless CDP is disabled and stopped. This still does not change the authoritative ticket. |
| DeviceTicket retains the real PUID | Not claimed as fixed; the build documents this design limit. |
| Uninstall did not restore original identity | Fixed with validated, protected, conflict-aware snapshots and verified restoration. |
| Elevated task from a user-writable path | Fixed by using a non-elevated current-user task and cross-session mutation locking. |

## Diagnostic-data additions

### Edition-aware minimum

The stable policy value is `HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry` even where the UI/ADMX label is now **Allow Diagnostic Data**.

The build chooses the lowest value documented as effective for the detected edition:

- Enterprise, Education, IoT Enterprise, and Windows Server: `0` (Diagnostic data off);
- Pro and other/unknown client editions: `1` (Required diagnostic data).

It deliberately does not write a placebo value `0` on Pro, where Windows treats it as `1`.

### Policies managed by `blockTelemetry`

The exact pre-tool existence, type, and value of every policy are saved before the first change. Policies are reconciled, `gpupdate.exe /force /wait:300` is run, and every non-CDP managed value is re-read. Enabled/applicable options must match their desired state; disabled or inapplicable options must match the protected baseline. Installation fails if local, domain, MDM, or another authority overwrites either state. CDP policy is verified with the CDP block later in the transaction.

Managed controls include:

- `AllowTelemetry` — edition-aware minimum;
- `AllowDeviceNameInTelemetry=0`;
- `DisableEnterpriseAuthProxy=1`;
- `DisableOneSettingsDownloads=1`;
- `DoNotShowFeedbackNotifications=1`;
- `LimitDiagnosticLogCollection=1`;
- `LimitEnhancedDiagnosticDataWindowsAnalytics=0`;
- `DisableDeviceDelete=0`;
- `DisableTelemetryOptInSettingsUx=1` on applicable clients;
- `DisableTailoredExperiencesWithDiagnosticData=1` for the current user;
- `AllowLinguisticDataCollection=0`; and
- current-user implicit text/ink restrictions.

#### Correction to the requested Windows Analytics value

`LimitEnhancedDiagnosticDataWindowsAnalytics=1` **enables** the Desktop/Windows Analytics exception. The requested Group Policy selection **Disable Windows Analytics collection** maps to `0`. The audited build uses `0`; using `1` would contradict the requested policy state.

#### `DisableEnterpriseAuthProxy` is not a collection block

That value only prevents `DiagTrack` from automatically using an authenticated proxy. It can change routing behavior and should not be interpreted as reducing the diagnostic-data level. The status and documentation label it accordingly.

### Services

When `blockTelemetry=true`, the build backs up, disables, stops, and verifies:

- `DiagTrack`; and
- `dmwappushservice`.

It stores original `Start`, `DelayedAutoStart`, and running state. Disabling `dmwappushservice` can break Intune/MDM synchronization. Disabling `DiagTrack` can break Endpoint Analytics, Windows Update for Business reporting, and other diagnostics-dependent workflows. The setting is therefore opt-in.

### Settings-equivalent controls

The build applies policy equivalents for:

- optional diagnostic data at the edition minimum;
- locking the optional-data opt-in UI where supported;
- tailored experiences off; and
- inking/typing diagnostic collection off.

These are policy controls, not simulated mouse clicks. Local Group Policy Editor can still display **Not Configured** because the build writes and verifies the policy registry values rather than modifying `Registry.pol`.

### Diagnostic-data deletion

`requestDiagnosticDataDelete=true` is a one-shot option and requires `blockTelemetry=true`. The build applies/verifies policies first, submits `Clear-WindowsDiagnosticData -Force` before stopping telemetry services, records the result, and clears the option only after the local command succeeds.

A successful command means Windows accepted a deletion request. It does not prove completion of server-side deletion. On processor-configured organizational devices, deletion may instead require the organization's administrative workflow.

## WPN additions

`blockWpn=true` manages:

- `WpnService`;
- the `WpnUserService` template; and
- every current `WpnUserService_*` instance.

The build saves exact static and instance startup values, records running state, sets `Start=4`, sets template `UserServiceFlags=0`, stops all managed services, and verifies the result. Restoration handles suffix changes without recreating stale per-user service keys.

The feature is opt-in because it can break push notifications, toast/tile/raw-notification workflows, Store-app background behavior, and WNS-triggered management operations.

## Reversibility and protected state

Protected state schema `6` is stored per user under `%ProgramData%\GDIDPrivacy\<SID>\state.json`. The object is validated before use, all restoration destinations are matched against compiled descriptors, and the ACL is restricted to Administrators/SYSTEM for writes with the intended user receiving read access.

The state includes:

- identity copies;
- all managed policy values;
- CDP, WPN, and telemetry service values;
- CDP/WPN per-user instance values;
- pre-change running state; and
- baseline-sealing metadata.

Schemas `3`, `4`, and `5` migrate to `6` without treating values previously written by an installed older build as originals. The backup is retained whenever restoration or verification fails.

## Parser-gate correction in 3.7.1

The initial 3.7 telemetry package was incorrectly described as statically
validated even though the non-Windows analysis environment could not execute
PowerShell's parser. A custom delimiter/string scan missed eight expandable-string
expressions in which a plain variable was immediately followed by a colon. Both
Windows PowerShell 5.1 and PowerShell 7 reject that form. This was a release-gate
failure, not a target-machine problem.

Version 3.7.1 braces all eight variables and adds a parser-first gate under both
engines, a dedicated interpolation regression rule, PSScriptAnalyzer 5.1/7
compatibility settings, one-log smoke testing, and a Windows CI workflow. This
environment still cannot execute that Windows gate, so the package is a corrected
candidate and must pass `tests\Run-AllChecks.cmd` before mutating commands are
used.


## Checksum-gate correction in 3.7.2

A target-machine run of the 3.7.1 validation gate passed both real PowerShell
parsers, both main-script smoke-test sets, and the complete PowerShell 7 package
validator. Windows PowerShell 5.1 failed only when the validator attempted to
call the `Get-FileHash` cmdlet. The same manifest verified successfully under
PowerShell 7, so the payload checksums themselves were not the defect.

Version 3.7.2 removes that cmdlet dependency. The validator now opens each file
read-only and computes SHA-256 through
`System.Security.Cryptography.SHA256`. It also inspects its own AST and fails if
a future revision removes the portable helper or reintroduces the external
file-hash cmdlet. This makes checksum verification independent of
`Microsoft.PowerShell.Utility` discovery and command auto-loading.

## GitHub checkout line-ending correction in 3.7.3

The release manifest hashes exact file bytes. Most project files are stored with
LF endings, while the `.bat` and `.cmd` launchers intentionally use CRLF. A
Windows GitHub-hosted runner can have `core.autocrlf=true`; without an explicit
repository policy, checkout rewrites LF payloads to CRLF before the validator
runs, causing widespread checksum failures even though GitHub's source archive
matches the manifest.

Version 3.7.3 adds `.gitattributes` rules that enforce LF for ordinary text and
preserve the batch launchers as exact CRLF files. The workflow also sets
`core.autocrlf=false` before `actions/checkout` and reports
`git ls-files --eol`. The validator requires the line-ending policy and includes
`.gitattributes` in the manifest coverage contract.

## Additional defects corrected during the audit

- strict Boolean conversion, so the string `false` cannot become true;
- unknown configuration keys fail closed;
- legacy configuration migration is explicit;
- stale tasks are removed when automatic rotation is disabled;
- current-user scheduled tasks are non-elevated;
- mutating operations use an exclusive cross-session lock;
- local identity writes and restoration are transactional and conflict-aware;
- state and runtime JSON writes are atomic;
- service state is checked live rather than inferred from configuration;
- HOSTS edits preserve encoding, use exact markers, include IPv4/IPv6, verify, and roll back on failure;
- compiled-EXE and script path resolution are handled separately; and
- unsupported API/AppInit hook mode is rejected rather than advertised.

## Effectiveness matrix

| Capability | Result |
|---|---|
| Disable/stop named CDP services and current instances | Effective when live verification succeeds. |
| Persist local registry masking against CDP reversion | Effective while CDP remains disabled; still local-only. |
| Disable/stop named WPN services and current instances | Effective when live verification succeeds; high collateral. |
| Apply edition-aware diagnostic policy minimum | Effective for local registry policy when not overridden by a higher authority. |
| Disable/stop `DiagTrack` and `dmwappushservice` | Effective when live verification succeeds; management collateral applies. |
| Turn off tailored experiences and inking/typing collection by policy | Effective for the managed user/device scope where the policies are supported. |
| Request deletion of uploaded Windows diagnostic data | Can submit the supported request; cannot prove server completion. |
| Rotate Microsoft-issued Device PUID | Not implemented or claimed. |
| Rewrite/forge a valid DeviceTicket | Not implemented or claimed. |
| Guarantee no identifier or telemetry is ever transmitted | Not possible while permitting unrestricted network egress; not claimed. |
| Block all Microsoft telemetry/apps | Not implemented or claimed. |

## Static verification performed in this environment

The package was checked in this environment for:

- valid JSON configuration;
- balanced lexical delimiters and terminated strings/comments;
- absence of all eight known ambiguous variable-plus-colon interpolations;
- duplicate function names;
- required telemetry/WPN/CDP implementation markers;
- required version/schema markers;
- prohibited legacy firewall/AppInit/cache-restart constructs;
- control characters and trailing whitespace;
- documentation/config consistency;
- clean archive contents; and
- SHA-256 checksums.

The exact output is in `STATIC_AUDIT_RESULTS.md`.

## Testing limitation

This analysis environment is not Windows and has no Windows registry, Service Control Manager, Task Scheduler, Group Policy engine, Windows PowerShell 5.1, or PowerShell 7 runtime. No live service/policy mutation or real PowerShell parser execution was performed here. The packaged dual-engine gate uses PowerShell's official parser without executing mutating commands, and the WPN/telemetry test plans specify disposable-VM lifecycle tests.

A build should not be accepted for production—or described as parser-validated—until `tests\Run-AllChecks.cmd` exits successfully on Windows. It should not be accepted solely because static checks pass. At minimum, test install, status, reboot/sign-in, disable/reconcile, and uninstall on each target Windows edition—especially Windows 10 Pro, Windows 10 Enterprise, Windows 11 Pro, Windows 11 Enterprise, and the intended Server release.
