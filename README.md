# GDID Privacy Tool — Audited HOSTS/Telemetry/WPN Build 3.8.1

This package is a corrected and deliberately narrower revision of the original [**gdid-privacy**](https://github.com/someguy0110/gdid-privacy) project. It focuses on system changes that can be applied, verified, and restored locally.

It can:

- inspect the current user's known `LID` and `DeviceId` registry copies;
- disable and stop Connected Devices Platform (CDP) services before applying a local registry mask;
- optionally disable Windows Push Notification Services (`WpnService`, `WpnUserService`, and current `WpnUserService_*` instances);
- optionally disable Connected User Experiences and Telemetry (`DiagTrack`) and Device Management WAP Push (`dmwappushservice`);
- apply and report edition-aware Windows diagnostic-data policies;
- apply the policy equivalents of turning off optional diagnostic data, tailored experiences, and inking/typing diagnostic collection;
- optionally submit Windows' supported diagnostic-data deletion request;
- manage grouped exact-name HOSTS entries for DDS/CDP, Activity, WNS/notify, optional AAD/DDS, and validated user-supplied names;
- apply several other documented privacy/feature policies; and
- restore exact protected pre-tool values during `uninstall`.

It **cannot rotate or replace Microsoft's authoritative server-issued Device PUID or the DPAPI-protected DeviceTicket**. The `rotate` command is a local registry mask only. It also cannot prove that every Microsoft component, application, security product, or identity path has stopped transmitting data.

## Safety and scope warnings

The high-collateral controls are **off by default**:

```json
"blockWpn": false,
"blockTelemetry": false,
"requestDiagnosticDataDelete": false,
"blockWnsHosts": false,
"blockAADHost": false
```

`blockWpn=true` can disable cloud push notifications, local toast/tile/raw-notification workflows, Store-app background behavior, and WNS-triggered management operations.

`blockWnsHosts=true` blocks six exact WNS/notify names. Microsoft documents that loss of WNS connectivity can stop push notifications and affect MDM device management, mail synchronization, and settings synchronization. It is therefore separate from the lower-collateral DDS and Activity groups.

`blockAADHost=true` adds `aad.cs.dds.microsoft.com`. It remains a separate opt-in because the name is associated by the referenced reverse-engineering work with an authentication-related path.

`blockTelemetry=true` can break or degrade:

- Microsoft Intune and other MDM synchronization that depends on `dmwappushservice`;
- Endpoint Analytics and Windows Update for Business reporting;
- diagnostic troubleshooting and reliability reporting;
- features that depend on OneSettings configuration downloads; and
- other management workflows that expect `DiagTrack` to be available.

Stopping `DiagTrack` is **not** a guarantee that Microsoft Defender for Endpoint or every other Microsoft component stops transmitting its own security or diagnostic data. Do not enable these controls on a managed production machine without testing.

## Requirements

- Windows 10, Windows 11, or Windows Server 2016 and later
- Windows PowerShell 5.1 or PowerShell 7+
- Administrator rights for `install` and `uninstall`
- The same Windows account for `install`, `rotate`, `status`, and `uninstall`, because the identity values and several privacy policies are under that user's HKCU hive

The installing account should itself be a member of Administrators. Do not elevate a standard-user session by entering credentials for a different administrator account; doing so targets the administrator's HKCU rather than the standard user's hive.

## Quick start

### Validate the package before invoking the main script

The first command after extracting the package should be:

```cmd
.\tests\Run-AllChecks.cmd
```

This non-mutating gate parses every PowerShell file under **Windows PowerShell
5.1 and PowerShell 7**, runs the package/static checks, and smoke-tests `help`,
`config`, and read-only `status` under both engines. It writes one complete log
under `tests\validation-results`. Do not proceed to `install` unless the final
summary reports zero failures. See [`TESTING.md`](TESTING.md).

After validation passes, inspect without changing anything:

```powershell
.\gdid-tool.ps1 status
```

Apply the default audited hardening. On a fresh schema-6 configuration this includes five DDS/CDP names and four Activity names, but not the high-collateral WNS or AAD groups:

```powershell
.\gdid-tool.ps1 install
```

Enable all 16 names from the referenced `GDID-Disabler` list:

```powershell
.\gdid-tool.ps1 config blockHosts true
.\gdid-tool.ps1 config blockDDSHosts true
.\gdid-tool.ps1 config blockActivityHosts true
.\gdid-tool.ps1 config blockWnsHosts true
.\gdid-tool.ps1 config blockAADHost true
.\gdid-tool.ps1 install
```

Enable the WPN service block:

```powershell
.\gdid-tool.ps1 config blockWpn true
.\gdid-tool.ps1 install
```

Enable diagnostic-data policy/service hardening:

```powershell
.\gdid-tool.ps1 config blockTelemetry true
.\gdid-tool.ps1 install
```

Request one supported diagnostic-data deletion operation during the next install:

```powershell
.\gdid-tool.ps1 config blockTelemetry true
.\gdid-tool.ps1 config requestDiagnosticDataDelete true
.\gdid-tool.ps1 install
```

The deletion flag is one-shot. It resets to `false` only after Windows accepts the request. Acceptance means the request was submitted; it is not proof that Microsoft has completed server-side deletion.

Restore every managed value to the protected pre-tool baseline:

```powershell
.\gdid-tool.ps1 uninstall
```

## Commands

| Command | Purpose |
|---|---|
| `status` | Report identity copies, edition/build, diagnostic-data minimum, CDP/WPN/telemetry services, managed policies, Settings-equivalent controls, HOSTS entries, task state, rollback state, and limitations. |
| `rotate` | Replace safely backed current-user `LID`/`DeviceId` registry copies with a new local mask after CDP is verified disabled. This is not server-side rotation. |
| `install` | Capture or migrate a protected baseline, reconcile all configuration, run `gpupdate /force`, verify policy values, optionally request data deletion, manage services, apply a local mask, and reconcile the task/HOSTS block. |
| `uninstall` | Restore the protected identity, policy, service, HOSTS, and task baseline; run `gpupdate /force`; retain the backup if any verification fails. |
| `config` | Show all configuration. |
| `config <key>` | Show one setting. |
| `config <key> <value>` | Change one setting; run `install` afterward to reconcile actual state. |
| `help` | Show built-in help. |

## Configuration

The shipped `gdid-config.json` is:

```json
{
  "schemaVersion": 6,
  "rotationMode": "onDemand",
  "timedIntervalMin": 30,
  "blockCDP": true,
  "blockWpn": false,
  "blockTelemetry": false,
  "requestDiagnosticDataDelete": false,
  "blockHosts": true,
  "blockDDSHosts": true,
  "blockActivityHosts": true,
  "blockWnsHosts": false,
  "blockAADHost": false,
  "additionalHostDomains": [],
  "blockDO": false,
  "killPhoneLink": false,
  "killOneDrive": false,
  "killStore": false,
  "killTimeline": false,
  "hookMethod": "registry"
}
```

| Key | Default | Effect |
|---|---:|---|
| `rotationMode` | `onDemand` | `onDemand`, `perLogon`, or `timed`. Legacy `perBoot` is migrated to `perLogon` because the target values are in HKCU. |
| `timedIntervalMin` | `30` | Rotation interval from 15 through 1440 minutes in `timed` mode. |
| `blockCDP` | `true` | Disable `EnableCdp`, `CDPSvc`, the `CDPUserSvc` template, and current `CDPUserSvc_*` instances. Required for persistent local masking. |
| `blockWpn` | `false` | Disable/stop `WpnService`, the `WpnUserService` template, and current `WpnUserService_*` instances. High collateral. |
| `blockTelemetry` | `false` | Apply the diagnostic-data policy set below, run Group Policy refresh, and disable/stop `DiagTrack` and `dmwappushservice`. High collateral. |
| `requestDiagnosticDataDelete` | `false` | One-shot request through `Clear-WindowsDiagnosticData -Force`; requires `blockTelemetry=true`. |
| `blockHosts` | `true` | Master switch for every managed HOSTS group and `additionalHostDomains`. When false, the tool removes its marked block. |
| `blockDDSHosts` | `true` | Add five DDS/CDP exact names, excluding the separately controlled AAD name. |
| `blockActivityHosts` | `true` | Add four Activity/Project Rome exact names. |
| `blockWnsHosts` | `false` | Add six WNS/notify exact names. High collateral: push, MDM notifications, mail sync, and settings sync can fail. |
| `blockAADHost` | `false` | Add `aad.cs.dds.microsoft.com`; may affect Microsoft-account or AAD-related functionality. |
| `additionalHostDomains` | `[]` | Optional validated exact FQDNs for newly discovered names. URLs, wildcards, IP literals, comments, and paths are rejected. |
| `blockDO` | `false` | Set `DODownloadMode=99`; does not disable `DoSvc` and is not GDID rotation. |
| `killPhoneLink` | `false` | Set `EnableMmx=0`. |
| `killOneDrive` | `false` | Set `DisableFileSyncNGSC=1`. |
| `killStore` | `false` | Set `AutoDownload=2`. |
| `killTimeline` | `false` | Set all three Activity History policies to `0`. |
| `hookMethod` | `registry` | `registry` or `none`. The original AppInit/API-hook mode is unsupported and rejected. |

Boolean values are parsed strictly. Strings such as `false`, `0`, `no`, and `off` become false; malformed values and unknown JSON keys are rejected rather than silently accepted.

`additionalHostDomains` is stored as a JSON array. The command interface accepts a comma-, semicolon-, or newline-separated list and normalizes it to lowercase exact names:

```powershell
.\gdid-tool.ps1 config additionalHostDomains "new.example.microsoft.com, second.example.microsoft.com"
.\gdid-tool.ps1 install

# Clear the custom list:
.\gdid-tool.ps1 config additionalHostDomains ""
.\gdid-tool.ps1 install
```

When a schema-5-or-earlier configuration is retained during an upgrade, the loader preserves the old behavior: `blockHosts` continues to control the Activity group, any existing `blockAADHost` choice is retained, and the new DDS and WNS group switches remain off until explicitly configured. A newly shipped schema-6 configuration uses the defaults shown above.

# Diagnostic-data implementation

## Edition-aware `AllowTelemetry`

The stable registry value is:

```text
HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection
    AllowTelemetry  REG_DWORD
```

Microsoft has changed the visible ADMX wording over time. It may appear as **Allow Telemetry** on older Windows/ADMX releases and as **Allow Diagnostic Data** on newer releases. The script reports the expected label and always manages the same registry value.

The script selects the lowest value Microsoft documents as supported by the detected edition:

| Edition family | Value | Reported level |
|---|---:|---|
| Windows 10/11 Enterprise | `0` | Diagnostic data off |
| Windows 10/11 Education | `0` | Diagnostic data off |
| Windows IoT Enterprise | `0` | Diagnostic data off |
| Windows Server 2016+ | `0` | Diagnostic data off |
| Windows 10/11 Pro | `1` | Required diagnostic data |
| Other/unknown client editions | `1` | Conservative supported minimum |

Writing `AllowTelemetry=0` on Pro does not produce a real “off” state; Windows treats it as `1`. This build therefore writes `1` on Pro and reports that fact instead of displaying a placebo `0`.

## Managed telemetry policy values

When `blockTelemetry=true`, the script applies each applicable value and verifies it again after `gpupdate /force`:

```text
HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection
```

| Registry value | Desired value | Meaning in this build |
|---|---:|---|
| `AllowTelemetry` | `0` or `1` | Edition-aware minimum described above. |
| `AllowDeviceNameInTelemetry` | `0` | Do not include the device name in Windows diagnostic data. |
| `DisableEnterpriseAuthProxy` | `1` | Prevent `DiagTrack` from automatically using an authenticated proxy. This changes proxy behavior; it does not by itself reduce collection volume. |
| `DisableOneSettingsDownloads` | `1` | Prevent Windows from connecting to OneSettings for dynamic configuration downloads. |
| `DoNotShowFeedbackNotifications` | `1` | Suppress Windows feedback prompts. This does not itself disable diagnostic collection. |
| `LimitDiagnosticLogCollection` | `1` | Prevent additional diagnostic-log collection when optional diagnostic data is enabled; defense-in-depth at level `0`/`1`. |
| `LimitEnhancedDiagnosticDataWindowsAnalytics` | `0` | Disable the Desktop/Windows Analytics exception. |
| `DisableDeviceDelete` | `0` | Keep the Settings Delete button and supported deletion path available. |
| `DisableTelemetryOptInSettingsUx` | `1` | Disable the optional-diagnostic-data opt-in controls in client Settings. |

### Important correction: `LimitEnhancedDiagnosticDataWindowsAnalytics`

The requested phrase **Disable Windows Analytics collection** maps to value `0`, not `1`.

```text
LimitEnhancedDiagnosticDataWindowsAnalytics = 0   # Disabled
LimitEnhancedDiagnosticDataWindowsAnalytics = 1   # Enabled exception
```

Value `1` enables the Desktop/Windows Analytics minimum-data exception when optional diagnostic data is selected. Setting it to `1` would contradict the requested disabled state. The script therefore writes `0`, reports the reason, and tests for `0`.

## Settings-equivalent controls

When `blockTelemetry=true`, the script also applies and reports the policy equivalents of the requested Settings changes.

### Send optional diagnostic data

Controlled by:

```text
HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\AllowTelemetry
HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection\DisableTelemetryOptInSettingsUx
```

The first forces the edition minimum; the second locks the Settings opt-in UI where applicable.

### Tailored experiences

```text
HKCU\SOFTWARE\Policies\Microsoft\Windows\CloudContent
    DisableTailoredExperiencesWithDiagnosticData = 1
```

### Improve inking and typing

The build applies both the documented machine policy and current-user restrictions:

```text
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput
    AllowLinguisticDataCollection = 0

HKCU\SOFTWARE\Microsoft\InputPersonalization
    RestrictImplicitTextCollection = 1
    RestrictImplicitInkCollection  = 1
```

### Delete diagnostic data

The build keeps deletion available with:

```text
HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection
    DisableDeviceDelete = 0
```

A one-shot command request can then be enabled:

```powershell
.\gdid-tool.ps1 config blockTelemetry true
.\gdid-tool.ps1 config requestDiagnosticDataDelete true
.\gdid-tool.ps1 install
```

The script first applies and verifies the policies, then calls:

```powershell
Clear-WindowsDiagnosticData -Force
```

It tries the current PowerShell host and then the inbox Windows PowerShell 5.1 host. The request occurs **before** `DiagTrack` and `dmwappushservice` are stopped. The result is recorded in runtime status. On Windows clients, this workflow requires Windows 10 version 1809/build 17763 or newer.

The request may be unavailable or ineffective when Windows diagnostic-data processor configuration is enabled; in that case deletion may need to be performed through the organization's administrative portal. The tool never reports server-side completion merely because the cmdlet returned successfully.

## Group Policy refresh and verification

After policy reconciliation, `install` and `uninstall` run:

```text
gpupdate.exe /force /wait:300
```

The process has a 330-second safety timeout. Nonzero exit status is treated as failure. Every non-CDP managed policy is then re-read: enabled/applicable options must match their desired value, while disabled or inapplicable options must match the protected baseline. If local, domain, or MDM policy overwrites a value, installation fails instead of reporting success. CDP policy is verified with the CDP service/template block later in the same transaction.

The script writes policy registry values; it does not edit `Registry.pol`. Therefore Local Group Policy Editor may continue to show **Not Configured** even while the policy registry value is active. `status` reports the actual registry value and whether it matches the requested control.

# Diagnostic-data service control

When `blockTelemetry=true`, the script manages:

```text
Connected User Experiences and Telemetry      DiagTrack
Device Management WAP Push message Routing    dmwappushservice
```

For each installed service it:

1. captures the exact original `Start` and `DelayedAutoStart` values in protected state;
2. records whether the service was running;
3. sets the service startup type to Disabled;
4. enforces `Start=4` directly on the existing service key;
5. stops the service;
6. re-reads live service and registry state; and
7. fails if any present service is still running or not disabled.

Turning `blockTelemetry` back off and running `install`, or running `uninstall`, restores the exact saved values. A service that was running at the original baseline is restarted when possible. Any failed restoration retains the protected backup for retry.

`dmwappushservice` is important for Intune/MDM synchronization. `DiagTrack` is used by Endpoint Analytics and Windows Update for Business reporting. These services must not be disabled on systems that depend on those functions.

# Windows Push Notification control

When `blockWpn=true`, the script manages:

- `WpnService`;
- the `WpnUserService` per-user service template; and
- all current `WpnUserService_*` instances.

It backs up:

```text
HKLM\SYSTEM\CurrentControlSet\Services\WpnService\Start
HKLM\SYSTEM\CurrentControlSet\Services\WpnService\DelayedAutoStart
HKLM\SYSTEM\CurrentControlSet\Services\WpnUserService\Start
HKLM\SYSTEM\CurrentControlSet\Services\WpnUserService\UserServiceFlags
HKLM\SYSTEM\CurrentControlSet\Services\WpnUserService_*\Start
```

It disables the system service, sets the per-user template to `Start=4` and `UserServiceFlags=0`, disables current suffixed instances, stops them, and verifies the result. Restoration handles suffixes that disappeared or were created after the original snapshot without recreating stale per-user service keys.

# CDP and local identity masking

`blockCDP=true` disables:

- `EnableCdp` policy;
- `CDPSvc`;
- the `CDPUserSvc` template; and
- current `CDPUserSvc_*` instances.

Only after these are verified disabled and stopped does the script replace existing current-user `LID`/`DeviceId` registry copies. It refuses to mask when:

- no protected install state exists;
- installation is incomplete;
- CDP is active;
- a current identity target lacks a protected backup; or
- a current value differs from both the protected original and the last mask recorded by the tool.

The write is transactional and verified. It remains a **local mask**, not a Device PUID or DeviceTicket change.

# Reversible protected state

The current protected-state schema is `6`. State is stored per user under:

```text
%ProgramData%\GDIDPrivacy\<user-SID>\state.json
```

The directory/file ACL is restricted so Administrators and SYSTEM can write while the intended user can read. Every state object and restoration target is validated against compiled descriptors before use. Paths read from JSON are never accepted as arbitrary write targets.

The state includes:

- original identity values;
- every managed policy value and whether its key/value existed;
- CDP/WPN/telemetry service `Start`, `DelayedAutoStart`, and template flags;
- current CDP/WPN per-user instance startup values; and
- which managed services were running.

Schemas `3`, `4`, and `5` from earlier audited builds are migrated before telemetry changes. Newly managed telemetry targets are captured before modification. The state file is deleted only after verified restoration.

# Status output

`status` separately reports:

- local identity copies;
- Windows product, edition, build, and supported diagnostic-data minimum;
- live CDP state;
- live WPN state;
- live `DiagTrack` and `dmwappushservice` state;
- every managed policy's requested, applicable, desired, actual, active, and reconciled status;
- Settings-equivalent summaries for optional diagnostic data, UI lock, tailored experiences, inking/typing, and data deletion;
- the most recent deletion request result;
- HOSTS entries;
- scheduled-task state;
- protected state/ACL/schema; and
- an honest limitation assessment.

A configured option is never treated as proof of successful application. Live values are checked.

# Scheduled task security

Automatic local masking uses a non-elevated current-user scheduled task. This avoids the original project's elevated task executing a user-writable script. The task is created only when:

- `blockCDP=true`;
- `hookMethod=registry`; and
- `rotationMode` is `perLogon` or `timed`.

Mutating commands are serialized with an exclusive per-user file lock that works across Windows sessions.

# HOSTS behavior

The script writes a marked block containing both `0.0.0.0` and `::` entries. It preserves the detected file encoding, replaces or removes only its marker-delimited records, verifies that the managed block contains the **exact requested set** with no missing, unexpected, duplicate, or malformed entries, restores a temporary backup on failure, rejects malformed/duplicate markers, and flushes the DNS cache. Unrelated records remain intact, although separator/trailing newlines around the managed block can be normalized.

The built-in groups are:

| Group/configuration | Exact names | Default |
|---|---|---:|
| `blockDDSHosts` | `dds.microsoft.com`, `fd.dds.microsoft.com`, `cs.dds.microsoft.com`, `continuum.dds.microsoft.com`, `cdpcs.access.microsoft.com` | `true` |
| `blockActivityHosts` | `activity.windows.com`, `activity.microsoft.com`, `assets.activity.windows.com`, `ppe.activity.windows.com` | `true` |
| `blockWnsHosts` | `client.wns.windows.com`, `global.notify.windows.com`, `sinnc-df.notify.windows.com`, `bn2-df.notify.windows.com`, `bn3p.notify.windows.com`, `db3p.notify.windows.com` | `false` |
| `blockAADHost` | `aad.cs.dds.microsoft.com` | `false` |
| `additionalHostDomains` | User-supplied validated exact FQDNs | empty |

The names are written whether or not they resolve at installation time. A current NXDOMAIN response is not treated as evidence that a name is permanently unused; conversely, a HOSTS entry does not prove that Windows currently contacts that name. No DNS lookup is needed to install an exact-name block.

HOSTS blocking remains exact-name and best effort. It cannot block an unlisted alias, wildcard family, direct IP connection, application-controlled DNS/DoH path, or another transport that bypasses the normal Windows resolver. The research-derived list is not represented as endpoint-complete.

# Validation and test plans

Run the complete non-mutating, dual-engine gate first:

```cmd
.\tests\Run-AllChecks.cmd
```

The gate invokes PowerShell's real parser for every `.ps1`, `.psm1`, and `.psd1`
file under both Windows PowerShell 5.1 and PowerShell 7. It also contains a
regression check for ambiguous expandable-string interpolation, verifies the
SHA-256 manifest and package contract through a .NET SHA-256 implementation
that does not depend on module auto-loading, optionally runs PSScriptAnalyzer
when installed, and collects all results in one log. The repository also ships a
`.gitattributes` policy that normalizes ordinary text to LF and declares the
`.bat` and `.cmd` launchers as `text eol=crlf`. Git stores normalized text in the
repository/index and writes or exports the Command Prompt launchers with CRLF,
so byte-for-byte checksums remain consistent across Windows and Linux checkouts,
GitHub source archives, and GitHub Actions. CI also builds a `git archive` ZIP
and validates its exported bytes. See [`TESTING.md`](TESTING.md).

Then use disposable VM snapshots and follow:

- [`tests/HOSTS_TEST_PLAN.md`](tests/HOSTS_TEST_PLAN.md)
- [`tests/WPN_TEST_PLAN.md`](tests/WPN_TEST_PLAN.md)
- [`tests/TELEMETRY_TEST_PLAN.md`](tests/TELEMETRY_TEST_PLAN.md)

The package's static audit is recorded in [`STATIC_AUDIT_RESULTS.md`](STATIC_AUDIT_RESULTS.md). A release is not syntax-validated until the dual-engine parser gate succeeds on Windows. Static analysis and read-only smoke tests do not replace a live Windows lifecycle test.

# What this build does not claim

It does not claim to:

- rotate an arbitrary or server-issued Device PUID;
- rewrite or forge a valid DeviceTicket;
- erase Microsoft's server-side identity history;
- make old and new identifiers unlinkable;
- block every WNS-adjacent, Microsoft identity, telemetry, Store, Defender, WAM, browser, application, or update path;
- provide safe system-wide API registry spoofing; or
- make Windows fully functional while guaranteeing zero Microsoft egress.

See [`AUDIT_REPORT.md`](AUDIT_REPORT.md) and [`REMOVED_FEATURES.md`](REMOVED_FEATURES.md).

# Build helper and launcher

`gdid-tool.bat` elevates only `install` and `uninstall`; other commands run normally.

`build-exe.ps1` first requires the dual-engine validation gate to pass, then creates a visible-console wrapper through `ps2exe`. The EXE is not marked always-elevated. Keep `gdid-config.json` beside it.

# References

Primary Microsoft documentation used for this build includes:

- Configure Windows diagnostic data in your organization
- Policy CSP — System
- Windows Privacy Compliance Guide
- Windows per-user services guidance
- Windows Push Notification Services overview
- Windows service guidance and Intune/Endpoint Analytics requirements
- `Clear-WindowsDiagnosticData` cmdlet documentation

The reverse-engineering claims that motivated the additional service controls come from [`SmtimesIWndr/We-running-GDID-back`](https://github.com/SmtimesIWndr/We-running-GDID-back). The grouped HOSTS names come from [`SmtimesIWndr/GDID-Disabler`](https://github.com/SmtimesIWndr/GDID-Disabler). Those observations and endpoint classifications are independent research, not Microsoft documentation. This build uses documented Windows controls where available and labels its remaining limits explicitly.
