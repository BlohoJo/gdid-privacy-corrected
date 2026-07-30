# Diagnostic-Data / Telemetry Windows VM Test Plan

Use disposable Windows virtual-machine snapshots. Do not begin on a managed production device. Disabling `dmwappushservice` can stop Intune/MDM synchronization, and disabling `DiagTrack` can affect Endpoint Analytics, Windows Update for Business reporting, diagnostics, and other management workflows.

## Test matrix

Exercise at least:

- Windows 10 Pro 22H2;
- Windows 10 Enterprise 22H2;
- Windows 11 Pro (current supported release);
- Windows 11 Enterprise (current supported release); and
- each intended Windows Server release.

Use a non-domain, non-MDM baseline first. Repeat policy-conflict tests on a domain/MDM test machine only where safe.

## 1. Static validation

From the package root:

```powershell
.\tests\Run-AllChecks.cmd
```

Expected: exit code `0` and no AST/static failures.

## 2. Capture a baseline

In elevated Windows PowerShell, capture:

```powershell
$root = Join-Path $env:TEMP 'gdid-telemetry-baseline'
New-Item -ItemType Directory -Path $root -Force | Out-Null

Get-CimInstance Win32_OperatingSystem |
  Select-Object Caption, Version, BuildNumber, OperatingSystemSKU |
  ConvertTo-Json | Set-Content (Join-Path $root 'os.json') -Encoding UTF8

Get-Service DiagTrack,dmwappushservice -ErrorAction SilentlyContinue |
  Select-Object Name,Status,StartType |
  ConvertTo-Json | Set-Content (Join-Path $root 'services.json') -Encoding UTF8

$paths = @(
 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection',
 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput',
 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent',
 'HKCU:\SOFTWARE\Microsoft\InputPersonalization',
 'HKLM:\SYSTEM\CurrentControlSet\Services\DiagTrack',
 'HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice'
)
foreach ($p in $paths) {
  if (Test-Path $p) {
    Get-ItemProperty $p | Export-Clixml (Join-Path $root ((($p -replace '[:\\]','_') + '.xml')))
  }
}
```

Save `./gdid-tool.ps1 status` output.

## 3. Verify the default is non-mutating

```powershell
.\gdid-tool.ps1 config blockTelemetry
.\gdid-tool.ps1 config requestDiagnosticDataDelete
.\gdid-tool.ps1 install
.\gdid-tool.ps1 status
```

Expected defaults are `False`. Telemetry policies and `DiagTrack`/`dmwappushservice` must match the protected baseline after installation.

## 4. Enable telemetry hardening

```powershell
.\gdid-tool.ps1 config blockTelemetry true
.\gdid-tool.ps1 install
.\gdid-tool.ps1 status
```

Verify service state:

```powershell
foreach ($name in 'DiagTrack','dmwappushservice') {
  $svc = Get-Service $name -ErrorAction SilentlyContinue
  $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
  if ($svc -or (Test-Path $key)) {
    $start = (Get-ItemProperty $key -Name Start -ErrorAction Stop).Start
    if ($start -ne 4) { throw "$name Start=$start, expected 4" }
    if ($svc -and $svc.Status -ne 'Stopped') { throw "$name is $($svc.Status)" }
  }
}
```

Verify policy values. On Pro, `AllowTelemetry` must be `1`; on Enterprise/Education/IoT Enterprise/Server it must be `0`:

```powershell
$dc = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'
Get-ItemProperty $dc | Select-Object AllowTelemetry,AllowDeviceNameInTelemetry,
 DisableEnterpriseAuthProxy,DisableOneSettingsDownloads,
 DoNotShowFeedbackNotifications,LimitDiagnosticLogCollection,
 LimitEnhancedDiagnosticDataWindowsAnalytics,DisableDeviceDelete,
 DisableTelemetryOptInSettingsUx | Format-List
```

Expected applicable values:

```text
AllowTelemetry                              0 or 1 by edition
AllowDeviceNameInTelemetry                  0
DisableEnterpriseAuthProxy                  1
DisableOneSettingsDownloads                 1
DoNotShowFeedbackNotifications              1
LimitDiagnosticLogCollection                1
LimitEnhancedDiagnosticDataWindowsAnalytics 0
DisableDeviceDelete                         0
DisableTelemetryOptInSettingsUx              1 (applicable clients)
```

Also verify:

```powershell
(Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput').AllowLinguisticDataCollection
(Get-ItemProperty 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent').DisableTailoredExperiencesWithDiagnosticData
(Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\InputPersonalization').RestrictImplicitTextCollection
(Get-ItemProperty 'HKCU:\SOFTWARE\Microsoft\InputPersonalization').RestrictImplicitInkCollection
```

Expected: `0`, `1`, `1`, `1` respectively.

Run `gpupdate /force` independently, then run `status` again. No requested value may silently revert.

## 5. Inspect Settings equivalents

On Windows client:

- Windows 11: Settings > Privacy & security > Diagnostics & feedback.
- Windows 10: Settings > Privacy > Diagnostics & feedback.

Confirm optional diagnostic data is off/locked at the edition minimum, tailored experiences are off, improve inking and typing is off, and Delete diagnostic data remains available where supported. UI wording and availability can vary by build and organizational policy; the registry/policy status is authoritative for this test.

## 6. Exercise one-shot deletion

Take a snapshot first, then:

```powershell
.\gdid-tool.ps1 config blockTelemetry true
.\gdid-tool.ps1 config requestDiagnosticDataDelete true
.\gdid-tool.ps1 install
.\gdid-tool.ps1 status
.\gdid-tool.ps1 config requestDiagnosticDataDelete
```

Expected:

- the request is submitted before the services are stopped;
- status records time, accepted/failure state, and message;
- the flag resets to `False` only after the local command succeeds;
- failure leaves it `True` for retry; and
- no output claims that server-side deletion is complete.

On a processor-configured enterprise device, verify that the tool reports failure/limitation rather than fabricating success if local deletion is unavailable.

## 7. Reboot/sign-in persistence

Reboot, sign in as the same user, and run elevated `status`. Verify policies remain reconciled and present services remain disabled/stopped. Record any Windows feature or management regressions.

## 8. Restore without full uninstall

```powershell
.\gdid-tool.ps1 config blockTelemetry false
.\gdid-tool.ps1 install
.\gdid-tool.ps1 status
```

Expected: all telemetry policy and service values match the protected baseline, and any captured service that was originally running is running again where possible.

## 9. Full uninstall from enabled state

Re-enable, install, then:

```powershell
.\gdid-tool.ps1 uninstall
```

Expected:

- identity is restored before related services are re-enabled;
- exact policy/service baseline is restored;
- `gpupdate /force` succeeds;
- post-refresh baseline verification succeeds;
- state is deleted only after all checks pass; and
- sign-out/reboot produces normal baseline behavior.

## 10. Failure-path tests

### Domain/MDM override

Apply a conflicting authoritative policy, run `install`, and verify it exits nonzero with a post-`gpupdate` mismatch. It must not print false success.

### Service stop failure

Use a disposable snapshot to deny/interrupt a service stop. Verify installation fails and protected rollback state remains.

### Policy tampering

After install, alter one managed value and run `status`; it must show a mismatch. Re-run install to reconcile. Alter a value before uninstall and verify restoration is exact or fails closed while retaining state.

### Missing service

Test a Windows edition where either service is absent. The tool should report not installed and continue, while still applying applicable policies.

### Pro edition placebo prevention

On Pro, manually set `AllowTelemetry=0`, run `install`, and verify the audited build writes/reports `1` rather than claiming diagnostic data is off.

## Acceptance criteria

Accept only when:

- the validator exits `0`;
- each edition receives its supported minimum;
- `LimitEnhancedDiagnosticDataWindowsAnalytics` is `0`;
- service and policy verification is independently confirmed;
- post-`gpupdate` conflicts terminate the operation;
- deletion reporting is truthful;
- restore/uninstall return exact baseline values; and
- collateral is acceptable for the intended machine.
