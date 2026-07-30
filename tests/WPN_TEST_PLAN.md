# WPN Lifecycle Test Plan

Use this plan on a **disposable Windows 10/11 VM snapshot**. The tests intentionally stop and disable core notification services. Do not begin on a production workstation, an MDM-managed device, or a machine needed for time-sensitive notifications.

## Scope

This plan verifies that `blockWpn`:

- captures a reversible baseline;
- disables `WpnService`;
- disables the `WpnUserService` template;
- prevents normal per-user service creation with `UserServiceFlags=0`;
- disables and stops current `WpnUserService_*` instances;
- remains effective across sign-out/reboot;
- restores the protected baseline when the option is turned off or the tool is uninstalled; and
- does not falsely report success when a required value/service remains active.

It does **not** prove that every Microsoft identity, PUID, WNS-adjacent, diagnostic-data, or telemetry path is silent.

## 1. Prepare the VM

1. Take a VM snapshot/checkpoint.
2. Copy the complete audited package to a stable path.
3. Sign in with the same administrator account that will run every test.
4. Confirm the machine is not enrolled in MDM and is not being used for remote wipe, remote find, mandatory app deployment, or similar WNS-triggered management.
5. Open **Windows PowerShell as Administrator** in the package directory.

Run the non-mutating parser/static validation first:

```powershell
.\tests\Run-AllChecks.cmd
```

Expected: exit code `0`, zero failures under both engines, and a complete log in `tests\validation-results`.

## 2. Capture a pre-tool baseline

Run:

```powershell
$baselineDir = Join-Path $env:TEMP 'GDID-WPN-Baseline'
New-Item -ItemType Directory -Path $baselineDir -Force | Out-Null

$serviceNames = @('WpnService', 'WpnUserService')
$serviceNames += @(Get-Service -Name 'WpnUserService_*' -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty Name)

Get-Service -Name ($serviceNames | Sort-Object -Unique) -ErrorAction SilentlyContinue |
    Select-Object Name, Status, StartType, ServiceType |
    ConvertTo-Json -Depth 5 |
    Set-Content -LiteralPath (Join-Path $baselineDir 'services.json') -Encoding UTF8

$serviceKeys = @(
    'HKLM:\SYSTEM\CurrentControlSet\Services\WpnService',
    'HKLM:\SYSTEM\CurrentControlSet\Services\WpnUserService'
)
$serviceKeys += @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction Stop |
    Where-Object PSChildName -Like 'WpnUserService_*' |
    Select-Object -ExpandProperty PSPath)

$registryBaseline = foreach ($path in $serviceKeys) {
    $item = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
    if ($null -eq $item) { continue }

    $start = $null
    $flags = $null
    $delayed = $null
    if ($item.Property -contains 'Start') { $start = (Get-ItemProperty -LiteralPath $path -Name Start).Start }
    if ($item.Property -contains 'UserServiceFlags') { $flags = (Get-ItemProperty -LiteralPath $path -Name UserServiceFlags).UserServiceFlags }
    if ($item.Property -contains 'DelayedAutoStart') { $delayed = (Get-ItemProperty -LiteralPath $path -Name DelayedAutoStart).DelayedAutoStart }

    [pscustomobject]@{
        Path = $path
        Start = $start
        UserServiceFlags = $flags
        DelayedAutoStart = $delayed
    }
}
$registryBaseline | ConvertTo-Json -Depth 5 |
    Set-Content -LiteralPath (Join-Path $baselineDir 'registry.json') -Encoding UTF8

Write-Host "Baseline saved to $baselineDir"
```

Also run:

```powershell
.\gdid-tool.ps1 status
```

Save the console output for comparison.

## 3. Confirm the default is non-mutating for WPN

The shipped configuration should show:

```powershell
.\gdid-tool.ps1 config blockWpn
```

Expected:

```text
blockWpn = False
```

Run:

```powershell
.\gdid-tool.ps1 install
.\gdid-tool.ps1 status
```

Expected:

- WPN values match the protected pre-tool baseline.
- `status` reports `blockWpn=false`.
- The protected state reports schema `6`.
- No `WpnService`, `WpnUserService`, or `WpnUserService_*` startup value was changed merely because the default is false.

Compare the current registry/service values with the files in `$baselineDir`.

## 4. Enable WPN blocking

Run:

```powershell
.\gdid-tool.ps1 config blockWpn true
.\gdid-tool.ps1 install
.\gdid-tool.ps1 status
```

The install must fail rather than print success if a required WPN service/value remains active.

Verify the static values:

```powershell
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\WpnService' -Name Start).Start
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\WpnUserService' -Name Start).Start
(Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\WpnUserService' -Name UserServiceFlags).UserServiceFlags
```

Expected:

```text
4
4
0
```

Verify current per-user instances:

```powershell
$instanceProblems = foreach ($svc in @(Get-Service -Name 'WpnUserService_*' -ErrorAction SilentlyContinue)) {
    $path = "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)"
    $start = (Get-ItemProperty -LiteralPath $path -Name Start -ErrorAction Stop).Start
    if ($start -ne 4 -or $svc.Status -ne 'Stopped') {
        [pscustomobject]@{ Name = $svc.Name; Start = $start; Status = $svc.Status }
    }
}
$instanceProblems | Format-Table -AutoSize
if (@($instanceProblems).Count -gt 0) { throw 'One or more WpnUserService instances were not fully disabled.' }
```

Verify the system service:

```powershell
$system = Get-Service WpnService
if ($system.Status -ne 'Stopped') { throw "WpnService is $($system.Status), not Stopped." }
```

Expected `status` summary:

- `WpnService Start=Disabled: True`
- `WpnUserService template Start=Disabled: True`
- `WpnUserService creation blocked: True`
- `Existing user instances disabled: True`
- `WPN services stopped: True`

## 5. Exercise the per-user lifecycle

1. Record the current suffixed service names:

   ```powershell
   Get-Service -Name 'WpnUserService_*' -ErrorAction SilentlyContinue |
       Select-Object Name, Status, StartType
   ```

2. Sign out and sign back in, or reboot.
3. Run `status` again from an elevated PowerShell window.
4. Inspect any newly created suffix:

   ```powershell
   Get-Service -Name 'WpnUserService_*' -ErrorAction SilentlyContinue |
       Select-Object Name, Status, StartType

   Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' |
       Where-Object PSChildName -Like 'WpnUserService_*' |
       ForEach-Object {
           [pscustomobject]@{
               Name = $_.PSChildName
               Start = (Get-ItemProperty -LiteralPath $_.PSPath -Name Start).Start
           }
       }
   ```

Expected: no usable running instance; any created instance has `Start=4` and is stopped. Because `UserServiceFlags=0`, some Windows builds may create no suffixed instance at all.

## 6. Check functional collateral

While `blockWpn=true`, test the functions relevant to the VM:

- local and cloud toast notifications;
- Mail/Calendar or other Store-app background notifications;
- Microsoft Store application behavior;
- Windows Security and Settings notification surfaces;
- account/enrollment/ESU workflows; and
- any management tooling that uses WNS.

Record every observed regression. Failure of notification-dependent features is expected collateral, not evidence that unrelated telemetry is blocked.

## 7. Restore WPN without uninstalling the rest of the tool

Run:

```powershell
.\gdid-tool.ps1 config blockWpn false
.\gdid-tool.ps1 install
.\gdid-tool.ps1 status
```

Expected:

- static `WpnService` values equal the pre-tool protected baseline;
- `WpnUserService` template values equal the baseline;
- an original suffixed instance is restored exactly if its original key still exists;
- a newer suffix receives the protected template `Start` value rather than a guessed default;
- a disappeared old suffix is **not recreated**;
- every captured WPN service that was running and still exists (`WpnService`, template, or captured suffix) is running again; and
- `status` reports that managed WPN values match the protected baseline.

Sign out/reboot once, then repeat the service and registry comparisons.

## 8. Verify uninstall from an enabled state

Re-enable WPN blocking:

```powershell
.\gdid-tool.ps1 config blockWpn true
.\gdid-tool.ps1 install
```

Then uninstall:

```powershell
.\gdid-tool.ps1 uninstall
```

Expected:

- WPN values reconcile to the protected baseline;
- managed HOSTS/task/policy state is restored/removed;
- the protected state file is deleted only after all restoration checks succeed; and
- a sign-out/reboot recreates normal per-user service instances from the restored template.

If uninstall reports a conflict or restoration failure, **do not delete `%ProgramData%\GDIDPrivacy` manually**. Save the error and state file ACL information, revert the VM snapshot, and investigate the mismatched value.

## 9. Failure-path tests

Run these only on a disposable snapshot.

### Service restart interference

After enabling `blockWpn`, attempt:

```powershell
Start-Service WpnService -ErrorAction SilentlyContinue
.\gdid-tool.ps1 status
```

Expected: the service remains disabled/stopped, or `status` visibly reports a mismatch. No false green success is acceptable.

### Introduce a template mismatch

Temporarily set the template to Manual:

```powershell
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\WpnUserService' -Name Start -Type DWord -Value 3
.\gdid-tool.ps1 status
```

Expected: `status` reports WPN is not fully blocked. Re-run elevated `install` to reconcile to `Start=4`.

### Verify state retention after a restoration conflict

Do not perform this on a real profile. In a snapshot, alter a managed value after installation and confirm that a failed uninstall retains protected state instead of deleting it or claiming success.

### Active scheduled-task cleanup

Where automatic rotation is configured in the test VM, start the managed task manually and immediately run `uninstall` from the same user. Confirm that the task is stopped before it is unregistered and that no `gdid-tool.ps1 rotate -Scheduled` process remains after uninstall. Repeat from a second interactive session when available to exercise both the explicit task stop and the cross-session exclusive operation lock.

### Cross-session mutation serialization

Open two interactive sessions under the same Windows account. In the first, pause a mutating command under a debugger or immediately launch a long-running `install`; in the second, run another mutating command such as:

```powershell
.\gdid-tool.ps1 config blockWpn false
```

Expected: the second command exits with `Another GDID Privacy operation is already running for this user` and does not change configuration or runtime state. After the first command exits, a new mutation succeeds. A stale `.lock` filename after a crash must not prevent a later run because only the live exclusive handle is authoritative.

### Configuration typo rejection

On a VM snapshot, add an unknown field such as `"blockWpnx": true` to `gdid-config.json`, then run:

```powershell
.\gdid-tool.ps1 config
```

Expected: a terminating unknown-key error. Restore the valid JSON before continuing. Also verify that the attached archive's legacy `blockDDS`, `blockActivity`, `lastRotation`, and valid `originalGDID` fields are accepted only for migration.

### Installed schema-4/5 migration safety

Using a disposable copy of a valid protected schema-4 or schema-5 state marked `installed=true`, arrange for a current `CDPUserSvc_*` instance to contain `Start=4`, then run this build's elevated `uninstall`. Expected: migration does not record that live `4` as an exact original. The current suffix is restored from the protected `Service.CDPUserSvc.Start` template snapshot, and protected state is retained if that restoration cannot be verified.

## 10. Acceptance criteria

Accept the build only when all of the following are true on the target Windows version:

- the validator exits `0`;
- enable, status, reboot/sign-in, disable, and uninstall paths behave as documented;
- every reported `[OK]` condition is confirmed by independent registry/service queries;
- no original per-user service key is recreated after it naturally disappears;
- restoration returns static values to the captured baseline;
- failed verification produces a terminating error and retains rollback data; and
- the observed notification/management collateral is acceptable for the intended machine.
