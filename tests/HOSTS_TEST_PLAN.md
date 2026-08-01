# HOSTS Grouping and Rollback Test Plan

Use a disposable Windows VM snapshot. Run the package-wide non-mutating gate
first:

```cmd
.\tests\Run-AllChecks.cmd
```

Do not continue unless both Windows PowerShell 5.1 and PowerShell 7 report zero
failures. The tests below modify the real Windows HOSTS file and require an
elevated shell for `install` and `uninstall`.

## Preconditions and capture

1. Save a byte-for-byte copy of the original file:

   ```powershell
   Copy-Item "$env:SystemRoot\System32\drivers\etc\hosts" `
     "$env:TEMP\hosts.before-gdid" -Force
   ```

2. Record its hash and encoding/BOM characteristics.
3. Confirm the package starts with the shipped schema-6 configuration.
4. Run `status` and capture its complete output.

## Test 1 — fresh default groups

The shipped defaults are:

```text
blockHosts=true
blockDDSHosts=true
blockActivityHosts=true
blockWnsHosts=false
blockAADHost=false
additionalHostDomains=[]
```

Run:

```powershell
.\gdid-tool.ps1 install
.\gdid-tool.ps1 status
```

Expected:

- the managed block is well formed;
- exactly nine names are requested;
- every requested name has one `0.0.0.0` line and one `::` line;
- no WNS/notify or AAD/DDS name is present in the managed block;
- status reports `Exact IPv4/IPv6 managed set present: True`;
- unrelated HOSTS records remain present and in the same order outside the
  marked block; the detected text encoding is retained. Separator/trailing
  newlines around the managed block may be normalized.

## Test 2 — all 16 built-in names

Run:

```powershell
.\gdid-tool.ps1 config blockDDSHosts true
.\gdid-tool.ps1 config blockActivityHosts true
.\gdid-tool.ps1 config blockWnsHosts true
.\gdid-tool.ps1 config blockAADHost true
.\gdid-tool.ps1 install
.\gdid-tool.ps1 status
```

Expected:

- exactly 16 unique names and 32 address/name lines appear inside the managed
  block;
- the WNS and AAD collateral warnings are displayed;
- status reports all four built-in groups active and exact-set verification
  succeeds;
- a name is written even if `Resolve-DnsName` currently returns NXDOMAIN.

The expected names are:

```text
dds.microsoft.com
fd.dds.microsoft.com
cs.dds.microsoft.com
aad.cs.dds.microsoft.com
continuum.dds.microsoft.com
cdpcs.access.microsoft.com
activity.windows.com
activity.microsoft.com
assets.activity.windows.com
ppe.activity.windows.com
client.wns.windows.com
global.notify.windows.com
sinnc-df.notify.windows.com
bn2-df.notify.windows.com
bn3p.notify.windows.com
db3p.notify.windows.com
```

## Test 3 — stale managed entries are removed

After Test 2, run:

```powershell
.\gdid-tool.ps1 config blockWnsHosts false
.\gdid-tool.ps1 install
.\gdid-tool.ps1 status
```

Expected:

- all six WNS/notify names disappear from both IPv4 and IPv6 entries;
- no stale WNS names remain in the managed block;
- exact-set verification succeeds for the remaining ten names.

Then set `blockAADHost=false`, install again, and confirm the exact set falls to
nine names.

## Test 4 — custom names

Run:

```powershell
.\gdid-tool.ps1 config additionalHostDomains `
  "Example.One.Microsoft.com.; second.example.microsoft.com; example.one.microsoft.com"
.\gdid-tool.ps1 install
.\gdid-tool.ps1 config additionalHostDomains
.\gdid-tool.ps1 status
```

Expected:

- names are lowercased;
- a trailing root dot is removed;
- duplicates are removed;
- the stored JSON value is an array;
- each resulting exact name receives one IPv4 and one IPv6 entry;
- status reports the custom group count and an explicit user-supplied-name
  warning.

Clear the list:

```powershell
.\gdid-tool.ps1 config additionalHostDomains ""
.\gdid-tool.ps1 install
```

Expected: all custom entries are removed and no built-in entries are disturbed.

## Test 5 — invalid custom values fail closed

Each command below must fail without changing `gdid-config.json` or HOSTS:

```powershell
.\gdid-tool.ps1 config additionalHostDomains "https://example.com/path"
.\gdid-tool.ps1 config additionalHostDomains "*.example.com"
.\gdid-tool.ps1 config additionalHostDomains "127.0.0.1"
.\gdid-tool.ps1 config additionalHostDomains "::1"
.\gdid-tool.ps1 config additionalHostDomains "name with spaces.example.com"
.\gdid-tool.ps1 config additionalHostDomains "example.com # comment"
```

Also test a JSON array containing a non-string or `null`; `status` must reject
the configuration rather than silently dropping the invalid element.

## Test 6 — exact-set diagnostics

With a valid managed block installed, manually introduce each defect one at a
time and run `status`:

- remove one IPv4 entry;
- remove one IPv6 entry;
- add an unexpected name;
- duplicate an entry;
- add an invalid line between the markers.

Expected: exact-set status is false and the relevant missing, unexpected,
duplicate, or invalid detail is reported. Running elevated `install` should
replace the malformed entry set with the exact configured set, unless the
marker structure itself is malformed.

## Test 7 — malformed marker refusal

Create either a duplicate begin marker, duplicate end marker, or reversed marker
order. Run `install`.

Expected:

- installation fails before changing the HOSTS file;
- the script reports malformed or duplicate markers;
- it does not guess which block to remove.

Restore the test file before continuing.

## Test 8 — transactional rollback

Arrange for the verification callback to fail in a disposable copy of the
script, or temporarily deny the final write after the backup is created.

Expected:

- the pre-update HOSTS bytes are restored;
- the command reports that update verification failed;
- if rollback itself fails, the temporary backup path is reported and retained.

## Test 9 — master switch with configured subgroups

Run:

```powershell
.\gdid-tool.ps1 config blockHosts false
.\gdid-tool.ps1 install
.\gdid-tool.ps1 status
```

Expected:

- the entire managed block is absent;
- subgroup settings remain recorded but report inactive;
- unrelated HOSTS records remain present and ordered; only separator/trailing
  newlines adjacent to the managed block may be normalized.

Re-enable `blockHosts=true`; the configured groups should be recreated.

## Test 10 — no active groups

Set all four built-in group switches false and clear custom names while leaving
`blockHosts=true`, then run `install`.

Expected:

- the script warns that no groups or custom names are enabled;
- any old managed block is removed;
- it does not throw the former `No HOSTS domains were supplied` error.

## Test 11 — schema-5 migration

Use a disposable copy of the package and replace the config with a valid
schema-5 file containing only the old HOSTS keys:

```json
{
  "schemaVersion": 5,
  "rotationMode": "onDemand",
  "timedIntervalMin": 30,
  "blockCDP": true,
  "blockWpn": false,
  "blockTelemetry": false,
  "requestDiagnosticDataDelete": false,
  "blockHosts": true,
  "blockAADHost": false,
  "blockDO": false,
  "killPhoneLink": false,
  "killOneDrive": false,
  "killStore": false,
  "killTimeline": false,
  "hookMethod": "registry"
}
```

Run `status` without saving configuration.

Expected:

- Activity grouping follows the old `blockHosts=true` behavior;
- DDS and WNS groups remain false;
- the custom list is empty;
- no silent expansion to nine or 16 names occurs.

Then change any config setting through the script and verify the saved file is
schema 6 with explicit group keys.

## Test 12 — uninstall and unrelated-content preservation

Add distinctive unrelated lines before and after the managed block. Run:

```powershell
.\gdid-tool.ps1 uninstall
```

Expected:

- the GDID Privacy begin/end block is gone;
- unrelated lines remain;
- the DNS cache is flushed;
- the protected state is deleted only after all other managed restoration has
  succeeded.

Finally compare the non-managed HOSTS records with the original capture,
allowing only separator/trailing-newline normalization around the removed
managed block, and restore the VM snapshot.
