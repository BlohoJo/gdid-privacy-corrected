# Removed or Deliberately Unsupported Features

## IP-address firewall blocking

Removed. The original implementation contained collection, parameter-binding, error-handling, and sinkhole defects. More importantly, rapidly changing shared frontend addresses made periodic IP rules structurally unreliable and potentially disruptive to unrelated Microsoft services.

The audited build retains only explicit exact-name HOSTS entries. Those entries are best effort and are not represented as endpoint-complete.

## API/AppInit registry hook

Rejected. The original archive did not provide a safe, complete deployment path, and AppInit DLL loading is not a reliable modern system-wide interception mechanism. A one-function hook would also miss native registry calls, identity APIs, caches, tickets, and other data sources.

`hookMethod` accepts `registry` or `none`. `api` is rejected.

## CDP cache deletion and restart

Removed. Deleting local CDP state and restarting CDP can trigger restoration of the authoritative value from the protected DeviceTicket. The audited build disables and verifies CDP before local masking and never presents cache deletion as rotation.

## Elevated startup rotation

Removed. The original highest-privilege scheduled task could execute a user-writable script. Automatic masking now uses a non-elevated current-user task and only when CDP has been installed and verified disabled.

## Server-side Device PUID rotation

Not implemented. Local `LID`/`DeviceId` writes do not rotate Microsoft's authoritative Device PUID. Genuine provisioning/renewal would require a different, carefully validated native identity workflow and would still not establish unlinkability.

## DeviceTicket rewriting or forgery

Not implemented. Re-encrypting local material does not create a Microsoft-valid arbitrary identity credential.

## “Block all Microsoft telemetry” mode

Not implemented. The telemetry option manages a documented Windows diagnostic-data policy set and two named services. Microsoft applications and Windows components can have independent data paths. A literal transmission guarantee requires an external default-deny network boundary or no network egress.

## Direct `Registry.pol` modification

Not implemented. The build writes and verifies policy registry values, then runs `gpupdate /force`. It does not claim that Local Group Policy Editor will show those settings as locally configured. Domain or MDM policy can supersede them; the tool detects post-refresh mismatches and fails rather than hiding the conflict.
