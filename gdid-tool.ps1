#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Audited GDID privacy hardening tool for Windows 10, Windows 11, and Windows Server.

.DESCRIPTION
    This script can:
      * inspect the current user's registry copies of the Windows Device PUID;
      * disable Connected Devices Platform (CDP) components and policy;
      * optionally disable Windows Push Notification Services (WNS/WPN),
        including the system service, per-user template, and live instances;
      * optionally set edition-aware minimum diagnostic-data policies, disable
        DiagTrack and dmwappushservice, and submit the supported Windows
        diagnostic-data deletion request;
      * apply selected, documented Windows privacy/feature policies;
      * add exact-name HOSTS entries for selected endpoints; and
      * locally replace existing HKCU GDID registry copies after CDP has been
        verifiably disabled.

    It cannot rotate, erase, or replace Microsoft's authoritative server-issued
    Device PUID or the DPAPI-protected DeviceTicket. The "rotate" command is a
    local registry mask only. It deliberately refuses to run while CDP is active,
    because the value would otherwise be restored from the authoritative ticket.

    Install and uninstall require elevation. Status, help, configuration reads,
    and an already-installed current-user rotation do not.

.PARAMETER Mode
    status | rotate | install | uninstall | config | help

.PARAMETER Key
    Configuration key for the config command.

.PARAMETER Value
    Configuration value for the config command.

.PARAMETER Scheduled
    Internal switch used by the current-user scheduled task.
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('status', 'rotate', 'install', 'uninstall', 'config', 'help')]
    [string]$Mode = 'status',

    [Parameter(Position = 1)]
    [string]$Key,

    [Parameter(Position = 2)]
    [AllowEmptyString()]
    [string]$Value,

    [switch]$Scheduled
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# -----------------------------------------------------------------------------
# Constants and configuration schema
# -----------------------------------------------------------------------------

$script:ToolVersion = '3.7.3-audited-telemetry'
$script:CurrentConfigSchema = 5
$script:CurrentStateSchema = 6

# PS2EXE leaves $PSScriptRoot empty in compiled programs. Newer releases expose
# $ScriptRoot, but the command-line executable path remains a useful fallback
# for older wrappers. Resolve both the companion-file root and the invocation
# target once so config loading and scheduled-task creation work identically in
# .ps1 and compiled .exe forms.
$ps2ExeRootVariable = Get-Variable -Name 'ScriptRoot' -ErrorAction SilentlyContinue
$ps2ExeRoot = if ($null -ne $ps2ExeRootVariable) {
    [string]$ps2ExeRootVariable.Value
} else {
    $null
}
$commandLineExecutable = @([Environment]::GetCommandLineArgs()) | Select-Object -First 1

$invocationCandidates = if (-not [string]::IsNullOrWhiteSpace([string]$PSScriptRoot)) {
    @($PSCommandPath, $MyInvocation.MyCommand.Path)
} else {
    # In a compiled wrapper, prefer the actual process image over script-host
    # variables whose contents vary among PS2EXE releases.
    @($commandLineExecutable, $PSCommandPath, $MyInvocation.MyCommand.Path)
}
$selectedInvocation = $invocationCandidates | Where-Object {
    -not [string]::IsNullOrWhiteSpace([string]$_)
} | Select-Object -First 1
$script:InvocationPath = if (-not [string]::IsNullOrWhiteSpace([string]$selectedInvocation)) {
    [IO.Path]::GetFullPath([string]$selectedInvocation)
} else {
    $null
}

$rootCandidates = @($PSScriptRoot, $ps2ExeRoot)
if (-not [string]::IsNullOrWhiteSpace([string]$script:InvocationPath)) {
    $rootCandidates += Split-Path -Parent $script:InvocationPath
}
$rootCandidates += (Get-Location).Path
$script:EffectiveScriptRoot = [IO.Path]::GetFullPath([string](@($rootCandidates | Where-Object {
    -not [string]::IsNullOrWhiteSpace([string]$_)
} | Select-Object -First 1)[0]))

$script:ScriptLeaf = if (-not [string]::IsNullOrWhiteSpace([string]$script:InvocationPath)) {
    Split-Path -Leaf $script:InvocationPath
} else {
    'gdid-tool.ps1'
}
$script:ConfigPath = Join-Path $script:EffectiveScriptRoot 'gdid-config.json'
$script:HostsBeginMarker = '# GDID Privacy :: begin'
$script:HostsEndMarker = '# GDID Privacy :: end'
$script:ExtendedPropertiesPath = 'HKCU:\SOFTWARE\Microsoft\IdentityCRL\ExtendedProperties'
$script:TokenRootPath = 'HKCU:\SOFTWARE\Microsoft\IdentityCRL\Immersive\production\Token'
$script:CDPPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
$script:CDPSvcPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\CDPSvc'
$script:CDPUserTemplatePath = 'HKLM:\SYSTEM\CurrentControlSet\Services\CDPUserSvc'
$script:WpnSvcPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\WpnService'
$script:WpnUserTemplatePath = 'HKLM:\SYSTEM\CurrentControlSet\Services\WpnUserService'
$script:DiagTrackSvcPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\DiagTrack'
$script:DmwappushSvcPath = 'HKLM:\SYSTEM\CurrentControlSet\Services\dmwappushservice'
$script:TelemetryPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'

$script:CurrentUserSid = if ($env:OS -eq 'Windows_NT') {
    [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
} else {
    'non-windows'
}
$script:StateFileSuffix = $script:CurrentUserSid.Replace('-', '_')
$script:ProgramDataRoot = if ($env:ProgramData) {
    $env:ProgramData
} elseif ($env:SystemDrive) {
    Join-Path $env:SystemDrive 'ProgramData'
} else {
    $script:EffectiveScriptRoot
}
$script:StateRoot = Join-Path $script:ProgramDataRoot 'GDIDPrivacy'
$script:StateDirectory = Join-Path $script:StateRoot $script:StateFileSuffix
$script:StatePath = Join-Path $script:StateDirectory 'state.json'
$script:RuntimeDirectory = if ($env:LOCALAPPDATA) {
    Join-Path $env:LOCALAPPDATA 'GDIDPrivacy'
} else {
    Join-Path $script:EffectiveScriptRoot '.gdid-runtime'
}
$script:RuntimePath = Join-Path $script:RuntimeDirectory 'gdid-runtime.json'
$script:OperationLockPath = Join-Path $script:RuntimeDirectory "operation-$($script:StateFileSuffix).lock"
$script:LegacyUntrustedStatePath = if ($env:LOCALAPPDATA) {
    Join-Path (Join-Path $env:LOCALAPPDATA 'GDIDPrivacy') 'gdid-state.json'
} else {
    $null
}
$script:HostsPath = if ($env:SystemRoot) {
    Join-Path $env:SystemRoot 'System32\drivers\etc\hosts'
} else {
    $null
}

# activity.windows.com is the lower-collateral default. The AAD/DDS endpoint is
# opt-in because it is in a Microsoft account/authentication-related path.
$script:ActivityHostDomains = @('activity.windows.com')
$script:AADHostDomains = @('aad.cs.dds.microsoft.com')

$script:DefaultConfig = @{
    schemaVersion      = $script:CurrentConfigSchema
    rotationMode       = 'onDemand' # onDemand | perLogon | timed; perBoot accepted as legacy alias
    timedIntervalMin   = 30
    blockCDP           = $true
    blockWpn           = $false     # high-collateral opt-in: disables system/user WNS services
    blockTelemetry     = $false     # opt-in: diagnostic-data policies plus DiagTrack/dmwappushservice
    requestDiagnosticDataDelete = $false # one-shot opt-in; submits Clear-WindowsDiagnosticData request
    blockHosts         = $true
    blockAADHost       = $false
    blockDO            = $false     # opt-in DODownloadMode=99; not a GDID rotation mechanism
    killPhoneLink      = $false
    killOneDrive       = $false
    killStore          = $false
    killTimeline       = $false
    hookMethod         = 'registry' # registry | none; api is unsupported
}

$script:BooleanConfigKeys = @(
    'blockCDP',
    'blockWpn',
    'blockTelemetry',
    'requestDiagnosticDataDelete',
    'blockHosts',
    'blockAADHost',
    'blockDO',
    'killPhoneLink',
    'killOneDrive',
    'killStore',
    'killTimeline'
)
$script:CurrentConfigKeys = @($script:DefaultConfig.Keys)
# These are recognized only so an attached-archive configuration can be
# migrated deliberately. Every other unknown key is rejected instead of being
# silently ignored after a spelling error.
$script:LegacyConfigKeys = @(
    'blockDDS',
    'blockActivity',
    'lastRotation',
    'originalGDID'
)

# Every value below is backed up before the first change and restored exactly.
$script:PolicyDescriptors = @(
    [pscustomobject]@{
        Id = 'CDP.EnableCdp'
        ConfigKey = 'blockCDP'
        Path = $script:CDPPolicyPath
        Name = 'EnableCdp'
        Kind = 'DWord'
        DesiredValue = 0
        Label = 'Connected Devices Platform policy'
    },
    [pscustomobject]@{
        Id = 'PhoneLink.EnableMmx'
        ConfigKey = 'killPhoneLink'
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
        Name = 'EnableMmx'
        Kind = 'DWord'
        DesiredValue = 0
        Label = 'Phone-PC linking policy'
    },
    [pscustomobject]@{
        Id = 'OneDrive.DisableFileSyncNGSC'
        ConfigKey = 'killOneDrive'
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive'
        Name = 'DisableFileSyncNGSC'
        Kind = 'DWord'
        DesiredValue = 1
        Label = 'OneDrive file-sync policy'
    },
    [pscustomobject]@{
        Id = 'Store.AutoDownload'
        ConfigKey = 'killStore'
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore'
        Name = 'AutoDownload'
        Kind = 'DWord'
        DesiredValue = 2
        Label = 'Microsoft Store automatic-update policy'
    },
    [pscustomobject]@{
        Id = 'Timeline.EnableActivityFeed'
        ConfigKey = 'killTimeline'
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
        Name = 'EnableActivityFeed'
        Kind = 'DWord'
        DesiredValue = 0
        Label = 'Activity Feed policy'
    },
    [pscustomobject]@{
        Id = 'Timeline.PublishUserActivities'
        ConfigKey = 'killTimeline'
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
        Name = 'PublishUserActivities'
        Kind = 'DWord'
        DesiredValue = 0
        Label = 'Publish User Activities policy'
    },
    [pscustomobject]@{
        Id = 'Timeline.UploadUserActivities'
        ConfigKey = 'killTimeline'
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
        Name = 'UploadUserActivities'
        Kind = 'DWord'
        DesiredValue = 0
        Label = 'Upload User Activities policy'
    },
    [pscustomobject]@{
        Id = 'DO.DODownloadMode'
        ConfigKey = 'blockDO'
        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'
        Name = 'DODownloadMode'
        Kind = 'DWord'
        DesiredValue = 99
        Label = 'Delivery Optimization simple-mode policy'
    },

    # Diagnostic-data controls. AllowTelemetry is resolved at runtime because
    # value 0 is honored only by Enterprise/Education/IoT Enterprise/Server;
    # Windows Pro's supported minimum is 1 (Required diagnostic data).
    [pscustomobject]@{
        Id = 'Telemetry.AllowTelemetry'
        ConfigKey = 'blockTelemetry'
        Path = $script:TelemetryPolicyPath
        Name = 'AllowTelemetry'
        Kind = 'DWord'
        DesiredValueResolver = 'MinimumDiagnosticData'
        Label = 'Allow Diagnostic Data / Allow Telemetry policy'
    },
    [pscustomobject]@{
        Id = 'Telemetry.AllowDeviceNameInTelemetry'
        ConfigKey = 'blockTelemetry'
        Path = $script:TelemetryPolicyPath
        Name = 'AllowDeviceNameInTelemetry'
        Kind = 'DWord'
        DesiredValue = 0
        MinimumBuild = 17763
        Label = 'Do not transmit the device name in diagnostic data'
    },
    [pscustomobject]@{
        Id = 'Telemetry.DisableEnterpriseAuthProxy'
        ConfigKey = 'blockTelemetry'
        Path = $script:TelemetryPolicyPath
        Name = 'DisableEnterpriseAuthProxy'
        Kind = 'DWord'
        DesiredValue = 1
        MinimumBuild = 16299
        Label = 'Disable automatic authenticated-proxy use by DiagTrack (proxy behavior only)'
    },
    [pscustomobject]@{
        Id = 'Telemetry.DisableOneSettingsDownloads'
        ConfigKey = 'blockTelemetry'
        Path = $script:TelemetryPolicyPath
        Name = 'DisableOneSettingsDownloads'
        Kind = 'DWord'
        DesiredValue = 1
        # ADMX support is documented for Windows 10 1909+ and Server 2016+;
        # the equivalent CSP is documented for Windows 11. Track the client
        # and server floors independently instead of treating it as Win11-only.
        MinimumClientBuild = 18363
        MinimumServerBuild = 14393
        Label = 'Disable OneSettings configuration downloads'
    },
    [pscustomobject]@{
        Id = 'Telemetry.DoNotShowFeedbackNotifications'
        ConfigKey = 'blockTelemetry'
        Path = $script:TelemetryPolicyPath
        Name = 'DoNotShowFeedbackNotifications'
        Kind = 'DWord'
        DesiredValue = 1
        Label = 'Disable diagnostic feedback notifications'
    },
    [pscustomobject]@{
        Id = 'Telemetry.LimitDiagnosticLogCollection'
        ConfigKey = 'blockTelemetry'
        Path = $script:TelemetryPolicyPath
        Name = 'LimitDiagnosticLogCollection'
        Kind = 'DWord'
        DesiredValue = 1
        MinimumClientBuild = 18363
        MinimumServerBuild = 14393
        Label = 'Limit optional diagnostic log collection'
    },
    [pscustomobject]@{
        Id = 'Telemetry.LimitEnhancedDiagnosticDataWindowsAnalytics'
        ConfigKey = 'blockTelemetry'
        Path = $script:TelemetryPolicyPath
        Name = 'LimitEnhancedDiagnosticDataWindowsAnalytics'
        Kind = 'DWord'
        # Value 1 ENABLES the Desktop/Windows Analytics exception. The requested
        # policy choice "Disable Windows Analytics collection" is value 0.
        DesiredValue = 0
        MinimumBuild = 16299
        Label = 'Disable Windows Analytics enhanced-data collection'
    },
    [pscustomobject]@{
        Id = 'Telemetry.DisableDeviceDelete'
        ConfigKey = 'blockTelemetry'
        Path = $script:TelemetryPolicyPath
        Name = 'DisableDeviceDelete'
        Kind = 'DWord'
        DesiredValue = 0
        MinimumBuild = 17763
        Label = 'Keep diagnostic-data deletion available'
    },
    [pscustomobject]@{
        Id = 'Telemetry.DisableTelemetryOptInSettingsUx'
        ConfigKey = 'blockTelemetry'
        Path = $script:TelemetryPolicyPath
        Name = 'DisableTelemetryOptInSettingsUx'
        Kind = 'DWord'
        DesiredValue = 1
        MinimumBuild = 17134
        ClientOnly = $true
        Label = 'Prevent optional diagnostic-data opt-in in Settings'
    },
    [pscustomobject]@{
        Id = 'Telemetry.DisableTailoredExperiencesWithDiagnosticData'
        ConfigKey = 'blockTelemetry'
        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'
        Name = 'DisableTailoredExperiencesWithDiagnosticData'
        Kind = 'DWord'
        DesiredValue = 1
        MinimumBuild = 15063
        ClientOnly = $true
        Label = 'Turn off tailored experiences using diagnostic data'
    },
    [pscustomobject]@{
        Id = 'Telemetry.AllowLinguisticDataCollection'
        ConfigKey = 'blockTelemetry'
        Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput'
        Name = 'AllowLinguisticDataCollection'
        Kind = 'DWord'
        DesiredValue = 0
        MinimumBuild = 14393
        ClientOnly = $true
        Label = 'Turn off inking and typing personalization data collection'
    },
    [pscustomobject]@{
        Id = 'Telemetry.RestrictImplicitTextCollection'
        ConfigKey = 'blockTelemetry'
        Path = 'HKCU:\SOFTWARE\Microsoft\InputPersonalization'
        Name = 'RestrictImplicitTextCollection'
        Kind = 'DWord'
        DesiredValue = 1
        ClientOnly = $true
        Label = 'Restrict implicit typing collection'
    },
    [pscustomobject]@{
        Id = 'Telemetry.RestrictImplicitInkCollection'
        ConfigKey = 'blockTelemetry'
        Path = 'HKCU:\SOFTWARE\Microsoft\InputPersonalization'
        Name = 'RestrictImplicitInkCollection'
        Kind = 'DWord'
        DesiredValue = 1
        ClientOnly = $true
        Label = 'Restrict implicit inking collection'
    }
)

$script:ServiceValueDescriptors = @(
    [pscustomobject]@{
        Id = 'Service.CDPSvc.Start'
        Path = $script:CDPSvcPath
        Name = 'Start'
    },
    [pscustomobject]@{
        Id = 'Service.CDPSvc.DelayedAutoStart'
        Path = $script:CDPSvcPath
        Name = 'DelayedAutoStart'
    },
    [pscustomobject]@{
        Id = 'Service.CDPUserSvc.Start'
        Path = $script:CDPUserTemplatePath
        Name = 'Start'
    },
    [pscustomobject]@{
        Id = 'Service.CDPUserSvc.UserServiceFlags'
        Path = $script:CDPUserTemplatePath
        Name = 'UserServiceFlags'
    },
    [pscustomobject]@{
        Id = 'Service.WpnService.Start'
        Path = $script:WpnSvcPath
        Name = 'Start'
    },
    [pscustomobject]@{
        Id = 'Service.WpnService.DelayedAutoStart'
        Path = $script:WpnSvcPath
        Name = 'DelayedAutoStart'
    },
    [pscustomobject]@{
        Id = 'Service.WpnUserService.Start'
        Path = $script:WpnUserTemplatePath
        Name = 'Start'
    },
    [pscustomobject]@{
        Id = 'Service.WpnUserService.UserServiceFlags'
        Path = $script:WpnUserTemplatePath
        Name = 'UserServiceFlags'
    },
    [pscustomobject]@{
        Id = 'Service.DiagTrack.Start'
        Path = $script:DiagTrackSvcPath
        Name = 'Start'
    },
    [pscustomobject]@{
        Id = 'Service.DiagTrack.DelayedAutoStart'
        Path = $script:DiagTrackSvcPath
        Name = 'DelayedAutoStart'
    },
    [pscustomobject]@{
        Id = 'Service.dmwappushservice.Start'
        Path = $script:DmwappushSvcPath
        Name = 'Start'
    },
    [pscustomobject]@{
        Id = 'Service.dmwappushservice.DelayedAutoStart'
        Path = $script:DmwappushSvcPath
        Name = 'DelayedAutoStart'
    }
)

# -----------------------------------------------------------------------------
# General helpers
# -----------------------------------------------------------------------------

function Write-Ok {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host "  [OK] $Message" -ForegroundColor Green
}

function Write-Warn {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host "  [WARN] $Message" -ForegroundColor Yellow
}

function Write-Info {
    param([Parameter(Mandatory = $true)][string]$Message)
    Write-Host "  [INFO] $Message" -ForegroundColor Cyan
}

function Assert-Windows {
    if ($env:OS -ne 'Windows_NT') {
        throw 'This tool can run only on Windows.'
    }
}

function Test-IsAdministrator {
    if ($env:OS -ne 'Windows_NT') {
        return $false
    }

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList @($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}


function Assert-Administrator {
    if (-not (Test-IsAdministrator)) {
        throw 'This command requires an elevated PowerShell window (Run as administrator).'
    }
}

function Assert-PathIsNotReparsePoint {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [ValidateSet('Any', 'Container', 'Leaf')][string]$ExpectedType = 'Any'
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    $item = Get-Item -LiteralPath $Path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Refusing trusted state path '$Path' because it is a reparse point."
    }
    if ($ExpectedType -eq 'Container' -and -not [bool]$item.PSIsContainer) {
        throw "Trusted state path '$Path' must be a directory."
    }
    if ($ExpectedType -eq 'Leaf' -and [bool]$item.PSIsContainer) {
        throw "Trusted state path '$Path' must be a file."
    }
}

function New-StateAclRule {
    param(
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$Identity,
        [Parameter(Mandatory = $true)][Security.AccessControl.FileSystemRights]$Rights,
        [Parameter(Mandatory = $true)][Security.AccessControl.InheritanceFlags]$Inheritance,
        [Parameter(Mandatory = $true)][Security.AccessControl.PropagationFlags]$Propagation
    )

    return (New-Object -TypeName Security.AccessControl.FileSystemAccessRule -ArgumentList @(
        $Identity,
        $Rights,
        $Inheritance,
        $Propagation,
        [Security.AccessControl.AccessControlType]::Allow
    ))
}

function Set-ProtectedStateDirectoryAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][Security.Principal.SecurityIdentifier]$ReadIdentity
    )

    $administrators = New-Object -TypeName Security.Principal.SecurityIdentifier -ArgumentList @('S-1-5-32-544')
    $system = New-Object -TypeName Security.Principal.SecurityIdentifier -ArgumentList @('S-1-5-18')
    $inherit = [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
               [Security.AccessControl.InheritanceFlags]::ObjectInherit
    $none = [Security.AccessControl.PropagationFlags]::None

    $acl = New-Object -TypeName Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($administrators)
    [void]$acl.AddAccessRule((New-StateAclRule -Identity $administrators -Rights ([Security.AccessControl.FileSystemRights]::FullControl) -Inheritance $inherit -Propagation $none))
    [void]$acl.AddAccessRule((New-StateAclRule -Identity $system -Rights ([Security.AccessControl.FileSystemRights]::FullControl) -Inheritance $inherit -Propagation $none))
    [void]$acl.AddAccessRule((New-StateAclRule -Identity $ReadIdentity -Rights ([Security.AccessControl.FileSystemRights]::ReadAndExecute) -Inheritance $inherit -Propagation $none))
    Set-Acl -LiteralPath $Path -AclObject $acl
}

function Protect-TrustedStateStorage {
    Assert-Administrator

    Assert-PathIsNotReparsePoint -Path $script:StateRoot -ExpectedType Container
    if (-not (Test-Path -LiteralPath $script:StateRoot)) {
        New-Item -ItemType Directory -Path $script:StateRoot -Force | Out-Null
    }
    Assert-PathIsNotReparsePoint -Path $script:StateRoot -ExpectedType Container

    # The common root is traversable/readable by normal users but writable only
    # by administrators and SYSTEM. Each SID-specific child is readable only by
    # that user, so one user's install cannot expose or overwrite another's.
    $users = New-Object -TypeName Security.Principal.SecurityIdentifier -ArgumentList @('S-1-5-32-545')
    Set-ProtectedStateDirectoryAcl -Path $script:StateRoot -ReadIdentity $users

    Assert-PathIsNotReparsePoint -Path $script:StateDirectory -ExpectedType Container
    if (-not (Test-Path -LiteralPath $script:StateDirectory)) {
        New-Item -ItemType Directory -Path $script:StateDirectory -Force | Out-Null
    }
    Assert-PathIsNotReparsePoint -Path $script:StateDirectory -ExpectedType Container
    $user = New-Object -TypeName Security.Principal.SecurityIdentifier -ArgumentList @($script:CurrentUserSid)
    Set-ProtectedStateDirectoryAcl -Path $script:StateDirectory -ReadIdentity $user
}


function Protect-TrustedStateFile {
    Assert-Administrator

    if (-not (Test-Path -LiteralPath $script:StatePath)) {
        throw "Trusted state file '$($script:StatePath)' does not exist."
    }
    Assert-PathIsNotReparsePoint -Path $script:StatePath -ExpectedType Leaf

    $administrators = New-Object -TypeName Security.Principal.SecurityIdentifier -ArgumentList @('S-1-5-32-544')
    $system = New-Object -TypeName Security.Principal.SecurityIdentifier -ArgumentList @('S-1-5-18')
    $user = New-Object -TypeName Security.Principal.SecurityIdentifier -ArgumentList @($script:CurrentUserSid)
    $noneInheritance = [Security.AccessControl.InheritanceFlags]::None
    $nonePropagation = [Security.AccessControl.PropagationFlags]::None

    $acl = New-Object -TypeName Security.AccessControl.FileSecurity
    $acl.SetAccessRuleProtection($true, $false)
    $acl.SetOwner($administrators)
    [void]$acl.AddAccessRule((New-StateAclRule -Identity $administrators -Rights ([Security.AccessControl.FileSystemRights]::FullControl) -Inheritance $noneInheritance -Propagation $nonePropagation))
    [void]$acl.AddAccessRule((New-StateAclRule -Identity $system -Rights ([Security.AccessControl.FileSystemRights]::FullControl) -Inheritance $noneInheritance -Propagation $nonePropagation))
    [void]$acl.AddAccessRule((New-StateAclRule -Identity $user -Rights ([Security.AccessControl.FileSystemRights]::ReadAndExecute) -Inheritance $noneInheritance -Propagation $nonePropagation))

    Set-Acl -LiteralPath $script:StatePath -AclObject $acl
}

function Convert-IdentityReferenceToSidText {
    param([Parameter(Mandatory = $true)][Security.Principal.IdentityReference]$IdentityReference)

    try {
        return $IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
    } catch {
        return $null
    }
}

function Test-TrustedAclObject {
    param(
        [Parameter(Mandatory = $true)]$Acl,
        [Parameter(Mandatory = $true)][string]$ReadSid
    )

    if (-not [bool]$Acl.AreAccessRulesProtected) {
        return $false
    }

    $ownerSid = $null
    try {
        $ownerAccount = New-Object -TypeName Security.Principal.NTAccount -ArgumentList @([string]$Acl.Owner)
        $ownerSid = $ownerAccount.Translate([Security.Principal.SecurityIdentifier]).Value
    } catch {
        try {
            $ownerSid = (New-Object -TypeName Security.Principal.SecurityIdentifier -ArgumentList @([string]$Acl.Owner)).Value
        } catch {
            return $false
        }
    }
    if ($ownerSid -notin @('S-1-5-32-544', 'S-1-5-18')) {
        return $false
    }

    $allowedSids = @('S-1-5-32-544', 'S-1-5-18', $ReadSid)
    $seen = @{}
    $rules = @($Acl.Access)
    if ($rules.Count -ne $allowedSids.Count) {
        return $false
    }

    foreach ($rule in $rules) {
        if ($rule.IsInherited -or
            $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            return $false
        }
        $sid = Convert-IdentityReferenceToSidText -IdentityReference $rule.IdentityReference
        if (-not $sid -or $sid -notin $allowedSids -or $seen.ContainsKey($sid)) {
            return $false
        }
        $seen[$sid] = $true

        $rights = [Security.AccessControl.FileSystemRights]$rule.FileSystemRights
        if ($sid -in @('S-1-5-32-544', 'S-1-5-18')) {
            if (($rights -band [Security.AccessControl.FileSystemRights]::FullControl) -ne
                [Security.AccessControl.FileSystemRights]::FullControl) {
                return $false
            }
        } else {
            # Do not use the composite Write/Modify/FullControl values as
            # a mask: those composites also include read/synchronize bits and
            # would incorrectly classify ReadAndExecute as writable.
            $writeMask = [Security.AccessControl.FileSystemRights]::WriteData -bor
                         [Security.AccessControl.FileSystemRights]::AppendData -bor
                         [Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
                         [Security.AccessControl.FileSystemRights]::WriteAttributes -bor
                         [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor
                         [Security.AccessControl.FileSystemRights]::Delete -bor
                         [Security.AccessControl.FileSystemRights]::ChangePermissions -bor
                         [Security.AccessControl.FileSystemRights]::TakeOwnership
            if (($rights -band $writeMask) -ne 0) {
                return $false
            }
            if (($rights -band [Security.AccessControl.FileSystemRights]::ReadAndExecute) -ne
                [Security.AccessControl.FileSystemRights]::ReadAndExecute) {
                return $false
            }
        }
    }

    foreach ($sid in $allowedSids) {
        if (-not $seen.ContainsKey($sid)) {
            return $false
        }
    }
    return $true
}


function Get-TrustedStateSecurityStatus {
    if (-not (Test-Path -LiteralPath $script:StatePath)) {
        return [pscustomobject]@{
            Exists = $false
            Protected = $false
            Detail = 'not installed'
        }
    }

    try {
        Assert-PathIsNotReparsePoint -Path $script:StateRoot -ExpectedType Container
        Assert-PathIsNotReparsePoint -Path $script:StateDirectory -ExpectedType Container
        Assert-PathIsNotReparsePoint -Path $script:StatePath -ExpectedType Leaf
        $rootAcl = Get-Acl -LiteralPath $script:StateRoot
        $directoryAcl = Get-Acl -LiteralPath $script:StateDirectory
        $fileAcl = Get-Acl -LiteralPath $script:StatePath
        $protected = (Test-TrustedAclObject -Acl $rootAcl -ReadSid 'S-1-5-32-545') -and
                     (Test-TrustedAclObject -Acl $directoryAcl -ReadSid $script:CurrentUserSid) -and
                     (Test-TrustedAclObject -Acl $fileAcl -ReadSid $script:CurrentUserSid)
        return [pscustomobject]@{
            Exists = $true
            Protected = $protected
            Detail = $(if ($protected) {
                'administrator/SYSTEM write; current user read-only'
            } else {
                'owner or ACL does not match the protected-state policy'
            })
        }
    } catch {
        return [pscustomobject]@{
            Exists = $true
            Protected = $false
            Detail = "ACL query failed: $($_.Exception.Message)"
        }
    }
}



function Test-ObjectProperty {
    param(
        [AllowNull()]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($null -eq $InputObject) {
        return $false
    }
    return $null -ne $InputObject.PSObject.Properties[$Name]
}

function Get-ObjectPropertyValue {
    param(
        [AllowNull()]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name,
        $Default = $null
    )

    if ($null -eq $InputObject) {
        return $Default
    }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $Default
    }
    return $property.Value
}

function Write-JsonFileAtomic {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$InputObject,
        [int]$Depth = 16
    )

    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory)) {
        New-Item -ItemType Directory -Path $directory -Force | Out-Null
    }

    $tempPath = "$Path.$PID.$([Guid]::NewGuid().ToString('N')).tmp"
    $backupPath = "$Path.$PID.$([Guid]::NewGuid().ToString('N')).bak"
    $encoding = New-Object -TypeName System.Text.UTF8Encoding -ArgumentList @($false)
    $json = $InputObject | ConvertTo-Json -Depth $Depth
    $success = $false
    $hadOriginal = Test-Path -LiteralPath $Path

    try {
        [IO.File]::WriteAllText($tempPath, $json + [Environment]::NewLine, $encoding)

        if ($hadOriginal) {
            Copy-Item -LiteralPath $Path -Destination $backupPath -Force
            try {
                [IO.File]::Replace($tempPath, $Path, $null, $true)
            } catch {
                Move-Item -LiteralPath $tempPath -Destination $Path -Force
            }
        } else {
            Move-Item -LiteralPath $tempPath -Destination $Path
        }

        $success = $true
    } catch {
        $writeError = $_
        if ($hadOriginal -and (Test-Path -LiteralPath $backupPath)) {
            try {
                Copy-Item -LiteralPath $backupPath -Destination $Path -Force
            } catch {
                throw "Writing '$Path' failed and its backup could not be restored. Backup retained at '$backupPath'. Write error: $($writeError.Exception.Message); restore error: $($_.Exception.Message)"
            }
        }
        throw $writeError
    } finally {
        Remove-Item -LiteralPath $tempPath -Force -ErrorAction SilentlyContinue
        if ($success) {
            Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
        }
    }
}


function ConvertTo-StrictBoolean {
    param(
        [AllowNull()]$InputObject,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($InputObject -is [bool]) {
        return [bool]$InputObject
    }

    if ($InputObject -is [byte] -or
        $InputObject -is [int16] -or
        $InputObject -is [int32] -or
        $InputObject -is [int64]) {
        if ([int64]$InputObject -eq 0) { return $false }
        if ([int64]$InputObject -eq 1) { return $true }
    }

    $text = [string]$InputObject
    switch -Regex ($text.Trim()) {
        '^(?i:true|yes|on|1)$'  { return $true }
        '^(?i:false|no|off|0)$' { return $false }
        default { throw "Configuration '$Name' must be true or false; received '$text'." }
    }
}

function Copy-DefaultConfig {
    $copy = @{}
    foreach ($name in $script:DefaultConfig.Keys) {
        $copy[$name] = $script:DefaultConfig[$name]
    }
    return $copy
}

function Test-ValidGDID {
    param([AllowNull()][string]$Value)
    return (-not [string]::IsNullOrWhiteSpace($Value)) -and ($Value -match '^[0-9A-Fa-f]{16}$')
}

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------

function Get-Config {
    $config = Copy-DefaultConfig

    if (-not (Test-Path -LiteralPath $script:ConfigPath)) {
        return $config
    }

    try {
        $rawText = Get-Content -LiteralPath $script:ConfigPath -Raw
        if ([string]::IsNullOrWhiteSpace($rawText)) {
            throw 'The file is empty.'
        }
        $raw = $rawText | ConvertFrom-Json
    } catch {
        throw "Cannot parse '$($script:ConfigPath)': $($_.Exception.Message)"
    }

    if ($null -eq $raw -or
        $raw -is [Array] -or
        $raw -is [string] -or
        @($raw.PSObject.Properties).Count -eq 0) {
        throw "Configuration '$($script:ConfigPath)' must contain one JSON object."
    }

    $allowedConfigKeys = @($script:CurrentConfigKeys + $script:LegacyConfigKeys)
    $unknownConfigKeys = @($raw.PSObject.Properties.Name | Where-Object {
        $_ -notin $allowedConfigKeys
    } | Sort-Object -Unique)
    if ($unknownConfigKeys.Count -gt 0) {
        throw "Configuration '$($script:ConfigPath)' contains unknown key(s): $($unknownConfigKeys -join ', '). Correct the spelling or remove the unsupported field."
    }

    if (Test-ObjectProperty -InputObject $raw -Name 'schemaVersion') {
        $configSchema = 0
        if (-not [int]::TryParse([string]$raw.schemaVersion, [ref]$configSchema) -or
            $configSchema -lt 1 -or $configSchema -gt $script:CurrentConfigSchema) {
            throw "Configuration 'schemaVersion' must be an integer from 1 through $($script:CurrentConfigSchema)."
        }
    }
    if (Test-ObjectProperty -InputObject $raw -Name 'originalGDID') {
        $legacyOriginalText = [string]$raw.originalGDID
        if (-not [string]::IsNullOrWhiteSpace($legacyOriginalText) -and
            -not (Test-ValidGDID $legacyOriginalText)) {
            throw "Legacy configuration 'originalGDID' must be null or exactly 16 hexadecimal characters."
        }
    }

    foreach ($name in $script:BooleanConfigKeys) {
        if (Test-ObjectProperty -InputObject $raw -Name $name) {
            $config[$name] = ConvertTo-StrictBoolean -InputObject $raw.$name -Name $name
        }
    }

    # Migrate the attached archive's pre-Issue-12 configuration shape. Its
    # blockActivity key represented the lower-collateral activity endpoint;
    # blockDDS is deliberately not promoted to blockAADHost because doing so
    # would silently opt the user into an authentication-related HOSTS block.
    $legacyBlockActivity = $null
    if (Test-ObjectProperty -InputObject $raw -Name 'blockActivity') {
        $legacyBlockActivity = ConvertTo-StrictBoolean -InputObject $raw.blockActivity -Name 'blockActivity'
    }
    if (-not (Test-ObjectProperty -InputObject $raw -Name 'blockHosts') -and
        $null -ne $legacyBlockActivity) {
        $config['blockHosts'] = [bool]$legacyBlockActivity
    }
    if (Test-ObjectProperty -InputObject $raw -Name 'blockDDS') {
        $null = ConvertTo-StrictBoolean -InputObject $raw.blockDDS -Name 'blockDDS'
        if (-not $Scheduled) {
            Write-Warn "Legacy config key 'blockDDS' is ignored. Use blockAADHost=true explicitly only after reviewing its Microsoft-account collateral risk."
        }
    }

    if (Test-ObjectProperty -InputObject $raw -Name 'rotationMode') {
        $rotationText = ([string]$raw.rotationMode).Trim().ToLowerInvariant()
        switch ($rotationText) {
            'ondemand' { $config['rotationMode'] = 'onDemand' }
            'perboot'  { $config['rotationMode'] = 'perLogon' }
            'perlogon' { $config['rotationMode'] = 'perLogon' }
            'timed'    { $config['rotationMode'] = 'timed' }
            default {
                throw "Configuration 'rotationMode' must be onDemand, perLogon, or timed; received '$($raw.rotationMode)'."
            }
        }
    }

    if (Test-ObjectProperty -InputObject $raw -Name 'timedIntervalMin') {
        $interval = 0
        if (-not [int]::TryParse([string]$raw.timedIntervalMin, [ref]$interval)) {
            throw "Configuration 'timedIntervalMin' must be an integer."
        }
        if ($interval -lt 15 -or $interval -gt 1440) {
            throw "Configuration 'timedIntervalMin' must be between 15 and 1440."
        }
        $config['timedIntervalMin'] = $interval
    }

    if (Test-ObjectProperty -InputObject $raw -Name 'hookMethod') {
        $hookMethod = ([string]$raw.hookMethod).Trim().ToLowerInvariant()
        if ($hookMethod -eq 'api') {
            # A legacy api setting must not make the config command unusable.
            # Treat it as disabled and require an explicit supported choice.
            $hookMethod = 'none'
            if (-not $Scheduled) {
                Write-Warn "Legacy hookMethod=api is unsupported and is being treated as hookMethod=none. Set registry explicitly to enable local masking."
            }
        }
        if ($hookMethod -notin @('registry', 'none')) {
            throw "Configuration 'hookMethod' must be registry or none; received '$hookMethod'."
        }
        $config['hookMethod'] = $hookMethod
    }

    $config['schemaVersion'] = $script:CurrentConfigSchema
    return $config
}


function Save-Config {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Config,
        [switch]$DropLegacyOriginalGDID
    )

    # Preserve the original project's one-value backup until an administrator
    # imports it into the protected reversible state. A config edit must never
    # silently destroy the only original-GDID backup.
    $legacyOriginal = if ($DropLegacyOriginalGDID) { $null } else { Get-LegacyOriginalGDID }

    $ordered = [ordered]@{
        schemaVersion = $script:CurrentConfigSchema
        rotationMode = [string]$Config['rotationMode']
        timedIntervalMin = [int]$Config['timedIntervalMin']
        blockCDP = [bool]$Config['blockCDP']
        blockWpn = [bool]$Config['blockWpn']
        blockTelemetry = [bool]$Config['blockTelemetry']
        requestDiagnosticDataDelete = [bool]$Config['requestDiagnosticDataDelete']
        blockHosts = [bool]$Config['blockHosts']
        blockAADHost = [bool]$Config['blockAADHost']
        blockDO = [bool]$Config['blockDO']
        killPhoneLink = [bool]$Config['killPhoneLink']
        killOneDrive = [bool]$Config['killOneDrive']
        killStore = [bool]$Config['killStore']
        killTimeline = [bool]$Config['killTimeline']
        hookMethod = [string]$Config['hookMethod']
    }
    if ($legacyOriginal) {
        $ordered['originalGDID'] = $legacyOriginal
    }

    Write-JsonFileAtomic -Path $script:ConfigPath -InputObject $ordered
}


function Convert-ConfigValue {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowEmptyString()][string]$Text
    )

    if ($Name -in $script:BooleanConfigKeys) {
        return (ConvertTo-StrictBoolean -InputObject $Text -Name $Name)
    }

    switch ($Name) {
        'rotationMode' {
            switch ($Text.Trim().ToLowerInvariant()) {
                'ondemand' { return 'onDemand' }
                'perboot'  { return 'perLogon' }
                'perlogon' { return 'perLogon' }
                'timed'    { return 'timed' }
                default { throw 'rotationMode must be onDemand, perLogon, or timed (perBoot is accepted as a legacy alias).' }
            }
        }
        'timedIntervalMin' {
            $number = 0
            if (-not [int]::TryParse($Text, [ref]$number) -or $number -lt 15 -or $number -gt 1440) {
                throw 'timedIntervalMin must be an integer between 15 and 1440.'
            }
            return $number
        }
        'hookMethod' {
            $normalized = $Text.Trim().ToLowerInvariant()
            if ($normalized -eq 'api') {
                throw "hookMethod=api is unsupported; use 'registry' or 'none'."
            }
            if ($normalized -notin @('registry', 'none')) {
                throw 'hookMethod must be registry or none.'
            }
            return $normalized
        }
        default {
            throw "Unknown configuration key '$Name'."
        }
    }
}


function Get-LegacyOriginalGDID {
    if (-not (Test-Path -LiteralPath $script:ConfigPath)) {
        return $null
    }

    try {
        $raw = Get-Content -LiteralPath $script:ConfigPath -Raw | ConvertFrom-Json
        if (Test-ObjectProperty -InputObject $raw -Name 'originalGDID') {
            $candidate = [string]$raw.originalGDID
            if (Test-ValidGDID $candidate) {
                return $candidate.ToUpperInvariant()
            }
        }
    } catch {
        # Get-Config provides the user-facing parse error.
    }
    return $null
}

function Remove-LegacyOriginalGDIDFromConfig {
    if (-not (Get-LegacyOriginalGDID)) {
        return $false
    }

    $config = Get-Config
    Save-Config -Config $config -DropLegacyOriginalGDID
    if (Get-LegacyOriginalGDID) {
        throw "The legacy originalGDID backup could not be removed from '$($script:ConfigPath)'."
    }
    return $true
}

# -----------------------------------------------------------------------------
# Registry snapshots and reversible state
# -----------------------------------------------------------------------------

function Get-RegistryValueSnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $snapshot = [ordered]@{
        id = $Id
        path = $Path
        name = $Name
        pathExisted = $false
        existed = $false
        kind = $null
        value = $null
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        return [pscustomobject]$snapshot
    }

    $snapshot.pathExisted = $true
    $item = Get-Item -LiteralPath $Path
    if (@($item.Property) -notcontains $Name) {
        return [pscustomobject]$snapshot
    }

    $snapshot.existed = $true
    $snapshot.kind = $item.GetValueKind($Name).ToString()
    $snapshot.value = (Get-ItemProperty -LiteralPath $Path -Name $Name).$Name
    return [pscustomobject]$snapshot
}

function Convert-RegistryValueForKind {
    param(
        [AllowNull()]$Value,
        [Parameter(Mandatory = $true)][string]$Kind
    )

    switch ($Kind) {
        'DWord'        { return [uint32]$Value }
        'QWord'        { return [uint64]$Value }
        'Binary'       { return [byte[]]@($Value) }
        'MultiString'  { return [string[]]@($Value) }
        'ExpandString' { return [string]$Value }
        default        { return [string]$Value }
    }
}


function Set-RegistryValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()]$Value,
        [Parameter(Mandatory = $true)]
        [ValidateSet('String', 'ExpandString', 'Binary', 'DWord', 'MultiString', 'QWord')]
        [string]$Kind
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -Force | Out-Null
    }

    $typedValue = Convert-RegistryValueForKind -Value $Value -Kind $Kind
    New-ItemProperty -LiteralPath $Path -Name $Name -Value $typedValue -PropertyType $Kind -Force | Out-Null
}

function Set-ExistingRegistryValue {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name,
        [AllowNull()]$Value,
        [Parameter(Mandatory = $true)]
        [ValidateSet('String', 'ExpandString', 'Binary', 'DWord', 'MultiString', 'QWord')]
        [string]$Kind
    )

    # Service instances and identity-token keys can disappear asynchronously.
    # Never recreate such a key merely to undo a value written while it existed.
    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }

    $typedValue = Convert-RegistryValueForKind -Value $Value -Kind $Kind
    try {
        New-ItemProperty -LiteralPath $Path -Name $Name -Value $typedValue -PropertyType $Kind -Force | Out-Null
    } catch {
        if (-not (Test-Path -LiteralPath $Path)) {
            return $false
        }
        throw
    }

    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }
    $actual = Get-RegistryValueSnapshot -Id 'verify' -Path $Path -Name $Name
    if (-not (Test-RegistrySnapshotHasValue -Snapshot $actual -Kind $Kind -ExpectedValue $Value)) {
        throw "Existing-key registry write verification failed for $Path\$Name."
    }
    return $true
}

function Restore-ExistingRegistrySnapshot {
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter(Mandatory = $true)][string]$ExpectedPath,
        [Parameter(Mandatory = $true)][string]$ExpectedName
    )

    # This helper is for service/ephemeral keys that this tool never creates.
    # If the key did not exist at baseline, or no longer exists, leave it alone.
    if (-not [bool]$Snapshot.pathExisted -or -not (Test-Path -LiteralPath $ExpectedPath)) {
        return $false
    }

    if ([bool]$Snapshot.existed) {
        $kind = [string]$Snapshot.kind
        if ([string]::IsNullOrWhiteSpace($kind)) {
            $kind = 'String'
        }
        return (Set-ExistingRegistryValue `
            -Path $ExpectedPath `
            -Name $ExpectedName `
            -Value $Snapshot.value `
            -Kind $kind)
    }

    try {
        $item = Get-Item -LiteralPath $ExpectedPath -ErrorAction Stop
        if (@($item.Property) -contains $ExpectedName) {
            Remove-ItemProperty -LiteralPath $ExpectedPath -Name $ExpectedName
        }
    } catch {
        if (-not (Test-Path -LiteralPath $ExpectedPath)) {
            return $false
        }
        throw
    }

    if ((Test-Path -LiteralPath $ExpectedPath) -and
        -not (Test-RegistrySnapshotMatches `
            -Snapshot $Snapshot `
            -ExpectedPath $ExpectedPath `
            -ExpectedName $ExpectedName)) {
        throw "Existing-key restoration verification failed for $ExpectedPath\$ExpectedName."
    }
    return (Test-Path -LiteralPath $ExpectedPath)
}


function Test-RegistryValuesEqual {
    param(
        [AllowNull()]$Expected,
        [AllowNull()]$Actual,
        [Parameter(Mandatory = $true)][string]$Kind
    )

    switch ($Kind) {
        'Binary' {
            $a = [byte[]]@($Expected)
            $b = [byte[]]@($Actual)
            if ($a.Count -ne $b.Count) { return $false }
            for ($i = 0; $i -lt $a.Count; $i++) {
                if ($a[$i] -ne $b[$i]) { return $false }
            }
            return $true
        }
        'MultiString' {
            $a = [string[]]@($Expected)
            $b = [string[]]@($Actual)
            if ($a.Count -ne $b.Count) { return $false }
            for ($i = 0; $i -lt $a.Count; $i++) {
                if ($a[$i] -cne $b[$i]) { return $false }
            }
            return $true
        }
        'DWord' { return [uint32]$Expected -eq [uint32]$Actual }
        'QWord' { return [uint64]$Expected -eq [uint64]$Actual }
        default { return [string]$Expected -ceq [string]$Actual }
    }
}


function Test-RegistrySnapshotHasValue {
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter(Mandatory = $true)][string]$Kind,
        [AllowNull()]$ExpectedValue
    )

    if (-not [bool]$Snapshot.existed -or [string]$Snapshot.kind -cne $Kind) {
        return $false
    }
    try {
        return (Test-RegistryValuesEqual -Expected $ExpectedValue -Actual $Snapshot.value -Kind $Kind)
    } catch {
        return $false
    }
}


function Test-RegistrySnapshotMatches {
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter(Mandatory = $true)][string]$ExpectedPath,
        [Parameter(Mandatory = $true)][string]$ExpectedName
    )

    $actual = Get-RegistryValueSnapshot -Id 'verify' -Path $ExpectedPath -Name $ExpectedName
    if ([bool]$Snapshot.existed -ne [bool]$actual.existed) {
        return $false
    }
    if (-not [bool]$Snapshot.existed) {
        return $true
    }

    $kind = [string]$Snapshot.kind
    if ([string]::IsNullOrWhiteSpace($kind)) {
        $kind = 'String'
    }
    if ([string]$actual.kind -cne $kind) {
        return $false
    }
    return (Test-RegistryValuesEqual -Expected $Snapshot.value -Actual $actual.value -Kind $kind)
}


function Restore-RegistrySnapshot {
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter(Mandatory = $true)][string]$ExpectedPath,
        [Parameter(Mandatory = $true)][string]$ExpectedName
    )

    # Never trust a path or value name read from a state file. All callers pass
    # a compile-time descriptor or a separately validated HKCU identity target.
    if ([bool]$Snapshot.existed) {
        $kind = [string]$Snapshot.kind
        if ([string]::IsNullOrWhiteSpace($kind)) {
            $kind = 'String'
        }
        Set-RegistryValue -Path $ExpectedPath -Name $ExpectedName -Value $Snapshot.value -Kind $kind
    } elseif (Test-Path -LiteralPath $ExpectedPath) {
        $item = Get-Item -LiteralPath $ExpectedPath
        if (@($item.Property) -contains $ExpectedName) {
            Remove-ItemProperty -LiteralPath $ExpectedPath -Name $ExpectedName
        }

        # Remove a key created solely by this tool only when it was originally
        # absent and is still completely empty. Never remove new third-party
        # values or subkeys that appeared after installation.
        if (-not [bool]$Snapshot.pathExisted) {
            $item = Get-Item -LiteralPath $ExpectedPath -ErrorAction SilentlyContinue
            if ($null -ne $item -and
                @($item.Property).Count -eq 0 -and
                @(Get-ChildItem -LiteralPath $ExpectedPath -ErrorAction SilentlyContinue).Count -eq 0) {
                Remove-Item -LiteralPath $ExpectedPath -Force
            }
        }
    }

    if (-not (Test-RegistrySnapshotMatches -Snapshot $Snapshot -ExpectedPath $ExpectedPath -ExpectedName $ExpectedName)) {
        throw "Restoration verification failed for $ExpectedPath\$ExpectedName."
    }
}


function Get-IdentityTargetSnapshots {
    $targets = @()
    $targets += Get-RegistryValueSnapshot -Id 'Identity.LID' -Path $script:ExtendedPropertiesPath -Name 'LID'

    if (Test-Path -LiteralPath $script:TokenRootPath) {
        foreach ($subKey in @(Get-ChildItem -LiteralPath $script:TokenRootPath)) {
            $path = "HKCU:\SOFTWARE\Microsoft\IdentityCRL\Immersive\production\Token\$($subKey.PSChildName)"
            $snapshot = Get-RegistryValueSnapshot -Id "Identity.Token.$($subKey.PSChildName)" -Path $path -Name 'DeviceId'
            if ([bool]$snapshot.existed) {
                $targets += $snapshot
            }
        }
    }

    return $targets
}

function Get-ServiceRuntimeSnapshot {
    $result = @()
    $names = @('CDPSvc', 'CDPUserSvc', 'WpnService', 'WpnUserService', 'DiagTrack', 'dmwappushservice')
    $names += @(Get-Service -Name 'CDPUserSvc_*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)
    $names += @(Get-Service -Name 'WpnUserService_*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name)

    foreach ($name in @($names | Sort-Object -Unique)) {
        $service = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($null -ne $service) {
            $result += [pscustomobject]@{
                name = $name
                wasRunning = ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running)
            }
        }
    }
    return $result
}

function Get-CDPUserInstanceServices {
    return @(Get-Service -Name 'CDPUserSvc_*' -ErrorAction SilentlyContinue | Sort-Object Name -Unique)
}

function Get-CDPInstanceStartSnapshots {
    $snapshots = @()
    foreach ($service in @(Get-CDPUserInstanceServices)) {
        $path = "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)"
        $snapshot = Get-RegistryValueSnapshot `
            -Id "Service.CDPUserSvc.Instance.$($service.Name).Start" `
            -Path $path `
            -Name 'Start'
        if ([bool]$snapshot.existed) {
            $snapshots += $snapshot
        }
    }
    return $snapshots
}

function Get-WpnUserInstanceServices {
    return @(Get-Service -Name 'WpnUserService_*' -ErrorAction SilentlyContinue | Sort-Object Name -Unique)
}

function Get-WpnInstanceStartSnapshots {
    $snapshots = @()
    foreach ($service in @(Get-WpnUserInstanceServices)) {
        $path = "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)"
        $snapshot = Get-RegistryValueSnapshot `
            -Id "Service.WpnUserService.Instance.$($service.Name).Start" `
            -Path $path `
            -Name 'Start'
        if ([bool]$snapshot.existed) {
            $snapshots += $snapshot
        }
    }
    return $snapshots
}

function Get-ManagedDescriptorsForStateSchema {
    param([Parameter(Mandatory = $true)][int]$SchemaVersion)

    $legacyPolicies = @($script:PolicyDescriptors | Where-Object { $_.Id -notlike 'Telemetry.*' })
    $cdpServices = @($script:ServiceValueDescriptors | Where-Object {
        $_.Id -notlike 'Service.Wpn*' -and
        $_.Id -notlike 'Service.DiagTrack*' -and
        $_.Id -notlike 'Service.dmwappushservice*'
    })
    $preTelemetryServices = @($script:ServiceValueDescriptors | Where-Object {
        $_.Id -notlike 'Service.DiagTrack*' -and
        $_.Id -notlike 'Service.dmwappushservice*'
    })

    if ($SchemaVersion -eq 3) {
        # Schema 3 predates WPN and telemetry management.
        return @($legacyPolicies + $cdpServices)
    }
    if ($SchemaVersion -in @(4, 5)) {
        # Schemas 4 and 5 include WPN; schema 5 also adds exact CDP-instance
        # rollback. Neither schema contains telemetry policies/services.
        return @($legacyPolicies + $preTelemetryServices)
    }
    if ($SchemaVersion -eq $script:CurrentStateSchema) {
        return @($script:PolicyDescriptors + $script:ServiceValueDescriptors)
    }
    throw "Trusted state schema '$SchemaVersion' is unsupported; expected 3, 4, 5, or $($script:CurrentStateSchema)."
}

function Test-AllowedRuntimeServiceName {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][int]$SchemaVersion
    )

    if ($Name -ceq 'CDPSvc' -or $Name -match '^CDPUserSvc_[A-Za-z0-9]+$' -or
        ($SchemaVersion -ge 5 -and $Name -ceq 'CDPUserSvc')) {
        return $true
    }
    if ($SchemaVersion -ge 4 -and
        ($Name -ceq 'WpnService' -or $Name -ceq 'WpnUserService' -or
         $Name -match '^WpnUserService_[A-Za-z0-9]+$')) {
        return $true
    }
    if ($SchemaVersion -ge 6 -and
        ($Name -ceq 'DiagTrack' -or $Name -ceq 'dmwappushservice')) {
        return $true
    }
    return $false
}

function Test-CDPInstanceSnapshotTarget {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($Name -cne 'Start') {
        return $false
    }

    $prefix = 'HKLM:\SYSTEM\CurrentControlSet\Services\CDPUserSvc_'
    if (-not $Path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        return $false
    }

    $suffix = $Path.Substring($prefix.Length)
    if ($suffix -notmatch '^[A-Za-z0-9]+$') {
        return $false
    }

    return $Id -ceq "Service.CDPUserSvc.Instance.CDPUserSvc_$suffix.Start"
}

function Test-WpnInstanceSnapshotTarget {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($Name -cne 'Start') {
        return $false
    }

    $prefix = 'HKLM:\SYSTEM\CurrentControlSet\Services\WpnUserService_'
    if (-not $Path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
        return $false
    }

    $suffix = $Path.Substring($prefix.Length)
    if ($suffix -notmatch '^[A-Za-z0-9]+$') {
        return $false
    }

    return $Id -ceq "Service.WpnUserService.Instance.WpnUserService_$suffix.Start"
}

function Test-IdentitySnapshotTarget {
    param(
        [Parameter(Mandatory = $true)][string]$Id,
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    if ($Id -ceq 'Identity.LID' -and
        $Path.Equals($script:ExtendedPropertiesPath, [StringComparison]::OrdinalIgnoreCase) -and
        $Name -ceq 'LID') {
        return $true
    }

    $prefix = $script:TokenRootPath.TrimEnd('\') + '\'
    if (-not $Path.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or $Name -cne 'DeviceId') {
        return $false
    }

    $leaf = $Path.Substring($prefix.Length)
    if ([string]::IsNullOrWhiteSpace($leaf) -or $leaf -match '[\\/]') {
        return $false
    }

    return $Id -ceq "Identity.Token.$leaf"
}

function Assert-SnapshotShape {
    param(
        [Parameter(Mandatory = $true)]$Snapshot,
        [Parameter(Mandatory = $true)][string]$Context,
        [AllowNull()][string]$RequiredKind
    )

    foreach ($propertyName in @('id', 'path', 'name', 'pathExisted', 'existed', 'kind', 'value')) {
        if (-not (Test-ObjectProperty -InputObject $Snapshot -Name $propertyName)) {
            throw "Trusted state snapshot '$Context' is missing '$propertyName'."
        }
    }
    if ($Snapshot.pathExisted -isnot [bool] -or $Snapshot.existed -isnot [bool]) {
        throw "Trusted state snapshot '$Context' has non-Boolean existence flags."
    }

    if ([bool]$Snapshot.existed) {
        $kind = [string]$Snapshot.kind
        $allowedKinds = @('String', 'ExpandString', 'Binary', 'DWord', 'MultiString', 'QWord')
        if ($kind -notin $allowedKinds) {
            throw "Trusted state snapshot '$Context' has unsupported registry kind '$kind'."
        }
        if ($RequiredKind -and $kind -cne $RequiredKind) {
            throw "Trusted state snapshot '$Context' must have registry kind '$RequiredKind', not '$kind'."
        }
    }
}

function Assert-TrustedState {
    param([Parameter(Mandatory = $true)]$State)

    if ($null -eq $State -or $State -is [Array] -or $State -is [string]) {
        throw 'Trusted state must contain one JSON object.'
    }

    foreach ($propertyName in @(
        'schemaVersion', 'userSid', 'installed', 'originalIdentity',
        'originalManagedValues', 'originalServiceRuntime'
    )) {
        if (-not (Test-ObjectProperty -InputObject $State -Name $propertyName)) {
            throw "Trusted state is missing '$propertyName'."
        }
    }
    $schemaVersion = [int]$State.schemaVersion
    if ($schemaVersion -notin @(3, 4, 5, $script:CurrentStateSchema)) {
        throw "Trusted state schema '$($State.schemaVersion)' is unsupported; expected 3, 4, 5, or $($script:CurrentStateSchema)."
    }
    if ([string]$State.userSid -cne $script:CurrentUserSid) {
        throw "Trusted state belongs to SID '$($State.userSid)', not '$($script:CurrentUserSid)'."
    }
    if ($State.installed -isnot [bool]) {
        throw "Trusted state property 'installed' must be Boolean."
    }
    if (-not (Test-ObjectProperty -InputObject $State.originalIdentity -Name 'values')) {
        throw "Trusted state is missing 'originalIdentity.values'."
    }

    $identitySeen = @{}
    $identityValues = @($State.originalIdentity.values)
    if ($identityValues.Count -gt 256) {
        throw 'Trusted state contains an unreasonable number of identity snapshots.'
    }
    foreach ($snapshot in $identityValues) {
        Assert-SnapshotShape -Snapshot $snapshot -Context ([string]$snapshot.id) -RequiredKind 'String'
        if (-not [bool]$snapshot.existed) {
            throw "Identity snapshot '$($snapshot.id)' must represent a value that existed before masking."
        }
        if (-not (Test-IdentitySnapshotTarget -Id ([string]$snapshot.id) -Path ([string]$snapshot.path) -Name ([string]$snapshot.name))) {
            throw "Trusted state contains an invalid identity target '$($snapshot.path)\$($snapshot.name)'."
        }
        $identityKey = ([string]$snapshot.path).ToLowerInvariant() + '|' + ([string]$snapshot.name).ToLowerInvariant()
        if ($identitySeen.ContainsKey($identityKey)) {
            throw "Trusted state contains duplicate identity target '$identityKey'."
        }
        $identitySeen[$identityKey] = $true
        if ([string]$snapshot.value -and ([string]$snapshot.value).Length -gt 4096) {
            throw "Trusted state identity value '$($snapshot.id)' is unreasonably long."
        }
    }

    $managedDescriptors = @(Get-ManagedDescriptorsForStateSchema -SchemaVersion $schemaVersion)
    $managed = @($State.originalManagedValues)
    if ($managed.Count -ne $managedDescriptors.Count) {
        throw 'Trusted state does not contain exactly one snapshot for every managed registry value.'
    }

    $managedSeen = @{}
    foreach ($descriptor in $managedDescriptors) {
        $matches = @($managed | Where-Object { [string]$_.id -ceq [string]$descriptor.Id })
        if ($matches.Count -ne 1) {
            throw "Trusted state must contain exactly one snapshot for '$($descriptor.Id)'."
        }
        $snapshot = $matches[0]
        Assert-SnapshotShape -Snapshot $snapshot -Context $descriptor.Id -RequiredKind $null
        if (-not ([string]$snapshot.path).Equals([string]$descriptor.Path, [StringComparison]::OrdinalIgnoreCase) -or
            [string]$snapshot.name -cne [string]$descriptor.Name) {
            throw "Trusted state target for '$($descriptor.Id)' does not match the compiled descriptor."
        }
        if ($managedSeen.ContainsKey([string]$snapshot.id)) {
            throw "Trusted state contains duplicate managed snapshot '$($snapshot.id)'."
        }
        $managedSeen[[string]$snapshot.id] = $true
    }

    $runtimeSnapshots = @($State.originalServiceRuntime)
    if ($runtimeSnapshots.Count -gt 128) {
        throw 'Trusted state contains an unreasonable number of service runtime snapshots.'
    }
    $runtimeSeen = @{}
    foreach ($runtime in $runtimeSnapshots) {
        if (-not (Test-ObjectProperty -InputObject $runtime -Name 'name') -or
            -not (Test-ObjectProperty -InputObject $runtime -Name 'wasRunning') -or
            $runtime.wasRunning -isnot [bool]) {
            throw 'Trusted state contains an invalid service runtime snapshot.'
        }
        $serviceName = [string]$runtime.name
        if (-not (Test-AllowedRuntimeServiceName -Name $serviceName -SchemaVersion $schemaVersion)) {
            throw "Trusted state contains disallowed service name '$serviceName'."
        }
        $runtimeKey = $serviceName.ToLowerInvariant()
        if ($runtimeSeen.ContainsKey($runtimeKey)) {
            throw "Trusted state contains duplicate service runtime snapshot '$serviceName'."
        }
        $runtimeSeen[$runtimeKey] = $true
    }

    if ($schemaVersion -ge 4) {
        if (-not (Test-ObjectProperty -InputObject $State -Name 'originalWpnInstanceValues')) {
            throw "Trusted state schema $schemaVersion is missing 'originalWpnInstanceValues'."
        }
        if (-not (Test-ObjectProperty -InputObject $State -Name 'wpnInstanceBaselineSealed') -or
            $State.wpnInstanceBaselineSealed -isnot [bool]) {
            throw "Trusted state schema $schemaVersion has an invalid or missing 'wpnInstanceBaselineSealed' flag."
        }

        $wpnInstances = @($State.originalWpnInstanceValues)
        if ($wpnInstances.Count -gt 128) {
            throw 'Trusted state contains an unreasonable number of WPN instance snapshots.'
        }

        $wpnSeen = @{}
        foreach ($snapshot in $wpnInstances) {
            Assert-SnapshotShape -Snapshot $snapshot -Context ([string]$snapshot.id) -RequiredKind 'DWord'
            if (-not [bool]$snapshot.existed) {
                throw "WPN instance snapshot '$($snapshot.id)' must represent an existing Start value."
            }
            if (-not (Test-WpnInstanceSnapshotTarget `
                -Id ([string]$snapshot.id) `
                -Path ([string]$snapshot.path) `
                -Name ([string]$snapshot.name))) {
                throw "Trusted state contains an invalid WPN instance target '$($snapshot.path)\$($snapshot.name)'."
            }

            $instanceKey = ([string]$snapshot.path).ToLowerInvariant() + '|start'
            if ($wpnSeen.ContainsKey($instanceKey)) {
                throw "Trusted state contains duplicate WPN instance target '$instanceKey'."
            }
            $wpnSeen[$instanceKey] = $true
        }
    }

    if ($schemaVersion -ge 5) {
        if (-not (Test-ObjectProperty -InputObject $State -Name 'originalCdpInstanceValues')) {
            throw "Trusted state schema $schemaVersion is missing 'originalCdpInstanceValues'."
        }
        if (-not (Test-ObjectProperty -InputObject $State -Name 'cdpInstanceBaselineSealed') -or
            $State.cdpInstanceBaselineSealed -isnot [bool]) {
            throw "Trusted state schema $schemaVersion has an invalid or missing 'cdpInstanceBaselineSealed' flag."
        }

        $cdpInstances = @($State.originalCdpInstanceValues)
        if ($cdpInstances.Count -gt 128) {
            throw 'Trusted state contains an unreasonable number of CDP instance snapshots.'
        }

        $cdpSeen = @{}
        foreach ($snapshot in $cdpInstances) {
            Assert-SnapshotShape -Snapshot $snapshot -Context ([string]$snapshot.id) -RequiredKind 'DWord'
            if (-not [bool]$snapshot.existed) {
                throw "CDP instance snapshot '$($snapshot.id)' must represent an existing Start value."
            }
            if (-not (Test-CDPInstanceSnapshotTarget `
                -Id ([string]$snapshot.id) `
                -Path ([string]$snapshot.path) `
                -Name ([string]$snapshot.name))) {
                throw "Trusted state contains an invalid CDP instance target '$($snapshot.path)\$($snapshot.name)'."
            }

            $instanceKey = ([string]$snapshot.path).ToLowerInvariant() + '|start'
            if ($cdpSeen.ContainsKey($instanceKey)) {
                throw "Trusted state contains duplicate CDP instance target '$instanceKey'."
            }
            $cdpSeen[$instanceKey] = $true
        }
    }
}

function New-State {
    $identityValues = @(Get-IdentityTargetSnapshots | Where-Object { [bool]$_.existed })
    $legacyOriginal = Get-LegacyOriginalGDID
    $migratedLegacy = $false

    if ($legacyOriginal) {
        foreach ($snapshot in $identityValues) {
            $snapshot.value = $legacyOriginal
            $snapshot.kind = 'String'
            $migratedLegacy = $true
        }
    }

    $managedValues = @()
    foreach ($descriptor in @($script:PolicyDescriptors + $script:ServiceValueDescriptors)) {
        $managedValues += Get-RegistryValueSnapshot -Id $descriptor.Id -Path $descriptor.Path -Name $descriptor.Name
    }

    $state = [pscustomobject][ordered]@{
        schemaVersion = $script:CurrentStateSchema
        createdAt = (Get-Date).ToString('o')
        toolVersion = $script:ToolVersion
        userSid = $script:CurrentUserSid
        installed = $false
        migratedLegacyOriginalGDID = $migratedLegacy
        originalIdentity = [pscustomobject][ordered]@{
            values = $identityValues
        }
        originalManagedValues = $managedValues
        originalServiceRuntime = @(Get-ServiceRuntimeSnapshot)
        originalWpnInstanceValues = @(Get-WpnInstanceStartSnapshots)
        wpnInstanceBaselineSealed = $false
        originalCdpInstanceValues = @(Get-CDPInstanceStartSnapshots)
        cdpInstanceBaselineSealed = $false
    }
    Assert-TrustedState -State $state
    return $state
}


function Get-State {
    if (-not (Test-Path -LiteralPath $script:StatePath)) {
        return $null
    }

    $security = Get-TrustedStateSecurityStatus
    if (-not $security.Protected) {
        throw "State file '$($script:StatePath)' is not trusted: $($security.Detail). It was not used."
    }

    try {
        $state = Get-Content -LiteralPath $script:StatePath -Raw | ConvertFrom-Json
    } catch {
        throw "Cannot parse state file '$($script:StatePath)': $($_.Exception.Message)"
    }

    Assert-TrustedState -State $state
    return $state
}


function Save-State {
    param([Parameter(Mandatory = $true)]$State)

    Assert-Administrator
    Assert-TrustedState -State $State

    if (Test-Path -LiteralPath $script:StatePath) {
        $security = Get-TrustedStateSecurityStatus
        if (-not $security.Protected) {
            throw "Refusing to overwrite untrusted state '$($script:StatePath)': $($security.Detail)"
        }
    }

    Protect-TrustedStateStorage
    Write-JsonFileAtomic -Path $script:StatePath -InputObject $State -Depth 20
    Protect-TrustedStateFile

    # Parse and validate the exact bytes just committed.
    $null = Get-State
}


function Import-LegacyOriginalGDIDIntoState {
    param([Parameter(Mandatory = $true)]$State)

    Assert-Administrator
    Assert-TrustedState -State $State
    $legacy = Get-LegacyOriginalGDID
    if (-not $legacy) {
        return $false
    }
    if ([bool]$State.installed) {
        return $false
    }

    $currentTargets = @(Get-IdentityTargetSnapshots | Where-Object { [bool]$_.existed })
    if ($currentTargets.Count -eq 0) {
        return $false
    }

    $values = @($State.originalIdentity.values)
    foreach ($target in $currentTargets) {
        $match = @($values | Where-Object {
            ([string]$_.path).Equals([string]$target.path, [StringComparison]::OrdinalIgnoreCase) -and
            [string]$_.name -ceq [string]$target.name
        })
        if ($match.Count -eq 1) {
            $match[0].value = $legacy
            $match[0].kind = 'String'
        } elseif ($match.Count -eq 0) {
            $target.value = $legacy
            $target.kind = 'String'
            $values += $target
        } else {
            throw "Protected state contains duplicate identity target '$($target.path)\$($target.name)'."
        }
    }

    $State.originalIdentity.values = @($values)
    if (Test-ObjectProperty -InputObject $State -Name 'migratedLegacyOriginalGDID') {
        $State.migratedLegacyOriginalGDID = $true
    } else {
        $State | Add-Member -MemberType NoteProperty -Name 'migratedLegacyOriginalGDID' -Value $true
    }
    Save-State -State $State
    if (-not (Remove-LegacyOriginalGDIDFromConfig)) {
        throw 'Legacy originalGDID was imported into protected state but was unexpectedly absent during one-time consumption.'
    }
    return $true
}

function Upgrade-StateToCurrentSchema {
    param([Parameter(Mandatory = $true)]$State)

    Assert-Administrator
    Assert-TrustedState -State $State

    $schemaVersion = [int]$State.schemaVersion
    if ($schemaVersion -eq $script:CurrentStateSchema) {
        return $false
    }
    if ($schemaVersion -notin @(3, 4, 5)) {
        throw "Cannot migrate trusted state schema '$schemaVersion'."
    }

    if ($schemaVersion -eq 3) {
        # Schema 3 predates WPN. Capture WPN values before this build can modify
        # them; the older CDP and identity backups remain untouched.
        $managed = @($State.originalManagedValues)
        foreach ($descriptor in @($script:ServiceValueDescriptors | Where-Object { $_.Id -like 'Service.Wpn*' })) {
            $managed += Get-RegistryValueSnapshot -Id $descriptor.Id -Path $descriptor.Path -Name $descriptor.Name
        }
        $State.originalManagedValues = @($managed)

        $wpnInstances = @(Get-WpnInstanceStartSnapshots)
        if (Test-ObjectProperty -InputObject $State -Name 'originalWpnInstanceValues') {
            $State.originalWpnInstanceValues = $wpnInstances
        } else {
            $State | Add-Member -MemberType NoteProperty -Name 'originalWpnInstanceValues' -Value $wpnInstances
        }
        if (Test-ObjectProperty -InputObject $State -Name 'wpnInstanceBaselineSealed') {
            $State.wpnInstanceBaselineSealed = $false
        } else {
            $State | Add-Member -MemberType NoteProperty -Name 'wpnInstanceBaselineSealed' -Value $false
        }
    }

    if ($schemaVersion -lt 5) {
        # Schema 4 added WPN but did not preserve individual CDPUserSvc_* Start
        # values. An already-installed older build may have written Start=4, so
        # never mislabel those live values as the original baseline.
        $cdpInstances = if ([bool]$State.installed) {
            @()
        } else {
            @(Get-CDPInstanceStartSnapshots)
        }
        $cdpBaselineSealed = [bool]$State.installed
        if (Test-ObjectProperty -InputObject $State -Name 'originalCdpInstanceValues') {
            $State.originalCdpInstanceValues = $cdpInstances
        } else {
            $State | Add-Member -MemberType NoteProperty -Name 'originalCdpInstanceValues' -Value $cdpInstances
        }
        if (Test-ObjectProperty -InputObject $State -Name 'cdpInstanceBaselineSealed') {
            $State.cdpInstanceBaselineSealed = $cdpBaselineSealed
        } else {
            $State | Add-Member -MemberType NoteProperty -Name 'cdpInstanceBaselineSealed' -Value $cdpBaselineSealed
        }
    }

    # Telemetry management is new in schema 6. Capture every newly compiled
    # policy/service target before any telemetry change. The ID comparison also
    # makes migration robust if an intermediate build captured only part of the
    # new descriptor set.
    $managedValues = @($State.originalManagedValues)
    $managedIds = @{}
    foreach ($snapshot in $managedValues) {
        $managedIds[[string]$snapshot.id] = $true
    }
    foreach ($descriptor in @(Get-ManagedDescriptorsForStateSchema -SchemaVersion $script:CurrentStateSchema)) {
        if (-not $managedIds.ContainsKey([string]$descriptor.Id)) {
            $managedValues += Get-RegistryValueSnapshot -Id $descriptor.Id -Path $descriptor.Path -Name $descriptor.Name
            $managedIds[[string]$descriptor.Id] = $true
        }
    }
    $State.originalManagedValues = @($managedValues)

    # Add runtime entries newly supported by later schemas without disturbing
    # prior wasRunning snapshots. DiagTrack/dmwappushservice were never managed
    # by schemas 3-5, so their current states are trustworthy migration inputs.
    $runtime = @($State.originalServiceRuntime)
    $runtimeNames = @{}
    foreach ($entry in $runtime) {
        $runtimeNames[[string]$entry.name] = $true
    }
    foreach ($entry in @(Get-ServiceRuntimeSnapshot)) {
        $name = [string]$entry.name
        $eligible = $name -ceq 'CDPUserSvc' -or
                    $name -ceq 'WpnService' -or $name -ceq 'WpnUserService' -or
                    $name -match '^WpnUserService_[A-Za-z0-9]+$' -or
                    $name -ceq 'DiagTrack' -or $name -ceq 'dmwappushservice'
        if ($eligible -and -not $runtimeNames.ContainsKey($name)) {
            $runtime += $entry
            $runtimeNames[$name] = $true
        }
    }
    $State.originalServiceRuntime = @($runtime)

    $State.schemaVersion = $script:CurrentStateSchema
    if (Test-ObjectProperty -InputObject $State -Name 'toolVersion') {
        $State.toolVersion = $script:ToolVersion
    } else {
        $State | Add-Member -MemberType NoteProperty -Name 'toolVersion' -Value $script:ToolVersion
    }

    Save-State -State $State
    return $true
}

function Ensure-State {
    Assert-Administrator

    if (Test-Path -LiteralPath $script:StatePath) {
        $state = Get-State
        $priorSchema = [int]$state.schemaVersion
        if (Upgrade-StateToCurrentSchema -State $state) {
            Write-Ok "Migrated protected reversible state from schema $priorSchema to $($script:CurrentStateSchema) and captured newly managed service-instance state before modification."
            $state = Get-State
        }
        if (Import-LegacyOriginalGDIDIntoState -State $state) {
            Write-Info 'Imported a pending legacy originalGDID into protected state and removed the user-writable legacy copy.'
        } elseif ([bool](Get-ObjectPropertyValue -InputObject $state -Name 'migratedLegacyOriginalGDID' -Default $false) -and
                  (Remove-LegacyOriginalGDIDFromConfig)) {
            Write-Info 'Removed a stale legacy originalGDID field because its protected import was already complete.'
        } elseif ((Get-LegacyOriginalGDID) -and [bool]$state.installed) {
            Write-Warn 'A legacy originalGDID remains in configuration but was not imported because installation is already complete. It is retained for a future uninstall/reinstall migration.'
        }
        return $state
    }

    Protect-TrustedStateStorage
    $state = New-State
    Save-State -State $state
    Write-Ok "Created protected reversible state backup at $($script:StatePath)"
    if ([bool]$state.migratedLegacyOriginalGDID) {
        if (-not (Remove-LegacyOriginalGDIDFromConfig)) {
            throw 'Legacy originalGDID was imported into protected state but was unexpectedly absent during one-time consumption.'
        }
        Write-Info 'Imported the legacy originalGDID backup into protected state and removed the user-writable legacy copy. Token restoration is necessarily best-effort because the legacy tool stored only one original value.'
    }
    if ($script:LegacyUntrustedStatePath -and
        (Test-Path -LiteralPath $script:LegacyUntrustedStatePath) -and
        -not $script:LegacyUntrustedStatePath.Equals($script:RuntimePath, [StringComparison]::OrdinalIgnoreCase)) {
        Write-Warn "Ignored obsolete user-writable state at '$($script:LegacyUntrustedStatePath)'."
    }
    return $state
}


function Get-ManagedSnapshot {
    param(
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)][string]$Id
    )

    $matches = @($State.originalManagedValues | Where-Object { [string]$_.id -ceq $Id })
    if ($matches.Count -ne 1) {
        throw "Trusted state does not contain exactly one managed snapshot '$Id'."
    }
    return $matches[0]
}


function Update-IdentityBackupsForNewTargets {
    param(
        [Parameter(Mandatory = $true)]$State,
        [AllowNull()][string]$KnownFakeValue
    )

    Assert-Administrator
    Assert-TrustedState -State $State
    $values = @($State.originalIdentity.values)
    $added = 0

    # Once a completed install has written a mask, an unfamiliar value cannot
    # be proved to be an original rather than a previously masked copy. Never
    # promote such a value into the trusted restoration baseline. Uninstall and
    # reinstall after authoritative values have been restored to capture newly
    # created token targets safely.
    if ([bool]$State.installed) {
        $unbacked = @()
        foreach ($target in @(Get-IdentityTargetSnapshots | Where-Object { [bool]$_.existed })) {
            $found = $false
            foreach ($saved in $values) {
                if (([string]$saved.path).Equals([string]$target.path, [StringComparison]::OrdinalIgnoreCase) -and
                    [string]$saved.name -ceq [string]$target.name) {
                    $found = $true
                    break
                }
            }
            if (-not $found) {
                $unbacked += "$($target.path)\$($target.name)"
            }
        }
        if ($unbacked.Count -gt 0) {
            Write-Warn "Found unbacked identity target(s) after installation and left them untouched: $($unbacked -join ', ')"
            Write-Info 'To adopt them safely, uninstall first so backed originals are restored, then run install again.'
        }
        return 0
    }

    foreach ($target in @(Get-IdentityTargetSnapshots | Where-Object { [bool]$_.existed })) {
        $found = $false
        foreach ($saved in $values) {
            $samePath = ([string]$saved.path).Equals([string]$target.path, [StringComparison]::OrdinalIgnoreCase)
            $sameName = [string]$saved.name -ceq [string]$target.name
            if ($samePath -and $sameName) {
                $found = $true
                break
            }
        }
        if ($found) {
            continue
        }

        if ($KnownFakeValue -and
            ([string]$target.value).Equals($KnownFakeValue, [StringComparison]::OrdinalIgnoreCase)) {
            Write-Warn "Did not back up newly discovered target '$($target.path)\$($target.name)' because it already contains the last local mask."
            continue
        }

        $values += $target
        $added++
    }

    $State.originalIdentity.values = @($values)
    Assert-TrustedState -State $State
    return $added
}

function Update-CDPInstanceBackupsForNewTargets {
    param([Parameter(Mandatory = $true)]$State)

    Assert-Administrator
    Assert-TrustedState -State $State
    if ([int]$State.schemaVersion -lt 5) {
        throw 'CDP instance backups require trusted-state schema 5 or newer.'
    }

    # Capture exact live-instance Start values only before the first CDP
    # modification. Any suffix created after the baseline is sealed is restored
    # from the protected CDPUserSvc template instead of being mistaken for an
    # original per-instance customization.
    if ([bool]$State.installed -or [bool]$State.cdpInstanceBaselineSealed) {
        return 0
    }

    $values = @($State.originalCdpInstanceValues)
    $added = 0
    foreach ($target in @(Get-CDPInstanceStartSnapshots)) {
        $found = $false
        foreach ($saved in $values) {
            if (([string]$saved.path).Equals([string]$target.path, [StringComparison]::OrdinalIgnoreCase) -and
                [string]$saved.name -ceq [string]$target.name) {
                $found = $true
                break
            }
        }
        if ($found) {
            continue
        }

        $values += $target
        $added++
    }

    $State.originalCdpInstanceValues = @($values)
    Assert-TrustedState -State $State
    return $added
}

function Update-WpnInstanceBackupsForNewTargets {
    param([Parameter(Mandatory = $true)]$State)

    Assert-Administrator
    Assert-TrustedState -State $State
    if ([int]$State.schemaVersion -lt 4) {
        throw 'WPN instance backups require trusted-state schema 4 or newer.'
    }

    # Per-user service instances are ephemeral derivatives of the template.
    # Capture exact instance Start values only before the first completed
    # installation (or during schema migration). Never promote a later instance
    # into the original baseline: it may already reflect this tool's controls.
    if ([bool]$State.installed -or [bool]$State.wpnInstanceBaselineSealed) {
        return 0
    }

    $values = @($State.originalWpnInstanceValues)
    $added = 0
    $staticStatus = Get-WpnBlockStatus

    foreach ($target in @(Get-WpnInstanceStartSnapshots)) {
        $found = $false
        foreach ($saved in $values) {
            if (([string]$saved.path).Equals([string]$target.path, [StringComparison]::OrdinalIgnoreCase) -and
                [string]$saved.name -ceq [string]$target.name) {
                $found = $true
                break
            }
        }
        if ($found) {
            continue
        }

        # If a previous partial install already disabled the template, a new
        # Start=4 instance is not a trustworthy pre-install baseline. It will be
        # restored from the backed-up template value instead.
        if ($staticStatus.StaticControlsDisabled -and
            (Test-RegistrySnapshotHasValue -Snapshot $target -Kind 'DWord' -ExpectedValue 4)) {
            continue
        }

        $values += $target
        $added++
    }

    $State.originalWpnInstanceValues = @($values)
    Assert-TrustedState -State $State
    return $added
}

function Get-RuntimeState {
    if (-not (Test-Path -LiteralPath $script:RuntimePath)) {
        return $null
    }

    try {
        $raw = Get-Content -LiteralPath $script:RuntimePath -Raw | ConvertFrom-Json
    } catch {
        return [pscustomobject]@{
            lastOperation = 'unknown'
            lastRotation = $null
            lastFakeGDID = $null
            lastResult = "Runtime-state parse error: $($_.Exception.Message)"
            lastDiagnosticDeleteAttempt = $null
            lastDiagnosticDeleteAccepted = $null
            lastDiagnosticDeleteResult = $null
        }
    }

    $fake = [string](Get-ObjectPropertyValue -InputObject $raw -Name 'lastFakeGDID')
    if ($fake -and -not (Test-ValidGDID $fake)) {
        $fake = $null
    }
    $result = [string](Get-ObjectPropertyValue -InputObject $raw -Name 'lastResult')
    if ($result.Length -gt 512) {
        $result = $result.Substring(0, 512)
    }
    $deleteResult = [string](Get-ObjectPropertyValue -InputObject $raw -Name 'lastDiagnosticDeleteResult')
    if ($deleteResult.Length -gt 512) {
        $deleteResult = $deleteResult.Substring(0, 512)
    }
    $deleteAcceptedRaw = Get-ObjectPropertyValue -InputObject $raw -Name 'lastDiagnosticDeleteAccepted'
    $deleteAccepted = if ($deleteAcceptedRaw -is [bool]) { [bool]$deleteAcceptedRaw } else { $null }

    return [pscustomobject]@{
        lastOperation = [string](Get-ObjectPropertyValue -InputObject $raw -Name 'lastOperation')
        lastRotation = [string](Get-ObjectPropertyValue -InputObject $raw -Name 'lastRotation')
        lastFakeGDID = $fake
        lastResult = $result
        lastDiagnosticDeleteAttempt = [string](Get-ObjectPropertyValue -InputObject $raw -Name 'lastDiagnosticDeleteAttempt')
        lastDiagnosticDeleteAccepted = $deleteAccepted
        lastDiagnosticDeleteResult = $deleteResult
    }
}

function Save-RuntimeState {
    param(
        [Parameter(Mandatory = $true)][string]$Operation,
        [AllowNull()][string]$LastFakeGDID,
        [Parameter(Mandatory = $true)][string]$Result,
        [bool]$IsRotation
    )

    if ($LastFakeGDID -and -not (Test-ValidGDID $LastFakeGDID)) {
        throw "Refusing to save invalid runtime GDID '$LastFakeGDID'."
    }
    if ($Result.Length -gt 512) {
        $Result = $Result.Substring(0, 512)
    }

    $previous = Get-RuntimeState
    $lastRotation = if ($IsRotation) {
        (Get-Date).ToString('o')
    } elseif ($null -ne $previous) {
        $previous.lastRotation
    } else {
        $null
    }

    $runtime = [ordered]@{
        schemaVersion = 2
        lastOperation = $Operation
        lastRotation = $lastRotation
        lastFakeGDID = $LastFakeGDID
        lastResult = $Result
        lastDiagnosticDeleteAttempt = if ($null -ne $previous) { $previous.lastDiagnosticDeleteAttempt } else { $null }
        lastDiagnosticDeleteAccepted = if ($null -ne $previous) { $previous.lastDiagnosticDeleteAccepted } else { $null }
        lastDiagnosticDeleteResult = if ($null -ne $previous) { $previous.lastDiagnosticDeleteResult } else { $null }
    }
    Write-JsonFileAtomic -Path $script:RuntimePath -InputObject $runtime
}

function Save-DiagnosticDeleteRuntimeState {
    param(
        [Parameter(Mandatory = $true)][bool]$Accepted,
        [Parameter(Mandatory = $true)][string]$Result
    )

    if ($Result.Length -gt 512) {
        $Result = $Result.Substring(0, 512)
    }
    $previous = Get-RuntimeState
    $runtime = [ordered]@{
        schemaVersion = 2
        lastOperation = if ($null -ne $previous -and $previous.lastOperation) { $previous.lastOperation } else { 'diagnostic-delete' }
        lastRotation = if ($null -ne $previous) { $previous.lastRotation } else { $null }
        lastFakeGDID = if ($null -ne $previous) { $previous.lastFakeGDID } else { $null }
        lastResult = if ($null -ne $previous -and $previous.lastResult) { $previous.lastResult } else { 'Diagnostic-data deletion request attempted.' }
        lastDiagnosticDeleteAttempt = (Get-Date).ToString('o')
        lastDiagnosticDeleteAccepted = $Accepted
        lastDiagnosticDeleteResult = $Result
    }
    Write-JsonFileAtomic -Path $script:RuntimePath -InputObject $runtime
}

function Remove-RuntimeState {
    Remove-Item -LiteralPath $script:RuntimePath -Force -ErrorAction SilentlyContinue
    if ((Test-Path -LiteralPath $script:RuntimeDirectory) -and
        @(Get-ChildItem -LiteralPath $script:RuntimeDirectory -Force -ErrorAction SilentlyContinue).Count -eq 0) {
        Remove-Item -LiteralPath $script:RuntimeDirectory -Force -ErrorAction SilentlyContinue
    }
}


# -----------------------------------------------------------------------------
# GDID inspection, local masking, and restoration
# -----------------------------------------------------------------------------

function Get-CurrentIdentityValues {
    $values = @()
    foreach ($snapshot in @(Get-IdentityTargetSnapshots)) {
        if ([bool]$snapshot.existed) {
            $text = [string]$snapshot.value
            $values += [pscustomobject]@{
                id = [string]$snapshot.id
                path = [string]$snapshot.path
                name = [string]$snapshot.name
                value = $text
                valid = (Test-ValidGDID $text)
            }
        }
    }
    return $values
}

function Convert-GDIDToDecimalText {
    param([Parameter(Mandatory = $true)][string]$Hex)

    [uint64]$number = 0
    $parsed = [uint64]::TryParse(
        $Hex,
        [Globalization.NumberStyles]::HexNumber,
        [Globalization.CultureInfo]::InvariantCulture,
        [ref]$number
    )
    if (-not $parsed) {
        return '(invalid hexadecimal value)'
    }
    return "g:$number"
}

function New-FakeGDID {
    $bytes = New-Object byte[] 6
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }

    $suffix = ([BitConverter]::ToString($bytes)).Replace('-', '')
    return ('0018' + $suffix).ToUpperInvariant()
}

function Restore-IdentitySnapshotsAfterFailedMask {
    param(
        [Parameter(Mandatory = $true)][object[]]$Snapshots,
        [Parameter(Mandatory = $true)][string]$ExpectedMaskValue
    )

    if (-not (Test-ValidGDID $ExpectedMaskValue)) {
        throw "Refusing rollback with invalid expected mask '$ExpectedMaskValue'."
    }

    $problems = @()
    foreach ($snapshot in @($Snapshots)) {
        $path = [string]$snapshot.path
        $name = [string]$snapshot.name
        if (-not (Test-IdentitySnapshotTarget -Id ([string]$snapshot.id) -Path $path -Name $name)) {
            $problems += "invalid target $path\$name"
            continue
        }

        $current = Get-RegistryValueSnapshot -Id 'mask-rollback-current' -Path $path -Name $name
        if (-not [bool]$current.existed) {
            # Ephemeral token values can disappear during the operation. Do not
            # recreate a key or value solely for rollback.
            continue
        }

        $alreadyPrevious = [string]$current.kind -ceq [string]$snapshot.kind -and
                           (Test-RegistryValuesEqual `
                               -Expected $snapshot.value `
                               -Actual $current.value `
                               -Kind ([string]$snapshot.kind))
        if ($alreadyPrevious) {
            continue
        }

        $isExpectedMask = [string]$current.kind -ceq 'String' -and
                          ([string]$current.value).Equals($ExpectedMaskValue, [StringComparison]::OrdinalIgnoreCase)
        if (-not $isExpectedMask) {
            $problems += "$path\$name changed concurrently"
            continue
        }

        try {
            $null = Restore-ExistingRegistrySnapshot `
                -Snapshot $snapshot `
                -ExpectedPath $path `
                -ExpectedName $name
        } catch {
            $problems += "${path}\${name}: $($_.Exception.Message)"
        }
    }

    if ($problems.Count -gt 0) {
        throw "Identity rollback could not safely reconcile: $($problems -join '; ')"
    }
}

function Set-LocalGDIDMask {
    param(
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)][string]$NewValue,
        [AllowNull()][string]$KnownMaskValue
    )

    if (-not (Test-ValidGDID $NewValue)) {
        throw "Refusing to write invalid GDID value '$NewValue'."
    }
    if ($KnownMaskValue -and -not (Test-ValidGDID $KnownMaskValue)) {
        throw "Refusing to trust invalid prior mask value '$KnownMaskValue'."
    }
    Assert-TrustedState -State $State

    $backups = @($State.originalIdentity.values)
    $targets = @()
    $unbacked = @()
    $conflicts = @()

    foreach ($current in @(Get-IdentityTargetSnapshots | Where-Object { [bool]$_.existed })) {
        $matches = @($backups | Where-Object {
            ([string]$_.path).Equals([string]$current.path, [StringComparison]::OrdinalIgnoreCase) -and
            [string]$_.name -ceq [string]$current.name -and
            [bool]$_.existed
        })
        if ($matches.Count -ne 1) {
            $unbacked += "$($current.path)\$($current.name)"
            continue
        }

        $original = $matches[0]
        $currentIsString = [string]$current.kind -ceq 'String'
        $matchesOriginal = $currentIsString -and
                           ([string]$current.value).Equals(
                               [string]$original.value,
                               [StringComparison]::OrdinalIgnoreCase
                           )
        $matchesKnownMask = $currentIsString -and $KnownMaskValue -and
                            ([string]$current.value).Equals(
                                $KnownMaskValue,
                                [StringComparison]::OrdinalIgnoreCase
                            )

        # A different current value may represent genuine Microsoft
        # reprovisioning, another administrator's change, or concurrent
        # identity maintenance. Never overwrite it and later restore a stale
        # original merely because the registry path was backed up long ago.
        if (-not $matchesOriginal -and -not $matchesKnownMask) {
            $conflicts += "$($current.path)\$($current.name)"
            continue
        }

        # Keep the immediately preceding value, not merely the original install
        # snapshot. It enables transactional rollback if one write,
        # verification, or runtime-state commit fails.
        $targets += $current
    }

    # A partial identity mask is both misleading and less effective. Fail
    # before the first write if any existing target is unbacked or has changed
    # independently since the protected baseline/last recorded mask.
    $preflightProblems = @()
    if ($unbacked.Count -gt 0) {
        $preflightProblems += "unbacked targets: $($unbacked -join ', ')"
    }
    if ($conflicts.Count -gt 0) {
        $preflightProblems += "independently changed targets: $($conflicts -join ', ')"
    }
    if ($preflightProblems.Count -gt 0) {
        throw "Refusing a partial or stale local GDID mask; $($preflightProblems -join '; '). Uninstall/reconcile first so current authoritative changes are not overwritten."
    }

    $written = @()
    try {
        foreach ($target in $targets) {
            $didWrite = Set-ExistingRegistryValue `
                -Path ([string]$target.path) `
                -Name ([string]$target.name) `
                -Value $NewValue `
                -Kind 'String'
            if (-not $didWrite) {
                throw "Identity target disappeared during masking: $($target.path)\$($target.name)"
            }
            $written += $target
        }

        $failures = @()
        foreach ($target in $targets) {
            $actual = Get-RegistryValueSnapshot -Id 'verify' -Path ([string]$target.path) -Name ([string]$target.name)
            if (-not [bool]$actual.existed -or
                [string]$actual.kind -cne 'String' -or
                -not ([string]$actual.value).Equals($NewValue, [StringComparison]::OrdinalIgnoreCase)) {
                $failures += "$($target.path)\$($target.name)"
            }
        }
        if ($failures.Count -gt 0) {
            throw "Local GDID write verification failed for: $($failures -join ', ')"
        }
    } catch {
        $writeError = $_.Exception.Message
        try {
            Restore-IdentitySnapshotsAfterFailedMask -Snapshots @($written) -ExpectedMaskValue $NewValue
        } catch {
            throw "Local GDID masking failed and rollback was incomplete. Write error: $writeError; rollback error: $($_.Exception.Message)"
        }
        throw "Local GDID masking failed; all still-existing values written by this attempt were rolled back. $writeError"
    }

    return [pscustomobject]@{
        Wrote = ($targets.Count -gt 0)
        Count = $targets.Count
        PreviousValues = @($targets)
    }
}


function Restore-IdentityPlanAfterFailedOriginalRestore {
    param([Parameter(Mandatory = $true)][object[]]$WrittenPlans)

    $problems = @()
    $reversed = @($WrittenPlans)
    [array]::Reverse($reversed)
    foreach ($plan in $reversed) {
        $previous = $plan.Previous
        $original = $plan.Original
        $path = [string]$previous.path
        $name = [string]$previous.name

        $current = Get-RegistryValueSnapshot -Id 'restore-rollback-current' -Path $path -Name $name
        if (-not [bool]$current.existed) {
            $problems += "$path\$name disappeared during rollback"
            continue
        }

        $alreadyPrevious = [string]$current.kind -ceq [string]$previous.kind -and
                           (Test-RegistryValuesEqual `
                               -Expected $previous.value `
                               -Actual $current.value `
                               -Kind ([string]$previous.kind))
        if ($alreadyPrevious) {
            continue
        }

        $stillOriginal = [string]$current.kind -ceq [string]$original.kind -and
                         (Test-RegistryValuesEqual `
                             -Expected $original.value `
                             -Actual $current.value `
                             -Kind ([string]$original.kind))
        if (-not $stillOriginal) {
            $problems += "$path\$name changed concurrently"
            continue
        }

        try {
            $didWrite = Restore-ExistingRegistrySnapshot `
                -Snapshot $previous `
                -ExpectedPath $path `
                -ExpectedName $name
            if (-not $didWrite) {
                $problems += "$path\$name disappeared during rollback"
            }
        } catch {
            $problems += "${path}\${name}: $($_.Exception.Message)"
        }
    }

    if ($problems.Count -gt 0) {
        throw "Identity restoration rollback could not safely reconcile: $($problems -join '; ')"
    }
}

function Restore-OriginalIdentity {
    param(
        [Parameter(Mandatory = $true)]$State,
        [AllowNull()][string]$KnownMaskValue
    )

    Assert-TrustedState -State $State
    if ($KnownMaskValue -and -not (Test-ValidGDID $KnownMaskValue)) {
        $KnownMaskValue = $null
    }

    $conflicts = @()
    $restorePlans = @()
    $alreadyOriginal = 0
    $gone = 0
    $backups = @($State.originalIdentity.values)
    $currentTargets = @(Get-IdentityTargetSnapshots | Where-Object { [bool]$_.existed })
    $currentByKey = @{}
    foreach ($current in $currentTargets) {
        $key = ([string]$current.path).ToLowerInvariant() + '|' + ([string]$current.name).ToLowerInvariant()
        if ($currentByKey.ContainsKey($key)) {
            throw "Current identity discovery returned duplicate target '$key'."
        }
        $currentByKey[$key] = $current
    }

    $backupKeys = @{}
    foreach ($snapshot in $backups) {
        $path = [string]$snapshot.path
        $name = [string]$snapshot.name
        if (-not (Test-IdentitySnapshotTarget -Id ([string]$snapshot.id) -Path $path -Name $name)) {
            throw "Refusing invalid identity restore target '$path\$name'."
        }

        $key = $path.ToLowerInvariant() + '|' + $name.ToLowerInvariant()
        $backupKeys[$key] = $true
        $current = if ($currentByKey.ContainsKey($key)) { $currentByKey[$key] } else { $null }
        if ($null -eq $current) {
            # The tool only masked values that existed. If an ephemeral token key
            # or value has since disappeared, recreating it would be harmful.
            $gone++
            continue
        }

        $originalMatches = [string]$current.kind -ceq [string]$snapshot.kind -and
                           (Test-RegistryValuesEqual `
                               -Expected $snapshot.value `
                               -Actual $current.value `
                               -Kind ([string]$snapshot.kind))
        if ($originalMatches) {
            $alreadyOriginal++
            continue
        }

        $knownMaskMatches = $KnownMaskValue -and
                            [string]$current.kind -ceq 'String' -and
                            ([string]$current.value).Equals($KnownMaskValue, [StringComparison]::OrdinalIgnoreCase)
        if (-not $knownMaskMatches) {
            $conflicts += "$path\$name (current value no longer matches the last recorded local mask)"
            continue
        }

        $restorePlans += [pscustomobject]@{
            Original = $snapshot
            Previous = $current
        }
    }

    # If restoration would write any backed target, inspect currently existing
    # targets that were created after the protected baseline. Leaving an
    # unbacked copy at a different identity while restoring older copies would
    # create a mixed/stale identity state. It is safe to leave such a target only
    # when every protected original has one identical String value and the new
    # target already contains that same value.
    if ($restorePlans.Count -gt 0) {
        $originalTexts = @($backups | Where-Object {
            [bool]$_.existed -and [string]$_.kind -ceq 'String'
        } | ForEach-Object {
            ([string]$_.value).ToUpperInvariant()
        } | Sort-Object -Unique)

        foreach ($current in $currentTargets) {
            $key = ([string]$current.path).ToLowerInvariant() + '|' + ([string]$current.name).ToLowerInvariant()
            if ($backupKeys.ContainsKey($key)) {
                continue
            }

            $safeUnbackedOriginal = $originalTexts.Count -eq 1 -and
                                    [string]$current.kind -ceq 'String' -and
                                    ([string]$current.value).Equals($originalTexts[0], [StringComparison]::OrdinalIgnoreCase)
            if (-not $safeUnbackedOriginal) {
                $conflicts += "$($current.path)\$($current.name) (unbacked current target would remain inconsistent with the protected restoration baseline)"
            }
        }
    }

    if ($conflicts.Count -gt 0) {
        throw "Refusing to overwrite identity value(s) that changed outside this tool or would leave a mixed identity state: $($conflicts -join '; '). No identity value was restored, and the protected backup was retained."
    }

    $writtenPlans = @()
    try {
        foreach ($plan in $restorePlans) {
            $snapshot = $plan.Original
            $didWrite = Set-ExistingRegistryValue `
                -Path ([string]$snapshot.path) `
                -Name ([string]$snapshot.name) `
                -Value $snapshot.value `
                -Kind ([string]$snapshot.kind)
            if (-not $didWrite) {
                throw "Identity target disappeared during restoration: $($snapshot.path)\$($snapshot.name)"
            }
            $writtenPlans += $plan
        }
    } catch {
        $restoreError = $_.Exception.Message
        try {
            Restore-IdentityPlanAfterFailedOriginalRestore -WrittenPlans @($writtenPlans)
        } catch {
            throw "Identity restoration failed and rollback to the immediately preceding mask was incomplete. Restore error: $restoreError; rollback error: $($_.Exception.Message)"
        }
        throw "Identity restoration failed; all still-existing values restored by this attempt were rolled back to the immediately preceding mask. $restoreError"
    }

    Write-Ok "Identity rollback complete: restored=$($restorePlans.Count), already-original=$alreadyOriginal, disappeared=$gone."
}


function Restore-LegacyOriginalIdentity {
    param([AllowNull()][string]$KnownMaskValue)

    $legacy = Get-LegacyOriginalGDID
    if (-not $legacy) {
        return $false
    }
    if ($KnownMaskValue -and -not (Test-ValidGDID $KnownMaskValue)) {
        $KnownMaskValue = $null
    }

    $targets = @(Get-IdentityTargetSnapshots | Where-Object { [bool]$_.existed })
    $plans = @()
    $conflicts = @()
    $alreadyOriginal = 0

    foreach ($current in $targets) {
        $isString = [string]$current.kind -ceq 'String'
        if ($isString -and
            ([string]$current.value).Equals($legacy, [StringComparison]::OrdinalIgnoreCase)) {
            $alreadyOriginal++
            continue
        }

        $isKnownMask = $KnownMaskValue -and $isString -and
                       ([string]$current.value).Equals($KnownMaskValue, [StringComparison]::OrdinalIgnoreCase)
        if ($isKnownMask) {
            $plans += $current
        } else {
            $conflicts += "$($current.path)\$($current.name)"
        }
    }

    if ($conflicts.Count -gt 0) {
        $maskNote = if ($KnownMaskValue) {
            "the recorded mask '$KnownMaskValue'"
        } else {
            'no trustworthy last-mask value is available'
        }
        throw "The legacy originalGDID backup cannot be restored safely because current target(s) do not equal either the legacy original or ${maskNote}: $($conflicts -join ', '). No identity value was changed."
    }

    $written = @()
    try {
        foreach ($current in $plans) {
            $didWrite = Set-ExistingRegistryValue `
                -Path ([string]$current.path) `
                -Name ([string]$current.name) `
                -Value $legacy `
                -Kind 'String'
            if (-not $didWrite) {
                throw "Legacy identity target disappeared during restoration: $($current.path)\$($current.name)"
            }
            $written += $current
        }
    } catch {
        $restoreError = $_.Exception.Message
        try {
            Restore-IdentitySnapshotsAfterFailedMask `
                -Snapshots @($written) `
                -ExpectedMaskValue $legacy
        } catch {
            throw "Legacy identity restoration failed and rollback was incomplete. Restore error: $restoreError; rollback error: $($_.Exception.Message)"
        }
        throw "Legacy identity restoration failed; all still-existing values changed by this attempt were rolled back. $restoreError"
    }

    if ($plans.Count -gt 0) {
        Write-Ok "Safely restored legacy originalGDID in $($plans.Count) target(s); already-original=$alreadyOriginal."
    } else {
        Write-Ok "All current identity targets already equal the legacy originalGDID; no registry write was needed."
    }
    return $true
}


# -----------------------------------------------------------------------------
# Policies and Connected Devices Platform service control
# -----------------------------------------------------------------------------

function Get-WindowsPlatformProfile {
    # Under StrictMode, directly reading an undefined script-scope variable can
    # throw even when it appears in the right-hand side of an -and expression.
    $cachedProfile = Get-Variable -Name 'WindowsPlatformProfile' -Scope Script -ErrorAction SilentlyContinue
    if ($null -ne $cachedProfile -and $null -ne $cachedProfile.Value) {
        return $cachedProfile.Value
    }

    $path = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $current = Get-ItemProperty -LiteralPath $path -ErrorAction Stop

    $buildText = [string](Get-ObjectPropertyValue -InputObject $current -Name 'CurrentBuildNumber')
    if ([string]::IsNullOrWhiteSpace($buildText)) {
        $buildText = [string](Get-ObjectPropertyValue -InputObject $current -Name 'CurrentBuild')
    }
    $build = 0
    if (-not [int]::TryParse($buildText, [ref]$build) -or $build -lt 1) {
        throw "Could not determine the Windows build from $path."
    }

    $editionId = [string](Get-ObjectPropertyValue -InputObject $current -Name 'EditionID')
    $productName = [string](Get-ObjectPropertyValue -InputObject $current -Name 'ProductName')
    $displayVersion = [string](Get-ObjectPropertyValue -InputObject $current -Name 'DisplayVersion')
    $installationType = [string](Get-ObjectPropertyValue -InputObject $current -Name 'InstallationType')
    $isServer = $installationType -match '(?i)server' -or $productName -match '(?i)server'
    $isWindows11 = (-not $isServer) -and $build -ge 22000
    $family = if ($isServer) {
        'Windows Server'
    } elseif ($isWindows11) {
        'Windows 11'
    } else {
        'Windows 10'
    }

    # Microsoft documents diagnostic-data value 0 as supported only on
    # Enterprise, Education, IoT Enterprise, and Server. Be conservative for
    # unknown/consumer editions: their supported minimum is value 1.
    $supportsDiagnosticDataOff = $isServer -or
        $editionId -match '^(?i:Enterprise|EnterpriseS|EnterpriseSN|Education|EducationN|IoTEnterprise|IoTEnterpriseS)'
    $minimum = if ($supportsDiagnosticDataOff) { 0 } else { 1 }
    $minimumName = if ($minimum -eq 0) { 'Diagnostic data off' } else { 'Required diagnostic data' }
    # The registry-backed policy remains AllowTelemetry on every supported
    # release. Microsoft documents the visible Group Policy label as "Allow
    # Telemetry" on Windows 10 and older Server releases, and "Allow Diagnostic
    # Data" on Windows 11 and Windows Server 2022+. Report that expected label
    # while also showing the stable registry value.
    $policyDisplayName = if ($isWindows11 -or ($isServer -and $build -ge 20348)) {
        'Allow Diagnostic Data (registry value: AllowTelemetry)'
    } else {
        'Allow Telemetry (registry value: AllowTelemetry)'
    }

    $script:WindowsPlatformProfile = [pscustomobject]@{
        Family = $family
        Build = $build
        EditionId = $editionId
        ProductName = $productName
        DisplayVersion = $displayVersion
        InstallationType = $installationType
        IsServer = [bool]$isServer
        IsWindows11 = [bool]$isWindows11
        SupportsDiagnosticDataOff = [bool]$supportsDiagnosticDataOff
        MinimumDiagnosticDataValue = [uint32]$minimum
        MinimumDiagnosticDataName = $minimumName
        DiagnosticPolicyDisplayName = $policyDisplayName
    }
    return $script:WindowsPlatformProfile
}

function Get-PolicyApplicability {
    param([Parameter(Mandatory = $true)]$Descriptor)

    $profile = Get-WindowsPlatformProfile
    $minimumBuildRaw = Get-ObjectPropertyValue -InputObject $Descriptor -Name 'MinimumBuild'
    $minimumClientBuildRaw = Get-ObjectPropertyValue -InputObject $Descriptor -Name 'MinimumClientBuild'
    $minimumServerBuildRaw = Get-ObjectPropertyValue -InputObject $Descriptor -Name 'MinimumServerBuild'
    $requiredBuild = if ([bool]$profile.IsServer -and $null -ne $minimumServerBuildRaw) {
        [int]$minimumServerBuildRaw
    } elseif (-not [bool]$profile.IsServer -and $null -ne $minimumClientBuildRaw) {
        [int]$minimumClientBuildRaw
    } elseif ($null -ne $minimumBuildRaw) {
        [int]$minimumBuildRaw
    } else {
        $null
    }
    if ($null -ne $requiredBuild -and [int]$profile.Build -lt [int]$requiredBuild) {
        $targetType = if ([bool]$profile.IsServer) { 'Windows Server' } else { 'Windows client' }
        return [pscustomobject]@{
            Applicable = $false
            Reason = "requires $targetType build $requiredBuild or newer"
        }
    }

    $clientOnly = [bool](Get-ObjectPropertyValue -InputObject $Descriptor -Name 'ClientOnly' -Default $false)
    if ($clientOnly -and [bool]$profile.IsServer) {
        return [pscustomobject]@{
            Applicable = $false
            Reason = 'client-only setting is not applicable to Windows Server'
        }
    }

    return [pscustomobject]@{
        Applicable = $true
        Reason = 'applicable'
    }
}

function Get-PolicyDesiredValue {
    param([Parameter(Mandatory = $true)]$Descriptor)

    $resolver = [string](Get-ObjectPropertyValue -InputObject $Descriptor -Name 'DesiredValueResolver')
    if ($resolver -ceq 'MinimumDiagnosticData') {
        return [uint32](Get-WindowsPlatformProfile).MinimumDiagnosticDataValue
    }
    if ($resolver) {
        throw "Unknown policy desired-value resolver '$resolver' for '$($Descriptor.Id)'."
    }
    return Get-ObjectPropertyValue -InputObject $Descriptor -Name 'DesiredValue'
}

function Get-PolicyDescriptor {
    param([Parameter(Mandatory = $true)][string]$Id)

    foreach ($descriptor in $script:PolicyDescriptors) {
        if ($descriptor.Id -eq $Id) {
            return $descriptor
        }
    }
    throw "Internal policy descriptor '$Id' was not found."
}

function Set-PolicyEnabled {
    param([Parameter(Mandatory = $true)]$Descriptor)

    $applicability = Get-PolicyApplicability -Descriptor $Descriptor
    if (-not [bool]$applicability.Applicable) {
        throw "Policy '$($Descriptor.Label)' is not applicable: $($applicability.Reason)."
    }

    $desired = Get-PolicyDesiredValue -Descriptor $Descriptor
    Set-RegistryValue -Path $Descriptor.Path -Name $Descriptor.Name -Value $desired -Kind $Descriptor.Kind
    $actual = Get-RegistryValueSnapshot -Id 'verify' -Path $Descriptor.Path -Name $Descriptor.Name
    if (-not (Test-RegistrySnapshotHasValue -Snapshot $actual -Kind $Descriptor.Kind -ExpectedValue $desired)) {
        throw "Policy verification failed for $($Descriptor.Label)."
    }
}

function Restore-PolicyFromState {
    param(
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)]$Descriptor
    )

    $snapshot = Get-ManagedSnapshot -State $State -Id $Descriptor.Id
    Restore-RegistrySnapshot -Snapshot $snapshot -ExpectedPath ([string]$Descriptor.Path) -ExpectedName ([string]$Descriptor.Name)
}

function Apply-FeaturePolicies {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Config,
        [Parameter(Mandatory = $true)]$State
    )

    # CDP policy is reconciled with the service template in the next section.
    foreach ($descriptor in @($script:PolicyDescriptors | Where-Object { $_.Id -ne 'CDP.EnableCdp' })) {
        $requested = [bool]$Config[$descriptor.ConfigKey]
        $applicability = Get-PolicyApplicability -Descriptor $descriptor
        if ($requested -and [bool]$applicability.Applicable) {
            Set-PolicyEnabled -Descriptor $descriptor
        } else {
            Restore-PolicyFromState -State $State -Descriptor $descriptor
            if ($requested -and -not [bool]$applicability.Applicable) {
                Write-Info "Skipped '$($descriptor.Label)': $($applicability.Reason)."
            }
        }
    }

    if ([bool]$Config['killPhoneLink']) {
        Stop-Process -Name 'PhoneExperienceHost' -Force -ErrorAction SilentlyContinue
    }
    if ([bool]$Config['killOneDrive']) {
        Stop-Process -Name 'OneDrive' -Force -ErrorAction SilentlyContinue
    }

    Write-Ok 'Feature and diagnostic-data policies reconciled with configuration.'
}

function Invoke-GroupPolicyRefresh {
    $gpupdate = Join-Path $env:SystemRoot 'System32\gpupdate.exe'
    if (-not (Test-Path -LiteralPath $gpupdate)) {
        throw "Group Policy refresh executable was not found at '$gpupdate'."
    }

    # /wait:300 keeps gpupdate noninteractive while allowing slow domain policy
    # processing substantially more time than the default command path.
    $process = Start-Process -FilePath $gpupdate -ArgumentList @('/force', '/wait:300') -NoNewWindow -PassThru
    if (-not $process.WaitForExit(330000)) {
        try { Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue } catch { }
        throw 'gpupdate /force /wait:300 did not finish within the 330-second safety limit.'
    }
    $process.Refresh()
    if ([int]$process.ExitCode -ne 0) {
        throw "gpupdate /force exited with code $($process.ExitCode)."
    }
    Write-Ok 'gpupdate /force completed successfully.'
}

function Assert-ConfiguredPoliciesReconciled {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Config,
        [Parameter(Mandatory = $true)]$State
    )

    Assert-TrustedState -State $State
    $mismatches = @()

    # CDP.EnableCdp is applied and verified with the CDP service/template block
    # later in the install transaction. Everything else has already been
    # reconciled before gpupdate and must still match afterward.
    foreach ($descriptor in @($script:PolicyDescriptors | Where-Object { $_.Id -ne 'CDP.EnableCdp' })) {
        $requested = [bool]$Config[$descriptor.ConfigKey]
        $applicability = Get-PolicyApplicability -Descriptor $descriptor

        if ($requested -and [bool]$applicability.Applicable) {
            $desired = Get-PolicyDesiredValue -Descriptor $descriptor
            $actual = Get-RegistryValueSnapshot -Id 'verify' -Path $descriptor.Path -Name $descriptor.Name
            if (-not (Test-RegistrySnapshotHasValue -Snapshot $actual -Kind $descriptor.Kind -ExpectedValue $desired)) {
                $actualText = if ([bool]$actual.existed) { [string]$actual.value } else { '(not set)' }
                $mismatches += "$($descriptor.Path)\$($descriptor.Name): expected configured=$desired actual=$actualText"
            }
            continue
        }

        # A disabled option, or an option that is not applicable to this build,
        # must remain at the protected pre-tool baseline after Group Policy
        # refresh. This catches policy residue and authoritative overrides rather
        # than claiming that an inactive option was successfully restored.
        $snapshot = Get-ManagedSnapshot -State $State -Id $descriptor.Id
        if (-not (Test-RegistrySnapshotMatches `
            -Snapshot $snapshot `
            -ExpectedPath ([string]$descriptor.Path) `
            -ExpectedName ([string]$descriptor.Name))) {
            $actual = Get-RegistryValueSnapshot -Id 'verify' -Path $descriptor.Path -Name $descriptor.Name
            $actualText = if ([bool]$actual.existed) { [string]$actual.value } else { '(not set)' }
            $expectedText = if ([bool]$snapshot.existed) { [string]$snapshot.value } else { '(not set)' }
            $mismatches += "$($descriptor.Path)\$($descriptor.Name): expected baseline=$expectedText actual=$actualText"
        }
    }

    if ($mismatches.Count -gt 0) {
        throw "Managed-policy verification failed after gpupdate /force. A local, domain, or MDM policy may be authoritative: $($mismatches -join '; ')"
    }
    Write-Ok 'All non-CDP managed policy values match the requested or protected-baseline state after Group Policy refresh.'
}

function Assert-ManagedPoliciesRestored {
    param([Parameter(Mandatory = $true)]$State)

    Assert-TrustedState -State $State
    $mismatches = @()
    foreach ($descriptor in $script:PolicyDescriptors) {
        $snapshot = Get-ManagedSnapshot -State $State -Id $descriptor.Id
        if (-not (Test-RegistrySnapshotMatches `
            -Snapshot $snapshot `
            -ExpectedPath ([string]$descriptor.Path) `
            -ExpectedName ([string]$descriptor.Name))) {
            $current = Get-RegistryValueSnapshot -Id 'verify' -Path $descriptor.Path -Name $descriptor.Name
            $currentText = if ([bool]$current.existed) { [string]$current.value } else { '(not set)' }
            $expectedText = if ([bool]$snapshot.existed) { [string]$snapshot.value } else { '(not set)' }
            $mismatches += "$($descriptor.Path)\$($descriptor.Name): expected baseline=$expectedText actual=$currentText"
        }
    }

    if ($mismatches.Count -gt 0) {
        throw "Managed-policy restoration did not survive gpupdate /force. A local, domain, or MDM policy may be authoritative: $($mismatches -join '; ')"
    }
    Write-Ok 'All managed policy values match the protected pre-tool baseline after Group Policy refresh.'
}

function Invoke-DiagnosticDataDeleteRequest {
    $attemptErrors = @()
    $command = Get-Command -Name 'Clear-WindowsDiagnosticData' -ErrorAction SilentlyContinue
    if ($null -eq $command) {
        try {
            Import-Module WindowsDiagnosticData -ErrorAction Stop
        } catch {
            $attemptErrors += "Current-host module import: $($_.Exception.Message)"
        }
        $command = Get-Command -Name 'Clear-WindowsDiagnosticData' -ErrorAction SilentlyContinue
    }

    if ($null -ne $command) {
        try {
            & $command -Force -ErrorAction Stop
            return [pscustomobject]@{
                Accepted = $true
                Message = 'Windows accepted the Clear-WindowsDiagnosticData request. This is a deletion request, not proof that Microsoft has completed server-side deletion.'
            }
        } catch {
            $attemptErrors += "Current-host cmdlet: $($_.Exception.Message)"
        }
    }

    # PowerShell 7 can be unable to load this Windows-only module even when the
    # inbox Windows PowerShell 5.1 host can. Retry through the fixed, local
    # Windows PowerShell executable; no user-controlled command text is used.
    $windowsPowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    if (Test-Path -LiteralPath $windowsPowerShell -PathType Leaf) {
        try {
            $fallbackOutput = @(& $windowsPowerShell `
                -NoLogo `
                -NoProfile `
                -NonInteractive `
                -Command "Import-Module WindowsDiagnosticData -ErrorAction Stop; Clear-WindowsDiagnosticData -Force -ErrorAction Stop" 2>&1)
            $fallbackExitCode = $LASTEXITCODE
            if ([int]$fallbackExitCode -eq 0) {
                return [pscustomobject]@{
                    Accepted = $true
                    Message = 'Windows PowerShell accepted the Clear-WindowsDiagnosticData request. This is a deletion request, not proof that Microsoft has completed server-side deletion.'
                }
            }
            $fallbackText = @($fallbackOutput | ForEach-Object { [string]$_ }) -join ' | '
            $attemptErrors += "Windows PowerShell fallback exited with code ${fallbackExitCode}: $fallbackText"
        } catch {
            $attemptErrors += "Windows PowerShell fallback: $($_.Exception.Message)"
        }
    } else {
        $attemptErrors += "Windows PowerShell fallback was not found at '$windowsPowerShell'."
    }

    $detail = if ($attemptErrors.Count -gt 0) { $attemptErrors -join '; ' } else { 'The cmdlet was not available.' }
    return [pscustomobject]@{
        Accepted = $false
        Message = "Clear-WindowsDiagnosticData could not be submitted: $detail"
    }
}

function Assert-ManagedServicePathsBackedForMutation {
    param(
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)]
        [ValidateSet('CDP', 'WPN', 'Telemetry')]
        [string]$Family
    )

    Assert-TrustedState -State $State
    $pattern = switch ($Family) {
        'CDP'       { 'Service.CDP*' }
        'WPN'       { 'Service.Wpn*' }
        'Telemetry' { 'Service.DiagTrack*', 'Service.dmwappushservice*' }
    }
    $unbackedPaths = @()

    foreach ($descriptor in @($script:ServiceValueDescriptors | Where-Object {
        $id = [string]$_.Id
        @($pattern | Where-Object { $id -like $_ }).Count -gt 0
    })) {
        $snapshot = Get-ManagedSnapshot -State $State -Id $descriptor.Id
        if ((Test-Path -LiteralPath ([string]$descriptor.Path)) -and -not [bool]$snapshot.pathExisted) {
            $unbackedPaths += [string]$descriptor.Path
        }
    }

    $unbackedPaths = @($unbackedPaths | Sort-Object -Unique)
    if ($unbackedPaths.Count -gt 0) {
        throw "$Family service/template key(s) appeared after the protected baseline and cannot be modified reversibly: $($unbackedPaths -join ', '). Turn the option off, complete restoration, then uninstall/reinstall to capture a fresh baseline."
    }
}

function Get-CDPServices {
    $services = @()
    foreach ($name in @('CDPSvc', 'CDPUserSvc')) {
        $service = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($null -ne $service) {
            $services += $service
        }
    }
    $services += @(Get-CDPUserInstanceServices)
    return @($services | Sort-Object Name -Unique)
}

function Get-CDPBlockStatus {
    $cdpStart = Get-RegistryValueSnapshot -Id 'status' -Path $script:CDPSvcPath -Name 'Start'
    $userStart = Get-RegistryValueSnapshot -Id 'status' -Path $script:CDPUserTemplatePath -Name 'Start'
    $userFlags = Get-RegistryValueSnapshot -Id 'status' -Path $script:CDPUserTemplatePath -Name 'UserServiceFlags'
    $policy = Get-RegistryValueSnapshot -Id 'status' -Path $script:CDPPolicyPath -Name 'EnableCdp'

    $services = @(Get-CDPServices)
    $instances = @($services | Where-Object { $_.Name -match '^CDPUserSvc_[A-Za-z0-9]+$' })
    $running = @($services | Where-Object {
        $_.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running
    })

    $instanceNotDisabled = @()
    foreach ($service in $instances) {
        $path = "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)"
        $start = Get-RegistryValueSnapshot -Id 'status' -Path $path -Name 'Start'
        if (-not (Test-RegistrySnapshotHasValue -Snapshot $start -Kind 'DWord' -ExpectedValue 4) -and
            ((Test-Path -LiteralPath $path) -or
             $null -ne (Get-Service -Name $service.Name -ErrorAction SilentlyContinue))) {
            $instanceNotDisabled += $service.Name
        }
    }

    $cdpSvcDisabled = (-not [bool]$cdpStart.pathExisted) -or
                      (Test-RegistrySnapshotHasValue -Snapshot $cdpStart -Kind 'DWord' -ExpectedValue 4)
    $userTemplateDisabled = (-not [bool]$userStart.pathExisted) -or
                            (Test-RegistrySnapshotHasValue -Snapshot $userStart -Kind 'DWord' -ExpectedValue 4)
    $userCreationBlocked = (-not [bool]$userFlags.pathExisted) -or
                           (Test-RegistrySnapshotHasValue -Snapshot $userFlags -Kind 'DWord' -ExpectedValue 0)
    $policyDisabled = Test-RegistrySnapshotHasValue -Snapshot $policy -Kind 'DWord' -ExpectedValue 0
    $instancesDisabled = $instanceNotDisabled.Count -eq 0
    $servicesStopped = $running.Count -eq 0
    $staticControlsDisabled = $cdpSvcDisabled -and $userTemplateDisabled -and $userCreationBlocked -and $policyDisabled

    return [pscustomobject]@{
        CDPSvcStartDisabled = $cdpSvcDisabled
        CDPUserTemplateDisabled = $userTemplateDisabled
        CDPUserCreationBlocked = $userCreationBlocked
        CDPUserInstancesDisabled = $instancesDisabled
        CDPUserInstanceCount = $instances.Count
        InstanceNotDisabledNames = @($instanceNotDisabled)
        PolicyDisabled = $policyDisabled
        ServicesStopped = $servicesStopped
        RunningServiceNames = @($running | Select-Object -ExpandProperty Name)
        StaticControlsDisabled = $staticControlsDisabled
        ReadyForLocalMask = ($staticControlsDisabled -and $instancesDisabled -and $servicesStopped)
    }
}

function Enable-CDPBlock {
    param([Parameter(Mandatory = $true)]$State)

    Assert-TrustedState -State $State
    if ([int]$State.schemaVersion -lt 5) {
        throw 'CDP blocking requires trusted-state schema 5 or newer.'
    }
    Assert-ManagedServicePathsBackedForMutation -State $State -Family 'CDP'

    $policy = Get-PolicyDescriptor -Id 'CDP.EnableCdp'
    Set-PolicyEnabled -Descriptor $policy

    if (Get-Service -Name 'CDPSvc' -ErrorAction SilentlyContinue) {
        Set-Service -Name 'CDPSvc' -StartupType Disabled
    }
    if (Test-Path -LiteralPath $script:CDPSvcPath) {
        Set-RegistryValue -Path $script:CDPSvcPath -Name 'Start' -Value 4 -Kind 'DWord'
    }

    # Microsoft documents changing the per-user service template Start value to
    # 4 and UserServiceFlags to 0 to prevent creation of new instances.
    if (Test-Path -LiteralPath $script:CDPUserTemplatePath) {
        Set-RegistryValue -Path $script:CDPUserTemplatePath -Name 'Start' -Value 4 -Kind 'DWord'
        Set-RegistryValue -Path $script:CDPUserTemplatePath -Name 'UserServiceFlags' -Value 0 -Kind 'DWord'
    }

    # Existing per-user instances can survive for the current sign-in. Disable
    # their own Start values as well as the template so they cannot be
    # demand-started again before logoff/reboot.
    foreach ($service in @(Get-CDPUserInstanceServices)) {
        $path = "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)"
        $start = Get-RegistryValueSnapshot -Id 'status' -Path $path -Name 'Start'
        if (-not (Test-RegistrySnapshotHasValue -Snapshot $start -Kind 'DWord' -ExpectedValue 4)) {
            try {
                Set-Service -Name $service.Name -StartupType Disabled
            } catch {
                if ($null -ne (Get-Service -Name $service.Name -ErrorAction SilentlyContinue)) {
                    throw
                }
                continue
            }
            $null = Set-ExistingRegistryValue -Path $path -Name 'Start' -Value 4 -Kind 'DWord'
        }
    }

    $stopFailures = @()
    $stopOrder = @()
    $stopOrder += @(Get-CDPUserInstanceServices)
    $template = Get-Service -Name 'CDPUserSvc' -ErrorAction SilentlyContinue
    if ($null -ne $template) { $stopOrder += $template }
    $system = Get-Service -Name 'CDPSvc' -ErrorAction SilentlyContinue
    if ($null -ne $system) { $stopOrder += $system }

    $seen = @{}
    foreach ($service in $stopOrder) {
        $key = ([string]$service.Name).ToLowerInvariant()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true

        $current = Get-Service -Name $service.Name -ErrorAction SilentlyContinue
        if ($null -ne $current -and
            $current.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
            try {
                if ($current.Name -ceq 'CDPSvc') {
                    Stop-Service -Name $current.Name
                } else {
                    Stop-Service -Name $current.Name -Force
                }
            } catch {
                $after = Get-Service -Name $current.Name -ErrorAction SilentlyContinue
                if ($null -ne $after -and
                    $after.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
                    $stopFailures += "$($current.Name): $($_.Exception.Message)"
                }
            }
        }
    }
    if ($stopFailures.Count -gt 0) {
        throw "Could not stop all CDP services: $($stopFailures -join '; ')"
    }

    Start-Sleep -Milliseconds 500
    $status = Get-CDPBlockStatus
    if (-not $status.ReadyForLocalMask) {
        $runningText = if (@($status.RunningServiceNames).Count -gt 0) {
            @($status.RunningServiceNames) -join ', '
        } else {
            'none'
        }
        $enabledInstanceText = if (@($status.InstanceNotDisabledNames).Count -gt 0) {
            @($status.InstanceNotDisabledNames) -join ', '
        } else {
            'none'
        }
        throw "CDP block verification failed. Running services: $runningText. Instances not disabled: $enabledInstanceText."
    }

    Write-Ok 'CDP policy, CDPSvc, CDPUserSvc template, and current CDPUserSvc instances are disabled and stopped.'
}

function Restore-CDPFromState {
    param([Parameter(Mandatory = $true)]$State)

    Assert-TrustedState -State $State
    $preRestoreStatus = Get-CDPRestoreStatus -State $State
    if ($preRestoreStatus.Reconciled) {
        Write-Info 'CDP already matches the protected baseline; no CDP registry or service write was needed.'
        return
    }

    $policy = Get-PolicyDescriptor -Id 'CDP.EnableCdp'
    Restore-PolicyFromState -State $State -Descriptor $policy

    $cdpStartDescriptor = @($script:ServiceValueDescriptors | Where-Object { $_.Id -ceq 'Service.CDPSvc.Start' })[0]
    $cdpDelayedDescriptor = @($script:ServiceValueDescriptors | Where-Object { $_.Id -ceq 'Service.CDPSvc.DelayedAutoStart' })[0]
    $userStartDescriptor = @($script:ServiceValueDescriptors | Where-Object { $_.Id -ceq 'Service.CDPUserSvc.Start' })[0]
    $userFlagsDescriptor = @($script:ServiceValueDescriptors | Where-Object { $_.Id -ceq 'Service.CDPUserSvc.UserServiceFlags' })[0]

    $cdpStart = Get-ManagedSnapshot -State $State -Id $cdpStartDescriptor.Id
    $cdpDelayed = Get-ManagedSnapshot -State $State -Id $cdpDelayedDescriptor.Id
    $userStart = Get-ManagedSnapshot -State $State -Id $userStartDescriptor.Id
    $userFlags = Get-ManagedSnapshot -State $State -Id $userFlagsDescriptor.Id

    if ([bool]$cdpStart.existed -and [string]$cdpStart.kind -ceq 'DWord') {
        [uint32]$savedSystemStart = 0
        if ([uint32]::TryParse([string]$cdpStart.value, [ref]$savedSystemStart)) {
            $null = Set-ServiceStartupTypeFromStartValue -ServiceName 'CDPSvc' -StartValue $savedSystemStart
        }
    }
    $null = Restore-ExistingRegistrySnapshot -Snapshot $cdpStart -ExpectedPath $cdpStartDescriptor.Path -ExpectedName $cdpStartDescriptor.Name
    $null = Restore-ExistingRegistrySnapshot -Snapshot $cdpDelayed -ExpectedPath $cdpDelayedDescriptor.Path -ExpectedName $cdpDelayedDescriptor.Name
    $null = Restore-ExistingRegistrySnapshot -Snapshot $userStart -ExpectedPath $userStartDescriptor.Path -ExpectedName $userStartDescriptor.Name
    $null = Restore-ExistingRegistrySnapshot -Snapshot $userFlags -ExpectedPath $userFlagsDescriptor.Path -ExpectedName $userFlagsDescriptor.Name

    if ([int]$State.schemaVersion -ge 5) {
        $backedPaths = @{}
        foreach ($snapshot in @($State.originalCdpInstanceValues)) {
            $path = [string]$snapshot.path
            $backedPaths[$path.ToLowerInvariant()] = $true
            if (-not (Test-Path -LiteralPath $path)) {
                continue
            }

            $serviceName = Split-Path -Leaf $path
            if ([bool]$snapshot.existed -and [string]$snapshot.kind -ceq 'DWord') {
                [uint32]$savedInstanceStart = 0
                if ([uint32]::TryParse([string]$snapshot.value, [ref]$savedInstanceStart)) {
                    $null = Set-ServiceStartupTypeFromStartValue -ServiceName $serviceName -StartValue $savedInstanceStart
                }
            }
            $null = Restore-ExistingRegistrySnapshot -Snapshot $snapshot -ExpectedPath $path -ExpectedName 'Start'
        }

        # A suffix created after the sealed baseline is restored to the saved
        # template Start value. It disappears at sign-out; future instances
        # inherit the restored template.
        if ([bool]$userStart.existed -and [string]$userStart.kind -ceq 'DWord') {
            [uint32]$savedTemplateStart = 0
            if ([uint32]::TryParse([string]$userStart.value, [ref]$savedTemplateStart)) {
                foreach ($service in @(Get-CDPUserInstanceServices)) {
                    $path = "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)"
                    if (-not $backedPaths.ContainsKey($path.ToLowerInvariant())) {
                        $null = Set-ServiceStartupTypeFromStartValue -ServiceName $service.Name -StartValue $savedTemplateStart
                        $null = Set-ExistingRegistryValue -Path $path -Name 'Start' -Value $savedTemplateStart -Kind 'DWord'
                    }
                }
            }
        }
    }

    $runtimeEntries = @($State.originalServiceRuntime | Where-Object {
        [string]$_.name -ceq 'CDPSvc' -or [string]$_.name -ceq 'CDPUserSvc' -or
        [string]$_.name -match '^CDPUserSvc_[A-Za-z0-9]+$'
    })
    foreach ($pattern in @('^CDPSvc$', '^CDPUserSvc$', '^CDPUserSvc_[A-Za-z0-9]+$')) {
        foreach ($runtime in @($runtimeEntries | Where-Object { [string]$_.name -match $pattern })) {
            if (-not [bool]$runtime.wasRunning) { continue }
            $serviceName = [string]$runtime.name
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($null -ne $service -and
                $service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
                try {
                    Start-Service -Name $serviceName
                } catch {
                    Write-Warn "Could not immediately restart ${serviceName}: $($_.Exception.Message)"
                }
            }
        }
    }

    $restoreStatus = Get-CDPRestoreStatus -State $State
    if (-not $restoreStatus.Reconciled) {
        throw "CDP restoration verification failed for: $(@($restoreStatus.Mismatches) -join ', ')."
    }

    Write-Ok 'Restored backed-up CDP policy, service-template, and captured instance values.'
}

function Get-PreviouslyRunningServiceMismatches {
    param(
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)]
        [ValidateSet('CDP', 'WPN', 'Telemetry')]
        [string]$Family
    )

    Assert-TrustedState -State $State
    $mismatches = @()

    foreach ($runtime in @($State.originalServiceRuntime)) {
        $name = [string]$runtime.name
        $relevant = switch ($Family) {
            'CDP' {
                $name -ceq 'CDPSvc' -or $name -ceq 'CDPUserSvc' -or
                $name -match '^CDPUserSvc_[A-Za-z0-9]+$'
            }
            'WPN' {
                $name -ceq 'WpnService' -or $name -ceq 'WpnUserService' -or
                $name -match '^WpnUserService_[A-Za-z0-9]+$'
            }
            'Telemetry' {
                $name -ceq 'DiagTrack' -or $name -ceq 'dmwappushservice'
            }
        }
        if (-not $relevant -or -not [bool]$runtime.wasRunning) {
            continue
        }

        # A per-user instance can legitimately disappear at sign-out. Do not
        # recreate it, but verify every previously-running service that still
        # exists after restoration.
        $service = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($null -ne $service -and
            $service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
            $mismatches += "Runtime.$name (was running before management)"
        }
    }

    return @($mismatches)
}

function Get-CDPRestoreStatus {
    param([Parameter(Mandatory = $true)]$State)

    Assert-TrustedState -State $State
    $mismatches = @()

    $policyDescriptor = Get-PolicyDescriptor -Id 'CDP.EnableCdp'
    $policySnapshot = Get-ManagedSnapshot -State $State -Id $policyDescriptor.Id
    if (-not (Test-RegistrySnapshotMatches `
        -Snapshot $policySnapshot `
        -ExpectedPath ([string]$policyDescriptor.Path) `
        -ExpectedName ([string]$policyDescriptor.Name))) {
        $mismatches += [string]$policyDescriptor.Id
    }

    foreach ($descriptor in @($script:ServiceValueDescriptors | Where-Object { $_.Id -like 'Service.CDP*' })) {
        $snapshot = Get-ManagedSnapshot -State $State -Id $descriptor.Id
        if (-not [bool]$snapshot.pathExisted) {
            continue
        }
        if (-not (Test-Path -LiteralPath ([string]$descriptor.Path))) {
            $mismatches += "$($descriptor.Id) (service key missing)"
            continue
        }
        if (-not (Test-RegistrySnapshotMatches `
            -Snapshot $snapshot `
            -ExpectedPath ([string]$descriptor.Path) `
            -ExpectedName ([string]$descriptor.Name))) {
            $mismatches += [string]$descriptor.Id
        }
    }

    if ([int]$State.schemaVersion -ge 5) {
        $backedPaths = @{}
        foreach ($snapshot in @($State.originalCdpInstanceValues)) {
            $path = [string]$snapshot.path
            $backedPaths[$path.ToLowerInvariant()] = $true
            if (Test-Path -LiteralPath $path) {
                if (-not (Test-RegistrySnapshotMatches -Snapshot $snapshot -ExpectedPath $path -ExpectedName 'Start') -and
                    (Test-Path -LiteralPath $path)) {
                    $mismatches += [string]$snapshot.id
                }
            }
        }

        $templateDescriptor = @($script:ServiceValueDescriptors | Where-Object {
            $_.Id -ceq 'Service.CDPUserSvc.Start'
        })[0]
        $templateSnapshot = Get-ManagedSnapshot -State $State -Id $templateDescriptor.Id
        if ([bool]$templateSnapshot.existed -and [string]$templateSnapshot.kind -ceq 'DWord') {
            [uint32]$expectedTemplateStart = 0
            if (-not [uint32]::TryParse([string]$templateSnapshot.value, [ref]$expectedTemplateStart)) {
                $mismatches += 'Service.CDPUserSvc.Start (invalid protected DWord value)'
            } else {
                foreach ($service in @(Get-CDPUserInstanceServices)) {
                    $path = "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)"
                    if ($backedPaths.ContainsKey($path.ToLowerInvariant())) {
                        continue
                    }
                    $actual = Get-RegistryValueSnapshot -Id 'status' -Path $path -Name 'Start'
                    if (-not (Test-RegistrySnapshotHasValue `
                        -Snapshot $actual `
                        -Kind 'DWord' `
                        -ExpectedValue $expectedTemplateStart) -and
                        (Test-Path -LiteralPath $path)) {
                        $mismatches += "Service.CDPUserSvc.Current.$($service.Name).Start"
                    }
                }
            }
        }
    }

    $mismatches += @(Get-PreviouslyRunningServiceMismatches -State $State -Family 'CDP')

    return [pscustomobject]@{
        Known = $true
        Reconciled = ($mismatches.Count -eq 0)
        Mismatches = @($mismatches)
    }
}

function Get-WpnServices {
    $services = @()

    foreach ($name in @('WpnService', 'WpnUserService')) {
        $service = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($null -ne $service) {
            $services += $service
        }
    }

    $services += @(Get-WpnUserInstanceServices)
    return @($services | Sort-Object Name -Unique)
}

function Get-WpnBlockStatus {
    $systemStart = Get-RegistryValueSnapshot -Id 'status' -Path $script:WpnSvcPath -Name 'Start'
    $userStart = Get-RegistryValueSnapshot -Id 'status' -Path $script:WpnUserTemplatePath -Name 'Start'
    $userFlags = Get-RegistryValueSnapshot -Id 'status' -Path $script:WpnUserTemplatePath -Name 'UserServiceFlags'

    # Enumerate once so the report is internally consistent even if a user
    # signs in or out while status is being collected.
    $services = @(Get-WpnServices)
    $instances = @($services | Where-Object { $_.Name -match '^WpnUserService_[A-Za-z0-9]+$' })
    $running = @($services | Where-Object {
        $_.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running
    })

    $instanceNotDisabled = @()
    foreach ($service in $instances) {
        $path = "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)"
        $start = Get-RegistryValueSnapshot -Id 'status' -Path $path -Name 'Start'
        if (-not (Test-RegistrySnapshotHasValue -Snapshot $start -Kind 'DWord' -ExpectedValue 4) -and
            ((Test-Path -LiteralPath $path) -or
             $null -ne (Get-Service -Name $service.Name -ErrorAction SilentlyContinue))) {
            $instanceNotDisabled += $service.Name
        }
    }

    $systemDisabled = (-not [bool]$systemStart.pathExisted) -or
                      (Test-RegistrySnapshotHasValue -Snapshot $systemStart -Kind 'DWord' -ExpectedValue 4)
    $userTemplateDisabled = (-not [bool]$userStart.pathExisted) -or
                            (Test-RegistrySnapshotHasValue -Snapshot $userStart -Kind 'DWord' -ExpectedValue 4)
    $userCreationBlocked = (-not [bool]$userFlags.pathExisted) -or
                           (Test-RegistrySnapshotHasValue -Snapshot $userFlags -Kind 'DWord' -ExpectedValue 0)
    $instancesDisabled = $instanceNotDisabled.Count -eq 0
    $servicesStopped = $running.Count -eq 0
    $staticControlsDisabled = $systemDisabled -and $userTemplateDisabled -and $userCreationBlocked
    $componentsPresent = [bool]$systemStart.pathExisted -or
                         [bool]$userStart.pathExisted -or
                         $services.Count -gt 0

    return [pscustomobject]@{
        ComponentsPresent = $componentsPresent
        WpnServiceStartDisabled = $systemDisabled
        WpnUserTemplateDisabled = $userTemplateDisabled
        WpnUserCreationBlocked = $userCreationBlocked
        WpnUserInstancesDisabled = $instancesDisabled
        WpnUserInstanceCount = $instances.Count
        InstanceNotDisabledNames = @($instanceNotDisabled)
        ServicesStopped = $servicesStopped
        RunningServiceNames = @($running | Select-Object -ExpandProperty Name)
        StaticControlsDisabled = $staticControlsDisabled
        FullyBlocked = ($staticControlsDisabled -and $instancesDisabled -and $servicesStopped)
    }
}

function Get-WpnInstanceBackup {
    param(
        [Parameter(Mandatory = $true)]$State,
        [Parameter(Mandatory = $true)][string]$Path
    )

    if ([int]$State.schemaVersion -lt 4) {
        return $null
    }

    $matches = @($State.originalWpnInstanceValues | Where-Object {
        ([string]$_.path).Equals($Path, [StringComparison]::OrdinalIgnoreCase) -and
        [string]$_.name -ceq 'Start'
    })
    if ($matches.Count -gt 1) {
        throw "Trusted state contains duplicate WPN instance backup for '$Path'."
    }
    if ($matches.Count -eq 1) {
        return $matches[0]
    }
    return $null
}

function Set-ServiceStartupTypeFromStartValue {
    param(
        [Parameter(Mandatory = $true)][string]$ServiceName,
        [Parameter(Mandatory = $true)][uint32]$StartValue
    )

    $service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($null -eq $service) {
        return $false
    }

    try {
        switch ($StartValue) {
            2 { Set-Service -Name $ServiceName -StartupType Automatic; return $true }
            3 { Set-Service -Name $ServiceName -StartupType Manual; return $true }
            4 { Set-Service -Name $ServiceName -StartupType Disabled; return $true }
            default { return $false }
        }
    } catch {
        # The exact registry snapshot is restored immediately afterward. Some
        # per-user service instances disappear during sign-out or reject an SCM
        # update while being torn down; in that case the restored template and
        # next sign-in/reboot establish the saved startup type.
        Write-Warn "Could not immediately update SCM startup type for $ServiceName; exact registry restoration will still be attempted: $($_.Exception.Message)"
        return $false
    }
}

function Enable-WpnBlock {
    param([Parameter(Mandatory = $true)]$State)

    Assert-TrustedState -State $State
    if ([int]$State.schemaVersion -lt 4) {
        throw 'WPN blocking requires trusted-state schema 4 or newer.'
    }
    Assert-ManagedServicePathsBackedForMutation -State $State -Family 'WPN'

    # Preflight all current instances before touching static controls. An
    # instance present before the first completed install must have an exact
    # backup. Instances created later are safely restored from the backed-up
    # WpnUserService template instead of being adopted as originals.
    foreach ($service in @(Get-WpnUserInstanceServices)) {
        $path = "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)"
        $start = Get-RegistryValueSnapshot -Id 'status' -Path $path -Name 'Start'
        if (-not (Test-RegistrySnapshotHasValue -Snapshot $start -Kind 'DWord' -ExpectedValue 4) -and
            $null -eq (Get-WpnInstanceBackup -State $State -Path $path) -and
            -not [bool]$State.installed -and
            -not [bool]$State.wpnInstanceBaselineSealed) {
            throw "Refusing to disable unbacked pre-install WPN instance '$($service.Name)'. Run install again so its original Start value can be captured safely."
        }
    }

    $systemService = Get-Service -Name 'WpnService' -ErrorAction SilentlyContinue
    if ($null -ne $systemService) {
        Set-Service -Name 'WpnService' -StartupType Disabled
    }
    if (Test-Path -LiteralPath $script:WpnSvcPath) {
        Set-RegistryValue -Path $script:WpnSvcPath -Name 'Start' -Value 4 -Kind 'DWord'
    }

    # Microsoft documents direct template registry management for per-user
    # services. Existing instances are managed separately below.
    if (Test-Path -LiteralPath $script:WpnUserTemplatePath) {
        Set-RegistryValue -Path $script:WpnUserTemplatePath -Name 'Start' -Value 4 -Kind 'DWord'
        Set-RegistryValue -Path $script:WpnUserTemplatePath -Name 'UserServiceFlags' -Value 0 -Kind 'DWord'
    }

    # Disable every currently instantiated per-user service as well as the
    # template. The template controls future logons; setting each live instance
    # to Start=4 prevents it from being demand-started again in this session.
    foreach ($service in @(Get-WpnUserInstanceServices)) {
        $path = "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)"
        $start = Get-RegistryValueSnapshot -Id 'status' -Path $path -Name 'Start'
        if (-not (Test-RegistrySnapshotHasValue -Snapshot $start -Kind 'DWord' -ExpectedValue 4)) {
            try {
                Set-Service -Name $service.Name -StartupType Disabled
            } catch {
                if ($null -ne (Get-Service -Name $service.Name -ErrorAction SilentlyContinue)) {
                    throw
                }
                continue
            }

            $null = Set-ExistingRegistryValue -Path $path -Name 'Start' -Value 4 -Kind 'DWord'
        }
    }

    $stopFailures = @()
    $stopOrder = @()
    $stopOrder += @(Get-WpnUserInstanceServices)
    $template = Get-Service -Name 'WpnUserService' -ErrorAction SilentlyContinue
    if ($null -ne $template) { $stopOrder += $template }
    $system = Get-Service -Name 'WpnService' -ErrorAction SilentlyContinue
    if ($null -ne $system) { $stopOrder += $system }

    $seen = @{}
    foreach ($service in $stopOrder) {
        $key = ([string]$service.Name).ToLowerInvariant()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true

        $current = Get-Service -Name $service.Name -ErrorAction SilentlyContinue
        if ($null -ne $current -and
            $current.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
            try {
                if ($current.Name -ceq 'WpnService') {
                    Stop-Service -Name $current.Name
                } else {
                    Stop-Service -Name $current.Name -Force
                }
            } catch {
                $after = Get-Service -Name $current.Name -ErrorAction SilentlyContinue
                if ($null -ne $after -and
                    $after.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
                    $stopFailures += "$($current.Name): $($_.Exception.Message)"
                }
            }
        }
    }
    if ($stopFailures.Count -gt 0) {
        throw "Could not stop all Windows Push Notification services: $($stopFailures -join '; ')"
    }

    Start-Sleep -Milliseconds 500
    $status = Get-WpnBlockStatus
    if (-not $status.FullyBlocked) {
        $runningText = if (@($status.RunningServiceNames).Count -gt 0) {
            @($status.RunningServiceNames) -join ', '
        } else {
            'none'
        }
        $enabledInstanceText = if (@($status.InstanceNotDisabledNames).Count -gt 0) {
            @($status.InstanceNotDisabledNames) -join ', '
        } else {
            'none'
        }
        throw "WPN block verification failed. Running services: $runningText. Instances not disabled: $enabledInstanceText."
    }

    if ($status.ComponentsPresent) {
        Write-Ok 'WpnService, WpnUserService template, and current WpnUserService instances are disabled and stopped.'
    } else {
        Write-Info 'Windows Push Notification service components are not installed on this Windows edition.'
    }
}

function Restore-WpnFromState {
    param([Parameter(Mandatory = $true)]$State)

    Assert-TrustedState -State $State
    if ([int]$State.schemaVersion -lt 4) {
        Write-Info 'Trusted state predates WPN management; no WPN setting was changed or restored.'
        return
    }

    $preRestoreStatus = Get-WpnRestoreStatus -State $State
    if ($preRestoreStatus.Reconciled) {
        Write-Info 'WPN already matches the protected baseline; no WPN registry or service write was needed.'
        return
    }

    $systemStartDescriptor = @($script:ServiceValueDescriptors | Where-Object { $_.Id -ceq 'Service.WpnService.Start' })[0]
    $systemDelayedDescriptor = @($script:ServiceValueDescriptors | Where-Object { $_.Id -ceq 'Service.WpnService.DelayedAutoStart' })[0]
    $userStartDescriptor = @($script:ServiceValueDescriptors | Where-Object { $_.Id -ceq 'Service.WpnUserService.Start' })[0]
    $userFlagsDescriptor = @($script:ServiceValueDescriptors | Where-Object { $_.Id -ceq 'Service.WpnUserService.UserServiceFlags' })[0]

    $systemStart = Get-ManagedSnapshot -State $State -Id $systemStartDescriptor.Id
    $systemDelayed = Get-ManagedSnapshot -State $State -Id $systemDelayedDescriptor.Id
    $userStart = Get-ManagedSnapshot -State $State -Id $userStartDescriptor.Id
    $userFlags = Get-ManagedSnapshot -State $State -Id $userFlagsDescriptor.Id

    if ([bool]$systemStart.existed -and [string]$systemStart.kind -ceq 'DWord') {
        [uint32]$savedSystemStart = 0
        if ([uint32]::TryParse([string]$systemStart.value, [ref]$savedSystemStart)) {
            $null = Set-ServiceStartupTypeFromStartValue -ServiceName 'WpnService' -StartValue $savedSystemStart
        }
    }
    $null = Restore-ExistingRegistrySnapshot -Snapshot $systemStart -ExpectedPath $systemStartDescriptor.Path -ExpectedName $systemStartDescriptor.Name
    $null = Restore-ExistingRegistrySnapshot -Snapshot $systemDelayed -ExpectedPath $systemDelayedDescriptor.Path -ExpectedName $systemDelayedDescriptor.Name
    $null = Restore-ExistingRegistrySnapshot -Snapshot $userStart -ExpectedPath $userStartDescriptor.Path -ExpectedName $userStartDescriptor.Name
    $null = Restore-ExistingRegistrySnapshot -Snapshot $userFlags -ExpectedPath $userFlagsDescriptor.Path -ExpectedName $userFlagsDescriptor.Name

    $backedPaths = @{}
    foreach ($snapshot in @($State.originalWpnInstanceValues)) {
        $path = [string]$snapshot.path
        $backedPaths[$path.ToLowerInvariant()] = $true

        # Per-user instances are removed at sign-out. Never recreate a stale
        # service key solely to restore an instance that no longer exists.
        if (-not (Test-Path -LiteralPath $path)) {
            continue
        }

        $serviceName = Split-Path -Leaf $path
        if ([bool]$snapshot.existed -and [string]$snapshot.kind -ceq 'DWord') {
            [uint32]$savedInstanceStart = 0
            if ([uint32]::TryParse([string]$snapshot.value, [ref]$savedInstanceStart)) {
                $null = Set-ServiceStartupTypeFromStartValue -ServiceName $serviceName -StartValue $savedInstanceStart
            }
        }
        $null = Restore-ExistingRegistrySnapshot -Snapshot $snapshot -ExpectedPath $path -ExpectedName 'Start'
    }

    # An instance may have been created after the original backup while WPN was
    # disabled. Restore such a live instance to the backed-up template Start
    # value; sign-out will remove it and future instances inherit the template.
    if ([bool]$userStart.existed -and [string]$userStart.kind -ceq 'DWord') {
        [uint32]$savedTemplateStart = 0
        if ([uint32]::TryParse([string]$userStart.value, [ref]$savedTemplateStart)) {
            foreach ($service in @(Get-WpnUserInstanceServices)) {
                $path = "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)"
                if (-not $backedPaths.ContainsKey($path.ToLowerInvariant())) {
                    $null = Set-ServiceStartupTypeFromStartValue -ServiceName $service.Name -StartValue $savedTemplateStart
                    $null = Set-ExistingRegistryValue -Path $path -Name 'Start' -Value $savedTemplateStart -Kind 'DWord'
                }
            }
        }
    }

    $runtimeEntries = @($State.originalServiceRuntime | Where-Object {
        [string]$_.name -ceq 'WpnService' -or [string]$_.name -ceq 'WpnUserService' -or
        [string]$_.name -match '^WpnUserService_[A-Za-z0-9]+$'
    })

    foreach ($runtime in @($runtimeEntries | Where-Object { [string]$_.name -ceq 'WpnService' })) {
        if ([bool]$runtime.wasRunning) {
            $service = Get-Service -Name 'WpnService' -ErrorAction SilentlyContinue
            if ($null -ne $service -and
                $service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
                try {
                    Start-Service -Name 'WpnService'
                } catch {
                    Write-Warn "Could not immediately restart WpnService: $($_.Exception.Message)"
                }
            }
        }
    }

    foreach ($runtime in @($runtimeEntries | Where-Object { [string]$_.name -ceq 'WpnUserService' })) {
        if ([bool]$runtime.wasRunning) {
            $service = Get-Service -Name 'WpnUserService' -ErrorAction SilentlyContinue
            if ($null -ne $service -and
                $service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
                try {
                    Start-Service -Name 'WpnUserService'
                } catch {
                    Write-Warn "Could not immediately restart WpnUserService template: $($_.Exception.Message)"
                }
            }
        }
    }

    foreach ($runtime in @($runtimeEntries | Where-Object { [string]$_.name -match '^WpnUserService_[A-Za-z0-9]+$' })) {
        if ([bool]$runtime.wasRunning) {
            $serviceName = [string]$runtime.name
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($null -ne $service -and
                $service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
                try {
                    Start-Service -Name $serviceName
                } catch {
                    Write-Warn "Could not immediately restart ${serviceName}: $($_.Exception.Message)"
                }
            }
        }
    }

    $restoreStatus = Get-WpnRestoreStatus -State $State
    if (-not $restoreStatus.Reconciled) {
        throw "WPN restoration verification failed for: $(@($restoreStatus.Mismatches) -join ', ')."
    }

    Write-Ok 'Restored backed-up Windows Push Notification service/template values.'
}


function Get-WpnRestoreStatus {
    param([Parameter(Mandatory = $true)]$State)

    Assert-TrustedState -State $State
    if ([int]$State.schemaVersion -lt 4) {
        return [pscustomobject]@{
            Known = $false
            Reconciled = $null
            Mismatches = @('Trusted state predates WPN management.')
        }
    }

    $mismatches = @()
    foreach ($descriptor in @($script:ServiceValueDescriptors | Where-Object { $_.Id -like 'Service.Wpn*' })) {
        $snapshot = Get-ManagedSnapshot -State $State -Id $descriptor.Id
        if (-not [bool]$snapshot.pathExisted) {
            continue
        }
        if (-not (Test-Path -LiteralPath ([string]$descriptor.Path))) {
            $mismatches += "$($descriptor.Id) (service key missing)"
            continue
        }
        if (-not (Test-RegistrySnapshotMatches `
            -Snapshot $snapshot `
            -ExpectedPath ([string]$descriptor.Path) `
            -ExpectedName ([string]$descriptor.Name))) {
            $mismatches += [string]$descriptor.Id
        }
    }

    $backedPaths = @{}
    foreach ($snapshot in @($State.originalWpnInstanceValues)) {
        $path = [string]$snapshot.path
        $backedPaths[$path.ToLowerInvariant()] = $true
        if (Test-Path -LiteralPath $path) {
            $matches = Test-RegistrySnapshotMatches -Snapshot $snapshot -ExpectedPath $path -ExpectedName 'Start'
            if (-not $matches -and (Test-Path -LiteralPath $path)) {
                $mismatches += [string]$snapshot.id
            }
        }
    }

    # Suffixes can change at sign-in. A current instance that did not exist at
    # backup is expected to inherit the saved template Start value.
    $templateDescriptor = @($script:ServiceValueDescriptors | Where-Object {
        $_.Id -ceq 'Service.WpnUserService.Start'
    })[0]
    $templateSnapshot = Get-ManagedSnapshot -State $State -Id $templateDescriptor.Id
    if ([bool]$templateSnapshot.existed -and [string]$templateSnapshot.kind -ceq 'DWord') {
        [uint32]$expectedTemplateStart = 0
        if (-not [uint32]::TryParse([string]$templateSnapshot.value, [ref]$expectedTemplateStart)) {
            $mismatches += 'Service.WpnUserService.Start (invalid protected DWord value)'
        } else {
            foreach ($service in @(Get-WpnUserInstanceServices)) {
                $path = "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)"
                if ($backedPaths.ContainsKey($path.ToLowerInvariant())) {
                    continue
                }
                $actual = Get-RegistryValueSnapshot -Id 'status' -Path $path -Name 'Start'
                if (-not (Test-RegistrySnapshotHasValue `
                    -Snapshot $actual `
                    -Kind 'DWord' `
                    -ExpectedValue $expectedTemplateStart) -and
                    (Test-Path -LiteralPath $path)) {
                    $mismatches += "Service.WpnUserService.Current.$($service.Name).Start"
                }
            }
        }
    }

    $mismatches += @(Get-PreviouslyRunningServiceMismatches -State $State -Family 'WPN')

    return [pscustomobject]@{
        Known = $true
        Reconciled = ($mismatches.Count -eq 0)
        Mismatches = @($mismatches)
    }
}



# -----------------------------------------------------------------------------
# Diagnostic-data service control
# -----------------------------------------------------------------------------

function Get-TelemetryServices {
    $services = @()
    foreach ($name in @('DiagTrack', 'dmwappushservice')) {
        $service = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($null -ne $service) {
            $services += $service
        }
    }
    return @($services | Sort-Object Name -Unique)
}

function Get-TelemetryBlockStatus {
    $entries = @()
    foreach ($item in @(
        [pscustomobject]@{ Name = 'DiagTrack'; Path = $script:DiagTrackSvcPath },
        [pscustomobject]@{ Name = 'dmwappushservice'; Path = $script:DmwappushSvcPath }
    )) {
        $service = Get-Service -Name $item.Name -ErrorAction SilentlyContinue
        $pathPresent = Test-Path -LiteralPath $item.Path
        $present = $pathPresent -or $null -ne $service
        $start = Get-RegistryValueSnapshot -Id 'status' -Path $item.Path -Name 'Start'
        $startDisabled = $present -and
            (Test-RegistrySnapshotHasValue -Snapshot $start -Kind 'DWord' -ExpectedValue 4)
        $running = $null -ne $service -and
            $service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running
        $statusText = if ($null -ne $service) { [string]$service.Status } else { '(not installed)' }
        $entries += [pscustomobject]@{
            Name = $item.Name
            Path = $item.Path
            Present = [bool]$present
            StartDisabled = [bool]$startDisabled
            Running = [bool]$running
            Status = $statusText
            StartValue = if ([bool]$start.existed) { [string]$start.value } else { '(not set)' }
        }
    }

    $presentEntries = @($entries | Where-Object { $_.Present })
    $notDisabled = @($presentEntries | Where-Object { -not $_.StartDisabled })
    $runningEntries = @($presentEntries | Where-Object { $_.Running })
    return [pscustomobject]@{
        ComponentsPresent = ($presentEntries.Count -gt 0)
        Entries = @($entries)
        ServicesStopped = ($runningEntries.Count -eq 0)
        StartsDisabled = ($notDisabled.Count -eq 0)
        FullyBlocked = ($presentEntries.Count -eq 0 -or
                        ($notDisabled.Count -eq 0 -and $runningEntries.Count -eq 0))
        RunningServiceNames = @($runningEntries | Select-Object -ExpandProperty Name)
        NotDisabledNames = @($notDisabled | Select-Object -ExpandProperty Name)
    }
}

function Enable-TelemetryBlock {
    param([Parameter(Mandatory = $true)]$State)

    Assert-TrustedState -State $State
    if ([int]$State.schemaVersion -lt 6) {
        throw 'Protected state predates telemetry service management. Run install again to migrate the state before enabling blockTelemetry.'
    }
    Assert-ManagedServicePathsBackedForMutation -State $State -Family 'Telemetry'

    foreach ($item in @(
        [pscustomobject]@{ Name = 'DiagTrack'; Path = $script:DiagTrackSvcPath },
        [pscustomobject]@{ Name = 'dmwappushservice'; Path = $script:DmwappushSvcPath }
    )) {
        $service = Get-Service -Name $item.Name -ErrorAction SilentlyContinue
        if ($null -ne $service) {
            Set-Service -Name $item.Name -StartupType Disabled
        }
        if (Test-Path -LiteralPath $item.Path) {
            $null = Set-ExistingRegistryValue -Path $item.Path -Name 'Start' -Value 4 -Kind 'DWord'
        }
    }

    $stopFailures = @()
    foreach ($name in @('dmwappushservice', 'DiagTrack')) {
        $service = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($null -ne $service -and
            $service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
            try {
                Stop-Service -Name $name -Force
            } catch {
                $after = Get-Service -Name $name -ErrorAction SilentlyContinue
                if ($null -ne $after -and
                    $after.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
                    $stopFailures += "${name}: $($_.Exception.Message)"
                }
            }
        }
    }
    if ($stopFailures.Count -gt 0) {
        throw "Could not stop all diagnostic-data services: $($stopFailures -join '; ')"
    }

    Start-Sleep -Milliseconds 500
    $status = Get-TelemetryBlockStatus
    if (-not $status.FullyBlocked) {
        $runningText = if (@($status.RunningServiceNames).Count -gt 0) {
            @($status.RunningServiceNames) -join ', '
        } else { 'none' }
        $enabledText = if (@($status.NotDisabledNames).Count -gt 0) {
            @($status.NotDisabledNames) -join ', '
        } else { 'none' }
        throw "Diagnostic-data service block verification failed. Running: $runningText. Start not disabled: $enabledText."
    }

    if ($status.ComponentsPresent) {
        Write-Ok 'DiagTrack and dmwappushservice are disabled and stopped.'
    } else {
        Write-Info 'DiagTrack and dmwappushservice are not installed on this Windows edition.'
    }
}

function Get-TelemetryRestoreStatus {
    param([Parameter(Mandatory = $true)]$State)

    Assert-TrustedState -State $State
    if ([int]$State.schemaVersion -lt 6) {
        return [pscustomobject]@{
            Known = $false
            Reconciled = $null
            Mismatches = @('Trusted state predates telemetry management.')
        }
    }

    $mismatches = @()
    foreach ($descriptor in @($script:ServiceValueDescriptors | Where-Object {
        $_.Id -like 'Service.DiagTrack*' -or $_.Id -like 'Service.dmwappushservice*'
    })) {
        $snapshot = Get-ManagedSnapshot -State $State -Id $descriptor.Id
        if (-not [bool]$snapshot.pathExisted) {
            continue
        }
        if (-not (Test-Path -LiteralPath ([string]$descriptor.Path))) {
            $mismatches += "$($descriptor.Id) (service key missing)"
            continue
        }
        if (-not (Test-RegistrySnapshotMatches -Snapshot $snapshot -ExpectedPath ([string]$descriptor.Path) -ExpectedName ([string]$descriptor.Name))) {
            $mismatches += [string]$descriptor.Id
        }
    }
    $mismatches += @(Get-PreviouslyRunningServiceMismatches -State $State -Family 'Telemetry')

    return [pscustomobject]@{
        Known = $true
        Reconciled = ($mismatches.Count -eq 0)
        Mismatches = @($mismatches)
    }
}

function Restore-TelemetryFromState {
    param([Parameter(Mandatory = $true)]$State)

    Assert-TrustedState -State $State
    if ([int]$State.schemaVersion -lt 6) {
        Write-Info 'Trusted state predates telemetry management; no telemetry service setting was changed or restored.'
        return
    }

    $preRestoreStatus = Get-TelemetryRestoreStatus -State $State
    if ($preRestoreStatus.Reconciled) {
        Write-Info 'Diagnostic-data services already match the protected baseline; no service write was needed.'
        return
    }

    foreach ($item in @(
        [pscustomobject]@{
            Name = 'DiagTrack'
            StartId = 'Service.DiagTrack.Start'
            DelayedId = 'Service.DiagTrack.DelayedAutoStart'
            Path = $script:DiagTrackSvcPath
        },
        [pscustomobject]@{
            Name = 'dmwappushservice'
            StartId = 'Service.dmwappushservice.Start'
            DelayedId = 'Service.dmwappushservice.DelayedAutoStart'
            Path = $script:DmwappushSvcPath
        }
    )) {
        $startSnapshot = Get-ManagedSnapshot -State $State -Id $item.StartId
        $delayedSnapshot = Get-ManagedSnapshot -State $State -Id $item.DelayedId

        if ([bool]$startSnapshot.existed -and [string]$startSnapshot.kind -ceq 'DWord') {
            [uint32]$savedStart = 0
            if ([uint32]::TryParse([string]$startSnapshot.value, [ref]$savedStart)) {
                $null = Set-ServiceStartupTypeFromStartValue -ServiceName $item.Name -StartValue $savedStart
            }
        }
        $null = Restore-ExistingRegistrySnapshot -Snapshot $startSnapshot -ExpectedPath $item.Path -ExpectedName 'Start'
        $null = Restore-ExistingRegistrySnapshot -Snapshot $delayedSnapshot -ExpectedPath $item.Path -ExpectedName 'DelayedAutoStart'
    }

    foreach ($runtime in @($State.originalServiceRuntime | Where-Object {
        ([string]$_.name -ceq 'DiagTrack' -or [string]$_.name -ceq 'dmwappushservice') -and
        [bool]$_.wasRunning
    })) {
        $name = [string]$runtime.name
        $service = Get-Service -Name $name -ErrorAction SilentlyContinue
        if ($null -ne $service -and
            $service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Running) {
            try {
                Start-Service -Name $name
            } catch {
                Write-Warn "Could not immediately restart ${name}: $($_.Exception.Message)"
            }
        }
    }

    $restoreStatus = Get-TelemetryRestoreStatus -State $State
    if (-not $restoreStatus.Reconciled) {
        throw "Diagnostic-data service restoration verification failed for: $(@($restoreStatus.Mismatches) -join ', ')."
    }
    Write-Ok 'Restored backed-up DiagTrack and dmwappushservice values and runtime state.'
}

# -----------------------------------------------------------------------------
# HOSTS file management
# -----------------------------------------------------------------------------

function Read-TextFilePreservingEncoding {
    param([Parameter(Mandatory = $true)][string]$Path)

    $reader = New-Object -TypeName IO.StreamReader -ArgumentList @(
        $Path,
        [Text.Encoding]::Default,
        $true
    )
    try {
        $content = $reader.ReadToEnd()
        $encoding = $reader.CurrentEncoding
    } finally {
        $reader.Dispose()
    }

    return [pscustomobject]@{
        Content = $content
        Encoding = $encoding
    }
}

function Write-HostsTextWithRollback {
    param(
        [Parameter(Mandatory = $true)][string]$NewContent,
        [Parameter(Mandatory = $true)][Text.Encoding]$Encoding,
        [Parameter(Mandatory = $true)][scriptblock]$Verify
    )

    $backupPath = "$($script:HostsPath).gdid.$PID.$([Guid]::NewGuid().ToString('N')).bak"
    Copy-Item -LiteralPath $script:HostsPath -Destination $backupPath -Force -ErrorAction Stop
    $completed = $false
    $restored = $false

    try {
        [IO.File]::WriteAllText($script:HostsPath, $NewContent, $Encoding)
        & $Verify
        $completed = $true
    } catch {
        $updateError = $_
        try {
            Copy-Item -LiteralPath $backupPath -Destination $script:HostsPath -Force -ErrorAction Stop
            $restored = $true
        } catch {
            throw "HOSTS update failed and rollback also failed. The backup was retained at '$backupPath'. Update error: $($updateError.Exception.Message); rollback error: $($_.Exception.Message)"
        }
        throw "HOSTS update failed and the original file was restored: $($updateError.Exception.Message)"
    } finally {
        if ($completed -or $restored) {
            Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-ConfiguredHostDomains {
    param([Parameter(Mandatory = $true)][hashtable]$Config)

    if (-not [bool]$Config['blockHosts']) {
        return @()
    }

    $domains = @($script:ActivityHostDomains)
    if ([bool]$Config['blockAADHost']) {
        $domains += $script:AADHostDomains
    }
    return @($domains | Sort-Object -Unique)
}

function Get-HostsBlockInfo {
    if (-not $script:HostsPath -or -not (Test-Path -LiteralPath $script:HostsPath)) {
        return [pscustomobject]@{
            Exists = $false
            WellFormed = $false
            Content = $null
            Encoding = [Text.Encoding]::Default
            BlockText = $null
            BeginCount = 0
            EndCount = 0
        }
    }

    $file = Read-TextFilePreservingEncoding -Path $script:HostsPath
    $content = [string]$file.Content
    $beginCount = ([regex]::Matches($content, [regex]::Escape($script:HostsBeginMarker))).Count
    $endCount = ([regex]::Matches($content, [regex]::Escape($script:HostsEndMarker))).Count
    $wellFormed = ($beginCount -eq 0 -and $endCount -eq 0) -or ($beginCount -eq 1 -and $endCount -eq 1)
    $blockText = $null

    if ($beginCount -eq 1 -and $endCount -eq 1) {
        $match = [regex]::Match(
            $content,
            "(?ms)$([regex]::Escape($script:HostsBeginMarker)).*?$([regex]::Escape($script:HostsEndMarker))"
        )
        if ($match.Success) {
            $blockText = $match.Value
        } else {
            $wellFormed = $false
        }
    }

    return [pscustomobject]@{
        Exists = $true
        WellFormed = $wellFormed
        Content = $content
        Encoding = $file.Encoding
        BlockText = $blockText
        BeginCount = $beginCount
        EndCount = $endCount
    }
}

function Flush-DnsCache {
    $ipconfig = Join-Path $env:SystemRoot 'System32\ipconfig.exe'
    try {
        & $ipconfig /flushdns | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Write-Warn "HOSTS changed, but ipconfig /flushdns returned exit code $LASTEXITCODE."
        }
    } catch {
        Write-Warn "HOSTS changed, but DNS cache flush failed: $($_.Exception.Message)"
    }
}

function Test-HostsDomainsBlocked {
    param([Parameter(Mandatory = $true)][string[]]$Domains)

    if ($Domains.Count -eq 0) {
        return $true
    }

    $info = Get-HostsBlockInfo
    if (-not $info.Exists -or -not $info.WellFormed -or $null -eq $info.BlockText) {
        return $false
    }

    foreach ($domain in $Domains) {
        $escaped = [regex]::Escape($domain)
        $hasV4 = [string]$info.BlockText -match "(?im)^\s*0\.0\.0\.0\s+$escaped\s*$"
        $hasV6 = [string]$info.BlockText -match "(?im)^\s*::\s+$escaped\s*$"
        if (-not $hasV4 -or -not $hasV6) {
            return $false
        }
    }
    return $true
}

function Install-HostsBlocks {
    param([Parameter(Mandatory = $true)][string[]]$Domains)

    if (-not $script:HostsPath -or -not (Test-Path -LiteralPath $script:HostsPath)) {
        throw "HOSTS file was not found at '$($script:HostsPath)'."
    }
    if ($Domains.Count -eq 0) {
        throw 'No HOSTS domains were supplied.'
    }

    $info = Get-HostsBlockInfo
    if (-not $info.WellFormed) {
        throw 'HOSTS contains malformed or duplicate GDID Privacy markers. It was left unchanged.'
    }

    $content = [string]$info.Content
    if ($null -ne $info.BlockText) {
        $content = $content.Replace([string]$info.BlockText, '')
    }

    $lines = @($script:HostsBeginMarker)
    foreach ($domain in @($Domains | Sort-Object -Unique)) {
        $lines += "0.0.0.0`t$domain"
        $lines += "::`t$domain"
    }
    $lines += $script:HostsEndMarker

    $trimmed = $content.TrimEnd("`r", "`n")
    if ($trimmed.Length -gt 0) {
        $newContent = $trimmed + "`r`n`r`n" + ($lines -join "`r`n") + "`r`n"
    } else {
        $newContent = ($lines -join "`r`n") + "`r`n"
    }

    Write-HostsTextWithRollback -NewContent $newContent -Encoding $info.Encoding -Verify {
        if (-not (Test-HostsDomainsBlocked -Domains $Domains)) {
            throw 'HOSTS write verification failed.'
        }
    }

    Flush-DnsCache
    Write-Ok "Installed exact-name IPv4/IPv6 HOSTS blocks for $($Domains.Count) domain(s)."
}

function Uninstall-HostsBlocks {
    if (-not $script:HostsPath -or -not (Test-Path -LiteralPath $script:HostsPath)) {
        return
    }

    $info = Get-HostsBlockInfo
    if (-not $info.WellFormed) {
        throw 'HOSTS contains malformed or duplicate GDID Privacy markers. It was left unchanged.'
    }
    if ($null -eq $info.BlockText) {
        return
    }

    $content = ([string]$info.Content).Replace([string]$info.BlockText, '')
    $content = $content.TrimEnd("`r", "`n")
    if ($content.Length -gt 0) {
        $content += "`r`n"
    }

    Write-HostsTextWithRollback -NewContent $content -Encoding $info.Encoding -Verify {
        $verify = Get-HostsBlockInfo
        if ($verify.BeginCount -ne 0 -or $verify.EndCount -ne 0) {
            throw 'HOSTS removal verification failed.'
        }
    }

    Flush-DnsCache
    Write-Ok 'Removed GDID Privacy HOSTS block.'
}

# -----------------------------------------------------------------------------
# Scheduled task: non-elevated and current-user only
# -----------------------------------------------------------------------------

function Get-RotationTaskName {
    $suffix = $script:CurrentUserSid.Replace('-', '_')
    return "GDIDRotator-$suffix"
}


function Uninstall-RotationTask {
    $names = @((Get-RotationTaskName), 'GDIDRotator')
    foreach ($taskName in @($names | Sort-Object -Unique)) {
        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($null -ne $task) {
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
            Write-Ok "Stopped and removed scheduled task '$taskName'."
        }
    }
}

function Install-RotationTask {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Config,
        [Parameter(Mandatory = $true)][bool]$LocalMaskEnabled
    )

    Uninstall-RotationTask
    if (-not $LocalMaskEnabled -or $Config['rotationMode'] -eq 'onDemand') {
        Write-Info 'Automatic local masking is disabled.'
        return
    }

    if ([string]::IsNullOrWhiteSpace($script:InvocationPath)) {
        throw 'Cannot determine the script/executable path for Task Scheduler.'
    }
    $invocationPath = (Resolve-Path -LiteralPath $script:InvocationPath).Path
    $extension = [IO.Path]::GetExtension($invocationPath)

    if ($extension -ieq '.exe') {
        $actionExecutable = $invocationPath
        $arguments = 'rotate -Scheduled'
    } else {
        if ($PSVersionTable.PSEdition -eq 'Core') {
            $actionExecutable = Join-Path $PSHOME 'pwsh.exe'
        } else {
            $actionExecutable = Join-Path $PSHOME 'powershell.exe'
        }
        if (-not (Test-Path -LiteralPath $actionExecutable)) {
            throw "PowerShell host executable was not found at '$actionExecutable'."
        }
        $arguments = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$invocationPath`" rotate -Scheduled"
    }

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $userId = $identity.Name
    $taskName = Get-RotationTaskName
    $action = New-ScheduledTaskAction -Execute $actionExecutable -Argument $arguments

    if ($Config['rotationMode'] -eq 'perLogon') {
        # The target values are under HKCU, so the correct current-user context
        # is logon rather than an AtStartup/S4U task.
        $triggers = @(New-ScheduledTaskTrigger -AtLogOn -User $userId)
    } elseif ($Config['rotationMode'] -eq 'timed') {
        $triggers = @(
            New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
                -RepetitionInterval (New-TimeSpan -Minutes ([int]$Config['timedIntervalMin'])) `
                -RepetitionDuration (New-TimeSpan -Days 3650)
        )
    } else {
        throw "Unexpected rotation mode '$($Config['rotationMode'])'."
    }

    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -MultipleInstances IgnoreNew

    $principal = New-ScheduledTaskPrincipal -UserId $userId -LogonType Interactive -RunLevel Limited

    Register-ScheduledTask `
        -TaskName $taskName `
        -Action $action `
        -Trigger $triggers `
        -Settings $settings `
        -Principal $principal `
        -Description 'Locally masks HKCU GDID registry copies. Does not rotate the Microsoft-issued Device PUID.' `
        -Force | Out-Null

    $verify = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
    if ($null -eq $verify) {
        throw "Task Scheduler did not return newly registered task '$taskName'."
    }

    Write-Ok "Created non-elevated current-user task '$taskName' (mode: $($Config['rotationMode']))."
    if ($Config['rotationMode'] -eq 'perLogon') {
        Write-Info 'The legacy perBoot behavior is implemented as perLogon/AtLogOn because the target values are under HKCU.'
    }
}


# -----------------------------------------------------------------------------
# Status and command implementations
# -----------------------------------------------------------------------------

function Get-PolicyActualStatus {
    param(
        [Parameter(Mandatory = $true)]$Descriptor,
        [Parameter(Mandatory = $true)][hashtable]$Config,
        [AllowNull()]$State
    )

    $actual = Get-RegistryValueSnapshot -Id 'status' -Path $Descriptor.Path -Name $Descriptor.Name
    $requested = [bool]$Config[$Descriptor.ConfigKey]
    $applicability = Get-PolicyApplicability -Descriptor $Descriptor
    $desired = Get-PolicyDesiredValue -Descriptor $Descriptor
    $active = [bool]$applicability.Applicable -and
        (Test-RegistrySnapshotHasValue `
            -Snapshot $actual `
            -Kind ([string]$Descriptor.Kind) `
            -ExpectedValue $desired)
    $valueText = if ([bool]$actual.existed) { [string]$actual.value } else { '(not set)' }

    $reconciled = $null
    if ($requested -and [bool]$applicability.Applicable) {
        $reconciled = $active
    } elseif ($null -ne $State) {
        try {
            $original = Get-ManagedSnapshot -State $State -Id $Descriptor.Id
            $reconciled = Test-RegistrySnapshotMatches `
                -Snapshot $original `
                -ExpectedPath ([string]$Descriptor.Path) `
                -ExpectedName ([string]$Descriptor.Name)
        } catch {
            $reconciled = $false
        }
    }

    return [pscustomobject]@{
        Id = [string]$Descriptor.Id
        Label = $Descriptor.Label
        Requested = $requested
        Applicable = [bool]$applicability.Applicable
        ApplicabilityReason = [string]$applicability.Reason
        DesiredValue = $desired
        Active = $active
        Reconciled = $reconciled
        Value = $valueText
    }
}


function Show-Status {
    Assert-Windows
    $config = Get-Config
    $state = $null
    $stateError = $null
    try {
        $state = Get-State
    } catch {
        $stateError = $_.Exception.Message
    }
    $runtime = Get-RuntimeState
    $platform = Get-WindowsPlatformProfile

    Write-Host "`n===== GDID Privacy Status (audited build) =====`n" -ForegroundColor Cyan

    Write-Host '-- Local registry identity copies --' -ForegroundColor Cyan
    $identityValues = @(Get-CurrentIdentityValues)
    if ($identityValues.Count -eq 0) {
        Write-Host '  No existing LID/DeviceId registry values were found.' -ForegroundColor DarkGray
    } else {
        foreach ($entry in $identityValues) {
            $decimal = if ($entry.valid) { Convert-GDIDToDecimalText -Hex $entry.value } else { '(invalid format)' }
            Write-Host "  $($entry.id): $($entry.value)  [$decimal]"
        }
    }
    Write-Warn 'These are local registry copies, not proof that the Microsoft-issued Device PUID or DeviceTicket changed.'

    Write-Host "`n-- Windows diagnostic-data capability --" -ForegroundColor Cyan
    Write-Host "  Product:                 $($platform.ProductName) $($platform.DisplayVersion)"
    Write-Host "  EditionID / build:       $($platform.EditionId) / $($platform.Build)"
    Write-Host "  Group Policy label:      $($platform.DiagnosticPolicyDisplayName)"
    Write-Host "  Supported minimum:       $($platform.MinimumDiagnosticDataValue) ($($platform.MinimumDiagnosticDataName))"
    Write-Host "  Diagnostic data off (0): $($platform.SupportsDiagnosticDataOff)"
    if (-not $platform.SupportsDiagnosticDataOff) {
        Write-Info 'This edition does not honor AllowTelemetry=0; the tool uses value 1 instead of reporting a placebo value 0.'
    }

    Write-Host "`n-- Actual CDP state --" -ForegroundColor Cyan
    $cdp = Get-CDPBlockStatus
    Write-Host "  CDPSvc Start=Disabled:              $($cdp.CDPSvcStartDisabled)"
    Write-Host "  CDPUserSvc template Start=Disabled: $($cdp.CDPUserTemplateDisabled)"
    Write-Host "  CDPUserSvc creation blocked:        $($cdp.CDPUserCreationBlocked)"
    Write-Host "  Current CDPUserSvc instances:         $($cdp.CDPUserInstanceCount)"
    Write-Host "  Current instances Start=Disabled:    $($cdp.CDPUserInstancesDisabled)"
    Write-Host "  EnableCdp policy disabled:          $($cdp.PolicyDisabled)"
    Write-Host "  CDP services stopped:               $($cdp.ServicesStopped)"
    if (@($cdp.RunningServiceNames).Count -gt 0) {
        Write-Warn "Running CDP services: $(@($cdp.RunningServiceNames) -join ', ')"
    }
    if (@($cdp.InstanceNotDisabledNames).Count -gt 0) {
        Write-Warn "CDPUserSvc instances not disabled: $(@($cdp.InstanceNotDisabledNames) -join ', ')"
    }

    Write-Host "`n-- Actual Windows Push Notification state --" -ForegroundColor Cyan
    $wpn = Get-WpnBlockStatus
    Write-Host "  WPN components present:                     $($wpn.ComponentsPresent)"
    Write-Host "  WpnService Start=Disabled:               $($wpn.WpnServiceStartDisabled)"
    Write-Host "  WpnUserService template Start=Disabled:  $($wpn.WpnUserTemplateDisabled)"
    Write-Host "  WpnUserService creation blocked:         $($wpn.WpnUserCreationBlocked)"
    Write-Host "  Existing user instances disabled:        $($wpn.WpnUserInstancesDisabled) ($($wpn.WpnUserInstanceCount) found)"
    Write-Host "  WPN services stopped:                    $($wpn.ServicesStopped)"
    if (@($wpn.RunningServiceNames).Count -gt 0) {
        Write-Warn "Running WPN services: $(@($wpn.RunningServiceNames) -join ', ')"
    }
    if (@($wpn.InstanceNotDisabledNames).Count -gt 0) {
        Write-Warn "WpnUserService instances not disabled: $(@($wpn.InstanceNotDisabledNames) -join ', ')"
    }

    Write-Host "`n-- Actual diagnostic-data service state --" -ForegroundColor Cyan
    $telemetryServices = Get-TelemetryBlockStatus
    foreach ($entry in @($telemetryServices.Entries)) {
        Write-Host ("  {0,-18} present={1}, status={2}, Start={3}, disabled={4}" -f
            $entry.Name, $entry.Present, $entry.Status, $entry.StartValue, $entry.StartDisabled)
    }
    Write-Host "  Diagnostic-data services stopped: $($telemetryServices.ServicesStopped)"
    Write-Host "  Telemetry service block complete: $($telemetryServices.FullyBlocked)"
    if (@($telemetryServices.RunningServiceNames).Count -gt 0) {
        Write-Warn "Running diagnostic-data services: $(@($telemetryServices.RunningServiceNames) -join ', ')"
    }

    Write-Host "`n-- Managed policies: requested vs actual --" -ForegroundColor Cyan
    foreach ($descriptor in $script:PolicyDescriptors) {
        $policyStatus = Get-PolicyActualStatus -Descriptor $descriptor -Config $config -State $state
        $reconciledText = if ($null -eq $policyStatus.Reconciled) {
            'unknown (no trusted backup)'
        } else {
            [string]$policyStatus.Reconciled
        }
        $color = if ($policyStatus.Reconciled -eq $true) { 'Green' } else { 'Yellow' }
        Write-Host (
            "  {0}: requested={1}, applicable={2}, desired={3}, controlActive={4}, reconciled={5}, value={6}" -f
            $policyStatus.Label,
            $policyStatus.Requested,
            $policyStatus.Applicable,
            $policyStatus.DesiredValue,
            $policyStatus.Active,
            $reconciledText,
            $policyStatus.Value
        ) -ForegroundColor $color
        if ($policyStatus.Requested -and -not $policyStatus.Applicable) {
            Write-Info "    Not applied: $($policyStatus.ApplicabilityReason)."
        }
    }
    Write-Info 'LimitEnhancedDiagnosticDataWindowsAnalytics is intentionally set to 0: that is the Group Policy choice Disable Windows Analytics collection. Value 1 would enable the Desktop/Windows Analytics exception.'
    Write-Info 'The tool writes the policy registry values and verifies them after gpupdate /force; it does not edit Registry.pol or make Local Group Policy Editor display them as locally configured.'

    Write-Host "`n-- Settings-equivalent diagnostics controls --" -ForegroundColor Cyan
    $settingsControlIds = @(
        'Telemetry.AllowTelemetry',
        'Telemetry.DisableTelemetryOptInSettingsUx',
        'Telemetry.DisableTailoredExperiencesWithDiagnosticData',
        'Telemetry.AllowLinguisticDataCollection',
        'Telemetry.RestrictImplicitTextCollection',
        'Telemetry.RestrictImplicitInkCollection',
        'Telemetry.DisableDeviceDelete'
    )
    $settingsStatuses = @{}
    foreach ($settingsId in $settingsControlIds) {
        $settingsDescriptor = Get-PolicyDescriptor -Id $settingsId
        $settingsStatuses[$settingsId] = Get-PolicyActualStatus -Descriptor $settingsDescriptor -Config $config -State $state
    }

    $minimumActive = [bool]$settingsStatuses['Telemetry.AllowTelemetry'].Active
    $optInLocked = if ([bool]$settingsStatuses['Telemetry.DisableTelemetryOptInSettingsUx'].Applicable) {
        [bool]$settingsStatuses['Telemetry.DisableTelemetryOptInSettingsUx'].Active
    } else { $null }
    $tailoredOff = if ([bool]$settingsStatuses['Telemetry.DisableTailoredExperiencesWithDiagnosticData'].Applicable) {
        [bool]$settingsStatuses['Telemetry.DisableTailoredExperiencesWithDiagnosticData'].Active
    } else { $null }
    $inkingTypingStatuses = @(
        $settingsStatuses['Telemetry.AllowLinguisticDataCollection'],
        $settingsStatuses['Telemetry.RestrictImplicitTextCollection'],
        $settingsStatuses['Telemetry.RestrictImplicitInkCollection']
    )
    $inkingApplicable = @($inkingTypingStatuses | Where-Object { [bool]$_.Applicable })
    $inkingTypingOff = if ($inkingApplicable.Count -gt 0) {
        @($inkingApplicable | Where-Object { -not [bool]$_.Active }).Count -eq 0
    } else { $null }
    $deleteAvailable = if ([bool]$settingsStatuses['Telemetry.DisableDeviceDelete'].Applicable) {
        [bool]$settingsStatuses['Telemetry.DisableDeviceDelete'].Active
    } else { $null }

    $optionalText = if (-not [bool]$config['blockTelemetry']) {
        'not managed (blockTelemetry=false)'
    } elseif ($minimumActive) {
        "forced to $($platform.MinimumDiagnosticDataName) ($($platform.MinimumDiagnosticDataValue))"
    } else {
        'NOT at the requested edition minimum'
    }
    $optInText = if ($null -eq $optInLocked) { 'not applicable' } elseif ($optInLocked) { 'disabled/locked' } else { 'not disabled' }
    $tailoredText = if ($null -eq $tailoredOff) { 'not applicable' } elseif ($tailoredOff) { 'off' } else { 'not forced off' }
    $inkingText = if ($null -eq $inkingTypingOff) { 'not applicable' } elseif ($inkingTypingOff) { 'off' } else { 'not fully forced off' }
    $deleteText = if ($null -eq $deleteAvailable) { 'not applicable' } elseif ($deleteAvailable) { 'available' } else { 'disabled by policy' }

    Write-Host "  Send optional diagnostic data: $optionalText"
    Write-Host "  Diagnostic-data opt-in UI:    $optInText"
    Write-Host "  Tailored experiences:         $tailoredText"
    Write-Host "  Improve inking and typing:    $inkingText"
    Write-Host "  Delete diagnostic data:       $deleteText"
    if ($null -ne $runtime -and $runtime.lastDiagnosticDeleteAttempt) {
        Write-Host "  Last deletion request:         $($runtime.lastDiagnosticDeleteAttempt); accepted=$($runtime.lastDiagnosticDeleteAccepted)"
    } elseif ([bool]$config['requestDiagnosticDataDelete']) {
        Write-Host '  Last deletion request:         pending (run install as Administrator)'
    } else {
        Write-Host '  Last deletion request:         none recorded by this tool'
    }

    Write-Host "`n-- HOSTS block --" -ForegroundColor Cyan
    $hostsInfo = Get-HostsBlockInfo
    $blockPresent = $null -ne $hostsInfo.BlockText
    if ([bool]$config['blockHosts']) {
        $domains = @(Get-ConfiguredHostDomains -Config $config)
        $hostsMatch = Test-HostsDomainsBlocked -Domains $domains
        Write-Host "  Requested domains: $($domains -join ', ')"
        Write-Host "  Marker block well formed: $($hostsInfo.WellFormed)"
        Write-Host "  Required IPv4/IPv6 entries present: $hostsMatch" -ForegroundColor $(if ($hostsMatch) { 'Green' } else { 'Yellow' })
    } else {
        $hostsMatch = (-not $blockPresent) -and [bool]$hostsInfo.WellFormed
        Write-Host '  Requested domains: (blocking disabled)'
        Write-Host "  Managed marker block absent: $(-not $blockPresent)" -ForegroundColor $(if ($hostsMatch) { 'Green' } else { 'Yellow' })
    }
    if ([bool]$config['blockAADHost']) {
        Write-Warn 'aad.cs.dds.microsoft.com is authentication-related and may break Microsoft-account functionality.'
    }

    Write-Host "`n-- Scheduled task --" -ForegroundColor Cyan
    try {
        $taskName = Get-RotationTaskName
        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        $taskExpected = [bool]$config['blockCDP'] -and
                        $config['hookMethod'] -eq 'registry' -and
                        $config['rotationMode'] -ne 'onDemand'
        if ($null -ne $task) {
            $taskColor = if ($taskExpected) { 'Green' } else { 'Yellow' }
            Write-Host "  ${taskName}: $($task.State) (expected=$taskExpected)" -ForegroundColor $taskColor
        } else {
            $taskColor = if ($taskExpected) { 'Yellow' } else { 'Green' }
            Write-Host "  ${taskName}: not installed (expected=$taskExpected)" -ForegroundColor $taskColor
        }
    } catch {
        Write-Warn "Could not query Task Scheduler: $($_.Exception.Message)"
    }

    Write-Host "`n-- Configuration --" -ForegroundColor Cyan
    foreach ($name in @(
        'rotationMode', 'timedIntervalMin', 'blockCDP', 'blockWpn', 'blockTelemetry',
        'requestDiagnosticDataDelete', 'blockHosts', 'blockAADHost', 'blockDO',
        'killPhoneLink', 'killOneDrive', 'killStore', 'killTimeline', 'hookMethod'
    )) {
        Write-Host ("  {0,-20} {1}" -f $name, $config[$name])
    }

    Write-Host "`n-- Reversible state --" -ForegroundColor Cyan
    $security = Get-TrustedStateSecurityStatus
    Write-Host "  Path:          $($script:StatePath)"
    Write-Host "  Protected ACL: $($security.Protected) ($($security.Detail))" -ForegroundColor $(if ($security.Protected) { 'Green' } else { 'Yellow' })
    if ($stateError) {
        Write-Warn $stateError
    } elseif ($null -ne $state) {
        Write-Host "  Schema:        $($state.schemaVersion)"
        Write-Host "  Installed:     $($state.installed)"
        Write-Host "  Created:       $(Get-ObjectPropertyValue -InputObject $state -Name 'createdAt')"
        Write-Host "  Backed targets: $(@($state.originalIdentity.values).Count)"
        if ([int]$state.schemaVersion -ge 4) {
            Write-Host "  WPN instance backups: $(@($state.originalWpnInstanceValues).Count)"
            Write-Host "  WPN baseline sealed:   $($state.wpnInstanceBaselineSealed)"
        } else {
            Write-Warn 'Protected state predates WPN support; run install as Administrator to migrate it before enabling blockWpn.'
        }
        if ([int]$state.schemaVersion -ge 5) {
            Write-Host "  CDP instance backups: $(@($state.originalCdpInstanceValues).Count)"
            Write-Host "  CDP baseline sealed:   $($state.cdpInstanceBaselineSealed)"
        } else {
            Write-Warn 'Protected state predates exact CDP instance rollback; run install as Administrator to migrate it before the next CDP modification.'
        }
        if ([int]$state.schemaVersion -ge 6) {
            Write-Host '  Telemetry policy/service rollback: captured'
        } else {
            Write-Warn 'Protected state predates telemetry rollback; run install as Administrator to migrate it before enabling blockTelemetry.'
        }
    } else {
        Write-Host '  No install state is present.' -ForegroundColor DarkGray
    }

    if ($null -ne $runtime) {
        Write-Host "`n-- Last local operation --" -ForegroundColor Cyan
        Write-Host "  Operation:     $($runtime.lastOperation)"
        Write-Host "  Last rotation: $($runtime.lastRotation)"
        Write-Host "  Last fake:     $($runtime.lastFakeGDID)"
        Write-Host "  Result:        $($runtime.lastResult)"
        if ($runtime.lastDiagnosticDeleteAttempt) {
            Write-Host "  Delete request attempted: $($runtime.lastDiagnosticDeleteAttempt)"
            Write-Host "  Delete request accepted:  $($runtime.lastDiagnosticDeleteAccepted)"
            Write-Host "  Delete request result:    $($runtime.lastDiagnosticDeleteResult)"
        }
    }

    Write-Host "`n-- Honest protection assessment --" -ForegroundColor Cyan
    if ([bool]$config['blockCDP']) {
        if ($cdp.ReadyForLocalMask) {
            Write-Ok 'The managed CDP component and current per-user instances are disabled and stopped for this boot.'
        } else {
            Write-Warn 'blockCDP=true, but CDP is not fully disabled according to live state; a local registry mask is not reliable.'
        }
    } elseif ($null -ne $state) {
        try {
            $cdpRestore = Get-CDPRestoreStatus -State $state
            if ($cdpRestore.Reconciled) {
                Write-Ok 'blockCDP=false and managed CDP registry values match the protected pre-tool baseline.'
            } else {
                Write-Warn "blockCDP=false, but CDP state does not match the protected baseline: $(@($cdpRestore.Mismatches) -join ', ')."
            }
        } catch {
            Write-Warn "Could not compare CDP state with the protected baseline: $($_.Exception.Message)"
        }
    } else {
        Write-Info 'blockCDP=false and no protected baseline exists for comparison.'
    }
    if ([bool]$config['blockWpn']) {
        if (-not $wpn.ComponentsPresent) {
            Write-Info 'WPN service components are not installed on this Windows edition.'
        } elseif ($wpn.FullyBlocked) {
            Write-Ok 'WpnService, the WpnUserService template, and current instances are disabled and stopped.'
        } else {
            Write-Warn 'blockWpn=true, but Windows Push Notification services are not fully disabled according to live state.'
        }
        Write-Warn 'Disabling WPN blocks cloud push notifications and can also break local toast/tile/raw notifications and notification-dependent Windows/app workflows.'
    } elseif ($null -ne $state -and [int]$state.schemaVersion -ge 4) {
        try {
            $wpnRestore = Get-WpnRestoreStatus -State $state
            if ($wpnRestore.Reconciled) {
                Write-Ok 'blockWpn=false and managed WPN registry values match the protected pre-tool baseline.'
            } else {
                Write-Warn "blockWpn=false, but WPN state does not match the protected baseline: $(@($wpnRestore.Mismatches) -join ', ')."
            }
        } catch {
            Write-Warn "Could not compare WPN state with the protected baseline: $($_.Exception.Message)"
        }
    }
    if ([bool]$config['blockTelemetry']) {
        if (-not $telemetryServices.ComponentsPresent) {
            Write-Info 'DiagTrack and dmwappushservice are not installed on this edition.'
        } elseif ($telemetryServices.FullyBlocked) {
            Write-Ok 'DiagTrack and dmwappushservice are disabled and stopped.'
        } else {
            Write-Warn 'blockTelemetry=true, but diagnostic-data services are not fully disabled according to live state.'
        }
        Write-Warn 'Diagnostic-data policies and service disabling reduce Windows diagnostic traffic, but they do not guarantee that all Microsoft telemetry or identity traffic is blocked.'
        if ([int]$platform.MinimumDiagnosticDataValue -eq 1) {
            Write-Info 'This Pro/consumer edition is set to Required diagnostic data (1), its supported minimum; Diagnostic data off (0) requires a qualifying edition.'
        }
    } elseif ($null -ne $state -and [int]$state.schemaVersion -ge 6) {
        try {
            $telemetryRestore = Get-TelemetryRestoreStatus -State $state
            if ($telemetryRestore.Reconciled) {
                Write-Ok 'blockTelemetry=false and diagnostic-data services match the protected baseline.'
            } else {
                Write-Warn "blockTelemetry=false, but diagnostic-data services do not match the protected baseline: $(@($telemetryRestore.Mismatches) -join ', ')."
            }
        } catch {
            Write-Warn "Could not compare diagnostic-data services with the protected baseline: $($_.Exception.Message)"
        }
    }
    if ([bool]$config['requestDiagnosticDataDelete']) {
        Write-Warn 'A one-shot diagnostic-data deletion request is pending. Run install as Administrator; the flag clears only after Windows accepts the request.'
    }
    if ([bool]$config['blockDO']) {
        Write-Info 'DODownloadMode=99 is an opt-in Delivery Optimization policy; it is not GDID rotation and can affect update delivery.'
    }
    Write-Warn 'HOSTS blocks are exact-name, best-effort resolver controls; they do not prove that all identity-reporting paths are blocked.'
    Write-Warn 'The tool cannot replace or verify removal of the authoritative server-issued identifier.'
    Write-Host ''
}


function Invoke-Rotate {
    Assert-Windows
    $config = Get-Config

    if ($config['hookMethod'] -ne 'registry') {
        throw 'Local masking is disabled because hookMethod=none.'
    }
    if (-not [bool]$config['blockCDP']) {
        throw 'Refusing a self-reverting local mask while blockCDP=false. Enable blockCDP and run install first.'
    }

    $state = Get-State
    $runtime = Get-RuntimeState
    if ($null -eq $state) {
        throw 'No protected reversible install state exists. Run install as Administrator before rotate.'
    }
    if (-not [bool]$state.installed) {
        throw 'The protected state records an incomplete installation. Run install as Administrator before rotate.'
    }

    $cdp = Get-CDPBlockStatus
    if (-not $cdp.ReadyForLocalMask) {
        throw 'Refusing to mask registry values because CDP is not fully disabled and stopped. Run install as Administrator.'
    }

    $newValue = New-FakeGDID
    $maskResult = Set-LocalGDIDMask `
        -State $state `
        -NewValue $newValue `
        -KnownMaskValue $(if ($null -ne $runtime) { $runtime.lastFakeGDID } else { $null })
    $resultText = if ($maskResult.Wrote) {
        "Local registry mask written and verified in $($maskResult.Count) target(s)."
    } else {
        'No currently existing, safely backed identity registry values were found; nothing was written.'
    }

    try {
        Save-RuntimeState -Operation 'rotate' `
            -LastFakeGDID $(if ($maskResult.Wrote) { $newValue } elseif ($null -ne $runtime) { $runtime.lastFakeGDID } else { $null }) `
            -Result $resultText `
            -IsRotation ([bool]$maskResult.Wrote)
    } catch {
        $runtimeError = $_.Exception.Message
        if ($maskResult.Wrote) {
            try {
                Restore-IdentitySnapshotsAfterFailedMask `
                    -Snapshots @($maskResult.PreviousValues) `
                    -ExpectedMaskValue $newValue
            } catch {
                throw "Runtime-state commit failed and the new local mask could not be rolled back completely. Runtime error: $runtimeError; rollback error: $($_.Exception.Message)"
            }
            throw "Runtime-state commit failed; the new local registry mask was rolled back to the immediately preceding values. $runtimeError"
        }
        throw "No identity values were changed, but runtime status could not be saved. $runtimeError"
    }

    if (-not $Scheduled) {
        Write-Host "`n===== Local GDID Registry Mask =====`n" -ForegroundColor Cyan
        if ($maskResult.Wrote) {
            Write-Ok "Wrote and verified local value $newValue in $($maskResult.Count) target(s)"
        } else {
            Write-Warn $resultText
        }
        Write-Warn 'The Microsoft-issued Device PUID and DeviceTicket were not changed.'
    }
}


function Install-All {
    Assert-Windows
    Assert-Administrator
    $config = Get-Config
    if ([bool]$config['requestDiagnosticDataDelete'] -and -not [bool]$config['blockTelemetry']) {
        throw 'requestDiagnosticDataDelete=true requires blockTelemetry=true so deletion remains available, applicable diagnostic-data policies are verified, and the diagnostic services are stopped only after the request is submitted.'
    }
    $platform = Get-WindowsPlatformProfile
    if ([bool]$config['requestDiagnosticDataDelete'] -and
        -not [bool]$platform.IsServer -and [int]$platform.Build -lt 17763) {
        throw 'The supported Settings/cmdlet diagnostic-data deletion workflow requires Windows 10 version 1809 (build 17763) or newer on client editions.'
    }
    $state = Ensure-State
    $runtime = Get-RuntimeState

    Write-Host "`n===== Installing GDID Privacy Hardening =====`n" -ForegroundColor Cyan

    $localMaskEnabled = [bool]$config['blockCDP'] -and $config['hookMethod'] -eq 'registry'

    # Remove both the audited task name and the original project's legacy task
    # before prerequisites are changed.
    Uninstall-RotationTask

    # When local masking is being disabled, restore known originals before any
    # service can be re-enabled.
    if (-not $localMaskEnabled) {
        Restore-OriginalIdentity -State $state -KnownMaskValue $(if ($null -ne $runtime) { $runtime.lastFakeGDID } else { $null })
    }

    $knownFake = if ($null -ne $runtime) { $runtime.lastFakeGDID } else { $null }
    $addedTargets = Update-IdentityBackupsForNewTargets -State $state -KnownFakeValue $knownFake
    if ($addedTargets -gt 0) {
        Save-State -State $state
        Write-Ok "Backed up $addedTargets newly discovered identity target(s) before modification."
    }

    if ([bool]$config['blockCDP']) {
        $addedCdpInstances = Update-CDPInstanceBackupsForNewTargets -State $state
        if ($addedCdpInstances -gt 0) {
            Save-State -State $state
            Write-Ok "Backed up $addedCdpInstances newly discovered CDPUserSvc instance Start value(s) before modification."
        }
    }

    if ([bool]$config['blockWpn']) {
        $addedWpnInstances = Update-WpnInstanceBackupsForNewTargets -State $state
        if ($addedWpnInstances -gt 0) {
            Save-State -State $state
            Write-Ok "Backed up $addedWpnInstances newly discovered WpnUserService instance Start value(s) before modification."
        }
    }

    if ([bool]$config['blockTelemetry']) {
        Write-Warn 'blockTelemetry disables DiagTrack and dmwappushservice. This can break Intune/MDM sync, Endpoint Analytics, Windows Update for Business reporting, and other diagnostics-dependent management workflows.'
        Write-Warn 'Stopping DiagTrack is not a guarantee that Microsoft Defender for Endpoint or every other Microsoft component stops transmitting its own security/diagnostic data.'
    }

    Apply-FeaturePolicies -Config $config -State $state
    Invoke-GroupPolicyRefresh
    Assert-ConfiguredPoliciesReconciled -Config $config -State $state

    if ([bool]$config['requestDiagnosticDataDelete']) {
        $deleteResult = Invoke-DiagnosticDataDeleteRequest
        Save-DiagnosticDeleteRuntimeState -Accepted ([bool]$deleteResult.Accepted) -Result ([string]$deleteResult.Message)
        if (-not [bool]$deleteResult.Accepted) {
            throw "Diagnostic-data deletion request was not accepted. The request flag remains enabled for retry. $($deleteResult.Message)"
        }
        $config['requestDiagnosticDataDelete'] = $false
        Save-Config -Config $config
        Write-Ok ([string]$deleteResult.Message)
        Write-Info 'The one-shot requestDiagnosticDataDelete flag was reset to false after Windows accepted the request.'
    }

    if ([bool]$config['blockCDP']) {
        if (-not [bool]$state.cdpInstanceBaselineSealed) {
            $state.cdpInstanceBaselineSealed = $true
            Save-State -State $state
            Write-Info 'Sealed the CDP per-user instance rollback baseline before the first CDP modification.'
        }
        Enable-CDPBlock -State $state
    } else {
        Restore-CDPFromState -State $state
        Write-Warn 'blockCDP=false: no persistent local registry mask will be applied.'
    }

    if ([bool]$config['blockWpn']) {
        if (-not [bool]$state.wpnInstanceBaselineSealed) {
            $state.wpnInstanceBaselineSealed = $true
            Save-State -State $state
            Write-Info 'Sealed the WPN per-user instance rollback baseline before the first WPN modification.'
        }
        Enable-WpnBlock -State $state
    } else {
        Restore-WpnFromState -State $state
        Write-Info 'Windows Push Notification service blocking is disabled.'
    }

    if ([bool]$config['blockTelemetry']) {
        Enable-TelemetryBlock -State $state
    } else {
        Restore-TelemetryFromState -State $state
        Write-Info 'Diagnostic-data service blocking is disabled.'
    }

    $domains = @(Get-ConfiguredHostDomains -Config $config)
    if ([bool]$config['blockHosts']) {
        Install-HostsBlocks -Domains $domains
    } else {
        Uninstall-HostsBlocks
        Write-Info 'HOSTS blocking is disabled.'
    }

    $lastFake = if ($localMaskEnabled -and $null -ne $runtime) { $runtime.lastFakeGDID } else { $null }
    $didMask = $false
    $maskResult = $null
    $resultText = 'Installed hardening without local registry masking.'
    if ($localMaskEnabled) {
        $newValue = New-FakeGDID
        $maskResult = Set-LocalGDIDMask `
            -State $state `
            -NewValue $newValue `
            -KnownMaskValue $knownFake
        if ($maskResult.Wrote) {
            $lastFake = $newValue
            $didMask = $true
            $resultText = "Install wrote and verified a local registry mask in $($maskResult.Count) target(s)."
            Write-Ok "Applied verified local registry mask $newValue in $($maskResult.Count) target(s)"
        } else {
            $resultText = 'Install found no currently existing, safely backed identity registry values to mask.'
            Write-Warn $resultText
        }
    }

    # Runtime metadata contains the last mask value used by conflict-safe
    # uninstall. Commit it before declaring the installation complete. If that
    # commit fails, roll the new mask back so no unrecorded mask remains.
    try {
        Save-RuntimeState -Operation 'install' -LastFakeGDID $lastFake -Result $resultText -IsRotation $didMask
    } catch {
        $runtimeError = $_.Exception.Message
        if ($didMask -and $null -ne $maskResult) {
            try {
                Restore-IdentitySnapshotsAfterFailedMask `
                    -Snapshots @($maskResult.PreviousValues) `
                    -ExpectedMaskValue $lastFake
            } catch {
                throw "Runtime-state commit failed and the install-time local mask could not be rolled back completely. Runtime error: $runtimeError; rollback error: $($_.Exception.Message)"
            }
            throw "Runtime-state commit failed; the install-time local registry mask was rolled back to the immediately preceding values. $runtimeError"
        }
        throw "Hardening changes were applied, but runtime status could not be saved. Re-run install or uninstall using the protected state. $runtimeError"
    }

    # Mark the reversible state as installed before Task Scheduler is touched.
    # If task registration fails, uninstall remains safe and status is truthful.
    $state.installed = $true
    Save-State -State $state

    Install-RotationTask -Config $config -LocalMaskEnabled $localMaskEnabled

    Write-Host "`n===== Install Complete =====`n" -ForegroundColor Green
    Write-Warn "This hardens local components; it does not rotate Microsoft's authoritative Device PUID."
    Write-Host "Run '.\$($script:ScriptLeaf) status' to inspect actual state." -ForegroundColor White
}


function Uninstall-All {
    Assert-Windows
    Assert-Administrator

    Write-Host "`n===== Uninstalling GDID Privacy Hardening =====`n" -ForegroundColor Cyan
    $errors = @()
    $runtime = Get-RuntimeState

    try {
        Uninstall-RotationTask
    } catch {
        $errors += "Scheduled-task cleanup: $($_.Exception.Message)"
        Write-Warn $errors[-1]
    }

    try {
        Uninstall-HostsBlocks
    } catch {
        $errors += "HOSTS cleanup: $($_.Exception.Message)"
        Write-Warn $errors[-1]
    }

    $state = $null
    try {
        $state = Get-State
        if ($null -ne $state -and [int]$state.schemaVersion -ne $script:CurrentStateSchema) {
            $priorSchema = [int]$state.schemaVersion
            if (Upgrade-StateToCurrentSchema -State $state) {
                Write-Info "Migrated protected reversible state from schema $priorSchema to $($script:CurrentStateSchema) before restoration."
                $state = Get-State
            }
        }
    } catch {
        $errors += "Trusted-state read/migration: $($_.Exception.Message)"
        Write-Warn $errors[-1]
        $state = $null
    }

    if ($null -eq $state) {
        if ($errors.Count -eq 0) {
            try {
                $legacyRestored = Restore-LegacyOriginalIdentity -KnownMaskValue $(if ($null -ne $runtime) { $runtime.lastFakeGDID } else { $null })
                if ($legacyRestored) {
                    if (-not (Remove-LegacyOriginalGDIDFromConfig)) {
                        throw 'Legacy identity restoration succeeded, but originalGDID could not be removed from configuration.'
                    }
                    Write-Ok 'Removed the consumed legacy originalGDID backup from configuration.'
                } else {
                    Write-Warn 'No reversible state backup was found; exact restoration of prior policies and service settings is impossible.'
                }
            } catch {
                $errors += "Legacy identity restoration: $($_.Exception.Message)"
            }
        }

        if ($errors.Count -gt 0) {
            throw "Uninstall was incomplete. No protected state was deleted. $($errors -join ' | ')"
        }

        Remove-RuntimeState
        Write-Host "`n===== Uninstall Complete (limited legacy cleanup) =====`n" -ForegroundColor Green
        Write-Warn 'No protected backup existed, so no unbacked policy or service value was changed.'
        return
    }

    $identityRestored = $false
    try {
        # Restore identity before re-enabling any component that might consume it.
        Restore-OriginalIdentity -State $state -KnownMaskValue $(if ($null -ne $runtime) { $runtime.lastFakeGDID } else { $null })
        $identityRestored = $true
    } catch {
        $errors += "Identity restoration: $($_.Exception.Message)"
        Write-Warn $errors[-1]
    }

    foreach ($descriptor in @($script:PolicyDescriptors | Where-Object { $_.Id -ne 'CDP.EnableCdp' })) {
        try {
            Restore-PolicyFromState -State $state -Descriptor $descriptor
        } catch {
            $errors += "$($descriptor.Label) restoration: $($_.Exception.Message)"
            Write-Warn $errors[-1]
        }
    }

    if ($identityRestored) {
        try {
            Restore-CDPFromState -State $state
        } catch {
            $errors += "CDP restoration: $($_.Exception.Message)"
            Write-Warn $errors[-1]
        }

        try {
            Restore-WpnFromState -State $state
        } catch {
            $errors += "WPN restoration: $($_.Exception.Message)"
            Write-Warn $errors[-1]
        }

        try {
            Restore-TelemetryFromState -State $state
        } catch {
            $errors += "Diagnostic-data service restoration: $($_.Exception.Message)"
            Write-Warn $errors[-1]
        }
    } else {
        $errors += 'CDP, WPN, and diagnostic-data service restoration were deliberately skipped because identity restoration failed.'
        Write-Warn $errors[-1]
    }

    try {
        Invoke-GroupPolicyRefresh
        Assert-ManagedPoliciesRestored -State $state
    } catch {
        $errors += "Group Policy refresh/restoration verification: $($_.Exception.Message)"
        Write-Warn $errors[-1]
    }

    if ($errors.Count -gt 0) {
        throw "Uninstall was incomplete. The protected backup was retained for retry. $($errors -join ' | ')"
    }

    Remove-Item -LiteralPath $script:StatePath -Force
    if ((Test-Path -LiteralPath $script:StateDirectory) -and
        @(Get-ChildItem -LiteralPath $script:StateDirectory -Force).Count -eq 0) {
        Remove-Item -LiteralPath $script:StateDirectory -Force
    }
    if ((Test-Path -LiteralPath $script:StateRoot) -and
        @(Get-ChildItem -LiteralPath $script:StateRoot -Force).Count -eq 0) {
        Remove-Item -LiteralPath $script:StateRoot -Force
    }
    Remove-RuntimeState
    Write-Ok 'Removed the protected reversible state after verified restoration.'

    Write-Host "`n===== Uninstall Complete =====`n" -ForegroundColor Green
    Write-Warn 'Sign out or reboot so per-user service instances are recreated with their restored template settings and Windows components observe the restored policy/service baseline.'
}


function Show-Config {
    param(
        [string]$ConfigKey,
        [AllowEmptyString()][string]$ConfigValue,
        [bool]$ValueWasSupplied
    )

    $config = Get-Config

    if ([string]::IsNullOrWhiteSpace($ConfigKey)) {
        Write-Host "`n-- GDID Configuration --" -ForegroundColor Cyan
        foreach ($name in @(
            'rotationMode', 'timedIntervalMin', 'blockCDP', 'blockWpn', 'blockTelemetry',
            'requestDiagnosticDataDelete', 'blockHosts', 'blockAADHost', 'blockDO',
            'killPhoneLink', 'killOneDrive', 'killStore', 'killTimeline', 'hookMethod'
        )) {
            Write-Host ("  {0,-20} {1}" -f $name, $config[$name])
        }
        Write-Host "`nUse: .\$($script:ScriptLeaf) config <key> <value>"
        return
    }

    if (-not $config.ContainsKey($ConfigKey)) {
        throw "Unknown configuration key '$ConfigKey'."
    }
    if ($ConfigKey -eq 'schemaVersion') {
        throw 'schemaVersion is managed by the tool and cannot be changed.'
    }

    if (-not $ValueWasSupplied) {
        Write-Host "$ConfigKey = $($config[$ConfigKey])"
        return
    }

    $config[$ConfigKey] = Convert-ConfigValue -Name $ConfigKey -Text $ConfigValue
    Save-Config -Config $config
    Write-Ok "$ConfigKey = $($config[$ConfigKey])"
    Write-Info "Run '.\$($script:ScriptLeaf) install' as Administrator to reconcile actual system state."
}

function Show-Help {
    Write-Host @"
GDID Privacy Tool (audited telemetry build)

Commands:
  status       Inspect local identity copies, Windows/edition diagnostic-data
               minimum, CDP/WPN/telemetry services, policies, HOSTS, task state,
               deletion-request history, and limitations.
  rotate       Replace existing HKCU GDID registry copies. This only runs after
               install has verifiably disabled CDP. It is not server rotation.
  install      Back up original values, reconcile hardening, run gpupdate /force,
               optionally request diagnostic-data deletion, apply a local mask,
               and create a safe current-user task.
  uninstall    Restore backed-up identity, policies, and service values, then
               run gpupdate /force.
  config       Read or set configuration.
  help         Show this text.

Configuration:
  rotationMode       onDemand | perLogon | timed
                     perBoot is accepted only as a legacy alias for perLogon,
                     because the target values live in HKCU.
  timedIntervalMin   15-1440
  blockCDP           Disable EnableCdp, CDPSvc, and CDPUserSvc template/instances.
  blockWpn           Disable and stop WpnService, WpnUserService template, and
                     current WpnUserService_* instances. High collateral.
  blockTelemetry     Apply edition-aware minimum diagnostic-data policies and
                     disable/stop DiagTrack plus dmwappushservice. Opt-in.
  requestDiagnosticDataDelete
                     One-shot flag. With blockTelemetry=true, install calls
                     Clear-WindowsDiagnosticData -Force before stopping telemetry
                     services, records the result, and resets the flag only after
                     Windows accepts the request.
  blockHosts         Block activity.windows.com by exact HOSTS name.
  blockAADHost       Also block aad.cs.dds.microsoft.com (higher collateral).
  blockDO            Set documented DODownloadMode=99; DoSvc is not disabled.
  killPhoneLink      Set EnableMmx=0.
  killOneDrive       Set DisableFileSyncNGSC=1.
  killStore          Set AutoDownload=2.
  killTimeline       Set all three activity-history policies to 0.
  hookMethod         registry | none. API mode is intentionally unsupported.

Diagnostic-data minimums:
  Enterprise/Education/IoT Enterprise/Server: AllowTelemetry=0.
  Pro and other client editions:              AllowTelemetry=1.
  The script reports both requested and actual values after gpupdate /force.

Important:
  Clear-WindowsDiagnosticData submits a deletion request; it does not prove that
  server-side deletion has completed. Diagnostic policies and service disabling
  reduce known Windows diagnostic traffic but cannot prove that every Microsoft
  telemetry or identity-reporting path is blocked.
"@
}

# -----------------------------------------------------------------------------
# Main and cross-session mutation lock
# -----------------------------------------------------------------------------

function Enter-OperationLock {
    if (-not (Test-Path -LiteralPath $script:RuntimeDirectory)) {
        New-Item -ItemType Directory -Path $script:RuntimeDirectory -Force | Out-Null
    }

    try {
        # An exclusive file handle serializes elevated, non-elevated, scheduled,
        # and multi-session processes for this SID. Unlike a Local\ named mutex,
        # the lock is not scoped to one Terminal Services session. A crash closes
        # the handle automatically; the harmless file may then be reused.
        return [IO.File]::Open(
            $script:OperationLockPath,
            [IO.FileMode]::OpenOrCreate,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None
        )
    } catch [IO.IOException] {
        throw 'Another GDID Privacy operation is already running for this user, possibly in another sign-in session.'
    }
}

function Exit-OperationLock {
    param([AllowNull()]$LockStream)

    if ($null -ne $LockStream) {
        $LockStream.Dispose()
    }
    Remove-Item -LiteralPath $script:OperationLockPath -Force -ErrorAction SilentlyContinue
    if ((Test-Path -LiteralPath $script:RuntimeDirectory) -and
        @(Get-ChildItem -LiteralPath $script:RuntimeDirectory -Force -ErrorAction SilentlyContinue).Count -eq 0) {
        Remove-Item -LiteralPath $script:RuntimeDirectory -Force -ErrorAction SilentlyContinue
    }
}

$operationLock = $null
$valueWasSupplied = $PSBoundParameters.ContainsKey('Value')
$mutating = $Mode -in @('rotate', 'install', 'uninstall') -or ($Mode -eq 'config' -and $valueWasSupplied)

try {
    if ($mutating) {
        Assert-Windows
        $operationLock = Enter-OperationLock
    }

    switch ($Mode) {
        'status'    { Show-Status }
        'rotate'    { Invoke-Rotate }
        'install'   { Install-All }
        'uninstall' { Uninstall-All }
        'config'    { Show-Config -ConfigKey $Key -ConfigValue $Value -ValueWasSupplied $valueWasSupplied }
        'help'      { Show-Help }
    }
} catch {
    if (-not $Scheduled) {
        Write-Host "`n[ERROR] $($_.Exception.Message)" -ForegroundColor Red
    }
    exit 1
} finally {
    if ($null -ne $operationLock) {
        Exit-OperationLock -LockStream $operationLock
    }
}
