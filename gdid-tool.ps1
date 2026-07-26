#!/usr/bin/env pwsh
<#
.SYNOPSIS
    GDID Privacy Tool - Control Windows Global Device Identifier tracking
.DESCRIPTION
    View, rotate, spoof, or block the Windows GDID (Global Device Identifier).
    GDID is a 64-bit MSA Device PUID used by Microsoft to track device identity
    across the Connected Devices Platform, Delivery Optimization, and telemetry.

    Modes:
      status       - Show current GDID, service/endpoint state
      rotate       - Immediately generate a new fake GDID
      refreshfw    - Refresh IP-based firewall rules (re-resolve DNS)
      install      - Install rotation + firewall rules as configured
      uninstall    - Remove all changes, restore defaults
      config       - View or change configuration
.PARAMETER Mode
    Subcommand to run: status, rotate, refreshfw, install, uninstall, config
.PARAMETER Key
    Config key to get/set (used with config subcommand)
.PARAMETER Value
    Config value to set (used with config subcommand)
.EXAMPLE
    .\gdid-tool.ps1 status
    .\gdid-tool.ps1 rotate
    .\gdid-tool.ps1 refreshfw
    .\gdid-tool.ps1 config rotationMode perBoot
    .\gdid-tool.ps1 install
#>

param(
    [Parameter(Position = 0)]
    [ValidateSet('status', 'rotate', 'refreshfw', 'install', 'uninstall', 'config', 'help')]
    [string]$Mode = 'status',

    [Parameter(Position = 1)]
    [string]$Key,

    [Parameter(Position = 2)]
    [string]$Value
)

#Requires -RunAsAdministrator

# ---------- Configuration ----------
$ConfigPath = Join-Path $PSScriptRoot 'gdid-config.json'

$DefaultConfig = @{
    rotationMode      = 'perBoot'    # perBoot | timed | onDemand
    timedIntervalMin  = 30
    blockDDS          = $true
    blockActivity     = $true
    blockCDP          = $true       # ON by default: disables CDPSvc/CDPUserSvc for max protection
    killPhoneLink     = $false
    killOneDrive      = $false
    killStore         = $false
    killTimeline      = $false
    blockDO           = $false      # Disable Delivery Optimization service (DoSvc)
    blockHosts        = $true       # ON by default: HOSTS blocking is name-based and immune to IP churn
    hookMethod        = 'registry'   # registry | api | none
    lastRotation      = $null
    originalGDID      = $null
}

function Get-Config {
    if (Test-Path $ConfigPath) {
        $c = Get-Content $ConfigPath -Raw | ConvertFrom-Json
        $merged = $DefaultConfig.Clone()
        foreach ($k in @($merged.Keys)) {
            if ($c.$k -ne $null) { $merged[$k] = $c.$k }
        }
        return $merged
    }
    return $DefaultConfig.Clone()
}

function Save-Config($cfg) {
    $cfg | ConvertTo-Json | Set-Content $ConfigPath -Force
}

# ---------- Registry paths ----------
$RegPaths = @(
    'HKCU:\SOFTWARE\Microsoft\IdentityCRL\ExtendedProperties',
    'HKCU:\SOFTWARE\Microsoft\IdentityCRL\Immersive\production\Token'
)

# NOTE: Several domains previously shipped were verified as NXDOMAIN (non-existent)
# as of July 2026. Only domains confirmed to resolve are included. IP-based blocking
# is inherently limited due to short TTLs (4-120s) on these Azure Front Door endpoints.
# HOSTS-based blocking is more reliable for name-level blocking.
$DDSDomains = @(
    'aad.cs.dds.microsoft.com'
)

$ActivityDomains = @(
    'activity.windows.com'
)

# geo.prod.do.dsp.mp.microsoft.com is Delivery Optimization (DoSvc), not GDID.
# Blocking it costs update bandwidth without affecting device identification.
# Include only if explicitly desired via config.
$DODomains = @(
    'geo.prod.do.dsp.mp.microsoft.com'
)

$HostsDomains = @(
    'aad.cs.dds.microsoft.com',
    'activity.windows.com'
)

$CDPStateDir = "$env:LOCALAPPDATA\ConnectedDevicesPlatform"

# ---------- Helpers ----------
function Get-CurrentGDID {
    $path = 'HKCU:\SOFTWARE\Microsoft\IdentityCRL\ExtendedProperties'
    if (Test-Path $path) {
        $lid = (Get-ItemProperty $path -Name 'LID' -ErrorAction SilentlyContinue).LID
        if ($lid) {
            $dec = [Convert]::ToUInt64($lid, 16)
            return @{ hex = $lid; decimal = "g:$dec"; source = "ExtendedProperties\LID" }
        }
    }
    # Fallback: search under Immersive\production\Token
    $tokenPath = 'HKCU:\SOFTWARE\Microsoft\IdentityCRL\Immersive\production\Token'
    if (Test-Path $tokenPath) {
        $subs = Get-ChildItem $tokenPath -ErrorAction SilentlyContinue
        foreach ($s in $subs) {
            $did = (Get-ItemProperty $s.PSPath -Name 'DeviceId' -ErrorAction SilentlyContinue).DeviceId
            if ($did) {
                $dec2 = [Convert]::ToUInt64($did, 16)
                return @{ hex = $did; decimal = "g:$dec2"; source = "Token\$($s.PSChildName)\DeviceId" }
            }
        }
    }
    return $null
}

function New-FakeGDID {
    # 64-bit random with 0018 prefix (Device PUID namespace)
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $bytes = New-Object byte[] 6
    $rng.GetBytes($bytes)
    $val = [uint64]0
    foreach ($b in $bytes) { $val = ($val -shl 8) -bor $b }
    return "0018{0:X12}" -f $val
}

function Write-GDID($hex) {
    # ExtendedProperties\LID
    $path1 = 'HKCU:\SOFTWARE\Microsoft\IdentityCRL\ExtendedProperties'
    if (-not (Test-Path $path1)) { New-Item -Path $path1 -Force | Out-Null }
    Set-ItemProperty -Path $path1 -Name 'LID' -Value $hex -Type String -Force

    # Immersive\production\Token\{*}\DeviceId
    $tokenPath = 'HKCU:\SOFTWARE\Microsoft\IdentityCRL\Immersive\production\Token'
    if (Test-Path $tokenPath) {
        $subs = Get-ChildItem $tokenPath -ErrorAction SilentlyContinue
        foreach ($s in $subs) {
            Set-ItemProperty -Path $s.PSPath -Name 'DeviceId' -Value $hex -Type String -Force -ErrorAction SilentlyContinue
        }
    }
}

function Clear-CDPState {
    if (Test-Path $CDPStateDir) {
        Remove-Item "$CDPStateDir\*" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "  [OK] Cleared CDP state" -ForegroundColor Green
    }
}

function Restart-CDP {
    Stop-Service CDPSvc -Force -ErrorAction SilentlyContinue
    Stop-Service CDPUserSvc -Force -ErrorAction SilentlyContinue
    Get-Service 'CDPUserSvc_*' -ErrorAction SilentlyContinue | Stop-Service -Force
    Start-Sleep 1
    # Only restart services that aren't intentionally disabled
    $anySkipped = $false
    $svcs = @(Get-Service 'CDPUserSvc_*' -ErrorAction SilentlyContinue) + @(Get-Service CDPUserSvc -ErrorAction SilentlyContinue) + @(Get-Service CDPSvc -ErrorAction SilentlyContinue)
    foreach ($svc in $svcs) {
        $startMode = (Get-CimInstance -ClassName Win32_Service -Filter "Name='$($svc.Name)'").StartMode
        if ($startMode -eq 'Disabled') {
            Write-Host "  [SKIP] $($svc.Name) is Disabled - not restarting" -ForegroundColor Yellow
            $anySkipped = $true
        } else {
            Start-Service $svc.Name -ErrorAction SilentlyContinue
        }
    }
    if ($anySkipped) {
        Write-Host "  [OK] Rotation complete. New GDID will take effect when CDP starts." -ForegroundColor Green
    }
}

# ---------- IP-based Firewall ----------
# NOTE: IP-based firewall blocking has inherent limitations documented in
# README.md#known-limitations. These endpoints use Azure Front Door shared
# frontends with TTLs as low as 4 seconds. IP rules built at one moment may
# not match the address CDP connects to moments later. HOSTS blocking
# ($cfg.blockHosts) is immune to address rotation. Disabling CDP services
# ($cfg.blockCDP) eliminates the tracking vector entirely.
function Install-FirewallRules {
    param(
        [string]$Group,
        [string[]]$Domains
    )

    $ips = [System.Collections.Generic.List[string]]::new()

    foreach ($domain in $Domains) {
        try {
            # @(...) forces array even for single-IP results,
            # preventing AddRange() from receiving a bare String
            $resolved = @([System.Net.Dns]::GetHostAddresses($domain) |
                Where-Object { $_.AddressFamily -eq 'InterNetwork' } |
                ForEach-Object { $_.IPAddressToString })
        } catch {
            Write-Host "  [DNS] $domain -> failed to resolve (skipped)" -ForegroundColor DarkGray
            continue
        }

        # Filter sinkholed responses (HOSTS file or upstream block)
        $usable = @($resolved | Where-Object { $_ -notin @('0.0.0.0', '127.0.0.1') })

        if ($usable.Count -eq 0) {
            if ($resolved.Count -gt 0) {
                Write-Host "  [DNS] $domain -> sinkholed ($($resolved -join ', ')) - skipped" -ForegroundColor Yellow
            } else {
                Write-Host "  [DNS] $domain -> did not resolve (skipped)" -ForegroundColor DarkGray
            }
            continue
        }

        $ips.AddRange([string[]]$usable)
        Write-Host "  [DNS] $domain -> $($usable -join ', ')" -ForegroundColor Cyan
    }

    $unique = [string[]]($ips | Sort-Object -Unique)

    if ($unique.Count -eq 0) {
        Write-Host "  [WARN] No IPs for group '$Group' - existing rule left untouched" -ForegroundColor Yellow
        return
    }

    $ruleName = "$Group (IP block)"
    try {
        # Create new rule first, then remove old ones — so failure leaves
        # the previous state intact
        $new = New-NetFirewallRule -DisplayName $ruleName -Group $Group `
                   -Direction Outbound -Action Block -Profile Any `
                   -RemoteAddress $unique -ErrorAction Stop

        Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue |
            Where-Object { $_.InstanceID -ne $new.InstanceID } |
            Remove-NetFirewallRule

        Write-Host "  [OK] Rule '$ruleName' blocking $($unique.Count) IP(s)" -ForegroundColor Green
    } catch {
        Write-Host "  [FAIL] Rule '$ruleName' NOT created: $($_.Exception.Message)" -ForegroundColor Red
    }
}

function Uninstall-FirewallRules {
    param([string]$Group)
    Get-NetFirewallRule -Group $Group -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    Write-Host "  [OK] Firewall rules removed from group '$Group'" -ForegroundColor Green
}

# Refresh IP-based firewall rules (call daily via scheduled task)
function Update-AllFirewallIPs {
    $cfg = Get-Config
    if ($cfg.blockDDS) {
        Install-FirewallRules -Group "GDID Privacy - Block DDS" -Domains $DDSDomains
    }
    if ($cfg.blockActivity) {
        Install-FirewallRules -Group "GDID Privacy - Block Activity" -Domains $ActivityDomains
    }
    Write-Host "  [OK] Firewall IPs refreshed" -ForegroundColor Green
}

# ---------- HOSTS file blocking ----------
$HostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
$HostsBeginMarker = "# GDID Privacy :: begin"
$HostsEndMarker   = "# GDID Privacy :: end"

function Install-HostsBlocks {
    param([string[]]$Domains)

    if (-not (Test-Path $HostsPath)) {
        Write-Host "  [WARN] HOSTS file not found at $HostsPath" -ForegroundColor Yellow
        return
    }

    $content = Get-Content $HostsPath -Raw -ErrorAction Stop
    if ($content -match [regex]::Escape($HostsBeginMarker)) {
        Write-Host "  [OK] HOSTS blocks already present - updating" -ForegroundColor Yellow
        # Remove existing GDID block
        $content = $content -replace "(?ms)$([regex]::Escape($HostsBeginMarker)).*?$([regex]::Escape($HostsEndMarker))", ""
    }

    $lines = @("", $HostsBeginMarker)
    foreach ($d in $Domains) {
        $lines += "0.0.0.0 $d"
    }
    $lines += $HostsEndMarker

    # Trim trailing whitespace before appending
    $content = $content.TrimEnd() + "`r`n" + ($lines -join "`r`n") + "`r`n"
    Set-Content -Path $HostsPath -Value $content -Encoding ASCII -Force
    Write-Host "  [OK] HOSTS file updated ($($Domains.Count) domains)" -ForegroundColor Green
}

function Uninstall-HostsBlocks {
    if (-not (Test-Path $HostsPath)) { return }

    $content = Get-Content $HostsPath -Raw -ErrorAction SilentlyContinue
    if (-not $content) { return }

    if ($content -match [regex]::Escape($HostsBeginMarker)) {
        $content = $content -replace "(?ms)\r?\n?$([regex]::Escape($HostsBeginMarker)).*?$([regex]::Escape($HostsEndMarker))\r?\n?", ""
        $content = $content.TrimEnd() + "`r`n"
        Set-Content -Path $HostsPath -Value $content -Encoding ASCII -Force
        Write-Host "  [OK] HOSTS blocks removed" -ForegroundColor Green
    } else {
        Write-Host "  [OK] No HOSTS blocks found" -ForegroundColor Yellow
    }
}

# ---------- Scheduled tasks ----------
function Install-RotationTask($cfg) {
    $taskName = "GDIDRotator"
    $scriptPath = Join-Path $PSScriptRoot 'gdid-tool.ps1'
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" rotate"

    $triggers = @()
    if ($cfg.rotationMode -eq 'perBoot') {
        $triggers += New-ScheduledTaskTrigger -AtStartup
    } elseif ($cfg.rotationMode -eq 'timed') {
        $triggers += New-ScheduledTaskTrigger -Daily -At "00:00"
        $triggers += New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes $cfg.timedIntervalMin) -RepetitionDuration ([TimeSpan]::MaxValue)
    }

    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest

    # Security note: scheduled tasks with RunLevel=Highest run from
    # wherever the script lives. Keep the script in a location writable
    # only by administrators (e.g. C:\Program Files\GDID) to avoid
    # persistence-primitive risk.
    if ($triggers.Count -eq 0) {
        Write-Host "  [SKIP] No triggers for rotationMode=$($cfg.rotationMode)" -ForegroundColor Yellow
        return
    }

    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $triggers -Settings $settings -Principal $principal -Force | Out-Null
    Write-Host "  [OK] Scheduled task '$taskName' created (mode: $($cfg.rotationMode))" -ForegroundColor Green

    # Warn if script lives in user-writable location
    $isUserPath = $PSScriptRoot -match "^$([regex]::Escape($env:USERPROFILE))" -or
                  $PSScriptRoot -match "^$([regex]::Escape($env:HOMEPATH))"
    if ($isUserPath) {
        Write-Host "  [SEC] Task runs as SYSTEM from a user-writable path: $PSScriptRoot" -ForegroundColor Yellow
        Write-Host "  [SEC] Consider moving to a protected directory (C:\Program Files\GDID)" -ForegroundColor Yellow
    }
}
function Install-IPRefreshTask {
    $taskName = "GDIDFirewallRefresh"
    $scriptPath = Join-Path $PSScriptRoot 'gdid-tool.ps1'
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`" refreshfw"
    $trigger = New-ScheduledTaskTrigger -Daily -At "02:00"
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -RunLevel Highest
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Settings $settings -Principal $principal -Force | Out-Null
    Write-Host "  [OK] Scheduled task '$taskName' created (daily IP refresh)" -ForegroundColor Green
}

function Uninstall-RotationTask {
    $taskName = "GDIDRotator"
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "  [OK] Scheduled task '$taskName' removed" -ForegroundColor Green
}

function Uninstall-IPRefreshTask {
    $taskName = "GDIDFirewallRefresh"
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    Write-Host "  [OK] Scheduled task '$taskName' removed" -ForegroundColor Green
}

# ---------- Feature kill switches ----------
function Install-FeatureKills($cfg) {
    if ($cfg.killPhoneLink) {
        Stop-Process -Name 'PhoneExperienceHost' -Force -ErrorAction SilentlyContinue
        $pkPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Phone'
        if (-not (Test-Path $pkPath)) { New-Item -Path $pkPath -Force | Out-Null }
        Set-ItemProperty -Path $pkPath -Name 'Enable' -Value 0 -Type DWord -Force
        Write-Host "  [OK] Phone Link disabled" -ForegroundColor Green
    }

    if ($cfg.killOneDrive) {
        Stop-Process -Name 'OneDrive' -Force -ErrorAction SilentlyContinue
        $odPath = 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive'
        if (-not (Test-Path $odPath)) { New-Item -Path $odPath -Force | Out-Null }
        Set-ItemProperty -Path $odPath -Name 'DisableFileSyncNGSC' -Value 1 -Type DWord -Force
        Write-Host "  [OK] OneDrive sync disabled (policy)" -ForegroundColor Green
    }

    if ($cfg.killStore) {
        $wsPath = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore'
        if (-not (Test-Path $wsPath)) { New-Item -Path $wsPath -Force | Out-Null }
        Set-ItemProperty -Path $wsPath -Name 'AutoDownload' -Value 2 -Type DWord -Force
        Write-Host "  [OK] Store auto-update disabled" -ForegroundColor Green
    }

    if ($cfg.killTimeline) {
        $atPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
        if (-not (Test-Path $atPath)) { New-Item -Path $atPath -Force | Out-Null }
        Set-ItemProperty -Path $atPath -Name 'EnableActivityFeed' -Value 0 -Type DWord -Force
        Set-ItemProperty -Path $atPath -Name 'PublishUserActivities' -Value 0 -Type DWord -Force
        Write-Host "  [OK] Activity History / Timeline disabled" -ForegroundColor Green
    }

    if ($cfg.blockCDP) {
        Set-Service CDPSvc -StartupType Disabled
        Set-Service CDPUserSvc -StartupType Disabled
        Get-Service 'CDPUserSvc_*' -ErrorAction SilentlyContinue | ForEach-Object {
            Set-Service $_.Name -StartupType Disabled
        }
        Write-Host "  [OK] CDP services disabled" -ForegroundColor Green
    }

    if ($cfg.blockDDS) {
        Install-FirewallRules -Group "GDID Privacy - Block DDS" -Domains $DDSDomains
    }

    if ($cfg.blockActivity) {
        Install-FirewallRules -Group "GDID Privacy - Block Activity" -Domains $ActivityDomains
    }

    if ($cfg.blockDO) {
        Stop-Service DoSvc -Force -ErrorAction SilentlyContinue
        Set-Service DoSvc -StartupType Disabled
        Write-Host "  [OK] Delivery Optimization service (DoSvc) disabled" -ForegroundColor Green
    }

    if ($cfg.blockHosts) {
        Install-HostsBlocks -Domains $HostsDomains
    }
}

function Uninstall-FeatureKills {
    $pkPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Phone'
    if (Test-Path $pkPath) { Remove-ItemProperty -Path $pkPath -Name 'Enable' -ErrorAction SilentlyContinue }

    $odPath = 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive'
    if (Test-Path $odPath) { Remove-ItemProperty -Path $odPath -Name 'DisableFileSyncNGSC' -ErrorAction SilentlyContinue }

    $wsPath = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore'
    if (Test-Path $wsPath) { Remove-ItemProperty -Path $wsPath -Name 'AutoDownload' -ErrorAction SilentlyContinue }

    $atPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'
    if (Test-Path $atPath) {
        Remove-ItemProperty -Path $atPath -Name 'EnableActivityFeed' -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $atPath -Name 'PublishUserActivities' -ErrorAction SilentlyContinue
    }

    Set-Service CDPSvc -StartupType Manual -ErrorAction SilentlyContinue
    Set-Service CDPUserSvc -StartupType Manual -ErrorAction SilentlyContinue
    Get-Service 'CDPUserSvc_*' -ErrorAction SilentlyContinue | ForEach-Object {
        Set-Service $_.Name -StartupType Manual -ErrorAction SilentlyContinue
    }

    Uninstall-FirewallRules -Group "GDID Privacy - Block DDS"
    Uninstall-FirewallRules -Group "GDID Privacy - Block Activity"

    Set-Service DoSvc -StartupType Manual -ErrorAction SilentlyContinue
    Write-Host "  [OK] DoSvc restored to Manual" -ForegroundColor Green

    Uninstall-HostsBlocks
}

# ---------- Subcommands ----------
function Show-Status {
    Write-Host "`n===== GDID Status =====`n" -ForegroundColor Cyan
    $gdid = Get-CurrentGDID
    if ($gdid) {
        Write-Host "  Current GDID hex:    $($gdid.hex)" -ForegroundColor White
        Write-Host "  Current GDID dec:    $($gdid.decimal)" -ForegroundColor White
        Write-Host "  Source:              $($gdid.source)" -ForegroundColor White

        $cfg = Get-Config
        if ($cfg.originalGDID -and $gdid.hex -eq $cfg.originalGDID) {
            Write-Host "  Status:              ORIGINAL (spoof not active)" -ForegroundColor Yellow
        } elseif ($cfg.originalGDID -and $gdid.hex -ne $cfg.originalGDID) {
            Write-Host "  Status:              SPOOFED" -ForegroundColor Green
            if (-not $cfg.blockCDP) {
                Write-Host "  [!] CDPSvc running — GDID may revert on service restart" -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "  No GDID found (no MSA or account removed)" -ForegroundColor Yellow
    }

    $cfg = Get-Config
    Write-Host "`n-- Configuration --" -ForegroundColor Cyan
    $cfg | Format-List | Out-String | Write-Host

    Write-Host "`n-- Services --" -ForegroundColor Cyan
    @('CDPSvc', 'CDPUserSvc', 'DoSvc') | ForEach-Object {
        $svc = Get-Service $_ -ErrorAction SilentlyContinue
        if ($svc) {
            $status = if ($svc.Status -eq 'Running') { 'RUNNING' } else { $svc.Status }
            $startup = (Get-CimInstance -ClassName Win32_Service -Filter "Name='$_'").StartMode
            Write-Host "  $_ : $status (startup: $startup)" -ForegroundColor $(
                if ($svc.Status -eq 'Running') { 'Green' } else { 'Yellow' }
            )
        }
    }

    Write-Host "`n-- Firewall Rules --" -ForegroundColor Cyan
    $ddsRules = Get-NetFirewallRule -Group "GDID Privacy - Block DDS" -ErrorAction SilentlyContinue
    $actRules = Get-NetFirewallRule -Group "GDID Privacy - Block Activity" -ErrorAction SilentlyContinue
    $allRules = @($ddsRules) + @($actRules)
    if ($allRules) {
        $allRules | ForEach-Object { Write-Host "  BLOCK: $($_.DisplayName) (group: $($_.Group))" -ForegroundColor Red }
    } else {
        Write-Host "  None" -ForegroundColor DarkGray
    }

    # Known limitations notice
    Write-Host "`n-- Protection Summary --" -ForegroundColor Cyan
    if ($cfg.blockCDP) {
        Write-Host "  CDP:       DISABLED — rotation persistent, GDID never reported" -ForegroundColor Green
    } else {
        Write-Host "  CDP:       ENABLED — rotation local-only, reverts on restart" -ForegroundColor Yellow
    }
    if ($cfg.blockHosts) {
        Write-Host "  HOSTS:     ACTIVE — name-based blocking (immune to IP rotation)" -ForegroundColor Green
    } else {
        Write-Host "  HOSTS:     off — config: blockHosts=true for reliable blocking" -ForegroundColor DarkGray
    }
    Write-Host "  IP rules:  Limited — Azure endpoints rotate addresses every 4-120s" -ForegroundColor DarkGray
    Write-Host "  Settings:  .\\gdid-tool.ps1 config <key> <value>" -ForegroundColor DarkGray

    Write-Host "`n-- Scheduled Tasks --" -ForegroundColor Cyan
    $rotatorTask = Get-ScheduledTask -TaskName "GDIDRotator" -ErrorAction SilentlyContinue
    $ipTask = Get-ScheduledTask -TaskName "GDIDFirewallRefresh" -ErrorAction SilentlyContinue
    if ($rotatorTask) { Write-Host "  GDIDRotator: $($rotatorTask.State)" -ForegroundColor Green }
    else { Write-Host "  GDIDRotator: None" -ForegroundColor DarkGray }
    if ($ipTask) { Write-Host "  GDIDFirewallRefresh: $($ipTask.State)" -ForegroundColor Green }
    else { Write-Host "  GDIDFirewallRefresh: None" -ForegroundColor DarkGray }

    Write-Host "`n-- Feature Kills --" -ForegroundColor Cyan
    $checks = @(
        @{ name = "Phone Link"; path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Windows\Phone'; prop = 'Enable' },
        @{ name = "OneDrive"; path = 'HKLM:\SOFTWARE\Policies\Microsoft\OneDrive'; prop = 'DisableFileSyncNGSC' },
        @{ name = "Store AutoUpdate"; path = 'HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore'; prop = 'AutoDownload' },
        @{ name = "Activity History"; path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; prop = 'EnableActivityFeed' }
    )
    foreach ($c in $checks) {
        if (Test-Path $c.path) {
            $val = (Get-ItemProperty $c.path -Name $c.prop -ErrorAction SilentlyContinue).$($c.prop)
            if ($val -ne $null) {
                Write-Host "  $($c.name): DISABLED (policy)" -ForegroundColor Yellow
                continue
            }
        }
        Write-Host "  $($c.name): ENABLED (default)" -ForegroundColor DarkGray
    }

    Write-Host "`n-- HOSTS File --" -ForegroundColor Cyan
    if (Test-Path $HostsPath) {
        $hostsContent = Get-Content $HostsPath -Raw -ErrorAction SilentlyContinue
        if ($hostsContent -and ($hostsContent -match [regex]::Escape($HostsBeginMarker))) {
            Write-Host "  GDID blocks: INSTALLED" -ForegroundColor Green
        } else {
            Write-Host "  GDID blocks: None" -ForegroundColor DarkGray
        }
    }
    Write-Host ""
}

function Invoke-Rotate {
    Write-Host "`n===== Rotating GDID =====`n" -ForegroundColor Cyan

    # Save original GDID before overwriting (only on first rotate)
    $cfg = Get-Config
    $original = Get-CurrentGDID
    if ($original -and (-not $cfg.ContainsKey('originalGDID') -or (-not $cfg.originalGDID))) {
        $cfg['originalGDID'] = $original.hex
        Save-Config $cfg
        Write-Host "  [INFO] Original GDID backed up: $($original.hex)" -ForegroundColor DarkGray
    }

    $new = New-FakeGDID
    Write-Host "  New GDID: $new" -ForegroundColor White

    Write-GDID $new
    Clear-CDPState

    $cfg['lastRotation'] = (Get-Date).ToString('o')
    Save-Config $cfg

    if ($cfg.blockCDP) {
        Write-Host "  [SKIP] CDP services disabled — rotation is persistent" -ForegroundColor Green
        Write-Host "  [OK] Rotation complete" -ForegroundColor Green
    } else {
        Restart-CDP
        Write-Host "  [OK] Rotation complete" -ForegroundColor Green

        # Verify and warn about CDPSvc restoring the real GDID
        Start-Sleep 2
        $after = Get-CurrentGDID
        if ($after) {
            if ($after.hex -eq $new) {
                Write-Host "  Current GDID: $($after.hex) (spoofed value held)" -ForegroundColor Green
            } elseif ($original -and $after.hex -eq $original.hex) {
                Write-Host "  Current GDID: $($after.hex) (restored by CDPSvc)" -ForegroundColor Yellow
                Write-Host "  [NOTE] CDPSvc reloaded the real GDID from the device ticket." -ForegroundColor Yellow
                Write-Host "  [NOTE] The spoofed value is only visible while CDP services are stopped." -ForegroundColor Yellow
                Write-Host "  [NOTE] Set blockCDP=true to prevent reversion (disables CDP entirely)." -ForegroundColor Yellow
            } else {
                Write-Host "  Current GDID: $($after.hex)" -ForegroundColor White
            }
        }
    }
}

function Install-All {
    $cfg = Get-Config

    Write-Host "`n===== Installing GDID Privacy =====`n" -ForegroundColor Cyan

    # First-run guidance
    if (-not $cfg.originalGDID) {
        Write-Host "----------------------------------------------------------------------" -ForegroundColor DarkGray
        Write-Host "  IMPORTANT — Known Limitations" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  IP-based firewall blocking has fundamental limits: Azure Front Door" -ForegroundColor White
        Write-Host "  endpoints rotate addresses every 4-120 seconds. IP rules go stale" -ForegroundColor White
        Write-Host "  almost immediately. HOSTS blocking (blockHosts=true, ON by default)" -ForegroundColor Green
        Write-Host "  is name-based and immune to IP rotation — it actually works." -ForegroundColor Green
        Write-Host ""
        Write-Host "  CDP services are DISABLED by default (blockCDP=true). This is" -ForegroundColor Green
        Write-Host "  the strongest protection: the real GDID is never reported." -ForegroundColor Green
        Write-Host ""
        Write-Host "  To re-enable CDP (Nearby Share, cross-device clipboard, etc.):" -ForegroundColor DarkGray
        Write-Host "    .\\gdid-tool.ps1 config blockCDP false" -ForegroundColor DarkGray
        Write-Host "    .\\gdid-tool.ps1 config blockHosts true  (keep HOSTS blocking)" -ForegroundColor DarkGray
        Write-Host "    .\\gdid-tool.ps1 install" -ForegroundColor DarkGray
        Write-Host "----------------------------------------------------------------------" -ForegroundColor DarkGray
        Write-Host ""
    }

    Invoke-Rotate

    Install-FeatureKills $cfg

    Install-RotationTask $cfg

    if ($cfg.blockDDS -or $cfg.blockActivity) {
        Install-IPRefreshTask
    }

    Write-Host "`n===== Install Complete =====`n" -ForegroundColor Green
    Write-Host "Run '.\\gdid-tool.ps1 status' to verify." -ForegroundColor White
    Write-Host "Run '.\\gdid-tool.ps1 config' to adjust settings." -ForegroundColor White
}

function Uninstall-All {
    Write-Host "`n===== Uninstalling GDID Privacy =====" -ForegroundColor Cyan

    Uninstall-RotationTask
    Uninstall-IPRefreshTask
    Uninstall-FeatureKills

    Write-Host "  [OK] Restoring CDP service defaults..." -ForegroundColor Yellow
    Set-Service CDPSvc -StartupType Manual -ErrorAction SilentlyContinue
    Set-Service CDPUserSvc -StartupType Manual -ErrorAction SilentlyContinue

    Write-Host "`n===== Uninstall Complete =====" -ForegroundColor Green
    Write-Host "Reboot recommended to restore all services." -ForegroundColor Yellow
}

function Show-Config {
    $cfg = Get-Config
    if ($Key) {
        if ($cfg.ContainsKey($Key)) {
            if ($Value) {
                $cfg[$Key] = $Value -as $($cfg[$Key].GetType())
                Save-Config $cfg
                Write-Host "  [OK] $Key = $($cfg[$Key])" -ForegroundColor Green
            } else {
                Write-Host "$Key = $($cfg[$Key])" -ForegroundColor White
            }
        } else {
            Write-Host "  [ERROR] Unknown config key: $Key" -ForegroundColor Red
            Write-Host "  Available keys: $($cfg.Keys -join ', ')" -ForegroundColor Yellow
        }
    } else {
        Write-Host "`n-- GDID Configuration --" -ForegroundColor Cyan
        $cfg | Format-List
        Write-Host "Usage: .\gdid-tool.ps1 config <key> [value]"
    }
}

function Show-Help {
    Write-Host @"
GDID Privacy Tool
  Control the Windows Global Device Identifier (device fingerprint used by
  Microsoft for cross-device tracking, telemetry, and ad targeting).

Modes:
  status       Show current GDID, services, firewall rules, feature kills
  rotate       Immediately generate and apply a new random GDID (0018 prefix)
  refreshfw    Re-resolve firewall domain IPs and update blocking rules
  install      Install everything: rotation, firewall rules, feature kills
  uninstall    Remove all changes and restore system defaults
  config       View or change configuration
  help         Show this help

Config keys:
  rotationMode      perBoot / timed / onDemand
  timedIntervalMin  15-1440 (minutes)
  blockDDS          true/false  Block aad.cs.dds.microsoft.com (firewall)
  blockActivity     true/false  Block activity.windows.com (firewall)
  blockCDP          true/false  Disable CDPSvc/CDPUserSvc entirely (ON by default)
  killPhoneLink     true/false  Disable Phone Link (cross-device tracking)
  killOneDrive      true/false  Disable OneDrive sync (GDID telemetry)
  killStore         true/false  Disable Store auto-updates
  killTimeline      true/false  Disable Activity History / Timeline
  blockDO           true/false  Disable Delivery Optimization service (DoSvc)
  blockHosts        true/false  Block via HOSTS file (ON by default, name-based)

Known limitations:
  - CDP is disabled by default (blockCDP=true) for maximum protection.
    Set blockCDP=false to re-enable Nearby Share, cross-device clipboard,
    and other CDP-dependent features. Rotation becomes local-only.
  - IP-based firewall rules: Azure Front Door TTLs are 4-120 seconds.
    Rules may not match the address CDP connects to moments later.
  - For reliable blocking without disabling CDP, use blockHosts=true
    (name-based HOSTS file blocking, immune to IP rotation).

Examples:
  .\gdid-tool.ps1 status
  .\gdid-tool.ps1 rotate
  .\gdid-tool.ps1 refreshfw
  .\gdid-tool.ps1 install
  .\gdid-tool.ps1 config rotationMode timed
  .\gdid-tool.ps1 config timedIntervalMin 15
  .\gdid-tool.ps1 config killPhoneLink true
  .\gdid-tool.ps1 config blockHosts true
  .\gdid-tool.ps1 install
"@
}

# ---------- Main ----------
switch ($Mode) {
    'status'   { Show-Status }
    'rotate'   { Invoke-Rotate }
    'refreshfw' { Update-AllFirewallIPs }
    'install'  { Install-All }
    'uninstall' { Uninstall-All }
    'config'   { Show-Config }
    'help'     { Show-Help }
    default    { Show-Status }
}
