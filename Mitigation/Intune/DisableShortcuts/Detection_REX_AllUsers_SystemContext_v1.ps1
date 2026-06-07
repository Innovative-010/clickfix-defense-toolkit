<#
.SYNOPSIS
    Intune Detection script for ClickFix REX shortcut mitigation for all user profiles.

.DESCRIPTION
    Designed to run as SYSTEM from Intune Remediations.
    Checks whether DisabledHotkeys contains R, E and X for:
      - all existing real user profiles under HKLM\...\ProfileList
      - loaded user hives under HKEY_USERS
      - unloaded user hives by temporarily loading NTUSER.DAT
      - the Default User profile, so new users inherit the setting

.NOTES
    Recommended Intune settings:
      - Run this script using the logged-on credentials: No
      - Run script in 64-bit PowerShell: Yes
      - Enforce script signature check: No during pilot, Yes only when signed
#>

#Requires -Version 5.1

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# -----------------------------
# Configuration
# -----------------------------
$RequiredHotkeys = 'REX'
$RequiredKeys    = @('R', 'E', 'X')
$ValueName       = 'DisabledHotkeys'
$SubKeyPath      = 'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
$ProfileListPath = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
$DefaultNtUser   = 'C:\Users\Default\NTUSER.DAT'

# -----------------------------
# Helper functions
# -----------------------------
function Exit-Compliant {
    param([string]$Message = 'Compliant')
    Write-Output $Message
    exit 0
}

function Exit-NonCompliant {
    param([string]$Message = 'Non-compliant')
    Write-Output $Message
    exit 1
}

function Test-DisabledHotkeysValue {
    param([AllowNull()][string]$CurrentValue)

    if ([string]::IsNullOrWhiteSpace($CurrentValue)) {
        return $false
    }

    $normalized = $CurrentValue.ToUpperInvariant()

    foreach ($key in $RequiredKeys) {
        if ($normalized -notlike "*$key*") {
            return $false
        }
    }

    return $true
}

function Get-UserProfiles {
    $profiles = New-Object System.Collections.Generic.List[object]
    $seenSids = New-Object 'System.Collections.Generic.HashSet[string]'

    if (Test-Path -Path $ProfileListPath) {
        # Do not filter only on S-1-5-21. Entra ID / Azure AD users can use S-1-12-1-* SIDs.
        $profileKeys = Get-ChildItem -Path $ProfileListPath -ErrorAction Stop

        foreach ($profileKey in $profileKeys) {
            try {
                $sid = $profileKey.PSChildName

                if ($sid -match '_Classes$' -or $sid -in @('S-1-5-18','S-1-5-19','S-1-5-20')) {
                    continue
                }

                $profile = Get-ItemProperty -Path $profileKey.PSPath -ErrorAction Stop

                if ([string]::IsNullOrWhiteSpace($profile.ProfileImagePath)) {
                    continue
                }

                $profilePath = [Environment]::ExpandEnvironmentVariables($profile.ProfileImagePath)

                # Skip well-known/non-interactive profiles. Default User is handled separately.
                if ($profilePath -match '\\(Default|Default User|Public|All Users|defaultuser0)$') {
                    continue
                }

                $ntUserPath = Join-Path -Path $profilePath -ChildPath 'NTUSER.DAT'

                if (Test-Path -Path $ntUserPath) {
                    if ($seenSids.Add($sid)) {
                        $profiles.Add([PSCustomObject]@{
                            Sid          = $sid
                            ProfilePath  = $profilePath
                            NtUserPath   = $ntUserPath
                            IsDefault    = $false
                            IsLoadedOnly = $false
                        })
                    }
                }
            }
            catch {
                # Detection should not be noisy. If a single profile cannot be read,
                # skip it rather than breaking detection for all profiles.
                continue
            }
        }
    }

    # Extra safety: include already-loaded interactive hives that might not be present in ProfileList enumeration.
    try {
        $loadedHives = Get-ChildItem -Path 'Registry::HKEY_USERS' -ErrorAction Stop |
            Where-Object {
                $_.PSChildName -notmatch '_Classes$' -and
                $_.PSChildName -notin @('S-1-5-18','S-1-5-19','S-1-5-20','.DEFAULT') -and
                ($_.PSChildName -match '^S-1-5-21-' -or $_.PSChildName -match '^S-1-12-1-')
            }

        foreach ($loadedHive in $loadedHives) {
            $sid = $loadedHive.PSChildName
            if ($seenSids.Contains($sid)) {
                continue
            }

            $profilePath = $null
            try {
                $volatileEnvPath = "Registry::HKEY_USERS\$sid\Volatile Environment"
                if (Test-Path -Path $volatileEnvPath) {
                    $profilePath = (Get-ItemProperty -Path $volatileEnvPath -Name 'USERPROFILE' -ErrorAction SilentlyContinue).USERPROFILE
                }
            }
            catch {
                $profilePath = $null
            }

            if ([string]::IsNullOrWhiteSpace($profilePath)) {
                $profilePath = '<loaded hive only>'
            }

            if ($seenSids.Add($sid)) {
                $profiles.Add([PSCustomObject]@{
                    Sid          = $sid
                    ProfilePath  = $profilePath
                    NtUserPath   = $null
                    IsDefault    = $false
                    IsLoadedOnly = $true
                })
            }
        }
    }
    catch {
        # Keep detection clean.
    }

    if (Test-Path -Path $DefaultNtUser) {
        if ($seenSids.Add('DEFAULT_USER_PROFILE')) {
            $profiles.Add([PSCustomObject]@{
                Sid          = 'DEFAULT_USER_PROFILE'
                ProfilePath  = 'C:\Users\Default'
                NtUserPath   = $DefaultNtUser
                IsDefault    = $true
                IsLoadedOnly = $false
            })
        }
    }

    return $profiles
}

function Mount-UserHive {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Profile
    )

    if (-not $Profile.IsDefault -and (Test-Path -Path "Registry::HKEY_USERS\$($Profile.Sid)")) {
        return [PSCustomObject]@{
            HiveRoot       = "Registry::HKEY_USERS\$($Profile.Sid)"
            LoadedByScript = $false
            TempName       = $null
        }
    }

    if ($Profile.IsLoadedOnly -or [string]::IsNullOrWhiteSpace($Profile.NtUserPath)) {
        throw "Hive for $($Profile.Sid) is not loaded and no NTUSER.DAT path is available."
    }

    $tempName = if ($Profile.IsDefault) {
        'TEMP_CLICKFIX_REX_DEFAULT'
    }
    else {
        "TEMP_CLICKFIX_REX_$($Profile.Sid -replace '[^A-Za-z0-9]', '_')"
    }

    $tempHiveRoot = "Registry::HKEY_USERS\$tempName"

    if (Test-Path -Path $tempHiveRoot) {
        return [PSCustomObject]@{
            HiveRoot       = $tempHiveRoot
            LoadedByScript = $false
            TempName       = $tempName
        }
    }

    $loadOutput = & reg.exe load "HKU\$tempName" "$($Profile.NtUserPath)" 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to load hive for $($Profile.Sid). reg.exe output: $loadOutput"
    }

    return [PSCustomObject]@{
        HiveRoot       = $tempHiveRoot
        LoadedByScript = $true
        TempName       = $tempName
    }
}

function Dismount-UserHive {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$HiveInfo
    )

    if ($HiveInfo.LoadedByScript -and -not [string]::IsNullOrWhiteSpace($HiveInfo.TempName)) {
        [GC]::Collect()
        [GC]::WaitForPendingFinalizers()
        Start-Sleep -Milliseconds 250
        & reg.exe unload "HKU\$($HiveInfo.TempName)" 2>&1 | Out-Null
    }
}

# -----------------------------
# Main detection logic
# -----------------------------
try {
    $profiles = Get-UserProfiles

    if ($null -eq $profiles -or $profiles.Count -eq 0) {
        Exit-Compliant 'Not applicable: no user profiles with NTUSER.DAT were found.'
    }

    $checkedCount = 0
    $nonCompliantCount = 0
    $errorCount = 0

    foreach ($profile in $profiles) {
        $hiveInfo = $null

        try {
            $hiveInfo = Mount-UserHive -Profile $profile
            $registryPath = "$($hiveInfo.HiveRoot)\$SubKeyPath"
            $checkedCount++

            if (-not (Test-Path -Path $registryPath)) {
                $nonCompliantCount++
                continue
            }

            $currentValue = (Get-ItemProperty -Path $registryPath -Name $ValueName -ErrorAction SilentlyContinue).$ValueName

            if (-not (Test-DisabledHotkeysValue -CurrentValue $currentValue)) {
                $nonCompliantCount++
                continue
            }
        }
        catch {
            # Treat detection errors as non-compliant so remediation gets a chance to repair.
            $errorCount++
        }
        finally {
            if ($null -ne $hiveInfo) {
                Dismount-UserHive -HiveInfo $hiveInfo
            }
        }
    }

    if (($nonCompliantCount + $errorCount) -gt 0) {
        Exit-NonCompliant "Non-compliant: $nonCompliantCount profile(s) missing required hotkeys '$RequiredHotkeys'; $errorCount detection error(s); $checkedCount profile(s) checked."
    }

    Exit-Compliant "Compliant: '$ValueName' contains '$RequiredHotkeys' for $checkedCount profile(s)."
}
catch {
    Exit-NonCompliant "Non-compliant: detection failed. $($_.Exception.Message)"
}
