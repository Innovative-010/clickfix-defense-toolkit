<#
.SYNOPSIS
    Intune Remediation script for ClickFix REX shortcut mitigation for all user profiles.

.DESCRIPTION
    Designed to run as SYSTEM from Intune Remediations.
    Ensures DisabledHotkeys contains R, E and X for:
      - all existing real user profiles under HKLM\...\ProfileList
      - loaded user hives under HKEY_USERS
      - unloaded user hives by temporarily loading NTUSER.DAT
      - the Default User profile, so new users inherit the setting

    The remediation is idempotent:
      - Existing DisabledHotkeys values are preserved.
      - Missing required letters are merged into the current value.
      - A backup of the first observed value is written to DisabledHotkeys_Backup_ClickFix.
      - Detailed logs are written locally; Intune output is kept short.

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
$BackupValueName = 'DisabledHotkeys_Backup_ClickFix'
$SubKeyPath      = 'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
$ProfileListPath = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList'
$DefaultNtUser   = 'C:\Users\Default\NTUSER.DAT'

# Set to $true for GitHub/demo/audit-only testing. Set to $false for Intune remediation.
$AuditOnly = $false

$LogFolder = 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs'
$LogFile   = Join-Path -Path $LogFolder -ChildPath 'ClickFix-REX-AllUsers-Remediation.log'
$MaxLogSizeBytes = 1MB

# -----------------------------
# Logging
# -----------------------------
function Initialize-Log {
    if (-not (Test-Path -Path $LogFolder)) {
        New-Item -Path $LogFolder -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }

    if (Test-Path -Path $LogFile) {
        $existingLog = Get-Item -Path $LogFile -ErrorAction Stop
        if ($existingLog.Length -gt $MaxLogSizeBytes) {
            $oldLog = "$LogFile.old"
            Move-Item -Path $LogFile -Destination $oldLog -Force -ErrorAction Stop
        }
    }
}

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet('INFO', 'WARN', 'ERROR')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $entry = "[$timestamp] [$Level] $Message"

    try {
        Add-Content -Path $LogFile -Value $entry -Encoding UTF8 -ErrorAction Stop
    }
    catch {
        # Keep Intune output clean; do not throw if logging fails.
    }
}

# -----------------------------
# Helper functions
# -----------------------------
function Get-UserProfiles {
    $profiles = New-Object System.Collections.Generic.List[object]
    $seenSids = New-Object 'System.Collections.Generic.HashSet[string]'

    if (-not (Test-Path -Path $ProfileListPath)) {
        Write-Log "ProfileList registry path not found: $ProfileListPath" 'WARN'
    }
    else {
        # Do not filter only on S-1-5-21. Entra ID / Azure AD users can use S-1-12-1-* SIDs.
        $profileKeys = Get-ChildItem -Path $ProfileListPath -ErrorAction Stop

        foreach ($profileKey in $profileKeys) {
            try {
                $sid = $profileKey.PSChildName

                # Skip well-known service/system SIDs and class hives.
                if ($sid -match '_Classes$' -or $sid -in @('S-1-5-18','S-1-5-19','S-1-5-20')) {
                    continue
                }

                $profile = Get-ItemProperty -Path $profileKey.PSPath -ErrorAction Stop

                if ([string]::IsNullOrWhiteSpace($profile.ProfileImagePath)) {
                    continue
                }

                $profilePath = [Environment]::ExpandEnvironmentVariables($profile.ProfileImagePath)

                # Skip well-known/non-interactive/default profiles. Default User is handled separately.
                if ($profilePath -match '\\(Default|Default User|Public|All Users|defaultuser0)$') {
                    Write-Log "Skipping non-target profile SID $sid, path: $profilePath"
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
                else {
                    Write-Log "Skipping SID $sid. NTUSER.DAT not found at: $ntUserPath" 'WARN'
                }
            }
            catch {
                Write-Log "Failed to read profile key $($profileKey.PSChildName): $($_.Exception.Message)" 'WARN'
            }
        }
    }

    # Extra safety: include already-loaded interactive hives that might not be present in ProfileList enumeration.
    # This covers edge cases and cloud-account SIDs such as S-1-12-1-*.
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
                Write-Log "Including loaded user hive not found in ProfileList filter: SID=$sid; ProfilePath=$profilePath" 'WARN'
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
        Write-Log "Failed to enumerate loaded HKEY_USERS hives: $($_.Exception.Message)" 'WARN'
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
    else {
        Write-Log "Default User NTUSER.DAT not found at: $DefaultNtUser" 'WARN'
    }

    return $profiles
}

function Mount-UserHive {
    param(
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Profile
    )

    if (-not $Profile.IsDefault -and (Test-Path -Path "Registry::HKEY_USERS\$($Profile.Sid)")) {
        Write-Log "Using already-loaded hive for $($Profile.Sid)."
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
        Write-Log "Using existing temporary hive HKU\$tempName for $($Profile.Sid)." 'WARN'
        return [PSCustomObject]@{
            HiveRoot       = $tempHiveRoot
            LoadedByScript = $false
            TempName       = $tempName
        }
    }

    Write-Log "Loading hive for $($Profile.Sid) from '$($Profile.NtUserPath)' into HKU\$tempName."
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
        Start-Sleep -Milliseconds 300

        Write-Log "Unloading temporary hive HKU\$($HiveInfo.TempName)."
        $unloadOutput = & reg.exe unload "HKU\$($HiveInfo.TempName)" 2>&1

        if ($LASTEXITCODE -ne 0) {
            Write-Log "Failed to unload HKU\$($HiveInfo.TempName). reg.exe output: $unloadOutput" 'WARN'
        }
    }
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

function Merge-DisabledHotkeysValue {
    param([AllowNull()][string]$CurrentValue)

    $orderedKeys = New-Object System.Collections.Generic.List[string]

    # Preserve existing order first.
    if (-not [string]::IsNullOrWhiteSpace($CurrentValue)) {
        foreach ($character in $CurrentValue.ToUpperInvariant().ToCharArray()) {
            $charString = [string]$character
            if (-not $orderedKeys.Contains($charString)) {
                $orderedKeys.Add($charString)
            }
        }
    }

    # Then append required keys in REX order.
    foreach ($requiredKey in $RequiredKeys) {
        if (-not $orderedKeys.Contains($requiredKey)) {
            $orderedKeys.Add($requiredKey)
        }
    }

    return ($orderedKeys -join '')
}

function Set-DisabledHotkeysForHive {
    param(
        [Parameter(Mandatory = $true)]
        [string]$HiveRoot,

        [Parameter(Mandatory = $true)]
        [string]$ProfileIdentifier
    )

    $registryPath = "$HiveRoot\$SubKeyPath"

    if (-not (Test-Path -Path $registryPath)) {
        if ($AuditOnly) {
            Write-Log "AUDIT: Would create registry path for ${ProfileIdentifier}: $registryPath"
        }
        else {
            New-Item -Path $registryPath -Force -ErrorAction Stop | Out-Null
            Write-Log "Created registry path for ${ProfileIdentifier}: $registryPath"
        }
    }

    $currentValue = $null
    try {
        $currentValue = (Get-ItemProperty -Path $registryPath -Name $ValueName -ErrorAction Stop).$ValueName
    }
    catch {
        $currentValue = $null
    }

    if (Test-DisabledHotkeysValue -CurrentValue $currentValue) {
        Write-Log "$ProfileIdentifier is already compliant. Current $ValueName='$currentValue'."
        return [PSCustomObject]@{
            Changed       = $false
            Compliant     = $true
            CurrentValue  = $currentValue
            NewValue      = $currentValue
        }
    }

    $newValue = Merge-DisabledHotkeysValue -CurrentValue $currentValue
    Write-Log "$ProfileIdentifier is non-compliant. Current $ValueName='$currentValue'; target merged value='$newValue'."

    if ($AuditOnly) {
        Write-Log "AUDIT: Would set $ValueName='$newValue' for $ProfileIdentifier."
        return [PSCustomObject]@{
            Changed       = $false
            Compliant     = $false
            CurrentValue  = $currentValue
            NewValue      = $newValue
        }
    }

    # Backup the first observed value only. Do not overwrite existing backup.
    $backupExists = $false
    try {
        $null = Get-ItemProperty -Path $registryPath -Name $BackupValueName -ErrorAction Stop
        $backupExists = $true
    }
    catch {
        $backupExists = $false
    }

    if (-not $backupExists) {
        $backupValue = if ($null -eq $currentValue) { '<missing>' } else { [string]$currentValue }
        New-ItemProperty -Path $registryPath -Name $BackupValueName -PropertyType String -Value $backupValue -Force -ErrorAction Stop | Out-Null
        Write-Log "Backed up original value for $ProfileIdentifier to $BackupValueName='$backupValue'."
    }

    New-ItemProperty -Path $registryPath -Name $ValueName -PropertyType String -Value $newValue -Force -ErrorAction Stop | Out-Null

    $checkValue = (Get-ItemProperty -Path $registryPath -Name $ValueName -ErrorAction Stop).$ValueName
    $isCompliant = Test-DisabledHotkeysValue -CurrentValue $checkValue

    if ($isCompliant) {
        Write-Log "Remediation successful for $ProfileIdentifier. $ValueName='$checkValue'."
    }
    else {
        Write-Log "Remediation verification failed for $ProfileIdentifier. $ValueName='$checkValue'." 'ERROR'
    }

    return [PSCustomObject]@{
        Changed       = $true
        Compliant     = $isCompliant
        CurrentValue  = $currentValue
        NewValue      = $checkValue
    }
}

# -----------------------------
# Main remediation logic
# -----------------------------
try {
    Initialize-Log

    Write-Log '========== ClickFix REX All Users Remediation Started =========='
    Write-Log "Running as: $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"
    Write-Log "Running SID: $([System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value)"
    Write-Log "Computer name: $env:COMPUTERNAME"
    Write-Log "PowerShell version: $($PSVersionTable.PSVersion)"
    Write-Log "Is 64-bit process: $([Environment]::Is64BitProcess)"
    Write-Log "PSHOME: $PSHOME"
    Write-Log "AuditOnly: $AuditOnly"
    Write-Log "Target subkey: $SubKeyPath"
    Write-Log "Required hotkeys: $RequiredHotkeys"

    if (-not [Environment]::Is64BitProcess) {
        Write-Log 'PowerShell is not running as a 64-bit process. Registry redirection may affect results.' 'WARN'
    }

    $profiles = Get-UserProfiles

    if ($null -eq $profiles -or $profiles.Count -eq 0) {
        Write-Log 'No user profiles with NTUSER.DAT were found. Nothing to remediate.' 'WARN'
        Write-Output 'Not applicable: no user profiles found.'
        exit 0
    }

    $processedCount = 0
    $changedCount = 0
    $alreadyCompliantCount = 0
    $failedCount = 0

    foreach ($profile in $profiles) {
        $hiveInfo = $null

        try {
            $processedCount++
            Write-Log "Processing profile: SID=$($profile.Sid); Path=$($profile.ProfilePath); Default=$($profile.IsDefault)."

            $hiveInfo = Mount-UserHive -Profile $profile
            $result = Set-DisabledHotkeysForHive -HiveRoot $hiveInfo.HiveRoot -ProfileIdentifier $profile.Sid

            if ($result.Compliant -eq $true -and $result.Changed -eq $false) {
                $alreadyCompliantCount++
            }
            elseif ($result.Compliant -eq $true -and $result.Changed -eq $true) {
                $changedCount++
            }
            else {
                $failedCount++
            }
        }
        catch {
            $failedCount++
            Write-Log "Failed to process profile $($profile.Sid). Error: $($_.Exception.Message)" 'ERROR'
        }
        finally {
            if ($null -ne $hiveInfo) {
                Dismount-UserHive -HiveInfo $hiveInfo
            }
        }
    }

    Write-Log "Summary: processed=$processedCount; changed=$changedCount; alreadyCompliant=$alreadyCompliantCount; failed=$failedCount."

    if ($AuditOnly) {
        Write-Log '========== ClickFix REX All Users Remediation Finished - Audit Only =========='
        Write-Output "AuditOnly: processed=$processedCount; wouldChange=$changedCount; alreadyCompliant=$alreadyCompliantCount; failed=$failedCount."
        exit 0
    }

    if ($failedCount -gt 0) {
        Write-Log '========== ClickFix REX All Users Remediation Finished With Errors ==========' 'ERROR'
        Write-Output "Remediation failed: processed=$processedCount; changed=$changedCount; alreadyCompliant=$alreadyCompliantCount; failed=$failedCount. See local IME log."
        exit 1
    }

    Write-Log '========== ClickFix REX All Users Remediation Finished Successfully =========='
    Write-Output "Remediation successful: processed=$processedCount; changed=$changedCount; alreadyCompliant=$alreadyCompliantCount; failed=0."
    exit 0
}
catch {
    try {
        Write-Log "Fatal remediation failure: $($_.Exception.Message)" 'ERROR'
        Write-Log '========== ClickFix REX All Users Remediation Failed ==========' 'ERROR'
    }
    catch {}

    Write-Output "Remediation failed: $($_.Exception.Message)"
    exit 1
}
