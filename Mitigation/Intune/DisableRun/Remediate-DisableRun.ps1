# Remediate-DisableRun.ps1
# Applies:
# - HKLM:\...\Policies\Explorer NoRun=1
# - Active Setup entry to enforce HKCU NoRun=1 at user logon

$ErrorActionPreference = "Stop"

$NoRunPathLM   = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$ActiveSetupKey = "HKLM:\Software\Microsoft\Active Setup\Installed Components\{9B8A2F2C-6A9A-4E34-9A8E-2B9A6F6D9D11}"

function Ensure-Key($Path) {
    if (-not (Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
}

function Set-Dword($Path, $Name, $Value) {
    Ensure-Key $Path
    New-ItemProperty -Path $Path -Name $Name -PropertyType DWord -Value $Value -Force | Out-Null
}

try {
    # 1) Machine-wide policy
    Set-Dword -Path $NoRunPathLM -Name "NoRun" -Value 1

    # 2) Active Setup for per-user HKCU enforcement at logon
    Ensure-Key $ActiveSetupKey
    New-ItemProperty -Path $ActiveSetupKey -Name "(Default)" -PropertyType String -Value "Disable Run (NoRun)" -Force | Out-Null
    New-ItemProperty -Path $ActiveSetupKey -Name "Version" -PropertyType String -Value "1,0,0,0" -Force | Out-Null

    # Runs in user context when user logs on
    $stub = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "New-Item -Path ''HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'' -Force | Out-Null; New-ItemProperty -Path ''HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'' -Name ''NoRun'' -PropertyType DWord -Value 1 -Force | Out-Null"'
    New-ItemProperty -Path $ActiveSetupKey -Name "StubPath" -PropertyType String -Value $stub -Force | Out-Null

    Write-Output "Remediated: Run (Win+R) disabled via HKLM NoRun=1 + Active Setup for HKCU."
    Write-Output "Note: Existing logged-on users may need logoff/logon to get HKCU applied, but Win+R is already blocked via HKLM."
    exit 0
}
catch {
    Write-Error "Remediation failed: $($_.Exception.Message)"
    exit 1
}
