# Detect-DisableRun.ps1
# Returns:
#   Exit 0 = Compliant (Run disabled as intended)
#   Exit 1 = Non-compliant (missing/incorrect settings)

$ErrorActionPreference = "Stop"

$NoRunPathLM   = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"
$ActiveSetupKey = "HKLM:\Software\Microsoft\Active Setup\Installed Components\{9B8A2F2C-6A9A-4E34-9A8E-2B9A6F6D9D11}"

try {
    $lmOk = $false
    if (Test-Path $NoRunPathLM) {
        $v = (Get-ItemProperty -Path $NoRunPathLM -Name "NoRun" -ErrorAction SilentlyContinue)."NoRun"
        if ($v -eq 1) { $lmOk = $true }
    }

    $asOk = $false
    if (Test-Path $ActiveSetupKey) {
        $stub = (Get-ItemProperty -Path $ActiveSetupKey -Name "StubPath" -ErrorAction SilentlyContinue)."StubPath"
        $ver  = (Get-ItemProperty -Path $ActiveSetupKey -Name "Version"  -ErrorAction SilentlyContinue)."Version"
        if ($stub -and $ver) { $asOk = $true }
    }

    if ($lmOk -and $asOk) {
        Write-Output "Compliant: Run (Win+R) is disabled (HKLM NoRun=1) and Active Setup is present."
        exit 0
    }

    Write-Output "Non-compliant: HKLM NoRun or Active Setup missing/incorrect. lmOk=$lmOk asOk=$asOk"
    exit 1
}
catch {
    Write-Output "Non-compliant (error): $($_.Exception.Message)"
    exit 1
}
