<# 
.SYNOPSIS
Scores Windows ClickFix quickfix protection posture.

.DESCRIPTION
Checks the quickfix controls from the ClickFix Quickfix Guide for Intune:
QF-1 Block Win+R, Win+E, and Win+X shortcuts
QF-2 Remove Run menu from Start Menu
QF-3 Block Command Prompt and command script processing
QF-4 Block minimum high-risk binaries with DisallowRun
QF-5 Detect uBlock Origin Lite or uBlock Origin in Edge, Chrome, and Firefox

The checks are non-remediating: they inspect registry policy and local browser
profile evidence but do not change protection settings. The script writes a
timestamped TXT report next to the script on every run, and can optionally write
a JSON report when -JsonPath is provided.

It can run as a standard user, admin, or SYSTEM.
When run as SYSTEM or admin it can usually inspect more loaded user hives.

.PARAMETER JsonPath
Optional path to write a JSON report.

.PARAMETER IncludeInformationalChecks
Adds non-scored checks for long-term hardening signals such as WDAC/AppLocker
registry policy presence and common Defender ASR policy presence.

.EXAMPLE
.\ClickFix-Protection-Score.ps1

Runs the scored quickfix checks and writes a timestamped TXT report next to the
script.

.EXAMPLE
.\ClickFix-Protection-Score.ps1 -JsonPath .\clickfix-score.json -IncludeInformationalChecks

Runs the scored quickfix checks, includes non-scored hardening signals, writes a
timestamped TXT report, and writes a JSON report to .\clickfix-score.json.
#>

[CmdletBinding()]
param(
    [string]$JsonPath,
    [switch]$IncludeInformationalChecks
)

$ErrorActionPreference = 'SilentlyContinue'

$RequiredHotKeys = @('R', 'E', 'X')
$RequiredBinaries = @(
    'powershell.exe',
    'pwsh.exe',
    'powershell_ise.exe',
    'cmd.exe',
    'wscript.exe',
    'cscript.exe',
    'mshta.exe',
    'WindowsTerminal.exe',
    'wt.exe'
)

$BrowserExtensions = @{
    Edge = @{
        Ids   = @(
            'cimighlppcgcoapaliogpjjdehbnofhn',
            'odfafepnkmbhccpbejgmiehpchacaeak'
        )
        Names = @('uBlock Origin Lite', 'uBlock Origin')
    }
    Chrome = @{
        Ids   = @(
            'ddkjiahejlhfcafbddmgiahcphecmpfh',
            'cjpalhdlnbpafiamejdnhcphjbkeiagm'
        )
        Names = @('uBlock Origin Lite', 'uBlock Origin')
    }
    Firefox = @{
        Ids   = @(
            'uBOLite@raymondhill.net',
            'uBlock0@raymondhill.net'
        )
        Names = @('uBlock Origin Lite', 'uBlock Origin')
    }
}

function Get-RegValue {
    param(
        [Parameter(Mandatory)] [string]$Path,
        [Parameter(Mandatory)] [string]$Name
    )

    try {
        $item = Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    } catch {
        return $null
    }
}

function Test-RegKey {
    param([Parameter(Mandatory)] [string]$Path)
    return [bool](Test-Path -LiteralPath $Path)
}

function Get-OSCaption {
    $currentVersionPath = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $productName = [string](Get-RegValue -Path $currentVersionPath -Name 'ProductName')
    $editionId = [string](Get-RegValue -Path $currentVersionPath -Name 'EditionID')
    $displayVersion = [string](Get-RegValue -Path $currentVersionPath -Name 'DisplayVersion')
    $currentBuild = [int](Get-RegValue -Path $currentVersionPath -Name 'CurrentBuild')

    if ($currentBuild -gt 0) {
        $windowsVersion = if ($currentBuild -ge 22000) { 'Windows 11' } else { 'Windows 10' }
        $edition = switch ($editionId) {
            'Professional' { 'Pro' }
            'Enterprise' { 'Enterprise' }
            'Education' { 'Education' }
            'Core' { 'Home' }
            default {
                if ($productName -match 'Windows\s+\d+\s+(.+)$') { $Matches[1] } else { $editionId }
            }
        }

        $captionParts = @($windowsVersion)
        if ($edition) { $captionParts += $edition }
        if ($displayVersion) { $captionParts += $displayVersion }
        return ($captionParts -join ' ')
    }

    return (Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty Caption)
}

function ConvertTo-RegistryPath {
    param([Parameter(Mandatory)] [string]$HiveName)
    return "Registry::HKEY_USERS\$HiveName"
}

function Get-LoadedUserHives {
    $hives = New-Object 'System.Collections.Generic.List[object]'

    Get-ChildItem -Path 'Registry::HKEY_USERS' | ForEach-Object {
        $name = Split-Path -Path $_.Name -Leaf
        if ($name -match '^S-1-5-21-\d+-\d+-\d+-\d+$') {
            [void]$hives.Add([pscustomobject]@{
                Sid  = $name
                Root = ConvertTo-RegistryPath -HiveName $name
            })
        }
    }

    if ($hives.Count -eq 0) {
        $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        [void]$hives.Add([pscustomobject]@{
            Sid  = $currentSid
            Root = 'HKCU:'
        })
    }

    return @($hives.ToArray())
}

function Get-LocalUserFolders {
    $usersRoot = Join-Path $env:SystemDrive 'Users'
    return @(Get-ChildItem -LiteralPath $usersRoot -Directory -ErrorAction SilentlyContinue)
}

function New-CheckResult {
    param(
        [Parameter(Mandatory)] [string]$Id,
        [Parameter(Mandatory)] [string]$Name,
        [Parameter(Mandatory)] [int]$Weight,
        [Parameter(Mandatory)] [int]$Earned,
        [Parameter(Mandatory)] [string]$Status,
        [Parameter(Mandatory)] [string]$Evidence,
        [string[]]$Recommendations = @()
    )

    [pscustomobject]@{
        Id              = $Id
        Name            = $Name
        Weight          = $Weight
        Earned          = $Earned
        Status          = $Status
        Evidence        = $Evidence
        Recommendations = $Recommendations
    }
}

function Get-ScoreStatus {
    param(
        [Parameter(Mandatory)] [double]$Ratio,
        [switch]$PartialAllowed
    )

    if ($Ratio -ge 1) { return 'Pass' }
    if ($PartialAllowed -and $Ratio -gt 0) { return 'Partial' }
    return 'Fail'
}

function Test-BrowserInstalled {
    param([Parameter(Mandatory)] [ValidateSet('Edge', 'Chrome', 'Firefox')] [string]$Browser)

    if ($Browser -eq 'Edge') {
        return $true
    }

    $browserPaths = if ($Browser -eq 'Chrome') {
        @(
            "$env:ProgramFiles\Google\Chrome\Application\chrome.exe",
            "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe",
            "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
        )
    } else {
        @(
            "$env:ProgramFiles\Mozilla Firefox\firefox.exe",
            "${env:ProgramFiles(x86)}\Mozilla Firefox\firefox.exe",
            "$env:LOCALAPPDATA\Mozilla Firefox\firefox.exe"
        )
    }

    foreach ($path in $browserPaths) {
        if ($path -and (Test-Path -LiteralPath $path)) {
            return $true
        }
    }

    $registryPaths = if ($Browser -eq 'Chrome') {
        @(
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe',
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome',
            'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome',
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Google Chrome'
        )
    } else {
        @(
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\App Paths\firefox.exe',
            'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Mozilla Firefox',
            'HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Mozilla Firefox',
            'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Mozilla Firefox'
        )
    }

    foreach ($path in $registryPaths) {
        if (Test-RegKey -Path $path) {
            return $true
        }
    }

    return $false
}

function Get-CheckBadge {
    param([Parameter(Mandatory)] [string]$Status)

    switch ($Status) {
        'Pass' { return '[TRUE]' }
        'Partial' { return '[PARTIAL]' }
        default { return '[FALSE]' }
    }
}

$script:TextOutputLines = New-Object 'System.Collections.Generic.List[string]'

function Add-TextOutputLine {
    param([AllowNull()] [string]$Text = '')

    [void]$script:TextOutputLines.Add([string]$Text)
}

function Write-ReportLine {
    param(
        [AllowNull()] [string]$Text = '',
        [string]$ForegroundColor
    )

    Add-TextOutputLine -Text $Text

    if ($ForegroundColor) {
        Write-Host $Text -ForegroundColor $ForegroundColor
    } else {
        Write-Host $Text
    }
}

function Write-StatusBadgeLine {
    param(
        [string]$Prefix = '',
        [Parameter(Mandatory)] [string]$Text
    )

    $remaining = $Text
    Write-Host $Prefix -NoNewline

    while ($remaining -match '\[(TRUE|FALSE|PARTIAL|SKIPPED)\]') {
        $match = $Matches[0]
        $before = $remaining.Substring(0, $remaining.IndexOf($match))
        if ($before) {
            Write-Host $before -NoNewline
        }

        $badgeColor = switch ($match) {
            '[TRUE]' { 'Green' }
            '[FALSE]' { 'Red' }
            '[PARTIAL]' { 'Yellow' }
            '[SKIPPED]' { 'DarkGray' }
        }
        Write-Host $match -ForegroundColor $badgeColor -NoNewline

        $remaining = $remaining.Substring($remaining.IndexOf($match) + $match.Length)
    }

    Write-Host $remaining
    Add-TextOutputLine -Text "$Prefix$Text"
}

function Get-ScoreBar {
    param(
        [Parameter(Mandatory)] [int]$Percentage,
        [int]$Width = 30
    )

    $filled = [math]::Round(($Percentage / 100) * $Width)
    if ($filled -lt 0) { $filled = 0 }
    if ($filled -gt $Width) { $filled = $Width }

    return ('[' + ('#' * $filled) + ('-' * ($Width - $filled)) + ']')
}

function Test-DisabledHotKeys {
    param([Parameter(Mandatory)] [object[]]$Hives)

    $checked = 0
    $passed = 0
    $details = New-Object 'System.Collections.Generic.List[string]'

    foreach ($hive in $Hives) {
        $path = Join-Path $hive.Root 'Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced'
        $value = [string](Get-RegValue -Path $path -Name 'DisabledHotKeys')
        $hasAll = $true

        foreach ($key in $RequiredHotKeys) {
            if ($value -notmatch [regex]::Escape($key)) {
                $hasAll = $false
            }
        }

        $checked++
        if ($hasAll) { $passed++ }
        [void]$details.Add("$($hive.Sid): DisabledHotKeys='$value'")
    }

    $ratio = if ($checked -gt 0) { $passed / $checked } else { 0 }
    $earned = [math]::Round(20 * $ratio)
    $status = Get-ScoreStatus -Ratio $ratio -PartialAllowed

    New-CheckResult `
        -Id 'QF-1' `
        -Name 'Block Win+R, Win+E, and Win+X shortcuts' `
        -Weight 20 `
        -Earned $earned `
        -Status $status `
        -Evidence ("{0}/{1} loaded user hive(s) contain DisabledHotKeys with R, E, and X. {2}" -f $passed, $checked, ($details.ToArray() -join '; ')) `
        -Recommendations @('Set HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\DisabledHotKeys to REX for standard users.')
}

function Test-RemoveRunMenu {
    param([Parameter(Mandatory)] [object[]]$Hives)

    $checked = 0
    $passed = 0
    $details = New-Object 'System.Collections.Generic.List[string]'

    foreach ($hive in $Hives) {
        $path = Join-Path $hive.Root 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        $value = Get-RegValue -Path $path -Name 'NoRun'
        $isEnabled = ($value -eq 1)

        $checked++
        if ($isEnabled) { $passed++ }
        [void]$details.Add("$($hive.Sid): NoRun='$value'")
    }

    $ratio = if ($checked -gt 0) { $passed / $checked } else { 0 }
    $earned = [math]::Round(15 * $ratio)
    $status = Get-ScoreStatus -Ratio $ratio -PartialAllowed

    New-CheckResult `
        -Id 'QF-2' `
        -Name 'Remove Run menu from Start Menu' `
        -Weight 15 `
        -Earned $earned `
        -Status $status `
        -Evidence ("{0}/{1} loaded user hive(s) have NoRun enabled. {2}" -f $passed, $checked, ($details.ToArray() -join '; ')) `
        -Recommendations @('Enable the user policy Remove Run menu from Start Menu, which sets NoRun to 1.')
}

function Test-CommandPromptBlocked {
    param([Parameter(Mandatory)] [object[]]$Hives)

    $checked = 0
    $scoreSum = 0
    $statusLines = New-Object 'System.Collections.Generic.List[string]'

    foreach ($hive in $Hives) {
        $path = Join-Path $hive.Root 'Software\Policies\Microsoft\Windows\System'
        $value = Get-RegValue -Path $path -Name 'DisableCMD'
        $commandPromptBlocked = ($value -eq 1) -or ($value -eq 2)
        $scriptProcessingBlocked = ($value -eq 1)
        $hiveRatio = 0
        if ($commandPromptBlocked) { $hiveRatio += 0.5 }
        if ($scriptProcessingBlocked) { $hiveRatio += 0.5 }
        $commandPromptBadge = if ($commandPromptBlocked) { '[TRUE]' } else { '[FALSE]' }
        $scriptProcessingBadge = if ($scriptProcessingBlocked) { '[TRUE]' } else { '[FALSE]' }

        $checked++
        $scoreSum += $hiveRatio
        [void]$statusLines.Add("- $($hive.Sid) DisableCMD='$value'")
        [void]$statusLines.Add("  - Command Prompt blocked $commandPromptBadge")
        [void]$statusLines.Add("  - Command script processing blocked $scriptProcessingBadge")
    }

    $ratio = if ($checked -gt 0) { $scoreSum / $checked } else { 0 }
    $earned = [math]::Round(20 * $ratio)
    $status = Get-ScoreStatus -Ratio $ratio -PartialAllowed
    $evidenceLines = @(
        "Result: Average command prompt/script processing coverage across $checked loaded user hive(s): $($ratio.ToString('P0'))."
        "DisableCMD checks:"
    ) + $statusLines.ToArray()

    New-CheckResult `
        -Id 'QF-3' `
        -Name 'Block Command Prompt and command script processing' `
        -Weight 20 `
        -Earned $earned `
        -Status $status `
        -Evidence ($evidenceLines -join [Environment]::NewLine) `
        -Recommendations @('Enable Prevent access to the command prompt and set DisableCMD to 1 so command script processing is disabled also.')
}

function Get-DisallowRunEntries {
    param([Parameter(Mandatory)] [string]$HiveRoot)

    $entries = New-Object 'System.Collections.Generic.List[string]'
    $keyPath = Join-Path $HiveRoot 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun'

    if (Test-RegKey -Path $keyPath) {
        $props = Get-ItemProperty -LiteralPath $keyPath
        foreach ($property in $props.PSObject.Properties) {
            if ($property.Name -notmatch '^PS') {
                [void]$entries.Add([string]$property.Value)
            }
        }
    }

    return @($entries.ToArray())
}

function Test-HighRiskBinariesBlocked {
    param([Parameter(Mandatory)] [object[]]$Hives)

    $checked = 0
    $scoreSum = 0
    $details = New-Object 'System.Collections.Generic.List[string]'
    $binaryLines = New-Object 'System.Collections.Generic.List[string]'

    foreach ($hive in $Hives) {
        $explorerPath = Join-Path $hive.Root 'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer'
        $enabled = (Get-RegValue -Path $explorerPath -Name 'DisallowRun') -eq 1
        $entries = @(Get-DisallowRunEntries -HiveRoot $hive.Root)
        $normalized = New-Object 'System.Collections.Generic.HashSet[string]' ([System.StringComparer]::OrdinalIgnoreCase)
        foreach ($entry in $entries) {
            if ($entry) {
                [void]$normalized.Add($entry)
            }
        }

        $missing = New-Object 'System.Collections.Generic.List[string]'
        foreach ($binary in $RequiredBinaries) {
            if (-not $normalized.Contains($binary)) {
                [void]$missing.Add($binary)
            }
        }

        $presentCount = $RequiredBinaries.Count - $missing.Count
        $ratio = if ($enabled) { $presentCount / $RequiredBinaries.Count } else { 0 }
        $enabledBadge = if ($enabled) { '[TRUE]' } else { '[FALSE]' }

        $checked++
        $scoreSum += $ratio
        [void]$details.Add("$($hive.Sid): DisallowRun='$enabled', present=$presentCount/$($RequiredBinaries.Count), missing='$($missing.ToArray() -join ', ')'")
        [void]$binaryLines.Add("- $($hive.Sid) DisallowRun $enabledBadge present=$presentCount/$($RequiredBinaries.Count)")

        foreach ($binary in $RequiredBinaries) {
            $isBlocked = $enabled -and $normalized.Contains($binary)
            $binaryBadge = if ($isBlocked) { '[TRUE]' } else { '[FALSE]' }
            [void]$binaryLines.Add("  - $binary $binaryBadge")
        }
    }

    $overallRatio = if ($checked -gt 0) { $scoreSum / $checked } else { 0 }
    $earned = [math]::Round(30 * $overallRatio)
    $status = Get-ScoreStatus -Ratio $overallRatio -PartialAllowed
    $evidenceLines = @(
        "Result: Average binary block coverage across $checked loaded user hive(s): $($overallRatio.ToString('P0'))."
        "Binary checks:"
    ) + $binaryLines.ToArray() + @(
        "Raw registry summary: $($details.ToArray() -join '; ')"
    )

    New-CheckResult `
        -Id 'QF-4' `
        -Name 'Block minimum high-risk binaries' `
        -Weight 30 `
        -Earned $earned `
        -Status $status `
        -Evidence ($evidenceLines -join [Environment]::NewLine) `
        -Recommendations @("Enable Don't run specified Windows applications and add: $($RequiredBinaries -join ', ').")
}

function Get-LocalBrowserExtensionEvidence {
    param(
        [Parameter(Mandatory)] [string]$Browser,
        [Parameter(Mandatory)] [string[]]$ExtensionIds,
        [Parameter(Mandatory)] [string[]]$ExpectedNames,
        [Parameter(Mandatory)] [object[]]$UserFolders
    )

    $relativeRoot = switch ($Browser) {
        'Edge' { 'AppData\Local\Microsoft\Edge\User Data' }
        'Chrome' { 'AppData\Local\Google\Chrome\User Data' }
        'Firefox' { 'AppData\Roaming\Mozilla\Firefox\Profiles' }
    }

    $installEvidence = New-Object 'System.Collections.Generic.List[string]'

    foreach ($userFolder in $UserFolders) {
        $browserDataRoot = Join-Path $userFolder.FullName $relativeRoot
        if (-not (Test-Path -LiteralPath $browserDataRoot)) {
            continue
        }

        if ($Browser -eq 'Firefox') {
            $profiles = @(Get-ChildItem -LiteralPath $browserDataRoot -Directory -ErrorAction SilentlyContinue)
            foreach ($profile in $profiles) {
                $extensionsJsonPath = Join-Path $profile.FullName 'extensions.json'
                if (Test-Path -LiteralPath $extensionsJsonPath) {
                    $extensionsJson = Get-Content -LiteralPath $extensionsJsonPath -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction SilentlyContinue
                    foreach ($addon in @($extensionsJson.addons)) {
                        $addonId = [string]$addon.id
                        $addonName = [string]$addon.defaultLocale.name
                        if (-not $addonName) {
                            $addonName = [string]$addon.name
                        }

                        $idMatch = $ExtensionIds -contains $addonId
                        $nameMatch = @($ExpectedNames | Where-Object { $addonName -match [regex]::Escape($_) }).Count -gt 0
                        if ($idMatch -or $nameMatch) {
                            $versionText = if ($addon.version) { [string]$addon.version } else { 'version not recorded' }
                            $matchText = if ($idMatch) { 'id' } else { "name:$addonName" }
                            [void]$installEvidence.Add("$($userFolder.Name)\$($profile.Name):${addonId}:${versionText}:$matchText")
                        }
                    }
                }

                $extensionsRoot = Join-Path $profile.FullName 'extensions'
                if (Test-Path -LiteralPath $extensionsRoot) {
                    $extensionFiles = @(Get-ChildItem -LiteralPath $extensionsRoot -File -ErrorAction SilentlyContinue)
                    foreach ($extensionFile in $extensionFiles) {
                        $fileBaseName = [System.IO.Path]::GetFileNameWithoutExtension($extensionFile.Name)
                        if (($ExtensionIds -contains $extensionFile.Name) -or ($ExtensionIds -contains $fileBaseName)) {
                            [void]$installEvidence.Add("$($userFolder.Name)\$($profile.Name):$($extensionFile.Name):file:id")
                        }
                    }
                }
            }

            continue
        }

        $profiles = @(Get-ChildItem -LiteralPath $browserDataRoot -Directory -ErrorAction SilentlyContinue)
        foreach ($profile in $profiles) {
            $extensionsRoot = Join-Path $profile.FullName 'Extensions'
            if (-not (Test-Path -LiteralPath $extensionsRoot)) {
                continue
            }

            $extensionFolders = @(Get-ChildItem -LiteralPath $extensionsRoot -Directory -ErrorAction SilentlyContinue)
            foreach ($extensionFolder in $extensionFolders) {
                $idMatch = $ExtensionIds -contains $extensionFolder.Name
                $nameMatch = $false
                $matchedName = $null
                $versions = @(Get-ChildItem -LiteralPath $extensionFolder.FullName -Directory -ErrorAction SilentlyContinue)

                if (-not $idMatch) {
                    foreach ($version in $versions) {
                        $manifestPath = Join-Path $version.FullName 'manifest.json'
                        if (-not (Test-Path -LiteralPath $manifestPath)) {
                            continue
                        }

                        $manifestText = Get-Content -LiteralPath $manifestPath -Raw -ErrorAction SilentlyContinue
                        foreach ($expectedName in $ExpectedNames) {
                            if ($manifestText -match [regex]::Escape($expectedName)) {
                                $nameMatch = $true
                                $matchedName = $expectedName
                                break
                            }
                        }

                        if ($nameMatch) {
                            break
                        }

                        $localeFolders = @(Get-ChildItem -LiteralPath (Join-Path $version.FullName '_locales') -Directory -ErrorAction SilentlyContinue)
                        foreach ($localeFolder in $localeFolders) {
                            $messagesPath = Join-Path $localeFolder.FullName 'messages.json'
                            if (-not (Test-Path -LiteralPath $messagesPath)) {
                                continue
                            }

                            $messagesText = Get-Content -LiteralPath $messagesPath -Raw -ErrorAction SilentlyContinue
                            foreach ($expectedName in $ExpectedNames) {
                                if ($messagesText -match [regex]::Escape($expectedName)) {
                                    $nameMatch = $true
                                    $matchedName = $expectedName
                                    break
                                }
                            }

                            if ($nameMatch) {
                                break
                            }
                        }

                        if ($nameMatch) {
                            break
                        }
                    }
                }

                if ($idMatch -or $nameMatch) {
                    $versionNames = @($versions | Select-Object -ExpandProperty Name)
                    $versionText = if ($versionNames.Count -gt 0) { $versionNames -join ',' } else { 'version folder not readable' }
                    $matchText = if ($idMatch) { 'id' } else { "name:$matchedName" }
                    [void]$installEvidence.Add("$($userFolder.Name)\$($profile.Name):$($extensionFolder.Name):${versionText}:$matchText")
                }
            }
        }
    }

    return @($installEvidence.ToArray())
}

function Test-BrowserExtensionInstalled {
    param([Parameter(Mandatory)] [object[]]$UserFolders)

    $browserResults = @{}
    $browserLines = New-Object 'System.Collections.Generic.List[string]'
    $scopedBrowsers = New-Object 'System.Collections.Generic.List[string]'
    $browserOrder = @('Edge', 'Chrome', 'Firefox')

    foreach ($browser in $browserOrder) {
        if (-not (Test-BrowserInstalled -Browser $browser)) {
            [void]$browserLines.Add("- $browser [SKIPPED] Browser not installed")
            [void]$browserLines.Add("  - Plugin [SKIPPED] Browser not installed")
            continue
        }

        [void]$scopedBrowsers.Add($browser)
        $expectedIds = @($BrowserExtensions[$browser].Ids)
        $expectedNames = @($BrowserExtensions[$browser].Names)
        $localInstalls = @(Get-LocalBrowserExtensionEvidence -Browser $browser -ExtensionIds $expectedIds -ExpectedNames $expectedNames -UserFolders $UserFolders)
        $found = $localInstalls.Count -gt 0

        $browserResults[$browser] = $found
        $pluginBadge = if ($found) { '[TRUE]' } else { '[FALSE]' }
        $profileText = if ($localInstalls.Count -gt 0) { $localInstalls -join ', ' } else { 'none' }
        [void]$browserLines.Add("- $browser [TRUE]")
        [void]$browserLines.Add("  - Plugin $pluginBadge localProfiles=$profileText")
    }

    $passed = @($browserResults.Values | Where-Object { $_ }).Count
    $targetCount = $scopedBrowsers.Count
    $ratio = if ($targetCount -gt 0) { $passed / $targetCount } else { 0 }
    $earned = [math]::Round(15 * $ratio)
    $status = Get-ScoreStatus -Ratio $ratio -PartialAllowed
    $evidenceLines = @(
        "Result: $passed/$targetCount in-scope browser target extension(s) installed."
        "In-scope browsers:"
    ) + @($scopedBrowsers.ToArray() | ForEach-Object { "- $_" }) + @(
        "Browser checks:"
    ) + $browserLines.ToArray()

    New-CheckResult `
        -Id 'QF-5' `
        -Name 'Detect uBlock Origin Lite or uBlock Origin in Edge/Chrome/Firefox' `
        -Weight 15 `
        -Earned $earned `
        -Status $status `
        -Evidence ($evidenceLines -join [Environment]::NewLine) `
        -Recommendations @()
}

function Get-InformationalChecks {
    $checks = New-Object 'System.Collections.Generic.List[object]'

    $wdacPolicyPath = 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy'
    $wdacEnabled = Test-RegKey -Path $wdacPolicyPath
    [void]$checks.Add([pscustomobject]@{
        Name     = 'WDAC policy registry presence'
        Status   = if ($wdacEnabled) { 'Observed' } else { 'Not observed' }
        Evidence = $wdacPolicyPath
    })

    $appLockerPath = 'HKLM:\Software\Policies\Microsoft\Windows\SrpV2'
    $appLockerEnabled = Test-RegKey -Path $appLockerPath
    [void]$checks.Add([pscustomobject]@{
        Name     = 'AppLocker policy registry presence'
        Status   = if ($appLockerEnabled) { 'Observed' } else { 'Not observed' }
        Evidence = $appLockerPath
    })

    $asrPath = 'HKLM:\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules'
    $asrEnabled = Test-RegKey -Path $asrPath
    [void]$checks.Add([pscustomobject]@{
        Name     = 'Defender ASR policy registry presence'
        Status   = if ($asrEnabled) { 'Observed' } else { 'Not observed' }
        Evidence = $asrPath
    })

    return @($checks.ToArray())
}

function Get-Rating {
    param([Parameter(Mandatory)] [int]$Score)

    if ($Score -ge 90) { return 'Excellent quickfix coverage' }
    if ($Score -ge 75) { return 'Good quickfix coverage' }
    if ($Score -ge 50) { return 'Moderate quickfix coverage' }
    if ($Score -ge 25) { return 'Low quickfix coverage' }
    return 'Very low quickfix coverage'
}

$loadedUserHives = @(Get-LoadedUserHives)
$localUserFolders = @(Get-LocalUserFolders)

$results = @(
    Test-DisabledHotKeys -Hives $loadedUserHives
    Test-RemoveRunMenu -Hives $loadedUserHives
    Test-CommandPromptBlocked -Hives $loadedUserHives
    Test-HighRiskBinariesBlocked -Hives $loadedUserHives
    Test-BrowserExtensionInstalled -UserFolders $localUserFolders
)

$totalScore = [int]($results | Measure-Object -Property Earned -Sum).Sum
$maxScore = [int]($results | Measure-Object -Property Weight -Sum).Sum
$rating = Get-Rating -Score $totalScore
$runTimestamp = Get-Date

$report = [pscustomobject]@{
    ComputerName        = $env:COMPUTERNAME
    User                = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    Timestamp           = $runTimestamp.ToString('s')
    OS                  = Get-OSCaption
    Score               = $totalScore
    MaxScore            = $maxScore
    Percentage          = [math]::Round(($totalScore / $maxScore) * 100, 0)
    Rating              = $rating
    Checks              = $results
    InformationalChecks = if ($IncludeInformationalChecks) { @(Get-InformationalChecks) } else { @() }
}

Write-ReportLine ''
Write-ReportLine '============================================================' -ForegroundColor DarkCyan
Write-ReportLine ' ClickFix Quickfix Protection Score' -ForegroundColor Cyan
Write-ReportLine '============================================================' -ForegroundColor DarkCyan
Write-ReportLine (' Computer : {0}' -f $report.ComputerName)
Write-ReportLine (' User     : {0}' -f $report.User)
Write-ReportLine (' OS       : {0}' -f $report.OS)
Write-ReportLine (' Score    : {0}/{1} ({2}%) {3}' -f $report.Score, $report.MaxScore, $report.Percentage, (Get-ScoreBar -Percentage $report.Percentage))
Write-ReportLine (' Rating   : {0}' -f $report.Rating)
Write-ReportLine '============================================================' -ForegroundColor DarkCyan
Write-ReportLine ''

foreach ($check in $results) {
    $color = switch ($check.Status) {
        'Pass' { 'Green' }
        'Partial' { 'Yellow' }
        default { 'Red' }
    }
    $badge = Get-CheckBadge -Status $check.Status

    Write-ReportLine ('{0,-9} {1,-5} {2}/{3}  {4}' -f $badge, $check.Id, $check.Earned, $check.Weight, $check.Name) -ForegroundColor $color
    $evidenceLines = @(([string]$check.Evidence) -split "`r?`n")
    if ($evidenceLines.Count -gt 1) {
        Write-ReportLine '          Evidence:'
        foreach ($evidenceLine in $evidenceLines) {
            Write-StatusBadgeLine -Prefix '                    ' -Text $evidenceLine
        }
    } else {
        Write-StatusBadgeLine -Prefix '          Evidence: ' -Text $evidenceLines[0]
    }

    if ($check.Status -ne 'Pass') {
        foreach ($recommendation in $check.Recommendations) {
            Write-ReportLine ('          Fix: {0}' -f $recommendation)
        }
    }

    Write-ReportLine ''
}

if ($IncludeInformationalChecks) {
    Write-ReportLine 'Informational long-term hardening signals' -ForegroundColor Cyan
    foreach ($check in $report.InformationalChecks) {
        Write-ReportLine ('- {0}: {1} ({2})' -f $check.Name, $check.Status, $check.Evidence)
    }
    Write-ReportLine ''
}

if ($JsonPath) {
    $json = $report | ConvertTo-Json -Depth 6
    Set-Content -LiteralPath $JsonPath -Value $json -Encoding UTF8
    Write-ReportLine ('JSON report written to: {0}' -f (Resolve-Path -LiteralPath $JsonPath).Path) -ForegroundColor Cyan
}

$textOutputDirectory = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
$textOutputName = 'ClickFix-Protection-Score-{0}.txt' -f $runTimestamp.ToString('yyyyMMdd-HHmmss')
$textOutputPath = Join-Path $textOutputDirectory $textOutputName
Write-ReportLine ('Text report written to: {0}' -f $textOutputPath) -ForegroundColor Cyan
Set-Content -LiteralPath $textOutputPath -Value $script:TextOutputLines -Encoding UTF8

exit $(if ($totalScore -ge 75) { 0 } else { 1 })
