
# Intune Remediation - Block Common Windows Shortcuts (REX)

This folder contains an Intune Remediation package to restrict commonly abused Windows shortcuts for all user profiles on a device.

The mitigation focuses on blocking the following shortcut keys:

| Shortcut | Description |
|---|---|
| `Win + R` | Opens the Run dialog |
| `Win + E` | Opens File Explorer |
| `Win + X` | Opens the Power User menu |

This control is intended as a **quickfix mitigation** for ClickFix-style attack scenarios where users are instructed to quickly open execution paths, administrative menus, or command entry points.

> This is not a replacement for a structural Application Control solution such as WDAC, AppLocker, or ThreatLocker.

---

## Files

| File | Purpose |
|---|---|
| `Detection_REX_AllUsers_SystemContext_v1.ps1` | Checks whether `DisabledHotkeys` contains `R`, `E`, and `X` for all relevant user profiles |
| `Remediation_REX_AllUsers_SystemContext_v1.ps1` | Applies or updates the `DisabledHotkeys` registry value for all relevant user profiles |

---

## What the scripts configure

The scripts validate and configure the following user-based registry value:

```text
HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced
DisabledHotkeys = REX
```

Because this is a per-user setting, the remediation is designed to run as **SYSTEM** and process multiple user hives.

---

## Scope

The scripts target:

- Existing real user profiles found under:

```text
HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList
```

- Loaded user hives under:

```text
HKEY_USERS
```

- Unloaded user hives by temporarily loading:

```text
NTUSER.DAT
```

- The Default User profile:

```text
C:\Users\Default\NTUSER.DAT
```

This ensures that both existing users and newly created users can receive the setting.

---

## Detection behavior

The detection script checks whether the `DisabledHotkeys` value contains all required letters:

```text
R
E
X
```

The device is reported as:

| Result | Meaning |
|---|---|
| Compliant | All checked profiles contain the required `REX` hotkeys |
| Non-compliant | One or more profiles are missing the required value |
| Non-compliant | A detection error occurred, so remediation can attempt repair |
| Not applicable | No user profiles with `NTUSER.DAT` were found |

The detection script exits with:

| Exit code | Meaning |
|---|---|
| `0` | Compliant / not applicable |
| `1` | Non-compliant / detection failed |

---

## Remediation behavior

The remediation script:

- Creates the required registry path if missing
- Preserves existing `DisabledHotkeys` values
- Merges missing required letters into the current value
- Ensures the final value contains `R`, `E`, and `X`
- Creates a backup value before changing the setting
- Processes existing, loaded, unloaded, and Default User profiles
- Writes local logging for troubleshooting

The backup value is stored as:

```text
DisabledHotkeys_Backup_ClickFix
```

The remediation is **idempotent**, meaning it can be safely run multiple times without continuously overwriting the same setting unnecessarily.

---

## Logging

The remediation script writes a local log file to:

```text
C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\ClickFix-REX-AllUsers-Remediation.log
```

If the log file grows larger than 1 MB, the script rotates it to:

```text
ClickFix-REX-AllUsers-Remediation.log.old
```

The Intune output is intentionally kept short. Use the local log for detailed troubleshooting.

---

## Recommended Intune Remediation settings

| Setting | Recommended value |
|---|---|
| Run this script using the logged-on credentials | `No` |
| Run script in 64-bit PowerShell | `Yes` |
| Enforce script signature check | `No` during pilot, `Yes` when scripts are signed |
| Detection script | `Detection_REX_AllUsers_SystemContext_v1.ps1` |
| Remediation script | `Remediation_REX_AllUsers_SystemContext_v1.ps1` |
| Assignment | Pilot group first |
| Schedule | Daily or according to your operational requirement |

> Important: These scripts are designed for **SYSTEM context**. Do not run them as the logged-on user if the goal is to remediate all user profiles on the device.

---

## Testing

For controlled testing, the remediation script contains an audit-only option:

```powershell
$AuditOnly = $false
```

Set this to:

```powershell
$AuditOnly = $true
```

to test the script logic without applying changes.

For Intune production remediation, keep it set to:

```powershell
$AuditOnly = $false
```

---

## Validation

After remediation, validate the setting for a user profile:

```powershell
Get-ItemProperty `
  -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" `
  -Name "DisabledHotkeys"
```

Expected result:

```text
DisabledHotkeys : REX
```

If the value already contained other disabled hotkeys, the script should preserve them and add the missing `R`, `E`, and `X` characters.

---

## Operational notes

- A user sign-out/sign-in or Explorer restart may be required before shortcut behavior changes are fully visible.
- Test with a pilot group before broad deployment.
- Confirm that blocking these shortcuts does not impact support workflows or business-critical user processes.
- This mitigation should be combined with stronger controls such as Application Control, Attack Surface Reduction rules, endpoint detection, and user awareness.

---
```
