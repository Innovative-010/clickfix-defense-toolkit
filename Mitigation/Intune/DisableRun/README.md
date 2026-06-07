# Disable Run Menu

This folder contains Intune remediation scripts to disable the Windows **Run menu / Run dialog**.

The goal is to reduce abuse of the Run dialog in ClickFix-style attacks, where users are instructed to open Run and execute malicious commands.

---

## Goal

Disable access to the Windows **Run menu / Run dialog** for standard users.

This helps reduce the risk of users launching commands through the Run interface.

| Feature | Risk |
|---|---|
| Run menu / Run dialog | Can be abused to paste and execute malicious commands |

---

## Scripts

| Script | Purpose |
|---|---|
| `Detect-DisableRun.ps1` | Detects if the Run menu is disabled |
| `Remediate-DisableRun.ps1` | Applies the required registry settings to disable the Run menu |

---

## What the remediation does

The remediation script applies the following machine-wide registry setting:

```powershell
HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer
NoRun = 1
```

It also creates an **Active Setup** entry to enforce the same setting for each user at logon:

```powershell
HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer
NoRun = 1
```

This ensures the Run menu setting is applied both at machine level and user level.

---

## Detection logic

The detection script checks if:

| Check | Expected value |
|---|---|
| `HKLM NoRun` | `1` |
| Active Setup key | Present |
| Active Setup `StubPath` | Present |
| Active Setup `Version` | Present |

If all checks are valid, the device is marked as compliant.

---

## Exit codes

| Exit code | Meaning |
|---|---|
| `0` | Compliant |
| `1` | Non-compliant or error |

---

## Intune configuration

Recommended Intune remediation settings:

| Setting | Recommended value |
|---|---|
| Run script in 64-bit PowerShell | Yes |
| Run this script using the logged-on credentials | No |
| Detection script | `Detect-DisableRun.ps1` |
| Remediation script | `Remediate-DisableRun.ps1` |
| Assignment | Pilot group first |
| Schedule | Daily or during testing based on your rollout approach |

---

## Important notes

Existing logged-on users may need to **sign out and sign in again** before the HKCU setting is applied through Active Setup.

The machine-wide `HKLM NoRun=1` setting is applied immediately by the remediation script.

This mitigation disables the **Run menu / Run dialog functionality**. It does not directly block keyboard shortcuts such as `Win + R`, `Win + E`, or `Win + X`.

---

## Validation

After remediation, validate the following registry value:

```powershell
Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRun"
```

Expected result:

```powershell
NoRun : 1
```

After user logon, validate the HKCU value:

```powershell
Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoRun"
```

Expected result:

```powershell
NoRun : 1
```

---
