# ⚡ ClickFix Quickfix Guide - Intune

This guide provides an **Intune-based quickfix approach** to reduce the risk of ClickFix-style attacks.

The goal is to quickly limit commonly abused execution paths for standard users by using Microsoft Intune policies and Intune-deployed PowerShell scripts.

> ⚠️ **Note:** This is a quickfix. It can reduce immediate exposure, but it does not replace structural **Application Control** such as **WDAC**, **AppLocker**, or **ThreatLocker**.
>
> Application Control is also recommended in **CIS Controls v8/v8.1 – Control 2, Safeguard 2.5: Allowlist Authorized Software**.
>
> In practice, this means only approved applications, scripts, binaries, and tools are allowed to run.

---

## ✅ Quickfix Overview

| Quickfix ID | Control | Purpose | Impact Level | Impact |
|---|---|---|---|---|
| [QF-1](https://github.com/Innovative-010/clickfix-defense-toolkit-private/blob/main/clickfix-quickfix-guide-intune.md#qf-1-%EF%B8%8F-block-common-windows-shortcuts) | ⌨️ Block common Windows shortcuts | Block `Win + R`, `Win + E`, and `Win + X` = `(REX)` | Low | May impact users who rely on Windows shortcuts for daily workflows |
| [QF-2](https://github.com/Innovative-010/clickfix-defense-toolkit-private/blob/main/clickfix-quickfix-guide-intune.md#qf-2--remove-run-menu-from-start-menu) | 🚫 Remove Run menu | Reduce access to the Run dialog | Medium | Users can no longer use Run for quick commands or UNC paths |
| [QF-3](https://github.com/Innovative-010/clickfix-defense-toolkit-private/blob/main/clickfix-quickfix-guide-intune.md#qf-3-%EF%B8%8F-block-command-prompt) | 🖥️ Block Command Prompt | Prevent command execution and script processing | High | May impact troubleshooting, legacy scripts, and admin tasks |
| [QF-4](https://github.com/Innovative-010/clickfix-defense-toolkit-private/blob/main/clickfix-quickfix-guide-intune.md#qf-4--block-minimum-high-risk-binaries) | 🧱 Block high-risk binaries | Restrict commonly abused Windows binaries and LOLBins | High | Can impact legitimate tools, installers, scripts, and support workflows |
| [QF-5](https://github.com/Innovative-010/clickfix-defense-toolkit-private/blob/main/clickfix-quickfix-guide-intune.md#qf-5--deploy-ublock-origin-lite) | 🧩 Deploy uBlock Origin Lite | Reduce exposure to malicious ads, fake CAPTCHA pages, redirects, and ClickFix landing pages | Low | May block some website elements or tracking-dependent functionality |


---

## QF-1 ⌨️ Block Common Windows Shortcuts

ClickFix attacks often instruct users to use Windows shortcuts to quickly open execution paths, file locations, command dialogs, or system menus.

This quickfix helps reduce abuse of commonly used Windows hotkeys by configuring the `DisabledHotKeys` registry value for user profiles.

---

### Recommended Action

Block commonly abused Windows shortcuts for standard users.

| Shortcut | Risk |
|---|---|
| `Win + R` | Opens the Run dialog, which can be abused to paste and execute malicious commands |
| `Win + E` | Opens File Explorer, which can be used to access downloads, scripts, mapped drives, or user-writable locations |
| `Win + X` | Opens the Quick Link menu, which provides access to system and administrative tools |

---

### Recommended Intune Deployment

Deploy this control using **Intune Remediations**.

You can find it here: https://intune.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesMenu/~/scripts

This provides a better operational approach because Intune can:

| Function | Purpose |
|---|---|
| Detection script | Checks whether the required shortcut restrictions are configured |
| Remediation script | Applies or repairs the required registry value |
| Reporting | Shows which devices are compliant or remediated |
| Continuous validation | Helps detect and repair configuration drift |

---

### Registry Configuration

Registry path per user:

```powershell
HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced
```

Registry value:

| Value name | Type | Required data |
|---|---|---|
| `DisabledHotKeys` | `REG_SZ` | `REX` |

This configuration blocks the following Windows hotkeys:

| Value | Shortcut |
|---|---|
| `R` | `Win + R` |
| `E` | `Win + E` |
| `X` | `Win + X` |

---

### Intune Remediation Settings

Recommended Intune configuration:

| Setting | Recommended value |
|---|---|
| Run this script using the logged-on credentials | `No` |
| Run script in 64-bit PowerShell | `Yes` |
| Enforce script signature check | Based on your organization policy |
| Assignment | Standard users or pilot group first |
| Schedule | Daily or during pilot/testing based on your rollout approach |

This script is designed to run in **SYSTEM context** and apply the setting across detected user profiles.

Because `DisabledHotKeys` is a user-based setting, users may need to **sign out and sign in again** before the shortcut restrictions are fully active.

---

### Detection Logic

The detection script validates whether the required `DisabledHotKeys` value is configured with `REX` for detected user profiles.

[Detection script - Disable REX shortcuts](./Mitigation/Intune/DisableShortcuts/Detection_REX_AllUsers_SystemContext_v1.ps1)

---

### Remediation Logic

The remediation script creates or updates the `DisabledHotKeys` registry value when it is missing or incomplete.

[Remediation script - Disable REX shortcuts](./Mitigation/Intune/DisableShortcuts/Remediation_REX_AllUsers_SystemContext_v1.ps1)

---

### Expected Result

Users should not be able to use the following shortcuts after the setting is applied:

| Shortcut | Expected result |
|---|---|
| `Win + R` | Run dialog should not open |
| `Win + E` | File Explorer should not open through the shortcut |
| `Win + X` | Quick Link menu should not open |

> ⚠️ Blocking `Win + E` can impact normal user experience. Validate this carefully before broad deployment.

---

## QF-2 🚫 Remove Run Menu from Start Menu

ClickFix attacks often rely on users opening the Run dialog and pasting a command.

Blocking `Win + R` helps, but removing the Run menu from the Start Menu reduces another common access path.

### Recommended Action

Remove the Run menu from the Start Menu for standard users.

---

### Intune Configuration

Configure this setting in Microsoft Intune using Administrative Templates:

```text
User Configuration > Administrative Templates > Start Menu and Taskbar > Remove Run menu from Start Menu (User)
```

Set the policy to:

```text
Enabled
```

### Screenshot
<img width="1122" height="324" alt="image" src="https://github.com/user-attachments/assets/2bb3e002-e922-4c9e-af0b-f487562c87f8" />


### Expected Result

Standard users should no longer be able to access Run from the Start Menu.
<img width="1074" height="926" alt="image" src="https://github.com/user-attachments/assets/47b3ed0c-f344-46e8-b5c7-929c6c53ccc8" />

---

## QF-3 🖥️ Block Command Prompt

Command Prompt can be abused to execute commands, launch scripts, start other binaries, or manually run commands provided during ClickFix-style social engineering attacks.

### Recommended Action

Block Command Prompt for standard users where it is not required for normal business operations.

---

### Intune Configuration

Configure this setting in Microsoft Intune using Administrative Templates:

```text
User Configuration > Administrative Templates > System > Prevent access to the command prompt (User)
```

Set the policy to:

```text
Enabled
```

Recommended option:

```text
Disable command prompt script processing also: Yes
```

This helps prevent users from opening `cmd.exe` and can also restrict command script processing such as `.bat` and `.cmd` files.

### Expected Result

Standard users should not be able to open Command Prompt or execute `.bat` and `.cmd` scripts.

---

## QF-4 🧱 Block Minimum High-Risk Binaries

Built-in Windows binaries can be abused to execute commands, launch scripts, or perform ClickFix-style execution.

As an Intune-based quickfix, the minimum recommended approach is to block the most commonly abused executables for standard users using the **Don't run specified Windows applications** policy.

> ⚠️ This is a quickfix control. It reduces exposure, but it is not a replacement for Application Control such as WDAC, AppLocker, or ThreatLocker.

---

### Recommended Action

Block the minimum set of high-risk executables that are commonly abused for:

- Command execution
- Script execution
- PowerShell abuse
- Windows Terminal access
- HTA/script abuse

---

### Intune Configuration

Configure this setting in Microsoft Intune using Administrative Templates:

```text
User Configuration > Administrative Templates > System > Don't run specified Windows applications
```

Set the policy to:

```text
Enabled
```

Then configure:

```text
List of disallowed applications
```

Add the following executables:

| Application | Purpose |
|---|---|
| `powershell.exe` | Blocks Windows PowerShell |
| `pwsh.exe` | Blocks PowerShell 7 / PowerShell Core |
| `powershell_ise.exe` | Blocks PowerShell ISE |
| `cmd.exe` | Blocks Command Prompt |
| `wscript.exe` | Blocks Windows Script Host GUI execution |
| `cscript.exe` | Blocks Windows Script Host CLI execution |
| `mshta.exe` | Blocks HTA abuse |
| `WindowsTerminal.exe` | Blocks Windows Terminal |
| `wt.exe` | Blocks Windows Terminal launcher |

---

### Expected Result

Standard users should not be able to launch the specified executables through common user interaction paths such as:

- Start Menu
- Search
- File Explorer
- Run dialog
- Shortcuts
- Double-click execution

This reduces the risk of users executing malicious commands or scripts as part of ClickFix-style social engineering attacks.

---

### Important Note

This is the **minimum recommended set** for reducing common ClickFix execution paths.

It does not fully protect against:

- Renamed binaries
- Alternative LOLBins
- File download utilities
- DLL execution abuse
- Advanced bypass techniques
- Unmanaged or user-installed tools

For stronger coverage, consider expanding the list after testing business impact.

---

## QF-5 🧩 Deploy uBlock Origin Lite

ClickFix attacks can be delivered through malicious ads, redirects, fake CAPTCHA pages, and scam landing pages.

Deploying **uBlock Origin Lite** as a managed browser extension helps reduce user exposure before they reach a ClickFix page.

---

### Recommended Action

Force-install **uBlock Origin Lite** for standard users.

| Browser | Extension ID |
|---|---|
| Microsoft Edge | `cimighlppcgcoapaliogpjjdehbnofhn` |
| Google Chrome | `ddkjiahejlhfcafbddmgiahcphecmpfh` |

---

### Microsoft Edge - Intune Value

```text
cimighlppcgcoapaliogpjjdehbnofhn
```

---

### Google Chrome - Intune Value

```text
ddkjiahejlhfcafbddmgiahcphecmpfh
```

---

### Intune Configuration

Configure the browser extension policy using the **Settings Catalog**.

Recommended configuration:

| Setting | Recommended value |
|---|---|
| Control which extensions are installed silently | `Enabled` |
| Extension/App IDs and update URLs to be silently installed | Add the Edge and/or Chrome value above |
| Allow specific extensions to be installed | `Enabled` |
| Extension IDs to exempt from the block list | Add the Edge and/or Chrome extension ID |

---

### Expected Result

uBlock Origin Lite is installed automatically and users have reduced exposure to:

- Malicious ads
- Fake CAPTCHA pages
- Scam redirects
- ClickFix landing pages

---

### Important Note

If your organization blocks browser extensions by default, make sure the uBlock Origin Lite extension IDs are also added to the allowlist or exemption list.

---

🧪 Validate the Quickfix

A mitigation is only useful if it actually works.

Test the controls with a standard user account before broad deployment.

| Test | Expected Result |
|---|---|
| Press `Win + R` | Run dialog is blocked |
| Press `Win + E` | File Explorer shortcut is blocked |
| Press `Win + X` | Admin menu is blocked or restricted |
| Open Run from Start Menu | Run option is unavailable |
| Start `powershell.exe` | Execution is blocked |
| Start `pwsh.exe` | Execution is blocked |
| Start `powershell_ise.exe` | Execution is blocked |
| Start `cmd.exe` | Execution is blocked |
| Start `wscript.exe` | Execution is blocked |
| Start `cscript.exe` | Execution is blocked |
| Start `mshta.exe` | Execution is blocked |
| Start `WindowsTerminal.exe` | Execution is blocked |
| Start `wt.exe` | Execution is blocked |

Document the outcome and review business impact.

---

## ⚠️ Known Limitations

This quickfix does not fully prevent ClickFix attacks.

Limitations:

- Blocks common shortcuts and known executable names only. New attack paths may appear over time, so implementing the long-term fix is still strongly recommended.
- Does not provide strong application allowlisting. For stronger control, use the long-term fix.
- May be bypassed by renamed binaries or alternative execution methods. To help detect copied or impersonated system tools, enable the ASR rule in Block mode: **Block use of copied or impersonated system tools**.
- Can impact legitimate business workflows. Test carefully before broad deployment.

---

## 🛡️ Recommended Long-Term Fix

For long-term protection, implement:

- **Application Control** – Implement WDAC, AppLocker, ThreatLocker, or another allowlisting solution to control what is allowed to execute.
- **Least Privilege** – Reduce unnecessary admin rights and use controls such as LAPS for local administrator password management.
- **Endpoint Hardening** – Apply CIS Benchmarks, remove unnecessary Windows apps, and enforce Attack Surface Reduction rules.
- **Detection and Monitoring** – Monitor suspicious execution paths, blocked attempts, and abuse of built-in Windows tools.
- **Continuous Validation** – Regularly (pen)test whether controls are working as expected and improve them where needed.

---

## 📌 Summary

This Intune-based quickfix helps reduce immediate exposure to ClickFix-style attacks by limiting the most commonly abused user execution paths, including Windows shortcuts, Run access, Command Prompt, scripting engines, Windows Terminal, and high-risk executables.

These controls should be tested, monitored, and treated as temporary mitigations. They reduce risk, but do not provide complete protection.

For long-term protection, implement Application Control, least privilege, endpoint hardening, detection and monitoring, and continuous validation.
