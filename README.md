# 🛡️ ClickFix Defense Toolkit 

This repository provides practical tools, detections, mitigations, tests and awareness material to help organizations defend against ClickFix-style social engineering attacks.

ClickFix is a dangerous social engineering attack that manipulates your clipboard to execute malicious code. When you copy what appears to be legitimate text (like a CAPTCHA solution or error fix), the website secretly replaces your clipboard content with harmful PowerShell scripts, batch commands, or other malicious code. When you paste and execute it, you unknowingly install malware on your system.

<img width="1530" height="791" alt="image" src="https://github.com/user-attachments/assets/e04baf2d-c48f-44bf-ab2c-61c5700b79ff" />


## ⚡ Fast Approach

Quick guides and validation scripts to block and verify commonly abused ClickFix execution paths.

| Resource | Purpose |
|---|---|
| [ClickFix Quickfix Guide - Intune](./clickfix-quickfix-guide-intune.md) | Intune-based quickfix guidance |
| [ClickFix Protection Score Powershell Script](./ClickFix-Protection-Score.ps1) | Checks whether each quickfix step is correctly applied |

> ⚠️ Quickfixes reduce immediate exposure, but should be tested, monitored, and treated as temporary mitigations. The detection script helps verify whether each quickfix control is actually in place.

---

## 🛡️ Long-Term Approach

For long-term protection, implement:

- **Application Control** – Implement WDAC, AppLocker, ThreatLocker, or another allowlisting solution to control what is allowed to execute.
- **Least Privilege** – Reduce unnecessary admin rights and use controls such as LAPS for local administrator password management.
- **Endpoint Hardening** – Apply CIS Benchmarks, remove unnecessary Windows apps, and enforce Attack Surface Reduction rules.
- **Detection and Monitoring** – Monitor suspicious execution paths, blocked attempts, and abuse of built-in Windows tools.
- **Continuous Validation** – Regularly (pen)test whether controls are working as expected and improve them where needed.

## 📂 Categories

This section provides the foundation for the ClickFix Quick Fix Implementation Guide. It gives organizations a structured overview of practical tools, mitigations, detections, tests, and research resources to help reduce exposure to ClickFix-style attacks.

---

### 🧰 Tools

Practical tools and solutions that can help prevent or reduce ClickFix attack execution.

| Name | Website | Notes |
|---|---|---|
| Windows Defender Application Control | https://learn.microsoft.com/en-us/intune/configmgr/protect/deploy-use/use-device-guard-with-configuration-manager | Microsoft application control solution to restrict unauthorized code execution. |
| App Control for Business and AppLocker | https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/appcontrol-and-applocker-overview | Microsoft controls for application allowlisting and execution restrictions. |
| ThreatLocker | https://www.threatlocker.com | Application allowlisting and endpoint control platform. |
| uBlock Origin | https://ublockorigin.com/ | Browser ad/content blocker that may reduce exposure to malicious ads and redirects. |

---

### 🔒 Mitigations

Basic security measures to reduce ClickFix-related risks.

| Name | Website | Notes |
|---|---|---|
| Block CMD, PowerShell and Regedit with Intune | https://call4cloud.nl/block-cmd-powershell-regedit-intune/ | Practical Intune-based approach to restrict commonly abused tools. |
| Prevent Access to Command Prompt using Intune | https://www.prajwaldesai.com/prevent-access-to-command-prompt-using-intune/ | Guide for blocking Command Prompt access through Intune policy. |
| ClickGrab Mitigations | https://mhaggis.github.io/ClickGrab/mitigations.html | Mitigation guidance focused on ClickFix-style techniques. |

---

### 🔍 Detections

Hunting queries and detection resources to identify ClickFix-related activity.

| Name | Website | Notes |
|---|---|---|
| ClickGrab Techniques | https://mhaggis.github.io/ClickGrab/techniques.html | Overview of ClickFix-related techniques and behaviors. |
| ClickGrab GitHub Repository | https://github.com/MHaggis/ClickGrab | Detection and research repository for ClickFix-style activity. |
| ClickFix FakeCaptcha Cloudflare | https://github.com/blwhit/ClickFix-FakeCaptcha-Cloudflare | Research and detection content related to fake CAPTCHA-style ClickFix campaigns. |

---

### 🧬 Tests

Safe test scenarios and simulation resources to validate ClickFix defenses.

| Name | Website | Notes |
|---|---|---|
| ClickFix Simulation Website | https://www.click-fix.nl | Simulation website to demonstrate and validate ClickFix awareness and defenses. |
| ClickFix Builder | https://github.com/drcrypterdotru/clickfix-builder | ClickFix builder resource. Use only in controlled and authorized test environments. |
| ClickFix Collection | https://clickfix.carsonww.com | Collected ClickFix domains, complete with before & after screenshots and the malicious clipboard commands attackers attempt to trick users into running. |

---

### 📰 News Articles / Blogs

Relevant articles, blogs, and research about ClickFix campaigns and social engineering techniques.

| Name | Website | Notes |
|---|---|---|
| The Hacker News - ClickFix Campaigns Expand Malware Delivery With New Loaders and Fake Update Lures | https://thehackernews.com/2026/06/clickfix-campaigns-expand-malware.html | ClickFix campaigns are evolving into advanced malware delivery operations. |
| Microsoft Security Blog - Think Before You ClickFix | https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/ | Microsoft analysis of the ClickFix social engineering technique. |

## 🎯 Goal

Help security teams reduce the risk of ClickFix attacks through layered defense, user awareness and continuous validation.

**Stay Safe! 🛡️ Your clipboard is more dangerous than you think.**
