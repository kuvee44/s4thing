# Windows Security Research Knowledge Base — Master Index
## Last Updated: 2026-04-22

> **Mission:** A curated, research-grade knowledge base for Windows security researchers — from OS internals foundations through elite-level vulnerability research. Every resource here was selected for technical depth, originality, and practical value for finding, analyzing, and exploiting Windows security bugs. This vault covers Local Privilege Escalation (LPE), sandbox escapes, kernel exploitation, and the full bug-hunting methodology pipeline.

---

## Navigation — Directory Tree

```
resource/
├── 00_index/                     ← YOU ARE HERE — master navigation
│   ├── MASTER_INDEX.md
│   ├── LEARNING_PATH.md
│   ├── TOP_100_MUST_READS.md
│   ├── RESEARCHERS_TO_FOLLOW.md
│   ├── GITHUB_TOP_REPOS.md
│   └── LABS_QUEUE.md
│
├── 01_foundations/               ← Windows internals, OS architecture, core concepts
├── 02_debugging_and_observability/← WinDbg, TTD, ProcMon, System Informer, ETW
├── 03_windows_security_model/    ← Tokens, ACLs, integrity levels, impersonation
├── 04_object_manager_namespace/  ← Object manager, symbolic links, directory objects
├── 05_rpc_com_alpc_namedpipes/   ← IPC mechanisms, COM security, ALPC
├── 06_filesystem_and_fileops/    ← NTFS, file operations, opportunistic locks
├── 07_services_installers_updaters/ ← Windows Installer, services, update mechanisms
├── 08_bug_classes/               ← Taxonomy of Windows LPE bug classes
├── 09_exploit_primitives/        ← Exploitation techniques and primitives
├── 10_kernel_win32k/             ← Kernel bugs, Win32k, driver exploitation
├── 11_patch_diff_and_root_cause/ ← BinDiff, patch analysis, incomplete fixes
├── 12_variant_hunting/           ← Methodology for finding bug variants
├── 13_cve_case_studies/          ← Detailed analyses of public CVEs
├── 14_blogs_and_researchers/     ← Researcher profiles, blog indexes
├── 15_github_and_code/           ← Key repos, PoCs, research tools
├── 16_talks_papers_slides/       ← Conference talks, academic papers
├── 17_labs_and_exercises/        ← Hands-on lab exercises
├── 18_reporting_and_bounty/      ← MSRC, ZDI, coordinated disclosure
└── 99_meta/                      ← Vault metadata, search logs, inclusion rules
```

---

## 01 — Foundations

| Title | Author | Difficulty | Tags |
|-------|--------|------------|------|
| Windows Internals Part 1 (7th Ed.) | Yosifovich, Ionescu, Russinovich, Solomon | Intermediate | `FOUNDATIONAL` `MUST-READ` `BOOK` |
| Windows Internals Part 2 (7th Ed.) | Yosifovich, Ionescu, Russinovich, Solomon | Intermediate-Advanced | `FOUNDATIONAL` `MUST-READ` `BOOK` |
| Windows Security Internals (1st Ed.) | James Forshaw | Advanced | `FOUNDATIONAL` `MUST-READ` `BOOK` `SECURITY` |
| Windows Kernel Programming (2nd Ed.) | Pavel Yosifovich | Intermediate | `FOUNDATIONAL` `BOOK` `KERNEL` |
| Rootkits: Subverting the Windows Kernel | Hoglund & Butler | Advanced | `HISTORICAL` `BOOK` `KERNEL` |
| The Art of Exploitation (Windows-relevant chapters) | Jon Erickson | Beginner-Intermediate | `FOUNDATIONAL` `BOOK` |
| Windows NT/2000 Native API Reference | Gary Nebbett | Advanced | `REFERENCE` `NTAPI` |
| Windows Undocumented Internals (Geoff Chappell) | Geoff Chappell | Advanced | `REFERENCE` `UNDOCUMENTED` |
| ReactOS Source Code | ReactOS Project | Intermediate | `REFERENCE` `SOURCE` |
| MSDN / Windows API Documentation | Microsoft | All | `REFERENCE` `OFFICIAL` |
| Windows Process and Thread Internals (blog series) | Alex Ionescu | Intermediate | `FOUNDATIONAL` `BLOG` |
| NT Insider Archives | OSR Online | Intermediate | `FOUNDATIONAL` `REFERENCE` `DRIVERS` |

---

## 02 — Debugging & Observability

| Title | Author | Difficulty | Tags |
|-------|--------|------------|------|
| WinDbg — Official Documentation | Microsoft | Intermediate | `REFERENCE` `OFFICIAL` |
| Time Travel Debugging (TTD) Overview | Microsoft Research / MSDN | Intermediate | `MUST-READ` `TTD` `TOOL` |
| WinDbg Preview — Getting Started | Microsoft | Beginner | `TOOL` `OFFICIAL` |
| WinDbg Cheat Sheet | Various community | Beginner-Intermediate | `REFERENCE` `CHEATSHEET` |
| Process Monitor (ProcMon) Documentation | Sysinternals / MSDN | Beginner | `TOOL` `OFFICIAL` |
| System Informer (formerly Process Hacker) | wj32, dmex | Intermediate | `TOOL` `OPEN-SOURCE` |
| Using ETW for Security Research | Various | Advanced | `ETW` `MONITORING` |
| Windows Performance Toolkit (WPR/WPA) | Microsoft | Intermediate | `TOOL` `PROFILING` |
| Debugging Windows with WinDbg (Pluralsight/MSDN) | Various | Intermediate | `TRAINING` |
| SilkETW — ETW collection for security | FuzzySecurity (b33f) | Intermediate | `TOOL` `ETW` `OPEN-SOURCE` |
| API Monitor by Rohitab | Rohitab | Beginner-Intermediate | `TOOL` `API-MONITORING` |
| Frida on Windows | Frida Project | Intermediate | `TOOL` `INSTRUMENTATION` |
| WinDbg: The Missing Manual (i.e., 0xbadc0de's posts) | Various bloggers | Intermediate | `BLOG` `REFERENCE` |

---

## 03 — Windows Security Model

| Title | Author | Difficulty | Tags |
|-------|--------|------------|------|
| Windows Security Internals Ch. 2–5 (Tokens) | James Forshaw | Advanced | `FOUNDATIONAL` `MUST-READ` |
| Windows Internals Part 1, Ch. 7 (Security) | Russinovich et al. | Intermediate | `FOUNDATIONAL` `MUST-READ` |
| Access Tokens in-depth (tiraniddo.dev) | James Forshaw | Advanced | `MUST-READ` `BLOG` |
| Integrity Levels and UAC | MSDN / Microsoft | Intermediate | `REFERENCE` `UAC` |
| Abusing Token Privileges for LPE | foxglovesecurity | Intermediate | `MUST-READ` `BLOG` `TOKEN` |
| Impersonation: A Security Perspective | Microsoft Security | Intermediate | `REFERENCE` `IMPERSONATION` |
| Named Pipe Impersonation | Various | Intermediate | `BLOG` `IMPERSONATION` |
| Windows Privilege Abuse: Audit, Detection & Defense | Palantir / blog | Advanced | `BLOG` `DETECTION` |
| NtObjectManager Documentation | James Forshaw (GitHub) | Advanced | `TOOL` `REFERENCE` `POWERSHELL` |
| AppContainer and Low-IL Sandbox Internals | Forshaw / MSDN | Advanced | `SANDBOX` `BLOG` |
| ACL, DACL, SACL — Security Descriptors In Depth | Microsoft / MSDN | Intermediate | `REFERENCE` `ACCESS-CONTROL` |
| Windows Authentication Architecture | Microsoft | Intermediate | `REFERENCE` `AUTH` |
| Credential Guard Internals | Alex Ionescu / others | Advanced | `BLOG` `LSASS` |
| LSASS Dumping Techniques | SpecterOps | Advanced | `OFFENSIVE` `BLOG` |
| SeDebugPrivilege and Its Implications | Various | Intermediate | `PRIVILEGE` `BLOG` |

---

## 04 — Object Manager & Namespace

| Title | Author | Difficulty | Tags |
|-------|--------|------------|------|
| Windows Object Manager Internals | Windows Internals Ch. 8 | Intermediate | `FOUNDATIONAL` |
| Symbolic Links in Windows (tiraniddo.dev) | James Forshaw | Advanced | `MUST-READ` `SYMLINK` `BLOG` |
| Directory Object Security and TOKTOU | Forshaw / Project Zero | Advanced | `MUST-READ` `BLOG` |
| Object Namespace Attacks (DEF CON 25) | James Forshaw | Advanced | `MUST-READ` `TALK` |
| NtObjectManager — object namespace tooling | James Forshaw | Advanced | `TOOL` `POWERSHELL` |
| Object Manager Symbolic Links as Exploit Primitive | Various | Advanced | `EXPLOIT-PRIMITIVE` |
| Device Map / Drive Letter Redirection | Forshaw / Zero | Advanced | `SYMLINK` `BLOG` |
| NTFS Junction Points and Reparse Points | Microsoft / MSDN | Intermediate | `REFERENCE` `JUNCTION` |
| Oplocks (Opportunistic Locks) Internals | MSDN / Forshaw | Advanced | `OPLOCK` `REFERENCE` |
| DOS Device Names and NT Namespace | Geoff Chappell | Advanced | `UNDOCUMENTED` `REFERENCE` |

---

## 05 — RPC / COM / ALPC / Named Pipes

| Title | Author | Difficulty | Tags |
|-------|--------|------------|------|
| COM Internals and Security | Windows Internals + Forshaw | Advanced | `FOUNDATIONAL` `COM` |
| A COM Security Tour (tiraniddo.dev series) | James Forshaw | Advanced | `MUST-READ` `BLOG` `COM` |
| ALPC Internals | Alex Ionescu / Windows Internals | Advanced | `FOUNDATIONAL` `ALPC` |
| RPC for Security Researchers | Various | Intermediate | `BLOG` `RPC` |
| Hunting for Bugs in Windows RPC | NCC Group / others | Advanced | `BLOG` `RPC` `BUG-HUNTING` |
| rpcdump / rpcview tooling | Various | Intermediate | `TOOL` `RPC` |
| Named Pipe Security Deep Dive | Forshaw / others | Advanced | `BLOG` `NAMEDPIPE` |
| COM Elevation Moniker | MSDN / Forshaw | Advanced | `COM` `UAC` `BLOG` |
| OLE Automation and Scripting Interfaces as Attack Surface | Various | Advanced | `COM` `ATTACK-SURFACE` |
| DCOM Lateral Movement | impacket / various | Advanced | `DCOM` `LATERAL-MOVEMENT` |
| NtAlpcSendWaitReceivePort and ALPC Security | Ionescu | Advanced | `ALPC` `REFERENCE` |

---

## 06 — Filesystem & File Operations

| Title | Author | Difficulty | Tags |
|-------|--------|------------|------|
| NTFS In Depth | Windows Internals Part 2 | Intermediate | `FOUNDATIONAL` |
| Junctions, Symlinks, and Hardlinks on NTFS | Forshaw / MSDN | Intermediate | `FOUNDATIONAL` `JUNCTION` `SYMLINK` |
| CreateFile — Security Implications | MSDN + Forshaw blog | Intermediate | `REFERENCE` |
| SetOpLock / NtFsControlFile for TOCTOU | Forshaw | Advanced | `OPLOCK` `TOCTOU` `BLOG` |
| NTFS Transactions (TxF) | Windows Internals | Intermediate | `REFERENCE` `TXF` |
| File Object Security and Sharing Modes | MSDN | Intermediate | `REFERENCE` |
| Arbitrary File Write → LPE Primitives | Multiple writeups | Advanced | `MUST-READ` `ARB-WRITE` `EXPLOIT-PRIMITIVE` |
| DLL Hijacking via File System | Various | Intermediate | `DLL-HIJACKING` `BLOG` |
| Printer Spooler File Operations (PrintNightmare analysis) | Cube0x0 / others | Advanced | `MUST-READ` `CVE` `BLOG` |
| Windows File System Filter Drivers | OSR / MSDN | Advanced | `KERNEL` `DRIVER` `REFERENCE` |
| CreateHardLink Security Implications | Forshaw / Zero | Advanced | `HARDLINK` `BLOG` |

---

## 07 — Services, Installers & Updaters

| Title | Author | Difficulty | Tags |
|-------|--------|------------|------|
| Windows Installer (MSI) Internals | MSDN / iTm4n | Intermediate | `FOUNDATIONAL` `MSI` |
| InstallerFileTakeOver (CVE-2021-41379) Analysis | Abdelhamid Naceri | Advanced | `MUST-READ` `BLOG` `CVE` |
| Windows Installer Repair Flow (ProcMon tracing) | itm4n | Advanced | `MUST-READ` `BLOG` `MSI` |
| Service Control Manager (SCM) Internals | Windows Internals | Intermediate | `FOUNDATIONAL` `SERVICE` |
| Weak Service Permissions → LPE | PrivescCheck / various | Intermediate | `BLOG` `SERVICE` `ENUM` |
| AlwaysInstallElevated Exploitation | Various | Beginner-Intermediate | `MSI` `BLOG` |
| Windows Update Agent Architecture | MSDN / research | Advanced | `UPDATE` `REFERENCE` |
| Scheduled Tasks as LPE Vector | various | Intermediate | `TASK-SCHEDULER` `BLOG` |
| Autorun Keys and Startup Locations | various | Beginner-Intermediate | `PERSISTENCE` `REFERENCE` |
| DLL Planting via Trusted Installers | itm4n / various | Advanced | `DLL-HIJACKING` `BLOG` |
| COM Object Hijacking | various | Advanced | `COM` `HIJACKING` `BLOG` |
| PrintNightmare Root Cause (CVE-2021-1675 / 34527) | Various researchers | Advanced | `MUST-READ` `CVE` `PRINTER` |

---

## 08 — Bug Classes

### Arbitrary File Write / Move / Delete

| Title | Author | Difficulty | Tags |
|-------|--------|------------|------|
| Arbitrary File Write to System (technique overview) | various | Advanced | `MUST-READ` `ARB-WRITE` |
| From Arbitrary File Write to SYSTEM — Techniques | SpecterOps / various | Advanced | `EXPLOIT-PRIMITIVE` |
| Windows Error Reporting (WER) as Write Primitive | various | Advanced | `WER` `ARB-WRITE` |
| DiagHub EoP via Arbitrary File Write | SandboxEscaper | Advanced | `HISTORICAL` `CVE` |

### Junction / Symlink / Hardlink Abuse

| Title | Author | Difficulty | Tags |
|-------|--------|------------|------|
| Symbolic Link Testing Tools (symboliclink-testing-tools) | James Forshaw | Advanced | `MUST-READ` `TOOL` `SYMLINK` |
| Junction + Oplock Race Condition Pattern | Forshaw / Zero | Advanced | `MUST-READ` `TOCTOU` `JUNCTION` |
| NtSetInformationFile Hardlink Creation | Various | Advanced | `HARDLINK` `BLOG` |

### Token Impersonation (Potato Variants)

| Title | Author | Difficulty | Tags |
|-------|--------|------------|------|
| Hot Potato (2016) | foxglovesecurity | Intermediate | `HISTORICAL` `POTATO` `BLOG` |
| Rotten Potato | foxglove / Stephen Breen | Intermediate | `HISTORICAL` `POTATO` `BLOG` |
| Juicy Potato | ohpe / decoder | Intermediate | `MUST-READ` `POTATO` `BLOG` |
| Sweet Potato | EasyClangComplete / various | Advanced | `POTATO` `BLOG` |
| PrintSpoofer (CVE-2020-1030) | itm4n | Advanced | `MUST-READ` `BLOG` `IMPERSONATION` |
| RoguePotato | decoder / Pierini | Advanced | `MUST-READ` `POTATO` `BLOG` |
| GodPotato | BeichenDream | Advanced | `POTATO` `BLOG` |
| BadPotato | BeichenDream | Advanced | `POTATO` `BLOG` |
| EfsPotato (PetitPotam-based) | zcgonvh | Advanced | `POTATO` `BLOG` |
| Token Stealing via SYSTEM service | multiple | Advanced | `TOKEN` `BLOG` |

### RPC / COM / Named Pipe Boundary Bugs

| Title | Author | Difficulty | Tags |
|-------|--------|------------|------|
| From Rags to SYSTEM via Named Pipes | various | Advanced | `NAMEDPIPE` `BLOG` |
| RPC Endpoint Security Misconfigurations | NCC Group | Advanced | `RPC` `BLOG` |
| COM LPE via Impersonation | Forshaw | Advanced | `COM` `IMPERSONATION` `BLOG` |

### Object Manager Namespace Abuse

| Title | Author | Difficulty | Tags |
|-------|--------|------------|------|
| Object Directory DACL Weaknesses | Forshaw | Advanced | `MUST-READ` `OBJECT-MANAGER` |
| Abusing the NT Namespace for LPE | Forshaw (DEF CON) | Advanced | `MUST-READ` `TALK` |

### Kernel Memory Corruption

| Title | Author | Difficulty | Tags |
|-------|--------|------------|------|
| HEVD — Hacksys Extreme Vulnerable Driver | HackSys Team | Intermediate | `MUST-READ` `LAB` `KERNEL` |
| Windows Kernel Pool Exploitation (Segment Heap) | Yarden Shafir | Advanced | `MUST-READ` `BLOG` `KERNEL` |
| Pool Internals and Exploitation Post-Win10 | Yarden Shafir / Alex Ionescu | Advanced | `MUST-READ` `KERNEL` `BLOG` |
| Windows Kernel Exploitation Tutorial Series | rootkits.xyz / various | Intermediate | `TRAINING` `KERNEL` |

### Win32k Bugs

| Title | Author | Difficulty | Tags |
|-------|--------|------------|------|
| Win32k Exploitation Overview | j00ru | Advanced | `MUST-READ` `WIN32K` |
| Win32k Attack Surface Reduction | Microsoft / Project Zero | Advanced | `WIN32K` `BLOG` |
| Bochspwn — Finding Race Conditions in the Kernel | j00ru & Mateusz Jurczyk | Advanced | `MUST-READ` `RACE` `KERNEL` `TALK` |

---

## 09 — Exploit Primitives

| Title | Author | Difficulty | Tags |
|-------|--------|------------|------|
| Windows Exploitation Primitives (I/O Ring) | Yarden Shafir | Advanced | `MUST-READ` `KERNEL` `BLOG` |
| Kernel Data-Only Attacks | various | Advanced | `KERNEL` `EXPLOIT-PRIMITIVE` |
| Arbitrary Read/Write to EoP — techniques | various | Advanced | `EXPLOIT-PRIMITIVE` |
| Controlled Kernel Memory Corruption → LPE flow | HackSys / others | Advanced | `KERNEL` `EXPLOIT-PRIMITIVE` |
| SYSTEM Token Stealing (classic technique) | various | Advanced | `TOKEN` `EXPLOIT-PRIMITIVE` |
| Write-What-Where to Token Privileges | various | Advanced | `EXPLOIT-PRIMITIVE` `TOKEN` |
| I/O Ring Exploitation (Windows 11) | Yarden Shafir | Advanced | `MUST-READ` `KERNEL` `BLOG` |
| NtQuerySystemInformation Leaks | various | Intermediate | `INFO-LEAK` `KERNEL` |
| Kernel Stack Overflow Exploitation | HEVD / various | Intermediate | `KERNEL` `STACK-OVF` |
| Use-After-Free in Kernel Pool | various | Advanced | `KERNEL` `UAF` |

---

## 10 — Kernel & Win32k

| Title | Author | Difficulty | Tags |
|-------|--------|------------|------|
| Windows Kernel Internals (WRK) | Alex Ionescu lectures | Advanced | `FOUNDATIONAL` `KERNEL` |
| Windows Driver Development (WDK Docs) | Microsoft | Intermediate | `REFERENCE` `DRIVER` |
| HEVD — Hacksys Extreme Vulnerable Driver (source) | HackSys Team | Intermediate | `LAB` `KERNEL` `OPEN-SOURCE` |
| Windows Kernel Exploitation: From Basics | various training | Intermediate | `TRAINING` `KERNEL` |
| Win32k Exploitation History | j00ru | Advanced | `WIN32K` `HISTORICAL` |
| Segment Heap Internals | Mark Dowd / LookingGlass | Advanced | `KERNEL` `HEAP` |
| Windows Heap Internals (user mode) | various | Intermediate | `HEAP` `BLOG` |
| SMEP and SMAP Bypass Techniques | various | Advanced | `KERNEL` `BYPASS` |
| KVA Shadowing (Meltdown mitigation) internals | Microsoft | Advanced | `KERNEL` `SPECTRE` |
| Driver Signature Enforcement Bypass | various | Advanced | `KERNEL` `DSE-BYPASS` |

---

## 11 — Patch Diff & Root Cause Analysis

| Title | Author | Difficulty | Tags |
|-------|--------|------------|------|
| BinDiff Documentation | Zynamics / Google | Intermediate | `TOOL` `PATCH-DIFF` |
| Diaphora — Binary Diffing Tool | Joxean Koret | Intermediate | `TOOL` `PATCH-DIFF` `OPEN-SOURCE` |
| Finding Windows Bugs by Patch Diffing (methodology) | Various bloggers | Advanced | `METHODOLOGY` `PATCH-DIFF` |
| MSRC Patch Tuesday Analysis — how to approach | various security blogs | Intermediate | `METHODOLOGY` |
| WinDiff — Windows binary diff tool | Joe Bialek | Advanced | `TOOL` `PATCH-DIFF` |
| patchdiff2 (IDA plugin) | Nicolas Pouvesle | Intermediate | `TOOL` `PATCH-DIFF` |
| Analyzing Incomplete Fixes (variant hunting methodology) | Forshaw / Zero | Advanced | `MUST-READ` `VARIANT-HUNTING` |
| Patch Tuesday Monthly — Google Project Zero blog | Project Zero | Advanced | `MUST-READ` `BLOG` |
| CVE-YYYY writeup template (how to write root cause) | various | Intermediate | `METHODOLOGY` |

---

## 12 — Variant Hunting

| Title | Author | Difficulty | Tags |
|-------|--------|------------|------|
| Finding Variants of Known Windows Bugs | Forshaw (various talks) | Advanced | `MUST-READ` `VARIANT-HUNTING` |
| Code Pattern Search with CodeQL | GitHub / Project Zero | Advanced | `CODEQL` `TOOL` |
| Jackalope — Coverage-guided Fuzzer | Google Project Zero | Advanced | `FUZZING` `TOOL` `OPEN-SOURCE` |
| WTF (Windows fuzzing framework) | 0vercl0k | Advanced | `FUZZING` `TOOL` `OPEN-SOURCE` |
| Hunting Attack Surface with NtObjectManager | Forshaw | Advanced | `TOOL` `BLOG` `ATTACK-SURFACE` |
| COM Attack Surface Enumeration | Forshaw | Advanced | `COM` `ATTACK-SURFACE` |
| Finding Race Conditions in NT Code | j00ru / Forshaw | Advanced | `RACE` `METHODOLOGY` |
| BinSkim / static analysis for bug patterns | Microsoft | Intermediate | `TOOL` `STATIC-ANALYSIS` |

---

## 13 — CVE Case Studies

### Arbitrary File Write / Installer

| Title | CVE | Author | Tags |
|-------|-----|--------|------|
| InstallerFileTakeOver Deep Dive | CVE-2021-41379 | Naceri | `MUST-READ` `MSI` `ARB-WRITE` |
| Windows Installer EoP Analysis | CVE-2021-26415 | Naceri / various | `MSI` `CVE` |
| SilentCleanup EoP | CVE-2019-1253 | various | `TASK-SCHEDULER` `CVE` |

### Print Spooler

| Title | CVE | Author | Tags |
|-------|-----|--------|------|
| PrintNightmare Root Cause | CVE-2021-1675 / 34527 | Cube0x0 / multiple | `MUST-READ` `PRINTER` |
| PrintSpoofer | CVE-2020-1030 | itm4n | `MUST-READ` `IMPERSONATION` |

### Token / Potato

| Title | CVE | Author | Tags |
|-------|-----|--------|------|
| Juicy Potato | Multiple CLSIDs | decoder / ohpe | `MUST-READ` `POTATO` |
| RoguePotato | Various | Decoder | `MUST-READ` `POTATO` |

### Object Manager / Symlink

| Title | CVE | Author | Tags |
|-------|-----|--------|------|
| DiagHub / WER arbitrary write | CVE-2018-8584 | SandboxEscaper | `HISTORICAL` `ARB-WRITE` |

### Kernel

| Title | CVE | Author | Tags |
|-------|-----|--------|------|
| Bochspwn race conditions | Multiple | j00ru | `MUST-READ` `RACE` `KERNEL` |
| Win32k Type Confusion | Multiple | Tarjei Mandt / others | `WIN32K` `TYPE-CONFUSION` |
| CLFS EoP | CVE-2022-24521 | Various | `KERNEL` `CVE` |
| Common Log File System bugs | CVE-2023-series | Ransomware operators / CISA | `KERNEL` `CVE` |

---

## 14 — Blogs & Researchers

| Researcher | Blog | Focus |
|-----------|------|-------|
| James Forshaw | tiraniddo.dev | Windows security, COM, object manager, sandbox escapes |
| Mateusz "j00ru" Jurczyk | j00ru.vexillium.org | Kernel, Win32k, Windows internals, fuzzing |
| itm4n (Clément Labro) | itm4n.github.io | LPE, Windows services, UAC, impersonation |
| decoder / Andrea Pierini | decoder.cloud | Potato exploits, RPC, LPE |
| Alex Ionescu | ionescu007.github.io | Windows internals, ALPC, bootloader |
| Yarden Shafir | yaniv.io / blog | Kernel pool, Windows 11 exploitation |
| Filip Dragovic | filip.io | LPE, various Windows bugs |
| Valentina Palmiotti | ibm.com/security/blog | LPE, kernel exploitation |
| Abdelhamid Naceri | halov.medium.com | Installer LPE, zero-days |
| Jonas Lyk | jonasLyk.github.io | LPE variants, Windows bugs |
| SandboxEscaper (historical) | sandboxescaper.blogspot.com | LPE zero-days (historical) |
| FuzzySecurity (b33f) | fuzzysecurity.com | Windows post-exploitation, ETW |
| Will Schroeder | harmj0y.net | Active Directory, token abuse, GhostPack |
| Benjamin Delpy | blog.gentilkiwi.com | Mimikatz, credentials, LSASS |
| Casey Smith | subt0x10.blogspot.com | AppLocker bypass, LOLBins |
| Matt Graeber | mattgraeber.com | PowerShell security, AMSI |
| Matt Hand | matterpreter.github.io | Offensive .NET, post-exploitation |
| ZeroPeril Team | zeroperil.co.uk/blog | COM LPE, various bugs |
| Synacktiv Team | synacktiv.com/publications | Various Windows vulns |
| Google Project Zero | googleprojectzero.blogspot.com | Windows bugs at depth, patch analysis |

---

## 15 — GitHub & Code

| Repo | Author | Description | Trust |
|------|--------|-------------|-------|
| sandbox-attacksurface-analysis-tools | tiraniddo | NtObjectManager + attack surface tools | HIGH |
| HEVD | HackSysTeam | Hacksys Extreme Vulnerable Driver | HIGH |
| PrivescCheck | itm4n | Windows LPE enumeration script | HIGH |
| PrintSpoofer | itm4n | Named pipe impersonation PoC | HIGH |
| JuicyPotatoNG | antonioCoco | Juicy Potato Next Gen | HIGH |
| RoguePotato | decoder-it | OXID resolver abuse for potato | HIGH |
| GodPotato | BeichenDream | Modern potato variant | MEDIUM |
| SharpUp | GhostPack / harmj0y | LPE auditing in .NET | HIGH |
| WinPwn | S3cur3Th1sSh1t | Windows pentest automation | MEDIUM |
| Seatbelt | GhostPack | Windows host safety checks | HIGH |
| Rubeus | GhostPack | Kerberos abuse | HIGH |
| mimikatz | gentilkiwi | Credential extraction | HIGH |
| Invoke-ReflectivePEInjection | PowerSploit | Reflective DLL injection | MEDIUM |
| WTF fuzzer | 0vercl0k | Windows kernel fuzzer | HIGH |
| jackalope | googleprojectzero | Coverage-guided fuzzer | HIGH |
| symboliclink-testing-tools | tiraniddo | Symlink/junction testing | HIGH |
| spelunky | tiraniddo | Windows object namespace explorer | HIGH |

---

## 16 — Talks, Papers & Slides

| Title | Author | Conference | Year |
|-------|--------|------------|------|
| Windows Exploitation in 2019 | Forshaw | DEF CON 27 | 2019 |
| A Decade of Windows Kernel Privilege Escalation | j00ru | Conference talk | 2016 |
| Exploiting the Windows Kernel — Forshaw talks | Forshaw | Various | 2016–2022 |
| Bochspwn Reloaded: Detecting Kernel Memory Disclosure | j00ru | Black Hat 2017 | 2017 |
| Windows 10 Mitigation Improvements | Microsoft (Ionescu) | Black Hat 2015 | 2015 |
| Abusing Windows Internals for Fun and Profit | Forshaw | DEF CON 25 | 2017 |
| I/O Ring Exploitation on Windows 11 | Yarden Shafir | Talk | 2022 |
| The Pool is Dead, Long Live the Pool | Yarden Shafir / Alex Ionescu | Hex Rays | 2020 |
| Weaponizing Windows Printing Technologies | Multiple | Various | 2021 |
| Breaking Protected Processes | Ionescu | REcon | 2015 |
| Bypassing Windows UAC Through DLL Planting | various | DEF CON | Various |
| Windows Sandbox Escape — Forshaw series | Forshaw | Infiltrate / DEF CON | 2019–2020 |
| Attacking Windows Service Accounts | various | SecTor / DEF CON | Various |

---

## 17 — Labs & Exercises

| Lab Title | Difficulty | Category |
|-----------|------------|----------|
| WinDbg Kernel Debugging Setup (KD over network) | Beginner | Debugging |
| TTD — Recording and replaying a crash | Beginner | Debugging |
| ProcMon trace of Windows Installer repair | Intermediate | Installer |
| Token analysis with System Informer | Beginner | Security Model |
| Enable SeImpersonatePrivilege, trace potato flow | Advanced | Potato |
| Reproduce PrintSpoofer on Windows 10 | Advanced | Impersonation |
| Set up HEVD + exploit Stack Overflow | Intermediate | Kernel |
| HEVD — Pool overflow exploitation | Advanced | Kernel |
| Build junction + oplock PoC with Forshaw's tools | Advanced | TOCTOU |
| Patch diff a Patch Tuesday advisory | Advanced | Patch Diff |
| COM server enumeration with NtObjectManager | Intermediate | COM |
| Write a PoC for weak service permissions | Intermediate | Services |
| DLL hijacking in a Windows service | Intermediate | DLL-Hijacking |
| Trace InstallerFileTakeOver technique | Advanced | Installer |
| Enumerate object namespace with WinObj | Beginner | Object Manager |

---

## 18 — Reporting & Bounty

| Title | Source | Tags |
|-------|--------|------|
| MSRC Submission Portal | Microsoft | `OFFICIAL` `SUBMISSION` |
| Windows Security Servicing Criteria | Microsoft Learn | `MUST-READ` `OFFICIAL` |
| ZDI Submission Guidelines | Trend Micro ZDI | `BOUNTY` `OFFICIAL` |
| Writing a Great Vulnerability Report | Various | `METHODOLOGY` |
| CVSS v3.1 Calculator | FIRST.org | `SCORING` `TOOL` |
| Coordinated Disclosure Best Practices | ISO / CERT | `METHODOLOGY` |
| HackerOne Disclosure Policy | HackerOne | `PLATFORM` |
| MSRC Severity Rating System | Microsoft | `OFFICIAL` `SCORING` |

---

## Priority Reading Queue — Top 20 (Read First)

> Start here if you're new. These 20 resources build the most critical foundations and skills.

1. **Windows Internals Part 1** (Ch. 1–7) — Russinovich et al.
2. **Windows Security Internals** — James Forshaw (entire book)
3. **Symbolic Links in Windows** — tiraniddo.dev
4. **A COM Security Tour** (blog series) — tiraniddo.dev
5. **Token Privileges for LPE** — foxglovesecurity
6. **PrintSpoofer Analysis** — itm4n.github.io
7. **RoguePotato writeup** — decoder.cloud
8. **InstallerFileTakeOver** — Naceri/Medium
9. **Abusing the NT Namespace** — Forshaw (DEF CON 25 talk + slides)
10. **Bochspwn Reloaded** — j00ru (Black Hat 2017)
11. **Pool is Dead** — Yarden Shafir / Ionescu
12. **I/O Ring Exploitation** — Yarden Shafir
13. **NtObjectManager README** — tiraniddo (GitHub)
14. **PrivescCheck README + usage** — itm4n
15. **HEVD Source Code + walkthrough** — HackSysTeam
16. **Windows Security Servicing Criteria** — Microsoft Learn
17. **Junction + Oplock technique** — Forshaw blog series
18. **Project Zero — Google blog (Windows tag)** — Project Zero team
19. **j00ru's kernel blog** — vexillium.org
20. **WinDbg Time Travel Debugging intro** — Microsoft / Channel9

---

## Legend — Tags

| Tag | Meaning |
|-----|---------|
| `FOUNDATIONAL` | Core knowledge; must master before advanced work |
| `MUST-READ` | Highest-value resource in this area; read before anything else |
| `LAB-WORTHY` | Has reproducible exercises or PoC code |
| `HISTORICAL` | Important for understanding evolution; may be patched |
| `VARIANT-HUNTING` | Directly useful for finding related bugs |
| `PATCH-DIFF` | Directly useful for patch analysis workflow |
| `EXPLOIT-PRIMITIVE` | A technique used to convert vuln to exploit |
| `REFERENCE` | Reference document, consult as needed |
| `TOOL` | A software tool or script |
| `OPEN-SOURCE` | Has source code available |
| `BOOK` | Long-form book resource |
| `BLOG` | Blog post / article |
| `TALK` | Conference talk / presentation |
| `OFFICIAL` | Official vendor documentation |
| `CVE` | Associated with a specific CVE |
| `OFFENSIVE` | Primarily offensive technique |
| `DETECTION` | Defensive / detection perspective |
