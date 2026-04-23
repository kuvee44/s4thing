# Chapter 15 — GitHub Repositories & Code

> A curated registry of repositories that are directly useful for Windows security research. Every entry here earns its place: either it is an indispensable tool, an educational lab environment, or a PoC that teaches a fundamental technique. Repositories are rated by trust level and annotated with what you actually use them for.

---

## Trust Levels

- **HIGH:** Core research tools from verified researchers; actively maintained; code reviewed by community
- **MEDIUM:** Useful but use with care — read source before running; may be outdated or from less-verified sources
- **CAUTION:** Historical, aggregated, or anonymous — verify everything; do not run on sensitive machines

---

## Category 1 — Research Tooling (Use Constantly)

### sandbox-attacksurface-analysis-tools (NtObjectManager)

| Field | Value |
|-------|-------|
| **Author** | James Forshaw / Google Project Zero |
| **URL** | https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools |
| **Trust** | HIGH |
| **Tags** | `research-tooling` `tokens` `RPC` `named-pipes` `COM` `object-manager` `PowerShell` |

**What it is:** A collection of Windows security research tools built around the NtObjectManager PowerShell module. The module exposes the NT object manager, security descriptors, tokens, and RPC/ALPC surfaces via PowerShell cmdlets.

**What you use it for:**
- `Get-NtToken` — inspect current or other process tokens (user SID, groups, privileges, impersonation level, integrity)
- `Get-NtSecurityDescriptor` / `Show-NtSecurityDescriptor` — view DACLs/SACLs on any object type
- `Get-NtProcess`, `Get-NtHandle` — enumerate processes and handles
- `Get-RpcServer` — enumerate all RPC servers registered on the machine; inspect security callbacks
- `Get-RpcEndpoint` — list active RPC endpoints
- `Get-ComClassEntry` — enumerate COM class registrations with security configuration
- Object namespace exploration: `Get-NtObject`, `ls \`, directory DACL inspection
- Named pipe enumeration: find pipes with overly permissive DACLs

**Learning path:** Install via `Install-Module NtObjectManager`, then work through examples in Forshaw's Windows Security Internals book. The book and this tool are designed as a pair.

---

### symboliclink-testing-tools

| Field | Value |
|-------|-------|
| **Author** | James Forshaw / Google Project Zero |
| **URL** | https://github.com/googleprojectzero/symboliclink-testing-tools |
| **Trust** | HIGH |
| **Tags** | `symlink` `junction` `oplock` `TOCTOU` `exploit-tooling` `foundational` |

**What it is:** A collection of utilities for testing and exploiting symbolic link and opportunistic lock behavior in Windows.

**Key utilities:**
- `SetOpLock.exe` — acquire an oplock on a file; blocks the next open attempt by the target process until you release it. Core tool for implementing the BaitAndSwitch TOCTOU pattern.
- `CreateJunction.exe` — create NTFS directory junctions (mount points) without requiring elevation.
- `CreateSymLink.exe` — create object manager symbolic links in `\RPC Control\` or `\BaseNamedObjects\`.
- `NtApiDotNet` library — the .NET library that powers all the tools; can be used directly in exploit code.

**Usage pattern for BaitAndSwitch:**
```
1. Identify: privileged process will write file at path X (found via ProcMon)
2. SetOpLock on the parent directory of X (or a file in the path)
3. When oplock triggers: swap directory X for a junction pointing to target directory Y
4. Release oplock → privileged process writes to attacker's chosen destination
```

---

### PrivescCheck

| Field | Value |
|-------|-------|
| **Author** | itm4n (Clément Labro) |
| **URL** | https://github.com/itm4n/PrivescCheck |
| **Trust** | HIGH |
| **Tags** | `LPE` `enumeration` `PowerShell` `services` `DLL-hijacking` `educational` |

**What it is:** A comprehensive PowerShell script that checks for common Windows LPE vectors. Unlike automated exploitation frameworks, it produces annotated findings with explanations.

**Checks performed:**
- Service binary/registry ACLs (writable by low-privilege users)
- Unquoted service paths
- DLL hijacking paths (directories in service binary's PATH that are writable)
- AlwaysInstallElevated MSI setting
- Stored credentials (Windows vault, DPAPI blobs)
- Hot fixes and missing patches
- Token privileges in current session
- Scheduled task misconfigurations
- UAC configuration

**Research use:** Run PrivescCheck output as a checklist of what to investigate after initial foothold. More importantly, reading the source code teaches you *how to detect* each vulnerability class — useful when writing custom enumeration for specific environments.

---

### PrintSpoofer

| Field | Value |
|-------|-------|
| **Author** | itm4n (Clément Labro) |
| **URL** | https://github.com/itm4n/PrintSpoofer |
| **Trust** | HIGH |
| **Tags** | `named-pipe` `impersonation` `SeImpersonatePrivilege` `ImpersonateNamedPipeClient` |

**What it is:** PoC for named pipe squatting to abuse SeImpersonatePrivilege. Creates a named pipe that catches the Print Spooler's authentication when it connects to a specially-named pipe, then calls `ImpersonateNamedPipeClient` to get a SYSTEM token.

**Why it matters technically:** The code demonstrates the exact `CreateNamedPipe` → `WaitForSingleObject` → `ConnectNamedPipe` → `ImpersonateNamedPipeClient` pattern that underlies all named pipe impersonation techniques. Read the source to understand the pattern before using.

---

### RpcView

| Field | Value |
|-------|-------|
| **Author** | silverf0x (Jean-Marie Borello et al.) |
| **URL** | https://github.com/silverf0x/RpcView |
| **Trust** | HIGH |
| **Tags** | `RPC` `endpoint-enumeration` `decompilation` `research-tool` |

**What it is:** GUI tool that enumerates all registered RPC servers on a Windows machine, shows their interfaces, endpoints, and can decompile IDL from running processes.

**Research use:** 
- Enumerate RPC interfaces exposed by services running as SYSTEM/high-privilege
- View security callbacks and authentication settings per interface
- Decompile interface IDL to understand method signatures
- Starting point for "what does this privileged service expose via RPC?"

The itm4n blog post "From RpcView to PetitPotam" demonstrates the exact workflow: use RpcView to find EfsRpcOpenFileRaw interface → realize it triggers authentication to caller-specified path → PetitPotam.

---

## Category 2 — Exploitation Labs

### HEVD — HackSys Extreme Vulnerable Driver

| Field | Value |
|-------|-------|
| **Author** | HackSysTeam (Ashfaq Ansari et al.) |
| **URL** | https://github.com/hacksysteam/HackSysExtremeVulnerableDriver |
| **Trust** | HIGH |
| **Tags** | `kernel` `driver` `exploitation-lab` `must-read` `educational` |

**What it is:** A deliberately vulnerable Windows kernel driver designed as a training environment for kernel exploitation. Each IOCTL handler contains a different vulnerability type.

**Vulnerability types included:**
- Stack buffer overflow
- Stack buffer overflow with GS (security cookie)
- Arbitrary overwrite (write-what-where)
- Pool buffer overflow (NonPaged)
- Pool buffer overflow (NonPaged with NX mitigation)
- Use-After-Free (NonPaged)
- Use-After-Free (Paged)
- Type Confusion
- Integer overflow
- Null pointer dereference
- Double fetch (race condition TOCTOU)
- Uninitialized memory (stack and heap variants)

**Setup:**
```
1. Set up VM pair (debuggee + debugger) with KDNET
2. On debuggee: enable test signing (bcdedit /set testsigning on)
3. Deploy HEVD.sys as a kernel driver
4. Write user-mode exploit code that calls DeviceIoControl with target IOCTL codes
5. Set breakpoints in WinDbg at the vulnerable dispatch routines
6. Exploit to achieve token stealing → SYSTEM shell
```

**Learning sequence:** Stack overflow first (simplest), then arbitrary overwrite (gives you write-what-where directly), then pool overflow (requires grooming), then UAF (requires lifetime management understanding), then double fetch (requires race tooling).

---

### Windows-Local-Privilege-Escalation-Cookbook

| Field | Value |
|-------|-------|
| **Author** | nickvourd |
| **URL** | https://github.com/nickvourd/Windows-Local-Privilege-Escalation-Cookbook |
| **Trust** | HIGH |
| **Tags** | `LPE` `cookbook` `lab` `educational` `structured` |

**What it is:** Structured labs covering Windows LPE techniques with step-by-step instructions, each technique mapped to a category and difficulty level. More organized than collecting individual PoCs.

---

## Category 3 — Enumeration and Post-Exploitation

### Sysinternals Suite

| Field | Value |
|-------|-------|
| **Author** | Microsoft (originally Mark Russinovich, Bryce Cogswell) |
| **URL** | https://learn.microsoft.com/en-us/sysinternals/ |
| **Trust** | HIGH |
| **Tags** | `debugging` `observability` `process-analysis` `security` |

**Key tools for security research:**
- **Process Monitor (procmon.exe):** Logs all file, registry, network, and process/thread events system-wide. The single most important research tool. Every LPE involving a service starts with a ProcMon trace of that service's operations.
- **Process Explorer:** Interactive process tree showing DLLs loaded, handles open, network connections, token details, strings. More powerful than Task Manager.
- **WinObj:** Browse the NT object namespace (`\`, `\Device`, `\BaseNamedObjects`, etc.). Essential for object manager research.
- **AccessChk:** Report permissions on any object type — files, registry keys, services, processes, named pipes. Use to find weak ACLs. `accesschk.exe -wuvc Everyone *` finds service binaries writable by Everyone.
- **Autoruns:** Shows every persistence location — registry run keys, scheduled tasks, services, drivers, browser extensions, etc. Complete map of the startup surface.
- **PsExec:** Execute processes as SYSTEM or as other users; useful in labs.

---

### System Informer (formerly Process Hacker)

| Field | Value |
|-------|-------|
| **Author** | wj32 → community (now Winsider Seminars & Solutions) |
| **URL** | https://github.com/winsiderss/systeminformer |
| **Trust** | HIGH |
| **Tags** | `process-analysis` `token-inspection` `handle-view` `kernel-view` |

**Why it matters over Process Explorer:**
- Shows token details (all privileges, integrity level, impersonation level) per process
- Handle view: all handles in a process with object name and type
- Kernel memory view: pool allocations, drivers, kernel modules
- Network connections with process attribution
- Open source — you can read and modify it

**Research use:** After running a PoC, open System Informer to inspect the resulting process token — confirm you have SYSTEM, check integrity level, check privileges.

---

### SharpUp and Seatbelt (GhostPack)

| Field | Value |
|-------|-------|
| **Author** | Will Schroeder / GhostPack / SpecterOps |
| **URL** | SharpUp: https://github.com/GhostPack/SharpUp — Seatbelt: https://github.com/GhostPack/Seatbelt |
| **Trust** | HIGH |
| **Tags** | `enumeration` `post-exploitation` `C#` `GhostPack` |

**SharpUp:** C# port of PowerUp — enumerates LPE vectors (weak service permissions, token privileges, modifiable paths). Runs without PowerShell (AMSI bypass concern).

**Seatbelt:** Comprehensive C# enumeration tool — runs a set of "safety checks" from an attacker's perspective. Checks: AppLocker policy, AV status, browser credentials, DPAPI blobs, event log settings, Kerberos tickets, LSA settings, mapped drives, named pipes, scheduled tasks, token privileges, UAC settings, WSUS configuration, and 100+ others.

---

### InstallerFileTakeOver

| Field | Value |
|-------|-------|
| **Author** | klinix5 (Abdelhamid Naceri) |
| **URL** | https://github.com/klinix5/InstallerFileTakeOver |
| **Trust** | MEDIUM-HIGH |
| **Tags** | `Windows-Installer` `arbitrary-file-move` `LPE` `CVE-2021-41379` |

**What it is:** PoC for the Windows Installer elevation of privilege via repair operation + junction redirect. Read the source to understand the exact junction setup required.

---

## Category 4 — Protocol and Network Tools

### impacket

| Field | Value |
|-------|-------|
| **Author** | Fortra (formerly SecureAuth / Core Security) + community |
| **URL** | https://github.com/fortra/impacket |
| **Trust** | HIGH |
| **Tags** | `SMB` `Kerberos` `NTLM` `RPC` `Python` `relay` |

**What it is:** Python library and collection of tools for Windows protocol manipulation — SMB, NTLM, Kerberos, LDAP, DCE/RPC, MS-SQL.

**Key tools:**
- `ntlmrelayx.py` — NTLM relay attack tool; can relay to LDAP, SMB, HTTP, RPC
- `secretsdump.py` — dump credentials from SAM, LSA secrets, NTDS.dit (remotely or locally)
- `smbexec.py`, `psexec.py`, `wmiexec.py` — remote execution via different protocols
- `getTGT.py`, `getST.py` — Kerberos ticket manipulation
- `rpcdump.py` — enumerate RPC endpoints

---

### pe-sieve

| Field | Value |
|-------|-------|
| **Author** | hasherezade |
| **URL** | https://github.com/hasherezade/pe-sieve |
| **Trust** | HIGH |
| **Tags** | `PE-analysis` `injection-detection` `malware` `memory-forensics` |

**What it is:** Detects various forms of process injection and PE modifications in running processes. Useful for verifying that an injection technique worked and inspecting the result.

---

## Category 5 — Fuzzing and Automated Discovery

### jackalope

| Field | Value |
|-------|-------|
| **Author** | Google Project Zero |
| **URL** | https://github.com/googleprojectzero/jackalope |
| **Trust** | HIGH |
| **Tags** | `fuzzing` `coverage-guided` `Windows` `kernel` `research-tool` |

**What it is:** Coverage-guided fuzzer for Windows targets. Supports persistent fuzzing mode, hardware coverage (Intel PT), and custom mutators. Designed for fuzzing kernel drivers, RPC interfaces, and user-mode targets.

---

### WTF (Windows fuzzing framework)

| Field | Value |
|-------|-------|
| **Author** | 0vercl0k (Axel Souchet) |
| **URL** | https://github.com/0vercl0k/wtf |
| **Trust** | HIGH |
| **Tags** | `fuzzing` `kernel` `snapshot-fuzzing` `Windows` `coverage-guided` |

**What it is:** Snapshot-based coverage-guided fuzzer for Windows kernel and user-mode targets. Takes a memory snapshot of a target at a specific execution point, then fuzzes mutations against that snapshot. Extremely fast because it avoids process restart overhead.

**Use case:** Fuzzing kernel drivers where setting up the initial state is expensive. Take a snapshot just before the vulnerable operation, fuzz the input against the snapshot repeatedly.

---

## Quick Reference Table

| # | Repo | Author | URL | Trust | Primary Use |
|---|------|--------|-----|-------|-------------|
| 1 | sandbox-attacksurface-analysis-tools | Forshaw/PZ | https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools | HIGH | Token/RPC/COM/object-namespace research |
| 2 | symboliclink-testing-tools | Forshaw/PZ | https://github.com/googleprojectzero/symboliclink-testing-tools | HIGH | Symlink/junction/oplock exploit building |
| 3 | PrivescCheck | itm4n | https://github.com/itm4n/PrivescCheck | HIGH | LPE enumeration + education |
| 4 | PrintSpoofer | itm4n | https://github.com/itm4n/PrintSpoofer | HIGH | Named pipe impersonation PoC |
| 5 | RpcView | silverf0x | https://github.com/silverf0x/RpcView | HIGH | RPC endpoint enumeration |
| 6 | Sysinternals Suite | Microsoft | https://learn.microsoft.com/en-us/sysinternals/ | HIGH | ProcMon, WinObj, AccessChk |
| 7 | InstallerFileTakeOver | klinix5 | https://github.com/klinix5/InstallerFileTakeOver | MED-HIGH | MSI repair LPE PoC |
| 8 | GodPotato | BeichenDream | https://github.com/BeichenDream/GodPotato | MEDIUM | Modern potato (educational) |
| 9 | SharpUp | GhostPack | https://github.com/GhostPack/SharpUp | HIGH | LPE enumeration (C#) |
| 10 | Seatbelt | GhostPack | https://github.com/GhostPack/Seatbelt | HIGH | Post-exploitation enumeration |
| 11 | HEVD | HackSysTeam | https://github.com/hacksysteam/HackSysExtremeVulnerableDriver | HIGH | Kernel exploitation lab |
| 12 | System Informer | winsiderss | https://github.com/winsiderss/systeminformer | HIGH | Process/token/handle analysis |
| 13 | impacket | Fortra | https://github.com/fortra/impacket | HIGH | SMB/Kerberos/NTLM/RPC tools |
| 14 | jackalope | PZ | https://github.com/googleprojectzero/jackalope | HIGH | Coverage-guided fuzzing |
| 15 | WTF fuzzer | 0vercl0k | https://github.com/0vercl0k/wtf | HIGH | Snapshot kernel fuzzing |
| 16 | awesome_windows_logical_bugs | sailay1996 | https://github.com/sailay1996/awesome_windows_logical_bugs | MEDIUM | Curated LPE references |
| 17 | Windows-LPE-Cookbook | nickvourd | https://github.com/nickvourd/Windows-Local-Privilege-Escalation-Cookbook | HIGH | Structured LPE labs |
| 18 | pe-sieve | hasherezade | https://github.com/hasherezade/pe-sieve | HIGH | Injection detection |

---

## References

- [R-1] sandbox-attacksurface-analysis-tools — James Forshaw / Google Project Zero — https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools
- [R-2] symboliclink-testing-tools — James Forshaw / Google Project Zero — https://github.com/googleprojectzero/symboliclink-testing-tools
- [R-3] PrivescCheck — itm4n — https://github.com/itm4n/PrivescCheck
- [R-4] HEVD — HackSysTeam — https://github.com/hacksysteam/HackSysExtremeVulnerableDriver
- [R-5] RpcView — silverf0x — https://github.com/silverf0x/RpcView
- [R-6] impacket — Fortra — https://github.com/fortra/impacket
- [R-7] WTF fuzzer — 0vercl0k — https://github.com/0vercl0k/wtf
- [R-8] jackalope — Google Project Zero — https://github.com/googleprojectzero/jackalope
