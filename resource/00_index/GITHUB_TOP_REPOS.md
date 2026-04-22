# Top GitHub Repositories for Windows Security Research
## Updated: 2026-04-22

> Trust levels: **HIGH** = actively maintained by known researcher, widely used, source-verifiable | **MEDIUM** = useful but verify before running | **CAUTION** = use in isolated VM only, may contain live exploits

---

## Research Tooling (Essential)

| Repo | Author | Stars | Description | Trust | Tags |
|------|--------|-------|-------------|-------|------|
| [sandbox-attacksurface-analysis-tools](https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools) | tiraniddo / Project Zero | 3.5k+ | NtObjectManager PowerShell module + attack surface analysis suite. Browse object namespace, inspect tokens, enumerate COM servers, test sandbox escapes. The single most important research toolkit. | HIGH | `FOUNDATIONAL` `TOOL` `POWERSHELL` `COM` `TOKEN` |
| [symboliclink-testing-tools](https://github.com/googleprojectzero/symboliclink-testing-tools) | tiraniddo / Project Zero | 1k+ | Tools for creating mount points, object manager symlinks, pipe servers, and oplock holders for TOCTOU testing. Required for junction/symlink attack research. | HIGH | `TOOL` `SYMLINK` `JUNCTION` `OPLOCK` |
| [PrivescCheck](https://github.com/itm4n/PrivescCheck) | itm4n | 3k+ | Comprehensive PowerShell script for Windows LPE enumeration. Covers services, registry, DLL hijacking, credentials, scheduled tasks, token privileges. Source is a textbook of LPE vectors. | HIGH | `TOOL` `ENUMERATION` `LPE` `POWERSHELL` |
| [spelunky](https://github.com/googleprojectzero/spelunky) | tiraniddo / Project Zero | 500+ | Windows object namespace explorer. Browse and analyze object directory DACLs, find misconfigured objects. | HIGH | `TOOL` `OBJECT-MANAGER` |
| [SilkETW](https://github.com/mandiant/SilkETW) | FuzzySecurity / Mandiant | 1.5k+ | .NET tool for ETW event collection and analysis. Use for security research monitoring, detecting attacker techniques, and understanding Windows telemetry. | HIGH | `TOOL` `ETW` `MONITORING` |
| [System Informer (Process Hacker)](https://github.com/winsiderss/systeminformer) | wj32, dmex | 10k+ | Advanced process/token/handle viewer. Source code is a masterclass in Windows internals. More powerful than Task Manager for security research. | HIGH | `TOOL` `INTERNALS` `TOKEN` |
| [API Monitor](http://www.rohitab.com/apimonitor) | Rohitab | N/A | API call interception and monitoring. Not GitHub-hosted but essential. Hook any Win32 or COM call, record parameters and return values. | HIGH | `TOOL` `API-MONITORING` |
| [WinObj](https://learn.microsoft.com/en-us/sysinternals/downloads/winobj) | Sysinternals | N/A | GUI tool for browsing Windows object namespace. See device objects, symbolic links, directory DACLs. | HIGH | `TOOL` `OFFICIAL` `OBJECT-MANAGER` |

---

## LPE Exploits / PoCs (Educational)

> **⚠️ WARNING:** Only run in isolated, air-gapped VMs on patched Windows versions for study. Never on production systems.

| Repo | Author | Stars | Description | Trust | Tags |
|------|--------|-------|-------------|-------|------|
| [PrintSpoofer](https://github.com/itm4n/PrintSpoofer) | itm4n | 2k+ | Named pipe impersonation via print spooler (CVE-2020-1030). Best documented Potato-style exploit. Read the associated blog post before running. | HIGH | `LPE` `IMPERSONATION` `NAMEDPIPE` `POC` |
| [JuicyPotatoNG](https://github.com/antonioCoco/JuicyPotatoNG) | antonioCoco | 2k+ | Modern evolution of Juicy Potato. Works on Windows 10 versions where original Juicy Potato was blocked. Uses different CLSID enumeration strategy. | HIGH | `LPE` `POTATO` `DCOM` `POC` |
| [RoguePotato](https://github.com/decoder-it/RoguePotato) | decoder-it | 2k+ | Uses custom OXID resolver to bypass CoInitializeSecurity restrictions. Highly effective on Windows Server 2019. | HIGH | `LPE` `POTATO` `OXID` `POC` |
| [GodPotato](https://github.com/BeichenDream/GodPotato) | BeichenDream | 3k+ | Modern potato using IRemUnknown2 COM interface. Works on Windows 2012–2022. | MEDIUM | `LPE` `POTATO` `POC` |
| [EfsPotato](https://github.com/zcgonvh/EfsPotato) | zcgonvh | 1k+ | Uses EFS (MS-EFSR / PetitPotam) to coerce NTLM auth from SYSTEM to attacker pipe. | MEDIUM | `LPE` `POTATO` `EFS` `POC` |
| [BadPotato](https://github.com/BeichenDream/BadPotato) | BeichenDream | 500+ | Another modern potato variant targeting specific Windows authentication flows. | MEDIUM | `LPE` `POTATO` `POC` |
| [InstallerFileTakeOver](https://github.com/klinix5/InstallerFileTakeOver) | klinix5 (Naceri) | 1.5k+ | CVE-2021-41379 — Windows Installer arbitrary file write via junction. Read blog post for full analysis. | HIGH | `LPE` `MSI` `ARB-WRITE` `CVE` |
| [UACME](https://github.com/hfiref0x/UACME) | hfiref0x | 5k+ | Massive catalog of UAC bypass techniques (60+). Each method documented with Windows version compatibility. Excellent research reference. | HIGH | `UAC` `BYPASS` `REFERENCE` `CATALOG` |
| [CVE-2021-1675 (PrintNightmare)](https://github.com/cube0x0/CVE-2021-1675) | Cube0x0 | 2k+ | PrintNightmare PoC — both local LPE and remote code execution variants. | HIGH | `CVE` `PRINTER` `RCE` `LPE` `POC` |
| [Juicy Potato](https://github.com/ohpe/juicy-potato) | ohpe | 5k+ | The original Juicy Potato — historical reference. Essential for understanding the technique evolution. | HIGH | `LPE` `POTATO` `HISTORICAL` |

---

## Kernel Research & Exploitation

| Repo | Author | Stars | Description | Trust | Tags |
|------|--------|-------|-------------|-------|------|
| [HackSysExtremeVulnerableDriver (HEVD)](https://github.com/hacksysteam/HackSysExtremeVulnerableDriver) | HackSysTeam | 4k+ | Intentionally vulnerable Windows kernel driver with every major bug class: stack overflow, pool overflow, UAF, type confusion, null ptr deref. The standard learning platform for Windows kernel exploitation. Includes exploit code. | HIGH | `KERNEL` `TRAINING` `DRIVER` `LAB` |
| [WTF (Windows Kernel Fuzzer)](https://github.com/0vercl0k/wtf) | 0vercl0k | 2k+ | Snapshot-based fuzzer for Windows kernel components. Uses KVM/WHV hypervisor. Used by researchers to find real kernel bugs. | HIGH | `KERNEL` `FUZZING` `TOOL` |
| [jackalope](https://github.com/googleprojectzero/jackalope) | Project Zero | 1k+ | Coverage-guided fuzzer used by Project Zero. Supports Windows targets via TinyInst instrumentation. | HIGH | `FUZZING` `KERNEL` `TOOL` |
| [loldrivers](https://www.loldrivers.io/) / [GitHub](https://github.com/magicsword-io/LOLDrivers) | Community | 1k+ | Database of signed-but-vulnerable Windows drivers useful for BYOVD (Bring Your Own Vulnerable Driver) and kernel primitive attacks. | HIGH | `KERNEL` `DRIVER` `REFERENCE` `DSE-BYPASS` |
| [kernel-exploit-factory](https://github.com/nccgroup/kernel-exploit-factory) | NCC Group | 500+ | Collection of Windows kernel exploit PoCs for research. | MEDIUM | `KERNEL` `POC` `REFERENCE` |
| [Vulnerable-Driver-Research](https://github.com/fengjixuchui/Vulnerable-Driver-Research) | fengjixuchui | 500+ | Research notes and PoCs for vulnerable driver exploitation. | MEDIUM | `KERNEL` `DRIVER` `RESEARCH` |

---

## Enumeration Tools

| Repo | Author | Stars | Description | Trust | Tags |
|------|--------|-------|-------------|-------|------|
| [SharpUp](https://github.com/GhostPack/SharpUp) | GhostPack (harmj0y) | 1.5k+ | .NET LPE auditing tool. Checks unquoted service paths, modifiable service binaries/paths, always-install-elevated, token privileges, DLL hijacking. Source code is a catalog of LPE checks. | HIGH | `ENUMERATION` `LPE` `NET` |
| [Seatbelt](https://github.com/GhostPack/Seatbelt) | GhostPack | 3k+ | Windows host security configuration audit. Checks credentials, network, software, audit policy, AppLocker, WDAC. Reading source teaches the full Windows security configuration landscape. | HIGH | `ENUMERATION` `AUDIT` `NET` |
| [WinPEAS](https://github.com/peass-ng/PEASS-ng) | carlospolop | 15k+ | Automated privilege escalation enumeration. Windows + Linux. Comprehensive but noisy — good for labs, not stealthy. | MEDIUM | `ENUMERATION` `LPE` `PENTEST` |
| [PowerView](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1) | harmj0y / PowerSploit | 12k+ (suite) | PowerShell Active Directory enumeration. Essential for domain-joined Windows LPE research. | HIGH | `ENUMERATION` `AD` `POWERSHELL` |
| [BloodHound](https://github.com/BloodHoundAD/BloodHound) | BloodHoundAD | 10k+ | Graph-based Active Directory attack path analyzer. Visualizes privilege escalation paths in AD environments. | HIGH | `AD` `ENUMERATION` `GRAPH` |
| [AccessChk](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk) | Sysinternals | N/A | Checks effective permissions on files, services, registry keys, kernel objects. Command-line and fast. | HIGH | `TOOL` `ENUMERATION` `OFFICIAL` |

---

## Network / Protocol Tools

| Repo | Author | Stars | Description | Trust | Tags |
|------|--------|-------|-------------|-------|------|
| [impacket](https://github.com/fortra/impacket) | Fortra (SecureAuth) | 13k+ | Python library for Windows networking protocols: SMB, MSRPC, DCERPC, Kerberos, LDAP, NTLM. Essential for RPC/DCOM attack research. | HIGH | `RPC` `SMB` `KERBEROS` `NETWORK` |
| [Responder](https://github.com/lgandx/Responder) | lgandx | 5k+ | LLMNR/NBT-NS/MDNS poisoner for NTLM hash capture. Useful for understanding how NTLM relay enables Potato attacks. | HIGH | `NTLM` `RELAY` `NETWORK` |
| [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) | byt3bl33d3r | 8k+ | Post-exploitation and enumeration for Windows/AD networks. SMB, WINRM, MSSQL, LDAP. | MEDIUM | `PENTEST` `AD` `NETWORK` |
| [Rubeus](https://github.com/GhostPack/Rubeus) | GhostPack | 4k+ | Kerberos abuse toolkit. AS-REP roasting, Kerberoasting, ticket dumping, ticket forging, S4U attacks. | HIGH | `KERBEROS` `AD` `NET` |
| [rpcdump](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/rpcdump) / [rpcview](https://github.com/silverf0x/RpcView) | silverf0x / community | 500+ | RPC endpoint enumeration. RpcView shows all registered RPC servers and their interfaces. Essential for RPC attack surface research. | HIGH | `RPC` `ENUMERATION` `TOOL` |

---

## Analysis Tools

| Repo | Author | Stars | Description | Trust | Tags |
|------|--------|-------|-------------|-------|------|
| [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | NSA | 50k+ | Free and open-source reverse engineering framework. Excellent for Windows binary analysis. Supports x86, x64, ARM. | HIGH | `REVERSING` `TOOL` `OFFICIAL` |
| [Diaphora](https://github.com/joxeankoret/diaphora) | Joxean Koret | 3k+ | Open-source binary diffing tool for IDA Pro + Ghidra. Free alternative to BinDiff. Essential for patch Tuesday analysis. | HIGH | `PATCH-DIFF` `TOOL` |
| [BinDiff](https://github.com/google/bindiff) | Google / Zynamics | 2k+ | Industry-standard binary diffing tool. Now free. Integrates with IDA Pro and Ghidra. | HIGH | `PATCH-DIFF` `TOOL` |
| [Frida](https://github.com/frida/frida) | Frida Project | 15k+ | Dynamic instrumentation framework. JavaScript-based hooking of Windows APIs and functions. Excellent for black-box analysis. | HIGH | `INSTRUMENTATION` `DYNAMIC-ANALYSIS` |
| [PE-bear](https://github.com/hasherezade/pe-bear) | hasherezade | 2k+ | PE file viewer and editor. Fast and accurate for initial triage of Windows executables. | HIGH | `PE` `REVERSING` `TOOL` |
| [hollows_hunter / pe-sieve](https://github.com/hasherezade/pe-sieve) | hasherezade | 3k+ | Memory scanning for injected/hollowed code. Useful for malware analysis and understanding injection techniques. | HIGH | `MALWARE` `ANALYSIS` `TOOL` |
| [x64dbg](https://github.com/x64dbg/x64dbg) | x64dbg team | 45k+ | Open-source x64/x32 Windows debugger. Excellent GUI, plugin ecosystem, scripting. Complement to WinDbg for user-mode debugging. | HIGH | `DEBUGGER` `TOOL` |
| [dnSpy](https://github.com/dnSpy/dnSpy) (archived) / [dnSpyEx](https://github.com/dnSpyEx/dnSpy) | Various | 25k+ | .NET assembly debugger and decompiler. Essential for reversing C# security tools and understanding GhostPack internals. | HIGH | `REVERSING` `NET` `DEBUGGER` |

---

## Key Repository Details

### sandbox-attacksurface-analysis-tools
**What it includes:**
- `NtApiDotNet` — .NET library exposing undocumented NT APIs
- `NtObjectManager` — PowerShell module wrapping NtApiDotNet
- `EditSection` — GUI for NT section objects
- `TokenViewer` — detailed token inspection GUI
- `ViewSecurityDescriptor` — SDDL/ACE display
- `ViewDelegation` — check delegation settings

**Essential NtObjectManager commands:**
```powershell
# Enumerate all named pipes
Get-NtNamedPipe | Select-Object Name, SecurityDescriptor

# Get COM server launch permissions
Get-ComServer | Select-Object Clsid, Name, LaunchPermission

# Create object manager symlink for testing
New-NtSymbolicLink \RPC Control\target -TargetNtObject \Device\NamedPipe\attacker

# Check token privileges
Get-NtToken -Current | Select-Object -ExpandProperty Privileges
```

### HEVD — Lab Setup Quick Reference
```
1. Install Windows 10 VM (use patched version for learning, unpatched for full exploit chain)
2. Enable kernel debugging (bcdedit /debug on, KDNET setup)
3. Load HEVD.sys (test signed or disable DSE via bcdedit /testsigning on)
4. Use provided exploit scripts (Python, C, C#) for each vulnerability class
5. Verify exploitation by checking SYSTEM token in exploited process
```
