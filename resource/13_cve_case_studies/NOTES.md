# CVE Case Studies — Analysis Patterns & Notes

> Methodological notes for analyzing Windows LPE CVEs.
> This file captures recurring patterns, analysis frameworks, and key questions
> to ask when reverse-engineering or reproducing a Windows privilege escalation bug.

---

## Common LPE Primitive Chain

Most Windows LPE bugs reduce to one of these chains:

```
[Root Cause]
    ↓
[Primitive Acquired]
    ↓
[Conversion Step(s)]
    ↓
[SYSTEM Code Execution]
```

### Chain Examples

**Arbitrary File Write chain:**
```
Race/TOCTOU in privileged service
    → Arbitrary file write as SYSTEM (e.g., to C:\Windows\System32\)
    → DLL plant in known-DLLs or search-path location
    → Privileged process loads attacker DLL
    → SYSTEM shell
```

**Token Impersonation chain:**
```
SeImpersonatePrivilege on service account
    → Induce SYSTEM process to connect to attacker-controlled named pipe
    → ImpersonateNamedPipeClient → capture SYSTEM token
    → CreateProcessAsUser / CreateProcessWithTokenW
    → SYSTEM shell
```

**Kernel UAF chain:**
```
Trigger use-after-free in win32k / ntoskrnl
    → Pool grooming → controlled reclaim of freed object
    → Arbitrary kernel R/W primitive
    → Overwrite token->Privileges or token->SepPrivilegeValue
    OR
    → Overwrite process->Token pointer
    → SYSTEM
```

**Arbitrary File Move chain:**
```
Privileged repair/update operation performs file move
    → Junction manipulation redirects destination
    → Arbitrary file at attacker-chosen path (SYSTEM-owned)
    → Overwrite binary in trusted PATH location
    OR
    → Add attacker DLL to trusted directory
    → SYSTEM
```

---

## Analysis Framework: Five Questions Per CVE

When studying any Windows LPE CVE, answer these:

1. **What privileged context performs the vulnerable operation?**
   (SYSTEM service? Elevated MSI? Kernel driver? Elevated process?)

2. **What is the *exact* flaw?**
   (Race condition? Missing check? Incorrect DACL? Unvalidated user input? Missing impersonation revert?)

3. **What primitive does the flaw expose?**
   (Arbitrary write? Arbitrary move? Arbitrary delete? Kernel R/W? Token handle? Pipe impersonation?)

4. **How is the primitive converted to code execution?**
   (DLL plant? ACL manipulation? Token overwrite? Binary replacement?)

5. **What is the *minimal* attacker capability required?**
   (Any local user? SeImpersonatePrivilege? Write access to specific directory? Specific version?)

---

## Recurring Windows Vulnerability Patterns

### Pattern 1: File Operation Races (TOCTOU)

**Trigger:** Privileged process checks a path, then acts on it. Attacker wins the race.
**Classic tool:** `CreateSymbolicLink`, `NtSetInformationFile(RenameInformation)`, junction manipulation
**Key APIs to watch:** `CreateFile`, `MoveFile`, `SetFileAttributes`, `SetFileSecurity`
**Researcher:** SandboxEscaper (multiple), James Forshaw (systematic analysis)

### Pattern 2: Object Namespace Symlink Planting

**Trigger:** Attacker creates a symlink in a directory accessible to low-priv users.
Privileged service resolves the symlink and operates on attacker-controlled target.
**Key namespaces:** `\BaseNamedObjects`, `\RPC Control`, `\Sessions\X\BaseNamedObjects`
**Tool:** NtObjectManager (James Forshaw) — `Get-NtObjectDirectory`, `New-NtSymbolicLink`
**Researcher:** James Forshaw (most CVEs in this class)

### Pattern 3: Named Pipe Impersonation

**Trigger:** Attacker creates a named pipe, induces SYSTEM service to connect.
Calls `ImpersonateNamedPipeClient` to steal the SYSTEM token.
**Key prerequisite:** `SeImpersonatePrivilege` (default for IIS, MSSQL, SQL Agent, many service accounts)
**Tool:** PrintSpoofer, RoguePotato, SweetPotato, GodPotato
**Researcher:** itm4n, Decoder

### Pattern 4: Installer/Repair File Operations

**Trigger:** Advertised MSI repair or Windows Update/installer process performs
file operations as SYSTEM, following paths influenced by registry or filesystem state.
**Key APIs:** `MoveFileEx`, junction/symlink at staging path
**Researcher:** Naceri, SandboxEscaper, various

### Pattern 5: Kernel Use-After-Free (win32k)

**Trigger:** Reference counting error or object lifecycle bug in win32k or ntoskrnl
leaves a pointer to freed memory. Heap spray/grooming reclaims the free with attacker data.
**Key components:** `win32k.sys`, `win32kfull.sys`, `win32kbase.sys`
**Mitigation target:** Kernel pool integrity checks, Virtualization-Based Security (HVCI)
**Researcher:** j00ru, Valentina Palmiotti, various APT-disclosed bugs

### Pattern 6: Vulnerable Kernel Driver IOCTL

**Trigger:** Third-party or OEM kernel driver exposes IOCTL without privilege check.
Provides kernel R/W, physical memory access, or MSR manipulation from user mode.
**Key search method:** `IDA Pro / Ghidra IOCTL handler analysis`, `DriverQuery`
**Tool:** KDMapper, kdexploit framework, individual PoCs
**Researcher:** Matteo Malvica, various hardware vendor CVEs

---

## Conversion Techniques: Primitive → SYSTEM

| Primitive | Conversion Method | Notes |
|-----------|------------------|-------|
| Arbitrary file write (SYSTEM) | Overwrite `C:\Windows\System32\` DLL | Requires service restart or DLL not yet loaded |
| Arbitrary file write (SYSTEM) | Write to `C:\Windows\System32\Tasks\` for scheduler | Scheduler re-runs as SYSTEM |
| Arbitrary file delete (SYSTEM) | Delete protected DLL → plant replacement | Plant before service restarts |
| Arbitrary file move (SYSTEM) | Move attacker DLL to trusted location | Then trigger load |
| Kernel R/W | Overwrite `EPROCESS.Token` | Point to elevated token |
| Kernel R/W | Overwrite `TOKEN.Privileges` | Enable SeDebugPrivilege or similar |
| Named pipe impersonation | `ImpersonateNamedPipeClient` + `CreateProcessAsUser` | Requires `SeImpersonatePrivilege` |
| Arbitrary DACL write | Set `DACL=NULL` on SYSTEM binary → overwrite | Full access from low-priv |

---

## Tooling for CVE Reproduction

| Tool | Purpose | Source |
|------|---------|--------|
| `PrivescCheck` | Automated Windows LPE enumeration | https://github.com/itm4n/PrivescCheck |
| `NtObjectManager` (PS) | Object namespace exploration, symlink/junction ops | https://github.com/tyranid/sandbox-attacksurface-analysis-tools |
| `PrintSpoofer` | Named pipe impersonation PoC | https://github.com/itm4n/PrintSpoofer |
| `RoguePotato` | COM impersonation LPE | https://github.com/antonioCoco/RoguePotato |
| `GodPotato` | Modern potato variant (Windows 10-11) | https://github.com/BeichenDream/GodPotato |
| `SetOpLock` | Opportunistic lock for race condition exploitation | SAAT toolkit |
| `WinObj` / `NtObjectManager` | Object directory browsing | Sysinternals / SAAT |
| `Process Monitor` | File/registry access tracing for race identification | Sysinternals |
| `WinDbg Preview` | Kernel debugging for UAF/memory corruption | Microsoft Store |
| `x64dbg / x32dbg` | User-mode debugging, exploit dev | https://x64dbg.com/ |

---

## CVE Research Workflow

```
1. IDENTIFY: Read MSRC advisory → note component, affected versions, bug class (CWE)
2. DIFF: Download patched vs unpatched binaries → BinDiff / Diaphora comparison
3. UNDERSTAND: Read researcher's original write-up or Project Zero issue
4. REPRODUCE: Set up VM with vulnerable version → confirm PoC runs
5. ANALYZE: Add instrumentation (ProcMon, WinDbg) to understand the primitive
6. GENERALIZE: Identify the pattern → which "recurring pattern" category?
7. DOCUMENT: Add to personal knowledge base with root cause + primitive + chain
```

---

## VM Setup for CVE Research

**Recommended base images (for offline research):**
- Windows 10 1903 (pre-many-2020-patches) — broad PoC compatibility
- Windows 10 21H2 — modern target, post most 2021 patches
- Windows 11 22H2 — modern mitigations (HVCI, CET, XFG active)
- Windows Server 2019 — service/AD context research

**Essential tools on research VM:**
- Process Monitor (Sysinternals)
- WinDbg Preview
- NtObjectManager PowerShell module
- PrivescCheck
- x64dbg
- Ghidra or IDA Free
