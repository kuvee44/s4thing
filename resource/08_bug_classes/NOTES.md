# 08 · Bug Classes — NOTES

## Taxonomy of Windows LPE Bug Classes

This document provides a structured taxonomy of Windows Local Privilege Escalation bug classes, their relationships, and the key concepts linking them. Use this alongside RESOURCES.md as a mental map.

---

## Level 1: Primitive Capability

All Windows LPE bugs reduce to one or more of these raw capabilities:

| Primitive | Description | Example APIs |
|-----------|-------------|--------------|
| **Arbitrary File Write** | Write attacker-controlled data to an attacker-chosen path | NtWriteFile, CopyFile via privileged process |
| **Arbitrary File Move/Rename** | Move/rename a file to an attacker-chosen destination | NtSetInformationFile(FileRenameInformation), MoveFileEx |
| **Arbitrary File Delete** | Delete a file at an attacker-chosen path | NtDeleteFile, DeleteFile via privileged process |
| **Arbitrary Directory Create** | Create a directory at an attacker-chosen path | CreateDirectory via privileged process |
| **Token Capture/Impersonation** | Obtain a token for a higher-privilege principal | ImpersonateNamedPipeClient, NtImpersonateThread |
| **Code Execution as SYSTEM** | Execute code in a SYSTEM-level context | CreateProcessAsUser, kernel token replacement |

---

## Level 2: Attack Classes

Attack classes combine primitives with Windows-specific mechanisms:

### 2.1 Filesystem Redirect Attacks

**Mechanism:** Redirect a privileged file operation to an attacker-controlled target using NTFS link types.

```
Vulnerability type: Privileged process opens path without OBJ_DONT_REPARSE
                   AND path is partially attacker-controlled

Attack structure:
  [Privileged Process]
        ↓ opens C:\Legitimate\Path\file.dll
  [NTFS Junction at C:\Legitimate\Path\]
        ↓ redirects to C:\AttackerDir\
  [Attacker DLL at C:\AttackerDir\file.dll]
        ↓ loaded as SYSTEM
  [Code execution as SYSTEM]
```

**Link types used:**
- NTFS junctions (most common — require only `FILE_WRITE_ATTRIBUTES` on directory)
- NTFS file symlinks (require SeCreateSymbolicLinkPrivilege or developer mode)
- Object manager symlinks (in `\??\` — require no special privilege)
- Mount points (require CreateFile access to directory)
- Hard links (require `FILE_WRITE_ATTRIBUTES` on target file directory)

**Enabling conditions:**
- Missing `OBJ_DONT_REPARSE` flag in NtCreateFile call
- Missing `FILE_FLAG_OPEN_REPARSE_POINT` in Win32 CreateFile call
- Impersonation dropped before file operation (many Windows services do this)

**Key mitigations:**
- `OBJ_DONT_REPARSE` / `FILE_FLAG_OPEN_REPARSE_POINT`
- Canonicalizing paths before privileged operations
- Running privileged operations with impersonated (non-SYSTEM) token

---

### 2.2 Token Impersonation Chains

**Mechanism:** Cause a SYSTEM-level process to authenticate to an attacker-controlled endpoint, then impersonate the resulting token.

```
Vulnerability type: Privileged process can be induced to connect to attacker-controlled
                   named pipe / RPC server

Attack structure:
  [Attacker creates named pipe: \\.\pipe\TARGET]
        ↓ waits for connection
  [Coercion: call API that makes SYSTEM connect to \\.\pipe\TARGET]
  (Print Spooler / Task Scheduler / EFS / DCOM etc.)
        ↓ SYSTEM connects to attacker's pipe
  [ImpersonateNamedPipeClient()]
        ↓ attacker now has SYSTEM token
  [CreateProcessWithToken() or token duplicate]
        ↓ SYSTEM shell
```

**Coercion methods (roughly chronological):**
1. DCOM activation (Rotten/Juicy Potato) — restricted in Win10 1809+
2. DCOM OXID resolver relay (RoguePotato) — requires helper machine
3. Print Spooler pipe (PrintSpoofer) — still works; spooler disable breaks it
4. Task Scheduler RPC (GodPotato) — works on Server 2012–2022
5. EFS RPC (SweetPotato variant) — partially patched
6. Local NTLM reflection (LocalPotato / CVE-2023-21746)

**Enabling condition:** Target process must have `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege`

**Key mitigation:** Restricting SeImpersonate grant to only truly necessary service accounts; network-level NTLM restrictions for relay variants

---

### 2.3 DLL Search Order Hijacking

**Mechanism:** Place an attacker-controlled DLL in a location that a privileged process searches before the legitimate DLL.

```
DLL search order (simplified, non-Safe-DLL mode):
  1. Same directory as the EXE
  2. System directory (GetSystemDirectory)
  3. Windows directory
  4. Current directory
  5. PATH directories

Attack: Place evil.dll in step N where privileged process searches,
        before legitimate evil.dll location at step N+1
```

**Enabling conditions:**
- Privileged process loads DLL from a user-writable directory
- DLL not specified with full path
- `LoadLibraryEx` without `LOAD_LIBRARY_SEARCH_SYSTEM32` flag
- Missing signature verification on loaded DLL

**Common triggers:**
- MSI repair (msiexec /fa) loading DLLs from application directory
- Windows service loading DLLs from %TEMP% or application data
- Arbitrary file write into a DLL search path slot

**Key mitigations:**
- `LOAD_LIBRARY_SEARCH_SYSTEM32` flag
- Code signing enforcement for loaded DLLs
- Removing world-write permission from DLL search paths

---

### 2.4 Windows Installer Repair / Update Flows

**Mechanism:** Trigger a Windows Installer repair operation that runs as SYSTEM and operates on user-influenced paths.

```
Attack structure:
  [msiexec /fa {ProductCode}] ← can be called by any user
        ↓ runs as SYSTEM
  [Reinstalls application files]
        ↓ searches for DLLs in installer cache + application directory
  [Attacker pre-planted DLL in application directory]
        ↓ loaded as SYSTEM
```

**Enabling conditions:**
- AlwaysInstallElevated policy (most dangerous — allows any MSI to run as SYSTEM)
- MSI packages that load DLLs from user-writable directories during repair
- MSI packages that execute scripts/binaries from user-writable locations

**Tooling:** Process Monitor during `msiexec /fa`; Orca MSI editor for package analysis; hijacklibs.net database

---

## Level 3: Attack Families and Their Evolution

### The "Potato" Family

```
Rotten Potato (2016)
  └─► [DCOM activation trigger → NTLM loopback → token capture]
      Mitigation: DCOM loopback restriction (Win10 1809+)
      
Juicy Potato (2018)
  └─► [Extended CLSID list for DCOM trigger]
      Mitigation: Same loopback restriction
      
RoguePotato (2020)
  └─► [OXID resolver on remote machine bypasses loopback restriction]
      Limitation: Requires helper machine / network
      
SweetPotato (2020)
  └─► [Combines EfsRpc + WebClient + PrintSpoofer variants]
      
PrintSpoofer (2020)
  └─► [Print Spooler pipe — no DCOM needed, single machine]
      Mitigation: Disable Print Spooler service
      
GodPotato (2022)
  └─► [ITaskSchedulerService RPC coercion — Server 2012-2022]
      
LocalPotato (2023)
  └─► [Local NTLM reflection — no pipe squatting needed]
      CVE-2023-21746
```

### The "Coercion" Family

```
PrintNightmare (2021)
  └─► [MS-RPRN RpcAddPrinterDriverEx — SYSTEM DLL load]
      └─► [MS-RPRN coercion → NTLM relay]
      
PetitPotam (2021)
  └─► [MS-EFSR EfsRpcOpenFileRaw — unauthenticated coercion]
      Partial patch: authentication now required
      
DFSCoerce (2022)
  └─► [MS-DFSNM NetrDfsRemoveStdRoot — NTLM coercion]
      
ShadowCoerce (2022)
  └─► [MS-FSRVP — Volume Shadow Copy coercion]
      
Coercer Tool
  └─► [Systematic survey of all coercible methods]
```

---

## Relationship Map

```
                    ┌─────────────────────────────────────────────────────┐
                    │           ARBITRARY FILESYSTEM PRIMITIVES            │
                    │  Write ←→ Move ←→ Delete ←→ Dir Create ←→ Dir Read  │
                    └──────────────────────┬──────────────────────────────┘
                                           │ enables
                          ┌────────────────┼─────────────────┐
                          ↓                ↓                  ↓
                    DLL Hijacking    Path Redirect      Hardlink/Junction
                          │          (via Junction)      (via NTFS link)
                          │                │                  │
                          └────────────────┴──────────────────┘
                                           │
                                           ↓
                              SYSTEM CODE EXECUTION (LPE)
                                           
                    ┌────────────────────────────────────────┐
                    │        TOKEN IMPERSONATION              │
                    │  SeImpersonate + Coercion Method        │
                    │  (Potato / PrintSpoofer / Coercion)     │
                    └──────────────────┬─────────────────────┘
                                       │
                                       ↓
                           ImpersonateNamedPipeClient
                              → Token Duplication
                              → SYSTEM Shell
```

---

## Key Questions When Analyzing a New LPE Bug

1. **What filesystem primitive does the bug provide?** (write / move / delete / read / dir create)
2. **Can the primitive target arbitrary paths, or only constrained paths?** (constrained may still be exploitable with junction tricks)
3. **Does the privileged process use `OBJ_DONT_REPARSE`?** (if not, junction/symlink attacks may be possible)
4. **Is there a reliable trigger?** (installer repair, cleanup service, scheduled task, user-initiated action)
5. **What is the execution context of the trigger?** (SYSTEM / NETWORK SERVICE / specific account?)
6. **Can oplock + junction be used to win any TOCTOU window?**
7. **What is the resulting primitive?** (code execution / token / credential theft?)
8. **What is the exploit chain?** (primitive → trigger → code execution → privilege)

---

## Common Mitigations and Their Coverage

| Mitigation | Covers |
|------------|--------|
| `OBJ_DONT_REPARSE` in NtCreateFile | Junction/symlink redirect attacks on file opens |
| Canonicalize paths before operation | Junction/symlink attacks on path construction |
| SeImpersonate restriction | Most Potato-family attacks |
| Disable Print Spooler | PrintSpoofer + PrintNightmare coercion |
| RPC Firewall rules | MS-EFSR, MS-RPRN, MS-DFSNM coercion methods |
| Code signing for loaded DLLs | DLL hijacking (partial — many legitimate apps don't sign DLLs) |
| Removing world-write from DLL paths | DLL search order hijacking |
| AlwaysInstallElevated = 0 | MSI elevation abuse |
| Impersonation before file ops | Many privileged service TOCTOU bugs |

---

*Last updated: 2026-04-22*
