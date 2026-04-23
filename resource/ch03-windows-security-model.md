# Chapter 03 — Windows Security Model

> The Windows security model — tokens, security descriptors, ACLs, integrity levels, impersonation, AppContainers — is the primary attack surface for privilege escalation and sandbox escape. Before finding bugs here, you must understand the model precisely enough to know when a behavior violates it. This chapter builds that model from the ground up.

---

## 1. Token Anatomy

Every thread and process has an associated *access token*. The token is the identity credential used for all access checks on the machine.

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
        → For restricted tokens: also check RestrictedSids list
     c. If match:
        - ACCESS_DENIED_ACE and (ACE.AccessMask & DesiredAccess) != 0:
          → DENY immediately (deny ACEs are checked before allow ACEs for explicit ACEs)
        - ACCESS_ALLOWED_ACE and (ACE.AccessMask & DesiredAccess):
          → Mark those bits as granted

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

### SeRelabelPrivilege

Allows a process to change an object's mandatory label. Normally, you can only lower an object's label (to match or below your own level). With `SeRelabelPrivilege`, you can raise it. Rarely granted, but some AV/EDR products grant it — overlooked escalation vector.

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

### LPAC (Less Privileged AppContainer)

LPAC removes even the `ALL APPLICATION PACKAGES` / `ALL RESTRICTED APPLICATION PACKAGES` grants, limiting access further. The Edge render process runs in LPAC. Most AppContainer escape vulnerabilities involve finding objects that grant `ALL APPLICATION PACKAGES` access without the LPAC exception.

### Escape Patterns

- Object with `ALL APPLICATION PACKAGES: WRITE` but not LPAC-aware → AppContainer can write, LPAC process cannot
- COM server registered accessible to AppContainer but implementing a dangerous operation
- Named pipe with `ALL APPLICATION PACKAGES: CONNECT` → AppContainer can connect and impersonate

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

## 9. Key Security APIs

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
```

---

## 10. Security Model Bug Patterns

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
