# Security Model — Research Notes

> Running notes on the Windows security model: attack patterns, WinDbg commands,
> PowerShell snippets, and research observations.

---

## Core Mental Model: The Three Gating Checks

Every access attempt in Windows passes through up to three sequential gates:

```
Request: Process P wants Access A on Object O
                          │
                          ▼
┌─────────────────────────────────────────────┐
│ Gate 1: MIC (Mandatory Integrity Control)   │
│                                             │
│ If Token.IntegrityLevel < Object.MinLabel   │
│ AND MIC policy flag applies:                │
│   → DENY immediately                        │
│   (regardless of DACL)                      │
└──────────────────┬──────────────────────────┘
                   │ Pass
                   ▼
┌─────────────────────────────────────────────┐
│ Gate 2: DACL (Discretionary ACL)            │
│                                             │
│ Walk ACEs in order:                         │
│   DENY ACE matching → remove from granted  │
│   ALLOW ACE matching → add to granted      │
│ NULL DACL → grant everything               │
│ Empty DACL → deny everything               │
└──────────────────┬──────────────────────────┘
                   │ Pass
                   ▼
┌─────────────────────────────────────────────┐
│ Gate 3: AppContainer Capability Check       │
│ (only if token is low-box/AppContainer)     │
│                                             │
│ Does object have AppContainer ACE?          │
│ If no → deny (AC cannot access non-AC-      │
│          labeled object unless explicitly   │
│          granted)                           │
│ Does token have required capability SID?    │
│   Yes → grant; No → deny                   │
└──────────────────┬──────────────────────────┘
                   │ Pass
                   ▼
                Access Granted
```

**Key insight for research:** A bug in MIC allows an attack from Gate 2 (DACL) alone. A bug in Gate 2 logic allows access below the DACL intent. A bug in Gate 3 allows AppContainer escape.

---

## Token Impersonation Levels — Decision Table

| Level | Can check identity? | Can impersonate locally? | Can delegate remotely? | Notes |
|-------|--------------------|--------------------------|-----------------------|-------|
| Anonymous | No | No | No | Completely anonymous |
| Identification | Yes | No | No | Identity visible but no impersonation; cannot open objects as this user |
| Impersonation | Yes | Yes | No | Can impersonate locally; most common for services |
| Delegation | Yes | Yes | Yes | Full delegation; constrained/unconstrained delegation in Kerberos |

**Critical rule:** `ImpersonateNamedPipeClient` returns an Impersonation-level token from the connecting client. If the connecting client is SYSTEM, you get a SYSTEM impersonation token. `SetThreadToken` + `CreateProcessWithToken` then elevates.

**The Potato insight:** Service accounts hold `SeImpersonatePrivilege`. If you coerce SYSTEM to connect to your named pipe (via print spooler, DCOM activation, etc.), you get a SYSTEM impersonation token, and with `SeImpersonatePrivilege` you can use it to create a SYSTEM process.

---

## UAC Split-Token Deep Dive

When an admin user logs in, they get TWO tokens (linked pair):
```
Standard User Token (Medium IL)   ←── linked ──→   Admin Token (High IL)
- Admin group DISABLED                               - Admin group ENABLED
- Most admin privileges stripped                     - Full privileges
- Used for: regular processes                        - Used for: elevated processes
```

`TOKEN_LINKED_TOKEN` info class via `NtQueryInformationToken` reveals the linked token.

**UAC bypass techniques categorized:**

| Category | Technique | Example |
|----------|-----------|---------|
| Auto-elevation executable abuse | Side-load DLL into auto-elevating exe | fodhelper.exe, eventvwr.exe |
| COM elevation moniker | Instantiate COM server with elevation | CMSTPLUA, IMsiServer |
| Environment variable abuse | Change %COMSPEC%, %SYSTEMROOT% | Various |
| File system trust path abuse | Plant file in trusted path checked before system32 | DLL search order hijack |
| Registry key abuse | Modify HKCU key checked by auto-elevated exe | fodhelper.exe HKCU check |
| AppInfo service abuse | Direct manipulation of UAC broker | Rare, often patched |

**MS stance:** UAC is NOT a security boundary. UAC bypasses are "defense-in-depth" issues. Medium-integrity code SHOULD be able to bypass UAC (by design intent), even if specific techniques are patched as hardening.

---

## Privilege Abuse Reference

### SeImpersonatePrivilege Attack Chain
```
Service account has SeImpersonatePrivilege
    │
    ├─ Method 1: Named Pipe + Coercion
    │     Create \\.\pipe\test
    │     Coerce SYSTEM auth to pipe (SpoolSample/PetitPotam)
    │     ImpersonateNamedPipeClient()
    │     CreateProcessWithTokenW() → SYSTEM shell
    │
    ├─ Method 2: DCOM Activation
    │     CoCreateInstanceEx with specific CLSID
    │     Catch SYSTEM authentication
    │     (Rotten Potato / Juicy Potato approach)
    │
    └─ Method 3: RPC Coercion
          Various RPC interfaces that trigger SYSTEM → client auth
```

### SeDebugPrivilege Attack Chain
```
SeDebugPrivilege enabled
    │
    ├─ OpenProcess(ALL_ACCESS, FALSE, lsass_pid)  → SYSTEM-level process handle
    ├─ ReadProcessMemory on LSASS → extract credentials
    └─ Inject into LSASS / DuplicateHandle for SYSTEM token
```

### SeLoadDriverPrivilege Attack Chain
```
SeLoadDriverPrivilege enabled
    │
    ├─ Drop vulnerable/malicious driver to disk
    ├─ NtLoadDriver() → kernel code execution
    └─ From kernel: disable DSE, load arbitrary code, token manipulation
```

### SeBackupPrivilege Attack Chain
```
SeBackupPrivilege enabled
    │
    ├─ OpenFile with FILE_FLAG_BACKUP_SEMANTICS → bypass DACL
    ├─ Read C:\Windows\System32\config\SAM → extract NT hashes
    └─ Read C:\Windows\NTDS\ntds.dit → domain hashes (on DC)
```

---

## AppContainer Capability SIDs — Key Capabilities for Research

```
internetClient          S-1-15-3-1    : Outbound internet access
internetClientServer    S-1-15-3-2    : Inbound + outbound internet
privateNetworkClient    S-1-15-3-3    : Private/intranet access
picturesLibrary         S-1-15-3-4    : Access Pictures library
videosLibrary           S-1-15-3-5    : Access Videos library
musicLibrary            S-1-15-3-6    : Access Music library
documentsLibrary        S-1-15-3-7    : Access Documents library
sharedUserCertificates  S-1-15-3-9    : User cert store
enterpriseAuthentication S-1-15-3-8   : Windows auth (NTLM/Kerberos)
removableStorage        S-1-15-3-10   : USB/removable drives
lpacCom                 (LPAC cap)    : COM access in LPAC context
```

**Research angle:** If an AppContainer process has `enterpriseAuthentication` capability, it can perform NTLM authentication — relevant for NTLM relay from a sandboxed context.

---

## Common SDDL Patterns to Recognize

```
SDDL format: O:<owner>G:<group>D:<dacl>S:<sacl>

Common SID abbreviations:
  WD = Everyone (World)
  AU = Authenticated Users
  BA = Built-in Administrators
  SY = Local System (SYSTEM)
  BU = Built-in Users
  IU = Interactive Users
  SU = Service
  LS = Local Service
  NS = Network Service
  AC = All Application Containers (S-1-15-2-1)
  ML = Mandatory Label

Example SDDL with MIC:
  D:(A;;GA;;;WD)(A;;GA;;;SY)S:(ML;;NW;;;ME)
  →  DACL: Everyone-GenericAll, SYSTEM-GenericAll
     SACL: Mandatory label Medium, No Write Up

Dangerous patterns:
  D:(A;;GA;;;WD)      → Everyone has full access (NULL equivalent risk)
  D:               	  → NULL DACL → full access to everyone
  (A;;WDWO;;;AU)      → Authenticated Users can write DACL and write owner
```

---

## Real CVE Analysis Notes

### CVE-2021-36934 (HiveNightmare / SeriousSam)
- **Root cause:** SAM, SYSTEM, and SECURITY registry hives in `C:\Windows\System32\config\` had overly permissive ACLs allowing `BUILTIN\Users` (standard users) to read them, due to VSS shadow copies inheriting wrong permissions
- **Impact:** Any local user could read NT password hashes → pass-the-hash, offline cracking
- **Security model component:** Security descriptor on filesystem objects
- **Detection with NtObjectManager:**
  ```powershell
  Get-NtSecurityDescriptor -Win32Path C:\Windows\System32\config\SAM -TypeName File |
    Show-NtSecurityDescriptor
  # Look for any ACE granting read access to non-admin users
  ```

### CVE-2019-1388 (Windows Certificate Dialog UAC Bypass)
- **Root cause:** Windows Certificate dialog ran as elevated process (High IL); clicking "Show information about this publisher" opened a hyperlink in IE, which inherited the High IL token
- **Impact:** UAC bypass — elevated IE window from which cmd.exe could be launched
- **Security model component:** UAC COM elevation moniker; token inheritance on child process
- **Lesson:** Elevated processes must not spawn children (especially browsers) that inherit their elevated token without explicit intent

---

## WinDbg — Security Model Specific Commands

```windbg
# Dump token for current process
!token

# Dump specific token by address
!token <address>

# Dump token for specific process
dt nt!_TOKEN poi(poi(poi(nt!PsGetCurrentProcess)+0x4b8)&~f)

# Full EPROCESS including token pointer
dt nt!_EPROCESS <addr> Token

# Inspect security descriptor of a file object
dt nt!_FILE_OBJECT <addr> SecurityDescriptor
dt nt!_SECURITY_DESCRIPTOR <sd_addr>

# Check SACL
dt nt!_ACL <sacl_addr>
dt nt!_ACCESS_ALLOWED_ACE <ace_addr>

# Integrity level label ACE type = 0x11 (SYSTEM_MANDATORY_LABEL_ACE_TYPE)
```

---

## Open Research Questions

- [ ] What is the exact condition under which `SeImpersonatePrivilege` allows calling `CreateProcessWithTokenW` with a SYSTEM primary token? (vs. requiring `SeAssignPrimaryTokenPrivilege`)
- [ ] Can a Low-IL process write to an object labeled Medium IL if the object has `NO_READ_UP` but not `NO_WRITE_UP`? How does the MIC check interact?
- [ ] How does the AppContainer capability check interact with object ownership? If an AppContainer process owns an object, can it access it despite lacking the relevant capability?
- [ ] What happens to token impersonation during an `NtCreateUserProcess` call — is the impersonation token of the creating thread evaluated, or is the process token used?
- [ ] Does `SeCreateTokenPrivilege` still work on Windows 11 without additional mitigations?

---

*Section: 03_windows_security_model/NOTES.md | Last updated: 2026-04-22*
