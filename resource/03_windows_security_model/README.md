# 03 — Windows Security Model

> **Prerequisites:** Section 01 (Foundations) — understand processes, threads, handles,
> kernel objects, and the object manager before diving deep into the security model.
>
> **Estimated study time:** 4–8 weeks for solid coverage; this section has the highest
> direct yield for privilege escalation vulnerability research.

---

## What This Section Covers

The Windows security model is the framework that governs *who can do what* on a Windows system. It consists of interconnected components:

- **Access Tokens** — the credential object attached to every thread and process
- **Security Descriptors** — the permission object attached to every securable object
- **Security Reference Monitor** — the kernel component that performs access checks
- **Mandatory Integrity Control (MIC)** — the integrity level sub-system
- **User Account Control (UAC)** — the privilege elevation mechanism
- **AppContainer** — the UWP/browser sandbox model
- **Authentication stack** — Kerberos, NTLM, LSA, credential storage

Understanding this model at the implementation level — not just the conceptual level — is the difference between finding privilege escalation bugs systematically and finding them by accident.

---

## Why This Section Has the Highest Research Yield

Every Windows privilege escalation vulnerability is, at its core, a violation of the security model:

| Vulnerability Pattern | Security Model Component Violated |
|----------------------|----------------------------------|
| `SeImpersonatePrivilege` → SYSTEM | Token impersonation level semantics |
| UAC bypass | UAC auto-elevation decision logic |
| World-writable system directory | Security descriptor on filesystem object |
| COM server reachable from AppContainer | AppContainer isolation policy |
| LSASS credential dump | Process access control + PPL |
| Token stealing | Token/object lifetime + access check |
| HiveNightmare | Security descriptor on registry hive |
| PrintNightmare (LPE component) | Security descriptor on spooler directory |

The security model is not a layer on top of Windows — it *is* the enforcement mechanism for every access decision. If you understand it deeply, you can find bugs in it.

---

## Section Structure

```
03_windows_security_model/
├── README.md          ← This file
├── RESOURCES.md       ← Annotated resource list (start here)
└── NOTES.md           ← Research notes, attack patterns, WinDbg commands
```

---

## Recommended Learning Path

### Phase 1: Token and Access Check Fundamentals (Week 1–2)

**Goal:** Be able to explain exactly what happens during a `CreateFile` call at the security layer.

1. Read **S-001 (Windows Security Internals)** Chapters 1–5:
   - Tokens: structure, fields, impersonation levels
   - Security descriptors: DACL, SACL, ACE types
   - Access check algorithm: `SeAccessCheck` walk-through
   - Mandatory Integrity Control

2. Alongside reading, run in PowerShell:
   ```powershell
   Install-Module NtObjectManager
   $tok = Get-NtToken -Current
   $tok.IntegrityLevel
   $tok | Get-NtTokenPrivilege
   $tok | Get-NtTokenGroup
   ```

3. Use WinDbg to inspect a live token:
   ```windbg
   !process 0 0 notepad.exe
   dt nt!_TOKEN <token_addr>
   ```

### Phase 2: UAC, Integrity Levels, and Impersonation (Week 3–4)

**Goal:** Understand how UAC split-token works and how impersonation can be abused.

1. Complete **S-001** Chapters 6–10
2. Read **S-004** (UAC documentation)
3. Study the Potato attack family timeline (S-009)

Lab exercises:
- Use `Get-NtToken -Linked` to get the linked elevated token
- Create a medium-integrity process and verify IL with NtObjectManager
- Study `PrintSpoofer` source code and trace its impersonation chain

### Phase 3: AppContainer and Sandbox (Week 5–6)

**Goal:** Understand AppContainer isolation well enough to identify an escape.

1. Read **S-006** (AppContainer Internals — Forshaw blog post)
2. Run a UWP app and inspect its token:
   ```powershell
   Get-NtProcess | Where-Object {$_.AppContainer} |
     Select-Object Name, AppContainerSid
   ```
3. Enumerate what an AppContainer process can access:
   ```powershell
   # Start calculator as AppContainer
   $proc = New-NtProcess -Win32Path C:\Windows\System32\calc.exe -AppContainer
   Get-AccessibleFile -Process $proc -Win32Path C:\Windows\System32\
   ```

### Phase 4: Credential Architecture (Week 7–8)

**Goal:** Understand how credentials are stored, where they can be stolen, and what protections exist.

1. Read **S-010** (LSA documentation + Mimikatz wiki)
2. Set up a lab: Windows Server with AD, domain-joined Windows 10 VM
3. Practice: dump creds from LSASS, extract SAM, use Pass-the-Hash

---

## Security Model Cheat Sheet

### Token Field → What It Controls

| Token Field | Controls |
|-------------|---------|
| `User SID` | Primary identity for access checks |
| `Groups[]` | Additional SIDs evaluated in DACL check |
| `Privileges` | Enabled/Disabled/Removed — kernel operations |
| `ImpersonationLevel` | Anonymous/Identify/Impersonate/Delegate |
| `IntegrityLevel` | MIC policy enforcement |
| `AppContainerSid` | AppContainer namespace and capability check |
| `Capabilities[]` | AppContainer capability SIDs |
| `IsRestricted` | Whether RestrictedSids[] apply |
| `RestrictedSids[]` | Whitelist filter (must pass both DACL and restricted check) |

### Access Check Algorithm (Simplified)

```
SeAccessCheck(SecurityDescriptor, Token, DesiredAccess):
  1. If Token is SeTcbPrivilege or owner matches: may bypass some checks
  2. MIC check: if Token.IL < Object.MinimumLabel AND policy prevents → DENY
  3. If Token is restricted: run access check twice (once with Groups, once with RestrictedSids)
     → GrantedAccess = intersection of both results
  4. Walk DACL entries in order:
     a. DENY ACE matching Token SID → remove from GrantedAccess
     b. ALLOW ACE matching Token SID → add to GrantedAccess
     c. Stop when DesiredAccess fully granted or DACL exhausted
  5. If NULL DACL: grant all access
  6. If no DACL entry grants remaining desired access → DENY remainder
```

### Integrity Level SIDs

| Level | SID | Typical holder |
|-------|-----|----------------|
| Untrusted (0) | S-1-16-0 | Explicitly untrusted processes |
| Low (1) | S-1-16-4096 | IE Protected Mode, some sandboxes |
| Medium (2) | S-1-16-8192 | Standard user processes |
| Medium+ (3) | S-1-16-8448 | Task Scheduler |
| High (4) | S-1-16-12288 | Elevated processes, admin tokens |
| System (5) | S-1-16-16384 | SYSTEM services |
| Protected (6) | S-1-16-20480 | PPL processes (anti-malware) |

---

## Key CVE Examples Mapping to This Section

| CVE | Bug Class | Security Model Component |
|-----|-----------|--------------------------|
| CVE-2021-36934 (HiveNightmare) | ACL misconfiguration | Security descriptor on SAM/SYSTEM/SECURITY hives |
| CVE-2021-1675 (PrintNightmare LPE) | Directory ACL + driver load | DACL on spooler driver dir + SeLoadDriverPrivilege |
| CVE-2019-1388 | COM elevation abuse | UAC COM elevation moniker |
| CVE-2020-0796 (SMBGhost, LPE) | Memory corruption → token steal | Pool exploit → token impersonation |
| CVE-2022-21882 | Win32k UAC bypass | User32/Win32k message hook elevation |
| Potato variants (many CVEs) | SeImpersonatePrivilege | Token impersonation level |

---

## Lab Exercises

### Exercise 1: Security Descriptor Audit
```powershell
# Find registry keys writable by standard users
Get-AccessibleKey -Win32Path HKLM:\SYSTEM\CurrentControlSet\Services `
  -AccessRights WriteKey -AllUsers | Format-Table Name, GrantedAccess
```

### Exercise 2: Token Comparison
```powershell
# Compare medium vs high integrity tokens
$medium = Get-NtToken -Current
$high = Get-NtToken -Linked  # Get the elevated linked token

# Compare privileges
$medium | Get-NtTokenPrivilege | Where-Object Enabled
$high | Get-NtTokenPrivilege | Where-Object Enabled
```

### Exercise 3: Impersonation Chain
```powershell
# Create a named pipe server and impersonate a client
$pipe = New-NtNamedPipeFile -Path \Device\NamedPipe\TestPipe `
  -ShareMode Read,Write -Access GenericReadWrite
# Have another process connect, then:
$pipe | Invoke-NtToken { Get-NtToken -Current }
```

### Exercise 4: AppContainer Analysis
```powershell
# List all AppContainer processes and their package SIDs
Get-NtProcess | Where-Object {$_.AppContainer} | ForEach-Object {
  $tok = $_.OpenToken()
  [PSCustomObject]@{
    Name = $_.Name
    PID  = $_.ProcessId
    PackageSid = $tok.AppContainerSid
    Capabilities = ($tok | Get-NtTokenGroup -Capabilities) -join ", "
  }
  $tok.Close()
}
```

---

*Section: 03_windows_security_model | Last updated: 2026-04-22*
