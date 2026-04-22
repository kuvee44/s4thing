# 04 — Object Manager Namespace

> **Prerequisites:** Section 01 (Foundations) — specifically the object manager chapter
> from Windows Internals. Section 03 (Security Model) — security descriptors and access
> checks on kernel objects.
>
> **Estimated study time:** 2–4 weeks for initial pass; return frequently as a reference
> when analyzing real vulnerabilities.

---

## What This Section Covers

The Windows Object Manager is the kernel component that manages all named kernel objects — files (via device objects), registry keys, processes, threads, tokens, sections, named pipes, events, mutexes, semaphores, ALPC ports, and more. Every object lives in a hierarchical namespace rooted at `\`.

This section covers:
- The object namespace structure and how names resolve
- How security is enforced on the namespace itself (not just on objects)
- Symbolic links and how they enable path substitution attacks
- The device map mechanism and its security implications
- Practical attack techniques derived from namespace properties

---

## Why Object Manager Research Matters

The object namespace is one of the most underexplored and richest attack surfaces in Windows privilege escalation. A single decade of research by James Forshaw produced dozens of high-severity CVEs from this attack surface. Key insights:

### 1. The Namespace is a Security Boundary
Every object directory has a security descriptor. If a lower-privileged process can create objects in a directory that a higher-privileged process looks up names in, it can substitute a malicious object — a classic **object squatting** attack.

### 2. Path Resolution is Not Atomic
Between when a privileged process validates a path and when it acts on the resolved object, a TOCTOU window exists. Symbolic links and junctions allow an attacker to redirect the path resolution during this window.

### 3. The Device Map is Per-Process (and Per-Impersonation)
`\??` (the DosDevices directory) resolves differently for different processes and different impersonation states. A privileged process resolving `C:\something` under impersonation can be redirected to a different device.

### 4. Registry Symlinks are Little-Known but Powerful
Registry keys support a symlink type (`REG_LINK`) that allows redirecting registry lookups — a mechanism analogous to filesystem symbolic links, applicable in arbitrary write → EoP chains.

---

## Section Structure

```
04_object_manager_namespace/
├── README.md          ← This file
├── RESOURCES.md       ← Annotated resource list (start here)
└── NOTES.md           ← Research notes, attack diagrams, code snippets
```

---

## Recommended Learning Path

### Phase 1: Namespace Architecture (Days 1–3)

**Goal:** Be able to navigate the object namespace and explain how names resolve.

1. Read **O-001** (Windows Internals — Object Manager chapter)
2. Install WinObj (Sysinternals) and spend 30 minutes exploring the namespace
3. Install NtObjectManager and explore via PowerShell:
   ```powershell
   Install-Module NtObjectManager
   ls NtObject:\
   ls NtObject:\Device
   ls NtObject:\BaseNamedObjects
   ```

4. Use WinDbg to inspect objects live:
   ```windbg
   !object \
   !object \Device
   !object \BaseNamedObjects
   ```

### Phase 2: Namespace Security (Days 4–7)

**Goal:** Understand how security descriptors on object directories create attack surface.

1. Read **O-002** (Windows Security Internals — Object Namespace section)
2. Inspect security descriptors on key directories:
   ```powershell
   # Who can create objects in \BaseNamedObjects?
   Get-NtSecurityDescriptor -Path \BaseNamedObjects -TypeName Directory |
     Show-NtSecurityDescriptor

   # Per-session namespace
   Get-NtSecurityDescriptor -Path "\Sessions\1\BaseNamedObjects" -TypeName Directory |
     Show-NtSecurityDescriptor
   ```

3. **Lab:** Find at least one object directory where standard users can create objects.

### Phase 3: Symbolic Link Attacks (Week 2)

**Goal:** Understand all symbolic link types and at least one attack chain.

1. Read **O-003** (Forshaw — Symbolic Link Attacks)
2. Clone and explore **O-004** (symbolic-link-testing-tools)
3. Implement a simple junction + oplock TOCTOU in the lab

Key experiment:
```
1. Create directory C:\TestDir as a regular user
2. Create junction C:\TestDir → C:\Windows\System32\drivers (replace the directory)
3. Observe: a process that writes to C:\TestDir\foo.txt now writes to System32\drivers\foo.txt
   (if it opens by path before following)
```

### Phase 4: Device Map and Advanced Topics (Week 3)

**Goal:** Understand device map attacks and registry symlinks.

1. Read **O-007** (Device Map research)
2. Read **O-008** (Registry symlinks)
3. Study Forshaw's "Arbitrary Write → EoP" methodology
4. Find and analyze one CVE from each category

---

## Object Namespace Attack Surface Summary

```
╔═══════════════════════════════════════════════════════════════╗
║          OBJECT MANAGER NAMESPACE ATTACK SURFACE              ║
╠═════════════════════════════╦═════════════════════════════════╣
║ Attack Type                 ║ What's Required                  ║
╠═════════════════════════════╬═════════════════════════════════╣
║ Object Directory Squatting  ║ Write access to directory        ║
║                             ║ + privileged process does lookup ║
╠═════════════════════════════╬═════════════════════════════════╣
║ NTFS Junction Attack        ║ Write access to parent dir       ║
║                             ║ + privileged process accesses    ║
║                             ║ + TOCTOU window exists           ║
╠═════════════════════════════╬═════════════════════════════════╣
║ Object Manager Symlink      ║ Create access in target dir      ║
║                             ║ (e.g. \BaseNamedObjects)         ║
╠═════════════════════════════╬═════════════════════════════════╣
║ DosDevice Override          ║ DefineDosDevice (user session)   ║
║                             ║ + privileged code resolves \??\  ║
╠═════════════════════════════╬═════════════════════════════════╣
║ Oplock TOCTOU               ║ Oplock on file involved in       ║
║                             ║ privileged operation             ║
╠═════════════════════════════╬═════════════════════════════════╣
║ Registry Symlink            ║ Write access to source key       ║
║                             ║ + privileged code writes to it   ║
╠═════════════════════════════╬═════════════════════════════════╣
║ Hard Link Abuse             ║ Create hard link to target       ║
║                             ║ + privileged code creates/       ║
║                             ║   writes to file by name         ║
╠═════════════════════════════╬═════════════════════════════════╣
║ Device Map Substitution     ║ Control impersonated user's      ║
║                             ║ device map + privileged code     ║
║                             ║ resolves path while impersonating║
╚═════════════════════════════╩═════════════════════════════════╝
```

---

## Practical: Auditing the Object Namespace

### Find Object Directories Where Standard Users Can Create Objects
```powershell
# Find directories in root namespace writable by current user
Get-AccessibleObject -NtType Directory -Path \ -Recurse -AccessRights CreateObject |
  Format-Table Name, GrantedAccess

# Check BaseNamedObjects specifically
$sd = Get-NtSecurityDescriptor -Path \BaseNamedObjects -TypeName Directory
Test-NtAccessMask -SecurityDescriptor $sd -Access CreateObject
```

### Enumerate Device Map
```powershell
# Show drive letter mappings in current session
ls NtObject:\??  # DosDevices virtual directory

# Show what C: maps to
(Get-NtSymbolicLink -Path "\??\C:").Target
```

### Registry Symlink Detection
```powershell
# Find REG_LINK values (registry symlinks) in current user hive
Get-ItemProperty -Path HKCU:\* | Where-Object { $_.PSObject.Properties.Name -contains "(default)" }
# Better: use Get-NtKey to enumerate with type
```

### Inspect Named Pipe Security
```powershell
# Enumerate all named pipes and their security descriptors
ls NtObject:\Device\NamedPipe | ForEach-Object {
  try {
    $sd = Get-NtSecurityDescriptor -Path "\Device\NamedPipe\$($_.Name)" -TypeName File
    [PSCustomObject]@{
      Name = $_.Name
      SDDL = $sd.ToSddl()
    }
  } catch {}
}
```

---

## Connection to Real CVEs

| CVE | Object Manager Component | Technique |
|-----|-------------------------|-----------|
| Multiple (2015–2023) | Object Manager symlink | Object directory squatting |
| CVE-2018-0983 | NTFS junction + oplock | Arbitrary write → EoP |
| CVE-2021-36934 | Filesystem object ACL | SAM hive world-readable |
| Multiple Forshaw bugs | Device map | Impersonated device map substitution |
| Multiple (registry) | Registry symlinks | Arbitrary registry write redirect |
| CVE-2015-2554 | Object Manager namespace | BaseNamedObjects squatting |

---

## Key Tools for This Section

| Tool | Source | Purpose |
|------|--------|---------|
| WinObj | Sysinternals | GUI namespace browser |
| NtObjectManager | PSGallery | PowerShell namespace access |
| symboliclink-testing-tools | GitHub/googleprojectzero | Attack toolkit |
| Process Monitor | Sysinternals | Path resolution tracing |
| WinDbg + NT symbols | Microsoft | Kernel-level namespace inspection |
| AccessChk | Sysinternals | Permission enumeration |

---

## Research Methodology: Finding Object Namespace Bugs

### Step 1: Identify Privileged Code Paths
- Find a service or privileged process that accesses named objects (files, registry, named pipes, events, etc.)
- Use Process Monitor to log all object accesses with path = target
- Identify: What names does it look up? What does it create?

### Step 2: Evaluate Attacker Control
For each name accessed by the privileged process:
- Can a lower-privileged attacker create an object with that name first?
- Can a lower-privileged attacker modify the object after the privileged process validates but before it uses?
- Can a lower-privileged attacker change the path resolution between validation and access?

### Step 3: Check Mitigations
- Does the code use `OBJ_DONT_REPARSE`? → Symlink attacks blocked
- Does the code use `OBJ_IGNORE_IMPERSONATED_DEVICEMAP`? → Device map attacks blocked
- Does the code use `FILE_OPEN_NO_RECALL` or other flags that limit TOCTOU?
- Is the directory protected with a restrictive DACL?

### Step 4: Build the Exploit Primitive
- Choose the appropriate tool: junction, oplock, DosDevice, object symlink, registry symlink
- Chain primitives to reach privilege escalation

---

*Section: 04_object_manager_namespace | Last updated: 2026-04-22*
