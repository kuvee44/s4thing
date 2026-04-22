# 04 — Object Manager Namespace: Resource List

> **Section purpose:** Master the Windows Object Manager namespace — the kernel's naming
> system for all securable kernel objects. The object namespace is a critical attack
> surface for privilege escalation, sandbox escape, and TOCTOU vulnerabilities.
>
> **Prerequisites:** Section 01 (Foundations) — particularly object manager internals.
> Section 03 (Security Model) — particularly how security descriptors apply to named objects.

---

## Resource Index

| # | Title | Type | Priority | Tag |
|---|-------|------|----------|-----|
| O-001 | Windows Internals Part 1 — Object Manager Chapter | Book Chapter | PRIMARY | FOUNDATIONAL |
| O-002 | Windows Security Internals — Object Namespace Section | Book Chapter | PRIMARY | FOUNDATIONAL |
| O-003 | James Forshaw — Object Manager Research | Blog/Research | HIGH | PROJECT-ZERO |
| O-004 | Symbolic Link Testing Tools | Tool / Source | HIGH | LAB-WORTHY |
| O-005 | NtObjectManager — Object Manager PowerShell Interface | Tool / Source | HIGH | LAB-WORTHY |
| O-006 | Object Manager Namespace — Geoff Chappell Deep Analysis | Reference | MEDIUM | DEEP-INTERNALS |
| O-007 | Device Map and OBJ_IGNORE_IMPERSONATED_DEVICEMAP | Blog/Research | HIGH | PROJECT-ZERO |
| O-008 | Registry Object Security and Hive Loading | Documentation + Research | MEDIUM | REGISTRY |

---

## Detailed Entries

---

### O-001 — Windows Internals Part 1 — Object Manager Chapter

- **Title:** Windows Internals, Part 1 — Chapter 8: Object Manager (Chapter numbering varies by edition)
- **Author / Organization:** Mark Russinovich, David Solomon, Alex Ionescu, Pavel Yosifovich
- **URL:** https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals
  - Part 1, Chapter on "System Mechanisms" and "Object Manager"
- **Resource type:** Book chapter (foundational reference)
- **Topic tags:** `object-manager` `object-header` `object-types` `object-namespace` `handle-tables` `reference-counting` `named-objects` `object-directory` `symbolic-links` `device-map` `object-attributes` `OB_OPEN_REASON`
- **Difficulty:** Advanced
- **Historical or current:** Current (7th edition covers Windows 10/11)
- **Trust level:** ★★★★★ — Authoritative; written by kernel engineers
- **Why it matters:**
  The Object Manager is the naming fabric of the Windows kernel. Every named kernel object — files, registry keys, named pipes, mutexes, events, semaphores, sections, device objects — exists in the object namespace. Understanding how the namespace resolves names, how symbolic links work, how security is enforced on directory objects, and how the device map affects path resolution is foundational for understanding object manager attack surfaces.
- **What it teaches:**
  - Object header structure: `_OBJECT_HEADER`, type index, reference counts, security descriptor pointer
  - Object types: `_OBJECT_TYPE` (File, Process, Thread, Token, Section, Key, ALPC Port, etc.)
  - Object directory (`\`, `\Device`, `\DosDevices`, `\Sessions`, `\KernelObjects`, etc.)
  - Symbolic link objects: how `\DosDevices\C:` resolves to `\Device\HarddiskVolume3`
  - Handle table: per-process, per-kernel, inheritance
  - Object name lookup: `ObpLookupObjectName` and the `OBJ_*` attribute flags
  - Device map: per-session device map, how `\??` is resolved per-process
  - Reference counting and object lifetime
  - Object callbacks (ObRegisterCallbacks)
- **Best use:**
  Read this chapter first, then immediately explore the live namespace with WinObj (Sysinternals) and NtObjectManager. Navigate from `\` to `\Device` to `\DosDevices` to understand how every file path in Windows maps through the namespace.
- **Related bug classes / primitives:**
  `object directory squatting` `symbolic link attacks` `TOCTOU via symbolic link reparse` `device map attacks` `object handle inheritance abuse` `object type confusion`
- **Suggested next resource:** O-002 (security model coverage of the same topic) then O-003 (Forshaw attack research)
- **Notes:**
  - WinObj (Sysinternals) is the best visualization tool for the object namespace
  - `\DosDevices` is a symbolic link to `\??` which is actually a per-session virtual directory backed by the device map
  - The object namespace is explored with `NtOpenDirectoryObject` / `NtQueryDirectoryObject` (NT native API)
  - Essential WinDbg commands:
    ```windbg
    !object \                    ; root directory
    !object \Device              ; device directory
    !object \DosDevices          ; DosDevices symlink
    dt nt!_OBJECT_DIRECTORY      ; directory object structure
    dt nt!_OBJECT_SYMBOLIC_LINK  ; symlink structure
    ```

---

### O-002 — Windows Security Internals — Object Namespace Section

- **Title:** Windows Security Internals — Object Manager Security and Namespace Chapters
- **Author / Organization:** James Forshaw (No Starch Press, 2023)
- **URL:** https://nostarch.com/windows-security-internals
  - Chapters covering: Object Manager security, named object security, per-session namespace, AppContainer namespace
- **Resource type:** Book chapters (security-focused reference)
- **Topic tags:** `object-security` `named-object-security` `object-directory-DACL` `per-session-namespace` `AppContainer-namespace` `BaseNamedObjects` `Sessions` `object-creation-security` `SDDL-on-objects` `object-directory-attacks`
- **Difficulty:** Advanced
- **Historical or current:** Current
- **Trust level:** ★★★★★ — Forshaw is the primary researcher in this area
- **Why it matters:**
  Forshaw's book adds the security research perspective to what Windows Internals describes. It explains how security descriptors on object directories work, what the per-session namespace isolation provides (and where it fails), how AppContainer processes get their own isolated namespace, and what attack paths exist through the object namespace.
- **What it teaches:**
  - Security descriptor on `_OBJECT_DIRECTORY`: who can create objects in the directory, who can look up names
  - `\BaseNamedObjects` vs. `\Sessions\<N>\BaseNamedObjects`: how per-session isolation works
  - AppContainer namespace: `\Sessions\<N>\AppContainerNamedObjects\<PackageSid>\`
  - How a medium-integrity process can create a named object in `\BaseNamedObjects` that poisons a lookup done by a high-integrity process
  - Object directory DACL attacks: if a lower-privilege process can create objects in a directory that a higher-privilege process looks up by name, it can substitute a malicious object
  - `OBJ_INHERIT`, `OBJ_PERMANENT`, `OBJ_EXCLUSIVE`, `OBJ_CASE_INSENSITIVE` flag security implications
  - How `\DosDevices` (the device map) is resolved and what the per-process device map means for sandboxing
- **Best use:**
  Read after O-001 to get the security perspective. Use NtObjectManager's `ls NtObject:\` to navigate the namespace and inspect security descriptors on object directories. This chapter directly enables object squatting attack research.
- **Related bug classes / primitives:**
  `BaseNamedObjects squatting` `object directory DACL misconfiguration` `per-session namespace bypass` `AppContainer namespace escape` `named object poisoning`
- **Suggested next resource:** O-003 (Forshaw's actual research papers on these attacks) and O-004 (symbolic link testing tools)
- **Notes:**
  - Key security question per object directory: Who can create objects in this directory? (DACL `OB_WRITE_DACL`, `OB_CREATE_OBJECT`)
  - `\BaseNamedObjects` on a default Windows install: Authenticated Users can create objects — this is intentional but creates attack surface
  - AppContainer namespace: AppContainer process gets its own subdirectory, isolated from main `\BaseNamedObjects`

---

### O-003 — James Forshaw — Object Manager Attack Research

- **Title:** Object Manager Namespace Security Research — tiraniddo.dev and Project Zero
- **Author / Organization:** James Forshaw / Google Project Zero
- **URL:**
  - tiraniddo.dev: https://www.tiraniddo.dev/
  - "Abusing Windows Symbolic Links" (BHUSA 2015): https://www.youtube.com/watch?v=pYRddwBhcZo (video)
  - "Windows Exploitation Tricks: Exploiting Arbitrary File Writes for Local Elevation of Privilege": https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html
  - "Exploiting Arbitrary Object Directory Creation for Local Elevation of Privilege" (2021): https://googleprojectzero.blogspot.com/2021/01/exploiting-arbitrary-object-directory.html
  - "Symlink Testing Tools" writeup: https://googleprojectzero.blogspot.com/2015/08/windows-10-symbolic-link-mitigations.html
  - "OBJ_DONT_REPARSE": https://www.tiraniddo.dev/2019/09/
  - ALPC/LPC security: multiple posts on tiraniddo.dev
- **Resource type:** Research blog posts + conference talks
- **Topic tags:** `symbolic-link-attack` `object-directory-squatting` `OBJ_DONT_REPARSE` `file-hard-link` `junction-point` `NTFS-reparse-point` `arbitrary-write-exploit` `TOCTOU` `ALPC-object-security` `object-creation-race`
- **Difficulty:** Advanced to Expert
- **Historical or current:** Current — techniques evolve but underlying concepts are stable
- **Trust level:** ★★★★★ — Forshaw discovered most of these attack classes and holds dozens of CVEs exploiting them
- **Why it matters:**
  Forshaw's research is the primary source for practical object manager namespace attacks. His work on symbolic link attacks, object directory squatting, and the `OBJ_DONT_REPARSE` flag directly enabled a decade of privilege escalation vulnerabilities. Understanding his research gives you the playbook for finding these bugs independently.
- **What it teaches:**
  - **Symbolic link attacks:** How a user-mode symlink (junction, NTFS symlink, object manager symlink) can redirect a privileged process's file/object access
  - **Object directory squatting:** Creating a malicious object in `\BaseNamedObjects` before a privileged process creates its legitimate object
  - **`OBJ_DONT_REPARSE` flag:** Added in Windows 10 to prevent object manager symbolic link traversal during lookup; how its absence is a bug
  - **Arbitrary file write → EoP:** If you have an arbitrary file write primitive, you can exploit it via:
    - `C:\Windows\System32\` DLL planting (if writable)
    - Registry symlink → redirect registry write to arbitrary key
    - Junction + hardlink + opportunistic lock (oplock) chains
  - **TOCTOU via oplock:** `NtCreateFile` → oplock → attacker runs → `NtWriteFile` → race window exploitation
  - **Hard link attacks:** If you can create a hard link to a privileged file, you can redirect writes
  - **Junction attacks:** If a privileged process creates a directory then uses it, planting a junction before the use redirects it
- **Best use:**
  Read Forshaw's BH 2015 talk first (fundamental overview), then read individual blog posts for specific techniques. Use symbolic-link-testing-tools (O-004) to replicate the attacks in a lab.
- **Related bug classes / primitives:**
  `NTFS junction attack` `object manager symlink attack` `oplock-based TOCTOU` `hard link planting` `arbitrary write → EoP` `object squatting` `OBJ_DONT_REPARSE absence` `reparse point attack`
- **Suggested next resource:** O-004 (lab tools), O-007 (device map attacks)
- **Notes:**
  - The "arbitrary file write → EoP" blog post is a must-read — it presents a general methodology
  - Key tool for this research: `CreateSymbolicLink` (requires SeCreateSymbolicLinkPrivilege or Developer Mode) vs. NTFS junctions (no privilege required)
  - NTFS junctions can be created by unprivileged users; NTFS symlinks require privilege
  - Object Manager symlinks can be created in `\??` if you have the right permissions

---

### O-004 — Symbolic Link Testing Tools

- **Title:** symboliclink-testing-tools — Windows Symbolic Link and Object Manager Attack Toolkit
- **Author / Organization:** James Forshaw / Google Project Zero
- **URL:** https://github.com/googleprojectzero/symboliclink-testing-tools
  - Individual tools: CreateSymlink, CreateDosDevice, CreateMountPoint, NtApiDotNet exploits
  - Companion blog: https://googleprojectzero.blogspot.com/2015/08/windows-10-symbolic-link-mitigations.html
- **Resource type:** Open-source exploit toolkit (LAB-WORTHY)
- **Topic tags:** `symbolic-link-testing` `NTFS-junction` `object-manager-symlink` `DosDevice-creation` `oplock` `directory-junction` `lab-tool` `PoC-framework`
- **Difficulty:** Intermediate to Advanced
- **Historical or current:** Current — actively used in recent PoC exploits
- **Trust level:** ★★★★★ — Reference implementation by the primary researcher in this area
- **Why it matters:**
  This toolkit is the primary lab tool for Windows symbolic link and object manager namespace attack research. It provides ready-to-use implementations of the building blocks for:
  - Creating NTFS junctions and symbolic links
  - Creating object manager symbolic links (DosDevice creation)
  - Oplock-based TOCTOU exploitation
  - Simulating arbitrary file write primitives for EoP research
- **What it teaches / enables:**
  - `CreateSymlink.exe` — creates NTFS symbolic links and junctions
  - `CreateDosDevice.exe` — creates `\DosDevices\X:` style device mappings
  - `CreateMountPoint.exe` — creates NTFS mount points (junctions)
  - Oplock server — holds an oplock on a file to create a TOCTOU window
  - `NtApiDotNet` — .NET library for NT native API calls (used by many PoC tools)
  - Helper scripts that implement the full "arbitrary write → EoP" chain
- **Best use:**
  Set up a Windows 10 lab VM. Clone the repo. Work through Forshaw's blog posts while running the tools. Use to develop custom PoC exploits for newly found file write primitives.
- **Related bug classes / primitives:**
  `arbitrary file write → EoP` `NTFS junction attack` `oplock TOCTOU` `DosDevice squatting` `object symlink attack`
- **Suggested next resource:** O-003 (conceptual background) — read before or alongside using these tools
- **Notes:**
  - Requires Windows 10 for full functionality; some features need Developer Mode for symlinks
  - `NtApiDotNet` is a separate, more complete .NET library for NT API access: https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools/tree/main/NtApiDotNet
  - Most modern Windows EoP PoC tools are built on NtApiDotNet

---

### O-005 — NtObjectManager — Object Manager PowerShell Interface

- **Title:** NtObjectManager PowerShell Module (part of sandbox-attacksurface-analysis-tools)
- **Author / Organization:** James Forshaw / Google Project Zero
- **URL:** https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools
  - PSGallery: `Install-Module NtObjectManager`
  - Object manager documentation: https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools/wiki
- **Resource type:** Tool / PowerShell module (LAB-WORTHY)
- **Topic tags:** `NtObjectManager` `object-namespace-exploration` `object-security` `symbolic-link-inspection` `object-directory-traversal` `named-pipe-security` `section-object` `ALPC-port` `device-object`
- **Difficulty:** Intermediate
- **Historical or current:** Current — actively maintained
- **Trust level:** ★★★★★ — Primary tool for object manager research
- **Why it matters:**
  NtObjectManager provides a PowerShell drive provider (`NtObject:\`) that maps directly to the Windows object manager namespace. You can navigate the namespace with `ls`, inspect security descriptors on object directories, and create/open any type of named NT object. It is indispensable for object namespace research.
- **What it teaches / enables:**
  - Navigate object namespace: `ls NtObject:\`, `ls NtObject:\Device`, etc.
  - Open and inspect named objects: `Get-NtObject -Path \BaseNamedObjects\SomeEvent`
  - Inspect security descriptors on object directories: `Get-NtSecurityDescriptor -Path \BaseNamedObjects`
  - Create object manager symbolic links: `New-NtSymbolicLink -Path \DosDevices\Z: -Target \Device\HarddiskVolume3`
  - Enumerate all accessible objects from a given privilege context
  - Open and inspect ALPC ports, named pipes, section objects, device objects
  - Enumerate `\Sessions\<N>\AppContainerNamedObjects\` for AppContainer namespace analysis
- **Best use:**
  Install and use alongside every section of this chapter. Run `ls NtObject:\` as the first step in any object namespace audit. Use `Get-NtSecurityDescriptor` on every object directory you find.
- **Related bug classes / primitives:**
  `object directory squatting` (find insecure directories to squat in), `object symlink research`, `AppContainer namespace analysis`
- **Suggested next resource:** Apply to hands-on research using O-004 for attack implementation
- **Notes:**
  ```powershell
  # Essential commands for object namespace exploration
  ls NtObject:\                           # Root namespace
  ls NtObject:\Device                    # Device directory
  ls NtObject:\BaseNamedObjects          # User-mode named objects
  ls "NtObject:\Sessions\1\BaseNamedObjects"  # Per-session named objects

  # Security descriptor on a directory
  Get-NtSecurityDescriptor -Path \BaseNamedObjects -TypeName Directory |
    Show-NtSecurityDescriptor

  # Create an object symlink (requires appropriate privileges)
  New-NtSymbolicLink -Path \BaseNamedObjects\TestLink -TargetPath \Device\Null

  # Enumerate what's accessible in a namespace
  Get-AccessibleObject -NtType Directory -Path \

  # Find named pipes and their security descriptors
  ls NtObject:\Device\NamedPipe |
    ForEach-Object { Get-NtSecurityDescriptor -Object $_ }
  ```

---

### O-006 — Geoff Chappell — Object Manager Deep Analysis

- **Title:** Windows Object Manager — Geoff Chappell's Deep Technical Analysis
- **Author / Organization:** Geoff Chappell
- **URL:** https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ob/
  - NTOSKRNL API documentation: https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/
  - Object type documentation: https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ob/obp/type.htm
- **Resource type:** Deep technical analysis (reference)
- **Topic tags:** `object-header` `object-type-table` `TypeIndex` `OBJECT_HEADER_CREATOR_INFO` `OBJECT_HEADER_NAME_INFO` `OBJECT_HEADER_QUOTA_INFO` `OBJECT_HEADER_PROCESS_INFO` `ObpTypeObjectType` `ObpDirectoryObjectType`
- **Difficulty:** Expert
- **Historical or current:** Mixed — some articles cover older Windows versions; check version notes
- **Trust level:** ★★★★☆ — Chappell's analysis is meticulous and based on deep reverse engineering; occasionally has minor version-specific inaccuracies
- **Why it matters:**
  Geoff Chappell's site provides the most detailed publicly available analysis of Windows kernel internal structures — more detailed than Windows Internals in many areas. His object manager coverage includes exact structure layouts, type index tables, and the precise behavior of `ObpLookupObjectName`. Essential for kernel exploit development that manipulates object headers.
- **What it teaches:**
  - Exact layout of `_OBJECT_HEADER` and its optional header parts (name info, creator info, quota info, handle info, process info, audit info, padding info, extended info)
  - `TypeIndex` encoding in `_OBJECT_HEADER` (XOR'd with `ObHeaderCookie` on Windows 8+) — relevant for type confusion exploitation
  - `_OBJECT_TYPE` structure and the type object table
  - `_OBJECT_DIRECTORY` internal structure: hash buckets, lookup algorithm
  - `ObpLookupObjectName`: full walk of the name resolution algorithm
  - Object creation sequence: `ObCreateObject` → type-specific alloc → header init → namespace insertion
- **Best use:**
  Use as reference when writing kernel exploits that involve object headers. Use to verify WRK-derived understanding against modern Windows builds. Essential when working on type confusion or object header corruption exploits.
- **Related bug classes / primitives:**
  `object type confusion` (TypeIndex corruption) `object header corruption` `object directory hash collision` `ObpLookupObjectName behavior exploitation`
- **Suggested next resource:** WRK source (F-010 from section 01) for the historical implementation; then compare with live WinDbg analysis
- **Notes:**
  - The `TypeIndex` in `_OBJECT_HEADER` is XOR'd with a per-boot cookie (`ObHeaderCookie`) on Windows 8+
  - Corrupting `TypeIndex` → type confusion → wrong dispatch table → kernel code execution (used in pool overflow exploits)
  - Formula: `TypeIndex = (object_header_address >> 8) XOR ObHeaderCookie XOR ObpObjectTypes[index]->Index`

---

### O-007 — Device Map and OBJ_IGNORE_IMPERSONATED_DEVICEMAP Research

- **Title:** Device Map Security and OBJ_IGNORE_IMPERSONATED_DEVICEMAP — Forshaw Research
- **Author / Organization:** James Forshaw / Google Project Zero
- **URL:**
  - "SandboxEscaper Exploit Analysis — Device Map" related analysis on tiraniddo.dev
  - "Abusing Access Tokens for UAC Bypasses" (mentions device map): https://www.tiraniddo.dev/
  - Project Zero issue: various device map related bugs
  - Windows documentation on device map: (mostly internal; Geoff Chappell covers it)
  - Forshaw device map research: search tiraniddo.dev for "device map"
  - "Sandboxed NTLM Downgrade Attacks": https://googleprojectzero.blogspot.com/2019/04/
- **Resource type:** Research blog posts
- **Topic tags:** `device-map` `DosDevices` `OBJ_IGNORE_IMPERSONATED_DEVICEMAP` `session-device-map` `per-process-device-map` `drive-letter-attack` `DosDevice-squatting` `impersonation-device-map`
- **Difficulty:** Expert
- **Historical or current:** Current
- **Trust level:** ★★★★★ — Forshaw is the primary researcher in this area
- **Why it matters:**
  The device map is the mechanism that backs the `\??` object directory (aka `\DosDevices`) — the per-session virtual directory that maps drive letters and device names. The device map is process-specific (inherited from the session) and can be manipulated in specific scenarios. Forshaw's research shows how device map manipulation enables attacks where a process resolves a path differently than expected by a privileged caller.
- **What it teaches:**
  - Device map architecture: `_EPROCESS.DeviceMap` points to a `_DEVICE_MAP` structure
  - `\??\` is resolved via the calling process's device map — it is NOT a fixed namespace location
  - Under impersonation: the device map used for `\??\` path resolution is the **impersonating thread's device map** by default — this can be exploited
  - `OBJ_IGNORE_IMPERSONATED_DEVICEMAP`: when set, the object manager uses the process's device map even when the calling thread is impersonating a different user — this flag was added as a security fix
  - Absence of `OBJ_IGNORE_IMPERSONATED_DEVICEMAP` in a privileged path resolution creates a device map substitution attack
  - How to create a custom device map and associate it with a thread during impersonation
  - Per-session device map: each logon session has a device map; impersonating a user may switch device maps
- **Best use:**
  Study after understanding basic impersonation (S-001/S-003) and object namespace (O-001/O-002). Essential for understanding a class of subtle path substitution bugs that arise in impersonating services.
- **Related bug classes / primitives:**
  `device map substitution` `\??\path redirection via impersonation` `drive letter squatting` `DosDevice attack` `impersonation + path resolution bug`
- **Suggested next resource:** O-003 (Forshaw symlink research) for related path substitution techniques
- **Notes:**
  - The device map is stored in `_EPROCESS` and `_ETHREAD` (during impersonation) — inspect with:
    ```windbg
    dt nt!_EPROCESS <addr> DeviceMap
    dt nt!_DEVICE_MAP <addr>
    ```
  - `\??\` is NOT a real directory in the object namespace — it is resolved dynamically via device map lookup
  - This is one of the more subtle and underexplored attack surfaces in Windows

---

### O-008 — Registry Object Security and Hive Loading

- **Title:** Registry Internals, Security, and Hive Loading Attacks
- **Author / Organization:** Microsoft (primary documentation); James Forshaw, Yarden Shafir (research)
- **URL:**
  - Registry security: https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-security-and-access-rights
  - Registry hive loading: https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regloadkey
  - NtLoadKey / NtLoadKeyEx: https://ntdoc.m417z.com/ (search NtLoadKey)
  - Yarden Shafir — Registry hive loading vulnerabilities: research blog
  - CVE-2021-36934 (HiveNightmare): affected registry hive ACLs
  - "Windows Exploitation Tricks: Exploiting Arbitrary File Writes" (Forshaw) — registry symlink section: https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html
- **Resource type:** Documentation + research posts
- **Topic tags:** `registry-security` `registry-hive` `NtLoadKey` `hive-loading-attack` `registry-symlink` `registry-ACL` `SAM-hive` `SYSTEM-hive` `SECURITY-hive` `HiveNightmare` `shadow-copy-ACL`
- **Difficulty:** Advanced
- **Historical or current:** Current
- **Trust level:** ★★★★☆ — Official docs + verified researcher posts
- **Why it matters:**
  The registry is a named object in the object manager (`\REGISTRY\` subtree). Registry keys have security descriptors. The hive loading mechanism (`NtLoadKey`) creates a security boundary. Registry symbolic links (a lesser-known feature) allow registry key redirection similar to filesystem symbolic links. All of these create attack surfaces that have yielded real CVEs.
- **What it teaches:**
  - Registry object in namespace: `\REGISTRY\MACHINE\SAM`, `\REGISTRY\USER\<SID>`, etc.
  - Registry key security: how DACLs and SACLs apply to registry keys
  - Registry hive loading: `RegLoadKey` / `NtLoadKey` / `NtLoadKeyEx` — loading an offline hive file into the registry namespace
  - Hive loading security: what checks are performed? Can an unprivileged process load a hive into a privileged namespace location?
  - Registry symbolic links: `REG_LINK` value type; how registry key lookups can be redirected
  - Forshaw's arbitrary write → EoP via registry symlink: redirect a write from a writable key to a sensitive key
  - HiveNightmare root cause: VSS shadow copy ACL inheritance incorrectly allowed standard users to read the SAM/SYSTEM/SECURITY hives under `C:\Windows\System32\config\`
  - Yarden Shafir's research on hive loading as an attack primitive
- **Best use:**
  Study the Forshaw "arbitrary write → EoP" post specifically for the registry symlink technique. Study HiveNightmare for the ACL misconfiguration pattern. Essential for understanding registry as an attack surface.
- **Related bug classes / primitives:**
  `registry symlink attack` `hive loading attack` `registry ACL misconfiguration` `SYSTEM hive read` `SAM extraction` `HiveNightmare variant` `NtLoadKey abuse`
- **Suggested next resource:** Section 03 (Security Model — S-008) for the SD misconfiguration angle; Section 05 for exploit primitives using registry symlinks
- **Notes:**
  - Registry symbolic links are created via `NtSetValueKey` with type `REG_LINK`
  - To exploit: create `HKCU\Software\Classes\<key>` (user-writable) as a symlink to `HKLM\<sensitive key>` — then trick a privileged process into writing via the user-accessible path
  - The object namespace path for registry: `\REGISTRY\MACHINE\` = HKLM, `\REGISTRY\USER\<SID>\` = HKCU
  - Check registry key ACLs with NtObjectManager:
    ```powershell
    Get-NtSecurityDescriptor -Win32Path HKLM:\SAM -TypeName Key |
      Show-NtSecurityDescriptor
    ```

---

## Object Namespace Cheat Sheet

### Key Namespace Locations

```
\                               Root object directory
├── Device\                     Device objects (HarddiskVolumeN, NamedPipe, etc.)
│   └── NamedPipe\              Named pipe objects
├── DosDevices → \??            Symlink to per-session DosDevices
├── ??\ (per-process)           Drive letters, device aliases (via device map)
│   ├── C: → \Device\HV3        C: drive symlink
│   └── UNC → \Device\Mup       UNC path
├── BaseNamedObjects\           User-mode named objects (events, mutexes, semaphores)
├── Sessions\                   Per-session directory
│   └── <N>\
│       ├── BaseNamedObjects\   Per-session named objects
│       ├── AppContainerNamedObjects\
│       │   └── <PackageSid>\   AppContainer-isolated named objects
│       └── DosDevices\         Per-session drive letters
├── REGISTRY\                   Registry namespace root
│   ├── MACHINE\                HKLM
│   └── USER\                   HKU (per-user hives)
├── KernelObjects\              Kernel-managed objects (low memory, etc.)
└── Windows\                    Windowing system objects
```

### Object Attribute Flags

| Flag | Value | Effect |
|------|-------|--------|
| `OBJ_INHERIT` | 0x002 | Handle inherited by child processes |
| `OBJ_PERMANENT` | 0x010 | Object persists after last handle closes |
| `OBJ_EXCLUSIVE` | 0x020 | Only one handle allowed at a time |
| `OBJ_CASE_INSENSITIVE` | 0x040 | Name lookup case-insensitive |
| `OBJ_OPENIF` | 0x080 | Open existing or create new |
| `OBJ_OPENLINK` | 0x100 | Open symbolic link itself, not target |
| `OBJ_KERNEL_HANDLE` | 0x200 | Handle accessible only from kernel mode |
| `OBJ_FORCE_ACCESS_CHECK` | 0x400 | Perform access check even in kernel mode |
| `OBJ_DONT_REPARSE` | 0x1000 | Do not follow symlinks during lookup |
| `OBJ_IGNORE_IMPERSONATED_DEVICEMAP` | 0x2000 | Use process device map, not impersonated one |

### Symbolic Link Attack Types

| Type | API | Privilege Needed | Redirection Level |
|------|-----|-----------------|-------------------|
| NTFS junction (mount point) | `CreateDirectoryJunction` or `fsutil` | None (on owned dir) | Directory-level |
| NTFS symlink | `CreateSymbolicLink` | SeCreateSymbolicLinkPrivilege OR Developer Mode | File or dir |
| Object Manager symlink | `NtCreateSymbolicLinkObject` | Low — can create in `\BaseNamedObjects` | Object namespace |
| DosDevice override | `DefineDosDevice` | None (for user session) | Drive letter / device name |
| Registry symlink | `NtSetValueKey` with REG_LINK | Write access to source key | Registry key |
| Hard link | `CreateHardLink` | None (on same volume, own file) | File identity redirect |

---

## WinDbg Object Manager Commands

```windbg
; Navigate namespace
!object \                        ; root directory
!object \Device                  ; device directory  
!object \Device\NamedPipe        ; named pipe device
!object \BaseNamedObjects        ; user named objects

; Inspect object structures
dt nt!_OBJECT_HEADER <addr>      ; object header
dt nt!_OBJECT_DIRECTORY <addr>   ; directory structure
dt nt!_OBJECT_SYMBOLIC_LINK <addr> ; symbolic link target
dt nt!_DEVICE_MAP <addr>         ; device map structure

; Find object by name
!object \Device\Harddisk0\DR0

; Dump EPROCESS device map
dt nt!_EPROCESS <pid_or_addr> DeviceMap

; Object type index table
dt nt!ObpObjectTypes

; Header cookie (for TypeIndex decoding)
? nt!ObHeaderCookie
```

---

*Last updated: 2026-04-22 | Section: 04_object_manager_namespace*
