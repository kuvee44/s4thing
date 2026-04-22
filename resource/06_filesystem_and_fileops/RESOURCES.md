# 06 · Filesystem and File Operations — RESOURCES.md

> **Section purpose:** Document the Windows filesystem and file operation security research landscape. NTFS, reparse points, symlinks, oplocks, and the NT I/O subsystem are the substrate on which dozens of LPE bug classes are built. This section covers both internals references (understanding how it works) and offensive research (understanding how it breaks).

---

## Table of Contents

1. [Windows Internals — Storage and Filesystem](#1-windows-internals--storage-and-filesystem)
2. [NTFS Internals and Research](#2-ntfs-internals-and-research)
3. [Reparse Points, Symlinks, and Junctions](#3-reparse-points-symlinks-and-junctions)
4. [OpLocks and TOCTOU](#4-oplocks-and-toctou)
5. [Filesystem Security Operations](#5-filesystem-security-operations)
6. [Filter Drivers and Security](#6-filter-drivers-and-security)

---

## 1. Windows Internals — Storage and Filesystem

---

### Entry 1.1

- **Title:** Windows Internals — Storage and File System Chapters
- **Author / Organization:** Mark Russinovich, Alex Ionescu, David Solomon, Andrea Allievi / Microsoft Press
- **URL:** *Windows Internals, Part 2 (8th edition), Chapters on Storage, File System, and I/O* + https://learn.microsoft.com/en-us/sysinternals/
- **Resource type:** Book (foundational reference)
- **Topic tags:** `Windows-internals` `NTFS` `I/O-subsystem` `IRP` `file-system-drivers` `FOUNDATIONAL` `storage`
- **Difficulty:** Intermediate–Advanced
- **Historical or current:** Current (8th edition covers Windows 10/11 and Server 2022)
- **Trust level:** ⭐⭐⭐⭐⭐ — Microsoft Press; co-authored by individuals who wrote significant portions of the Windows kernel
- **Why it matters:** The Windows I/O subsystem (IRP dispatch, file system drivers, filter manager, minifilter drivers) is the architectural foundation for every file-related security vulnerability. Without understanding how file opens are processed (IRP_MJ_CREATE), how security checks are performed (SeAccessCheck in the I/O manager), and how filter drivers intercept operations, filesystem security research is superficial.
- **What it teaches:**
  - The IRP (I/O Request Packet) model: major function codes, completion routines, cancel logic
  - How `NtCreateFile` becomes `IRP_MJ_CREATE` in the filesystem driver
  - NTFS driver architecture: how it processes opens, creates, reads, writes
  - The filter manager (FltMgr): how minifilter drivers intercept I/O
  - Sparse files, volume shadow copies, and their security implications
  - Security descriptors on NTFS files: ACL evaluation during file open
  - The `FILE_OBJECT` structure and its relationship to process context
  - Volume manager and disk structure: partition table, GPT, disk signatures
- **Best use:** Read the I/O system chapter (Part 1) and the storage/file system chapter (Part 2) together. Lab alongside with WinDbg `!irp`, `!fileobj`, and `!drvobj` commands to see live structures.
- **Related bug classes / primitives:** File Security, NTFS Operations, Filter Driver Security, IRP Processing
- **Suggested next resource:** Entry 2.1 (NTFS internals deep dive); Entry 3.1 (reparse points documentation)
- **Notes:** The WDK (Windows Driver Kit) documentation complements Windows Internals for driver-level detail. The `!fileobj` and `!fileext` WinDbg extensions are essential for examining FILE_OBJECT structures live.

---

## 2. NTFS Internals and Research

---

### Entry 2.1

- **Title:** NTFS Internals — Documentation and Research
- **Author / Organization:** Microsoft documentation + libyal/ntfs-3g reverse engineering community + Carrier (Sleuth Kit)
- **URL:** https://learn.microsoft.com/en-us/windows/win32/fileio/ntfs-technical-reference + https://github.com/libyal/libfsntfs/blob/main/documentation/New%20Technologies%20File%20System%20(NTFS).asciidoc + https://flatcap.github.io/linux-ntfs/ntfs/
- **Resource type:** Technical documentation + reverse-engineered specifications
- **Topic tags:** `NTFS` `MFT` `internals` `filesystem-research` `forensics` `security-implications`
- **Difficulty:** Advanced
- **Historical or current:** Current (NTFS format is stable; security research evolves)
- **Trust level:** ⭐⭐⭐⭐ — Microsoft official documentation + community reverse engineering; some gaps remain
- **Why it matters:** Deep NTFS knowledge enables: finding MFT-level bugs (out-of-bounds access in NTFS driver), understanding how hard links work at the MFT record level, building NTFS parsers for forensics/detection, and understanding the security implications of NTFS features like alternate data streams, extended attributes, and object IDs.
- **What it teaches:**
  - MFT (Master File Table) structure: FILE record layout, attribute types (STANDARD_INFORMATION, FILE_NAME, DATA, REPARSE_POINT, SECURITY_DESCRIPTOR)
  - B-tree index structures for directory listings ($I30 index)
  - Hard links at the MFT level: multiple FILE_NAME attributes referencing one MFT record
  - Reparse points at the MFT level: REPARSE_POINT attribute, reparse data buffer structure
  - Alternate Data Streams (ADS): how multiple DATA attributes are stored per MFT record
  - Journal ($UsnJrnl / $LogFile): forensic and detection implications
  - Cluster allocation: `$Bitmap` file and cluster chain tracking
- **Best use:** Read alongside hands-on NTFS exploration with NTFSInfo (Sysinternals), `fsutil`, and raw disk hex editors. Writing an MFT parser is an excellent learning exercise.
- **Related bug classes / primitives:** NTFS Driver Vulnerabilities, Hard Link Security, Reparse Point Abuse, ADS Hiding
- **Suggested next resource:** Entry 3.1 (reparse points security); 08_bug_classes Entry 2.4 (hard link security)
- **Notes:** The `$ATTRIBUTE_LIST` attribute for large files (MFT records exceeding one record) is a common source of NTFS parsing bugs in security tools. The libyal project's NTFS documentation is the most complete public spec.

---

## 3. Reparse Points, Symlinks, and Junctions

---

### Entry 3.1

- **Title:** Reparse Points and Symbolic Links (MSDN)
- **Author / Organization:** Microsoft
- **URL:** https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points + https://learn.microsoft.com/en-us/windows/win32/fileio/symbolic-links
- **Resource type:** Official Microsoft documentation
- **Topic tags:** `reparse-points` `symbolic-links` `junctions` `NTFS` `MSDN` `FOUNDATIONAL`
- **Difficulty:** Intermediate
- **Historical or current:** Current
- **Trust level:** ⭐⭐⭐⭐⭐ — Microsoft official documentation
- **Why it matters:** Reparse points are the NTFS mechanism for symbolic links, junctions, mount points, and OneDrive stub files. Understanding the reparse point data model at the NTFS and Win32 API level is prerequisite for understanding how symlink/junction exploits work at the kernel layer — not just as "tricks" but as documented filesystem behaviors being misused.
- **What it teaches:**
  - Reparse point structure: tag (IO_REPARSE_TAG_SYMLINK, IO_REPARSE_TAG_MOUNT_POINT, etc.), reparse GUID, reparse data buffer
  - Win32 junction creation: `FSCTL_SET_REPARSE_POINT` via `DeviceIoControl`
  - Difference between absolute and relative symbolic link targets
  - Security requirements for creating/deleting reparse points: `FILE_WRITE_ATTRIBUTES` permission on the directory
  - How the I/O manager processes reparse points during path resolution (re-parsing loop, maximum reparse count)
  - `FILE_FLAG_OPEN_REPARSE_POINT`: bypassing symlink traversal for direct file access
- **Best use:** Read both pages fully. Then experiment: create junctions and symlinks using `mklink`, `fsutil reparsepoint`, and raw `DeviceIoControl` to understand each mechanism at the API level.
- **Related bug classes / primitives:** Junction Abuse, Symbolic Link Attacks, NTFS Operations, Mount Point Abuse
- **Suggested next resource:** 08_bug_classes Entry 2.1 (symboliclink-testing-tools); Entry 3.2 (Forshaw research)
- **Notes:** The reparse tag registry (defined in ntifs.h / wdm.h) is the authoritative list of all Microsoft and third-party reparse tags. Third-party reparse tags (e.g., OneDrive stub files) can sometimes be abused similarly to symlinks.

---

### Entry 3.2

- **Title:** Symbolic Link Security — James Forshaw Research (Tyranid's Lair)
- **Author / Organization:** James Forshaw / Google Project Zero
- **URL:** https://www.tiraniddo.dev/ *(search "symbolic link", "reparse point", "junction")*
- **Resource type:** Blog series
- **Topic tags:** `symbolic-links` `junctions` `mount-points` `security-research` `NTFS` `object-manager`
- **Difficulty:** Advanced
- **Historical or current:** Current
- **Trust level:** ⭐⭐⭐⭐⭐
- **Why it matters:** Forshaw's blog is the primary literature on Windows symbolic link security. While MSDN documents how symlinks work, Forshaw documents how they break security boundaries. The combination of Windows-layer symlinks (Win32 symlinks, NTFS junctions, mount points) with NT-layer symlinks (object manager symbolic link objects) creates a complex interaction that enables many attack classes.
- **What it teaches:**
  - The full taxonomy of Windows link types and their security models
  - How the NT object manager namespace intersects with NTFS for symlink resolution
  - The `\??\` DOS device namespace: per-user symlinks without privileges
  - Cross-layer attacks: using an object manager symlink to redirect a file operation through a junction
  - Historical CVEs that were enabled by improper symlink handling in privileged code
- **Best use:** Read in conjunction with Entry 3.1 (MSDN) for a complete layered model. Use `WinObj` (Sysinternals) and `NtObjectManager` to explore the namespace live.
- **Related bug classes / primitives:** All junction/symlink/mount-point attack classes
- **Suggested next resource:** 08_bug_classes Entry 2.1 (lab tools); Entry 4.1 (oplock combination)
- **Notes:** Key posts to find: "Windows Symlinks Revisited" and any post in the "Windows Exploitation Tricks" series touching filesystem operations.

---

## 4. OpLocks and TOCTOU

---

### Entry 4.1

- **Title:** OpLocks and TOCTOU — BaitAndSwitch Technique
- **Author / Organization:** James Forshaw / Google Project Zero
- **URL:** https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html *(oplock section)* + https://github.com/googleprojectzero/symboliclink-testing-tools *(SetOpLock, BaitAndSwitch)*
- **Resource type:** Blog post + tool
- **Topic tags:** `oplock` `TOCTOU` `BaitAndSwitch` `race-condition` `FOUNDATIONAL` `exploit-primitive` `file-system`
- **Difficulty:** Advanced
- **Historical or current:** Current
- **Trust level:** ⭐⭐⭐⭐⭐ — Project Zero primary source
- **Why it matters:** The combination of opportunistic locks with junction swapping (BaitAndSwitch) is the primary technique for converting TOCTOU vulnerabilities in privileged services into reliable exploitation. Without oplocks, exploiting TOCTOU requires unreliable timing. With oplocks, the race window is converted into a deterministic synchronization point — the attacker controls exactly when the privileged operation proceeds.
- **What it teaches:**
  - FSCTL_REQUEST_OPLOCK semantics for the filter oplock type
  - The BaitAndSwitch sequence: (1) place oplock on bait file, (2) wait for privileged process to touch bait, (3) receive break notification, (4) swap junction from bait to real target, (5) release oplock, (6) privileged process operates on real target
  - Why this is "reliable": the privileged process is synchronously blocked until step 5
  - Corner cases: what happens if the privileged process opens the file with `FILE_FLAG_OPEN_REPARSE_POINT`
  - How to detect when a privileged service opens your bait file: oplock notification vs. Process Monitor
- **Best use:** Lab this technique step-by-step using SetOpLock and CreateMountPoint from symboliclink-testing-tools. Use WinDbg kernel debugging to observe the IRP being held pending during the oplock break.
- **Related bug classes / primitives:** TOCTOU, Junction Abuse, Arbitrary File Write, Symlink Attacks
- **Suggested next resource:** 09_exploit_primitives Entry 2.1 (oplocks as exploit primitive); 08_bug_classes Entry 6.1 (BaitAndSwitch utility)
- **Notes:** The filter oplock (`OPLOCK_LEVEL_CACHE_HANDLE | OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_WRITE`) is the most useful variant for this attack. The break callback fires before any data is transferred to the privileged process.

---

## 5. Filesystem Security Operations

---

### Entry 5.1

- **Title:** Arbitrary File Writes for LPE — James Forshaw 2018
- **Author / Organization:** James Forshaw / Google Project Zero
- **URL:** https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html
- **Resource type:** Blog post
- **Topic tags:** `arbitrary-file-write` `LPE` `NTFS` `DLL-hijacking` `junction` `oplock` `FOUNDATIONAL`
- **Difficulty:** Advanced
- **Historical or current:** Current
- **Trust level:** ⭐⭐⭐⭐⭐ — Project Zero; canonical reference
- **Why it matters:** This post is the primary reference for turning arbitrary file write vulnerabilities into full LPE. It bridges the gap between "can write file at arbitrary path" and "executing code as SYSTEM." Every Windows security researcher must understand this chain.
- **What it teaches:**
  - The canonical exploitation path: arbitrary write → create DLL in trusted directory → privileged service DLL search hits attacker DLL → code runs as SYSTEM
  - NtSetInformationFile rename trick for writing to normally inaccessible paths
  - How to use junctions + oplocks (BaitAndSwitch) for reliable exploitation
  - The Windows Installer repair as a trigger mechanism: cause msiexec to "repair" an application, triggering privileged DLL loads
  - Defense: `LoadLibraryEx` with `LOAD_LIBRARY_AS_DATAFILE` or path normalization in privileged loaders
- **Best use:** This is a primary reference — read before studying any specific arbitrary-file-write CVE. Bookmark and return when analyzing new bugs.
- **Related bug classes / primitives:** Arbitrary File Write, DLL Hijacking, Windows Installer Repair, Junction Abuse
- **Suggested next resource:** 08_bug_classes Entry 1.1 (same post, with additional context from that section)
- **Notes:** Cross-referenced in 08_bug_classes section. The Windows Installer repair trigger described here led to dozens of follow-on CVEs over several years.

---

### Entry 5.2

- **Title:** NtCreateFile Object Attributes Flags — Security Implications
- **Author / Organization:** Microsoft WDK documentation + James Forshaw analysis
- **URL:** https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_object_attributes + https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile
- **Resource type:** Official documentation + researcher analysis
- **Topic tags:** `NtCreateFile` `OBJ_ATTRIBUTES` `object-attributes` `security-flags` `Windows-API` `NT-internals`
- **Difficulty:** Advanced
- **Historical or current:** Current
- **Trust level:** ⭐⭐⭐⭐⭐ — Microsoft documentation primary; researcher analysis adds security context
- **Why it matters:** `NtCreateFile` is the lowest-level NT API for file operations, and its `OBJECT_ATTRIBUTES` parameter contains flags that have significant security implications: `OBJ_CASE_INSENSITIVE`, `OBJ_KERNEL_HANDLE`, `OBJ_FORCE_ACCESS_CHECK`, `OBJ_DONT_REPARSE`. Understanding these flags explains why certain code paths are or aren't vulnerable to symlink/junction attacks.
- **What it teaches:**
  - `OBJ_DONT_REPARSE`: prevents reparse point traversal — the key defense flag against junction attacks
  - `OBJ_FORCE_ACCESS_CHECK`: forces access check even in kernel mode — why missing this is a security bug
  - `OBJ_KERNEL_HANDLE`: creates a kernel-only handle (accessible only from kernel mode)
  - How user-mode vs. kernel-mode `NtCreateFile` calls differ in security enforcement
  - Why some privileged services are vulnerable: they call `NtCreateFile` without `OBJ_DONT_REPARSE` when operating on paths influenced by user input
  - `FILE_FLAG_OPEN_REPARSE_POINT` (Win32 equivalent) and when it is/isn't used
- **Best use:** Read alongside NTFS reparse point documentation (Entry 3.1). When auditing privileged file operations, check for `OBJ_DONT_REPARSE` usage.
- **Related bug classes / primitives:** Junction Abuse, Symbolic Link Attacks, NTFS Operations, Privileged Code Auditing
- **Suggested next resource:** Entry 4.1 (oplock combination); 08_bug_classes Entry 2.3 (CVE case studies)
- **Notes:** When auditing code with IDA/Ghidra, search for `NtCreateFile`/`ZwCreateFile` calls in privileged services and check the `Attributes` field for `OBJ_DONT_REPARSE`. Absence of this flag in code that operates on user-influenced paths is a vulnerability indicator.

---

### Entry 5.3

- **Title:** Handle Inheritance and File Security in Windows
- **Author / Organization:** Microsoft MSDN + Windows Internals
- **URL:** https://learn.microsoft.com/en-us/windows/win32/sysinfo/handle-inheritance + https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-lists
- **Resource type:** Official documentation
- **Topic tags:** `handle-inheritance` `file-security` `ACL` `access-control` `security-descriptors` `Windows-API`
- **Difficulty:** Intermediate
- **Historical or current:** Current
- **Trust level:** ⭐⭐⭐⭐⭐ — Microsoft official documentation
- **Why it matters:** Handle inheritance (the ability of child processes to receive inheritable handles) and NTFS ACL semantics are foundational to understanding privilege boundaries in file operations. Inheritance bugs — where a privileged parent unintentionally passes an open file handle to an untrusted child — are a recurring source of security vulnerabilities. ACL misconfiguration is the most common real-world file system security bug.
- **What it teaches:**
  - Handle inheritance mechanics: `SECURITY_ATTRIBUTES.bInheritHandle`, `CreateProcess` `bInheritHandles`, `SetHandleInformation`
  - How inherited handles bypass security checks (the child inherits the access rights of the parent's open)
  - NTFS ACL evaluation: DACL, SACL, owner, group — how `SeAccessCheck` processes ACEs
  - ACE types: `ACCESS_ALLOWED_ACE`, `ACCESS_DENIED_ACE`, `SYSTEM_AUDIT_ACE` — ordering matters
  - Inheritance flags: `OBJECT_INHERIT_ACE`, `CONTAINER_INHERIT_ACE`, `INHERIT_ONLY_ACE`, `NO_PROPAGATE_INHERIT_ACE`
  - Common misconfigurations: world-writable directories with wrong inheritance, missing `DENY` ACEs for critical paths
- **Best use:** Use `icacls`, `Get-Acl`, and Sysinternals Process Explorer (handle tab) together to explore permissions on a live system. Look for world-writable directories in `%ProgramFiles%` and `%SystemRoot%`.
- **Related bug classes / primitives:** File ACL Misconfiguration, Handle Reuse, Privileged Service Security, DLL Hijacking
- **Suggested next resource:** Entry 5.1 (exploitation of permissive paths); Entry 2.1 (NTFS structure for security descriptors)
- **Notes:** `AccessChk` (Sysinternals) is the most powerful tool for finding ACL misconfigurations: `accesschk.exe -w -u "Everyone" c:\windows\system32\` scans for world-writable files/dirs in System32.

---

## 6. Filter Drivers and Security

---

### Entry 6.1

- **Title:** Filesystem Filter Drivers — Security Implications of the Filter Driver Model
- **Author / Organization:** Microsoft WDK documentation + various security researchers
- **URL:** https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/file-system-filter-drivers + https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/about-file-system-filter-drivers
- **Resource type:** Official WDK documentation + researcher analysis
- **Topic tags:** `filter-drivers` `minifilters` `FltMgr` `filesystem-security` `AV-hooks` `EDR` `kernel-drivers`
- **Difficulty:** Advanced
- **Historical or current:** Current
- **Trust level:** ⭐⭐⭐⭐⭐ — Microsoft official documentation
- **Why it matters:** Filesystem filter drivers (minifilters) are the mechanism by which AV/EDR products intercept file I/O for malware detection, encryption products implement transparent encryption, and backup products capture changes. Understanding the filter driver model is necessary for: (1) understanding how security products monitor file operations, (2) identifying bypass techniques, (3) auditing filter driver implementations for vulnerabilities.
- **What it teaches:**
  - The Filter Manager (FltMgr) model: pre-operation and post-operation callbacks
  - Minifilter altitude numbers: how filtering order is determined
  - How filters can intercept `IRP_MJ_CREATE`, `IRP_MJ_READ`, `IRP_MJ_WRITE`, `IRP_MJ_SET_INFORMATION`
  - The `FLT_CALLBACK_DATA` structure: how filters examine and modify I/O requests
  - Bypass techniques: creating files at the device level (below filter manager), using different volume paths, kernel-direct I/O
  - Security implications: EDR blind spots when using device-level access or alternate volume paths
- **Best use:** Read the WDK minifilter documentation, then install an open-source filter driver (e.g., the WDK sample "minispy") to observe I/O interception. Use WinDbg `!fltkd.filters` to see loaded filters.
- **Related bug classes / primitives:** EDR Bypass, AV Bypass, Kernel Driver Security, Altitude Number Exploitation
- **Suggested next resource:** Entry 6.2 (Windows File System Minifilters — research and tools); Entry 1.1 (Windows Internals I/O chapter)
- **Notes:** The `!fltkd` WinDbg extension shows loaded filter drivers, their altitudes, and their operation callbacks. Altitude numbers are publicly registered with Microsoft — searching the altitude database reveals which security product is at which layer.

---

### Entry 6.2

- **Title:** Windows File System Minifilters — Research and Offensive Tools
- **Author / Organization:** Various (EDR bypass researchers, Aleksandra Doncheva, Grzegorz Tworek / NtRaiseHardError)
- **URL:** https://github.com/mwrlabs/KernelFuzz *(kernel fuzzing including filter drivers)* + search "minifilter bypass" on GitHub and research blogs
- **Resource type:** Research papers + blog posts + tools
- **Topic tags:** `minifilter` `filter-driver` `EDR-bypass` `AV-bypass` `kernel-research` `filesystem`
- **Difficulty:** Expert
- **Historical or current:** Current (active research area 2022–2024)
- **Trust level:** ⭐⭐⭐⭐ — Varies by author; reputable researchers in this space include those publishing at OffensiveCon, DefCon, and in academic venues
- **Why it matters:** As EDR products increasingly rely on minifilter drivers for filesystem event monitoring, understanding minifilter bypass techniques has become critical for both red teams and product security researchers. Bugs in minifilter implementations can also provide kernel-level exploitation paths.
- **What it teaches:**
  - Minifilter bypass categories: (1) below-filter I/O (device-level), (2) alternate data streams that filters miss, (3) kernel-mode code that bypasses FltMgr entirely, (4) exploiting filter driver bugs
  - How to identify what operations a specific EDR filter intercepts by examining its altitude and callback table
  - BYOVD technique applied to filters: using a vulnerable signed filter driver to load unsigned code
  - Research methodology: kernel fuzzing filter driver callback handlers
- **Best use:** Primarily for advanced red team / EDR research. Lab with a test VM + WinDbg. Study known minifilter bypass techniques before attempting novel research.
- **Related bug classes / primitives:** EDR Bypass, BYOVD, Kernel Driver Security, Filter Driver Vulnerabilities
- **Suggested next resource:** Entry 6.1 (foundational filter driver model); PPL bypass resources (09_exploit_primitives Entry 4.1)
- **Notes:** This is a rapidly evolving area. Follow OffensiveCon proceedings and the @secsidney / @grzegorztworek Twitter/X feeds for current research.

---

### Entry 6.3

- **Title:** Paged Pool and NTFS — Pool Allocation in the NTFS Driver
- **Author / Organization:** Multiple kernel security researchers + Windows Internals
- **URL:** https://googleprojectzero.blogspot.com/ (search "pool" + "NTFS") + Windows Internals Part 1 (Memory Management chapter — pool allocator)
- **Resource type:** Blog posts + book chapter
- **Topic tags:** `paged-pool` `NTFS` `kernel-pool` `pool-overflow` `UAF` `kernel-vulnerability`
- **Difficulty:** Expert
- **Historical or current:** Current (pool isolation changed in Windows 10 20H1 — important for exploit reliability)
- **Trust level:** ⭐⭐⭐⭐ — Windows Internals primary; researcher posts vary
- **Why it matters:** The NTFS driver is the single largest kernel-mode component after ntoskrnl. It performs extensive paged and non-paged pool allocations for MFT records, directory entries, file objects, and internal state. Vulnerabilities in NTFS pool allocation (overflows, UAFs, integer overflows in allocation size calculations) represent a significant kernel attack surface that has produced multiple Project Zero CVEs.
- **What it teaches:**
  - Windows kernel pool allocator: lookaside lists, pool segments, allocation headers (pre-Windows 10 vs. post-20H1 Safe Unlinking + pool isolation)
  - How NTFS allocates pool for FCB (File Control Block), CCB (Context Control Block), SCB (Stream Control Block)
  - Pool overflow exploitation: overflowing into adjacent pool allocations, fake pool headers
  - Post-Windows 10 20H1 pool isolation: each pool type (paged, non-paged, etc.) is now in separate regions — cross-type overflow exploitation is harder
  - UAF patterns in NTFS: incorrect reference counting on FCB/SCB objects
  - How to enumerate NTFS pool allocations in WinDbg: `!pool`, `!poolused`
- **Best use:** Advanced kernel vulnerability research. Study pool allocator first (Windows Internals), then read NTFS-specific CVE writeups from Project Zero.
- **Related bug classes / primitives:** Kernel Pool Overflow, UAF, Integer Overflow, Kernel Exploit Composition
- **Suggested next resource:** Windows Internals Memory Management chapter; Project Zero NTFS CVE writeups (search "NTFS" on projectzero.blogspot.com)
- **Notes:** Windows 10 20H1's pool isolation (Segment Heap for kernel pool) significantly changed the exploitation landscape. Pre-20H1 techniques (pool spray with specific sizes) often don't translate directly to newer Windows versions.

---

*Last updated: 2026-04-22 · Maintained as part of the windows-research-vault*
