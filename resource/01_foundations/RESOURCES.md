# 01 — Foundations: Windows Internals Resource List

> **Section purpose:** Establish a deep, accurate mental model of how Windows works
> internally — kernel architecture, memory management, processes, threads, I/O, registry,
> and boot. This is the bedrock layer every other research track depends on.
>
> **How to use this file:** Read entries in the order suggested by `Suggested next resource`.
> Treat [MUST-READ] items as hard prerequisites before moving into vulnerability research.

---

## Resource Index

| # | Title | Type | Difficulty | Tag |
|---|-------|------|------------|-----|
| F-001 | Windows Internals Part 1 & 2 (7th ed.) | Book | Advanced | MUST-READ |
| F-002 | Windows Security Internals | Book | Advanced | MUST-READ |
| F-003 | Windows Kernel Programming (Yosifovich) | Book | Intermediate–Advanced | PRACTICAL |
| F-004 | Rootkits: Subverting the Windows Kernel | Book | Advanced | HISTORICAL |
| F-005 | Windows via C/C++ (Richter & Nassare) | Book | Intermediate | USER-MODE |
| F-006 | Microsoft Docs — Windows API Reference | Documentation | All levels | REFERENCE |
| F-007 | NT Insider (OSR Online) | Article Series | Advanced | KERNEL-DEV |
| F-008 | Windows Driver Kit Documentation | Documentation | Advanced | DRIVER-DEV |
| F-009 | ReactOS Source Code | Source Code | Advanced | INTERNALS |
| F-010 | Windows Research Kernel (WRK) | Source Code | Expert | HISTORICAL |

---

## Detailed Entries

---

### F-001 — Windows Internals Part 1 & 2

- **Title:** Windows Internals, Part 1 (7th Edition) / Windows Internals, Part 2 (7th Edition)
- **Author / Organization:** Mark Russinovich, David Solomon, Alex Ionescu, Pavel Yosifovich
- **URL:** https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals
  - Part 1 ISBN: 978-0-7356-8418-1
  - Part 2 ISBN: 978-0-13-585561-6
  - Also available: O'Reilly Learning, Amazon
- **Resource type:** Book (technical reference)
- **Topic tags:** `kernel-architecture` `processes` `threads` `memory-management` `virtual-memory` `I/O-subsystem` `registry` `executive` `HAL` `boot` `services` `security-reference-monitor`
- **Difficulty:** Advanced (assumes C/C++ and OS concepts)
- **Historical or current:** Current — 7th edition covers Windows 10 / Windows Server 2019; many concepts apply to Windows 11
- **Trust level:** ★★★★★ — Written by Microsoft engineers; Russinovich co-created Sysinternals; Ionescu co-created EMET. Authoritative.
- **Why it matters:**
  Every Windows vulnerability ultimately touches a kernel structure, a memory management policy, a handle table entry, or a security check performed inside the executive. Without this book you are guessing. With it you can trace any behavior back to a documented internal mechanism. Bug hunters who have read this deeply make faster, more accurate hypotheses.
- **What it teaches:**
  - Executive and kernel layer separation; IRQL model
  - Process and thread internals: EPROCESS, ETHREAD, job objects, fibers
  - Virtual memory: VAD trees, section objects, PFN database, working sets, paging, large pages
  - Object manager: object headers, handle tables, reference counting, named objects
  - I/O subsystem: IRP lifecycle, driver stacking, filter drivers, completion routines
  - Registry internals: hive format, cell index, log files
  - Security Reference Monitor: access check algorithm, token structure, privilege evaluation
  - Boot process: UEFI, boot manager, OS loader, Phase 0/1 kernel init
  - Startup and shutdown, services, session management
- **Best use:**
  Use as a primary reference when reversing kernel code, writing exploits, or analyzing a crash dump. Read Part 1 cover to cover first; use Part 2 as needed by topic. Keep WinDbg open alongside to verify structures live.
- **Related bug classes / primitives:**
  `use-after-free` (kernel object lifetime), `double-fetch` (user/kernel data races), `pool corruption` (pool allocator internals), `handle table spraying`, `NULL deref` (NULL page mapping history), `token stealing`, `ACL bypass`
- **Suggested next resource:** F-002 (Windows Security Internals) — once kernel fundamentals are solid, move to the security model layer
- **Notes:**
  - Part 1 covers: System architecture, processes, threads, jobs, memory, I/O, storage
  - Part 2 covers: Startup/shutdown, registry, cache, file systems, networking, management mechanisms
  - The 7th edition added significant coverage of Windows 10 security features (VBS, HVCI, CG, Device Guard)
  - Pair with WinDbg and the `!process`, `!thread`, `!object`, `dt nt!_EPROCESS` commands to explore live
  - Russinovich's Sysinternals tools (Process Explorer, VMMap, WinObj) are the companion tools for this book

---

### F-002 — Windows Security Internals

- **Title:** Windows Security Internals: A Deep Dive into Windows Authentication, Authorization, and Auditing
- **Author / Organization:** James Forshaw (Google Project Zero)
- **URL:** https://nostarch.com/windows-security-internals
  - Publisher: No Starch Press, 2023
  - ISBN: 978-1-7185-0125-5
- **Resource type:** Book (security-focused technical reference)
- **Topic tags:** `access-tokens` `security-descriptors` `ACL` `DACL` `SACL` `impersonation` `privilege-escalation` `object-manager-security` `AppContainer` `sandbox` `integrity-levels` `UAC` `LSA` `authentication` `authorization` `auditing` `Win32k` `COM-security`
- **Difficulty:** Advanced (assumes basic Windows API familiarity; knowledge of F-001 is helpful but not mandatory)
- **Historical or current:** Current — covers Windows 10/11; written in 2022–2023
- **Trust level:** ★★★★★ — Forshaw is one of the most prolific and trusted Windows security researchers alive. He discovered hundreds of Windows privilege escalation bugs. This book is the primary source for the security model.
- **Why it matters:**
  The Windows security model — tokens, security descriptors, ACLs, impersonation, integrity levels, AppContainers — is the primary attack surface for privilege escalation and sandbox escape. Before this book, this knowledge was scattered across documentation, blog posts, and brain dumps. Forshaw consolidated it into a single authoritative work, with working PowerShell examples using his NtObjectManager tools.
- **What it teaches:**
  - Token structure: user SID, group SIDs, privileges, default DACL, restricted tokens, impersonation levels
  - Security descriptor format: owner, group, DACL, SACL — binary layout and semantics
  - Access check algorithm in detail: how the SRM evaluates a token against a security descriptor
  - Mandatory Integrity Control (MIC): integrity levels, policy flags (NO_WRITE_UP, NO_READ_UP, NO_EXECUTE_UP)
  - UAC: elevation mechanisms, auto-elevation, COM elevation moniker, UAC bypass attack surface
  - Impersonation: client impersonation, identity/impersonation/delegation levels, impersonation attacks
  - AppContainer: capabilities, package SIDs, LPAC (Less Privileged AppContainer)
  - Object security: named pipes, registry keys, file system DACLs, object directory DACLs
  - Authentication: Kerberos, NTLM, credential providers, LSA secrets, Protected Users
  - COM security: activation permissions, launch permissions, surrogate processes
- **Best use:**
  Read alongside NtObjectManager PowerShell sessions. Every chapter has hands-on labs. Keep `Get-NtToken`, `Get-NtSecurityDescriptor`, `Show-NtSecurityDescriptor` open. Essential reading for anyone researching privilege escalation, sandbox escapes, or authentication bugs.
- **Related bug classes / primitives:**
  `token impersonation abuse` `SeImpersonatePrivilege escalation` `UAC bypass` `ACL misconfiguration` `AppContainer escape` `integrity level bypass` `COM activation abuse` `NtImpersonateThread` `PrintSpoofer / RoguePotato variants`
- **Suggested next resource:** F-003 for kernel driver writing skills; or jump to section 03 (Windows Security Model) for deep dives into specific bug classes
- **Notes:**
  - Available as DRM-free PDF from No Starch Press — worth buying directly
  - Forshaw's companion tool is the sandbox-attacksurface-analysis-tools repo (see F-007 in section 03)
  - This book replaced the need to read 30 separate blog posts and documentation pages
  - Covers material that directly maps to Windows EoP bugs (e.g. CVE-2021-36934 HiveNightmare, many token/impersonation bugs)

---

### F-003 — Windows Kernel Programming (Yosifovich)

- **Title:** Windows Kernel Programming (2nd Edition)
- **Author / Organization:** Pavel Yosifovich
- **URL:** https://leanpub.com/windowskernelprogramming
  - Also: https://github.com/zodiacon/windowskernelprogrammingbook (companion code)
  - Publisher: Leanpub (self-published), continuously updated
- **Resource type:** Book (practical programming reference)
- **Topic tags:** `kernel-drivers` `WDM` `KMDF` `IRPs` `dispatch-routines` `DriverEntry` `driver-objects` `device-objects` `pool-allocation` `MDL` `kernel-synchronization` `fast-I/O`
- **Difficulty:** Intermediate to Advanced (requires C++ and OS fundamentals)
- **Historical or current:** Current — updated for Windows 10/11
- **Trust level:** ★★★★☆ — Yosifovich is co-author of Windows Internals 7th ed.; highly practical and accurate
- **Why it matters:**
  Writing and understanding kernel drivers is a prerequisite for kernel-mode exploit development, driver fuzzing, and understanding attack surfaces exposed by third-party drivers. This book is the most practical entry point for writing your first kernel driver.
- **What it teaches:**
  - Setting up a kernel driver development environment (WDK + Visual Studio)
  - DriverEntry, driver unload, device creation
  - IRP handling: IRP_MJ_CREATE, IRP_MJ_CLOSE, IRP_MJ_READ, IRP_MJ_WRITE, IRP_MJ_DEVICE_CONTROL
  - Pool allocation: NonPagedPool, PagedPool, lookaside lists
  - Synchronization: spinlocks, mutexes, fast mutexes, ERESOURCEs
  - User/kernel data transfer: buffered I/O, direct I/O, neither I/O
  - Process and thread notifications
  - Registry callbacks
  - KMDF framework basics
- **Best use:**
  Work through all examples. Use a VM with kernel debugging enabled. Pair with WinDbg and the kernel symbols. Essential for exploit developers who need to understand driver IOCTL surfaces.
- **Related bug classes / primitives:**
  `IOCTL attack surface` `arbitrary kernel write via IRP` `pool overflow` `use-after-free in driver` `race condition in dispatch routines` `uninitialized kernel memory disclosure`
- **Suggested next resource:** F-007 (NT Insider) for deeper kernel internals articles; F-008 (WDK docs) for API reference
- **Notes:**
  - Companion code at https://github.com/zodiacon/windowskernelprogrammingbook
  - The author has a YouTube channel with supplementary lectures
  - Leanpub format means you always get the latest version once purchased

---

### F-004 — Rootkits: Subverting the Windows Kernel

- **Title:** Rootkits: Subverting the Windows Kernel
- **Author / Organization:** Greg Hoglund, James Butler
- **URL:** (Out of print; find via ISBN 0-321-29431-9 or secondhand sources)
  - Publisher: Addison-Wesley, 2005
- **Resource type:** Book (historical reference)
- **Topic tags:** `rootkits` `DKOM` `SSDT-hooking` `kernel-patching` `driver-signing-bypass` `stealth` `ring0`
- **Difficulty:** Advanced
- **Historical or current:** **Historical** — Written for Windows XP/2003 era. Many techniques are mitigated by PatchGuard (KPP), DSE, HVCI on modern Windows. Read for conceptual understanding, not for current exploitation.
- **Trust level:** ★★★★☆ — Historically accurate and well-written; outdated for modern targets
- **Why it matters:**
  Establishes the foundational vocabulary and mental model for kernel-mode attack techniques. Concepts like DKOM (Direct Kernel Object Manipulation), SSDT hooking, and IAT patching are the ancestors of modern kernel exploitation primitives. Understanding why Microsoft built PatchGuard requires understanding what it was designed to prevent.
- **What it teaches:**
  - SSDT hooking and IAT patching (historical)
  - Direct Kernel Object Manipulation (DKOM): unlinking processes from the active process list
  - Kernel memory patching
  - Early driver loading and persistence
  - Hiding files, processes, network connections
  - Kernel debugging evasion
- **Best use:**
  Read once for historical context. Do not attempt to apply techniques directly to modern Windows without understanding PatchGuard, DSE, HVCI mitigations. Use as conceptual background when reading modern kernel exploit writeups.
- **Related bug classes / primitives:**
  `DKOM` `SSDT hooking` (deprecated) → modern equivalents: `kernel CFG bypass` `HVCI bypass` `DSE bypass`
- **Suggested next resource:** F-001 (Windows Internals) for the modern kernel model that replaced the XP-era structures
- **Notes:**
  - The techniques in this book are the reason PatchGuard exists
  - Modern equivalents to study: VBS/HVCI bypass techniques, kernel CFG, arbitrary kernel write → token stealing workflow

---

### F-005 — Windows via C/C++

- **Title:** Windows via C/C++ (5th Edition)
- **Author / Organization:** Jeffrey Richter, Christophe Nassare
- **URL:** (Out of print; ISBN 978-0-7356-2216-0; find on O'Reilly Learning or secondhand)
  - Publisher: Microsoft Press, 2007
- **Resource type:** Book (user-mode programming reference)
- **Topic tags:** `user-mode` `Win32-API` `processes` `threads` `fibers` `memory-mapped-files` `DLL` `structured-exception-handling` `heap-management` `I/O-completion-ports` `synchronization`
- **Difficulty:** Intermediate
- **Historical or current:** Partially dated (pre-Windows 10) but the Win32 API fundamentals covered remain accurate
- **Trust level:** ★★★★☆ — Richter is a highly respected Windows expert; content is accurate for the era
- **Why it matters:**
  Before exploiting Windows, you need to be able to program it. This book provides the most thorough treatment of Win32 programming: how processes are created, how DLLs load, how heap memory is managed, how threads synchronize. This is the user-mode complement to Windows Internals.
- **What it teaches:**
  - Process and thread creation: CreateProcess, CreateThread, process attributes
  - Virtual memory API: VirtualAlloc, VirtualProtect, memory regions and pages
  - DLL loading: LoadLibrary, DllMain, DLL injection concepts
  - Heap management: HeapCreate, HeapAlloc, heap walking
  - Structured Exception Handling (SEH): try/except/__try/__finally
  - I/O completion ports and asynchronous I/O
  - Memory-mapped files and section objects
  - Thread synchronization: events, mutexes, semaphores, critical sections, SRW locks
- **Best use:**
  Use as a reference when writing exploitation tooling or understanding how shellcode interacts with the Win32 environment. SEH chapter is particularly relevant for exploit development.
- **Related bug classes / primitives:**
  `SEH overwrite` `heap exploitation` `DLL injection` `process injection` `virtual memory manipulation`
- **Suggested next resource:** F-001 (Windows Internals) to understand what happens underneath the Win32 API calls
- **Notes:**
  - Chapter on SEH is the best written explanation of Windows exception handling
  - Memory-mapped files chapter is essential for understanding section object attacks
  - Some API behavior has changed in Windows 8+ (e.g., heap hardening), but core concepts remain valid

---

### F-006 — Microsoft Docs — Windows API Reference

- **Title:** Windows API Reference Documentation
- **Author / Organization:** Microsoft
- **URL:** https://learn.microsoft.com/en-us/windows/win32/api/
  - Also: https://learn.microsoft.com/en-us/windows/win32/ (top-level)
  - NT Native API (undocumented): https://ntdoc.m417z.com/ (community-maintained)
- **Resource type:** Official documentation (online reference)
- **Topic tags:** `Win32-API` `security-API` `process-API` `memory-API` `registry-API` `file-API` `networking-API` `authentication-API` `authorization-API`
- **Difficulty:** All levels
- **Historical or current:** Current — continuously updated by Microsoft
- **Trust level:** ★★★★★ — Official source; however, some internal/undocumented behavior is not covered
- **Why it matters:**
  The authoritative reference for every documented Windows function. Every exploit, every tool, every piece of shellcode calls Win32 or NT native APIs. You need this open constantly.
- **What it teaches:**
  - Complete function signatures, parameters, return values, error codes
  - Security remarks (often contain subtle security-relevant behavior)
  - Requirements (minimum OS version, required privileges)
  - Remarks section often contains subtle security-relevant behavior
- **Best use:**
  Use as a lookup reference, not a learning resource. Read the **Remarks** and **Security Remarks** sections carefully — they often document the edge cases that become vulnerabilities.
- **Related bug classes / primitives:**
  Everything — API misuse, TOCTOU, parameter validation bugs, privilege checks
- **Suggested next resource:** F-007 (NT Insider) for deeper articles that go beyond the documented behavior
- **Notes:**
  - Supplement with ntdoc.m417z.com for NT native API (NtCreateFile, NtOpenProcess, etc.) which is not fully documented by Microsoft
  - The "Security Considerations" subsections are worth reading even when not actively researching a specific function
  - ReactOS (F-009) can supplement when you need to see an actual implementation of a documented function

---

### F-007 — NT Insider (OSR Online)

- **Title:** The NT Insider — Technical Articles on Windows Kernel Development
- **Author / Organization:** OSR Open Systems Resources, Inc.
- **URL:** https://www.osr.com/nt-insider/
  - Archive: https://www.osr.com/nt-insider/archive/
- **Resource type:** Article series / technical journal
- **Topic tags:** `kernel-development` `driver-development` `IRP-internals` `paging` `memory-manager` `I/O-manager` `PnP` `power-management` `filter-drivers` `synchronization` `debugging`
- **Difficulty:** Advanced
- **Historical or current:** Mixed — articles span from 1994 to present; always check the date; older articles may reflect pre-Vista or pre-Win10 behavior
- **Trust level:** ★★★★☆ — OSR is a respected kernel consultancy; articles are written by working kernel engineers
- **Why it matters:**
  NT Insider fills the gap between the high-level documentation (MSDN/WDK) and the implementation details in Windows Internals. Articles often contain practical insights that took engineers years to discover. Essential for anyone writing kernel drivers or analyzing driver attack surfaces.
- **What it teaches:**
  - Subtle IRP behavior (cancellation, completion, IoMarkIrpPending)
  - Memory manager details beyond what Windows Internals covers
  - Practical debugging workflows with WinDbg
  - Driver verifier usage for catching driver bugs
  - Synchronization pitfalls
  - Filter driver architecture
- **Best use:**
  Search the archive for specific topics when you encounter something confusing in kernel code. The articles are often the only written source for certain behaviors.
- **Related bug classes / primitives:**
  `IRP cancellation races` `completion routine bugs` `MDL mapping issues` `lookaside list misuse`
- **Suggested next resource:** F-008 (WDK Documentation)
- **Notes:**
  - Search the archive before spending hours reverse-engineering kernel behavior
  - OSR also offers a mailing list (NTDEV) where kernel engineers answer questions
  - Some articles are available only to subscribers

---

### F-008 — Windows Driver Kit Documentation

- **Title:** Windows Driver Kit (WDK) Documentation
- **Author / Organization:** Microsoft
- **URL:** https://learn.microsoft.com/en-us/windows-hardware/drivers/
  - WDK download: https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk
  - DDI reference: https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/
- **Resource type:** Official documentation
- **Topic tags:** `WDK` `KMDF` `UMDF` `WDM` `DDI` `kernel-drivers` `filter-drivers` `minifilter` `bus-drivers` `PnP` `power-management` `DMA` `interrupt-handling`
- **Difficulty:** Advanced
- **Historical or current:** Current — continuously updated
- **Trust level:** ★★★★★ — Official Microsoft source
- **Why it matters:**
  The WDK documentation is the official reference for kernel driver development. Every kernel driver API, every kernel data structure documented by Microsoft, every design guideline is here. It is required reading for writing drivers or understanding driver attack surfaces.
- **What it teaches:**
  - Kernel-mode DDI (Device Driver Interface) reference
  - KMDF and UMDF framework design and API
  - Safe driver design guidelines (which, when violated, create vulnerabilities)
  - PnP and power management models
  - Minifilter driver architecture (file system filters)
  - WDK build system and driver signing
- **Best use:**
  Use as API reference when writing or analyzing drivers. The "Design Guide" sections are worth reading to understand intended usage vs. what drivers actually do (the gap is where bugs live).
- **Related bug classes / primitives:**
  `IOCTL validation` `ProbeForRead/Write bypass` `arbitrary kernel write via misconfigured IOCTL` `race conditions` `use-after-free`
- **Suggested next resource:** F-003 (Yosifovich kernel programming book) for practical application of WDK concepts
- **Notes:**
  - The DDI reference documents kernel functions, macros, and structures
  - Driver samples in the WDK are useful starting points but have been known to contain bugs
  - The "Kernel-Mode Driver Architecture" guide is the best starting point within the WDK docs

---

### F-009 — ReactOS Source Code

- **Title:** ReactOS — Open Source Windows-Compatible Operating System
- **Author / Organization:** ReactOS Foundation (community)
- **URL:** https://github.com/reactos/reactos
  - Online code browser: https://doxygen.reactos.org/
  - Also: https://github.com/reactos/reactos/tree/master/ntoskrnl
- **Resource type:** Source code (reference implementation)
- **Topic tags:** `NT-kernel-internals` `executive` `object-manager` `memory-manager` `process-manager` `I/O-manager` `security-reference-monitor` `Win32-subsystem` `NTDLL`
- **Difficulty:** Advanced
- **Historical or current:** Current (ongoing development) but implements pre-Vista era APIs in many areas; treat as educational reference
- **Trust level:** ★★★☆☆ — ReactOS is not byte-for-byte identical to Windows NT. Behavior may differ from production Windows. Use to understand concepts, verify against real Windows with WinDbg.
- **Why it matters:**
  When you need to understand the internal implementation of a kernel function and WinDbg is not enough, ReactOS provides readable C source code for NT-compatible implementations. The object manager, process manager, and security reference monitor implementations are particularly educational.
- **What it teaches:**
  - How NT internal structures are laid out in memory
  - Implementation of executive functions (ObReferenceObjectByHandle, etc.)
  - Security Reference Monitor internal access check logic
  - NTDLL and system call stubs
  - Win32 subsystem (CSRSS) structure
- **Best use:**
  Use to understand algorithmic behavior of Windows internals. Always cross-verify ReactOS behavior against real Windows using WinDbg, because implementation details differ. Good for: understanding `ObpLookupObjectName`, access check flows, handle table implementation.
- **Related bug classes / primitives:**
  `object manager security` `handle table internals` `access check algorithm` `security reference monitor`
- **Suggested next resource:** F-010 (WRK) for an actual older Windows kernel source
- **Notes:**
  - The ntoskrnl/ directory contains the kernel implementation
  - The Win32SS/ directory contains win32k equivalent
  - Doxygen browser makes it searchable: https://doxygen.reactos.org/

---

### F-010 — Windows Research Kernel (WRK)

- **Title:** Windows Research Kernel (WRK) — Windows Server 2003 Kernel Source
- **Author / Organization:** Microsoft (academic release)
- **URL:** https://github.com/HighSchool2015/WRK
  - Original release: http://www.microsoft.com/windowsacademic (archived)
  - Also: https://github.com/zhuhuibeishadiao/ntoskrnl (WRK mirror)
- **Resource type:** Source code (historical reference kernel)
- **Topic tags:** `NT-kernel-source` `executive` `scheduler` `memory-manager` `object-manager` `security-reference-monitor` `I/O-manager` `Windows-2003`
- **Difficulty:** Expert
- **Historical or current:** **Historical** — This is Windows Server 2003 / Windows XP SP1 era kernel source. Modern Windows kernel differs significantly. Do not assume current behavior from WRK.
- **Trust level:** ★★★★★ for the era it covers — actual Microsoft kernel source; ★★☆☆☆ for modern applicability
- **Why it matters:**
  The WRK was released to universities for OS research. It contains actual Windows NT kernel source code for the scheduler, memory manager, object manager, I/O manager, and security reference monitor. Reading the real source code provides clarity that no amount of reverse engineering can fully replicate.
- **What it teaches:**
  - Exact implementation of the NT scheduler (priority-based preemptive scheduling)
  - Memory manager: working set management, page fault handling, PTE structure
  - Object manager: ObpLookupObjectName, handle table management
  - Security Reference Monitor: SeAccessCheck implementation (core access check algorithm)
  - I/O Manager: IoCallDriver, IRP routing
  - Executive primitives: lookaside lists, zone allocators, APCs
- **Best use:**
  Read SeAccessCheck to understand the access check algorithm at the source level. Read the object manager to understand naming and lookup. Use as historical baseline — then track changes by reading Windows Internals 7th ed. commentary on what changed since XP.
- **Related bug classes / primitives:**
  `access check bypass` `object manager security` `handle inheritance` `ALPC` `LPC internals`
- **Suggested next resource:** Return to F-001 (Windows Internals 7th ed.) with new depth from having seen actual source code
- **Notes:**
  - The WRK was officially released under academic license; verify you are using a legitimate copy
  - Focus files: `base/ntos/se/accesschk.c` (access check), `base/ntos/ob/` (object manager), `base/ntos/mm/` (memory manager)
  - Many structures documented in Windows Internals become clear when you read the actual initialization code in the WRK
  - Cross-reference with Geoff Chappell's analysis at https://www.geoffchappell.com/

---

## Quick Reference: Learning Sequence

```
Beginner → Windows Internals
     ↓
F-001 Windows Internals Part 1 (read fully)
     ↓
F-005 Windows via C/C++ (user-mode foundation)
     ↓
F-002 Windows Security Internals (security model)
     ↓
F-003 Windows Kernel Programming (write drivers)
     ↓
F-006 Windows API Docs + F-008 WDK Docs (ongoing reference)
     ↓
F-007 NT Insider (fill knowledge gaps)
     ↓
F-009 ReactOS / F-010 WRK (source-level understanding)
     ↓
F-004 Rootkits book (historical context)
     ↓
→ Proceed to section 03 (Security Model) and section 05 (Exploit Techniques)
```

---

## Essential WinDbg Commands for This Section

```windbg
# Process internals
!process 0 0              ; list all processes
dt nt!_EPROCESS <addr>    ; dump EPROCESS structure
!thread <addr>            ; dump thread info
dt nt!_ETHREAD <addr>

# Memory
!vmstat                   ; virtual memory statistics
!pte <addr>               ; page table entry for address
!pool <addr>              ; pool header for allocation
!poolused                 ; pool usage by tag

# Object manager
!object \                 ; root object directory
!object \Device           ; device directory
dt nt!_OBJECT_HEADER <addr>
!handle <handle> <pid>    ; decode handle

# Security
!token <addr>             ; dump token
dt nt!_TOKEN <addr>
dt nt!_SEP_TOKEN_PRIVILEGES <addr>
```

---

*Last updated: 2026-04-22 | Section maintainer: research-vault*
