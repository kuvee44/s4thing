# 01 — Windows Internals Foundations

> **Prerequisites:** Basic C/C++ programming; familiarity with operating system concepts
> (user space vs. kernel space, virtual memory, system calls).
>
> **Estimated study time:** 6–12 weeks for deep first pass; ongoing reference use thereafter.

---

## What This Section Covers

This section establishes the foundational mental model required for serious Windows security research. It covers the internals of the Windows operating system from the ground up: kernel architecture, memory management, process and thread management, the I/O subsystem, the object manager, the registry, boot processes, and the security reference monitor.

**Without this foundation, vulnerability research degenerates into pattern matching.** With it, you can derive new attack primitives from first principles.

---

## Why Foundations Matter in Windows Research

Windows is a complex, layered system. A privilege escalation vulnerability might exist because:

- A kernel pool allocation can be overflowed (requires understanding pool allocator internals)
- A handle can be inherited unexpectedly across a privilege boundary (requires understanding handle table internals)
- A token impersonation level is not checked correctly (requires understanding token and security reference monitor internals)
- A section object can be mapped with unexpected permissions (requires understanding memory manager and object security)

Each of these requires deep knowledge of the relevant subsystem. The resources in this section build that knowledge systematically.

---

## Section Structure

```
01_foundations/
├── README.md          ← This file
├── RESOURCES.md       ← Annotated resource list (start here)
└── NOTES.md           ← Research and study notes
```

---

## Recommended Reading Order

### Stage 1: Architecture Overview (Week 1–2)
Start with **F-001 Windows Internals Part 1**, chapters 1–3:
- System architecture and concepts
- System mechanisms (traps, exceptions, system calls)
- Processes and jobs

**Goal:** Be able to explain in detail what happens when a process is created, from `CreateProcess()` in user mode down to `PspAllocateProcess()` in the kernel.

### Stage 2: Memory and Objects (Week 3–4)
Continue **F-001**, chapters 4–8:
- Threads, fibers, user-mode scheduling
- Memory management (virtual memory model, VAD, working sets)
- I/O system
- Storage management

**Goal:** Be able to explain how a `VirtualAlloc(MEM_COMMIT)` call results in physical memory being assigned to pages, and what a page fault does.

### Stage 3: Security Foundation (Week 5–6)
- Complete **F-001** Part 1 (remaining chapters: registry, boot, startup)
- Begin **F-002 Windows Security Internals**, chapters 1–5

**Goal:** Be able to trace a `CreateFile()` call and explain every security check it triggers, from the handle table through the security reference monitor access check.

### Stage 4: Kernel Programming (Week 7–8)
Work through **F-003 Windows Kernel Programming**:
- Write a minimal filter driver
- Write a driver with IOCTL interface
- Write a driver that reads process memory

**Goal:** Be able to write a functional kernel driver from scratch. Understand the IOCTL interface well enough to identify validation failures in third-party drivers.

### Stage 5: Deep Reference (Week 9–12 and ongoing)
- **F-001 Part 2** (storage, networking, management mechanisms)
- **F-007 NT Insider** articles for specific topics
- **F-009 ReactOS** / **F-010 WRK** for source-level understanding of specific subsystems
- **F-006 Microsoft Docs** and **F-008 WDK** as ongoing API reference

---

## Lab Setup Requirements

Every concept in this section should be verified empirically. Set up the following before reading:

### Virtual Machine
- Windows 10/11 (latest version) VM — target machine
- Windows 10/11 VM — host/debugger machine
- Enable kernel debugging over network (KDNET) or serial

### Tools
| Tool | Purpose | Source |
|------|---------|--------|
| WinDbg Preview | Kernel and user-mode debugging | Microsoft Store |
| Process Explorer | Process internals visualization | Sysinternals |
| VMMap | Virtual memory visualization | Sysinternals |
| WinObj | Object manager namespace browser | Sysinternals |
| Process Monitor | System call tracing | Sysinternals |
| LiveKd | Live kernel dump without rebooting | Sysinternals |
| WDK (latest) | Kernel driver development | Microsoft |
| NtObjectManager | PowerShell security object tools | GitHub/PSGallery |

### WinDbg Setup
```
# Configure kernel debugging over network (on target VM)
bcdedit /debug on
bcdedit /dbgsettings net hostip:<host_ip> port:50000 key:1.2.3.4

# On host, connect WinDbg:
# File → Kernel Debug → Net → Port: 50000, Key: 1.2.3.4

# Load symbols
.sympath srv*c:\symbols*https://msdl.microsoft.com/download/symbols
.reload /f
```

---

## Key Structures to Know Cold

The following data structures appear constantly in Windows security research. Use WinDbg `dt` commands to explore them live:

```
nt!_EPROCESS          ; Process executive object
nt!_ETHREAD           ; Thread executive object
nt!_TOKEN             ; Security token
nt!_OBJECT_HEADER     ; Object manager object header
nt!_HANDLE_TABLE      ; Process handle table
nt!_POOL_HEADER       ; Kernel pool allocation header
nt!_PTE               ; Page table entry
nt!_MMVAD             ; Virtual address descriptor (VAD node)
nt!_FILE_OBJECT       ; File object
nt!_DRIVER_OBJECT     ; Driver object
nt!_DEVICE_OBJECT     ; Device object
nt!_IRP               ; I/O request packet
```

---

## Connection to Vulnerability Research

| Subsystem | Relevant Bug Classes |
|-----------|---------------------|
| Pool allocator | Pool overflow, use-after-free, pool spraying |
| Object manager | Handle race conditions, object lifetime bugs, namespace attacks |
| Memory manager | Section object attacks, PTE manipulation, working set abuse |
| I/O system | IRP manipulation, IOCTL validation failures, completion race |
| Process manager | Process injection, handle inheritance abuse |
| Security Reference Monitor | Access check bypass, token manipulation |
| Registry | Hive loading attacks, registry key security bypass |

---

## Progress Checklist

- [ ] Can explain the IRQL model and why it matters for synchronization
- [ ] Can describe the kernel pool architecture (paged, non-paged, session, special)
- [ ] Can walk a page fault from user-mode access to PFN database update
- [ ] Can explain handle table structure and how handle inheritance works
- [ ] Can describe the object manager namespace and how named objects are resolved
- [ ] Can trace a security access check from `CreateFile` to `SeAccessCheck`
- [ ] Can write a minimal kernel driver with IRP dispatch table
- [ ] Can set a breakpoint on a kernel function and dump arguments in WinDbg
- [ ] Can read an EPROCESS structure and locate the token pointer

---

*Section: 01_foundations | Last updated: 2026-04-22*
