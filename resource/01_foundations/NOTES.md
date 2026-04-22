# Foundations — Research & Study Notes

> Personal notes, insights, observations, and cross-references accumulated during study
> of Windows internals foundations. Update this file as you go.

---

## Key Mental Models

### The Ring Model vs. The Reality

Windows does not operate as a simple ring 0 / ring 3 split. The actual privilege levels are:

```
Ring 0  : Kernel mode (ntoskrnl.exe, drivers)
          └── Hypervisor (VTL1) — above kernel, below hypervisor
Ring 3  : User mode
          ├── Highly privileged processes (SYSTEM, lsass.exe, services.exe)
          ├── Medium integrity processes (standard user apps)
          └── Low / AppContainer (sandboxed apps, browsers, Edge)
```

**Research implication:** Many "privilege escalation" bugs are not ring 3→0. They are
medium integrity → SYSTEM within ring 3. The Windows security model layers (tokens,
integrity levels, AppContainer) create sub-privileges within user mode.

---

### The Executive = The Policy Layer

The NT executive (ntoskrnl.exe) is organized into components:
- **Ob** (Object Manager) — naming, handle management, lifetime
- **Se** (Security) — token management, access checks, auditing
- **Ps** (Process/Thread Manager) — process/thread creation and management
- **Mm** (Memory Manager) — virtual memory, paging, VAD
- **Io** (I/O Manager) — IRP routing, device/driver objects
- **Cm** (Configuration Manager) — registry
- **Ex** (Executive support) — lookaside lists, worker threads, callbacks
- **Ke** (Kernel) — scheduler, DPCs, APCs, spinlocks
- **Hal** (Hardware Abstraction Layer) — hardware-specific operations

Each component has a two or three letter prefix. Recognizing these in WinDbg symbol names is essential.

---

### Pool Allocation Fundamentals

The kernel pool is a slab allocator. Key pool types:

| Pool Type | Pageable? | Use |
|-----------|-----------|-----|
| NonPagedPool | No | Must never page out (DPC/ISR context) |
| NonPagedPoolNx | No | Non-executable NP pool (Win 8+) |
| PagedPool | Yes | Can page out; most kernel objects |
| SessionPool | Yes | Per-session objects (Win32k, CSRSS) |

**Pool tag:** 4-byte ASCII tag on every allocation (e.g., `Proc` for EPROCESS, `File` for FILE_OBJECT). Essential for debugging and pool feng shui.

```windbg
# Find all allocations with a specific tag
!poolfind Proc 0    ; search non-paged pool for tag 'Proc'
!poolfind File 1    ; search paged pool for tag 'File'
```

**Pool overflow primitive:** Overflow into the next chunk's header → control the `PoolType`, `BlockSize`, and `PoolTag` fields → potentially redirect a free operation.

---

### Virtual Memory Model

Key facts for exploit developers:

- Each process has a 128TB user virtual address space (x64)
- VAD (Virtual Address Descriptor) tree: a red-black tree tracking committed memory regions
- PTE (Page Table Entry): ultimate source of truth for physical mapping, permissions, and page state
- `NtAllocateVirtualMemory` creates a VAD node; `NtMapViewOfSection` also creates one
- The working set is the set of currently resident (non-paged) pages for a process

**NULL page note:** On 32-bit Windows (XP era), userland could allocate page 0, enabling kernel NULL deref exploitation. Mitigated in Vista+ (NULL page cannot be allocated by user mode, `MmLowestUserAddress` = 0x10000).

**Guard pages:** VAD nodes can be marked as `MEM_GUARD`. First access raises a guard page exception. Used for stack growth and as a security feature in some allocators.

---

### Handle Tables

```
_EPROCESS.ObjectTable → _HANDLE_TABLE
    └── TableCode → _HANDLE_TABLE_ENTRY[] (or multi-level tree)
         └── _HANDLE_TABLE_ENTRY
              ├── ObjectPointerBits → _OBJECT_HEADER (shifted right 4 bits)
              └── GrantedAccessBits → access rights granted when handle was opened
```

**Key insight:** The granted access in the handle table entry is set at `OpenXxx/CreateXxx` time and is NOT re-checked on subsequent operations. If you can modify a handle table entry, you can escalate the access rights of an existing handle.

**Handle inheritance:** Handles with `HANDLE_FLAG_INHERIT` set are duplicated into child processes via `CreateProcess`. Bug pattern: inheriting a privileged handle into an unprivileged process.

---

### IRP Lifecycle

Understanding IRPs is essential for:
- Writing kernel drivers correctly
- Identifying race conditions in dispatch routines
- Understanding filter driver attack surfaces

```
User: ReadFile(handle, ...)
  → NtReadFile (system call)
    → IoCreateIrp / IoBuildSynchronousFsdRequest
      → IoCallDriver (top of driver stack)
        → Dispatch routines (IRP_MJ_READ) at each driver
          → IoCompleteRequest (from bottom driver up)
            → Completion routines execute
              → IRP freed
                → NtReadFile returns to user
```

**Bug patterns:**
- Not calling `IoMarkIrpPending` before returning `STATUS_PENDING`
- Accessing IRP after `IoCompleteRequest`
- Cancellation races: IRP cancelled between dispatch and completion
- Completing the same IRP twice

---

## WinDbg One-Liners

### Dump all process tokens
```windbg
!for_each_process "dt nt!_TOKEN poi(poi(@$extret+0x4b8)&~0xf)"
```

### Find kernel base
```windbg
? nt
lm m nt
```

### Dump SSDT
```windbg
dps nt!KiServiceTable L nt!KiServiceLimit
```

### Find pool allocations by tag
```windbg
!poolfind Driv 0
```

### Walk VAD tree for process
```windbg
!vad
!vad <root_addr> 1
```

### Dump handle table entries
```windbg
!handle 0 0xf <pid>
```

---

## Cross-Reference: Structures ↔ Bug Classes

| Structure | Field of Interest | Bug Class |
|-----------|------------------|-----------|
| `_EPROCESS` | `Token` (offset 0x4b8 on Win11) | Token theft/manipulation |
| `_EPROCESS` | `ObjectTable` | Handle table attack |
| `_EPROCESS` | `ActiveProcessLinks` | DKOM (historical, PG-protected) |
| `_TOKEN` | `Privileges` | Privilege escalation |
| `_TOKEN` | `IntegrityLevel` | Integrity bypass |
| `_OBJECT_HEADER` | `TypeIndex` | Object type confusion |
| `_POOL_HEADER` | `BlockSize`/`PoolType` | Pool overflow |
| `_PTE` | Protection bits | PTE manipulation (kernel write prim) |
| `_HANDLE_TABLE_ENTRY` | `GrantedAccessBits` | Handle escalation |

---

## Important Offsets (Windows 11 22H2 x64)

> **Warning:** These offsets change between builds. Always verify with `dt` in WinDbg.

```c
EPROCESS.UniqueProcessId        = 0x440
EPROCESS.ActiveProcessLinks     = 0x448
EPROCESS.Token                  = 0x4b8
EPROCESS.ObjectTable            = 0x570
EPROCESS.SeAuditProcessCreation = 0x878 (approx)

TOKEN.Privileges.Present        = 0x040
TOKEN.Privileges.Enabled        = 0x048
TOKEN.IntegrityLevelIndex       = varies (use dt to find)

_OBJECT_HEADER.TypeIndex        = 0x18
_OBJECT_HEADER.Body             = 0x30 (follows header)
```

---

## Commonly Confused Concepts

### IRQL vs. Privilege Level
- **IRQL** = Interrupt Request Level (0=PASSIVE, 2=DISPATCH, >2=device IRQL)
  - Governs what the scheduler and memory manager can do on the current CPU
  - IRQL ≥ DISPATCH_LEVEL: cannot touch paged memory, cannot wait
- **Privilege level** = Ring 0 (kernel) vs. Ring 3 (user)
  - These are orthogonal: a kernel thread runs at PASSIVE_LEVEL most of the time

### Handle vs. Pointer
- A **handle** is a process-local index into the handle table. It is opaque to the kernel.
- A **pointer** (PVOID, PEPROCESS, etc.) is a kernel virtual address.
- Converting: `ObReferenceObjectByHandle(handle, ..., &pObject)` → kernel validates the handle and returns a kernel pointer, with an incremented reference count.

### Section Object vs. Memory-Mapped File
- A **section object** (`_SECTION`, `_CONTROL_AREA`) is the kernel object backing shared memory
- A **memory-mapped file** is the user-visible result of `MapViewOfFile` (= `NtMapViewOfSection`)
- Multiple processes can map views of the same section object → shared memory
- **Bug pattern:** Section created with `PAGE_EXECUTE_READWRITE` by a privileged process, mapped by an unprivileged one

---

## Open Questions / Things to Verify

- [ ] How does `ObpLookupObjectName` handle symbolic link cycles? Is there a depth limit?
- [ ] Exactly which checks prevent a medium-integrity process from writing to a SYSTEM process's VAD via `NtWriteVirtualMemory`? (Access check on process handle? Token check?)
- [ ] What is the current behavior of `NtAllocateVirtualMemory` with `MEM_RESERVE | MEM_COMMIT` at address 0x1000 on Windows 11?
- [ ] In what scenarios can `NtSetInformationToken` be called to modify an existing token's integrity level?

---

*Section: 01_foundations/NOTES.md | Last updated: 2026-04-22*
