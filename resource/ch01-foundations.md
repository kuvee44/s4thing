# Chapter 01 — Windows Internals Foundations

> **Scope:** NT executive architecture, ring model reality, EPROCESS/ETHREAD, handle tables,
> kernel pool allocator, virtual memory model, IRP lifecycle, Security Reference Monitor,
> VBS/VTL changes in Windows 11 24H2, segment heap hardening 2024, new EPROCESS security fields
> (Build 26100), CVE-2024-21338 case study, and the 2024 vulnerable driver blocklist.
> **Target audience:** Security researcher who can write C and understands OS concepts.
> **Lab requirement:** WinDbg connected to a kernel-debug VM via KDNET before reading.

---

## 1. The NT Executive — Subsystem Map

The Windows kernel image (`ntoskrnl.exe`) is not a monolith — it is an executive composed of
cooperating components, each with a two- or three-letter prefix used consistently in symbol
names, structure names, and internal documentation. Recognizing these prefixes in a WinDbg
session turns noise into signal.

```
ntoskrnl.exe — NT Executive
│
├── Ob  Object Manager        — naming, lifetime, reference counting, handle tables
├── Se  Security              — token management, access checks, auditing (SRM)
├── Ps  Process/Thread Mgr    — EPROCESS/ETHREAD creation, scheduling setup
├── Mm  Memory Manager        — virtual memory, VAD, PTEs, paging, working sets
├── Io  I/O Manager           — IRP routing, driver/device objects, completion
├── Cm  Configuration Mgr     — registry (hive format, cell index, notifications)
├── Ex  Executive Support     — lookaside lists, worker threads, callbacks, timers
├── Ke  Kernel                — scheduler, DPCs, APCs, spinlocks, interrupts
└── Hal Hardware Abstraction  — hardware-specific I/O, interrupt routing, time
```

**Why this matters for exploit development:** When you encounter a crash or a symbol in WinDbg,
the prefix tells you which subsystem owns it. `SeAccessCheck` is in Security. `ObReferenceObjectByHandle`
is in Object Manager. `MmAllocateNonCachedMemory` is in Memory Manager. Every kernel vulnerability
lives inside one of these components, and the prefix narrows the hypothesis space immediately.

### IRQL — The Orthogonal Privilege Axis

Hardware privilege (ring 0 / ring 3) and IRQL are independent axes:

```
IRQL 0  PASSIVE_LEVEL   — Normal thread execution; all memory accessible; can wait
IRQL 1  APC_LEVEL       — APC delivery blocked; still paged memory OK
IRQL 2  DISPATCH_LEVEL  — Scheduler disabled; CANNOT touch paged memory; CANNOT wait
IRQL >2 Device IRQLs    — ISR context; extremely limited operations
```

A kernel thread running at PASSIVE_LEVEL at ring 0 can allocate PagedPool, acquire mutexes, and
call `KeWaitForSingleObject`. The same thread at DISPATCH_LEVEL cannot — doing so causes a
`DRIVER_IRQL_NOT_LESS_OR_EQUAL` bug check. Exploit developers hit this when injecting work into
DPC routines or when a race condition lands code at the wrong IRQL.

---

## 2. The Ring Model — Reality vs. Textbook

The textbook says: ring 0 = kernel, ring 3 = user. Windows uses only these two hardware rings.
The reality has far more privilege gradations, especially relevant for privilege escalation research.

### Hardware Rings (x86-64)

```
Ring 0  — ntoskrnl.exe, drivers, win32k.sys
Ring 3  — all user-mode processes
(Rings 1 and 2 are unused by Windows)
```

### VTL (Virtual Trust Level) — The Hypervisor Dimension

With Virtualization-Based Security (VBS) enabled:

```
VTL 1   Secure World   — Isolated User Mode (IUM), Secure Kernel (skci.dll, HVCI enforcer)
VTL 0   Normal World   — ntoskrnl.exe, drivers, user mode (the usual Windows)
```

VTL 1 is effectively "above kernel" — the Secure Kernel runs inside VTL 1 and enforces policies
that normal-world kernel code cannot bypass. HVCI (Hypervisor-Protected Code Integrity) runs in
VTL 1 and validates kernel page permissions so that even a kernel write primitive cannot mark
non-code pages executable. This is why modern kernel exploits must now find a code-reuse primitive
or a VTL 1 escape rather than simply writing shellcode to a kernel buffer.

**Windows 11 24H2 (Build 26100, October 2024) changes:** HVCI is now enabled by default on all
new installs with compatible hardware. For the impact on exploit development, see Section 8.

> **Deep dive:** ch03 §9 covers Administrator Protection built on VTL. ch10 §10.11 covers in-wild exploitation of VTL0→VTL1 escape (CVE-2025-21333).

### Software Privilege Layers Within Ring 3

Below the hardware ring boundary, Windows enforces additional layers entirely in software:

```
Ring 3 (user mode)
├── Integrity Level 5 = System     (SYSTEM service processes)
├── Integrity Level 4 = High       (elevated administrator processes)
├── Integrity Level 3 = Medium+    (Task Scheduler)
├── Integrity Level 2 = Medium     (standard user applications — the default)
├── Integrity Level 1 = Low        (IE Protected Mode, some brokers)
├── Integrity Level 0 = Untrusted  (explicit sandboxes)
└── AppContainer                   (additional isolation on top of IL; UWP, Edge renderer)
```

**Research implication:** Most Windows privilege escalation bugs are NOT ring 3 to ring 0.
They are Medium IL to SYSTEM within ring 3, or AppContainer to Medium IL. The Windows security
model layers (tokens, integrity levels, AppContainer) create distinct privilege boundaries purely
in software. Understanding which boundary a bug violates is the first step in assessing impact.

---

## 3. EPROCESS — The Process Executive Object

Every live Windows process has one `_EPROCESS` structure in kernel memory. This is the central
data structure for process security research.

```c
// Simplified EPROCESS layout — key fields with Win11 22H2 x64 offsets
// Always verify with: dt nt!_EPROCESS in WinDbg (offsets change per build)
typedef struct _EPROCESS {
    KPROCESS   Pcb;                    // 0x000 — embedded KPROCESS (scheduler state)
    // ...
    ULONG_PTR  UniqueProcessId;        // 0x440 — PID
    LIST_ENTRY ActiveProcessLinks;     // 0x448 — doubly-linked list of all processes
    // ...
    EX_FAST_REF Token;                 // 0x4b8 — fast ref to _TOKEN (pointer | refcount in low bits)
    // ...
    PVOID      ObjectTable;            // 0x570 — _HANDLE_TABLE pointer
    // ...
    UNICODE_STRING ImageFileName;      // short image name (15 chars); full name in SeAuditName
    // ...
} EPROCESS;
```

### Key EPROCESS Fields for Security Research

**`Token` (offset 0x4b8 on Win11 22H2):** An `EX_FAST_REF` union — the actual token pointer has
the bottom 4 bits used as a reference count. To get the real pointer: `Token.Value & ~0xf`.
Token stealing attacks write a SYSTEM process token address into this field of a lower-privileged
process.

**`ActiveProcessLinks`:** Doubly-linked list connecting all EPROCESS structures in the system.
`NtQuerySystemInformation(SystemProcessInformation)` walks this list to return the process list.
DKOM (Direct Kernel Object Manipulation) attacks unlink a process from this list to hide it.
PatchGuard (KPP) monitors this structure on modern Windows — corruption triggers a deliberate
system crash.

**`ObjectTable`:** Points to the `_HANDLE_TABLE` for this process. Corrupting handle table entries
is a technique to escalate handle access rights without re-running an access check.

### New EPROCESS Security Fields — Build 26100 (Windows 11 24H2)

Build 26100 introduced and expanded several security-relevant EPROCESS fields. Always verify
current offsets with `dt nt!_EPROCESS` in WinDbg:

**`TrustletIdentity`:** Links the process to a VBS Enclave or TrustLet. A non-zero value indicates
the process is a Secure Enclave running inside VTL 1 (e.g., `lsaiso.exe` for Credential Guard).
Attempting to directly read or write the memory of a TrustLet process from VTL 0 kernel code will
fail — VTL 1 enforces the isolation boundary at the hypervisor level.

**`SignatureLevel` / `SectionSignatureLevel`:** Control code integrity enforcement granularity on
a per-process basis. These fields determine what signing policies apply when mapping executable
sections into the process. Bypassing these fields is a prerequisite for injecting unsigned code
into protected processes.

**`MitigationFlagsOverride`:** A per-process override for system-wide mitigation policies. Some
mitigations applied system-wide via `NtSetSystemInformation` can be overridden at the process
level through this field. Kernel exploits that modify this field can disable mitigations (such as
CFG or CET) for a target process.

**`KernelSilo` / `SiloedProcess`:** Container isolation fields, significantly expanded for Windows
Server 2025 and 24H2. A process running inside a silo has an isolated object namespace, registry
view, and process list. Silo escape vulnerabilities allow a containerized process to affect the
host NT environment.

**`ProtectedProcessFlags` (extended):** Additional PPL (Protected Process Light) signer types were
added in 24H2. The signer type determines what other processes may open a PPL with what access.
New signer types tighten the set of processes that can interact with kernel security services.

### New ETHREAD Security Fields — Build 26100

**`CetUserShadowStack`:** The CET (Control-flow Enforcement Technology) user-mode shadow stack
pointer for this thread. A kernel-context write into this field can redirect the shadow stack to
attacker-controlled memory, enabling a CET bypass. This is a high-value target for kernel exploit
chains on 24H2 systems with CET enabled.

**`SuppressDebugMsg`:** Per-thread anti-debug policy bit. When set, debug messages from this thread
are suppressed. Anti-debug techniques operating at the kernel level may set this to conceal activity
from user-mode debugger attachments.

**`ThreadLoggingEnabled`:** Per-thread ETW (Event Tracing for Windows) trace enable flag. Clearing
this bit suppresses per-thread telemetry. An attacker with kernel write access can flip this bit to
blind EDR products that rely on kernel ETW channels for behavioral visibility into a specific thread.

### WinDbg — Working With EPROCESS

```windbg
; List all processes (brief)
!process 0 0

; Find a specific process by name
!process 0 0 lsass.exe

; Dump full EPROCESS structure
dt nt!_EPROCESS <addr>

; Dump only the Token field
dt nt!_EPROCESS <addr> Token

; Switch debugger context to process (required to read its user-mode memory)
.process /p <eprocess_addr>

; Get the real token pointer from an EPROCESS address
? (poi(<eprocess_addr>+0x4b8) & ~0xf)

; Dump the token at that address
!token (poi(<eprocess_addr>+0x4b8) & ~0xf)

; Dump tokens for all processes using for_each_process
!for_each_process "!token (poi(@$extret+0x4b8) & ~0xf)"

; Check HVCI / CI enforcement mode (Build 26100+)
; 0x8 = HVCI enforced, 0x4 = KMCI (kernel mode CI), 0x2 = IUM (Isolated User Mode)
dx @$ci = *(int*)&nt!g_CiOptions
```

### ETHREAD — The Thread Executive Object

```c
typedef struct _ETHREAD {
    KTHREAD       Tcb;              // 0x000 — embedded KTHREAD (scheduler state)
    // ...
    CLIENT_ID     Cid;              // Thread ID + process ID pair
    // ...
    EX_FAST_REF   ThreadToken;      // Impersonation token (NULL = not impersonating)
    // ...
    PEPROCESS     ThreadsProcess;   // Owning process
    // ...
    // Build 26100 additions (verify offsets with dt nt!_ETHREAD):
    PVOID         CetUserShadowStack;    // CET shadow stack pointer
    BOOLEAN       SuppressDebugMsg;     // Anti-debug policy bit
    BOOLEAN       ThreadLoggingEnabled; // Per-thread ETW trace enable
} ETHREAD;
```

**Thread token vs. process token:** The Security Reference Monitor checks the thread's
impersonation token first. If the thread is not impersonating (ThreadToken is NULL), it falls
back to the process token. This is why impersonation attacks work: if you can set the thread
token to a SYSTEM-level impersonation token, the thread operates as SYSTEM for the duration of
that operation, without modifying the process token (which would be globally visible).

> **Exploitation context:** ch09 §3.9 shows how a 1-byte PreviousMode overwrite exploits _KTHREAD. ch10 §10.10 shows how FudModule reads EPROCESS.Token for token stealing.

```windbg
; Dump current thread
!thread

; Full thread info by ETHREAD address
!thread <addr> f

; All threads of a specific process
!process <eprocess_addr> 7

; Switch thread context
.thread <ethread_addr>
```

---

## 4. The Object Manager and Handle Tables

Every kernel resource — process, thread, file, registry key, event, mutex, token, section — is
a kernel object managed by the Object Manager (prefix: `Ob`). Objects live in kernel pool memory
with a standard `_OBJECT_HEADER` prepended to the object body.

### Object Header Structure

```c
typedef struct _OBJECT_HEADER {
    LONG_PTR  PointerCount;     // Total references (kernel pointers hold object alive)
    LONG_PTR  HandleCount;      // Open handle count (drops to 0 → delete procedure called)
    // ...
    UCHAR     TypeIndex;        // Index into ObpObjectTypes[] (XOR'd with cookie, Win8+)
    UCHAR     TraceFlags;
    UCHAR     InfoMask;         // Bitmask: which optional sub-headers precede this header
    UCHAR     Flags;            // Permanent, DefaultSecurityQuota, etc.
    // Optional headers (name, creator info, etc.) precede the _OBJECT_HEADER
    // Object body follows immediately after _OBJECT_HEADER
} OBJECT_HEADER;

// To get from object body pointer to header:
POBJECT_HEADER hdr = (POBJECT_HEADER)((PUCHAR)objectBody - sizeof(OBJECT_HEADER));
```

**TypeIndex obfuscation (Win8+):** The raw `TypeIndex` stored in memory is XOR'd with a
per-boot random cookie and with bits from the page address. This prevents reliable type confusion
attacks: an attacker who overwrites TypeIndex must also leak the cookie or pre-compute the
XOR'd value. This is a non-trivial mitigation for type confusion exploits.

### Object Namespace

The object manager maintains a hierarchical namespace analogous to a filesystem:

```
\                               Root directory
├── Device\                     Kernel device objects (disk, network, etc.)
├── Driver\                     Driver objects
├── BaseNamedObjects\           User-accessible named objects (mutexes, events, sections)
├── Sessions\<N>\               Per-session named objects (N = logon session ID)
│   └── AppContainerNamedObjects\<PackageSid>\   AppContainer-isolated namespace
├── KernelObjects\              Kernel-only sentinel objects
├── ObjectTypes\                Object type descriptor objects
└── GLOBAL??                    Symlinks to DOS device names (C:, \\.\pipe, etc.)
```

```windbg
; Navigate the object namespace
!object \
!object \Device
!object \BaseNamedObjects

; Inspect an object
!object \Device\Harddisk0\DR0

; Dump the object header
dt nt!_OBJECT_HEADER <header_addr>

; List all object types registered in the system
!objtype
```

### Handle Tables — Structure and Security

A handle is a 32-bit integer, opaque to user mode, that the kernel uses as an index into the
calling process's handle table. The table is stored in pageable kernel memory, pointed to by
`EPROCESS.ObjectTable`.

```
EPROCESS.ObjectTable -> _HANDLE_TABLE
    .TableCode -> (low 2 bits = level; 00 = single page, 01 = 2-level, 10 = 3-level)
        Level 0: direct array of _HANDLE_TABLE_ENTRY (up to 256 handles per page)
        Level 1: array of pointers to entry pages (up to ~16K handles)
        Level 2: 2-level tree (up to ~16M handles)

_HANDLE_TABLE_ENTRY (16 bytes on x64):
    ObjectPointerBits : 52-bit encoded pointer to _OBJECT_HEADER (addr >> 4)
    GrantedAccessBits : access rights stored when handle was opened
    Attributes        : HANDLE_FLAG_INHERIT, HANDLE_FLAG_PROTECT_FROM_CLOSE
```

**Critical security property — no re-evaluation:** `GrantedAccessBits` is evaluated and stored
when the handle is opened (`OpenProcess`, `CreateFile`, etc.). Subsequent operations using the
handle (e.g., `ReadFile`, `WriteProcessMemory`) do NOT re-run the access check — they only verify
that the handle's stored access mask covers the requested operation. If an attacker achieves an
arbitrary kernel write and overwrites `GrantedAccessBits` to add `PROCESS_ALL_ACCESS`, they
escalate the handle permanently without passing any security check.

**Handle inheritance abuse:** Handles with `HANDLE_FLAG_INHERIT` set are duplicated into child
processes on `CreateProcess`. A bug pattern: a privileged service opens a handle to a sensitive
resource (e.g., a SYSTEM process with `PROCESS_ALL_ACCESS`) and then spawns a lower-privileged
child. The child inherits the fully-privileged handle — a privilege boundary violation exploitable
via `DuplicateHandle` or direct use.

```windbg
; List all handles for a process (verbose)
!handle 0 f <pid>

; Decode a specific handle value for a process
!handle <handle_value> f <pid>

; Dump the handle table structure
dt nt!_HANDLE_TABLE <objecttable_addr>

; Dump a handle table entry
dt nt!_HANDLE_TABLE_ENTRY <entry_addr>
```

---

## 5. The Kernel Pool Allocator

The kernel pool is the slab allocator for all kernel data structures. Understanding its internals
is required for pool overflow exploitation and pool feng shui grooming techniques.

### Pool Types

| Pool Type | Pageable | Executable | Notes |
|-----------|----------|------------|-------|
| `NonPagedPool` | No | Yes (legacy) | Pre-Windows 8; avoid in new code |
| `NonPagedPoolNx` | No | **No** | Standard NP pool, Windows 8+; default |
| `PagedPool` | Yes | No | Most kernel objects; can page out at PASSIVE_LEVEL |
| `SessionPool` | Yes | No | Per-logon-session objects; win32k.sys |
| `NonPagedPoolNxCacheAligned` | No | No | Cache-line-aligned NP allocations |

**NonPagedPoolNx is the default for modern driver allocations.** The Nx (non-executable) property
means pool overflows cannot place shellcode in the overflowed buffer — the CPU will fault on
execute. Attackers must instead corrupt a function pointer or a data structure that is subsequently
dereferenced in a call.

### Classic Pool Header (pre-Win10 21H2)

```c
// _POOL_HEADER — 8 bytes prepended to every allocation in the classic pool
typedef struct _POOL_HEADER {
    union {
        struct {
            USHORT PreviousSize : 8;  // Previous block size (in 16-byte granularity units)
            USHORT PoolIndex    : 8;
            USHORT BlockSize    : 8;  // This block size (in 16-byte units)
            USHORT PoolType     : 8;  // Pool type flags
        };
        ULONG  Ulong1;
    };
    ULONG  PoolTag;          // 4-byte ASCII tag — stored little-endian in memory
    union {
        PEPROCESS ProcessBilled;
        struct {
            USHORT AllocatorBackTraceIndex;
            USHORT PoolTagHash;
        };
    };
} POOL_HEADER; // Total: 16 bytes on x64 (header + tag + union)
```

**Classic pool overflow:** Overflow into `POOL_HEADER.PoolType`, `BlockSize`, and `PoolTag` of the
adjacent chunk. With control of these fields, the attacker can craft a fake free operation that
redirects to an attacker-controlled address — a write-what-where primitive via pool freelist
manipulation.

### Segment Heap (Windows 10 21H2+)

Microsoft replaced the classic pool allocator with a segment-heap design for kernel pool. Key
differences:

- Allocations are made from large page-backed segments, not the classic slab.
- Allocation metadata is separated from the allocation body (reduces header corruption impact).
- Free list encoding uses per-segment encryption, complicating metadata overwrite attacks.
- Classic `POOL_HEADER` overflow → controlled free does NOT apply directly.

**Modern exploitation approach:** Overflow into adjacent object bodies (not headers) to corrupt
data fields, function pointers, or object types. Pool feng shui techniques are still applicable
but targeting different objects.

### Segment Heap Hardening — 2024 Updates

The segment heap received additional hardening in 2024 builds that directly impacts exploitation
techniques:

**Metadata pointer encoding:** Free-list pointers in the VS (Variable Size) allocator and LFH
(Low Fragmentation Heap) buckets are now XOR-encoded with a per-session random secret. An attacker
who overwrites a free-list pointer must first leak the session secret to construct a valid encoded
pointer. Unencoded pointer writes cause a fault on the next allocation from that bucket.

**Type isolation:** Allocations of different kernel object types are placed in separate segments.
For example, `_TOKEN` objects and `_EPROCESS` objects will not share a segment. This prevents a
heap spray from placing attacker-controlled objects of one type adjacent to critical objects of
another type by simply spraying the same size class.

**Safe-unlinking checks expanded:** The existing safe-unlinking validation (verifying that
`entry->Flink->Blink == entry` before unlinking) has been extended to cover additional list types
within the segment heap internal structure.

**Impact on exploit chains — required sequence for modern kernel heap exploits (2024+):**

```
1. Information leak primitive  →  leak heap metadata secret / object addresses
2. Heap spray (type-specific)  →  spray objects of the exact target type to fill correct segment
3. Type confusion trigger      →  corrupt object type field or confuse allocator about type
4. Arbitrary read/write        →  leverage type confusion for R/W primitive
5. EPROCESS token swap         →  write SYSTEM token into target EPROCESS.Token field
```

The key change from pre-2024 chains: generic heap sprays that ignore type isolation will fail.
The spray must place objects in the specific segment where the victim object lives.

### Pool Tags

Every pool allocation carries a 4-byte ASCII tag. Tags are stored little-endian in memory, so
the tag `'Proc'` appears as bytes `63 6F 72 50` (`corP`) when viewed with `db`.

Common tags relevant to security research:

| Tag | Object |
|-----|--------|
| `Proc` | EPROCESS |
| `Thre` | ETHREAD |
| `File` | FILE_OBJECT |
| `Toke` | _TOKEN |
| `Driv` | DRIVER_OBJECT |
| `Irp ` | IRP |
| `MmSt` | Memory manager structures |
| `HvlE` | Hypervisor structures |

```windbg
; Find all NonPagedPool allocations with tag 'Proc'
!poolfind Proc 0

; Find all PagedPool allocations with tag 'File'
!poolfind File 1

; Pool usage grouped by tag (sorted by allocation count)
!poolused 2

; Pool usage sorted by total bytes
!poolused 4

; Inspect a specific pool allocation
!pool <allocation_addr>
```

### Pool Feng Shui — Grooming Technique

Pool feng shui is the technique of pre-arranging pool allocations so a vulnerable allocation
lands immediately adjacent to a target object, enabling precise overflow targeting.

**Steps:**

1. **Drain:** Allocate many same-size objects to consume free chunks of the target size class.
2. **Create holes:** Free specific objects in a controlled pattern to create gaps at known offsets.
3. **Trigger vulnerable allocation:** The vulnerable code path allocates into one of the prepared
   gaps, landing adjacent to the target object.
4. **Overflow/overwrite:** Trigger the bug to overwrite the target object's fields.

For segment-heap targets with 2024 type isolation, the grooming must respect type boundaries —
drain and spray with objects of the same type as the victim to land in the same segment. Commonly
targeted objects for grooming: `_OBJECT_TYPE_INITIALIZER` (contains function pointer table),
lookaside list entries, or the token structure itself.

> **See also:** ch10 §10.1–10.5 for full Segment Heap exploitation workflow. ch08 §8 for pool corruption bug class overview.

---

## 6. Virtual Memory — VAD Tree, PTEs, Section Objects

### Address Space Layout (x64)

```
0x0000000000000000 - 0x00007FFFFFFFFFFF   User-mode VA space (128 TB)
0xFFFF800000000000 - 0xFFFFFFFFFFFFFFFF   Kernel VA space (128 TB, KASLR randomized)

User-mode regions (approximate; ASLR randomizes base):
  0x00000000000000 - 0x0000FFFF           Not mappable (NULL page prevention)
                                           MmLowestUserAddress = 0x10000
  Image load region                       ntdll.dll, PE images
  Stack                                   grows down; guard page at bottom
  Heap                                    grows from HeapCreate base
```

**Historical note — NULL page mapping (32-bit XP era):** On 32-bit Windows XP, user mode could
map page 0, enabling kernel NULL dereference exploitation: the kernel dereferences NULL, lands in
attacker-controlled memory. Vista+ blocks this via `MmLowestUserAddress = 0x10000`. On 64-bit
Windows this is non-exploitable due to address space size.

### The VAD Tree

Every committed user-mode memory region is tracked by a `_MMVAD` node in a per-process red-black
tree rooted at `EPROCESS.VadRoot`. One node covers each contiguous range of pages with the same
type and protection.

```c
typedef struct _MMVAD {
    ULONG_PTR   StartingVpn;       // Starting virtual page number (VPN = VA >> 12)
    ULONG_PTR   EndingVpn;         // Ending virtual page number (inclusive)
    MMVAD_FLAGS VadFlags;          // Type, protection, private/shared, no-cache, guard, etc.
    PVOID       FirstPrototypePte; // For file-backed sections: first prototype PTE
    MMVAD*      LeftChild;
    MMVAD*      RightChild;
    MMVAD*      Parent;
    // ...
} MMVAD;
```

**VAD types and their security relevance:**

| VadType | Meaning | Research relevance |
|---------|---------|-------------------|
| `VadNone` (0) | Private committed memory (VirtualAlloc) | Standard exploit workspace |
| `VadImageMap` (2) | PE image mapping (LoadLibrary) | Code injection, DLL injection |
| `VadAwe` (3) | AWE physical memory mapping | Uncommon; AWE exploits |
| `VadRotatePhysical` (4) | GPU/driver physical mapping | Driver attack surface |

```windbg
; Walk the VAD tree for current process
!vad

; Verbose VAD walk (shows protection and type for each node)
!vad <vad_root_addr> 1

; Show memory region info for a specific address
!address <user_addr>
```

### Page Table Entries (PTEs)

The PTE is the hardware page table entry mapping a virtual page to a physical frame with CPU-enforced
access permissions. Windows uses a 4-level page table hierarchy on x64 (PML4 -> PDPT -> PD -> PT).

```
x64 PTE bit layout (64-bit):
  Bit  0   (P)    Present: 1 = page resident in physical memory
  Bit  1   (R/W)  Read/Write: 0 = read-only, 1 = read-write
  Bit  2   (U/S)  User/Supervisor: 0 = kernel-only, 1 = user-accessible
  Bit  3   (PWT)  Write-Through cache policy
  Bit  4   (PCD)  Cache Disable
  Bit  5   (A)    Accessed (set by CPU on read)
  Bit  6   (D)    Dirty (set by CPU on write)
  Bit  7   (PS)   Page Size (used in PDE for large pages)
  Bits 12-51      Physical Frame Number (PFN)
  Bit  63  (XD)   Execute Disable (NX bit)

Software-defined PTE states (P=0):
  Demand-zero: all bits 0 — page not yet allocated, zero on demand
  Transition:  PFN set, P=0 — page on standby/modified list, not in working set
  Paged-out:   P=0, PFN points to pagefile entry — page swapped to disk
```

**PTE manipulation as a kernel exploit primitive:** With an arbitrary kernel write, an attacker
can:
1. Find the PTE for a user-mode page (using the self-referencing PTE trick or PTE_BASE)
2. Clear bit 63 (NX) and ensure bit 1 (R/W) is set
3. The user-mode page is now executable from kernel mode

HVCI defeats this: PTE updates flow through the Secure Kernel (VTL 1), which rejects attempts to
make non-code pages executable. This is why HVCI-enabled targets (including all new 24H2 installs
with compatible hardware) require code-reuse attacks.

```windbg
; Display PTE for a virtual address
!pte <virtual_addr>

; Manual virtual-to-physical translation
!vtop <cr3_value> <virtual_addr>

; Physical page information by PFN
!pfn <pfn_number>
```

### Guard Pages

Guard pages have the `PAGE_GUARD` modifier set in the VAD/PTE protection. First access raises
`STATUS_GUARD_PAGE_VIOLATION`:

- **Thread stack growth:** The lowest committed stack page is a guard page. Touching it causes the
  Memory Manager to commit the next lower page and move the guard page down one level, growing the
  stack automatically.
- **Heap corruption detection:** Some allocators (e.g., PageHeap) place guard pages between
  allocations to catch overflows.
- **Security tripwire:** Developers can create deliberate guard pages to detect unexpected access.

An uncontrolled stack overflow that silently consumes all guard pages (and stack memory) before
the process crashes can sometimes be redirected as an exploit primitive if it overwrites adjacent
stack frames.

### Section Objects — The Shared Memory Mechanism

A section object (`_SECTION`, backed by a `_CONTROL_AREA` + `_SEGMENT` in kernel pool) is the
kernel object underpinning all file mappings and inter-process shared memory.

```
CreateFileMapping(hFile, NULL, PAGE_READWRITE, 0, 4096, "MySection")
    -> NtCreateSection(...)
        -> MiCreateSection()
            -> Allocates _CONTROL_AREA in kernel pool (tag: 'CcCa' or similar)
            -> Allocates _SEGMENT
            -> Returns HANDLE to _SECTION object in calling process

MapViewOfFile(hMapping, FILE_MAP_ALL_ACCESS, 0, 0, 0)
    -> NtMapViewOfSection(...)
        -> MiMapViewOfSection()
            -> Creates _MMVAD node covering mapped range in calling process's VAD tree
            -> Returns user-mode VA pointer
```

**Security-relevant patterns:**

1. A privileged process creates a section with `PAGE_EXECUTE_READWRITE` and names it in
   `\BaseNamedObjects\`. An unprivileged process opens the section and writes shellcode to it.
   The privileged process then executes from that shared page — arbitrary code execution under
   elevated privilege.

2. A section object's security descriptor controls who can open it. Misconfigured sections in
   `\BaseNamedObjects\` with world-open permissions (`Everyone: GENERIC_ALL`) are classic
   privilege escalation targets.

3. `NtMapViewOfSection` can create a mapping writable by one caller but readable (or executable)
   by another if the section's protection and callers' desired access are crafted correctly.

---

## 7. The IRP Lifecycle

The I/O Request Packet (IRP) is the fundamental communication unit between the I/O Manager and
kernel drivers. Writing correct drivers requires deep IRP understanding; finding driver bugs
requires the same knowledge applied adversarially.

### IRP Structure Key Fields

```c
typedef struct _IRP {
    CSHORT              Type;            // IO_TYPE_IRP (always)
    USHORT              Size;
    PMDL                MdlAddress;      // For direct I/O — MDL describing user buffer
    ULONG               Flags;           // IRP_NOCACHE, IRP_SYNCHRONOUS_API, etc.
    union {
        IRP*            MasterIrp;       // For associated IRPs (scatter-gather)
        PVOID           SystemBuffer;    // For buffered I/O — kernel-side copy
    } AssociatedIrp;
    IO_STATUS_BLOCK     IoStatus;        // Status + Information (bytes transferred) on completion
    KPROCESSOR_MODE     RequestorMode;   // KernelMode or UserMode — CRITICAL for validation
    BOOLEAN             PendingReturned; // Must be TRUE if STATUS_PENDING returned from dispatch
    BOOLEAN             Cancel;          // Set to TRUE when IRP cancellation requested
    KIRQL               CancelIrql;
    PDRIVER_CANCEL      CancelRoutine;
    // IO_STACK_LOCATION array follows the IRP in memory
} IRP;
```

### Complete IRP Lifecycle Trace

```
User mode: ReadFile(handle, buffer, length, &bytesRead, NULL)
    |
    | [system call boundary — SSDT -> NtReadFile]
    ↓
NtReadFile():
    1. ObReferenceObjectByHandle(handle, FILE_READ_DATA, ...) -> FILE_OBJECT*
    2. IoAllocateIrp(StackSize, FALSE) -> IRP*
    3. Fill IRP stack location:
         MajorFunction = IRP_MJ_READ
         Parameters.Read.Length = length
         Parameters.Read.ByteOffset = filePosition
    4. For METHOD_BUFFERED: copy user buffer to Irp->AssociatedIrp.SystemBuffer
    5. IoSetCompletionRoutine(Irp, ...) if synchronous
    6. IoCallDriver(TopOfDeviceStack, Irp)
    |
    ↓ [each driver in the device stack receives IRP via its dispatch table]
Filter Driver (if present):
    - Optionally inspect/modify the IRP
    - IoCopyCurrentIrpStackLocationToNext(Irp)
    - IoCallDriver(NextDevice, Irp) — forward down
    |
    ↓
Lowest Driver (e.g., disk driver):
    1. IoMarkIrpPending(Irp)          <- MANDATORY before returning STATUS_PENDING
    2. Queue to internal work queue
    3. return STATUS_PENDING
    |
    | [hardware interrupt / DPC fires when I/O completes]
    ↓
DPC / Worker Thread:
    1. Transfer data
    2. Irp->IoStatus.Status = STATUS_SUCCESS
    3. Irp->IoStatus.Information = bytes_transferred
    4. IoCompleteRequest(Irp, IO_DISK_INCREMENT)
    |
    ↓ [completion routines execute LIFO, one per driver that set one]
Completion Routines (bottom-up):
    - Each may transform or post-process the IRP
    - Must return STATUS_MORE_PROCESSING_REQUIRED to retain the IRP
    - Otherwise return STATUS_SUCCESS to continue unwinding
    |
    ↓
IRP freed internally after last completion routine returns
NtReadFile: event signaled, returns STATUS_SUCCESS with bytesRead filled
```

### IRP Bug Patterns — Driver Attack Surface

| Bug | Root Cause | Consequence |
|-----|-----------|-------------|
| Missing `IoMarkIrpPending` | Return `STATUS_PENDING` without setting the flag | IRP completed twice; crash |
| Access after `IoCompleteRequest` | Read/write IRP fields post-completion | Use-after-free; heap corruption |
| Cancellation race | IRP cancelled between dispatch and completion | NULL dereference; double-free |
| Double complete | `IoCompleteRequest` called twice on same IRP | Kernel panic |
| No `ProbeForRead/Write` | Access user buffer without validation | TOCTOU; kernel memory overwrite |
| Wrong buffering method | Mix buffered/direct/neither modes | Memory disclosure or write |
| Missing `STATUS_MORE_PROCESSING_REQUIRED` | Completion routine forgets sentinel | IRP freed prematurely |
| Synchronous IRP at DISPATCH_LEVEL | Wait inside an IOCTL at wrong IRQL | Deadlock or BSOD |
| ProbeForRead bypass | Check once, use multiple times (TOCTOU) | Arbitrary kernel read/write |

```windbg
; Inspect an IRP by address
!irp <irp_addr>

; Dump IRP structure fields
dt nt!_IRP <irp_addr>

; View device object and its pending IRP queue
!devobj <device_object_addr>
```

---

## 8. The Security Reference Monitor — Access Check

The Security Reference Monitor (SRM, prefix: `Se`) is the kernel component that performs all
access control decisions. It is invoked for every object open operation and is the enforcement
point for both the DACL and Mandatory Integrity Control.

### Token vs. Security Descriptor

The access check is always a comparison between:
- **Token** (who is asking): user SID, group SIDs, privileges, integrity level, AppContainer state
- **Security Descriptor** (what is the object's policy): DACL, SACL, mandatory label

### The Three-Gate Access Check

```
Request: Token T wants access mask A on Object O
                          |
                          v
+---------------------------------------------------+
| Gate 1: Mandatory Integrity Control (MIC)         |
|                                                   |
| Compare Token.IntegrityLevel vs SD.MandatoryLabel |
|                                                   |
| NO_WRITE_UP (default): if Token.IL < Object.IL    |
|   AND requested access includes any write right   |
|   -> DENY immediately (before DACL evaluation)    |
|                                                   |
| NO_READ_UP: if Token.IL < Object.IL               |
|   AND requested access includes any read right    |
|   -> DENY                                         |
|                                                   |
| NO_EXECUTE_UP: similar for execute rights         |
+--------------------+------------------------------+
                     | PASS
                     v
+---------------------------------------------------+
| Gate 2: DACL Check                                |
|                                                   |
| Special shortcuts:                                |
|   NULL DACL -> grant all access (fully open)      |
|   Empty DACL -> deny all access                   |
|   Owner matches token -> WRITE_DACL/READ_CONTROL  |
|   SeTakeOwnershipPrivilege -> WRITE_OWNER         |
|                                                   |
| Walk ACEs in order:                               |
|   ACCESS_DENIED_ACE: SID in token? -> clear bits  |
|   ACCESS_ALLOWED_ACE: SID in token? -> set bits   |
|   Stop when DesiredAccess fully satisfied         |
|                                                   |
| GrantedAccess covers DesiredAccess? -> PASS       |
| Otherwise -> DENY                                 |
+--------------------+------------------------------+
                     | PASS
                     v
+---------------------------------------------------+
| Gate 3: AppContainer Capability Check             |
| (only if token has IsAppContainer = TRUE)         |
|                                                   |
| Does SD contain AppContainer-specific ACEs?       |
| Does token's Capabilities[] include required SID? |
|   Yes -> PASS; No -> DENY                         |
+--------------------+------------------------------+
                     | PASS
                     v
                 Access Granted
```

**ACE ordering is critical:** A well-formed DACL places Deny ACEs before Allow ACEs. The SRM
processes ACEs strictly in order. If a DACL has `Allow Everyone: GENERIC_ALL` as the first ACE
followed by `Deny Domain Users: GENERIC_ALL`, the Allow wins — the Deny comes too late to remove
already-granted bits. This is a common ACL misconfiguration leading to unintended access.

**Privilege-based bypasses — privilege overrides DACL:**

| Privilege | Effect on Access Check |
|-----------|----------------------|
| `SeTakeOwnershipPrivilege` | Bypass: can set WRITE_OWNER on any object |
| `SeSecurityPrivilege` | Bypass: can read/write SACL on any object |
| `SeBackupPrivilege` | Bypass: FILE_FLAG_BACKUP_SEMANTICS skips DACL on file open |
| `SeRestorePrivilege` | Bypass: same bypass for file write operations |
| `SeDebugPrivilege` | Special case: enables PROCESS_ALL_ACCESS on any process handle |

```windbg
; Dump a token by address
!token <addr>
dt nt!_TOKEN <addr>

; Dump token privileges structure
dt nt!_SEP_TOKEN_PRIVILEGES <addr>

; Security descriptor display
!sd <sd_addr>

; ACL inspection
!acl <acl_addr>

; SID string display
!sid <sid_addr>

; Full EPROCESS + token dump for a specific process
.process /p <eprocess_addr>
!token
```

---

## 9. Recent Developments (2024–2025)

### 9.1 VBS/VTL Changes — Windows 11 24H2 (Build 26100, October 2024)

#### HVCI On By Default

HVCI (Hypervisor-Protected Code Integrity) is now enabled by default on all new Windows 11 24H2
installs with compatible hardware. This is the single most significant change for kernel exploit
developers since the introduction of PatchGuard.

**Hardware requirements for 24H2 HVCI:**
- SLAT (Second Level Address Translation): Intel EPT or AMD RVI
- IOMMU: Intel VT-d or AMD-Vi (required for DMA protection)
- TPM 2.0
- Secure Boot
- MBEC (Mode-Based Execute Control) — required for the lower-overhead path

**Performance overhead:**
- With MBEC hardware support: approximately 2% overhead
- Without MBEC (software emulation): 5–10% overhead

**Impact on kernel exploit development:**

A write primitive alone is no longer sufficient on HVCI-enabled systems. The classic exploit
chain `arbitrary write → PTE flip to executable → shellcode execute` is blocked by the Secure
Kernel in VTL 1, which intercepts PTE modification hypercalls and rejects changes that would
make non-code pages executable.

Required primitive upgrade: a code-reuse attack (ROP chain executing from existing kernel code)
or a VTL 1 escape (targeting the Secure Kernel itself, a significantly higher bar).

```windbg
; Check HVCI / Code Integrity enforcement mode
; 0x8 = HVCI enforced (VTL1 active)
; 0x4 = KMCI (kernel mode code integrity, no VTL1 required)
; 0x2 = IUM (Isolated User Mode / Credential Guard)
dx @$ci = *(int*)&nt!g_CiOptions
```

#### Credential Guard On By Default (Domain-Joined)

Credential Guard is now enabled by default on domain-joined systems in 24H2. The implementation
runs `lsaiso.exe` as a TrustLet in VTL 1. NTLM hashes and Kerberos ticket-granting ticket (TGT)
material are stored inside the VTL 1 enclave, inaccessible to VTL 0 kernel code.

Consequence for credential dumping tools: LSASS memory read attacks (Mimikatz-style) against
`lsass.exe` in VTL 0 will find that credential material has been replaced with opaque handles.
The actual secrets live in `lsaiso.exe` in VTL 1.

Check from kernel debug session:
```windbg
; lsaiso.exe TrustletIdentity will be non-zero
!process 0 0 lsaiso.exe
dt nt!_EPROCESS <addr> TrustletIdentity
```

#### securekernel.exe VTLCALL Interface Update

The VTLCALL interface (the hypercall table between VTL 0 and the Secure Kernel) received new
entries in 24H2 `securekernel.exe`. Notable addition: `SkmmVtlProtect`, which provides VTL 1
managed memory protection services. Analysis of the updated VTLCALL table is a prerequisite for
any VTL 1 escape research targeting 24H2.

### 9.2 CVE-2024-21338 — EPROCESS Manipulation Case Study

This CVE is the most significant public example of EPROCESS-based exploitation in 2024. It
demonstrates the full attack chain from a built-in Windows driver vulnerability to EDR blindness.

**Vulnerability:**
- **Component:** `appid.sys` — the Windows AppLocker kernel driver, a built-in Windows component
- **Class:** Arbitrary kernel read/write primitive via IOCTL handler vulnerability
- **CVSS Score:** 7.8 (High)
- **Patch:** February 2024 Patch Tuesday (KB5034763)
- **CISA KEV:** Added to the Known Exploited Vulnerabilities catalog

**Threat actor:** Lazarus Group (DPRK APT) — used in the FudModule v2 rootkit campaign.

**Why `appid.sys` is notable:** Unlike BYOVD (Bring Your Own Vulnerable Driver) attacks that
require installing a third-party driver, `appid.sys` is a built-in Windows driver. It is present
on systems where AppLocker is configured — often the same enterprise security-hardened environments
that have blocked third-party driver loading.

**Full attack chain:**

```
1. Exploit CVE-2024-21338 in appid.sys IOCTL handler
   → Obtain arbitrary kernel read/write primitive (VTL 0)

2. Walk PsActiveProcessHead linked list
   → Traverse EPROCESS.ActiveProcessLinks to enumerate all processes
   → Locate target EPROCESS and SYSTEM EPROCESS structures

3. Token stealing
   → Read SYSTEM_EPROCESS.Token → get SYSTEM token address
   → Write SYSTEM token address into target_EPROCESS.Token
   → Target process now runs with SYSTEM privileges

4. DKOM — Direct Kernel Object Manipulation
   → Modify target_EPROCESS.ActiveProcessLinks
   → Unlink process from doubly-linked list
   → Process no longer appears in NtQuerySystemInformation(SystemProcessInformation)
   → Hidden from Task Manager, Process Explorer, EDR process enumeration

5. EDR callback nullification
   → Locate and null out PsLoadImageNotifyRoutine[] array entries
   → Locate and null out PsCreateProcessNotifyRoutine[] array entries
   → EDR kernel callbacks are no longer invoked for image loads and process creation
   → Kernel-level behavioral visibility of EDR products is severed
```

**Research significance:** Step 5 — nullifying `PsLoadImageNotifyRoutine` — is particularly
impactful because most modern EDRs rely on these callbacks as the primary kernel telemetry channel.
After nullification, the EDR's kernel driver continues running but receives no notifications for
new processes or image loads. The attacker has achieved kernel-level stealth without directly
attacking the EDR driver itself.

**Reference:** https://decoded.avast.io/janvojtesek/lazarus-and-the-fudmodule-rootkit-beyond-byovd-with-an-admin-to-kernel-zero-day

> **Full exploit chain:** ch13 §13.10. **Variant hunting:** ch12 §11. **Callback table layout:** ch10 §10.10.

### 9.3 Vulnerable Driver Blocklist — Auto-Update (2024)

The Microsoft Recommended Driver Block Rules list (`wdac_policy.xml`) was significantly expanded
in 2024. The blocklist now ships via two channels:

- **Windows Defender signature updates (daily):** The blocklist is embedded in Defender definition
  updates, meaning new entries propagate within 24 hours to systems with real-time protection
  enabled.
- **Windows Update (monthly baseline):** The blocklist is also updated as part of the monthly
  cumulative update, reaching systems that may have Defender disabled.

**Practical impact for BYOVD research:**

BYOVD (Bring Your Own Vulnerable Driver) techniques that rely on drivers from the public lists
(e.g., drivers named in public CVEs, tools like LOLDrivers, or drivers previously used in public
exploit chains) will fail on up-to-date Windows 11 24H2 systems. The kernel's driver load path
checks the signature against the blocklist before allowing the driver to initialize.

This does not eliminate BYOVD as a class — it raises the cost by requiring less-known vulnerable
drivers. However, it significantly degrades the reliability of commodity BYOVD kits.

**Current blocklist:** https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules

---

## 10. Cross-Reference: Structures → Bug Classes

| Structure | Field(s) of Interest | Relevant Bug Class | Notable 2024 CVE |
|-----------|---------------------|-------------------|--------------------|
| `_EPROCESS` | `Token` (0x4b8, Win11) | Token theft, token pointer overwrite | CVE-2024-21338 (Lazarus/appid.sys) |
| `_EPROCESS` | `ObjectTable` | Handle table corruption | — |
| `_EPROCESS` | `ActiveProcessLinks` | DKOM process hiding (PatchGuard monitored) | CVE-2024-21338 (DKOM chain) |
| `_EPROCESS` | `TrustletIdentity` (Build 26100) | VBS Enclave / TrustLet identification | — |
| `_EPROCESS` | `SignatureLevel` / `SectionSignatureLevel` | Code integrity bypass per-process | — |
| `_EPROCESS` | `MitigationFlagsOverride` | Per-process mitigation disable | — |
| `_ETHREAD` | `ThreadToken` | Impersonation token injection | — |
| `_ETHREAD` | `CetUserShadowStack` (Build 26100) | CET shadow stack redirect | Shadow stack attacks |
| `_ETHREAD` | `ThreadLoggingEnabled` (Build 26100) | Per-thread EDR telemetry blind | — |
| `_TOKEN` | `Privileges.Present/Enabled` | Privilege escalation | — |
| `_TOKEN` | `IntegrityLevel` | Integrity level bypass | — |
| `_TOKEN` | `IsAppContainer`, `AppContainerSid` | AppContainer sandbox escape | — |
| `_TOKEN` | `RestrictedSids[]`, `IsRestricted` | Restricted token bypass | — |
| `_OBJECT_HEADER` | `TypeIndex` | Object type confusion (obfuscated in Win8+) | — |
| `_POOL_HEADER` | `BlockSize`, `PoolType`, `PoolTag` | Pool overflow (classic pool) | — |
| `Segment Heap` | Free-list pointers (XOR-encoded, 2024) | Type confusion after infoleak | Heap-based type confusion |
| `_HANDLE_TABLE_ENTRY` | `GrantedAccessBits` | Handle access escalation via kernel write | — |
| `_PTE` | NX bit (bit 63), U/S bit (bit 2) | PTE manipulation — blocked by HVCI on 24H2 | — |
| `_MMVAD` | `VadFlags`, protection | Section object abuse, VAD tree confusion | — |
| `_CONTROL_AREA` | Section metadata | Cross-process shared memory manipulation | — |
| `_IRP` | `IoStatus`, `PendingReturned`, `Cancel` | IRP lifecycle bugs in drivers | — |
| `_FILE_OBJECT` | `SecurityDescriptor` | File object ACL bypass | — |
| `_SECURITY_DESCRIPTOR` | DACL pointer, MandatoryLabel | NULL DACL, DACL misconfiguration | — |
| `_DRIVER_OBJECT` | `MajorFunction[]` | Dispatch table hook (DKOM-style attack) | — |
| `PsLoadImageNotifyRoutine[]` | Callback array | EDR callback nullification | CVE-2024-21338 (FudModule) |
| `PsCreateProcessNotifyRoutine[]` | Callback array | EDR callback nullification | CVE-2024-21338 (FudModule) |

### Key Offsets (Windows 11 22H2 x64)

> Always verify with `dt` in WinDbg — offsets change between builds.
> For 24H2 (Build 26100), re-verify all offsets as new fields were added.

```c
// EPROCESS (Win11 22H2 baseline — verify for 24H2)
EPROCESS.UniqueProcessId    = 0x440
EPROCESS.ActiveProcessLinks = 0x448
EPROCESS.Token              = 0x4b8   // EX_FAST_REF; mask with ~0xf for pointer
EPROCESS.ObjectTable        = 0x570

// TOKEN
TOKEN.Privileges.Present    = 0x040
TOKEN.Privileges.Enabled    = 0x048
// IntegrityLevelIndex: verify per-build with dt

// OBJECT_HEADER
OBJECT_HEADER.TypeIndex     = 0x018
OBJECT_HEADER.InfoMask      = 0x01A
// Object body starts at: OBJECT_HEADER addr + sizeof(OBJECT_HEADER) = +0x030
```

---

## 11. Essential WinDbg Commands — Foundational Research

```windbg
; === KERNEL BASE ===
? nt                                        ; kernel image base
lm m nt                                     ; kernel module info and range

; === PROCESS / THREAD ===
!process 0 0                                ; all processes brief
!process 0 0 lsass.exe                     ; find process by name
!process <eprocess> 7                       ; process + all threads
.process /p <eprocess>                      ; switch context to process
!thread                                     ; current thread info
.thread <ethread>                           ; switch to thread context

; === TOKEN & SECURITY ===
!token                                      ; current token
!token <addr>                               ; token at address
!token (poi(<eproc>+0x4b8) & ~0xf)        ; token from EPROCESS
dt nt!_TOKEN <addr>                         ; full token structure
!sd <sd_addr>                               ; security descriptor
!acl <acl_addr>                             ; ACL entries
!sid <sid_addr>                             ; SID string

; === HVCI / CODE INTEGRITY (Build 26100) ===
dx @$ci = *(int*)&nt!g_CiOptions           ; 0x8=HVCI, 0x4=KMCI, 0x2=IUM

; === MEMORY ===
!vad                                        ; VAD tree for current process
!vad <root> 1                              ; verbose VAD walk
!pte <addr>                                 ; page table entry
!address <addr>                             ; region info (protection, type)
!address -f:PAGE_EXECUTE_READ_WRITE         ; find executable+writable pages

; === POOL ===
!pool <addr>                                ; pool block info
!poolfind Proc 0                            ; NP pool by tag
!poolfind File 1                            ; paged pool by tag
!poolused 2                                 ; usage sorted by count

; === OBJECT MANAGER ===
!object \                                   ; root namespace
!object \BaseNamedObjects                  ; named objects
!objtype                                    ; all object types
dt nt!_OBJECT_HEADER <addr>

; === HANDLE TABLE ===
!handle 0 f <pid>                           ; all handles for process
!handle <hval> f <pid>                      ; decode specific handle

; === SSDT ===
dps nt!KiServiceTable L nt!KiServiceLimit  ; dump system call table

; === IRP ===
!irp <addr>                                 ; IRP state
!devobj <addr>                              ; device object + pending IRPs

; === EDR CALLBACK ARRAYS (CVE-2024-21338 research) ===
dps nt!PsLoadImageNotifyRoutine L 8        ; image load callbacks (check for nulled entries)
dps nt!PsCreateProcessNotifyRoutine L 8   ; process create callbacks

; === BATCH TOKEN DUMP ===
!for_each_process "!token (poi(@$extret+0x4b8) & ~0xf)"
```

---

## References

[R-1] *Windows Internals, 7th Edition (Part 1 & 2)* — Mark Russinovich, David Solomon, Alex Ionescu, Pavel Yosifovich — https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals

[R-2] *Windows Security Internals: A Deep Dive into Windows Authentication, Authorization, and Auditing* — James Forshaw — https://nostarch.com/windows-security-internals

[R-3] *Windows Kernel Programming, 2nd Edition* — Pavel Yosifovich — https://leanpub.com/windowskernelprogramming

[R-4] *Windows via C/C++, 5th Edition* — Jeffrey Richter, Christophe Nassare — (ISBN 978-0-7356-2216-0; O'Reilly Learning)

[R-5] ReactOS Source Code (NT-compatible open-source kernel) — https://github.com/reactos/reactos

[R-6] Windows Research Kernel (WRK) — Windows Server 2003 kernel source; key file: `base/ntos/se/accesschk.c` — https://github.com/HighSchool2015/WRK

[R-7] MSDN Win32 API Reference — https://learn.microsoft.com/en-us/windows/win32/api/

[R-8] NT Native API Reference (community-maintained) — https://ntdoc.m417z.com/

[R-9] *Lazarus and the FudModule Rootkit: Beyond BYOVD with an Admin-to-Kernel Zero-Day* — Jan Vojtěšek, Avast Threat Labs, February 2024 — https://decoded.avast.io/janvojtesek/lazarus-and-the-fudmodule-rootkit-beyond-byovd-with-an-admin-to-kernel-zero-day

[R-10] *Microsoft Recommended Driver Block Rules* — Windows App Control for Business documentation — https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules

[R-11] *Microsoft Pluton and VBS Improvements in Windows 11 24H2* — Microsoft Security Blog — https://www.microsoft.com/en-us/security/blog/2024/09/24/advancing-windows-security/

[R-12b] *Hypervisor-Protected Code Integrity (HVCI)* — Microsoft Docs — https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/device-guard-and-credential-guard

[R-12] *Virtualization-Based Security (VBS) Overview* — Microsoft Docs — https://learn.microsoft.com/en-us/windows-hardware/design/device-experiences/oem-vbs

[R-13] LOLDrivers — Living Off The Land Drivers project (vulnerable and malicious driver catalog) — https://www.loldrivers.io/
