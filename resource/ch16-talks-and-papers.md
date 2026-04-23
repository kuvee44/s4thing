# Chapter 16 — Talks, Papers & Methodology

> Conference talks and papers are where research methodology is made explicit. A blog post shows *what* was found. A conference talk, when it is a good one, shows *how* it was found and *why that method works*. This chapter covers the most important talks in the Windows security research canon — not by novelty of the CVE, but by the density of transferable methodology. A researcher who internalizes j00ru's Bochspwn methodology can design a tool that finds 30 bugs in a new subsystem. One who only knows "j00ru found 30 infoleaks in 2017" cannot.

---

## How to Read a Conference Talk as a Researcher

Before the catalog — the extraction framework. When reading or watching a talk, extract answers to these five questions. Talks that answer only 1 and 3 are technique demonstrations. Talks that answer 2, 4, and 5 are methodology contributions.

1. **What is the vulnerability class?** Not the specific CVE — the class. Double-fetch. Missing impersonation. Confused deputy. Weak ACL on shared object.
2. **How was it discovered?** Manual code review? Systematic enumeration? Tool-driven pattern detection? Variant hunt from a previous patch?
3. **What is the exploitation chain?** Vulnerability → primitive → code execution / SYSTEM / sandbox escape.
4. **What did the patch do?** Point fix (blocking one specific code path) or architectural fix (removing the property that enables the class)? Point fixes leave variants.
5. **What methodology generalizes?** Can you apply this approach to find similar bugs in a different component, a different OS version, or a different subsystem? If yes, what would the search query / tool filter / code pattern look like?

Use this framework as a reading checklist. Every talk below is annotated with answers to these questions.

---

## Tier 1 — Methodology-Defining Talks

### Bochspwn: Identifying 0-Days via System-Wide Memory Access Pattern Analysis
**Speaker:** j00ru (Mateusz Jurczyk)
**Conference:** Black Hat USA 2013
**URL:** https://j00ru.vexillium.org/talks/blackhat-usa-bochspwn-identifying-0-days-via-memory-access-analysis/

**What it introduced:**

The first demonstration that an entire kernel vulnerability class can be defined as a memory access pattern and detected mechanically across the entire kernel, without reading source code or auditing individual functions.

**The technical mechanism:**

The Bochs x86 CPU emulator is extended with a memory access instrumentation layer. Every memory read and write that occurs during emulated execution is logged: physical address, virtual address, thread context, syscall context, access type. This gives a complete memory access trace for any syscall or kernel operation.

From this trace, j00ru extracts a pattern: **double-fetch** — the kernel reads the same user-mode virtual address twice within a single syscall dispatch, without an appropriate synchronization lock between the two reads.

**Why double-fetch is a vulnerability class:**

The kernel frequently validates user-supplied values before using them — reading `len` from user memory, checking `len <= MAX_LEN`, then reading `len` again to pass to `memcpy`. The user controls the memory page. A concurrently running attacker thread can modify `len` in the window between the validation read and the use read. If `len` is set to `0xFFFFFFFF` after the `≤ MAX_LEN` check but before the `memcpy`, a heap or stack overflow occurs.

The key property that makes this exploitable: user-mode memory is mapped into the kernel's virtual address space (in pre-KVAS Windows) and can be modified by the user while the kernel is running in another thread.

**Framework 5-question analysis:**

1. *Class:* Double-fetch TOCTOU — user-mode pointer dereferenced multiple times in the same syscall dispatch without a lock
2. *Discovery:* Automated pattern detection via x86 emulator instrumentation — no source code, no manual audit
3. *Exploitation:* Race the check-vs-use window; trigger heap/stack overflow with oversized value after validation
4. *Patch:* Per-bug point fixes — copy the value once into a kernel-controlled variable, use only the copy. The architectural lesson (never re-read user memory after validation) was not enforced universally.
5. *Generalization:* The Bochspwn approach generalizes to any vulnerability class that can be defined as a temporal memory access pattern. Any class where the vulnerability is visible in the sequence of memory reads and writes — not in the semantic meaning of the data — can be found this way.

**Scale:** Multiple bugs surviving from NT4 (1996). Not because they were subtle, but because no one had looked for the pattern systematically. The same code existed for 15+ years.

**The broader lesson for methodology:**

Tool-driven vulnerability class discovery is categorically different from bug-by-bug auditing. A manual auditor checks one function, finds one bug. A tool that detects a vulnerability pattern checks every function simultaneously. The investment in building the tool amortizes over every bug it finds.

---

### Bochspwn Reloaded: Detecting Kernel Memory Disclosure with x86 Emulation and Taint Tracking
**Speaker:** j00ru (Mateusz Jurczyk)
**Conference:** Black Hat USA 2017
**URL:** https://j00ru.vexillium.org/talks/blackhat-usa-bochspwn-reloaded-detecting-kernel-memory-disclosure/

**What it introduced:**

Same Bochs instrumentation framework as 2013, new vulnerability class: **kernel information disclosure via uninitialized memory**. The pattern: kernel allocates a stack frame or pool buffer, initializes some fields but not others (padding bytes, union members, partially-filled arrays), copies the full buffer to a user-mode output address. The uninitialized bytes may contain kernel pointers from previous uses of that memory, defeating KASLR.

**The detection mechanism — taint tracking:**

A *shadow memory* bitmap is maintained parallel to the system's physical memory. One bit per physical byte. The bit starts at `1` (tainted = uninitialized) when memory is allocated. Any write to the byte clears the bit to `0` (clean). When the kernel writes to a user-mode virtual address, the Bochs instrumentation checks if the source bytes are tainted. Tainted bytes reaching user mode = infoleak.

**Taint sources:**
- Freshly allocated kernel stack frame bytes that are never written in the function prologue
- Pool allocations where some struct fields are not initialized for a particular code path
- Tagged union members (union field `A` written for one code path, field `B` written for another; if the full union is copied, the inactive field leaks)

**Taint sinks:**
- Any write to a user-mode virtual address range
- `RtlCopyMemory`, `memcpy`, `NtQuerySystemInformation` output buffer, IOCTL return buffer, etc.

**Why uninitialized memory matters post-KASLR (2017 context):**

In 2017, KASLR was the primary mitigation against kernel exploitation. A reliable kernel infoleak breaks KASLR — the leaked kernel pointer tells the attacker where the kernel is loaded, enabling the remainder of an exploit chain. The Bochspwn Reloaded approach found ~30 infoleak vulnerabilities across `NtQuerySystemInformation` return structures, GDI subsystem output, win32k font handler output buffers, various IOCTL handlers.

**The structural lesson for variant hunting:**

Infoleaks are not isolated one-off bugs — they arise from *structural patterns* in how C code handles structs and buffers:

1. **Padding bytes:** The C compiler inserts alignment padding between struct fields (e.g., a `BYTE` field followed by a `DWORD` gets 3 bytes of padding). This padding is never written by application logic. If the struct is then copied to user mode as a block of bytes, the padding leaks whatever was in that memory before.
   ```c
   // Typical leak: sizeof(struct) includes 3 bytes of padding never written
   typedef struct { BYTE flag; DWORD value; } FOO; // compiler adds 3 bytes padding
   NtQueryFoo(out, sizeof(FOO)); // copies padding bytes too
   ```

2. **Tagged union layouts:** `union { struct A a; struct B b; }` where code path 1 initializes `a` and code path 2 initializes `b`, but in both cases the full `sizeof(union)` is copied. The inactive variant's bytes leak.

3. **Partially-filled arrays:** Array of 10 elements, only 6 populated in a loop, but `sizeof(array)` bytes are copied.

4. **Pool reuse without zeroing:** A pool block freed and reallocated to a different caller retains bytes from the previous use. If the new caller copies the block before fully initializing it, the previous use's data leaks.

**Manual variant search from this framework:**

Search for `RtlCopyMemory` / `memcpy` where the source is a stack-allocated struct. Check whether all fields including padding are initialized before the copy. The Windows kernel headers (available via the WDK and public symbols) show the exact struct layouts including alignment. This is still a valid manual code review pattern — Bochspwn Reloaded automated the search, but the same bugs can be found manually with a narrower scope.

**Framework 5-question analysis:**

1. *Class:* Kernel infoleak via uninitialized memory — struct padding, union inactive fields, partial arrays
2. *Discovery:* Taint tracking via shadow memory + Bochs emulation
3. *Exploitation:* Read the output buffer from a `NtQueryXxx` call; extract kernel pointers; use to defeat KASLR; continue exploit chain
4. *Patch:* Per-bug `RtlZeroMemory` or `memset` before the struct is populated. No architectural fix preventing the pattern.
5. *Generalization:* Manual variant hunt: find all `RtlCopyMemory` calls in kernel where source is stack-allocated struct → check struct definition for padding → determine if padding bytes are zeroed before copy. Scope: any kernel version, any driver.

---

### Bochspwn Revolutions: Further Exploitation of Double-Fetch Bugs in the Windows Kernel
**Speaker:** j00ru (Mateusz Jurczyk)
**Conference:** Infiltrate 2018
**URL:** https://j00ru.vexillium.org/talks/infiltrate-bochspwn-revolutions/

**What it introduced:**

Engineering refinements to both the double-fetch detector and the taint tracker that reduced false positive rates and extended detection coverage to code paths the earlier versions missed.

**Specific improvements:**

1. **Cross-boundary taint tracking:** Bochspwn 2013 tracked double-fetches only within a single syscall dispatch function. If the kernel called a helper function that did the first read, and a second helper function that did the second read, the pattern crossed a function call boundary — the 2013 detector missed it. Revolutions tracks the "user memory was read" state across the call stack for the duration of the syscall, detecting cross-function double-fetch patterns.

2. **Pool reallocation taint persistence:** If a pool block is freed and reallocated to a different caller, some bytes from the previous allocation may remain unwritten by the new caller. Revolutions tracks which bytes in a reallocated block were written by the new caller vs. inherited from the previous use. This found bugs where a struct was passed between functions and only partially re-initialized before use.

3. **False positive reduction heuristics:** The critical engineering contribution. At scale, a taint analysis system generates large numbers of false positives — legitimate code patterns that trigger the detection rule but are not exploitable. Revolutions documents the heuristics needed to filter:
   - PRNG seeding via stack noise (intentional use of uninitialized bytes as entropy)
   - Compiler-optimized loop unrolling that creates write patterns the shadow memory bitmap misidentifies as partial writes
   - `_mm_undefined_ps()` and similar intrinsics that explicitly declare uninitialized vector registers as an optimization hint

**The fundamental principle made explicit:**

*False positive reduction is the bottleneck in automated vulnerability discovery.* Finding more signals does not produce more bugs unless the signals are actionable. Every fuzzer, taint analyzer, CodeQL query, and Semgrep rule faces this constraint: the useful signal is buried in noise, and the engineering work is in noise reduction. This principle applies beyond Bochspwn to any automated analysis approach.

**New bugs found:** Double-fetch patterns crossing DPC (Deferred Procedure Call) boundaries — impossible to detect with single-call-scope taint. Also additional infoleak patterns in driver stack components that the 2017 version instrumented less accurately.

**Framework 5-question analysis:**

1. *Class:* Same as Bochspwn 2013/2017 — double-fetch and uninitialized memory; the contribution is detection coverage improvement, not a new class
2. *Discovery:* Automated — engineering improvements to the existing framework
3. *Exploitation:* Same chains as prior work
4. *Patch:* Point fixes per bug
5. *Generalization:* The false positive reduction methodology generalizes to any automated analysis tool. When building a bug-finding tool: measure false positive rate explicitly, document each false positive category and the heuristic that filters it, and treat false positive reduction as first-class engineering work.

---

### Abusing the NT Object Manager Namespace
**Speaker:** James Forshaw
**Conference:** DEF CON 25 (2017)
**Slides:** Available via DEF CON media archive — search "Forshaw DEF CON 25"

**What it introduced:**

The first comprehensive treatment of the NT object namespace as an *attack surface with exploitable security properties*, rather than an implementation detail for named objects. The key reframe: the object namespace is not just a name→handle mapping system — it is a privilege boundary with its own ACLs, symlink resolution semantics, and per-session directory scoping. Misconfigurations in this boundary are exploitable from low-privilege user space.

**Core techniques demonstrated:**

**Object manager symlink in \BaseNamedObjects\Local\:**
Low-privilege processes can create symbolic link objects in the per-session named object directory (`\Sessions\N\BaseNamedObjects\Local\`). If a privileged process opens a named object (mutex, event, section) using a name that includes a path segment that can be replaced by an attacker-controlled symlink, the privileged process follows the attacker's symlink to an attacker-controlled object.

Attack pattern: privileged process opens `\BaseNamedObjects\TargetMutex`. Attacker creates a symlink at `\BaseNamedObjects\TargetMutex` pointing to `\BaseNamedObjects\AttackerControlledMutex`. Privileged process follows the symlink, obtains a handle to the attacker-controlled object. If the attacker can then race or control the object's state, this becomes a primitive.

**Directory object DACL weakness:**
Object namespace directory objects have DACLs just like file system directories. A directory with `World:CREATE_LINK` or `World:WRITE_DAC` allows any user to create symlinks within it or modify its DACL. Forshaw enumerated the object namespace tree using NtObjectManager and found directories where the DACL was weak. WinObj (Sysinternals) shows the namespace tree but does not display ACLs — NtObjectManager does.

**Device map redirection:**
The `\??\` namespace (the "DosDevices" path) is resolved through the *process's device map object*, which is a per-process kernel structure. For normal processes, the device map is inherited and contains standard drive letter mappings. The device map can be replaced by calling `NtSetInformationProcess` with `ProcessDeviceMap`. Replacing the device map redirects all `\??\X:` resolutions — which includes every `C:\` path the process resolves — to attacker-controlled objects.

**Why this talk is foundational:**

It established object manager symbolic link abuse as a first-class LPE primitive and provided the enumeration methodology (NtObjectManager) to find misconfigured directories systematically. Every junction+oplock TOCTOU technique that followed this talk builds on the conceptual foundation it established: that the namespace itself is a trust boundary with exploitable misconfigurations, not just a name lookup mechanism.

**Framework 5-question analysis:**

1. *Class:* Object manager namespace privilege escalation — symlink abuse, weak directory DACLs, device map redirection
2. *Discovery:* Systematic enumeration of the namespace tree using NtObjectManager + DACL inspection; not manual code review
3. *Exploitation:* Redirect privileged process's named object lookups, file lookups, or device lookups to attacker-controlled objects
4. *Patch:* Per-directory DACL hardening (Microsoft tightened several directory DACLs in subsequent patches). The enumeration methodology still finds new misconfigurations.
5. *Generalization:* Run NtObjectManager's `Get-NtDirectoryChild -Recurse` on the object namespace and inspect ACLs on all directory objects. Filter for directories with `CREATE_LINK` or `WRITE_DAC` access from low-privilege SIDs. Any such directory is a potential symlink injection point.

---

### Windows Exploitation Tricks: Exploiting Arbitrary File Writes for Local Elevation of Privilege
**Speaker/Author:** James Forshaw
**Platform:** Google Project Zero Blog (2018)
**URL:** https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html

**What it introduced:**

The canonical reference for converting an arbitrary file write primitive (a bug that allows writing to an attacker-chosen path as a privileged process) into code execution as SYSTEM. Defines and names the key exploitation patterns used in virtually every subsequent Windows LPE writeup.

**Techniques defined with step-by-step mechanics:**

**1. NtSetInformationFile FileRenameInformation as a file move primitive:**

`NtSetInformationFile` with the `FileRenameInformation` class renames (or moves) a file. A privileged process that can be induced to call this on an attacker-influenced file handle — with the destination path supplied by the attacker — provides an arbitrary file move as SYSTEM. No explicit "rename as SYSTEM" API exists; this is the mechanism through which SYSTEM-level file moves happen.

Use cases: BITS `MoveFile` (CVE-2020-0787), service logging path changes, any service that moves a file based on a user-supplied destination.

**2. MoveFileEx with MOVEFILE_DELAY_UNTIL_REBOOT:**

Registers a file move to be performed at next boot, processed by `smss.exe` during early system initialization — before access control is fully enforced on most paths. The move operations registered here run as SYSTEM with broad filesystem access. If an attacker can add an entry to the pending move list (via the `PendingFileRenameOperations` registry value under `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager`), they can arrange for a SYSTEM-level file move to occur at next reboot.

The registry value is writable by administrators by default, but if any vulnerability gives arbitrary write to that value, or if the path of the target file can be a junction, this becomes a privileged move primitive.

**3. Junction + Oplock TOCTOU (BaitAndSwitch):**

The complete, named formulation of the junction + oplock pattern. Step by step:

```
1. Identify: a privileged process will write to path P (e.g., C:\Windows\Temp\service.log)

2. Setup: 
   - Create directory D at C:\AttackerDir\
   - Create a file F at C:\AttackerDir\service.log (just so the directory is non-empty)
   - Set an exclusive oplock on file F using CreateFile + DeviceIoControl(FSCTL_REQUEST_OPLOCK)

3. Redirect: convert C:\Windows\Temp to a junction pointing to C:\AttackerDir\
   - Using CreateFile with OPEN_REPARSE_POINT to get a handle, then NtFsControlFile(FSCTL_SET_REPARSE_POINT)
   - Or using mklink /J from an elevated context (but you can also use NtCreateFile directly for junction creation without elevation in certain temp dirs)

4. Wait: the privileged process opens C:\Windows\Temp\service.log
   - Because Temp is now a junction pointing to C:\AttackerDir\, the process opens C:\AttackerDir\service.log
   - Opening this file triggers the oplock on F → the oplock fires, pausing the privileged process's I/O

5. Swap: while the privileged process is paused on the oplock:
   - Delete or replace the junction at C:\Windows\Temp
   - Create a new junction at C:\Windows\Temp pointing to C:\Windows\System32\
   - Release the oplock

6. Result: the privileged process resumes its I/O, now writing to C:\Windows\System32\service.log
   → arbitrary file created in System32 as SYSTEM

7. Convert to code execution:
   - If the filename matches a DLL search order path (e.g., a DLL that a SYSTEM service searches for in System32), write a malicious DLL
   - Or replace a service binary if write access is to a service binary directory
```

**4. Converting write to code execution:**

The write alone is not code execution. Conversion techniques:
- **DLL hijack:** The written file is a DLL in a directory that a SYSTEM-level service loads from. The service loads the DLL on next start or next relevant action.
- **Service binary replacement:** If the written file is or can be made to be the path of a service's `ImagePath`, the service will execute it on next start.
- **Scheduled task or startup entry:** Writing to a startup path causes execution at next logon or system start.

**Framework 5-question analysis:**

1. *Class:* Arbitrary file write/move primitive exploitation — converting SYSTEM-level file operations into code execution
2. *Discovery:* ProcMon trace of privileged processes + manual identification of write operations influenced by attacker
3. *Exploitation:* Junction + oplock TOCTOU to redirect write → DLL hijack or binary replacement → code execution as SYSTEM
4. *Patch:* Per-bug fixes in the specific component. The junction + oplock primitive itself is not patched — it is a feature of the filesystem. Each service that has a vulnerable file operation gets its own fix.
5. *Generalization:* For any privileged process that writes to a path under `Temp` or under a user-controllable directory: (a) can you create a junction at that path? (b) can you set an oplock on a file in the target directory? If both yes, the BaitAndSwitch pattern applies.

**Impact:** This single post is referenced in nearly every Windows LPE writeup from 2018 onward. itm4n's CVE-2020-0668 and CVE-2020-0787, Naceri's InstallerFileTakeOver, and dozens of other published exploits all use techniques defined here.

---

### The Pool Is Dead, Long Live the Pool
**Speakers:** Yarden Shafir, Alex Ionescu
**Platform:** windows-internals.com / presented at multiple conferences (2020)
**URL:** https://windows-internals.com/ (search "pool is dead")
**Slides/paper:** https://github.com/yardenshafir/conference_talks

**What it introduced:**

Comprehensive technical analysis of the transition from the NT executive pool allocator (used since Windows NT 3.1, ~1993) to the Segment Heap (introduced in Windows 10 RS1 for user mode, extended to kernel pool in Windows 10 2004 / 20H1). This transition broke virtually every kernel pool exploitation technique developed over the prior decade.

**The NT pool allocator (pre-2020) — what was exploitable:**

Each pool allocation has an 8-byte (x86) or 16-byte (x64) header immediately preceding it in memory:
```
[PoolHeader: PoolType | BlockSize | PreviousSize | PoolTag | ProcessBilled]
[Allocation data...]
[Next chunk's PoolHeader immediately follows]
```

Overflowing an allocation by even a few bytes corrupts the immediately following chunk's `PoolHeader`. By controlling what chunk follows the target (pool feng shui — spraying specific allocations to achieve a predictable layout), the attacker controls which header is corrupted. Classic exploitation: corrupt the `Flink`/`Blink` pointers in the free list entry embedded in the pool header → when that chunk is freed, the free list unlink operation writes an attacker-controlled value to an attacker-controlled address (write-what-where). Then convert write-what-where to SYSTEM token via token field manipulation.

**The Segment Heap (Windows 10 2004+) — what changed:**

The kernel pool was migrated to use the Segment Heap architecture (originally from user-mode heap). Key changes:

- **Metadata separation:** Pool allocation metadata (free list pointers, size class information, backend state) is stored in a separate heap descriptor structure (`SEGMENT_HEAP`), not inline with allocations. Overflowing into adjacent memory no longer directly corrupts pool metadata — the overflow reaches the next allocation's *data*, not the next chunk's *header*. This removes the classic "corrupt next chunk header to control free list unlink" chain.

- **Free list randomization:** For certain size classes, the Segment Heap introduces randomized free list ordering. Deterministic feng shui assumptions (spray N allocations of size X, target is now at a predictable offset) break for those classes.

- **Sub-allocator architecture:** Multiple sub-allocators serve different allocation sizes:
  - **LFH (Low Fragmentation Heap):** Handles small, fixed-size allocations (below ~512 bytes). LFH subsegments group allocations of the same size. Overflow within an LFH subsegment reaches adjacent same-size allocations.
  - **VS (Variable Size):** Handles medium allocations. Still has some inline chunk metadata (VS header, not pool header) — different structure, but still potentially corruptible.
  - **Backend:** Large allocations, page-aligned. Overflow behavior different again.

- **What still works:**
  - **Cross-cache attacks:** Overflowing from a chunk of type A into an allocation of type B (if the heap places them in adjacent pages). Requires spraying type B allocations around the target to achieve adjacency — less deterministic but still possible.
  - **Use-after-free:** Not affected by metadata separation. Freed memory can still be accessed via a retained pointer. The UAF exploitation chain uses the dangling pointer directly rather than corrupting pool metadata.
  - **Page-level attacks:** If the overflow crosses a page boundary, the page immediately following in the virtual address space may contain a controlled or interesting object.

**Framework 5-question analysis:**

1. *Class:* This is not a vulnerability class — it is a mitigation analysis. The class it analyzes is pool heap corruption.
2. *Discovery:* N/A — reverse engineering of new heap architecture
3. *Exploitation:* Post-transition techniques: cross-cache attack via spray, UAF via dangling pointer, page-level attacks
4. *Patch (as mitigation):* The Segment Heap transition was the mitigation. It did not close all pool exploitation paths, but it eliminated the easiest and most deterministic ones (metadata corruption via overflow).
5. *Generalization:* Any kernel pool exploitation research on Windows 10 2004+ must be understood in terms of the Segment Heap architecture. HEVD exploits and prior exploit code written for NT pool require re-evaluation. Cross-cache attacks require identifying which pool types the target allocation and an attacker-controllable allocation belong to, and whether they can be co-located.

**Practical implication:** If you are writing a HEVD-based pool exploit or studying an existing kernel exploit for a modern Windows version, this paper is required reading before touching pool-related code. The techniques from 2010–2019 pool exploitation guides simply do not apply to current systems without adaptation.

---

### One I/O Ring to Rule Them All: A New Attack Primitive on Windows 11
**Speaker:** Yarden Shafir
**Platform:** windows-internals.com (2022)
**URL:** https://windows-internals.com/one-io-ring-to-rule-them-all-a-new-attack-primitive-on-windows-11/

**What it introduced:**

Identifies the Windows 11 user-mode I/O Ring implementation as a new *post-corruption kernel exploitation primitive* — a way to convert any kernel bug that provides a single arbitrary write into a full repeatable arbitrary read/write capability.

**I/O Ring background:**

Windows 11 (21H2) introduced `NtCreateIoRing`, `NtSubmitIoRing`, and related syscalls — a kernel-mode I/O ring analogous to Linux's `io_uring`. The ring allows user-mode programs to queue batched I/O operations (file reads, writes, directory enumerations) without a syscall per operation after the ring is set up. The ring buffer is shared between user mode and kernel mode via a mapped memory region.

**The exploitation primitive:**

When a program registers buffers for I/O Ring operations (`IoRingRegisterBuffers`), the kernel allocates an `IORING_BUFFER_INFO` array. Each entry has the form `{Buffer (kernel VA of the registered buffer), Size}`. The kernel uses these entries as a table: when an I/O operation references buffer ID N, the kernel looks up `IORING_BUFFER_INFO[N].Buffer` to find the kernel virtual address to read from or write to.

**The attack:**

Any kernel bug that provides a write-what-where (a single pointer-sized write to an arbitrary kernel address) can overwrite one `IORING_BUFFER_INFO` entry. Set `Buffer` to an arbitrary kernel VA and `Size` to a large value. Then:

```
Arbitrary kernel READ:
  Submit IoRingOpRead to buffer ID N (the corrupted entry)
  → Kernel copies from IORING_BUFFER_INFO[N].Buffer (= arbitrary kernel VA)
    to the user-mode output buffer
  → User mode reads the user-mode buffer → has contents of arbitrary kernel address

Arbitrary kernel WRITE:
  Submit IoRingOpWrite from buffer ID N (the corrupted entry)
  → Kernel copies from user-mode source buffer
    to IORING_BUFFER_INFO[N].Buffer (= arbitrary kernel VA)
  → Arbitrary kernel address now contains attacker-supplied bytes
```

This converts a **single-shot write** into a **repeatable, bidirectional arbitrary read/write**. Any subsequent operation using the corrupted buffer entry gives read or write access to any kernel VA.

**Exploitation chain using this primitive:**

```
1. Trigger the kernel bug → overwrite one IORING_BUFFER_INFO[N].Buffer with target VA
2. Use I/O Ring read to read SYSTEM process token address
   (start from PsInitialSystemProcess symbol → follow _EPROCESS.Token)
3. Use I/O Ring read to read current process _EPROCESS.Token address
4. Use I/O Ring write to overwrite current process _EPROCESS.Token with SYSTEM token value
5. Call CreateProcess → new process inherits SYSTEM token → shell as SYSTEM
```

**Why this is the current standard primitive:**

Post-GDI bitmap technique (patched), post-NT pool metadata exploitation (mitigated by Segment Heap), the I/O Ring primitive became the canonical post-corruption technique for Windows 11 kernel exploitation between 2022 and 2024. Any write-up from this period that says "arbitrary kernel read/write primitive" without further specification is almost certainly using the I/O Ring approach.

**Framework 5-question analysis:**

1. *Class:* Post-corruption exploitation primitive — not a vulnerability class itself, but a technique for amplifying any kernel write bug
2. *Discovery:* Reverse engineering of the I/O Ring implementation + recognition of the `IORING_BUFFER_INFO` array as an attacker-controllable dispatch table
3. *Exploitation:* See chain above — single arbitrary write → I/O Ring buffer info corruption → arbitrary read/write → token swap → SYSTEM
4. *Patch:* Microsoft added an integrity check to `IORING_BUFFER_INFO` entries in later Windows 11 updates (a hash-based verification that the entry has not been tampered with from user mode). This closes the primitive for bugs that can only corrupt user-accessible memory; kernel-only writes may still bypass this check depending on the specific buffer location.
5. *Generalization:* For any kernel write primitive on Windows 11 (pre-mitigation builds), check whether the write can reach the `IORING_BUFFER_INFO` array. If the array is in kernel-mode-only memory, the I/O Ring approach may still work even post-mitigation. The general principle — find a kernel data structure that functions as a dispatch table and can be corrupted to control subsequent memory accesses — generalizes beyond I/O Ring specifically.

---

## Tier 2 — Important Technique and Series Talks

### j00ru Registry Research Series (2023–2024)

This is not one talk — it is four talks delivered across 18 months, each building on the previous. Treated as a single entry because the methodology arc is the contribution, not any individual CVE.

**Talks:**

| Title | Conference | Year | URL |
|-------|-----------|------|-----|
| Exploring the Windows Registry as a Powerful LPE Attack Surface | BlueHat IL | 2023 | https://j00ru.vexillium.org/talks/bluehat-exploring-the-windows-registry-as-a-powerful-lpe-attack-surface/ |
| Practical Exploitation of Windows Registry Vulnerabilities | OffensiveCon | 2024 | https://j00ru.vexillium.org/talks/offensivecon-practical-exploitation-of-windows-registry-vulnerabilities/ |
| Peeling Back the Windows Registry Layers | REcon | 2024 | https://j00ru.vexillium.org/talks/recon-peeling-back-the-windows-registry-layers/ |
| Windows Registry Deja Vu: Return of Confused Deputies | CONFidence | 2024 | https://j00ru.vexillium.org/talks/confidence-windows-registry-deja-vu-the-return-of-confused-deputies/ |

**Cumulative result:** 50+ CVEs in the Windows Configuration Manager kernel subsystem (`cm.sys`, `nt!CmpXxx` functions). New exploitation primitive: hive-based memory corruption via cell map manipulation.

**The subsystem selection argument (BlueHat IL 2023):**

The Configuration Manager handles all Windows registry operations in the kernel. It is large (~100K lines of kernel code), has been present since Windows NT 3.1, and has historically received almost no public security attention. Its feature set is complex:
- **Hive symbolic links** (`REG_LINK` values): A key value of this type redirects key lookups to another hive path. Resolution happens in the kernel.
- **Registry transactions (TxR)**: Kernel-mode transaction support via KTM (Kernel Transaction Manager). Operations can be grouped into a transaction, which can be committed or rolled back. Transaction isolation semantics introduce versioning.
- **Key virtualization**: UAC registry virtualization redirects writes from non-elevated processes targeting `HKLM\SOFTWARE\` to a per-user virtual store. The mapping and redirect logic is in the kernel.
- **Predefined handles**: `HKEY_LOCAL_MACHINE`, `HKEY_CURRENT_USER`, `HKEY_CLASSES_ROOT` etc. are not real handles — they are constants (e.g., `0x80000002`) that `NtOpenKey` resolves per-process to real hive paths via `ObpTranslateGrantedAccess`.
- **Layered keys**: Windows 10+ registry composition for container isolation. Multiple hive "layers" are composited by the kernel into a single logical key view.

Each feature adds a new resolution layer. Each layer is a potential place where the caller's privilege level is not re-validated after the resolution. That is the bug class.

**The confused deputy class:**

A low-privilege caller passes a handle (predefined handle, transaction handle, or `REG_LINK` symlink) to a registry API. The kernel resolves the handle through a privileged code path. The resolution produces an internal representation (a `_CM_KEY_CONTROL_BLOCK`) that has elevated permissions. Subsequent operations using this internal representation proceed without re-checking the *original caller's* security context. The caller provided a low-privilege handle; the operation runs with elevated-privilege internals.

Multiple code paths in the Configuration Manager have this property because each feature (symlinks, transactions, virtualization, predefined handles, layered keys) was implemented independently and each added its own resolution logic without uniformly enforcing caller privilege re-validation after resolution.

**The hive-based memory corruption primitive (OffensiveCon 2024):**

The registry stores all data in "hive" files (`C:\Windows\System32\config\SYSTEM`, `SAM`, `SOFTWARE`, and per-user `NTUSER.DAT`). When loaded, the kernel maps hive pages into kernel memory. Within each hive, data is accessed via a *cell map* — an array of pointers. Each entry in the cell map translates a hive-internal cell offset (a 32-bit value stored in registry data structures) to a kernel virtual address.

If a bug allows corrupting a cell map entry (pointing one entry to an arbitrary kernel VA), subsequent registry operations that dereference that entry become kernel arbitrary read or write:

- **Arbitrary read:** Call `RegQueryValueEx` on a key whose value cell points to the corrupted cell map entry. The kernel reads from the arbitrary VA and returns it as registry data.
- **Arbitrary write:** Call `RegSetValueEx` on a key whose value data is stored via the corrupted cell map entry. The kernel writes registry data to the arbitrary VA.

This primitive is architecturally distinct from pool heap corruption:
- Pool heap corruption requires overflowing heap metadata (blocked by Segment Heap metadata separation)
- Hive corruption operates through the registry's own dispatch table (cell map), not through heap metadata
- The cell map lives in kernel memory mapped from hive pages — a different memory region from pool

**Hive binary format internals (REcon 2024):**

Full structure layout for the hive binary format:
- `HBASE_BLOCK` (hive header): signature, version, timestamp, root cell offset
- `HBIN` pages (4KB aligned blocks): each contains a sequence of variable-size cells; each cell has a 4-byte size header (positive = allocated, negative = free)
- `_CM_KEY_NODE` (key node cell): subkey list, value list, security descriptor cell offset
- `_CM_KEY_VALUE` (value cell): data type, data size, inline data (≤4 bytes) or cell offset to data cell
- Cell map: maps 4KB-aligned cell offsets to kernel VAs for the corresponding hive page

The cell map is the O(1) offset→pointer translation that makes hive access efficient. Its corruption is the primitive.

**Variant hunting post-patch (CONFidence 2024):**

After the initial CVE wave was patched, j00ru systematically re-enumerated every code path that touches predefined handles, transactions, symlinks, and virtualization — the same enumeration that found the original bugs. Result: the confused deputy pattern re-appeared in different specific code paths. Microsoft's fixes were consistently point fixes: blocking the exact call sequence that the PoC demonstrated, without enforcing the architectural constraint (always re-validate caller privilege after resolving any predefined handle or symlink). New variants emerged from code paths the original fixes did not cover.

**Framework 5-question analysis (for the series as a whole):**

1. *Class:* Confused deputy / privilege boundary confusion — privileged code path triggered via low-privilege caller input; hive-based memory corruption as exploitation primitive
2. *Discovery:* Systematic feature interaction enumeration within one subsystem (not per-function audit, not fuzzing)
3. *Exploitation:* Confused deputy → OOB write into hive cell map → arbitrary kernel read/write → token swap → SYSTEM
4. *Patch:* Point fixes throughout the series. No architectural fix to the privilege re-validation problem.
5. *Generalization:* The methodology: (a) select a complex, underexplored subsystem; (b) enumerate all features; (c) enumerate all feature combinations; (d) for each combination, ask "is the caller's privilege re-validated at every resolution step?" — this question finds confused deputy bugs in any subsystem. The formula: *underexplored subsystem* × *feature interaction enumeration* = disproportionate bug density.

---

### A Decade of Windows Kernel Privilege Escalation
**Speaker:** j00ru (Mateusz Jurczyk)
**Year:** 2016
**URL:** Search "j00ru decade Windows kernel privilege escalation" — available via conference recording archives

**Content:**

Historical survey of Windows kernel LPE techniques from NT4 through Windows 10, organized chronologically. For each era, covers the dominant exploitation technique, the specific mitigation introduced to close it, and the technique that emerged to bypass that mitigation.

The timeline:
- **NT4–XP:** NULL page mapping (allocate 0x00000000 in user space, kernel NULL pointer dereference lands in attacker-controlled memory). Closed by null deref protection on 32-bit, non-issue on 64-bit.
- **Vista–Win7:** GDI bitmap technique (BITMAP object in kernel pool stores user-mode address of bitmap bits; corrupt bitmap object to make `BitBlt` operations read/write arbitrary kernel memory). Provided clean arbitrary read/write. Closed in Windows 10 Creators Update.
- **Win7–Win8:** Pool overflow to free list manipulation (pool header corruption, write-what-where, write to SYSTEM token fields). Closed progressively by pool hardening and Segment Heap.
- **Win10:** Token stealing via kernel write primitives — find `_EPROCESS.Token` via `PsInitialSystemProcess`, overwrite current process token. Still the standard payload, but primitive acquisition methods changed.
- **SMEP, SMAP, KASLR, HVCI:** Each mitigation's introduction date, what class of technique it closed, and what survived.

**Why read it:**

The best single resource for understanding *why* each kernel security mitigation exists and what specific attack it was designed to prevent. Context needed for understanding modern exploitation constraints — if you know what SMEP was introduced to stop (execute user-mode shellcode from kernel context), you understand what it does not stop (execute kernel-mode ROP gadgets). If you know what KASLR was introduced to stop (hardcoded kernel addresses), you understand why an infoleak that leaks one kernel pointer is sufficient to defeat it.

---

### Breaking Protected Processes
**Speaker:** Alex Ionescu
**Conference:** REcon 2015
**URL:** Search "Ionescu REcon 2015 Protected Processes" — archived in REcon media

**Content:**

Protected Processes (PP) and Protected Process Light (PPL) — the Windows mechanism that prevents even SYSTEM-level processes from opening LSASS, antivirus processes, and DRM-protected processes with `PROCESS_ALL_ACCESS`. Covers: the PP/PPL trust hierarchy (PP > PPL), the Signer trust levels that determine the PPL tier (Microsoft Signing Level > Microsoft > Windows TCB > Windows > Antimalware > LSA > etc.), how PPL prevents `OpenProcess` with `PROCESS_VM_READ` or `PROCESS_INJECT_THREAD` even from SYSTEM processes.

The protection: the kernel checks the protection level of both the caller's process and the target process. If the target has a higher protection level than the caller, or a different signing authority, `NtOpenProcess` returns `ACCESS_DENIED` even if the caller is SYSTEM. This is a capability check separate from the access token check.

The limitations of PPL: a driver loaded at the right signer level can bypass PP/PPL restrictions. Several research groups have documented PPL bypass via loading a signed-but-exploitable driver (BYOVD — Bring Your Own Vulnerable Driver).

**Why read it:** PPL bypass is a live research area (itm4n, Elastic Security Labs). Understanding the protection model (what is enforced, at what level, with what trust hierarchy) is prerequisite to understanding the bypass techniques.

---

## Key Conference Venues

| Venue | Focus | Archive |
|-------|-------|---------|
| Black Hat USA / Europe | Cutting-edge research; strong kernel and Windows track | https://www.blackhat.com/html/archives.html |
| DEF CON | Wide range; many Windows LPE and exploitation talks | https://media.defcon.org/ |
| BlueHat | Microsoft-organized; Windows-focused; mix of Microsoft engineers and external researchers | https://www.microsoft.com/en-us/msrc/bluehat-conference |
| OffensiveCon | Exploitation-focused; high technical depth; predominantly Windows and Linux kernel | https://www.offensivecon.org/ |
| REcon | Reverse engineering and internals deep dives; strong historical material | https://recon.cx/ |
| Infiltrate | Exploitation methodology; more offensive focus; less widely archived | https://infiltratecon.com/ |
| CONFidence | Central/Eastern European security conference; j00ru's variant hunting talks appeared here | https://confidence.org.pl/ |
| OffensiveCon / BlueHat IL | Israeli BlueHat instance; j00ru's registry series started here | — |

**Where to find archived talks:**

- Black Hat: https://www.blackhat.com/html/archives.html (slides and papers; some videos behind subscription)
- DEF CON: https://media.defcon.org/ (free, full recordings)
- REcon: https://recon.cx/ (most talks freely available post-conference)
- j00ru's personal archive of all his talks: https://j00ru.vexillium.org/talks/ — the most complete source for Bochspwn and registry series materials

---

## Academic Papers

### Tarjei Mandt — "Kernel Pool Exploitation on Windows 7"
**Conference:** DEF CON 19 (2011)
**Content:** The original systematic treatment of Windows kernel pool exploitation before Segment Heap. Pool chunk layout (POOL_HEADER structure, block size encoding, tag, previous size), freelist data structures (lookaside list vs. ListHead array), pool overflow exploitation chain (corrupt adjacent chunk header, control free list unlink, achieve write-what-where, then token field manipulation).

**Why read it now:** This is the architectural reference for the pre-2020 pool. "The Pool Is Dead" (Shafir/Ionescu) is written assuming the reader understands the NT pool allocator first. Read Mandt's paper before reading "The Pool Is Dead."

### Phrack — Classic Kernel Exploitation References
**URL:** http://phrack.org/

Phrack 68 contains the "Modern Windows Kernel Exploitation" series — covers pool exploitation, kernel shellcode, token stealing in historical detail. Phrack 67 "Exploit frameworks, the kernel, and you." These are the foundational documents for understanding how the field's vocabulary and technique set developed. Dated for current Windows (pre-Segment Heap, pre-KASLR, pre-SMEP) but necessary for understanding why the current techniques look the way they do.

### "Windows 8 Kernel Memory Protections Bypass"
Pool header safe unlinking bypass. Documents techniques used against Windows 8's pool hardening (the first Windows version to add pool header integrity checks). Contextualizes the incremental hardening between Win7 pool and the Segment Heap transition.

### Project Zero Technical Issue Reports (as a research corpus)
**URL:** https://bugs.chromium.org/p/project-zero/issues/list?q=windows

Each Project Zero issue report is a mini-paper: root cause analysis, reproduction steps, PoC code (often), disclosure timeline. For Windows bugs, Forshaw's issues in particular are often more technically detailed than the corresponding blog post — the blog post is written for a general audience; the issue report is written for the vendor's engineering team. Reading a Forshaw issue report vs. his blog post on the same bug typically reveals additional technical nuance.

The issue tracker is also a leading indicator: issues are made public 90 days after disclosure even without a patch. Checking the tracker weekly gives access to vulnerability details ~90 days before the blog posts appear.

---

## Cross-Talk Reading Order

For a researcher building toward kernel exploitation capability, the talks have natural dependencies:

```
Mandt DEF CON 19 (2011)          ← understand NT pool architecture
    ↓
Pool Is Dead (Shafir/Ionescu)    ← understand what changed and why
    ↓
j00ru "Decade of LPE" (2016)    ← understand mitigation timeline
    ↓
I/O Ring primitive (Shafir)     ← understand current exploitation technique

Bochspwn (j00ru, 2013)          ← understand tool-driven class discovery
    ↓
Bochspwn Reloaded (2017)        ← taint tracking extension
    ↓
Bochspwn Revolutions (2018)     ← false positive reduction engineering
    ↓
Registry series (2023–2024)     ← subsystem-level feature interaction methodology

Forshaw DEF CON 25 (2017)       ← object namespace attack surface
    ↓
Windows Exploitation Tricks (2018) ← file write exploitation chains
```

The Bochspwn series and the Forshaw series are independent tracks. The pool track is a prerequisite for the I/O Ring primitive.

---

## References

- [R-1] Bochspwn BH 2013 — j00ru — https://j00ru.vexillium.org/talks/blackhat-usa-bochspwn-identifying-0-days-via-memory-access-analysis/
- [R-2] Bochspwn Reloaded BH 2017 — j00ru — https://j00ru.vexillium.org/talks/blackhat-usa-bochspwn-reloaded-detecting-kernel-memory-disclosure/
- [R-3] Bochspwn Revolutions Infiltrate 2018 — j00ru — https://j00ru.vexillium.org/talks/infiltrate-bochspwn-revolutions/
- [R-4] Forshaw DEF CON 25 Object Manager — James Forshaw
- [R-5] Windows Exploitation Tricks (2018) — Forshaw / Project Zero — https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html
- [R-6] The Pool Is Dead — Shafir / Ionescu — https://windows-internals.com/
- [R-7] One I/O Ring to Rule Them All — Yarden Shafir — https://windows-internals.com/one-io-ring-to-rule-them-all-a-new-attack-primitive-on-windows-11/
- [R-8] Registry BlueHat IL 2023 — j00ru — https://j00ru.vexillium.org/talks/bluehat-exploring-the-windows-registry-as-a-powerful-lpe-attack-surface/
- [R-9] Registry OffensiveCon 2024 — j00ru — https://j00ru.vexillium.org/talks/offensivecon-practical-exploitation-of-windows-registry-vulnerabilities/
- [R-10] Registry REcon 2024 — j00ru — https://j00ru.vexillium.org/talks/recon-peeling-back-the-windows-registry-layers/
- [R-11] Registry CONFidence 2024 — j00ru — https://j00ru.vexillium.org/talks/confidence-windows-registry-deja-vu-the-return-of-confused-deputies/
- [R-12] j00ru talk archive — https://j00ru.vexillium.org/talks/
- [R-13] Black Hat Archives — https://www.blackhat.com/html/archives.html
- [R-14] DEF CON Media Archive — https://media.defcon.org/
- [R-15] Project Zero Issue Tracker (Windows) — https://bugs.chromium.org/p/project-zero/issues/list?q=windows
- [R-16] Kernel Pool Exploitation on Windows 7 — Tarjei Mandt — DEF CON 19 (2011)
- [R-17] Phrack archives — http://phrack.org/
