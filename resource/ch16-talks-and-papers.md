# Chapter 16 — Talks, Papers & Methodology

> Conference talks and papers are where research methodology is made explicit. This chapter covers the most important talks chronologically, with emphasis on what each one *teaches about methodology* — not just what bugs were found. A researcher who understands j00ru's Bochspwn methodology can apply it; one who only knows "j00ru found 30 infoleaks" cannot.

---

## Tier 1 — Methodology-Defining Talks

### Bochspwn: Identifying 0-days via System-Wide Memory Access Pattern Analysis
**Speaker:** j00ru (Mateusz Jurczyk) | **Conference:** Black Hat USA 2013
**URL:** https://j00ru.vexillium.org/talks/blackhat-usa-bochspwn-identifying-0-days-via-memory-access-analysis/

**The innovation:** First demonstration of tool-driven systematic kernel vulnerability class discovery. Instruments the Bochs x86 emulator — every memory read/write the kernel performs is logged. Pattern detected: *double-fetch* — same user-mode address read twice within a single syscall dispatch without an appropriate lock between reads.

**The double-fetch class:** Kernel reads user-mode value, validates it, then reads it again (instead of using the validated copy). Attacker thread changes the value between validation and use. Classic example: validate `len <= MAX`, then read `len` again for the actual copy operation — attacker sets `len = 0xFFFFFFFF` in the race window.

**Why it matters for methodology:** This is the first proof that vulnerability classes can be defined as memory access *patterns* and detected mechanically. The insight generalizes: any class where the vulnerability manifests as a temporal sequence of memory accesses can be found with an instrumented emulator. Pre-dates modern fuzzing as the dominant paradigm.

**Scale:** Found double-fetch bugs surviving from NT4 era (15+ years). Not because they were hidden — because no one had looked systematically.

---

### Bochspwn Reloaded: Detecting Kernel Memory Disclosure with x86 Emulation and Taint Tracking
**Speaker:** j00ru (Mateusz Jurczyk) | **Conference:** Black Hat USA 2017
**URL:** https://j00ru.vexillium.org/talks/blackhat-usa-bochspwn-reloaded-detecting-kernel-memory-disclosure/

**The innovation:** Same Bochs instrumentation framework, new pattern — *taint tracking*. Mark every byte of kernel stack/pool memory as "uninitialized" at allocation. Propagate taint through copies and moves. Detect if any tainted byte reaches a user-mode memory address (via `memcpy`, `NtQuerySystemInformation`, IOCTL return buffer, etc.).

**Why uninitialized memory matters post-KASLR:** Uninitialized padding bytes in kernel structs, union fields, or stack frames may contain kernel pointers from previous uses of that memory. These pointers defeat KASLR when returned to user mode.

**Technical depth:**
- Shadow memory: a parallel bitmap tracking "tainted" status for every physical byte in the system
- Taint sources: any byte in a freshly allocated stack frame or pool block that has never been written
- Taint sinks: writes to user-mode addresses (detected by VA range check)
- False positive sources: intentional use of uninitialized memory as entropy (e.g., PRNG seeding) — required heuristic filtering

**Scale:** ~30 information disclosure vulnerabilities in Windows kernel and drivers. Bugs distributed across: `nt!NtQuerySystemInformation`, GDI subsystem, win32k font handling, various IOCTL handlers.

**Structural lesson for variant hunters:** Infoleaks are not isolated. They are *structural* — they arise from:
1. C struct padding bytes (compiler adds padding to align fields; these are never written but get copied)
2. Tagged union layouts (union field `A` initialized, union field `B` not, but full union size is copied)
3. Stack arrays only partially filled (copy of full array size)
4. Pool allocations reused without zeroing

Manual variant hunt path: search for `RtlCopyMemory` / `memcpy` where the source is a stack-allocated struct with `__declspec(align(...))` or explicit padding fields.

---

### Abusing the NT Object Manager Namespace
**Speaker:** James Forshaw | **Conference:** DEF CON 25 (2017)
**Slides/recording:** Search "Forshaw DEF CON 25 Object Manager"

**The innovation:** First comprehensive treatment of the NT object namespace as an *attack surface*, not just an implementation detail. The talk maps the namespace tree, identifies weak DACLs on directory objects, and demonstrates symlink attacks for LPE.

**Core techniques introduced:**
- **Object manager symlink in \BaseNamedObjects:** Low-privilege processes can create symlink objects in `\BaseNamedObjects\Local\` — redirecting named object lookups for privileged processes
- **Directory DACL weakness:** Object namespace directories with `World:WRITE_DAC` or `World:CREATE_LINK` — allows creating symlinks that redirect another process's object lookups
- **Device map redirection:** The `\??\` device namespace is resolved through the process's device map — modifiable by low-privilege users to redirect drive letter lookups

**Why this talk is foundational:** It established symbolic link abuse as a first-class Windows exploitation primitive. Every "junction + oplock" TOCTOU technique in the subsequent 7 years builds on the conceptual foundation established here.

---

### Windows Exploitation Tricks: Exploiting Arbitrary File Writes for Local Elevation of Privilege
**Speaker:** James Forshaw | **Platform:** Google Project Zero Blog (2018)
**URL:** https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html

**The innovation:** Defines the complete "arbitrary file write → SYSTEM" exploitation chain and all its variants. Introduces the junction + oplock TOCTOU pattern as a reliable primitive.

**Techniques covered:**
1. **NtSetInformationFile FileRenameInformation:** Rename a file to an attacker-chosen path. If a privileged process can be induced to call this on an attacker-influenced file, it is an arbitrary file move primitive.
2. **MoveFileEx with MOVEFILE_DELAY_UNTIL_REBOOT:** Register a file to be moved at next boot (before access control is enforced on most paths). Persistence-aware arbitrary file move.
3. **Junction + oplock TOCTOU (BaitAndSwitch):** 
   - Privileged process will write to path `X`
   - Set oplock on directory containing `X`
   - Oplock triggers when privileged process opens the directory
   - During oplock hold: swap directory junction to point to target directory
   - Release oplock → privileged process writes to `target_directory\filename`
4. **Converting write to SYSTEM:** Write a DLL to a directory that a SYSTEM process will load from (DLL hijacking); or write to a service binary path; or write to `WindowsApps\` or `System32\` (requires a second trick for the latter).

**Impact:** This single post defined the vocabulary and technique set for a generation of Windows LPE research. Nearly every "arbitrary file write to SYSTEM" writeup after 2018 references it.

---

### The Pool Is Dead, Long Live the Pool
**Speakers:** Yarden Shafir, Alex Ionescu | **Platform:** Hex Rays / conference (2020)
**URL:** https://windows-internals.com/ (search "pool is dead")

**The innovation:** Comprehensive analysis of the transition from the NT pool allocator (similar to slab allocator) to the Segment Heap in Windows 10 2004+. Maps exactly what changed and why old pool exploitation techniques broke.

**Key changes documented:**
- **Segment Heap replaces NT Heap for kernel pool allocations** (starting Win10 2004 / RS6, configurable per process and kernel pools)
- Pool header metadata is moved away from the allocation itself — attackers overflowing a pool allocation no longer directly corrupt pool headers
- **Free list randomization:** The segment heap introduces randomized free list ordering, breaking deterministic feng shui assumptions
- **Backend allocator vs. LFH vs. VS:** The Segment Heap has multiple sub-allocators with different characteristics for different size classes
- **What still works:** Cross-cache attacks (corrupting an allocation of one type that is physically adjacent to a target type), page-level attacks, use-after-free (not affected by metadata separation)

**Why it matters:** Understanding this transition is required for any kernel pool exploitation research on Windows 10 2004+. Prior exploits written for the NT pool allocator do not transfer directly.

---

### One I/O Ring to Rule Them All: A New Attack Primitive on Windows 11
**Speaker:** Yarden Shafir | **Platform:** windows-internals.com (2022)
**URL:** https://windows-internals.com/one-io-ring-to-rule-them-all-a-new-attack-primitive-on-windows-11/

**The innovation:** Identifies Windows 11's user-mode I/O Ring implementation as a new kernel exploitation primitive. An OOB write or UAF that touches the `IORING_BUFFER_INFO` array provides full kernel read/write capability.

**I/O Ring overview:** Windows 11 introduced kernel-mode support for user-mode I/O rings (analogous to Linux io_uring). The ring allows user mode to submit batched I/O operations. The kernel maps ring buffer metadata into kernel address space.

**The primitive:**
- `IORING_BUFFER_INFO` array contains `{Buffer, Size}` entries that the kernel uses to identify registered buffers
- If an attacker can overwrite an `IORING_BUFFER_INFO` entry (via any kernel arbitrary write), they can point it to any kernel address
- Submitting a read I/O to the corrupted buffer entry causes the kernel to copy from the attacker-specified kernel address → user-mode buffer (arbitrary read)
- Submitting a write I/O causes the kernel to copy from a user-mode buffer → attacker-specified kernel address (arbitrary write)
- Result: **full arbitrary kernel read/write from any kernel bug that gives a single pointer-sized write**

**Significance:** This is the current primary exploit primitive for Windows 11 kernel exploitation (as of 2022–2024). References to "I/O Ring primitive" in any 2022+ Windows kernel exploit write-up refer to this technique.

---

## Tier 2 — Important Technique Talks

### j00ru Registry Research Series (2023–2024)

| Talk | Conference | Year | URL |
|------|-----------|------|-----|
| Exploring the Windows Registry as a Powerful LPE Attack Surface | BlueHat IL | 2023 | https://j00ru.vexillium.org/talks/bluehat-exploring-the-windows-registry-as-a-powerful-lpe-attack-surface/ |
| Practical Exploitation of Windows Registry Vulnerabilities | OffensiveCon | 2024 | https://j00ru.vexillium.org/talks/offensivecon-practical-exploitation-of-windows-registry-vulnerabilities/ |
| Peeling Back the Windows Registry Layers | REcon | 2024 | https://j00ru.vexillium.org/talks/recon-peeling-back-the-windows-registry-layers/ |
| Windows Registry Deja Vu: Return of Confused Deputies | CONFidence | 2024 | https://j00ru.vexillium.org/talks/confidence-windows-registry-deja-vu-the-return-of-confused-deputies/ |

**Cumulative result:** 50+ CVEs in the Windows registry kernel subsystem (Configuration Manager / `cm.sys`). New bug class introduced: hive-based memory corruption via cell map manipulation.

**Talk-by-talk methodology progression:**

**BlueHat IL 2023 — Attack surface selection.** The initial talk introduces *why* the registry is an underexplored attack surface: the Configuration Manager kernel code (`nt!CmpXxx` functions) is large, has complex features that interact with each other, and has historically received little public security attention. Features covered:
- Hive symbolic links (`REG_LINK` values, `\Registry\Machine\...` symlink resolution)
- Registry transactions (TxR — kernel-mode transaction support via KTM)
- Key virtualization (UAC registry virtualization, `\Registry\Machine\SOFTWARE\Classes` vs. `\Registry\User\...` virtual store)
- Predefined handles (`HKEY_CLASSES_ROOT` pre-defined key handle resolution through a per-process registry root)
- Layered keys (Windows 10+ registry composition for container isolation)

**The core bug class identified:** *Confused deputy / privilege boundary confusion* — a caller at low privilege provides a handle that is resolved through a privileged code path without re-checking the caller's privilege level. The registry has multiple such paths because each feature (symlinks, transactions, virtual store, predefined handles) adds a new resolution layer, and each layer is a potential boundary crossing.

**OffensiveCon 2024 — Exploitation companion.** Companion to the BlueHat talk, focused on converting registry bugs into LPE. The key contribution: **hive-based memory corruption** as a new exploitation primitive architecturally distinct from pool heap corruption. The registry stores data in "hives" (files like `SYSTEM`, `SOFTWARE`) mapped into kernel memory. A hive's cell map — an array of pointers used to resolve offsets into hive data — can be corrupted by certain bugs to yield:
- Arbitrary kernel read (point a cell map entry to any kernel VA, read it as registry data)
- Arbitrary kernel write (point a cell map entry to a target VA, write registry data there)

This primitive bypasses Segment Heap metadata protections entirely because it operates through the registry's own data structures, not through pool heap metadata.

**REcon 2024 — Internal architecture deep dive.** The most technical of the four talks. Covers the full hive binary format (`HBASE_BLOCK`, `HBIN` blocks, `_CM_KEY_NODE`, `_CM_KEY_VALUE`, cell allocation mechanics). Explains how the cell map provides the O(1) offset→pointer translation that makes hive-based primitives work.

**CONFidence 2024 — Variant hunting post-patch.** After initial patches: the same confused deputy patterns re-emerged in different code paths. j00ru demonstrates that Microsoft's fixes were consistently point fixes (blocking the specific call path) rather than root-cause fixes (enforcing privilege boundaries at the registry layer architecture). The variants were found by systematic re-enumeration of every code path that accesses predefined handles, transactions, symlinks, and virtualization — the same methodology that found the originals.

**Methodology lesson:** Subsystem selection matters more than technique. By choosing the Configuration Manager (one complex subsystem) instead of hunting isolated bugs across all of Windows, j00ru found 50+ CVEs vs. the 1–5 that manual auditing of a single function would yield. The formula: *underexplored subsystem* × *feature interaction enumeration* × *exploitation-as-discovery* (hard-to-exploit bug → find structural primitive nearby) = disproportionate bug density.

---

### Bochspwn Revolutions: Further Exploitation of Double-Fetch Bugs in the Windows Kernel
**Speaker:** j00ru | **Conference:** Infiltrate 2018
**URL:** https://j00ru.vexillium.org/talks/infiltrate-bochspwn-revolutions/

**The innovation:** Engineering refinements to the Bochspwn framework that reduced false positive rate and improved taint persistence:
- Taint tracking across function call boundaries (not just within a single syscall dispatch function)
- Pool reallocation taint: if a pool block is freed and reallocated, the new allocation retains taint from the previous use if relevant bytes are not overwritten
- Heuristic improvements for filtering intentional uninitialized-memory uses (entropy sources)

**New bugs found:** Additional double-fetch variants in paths that Bochspwn 2013 missed because they crossed DPC boundaries or were in driver stack components instrumented less accurately.

**Why it matters for methodology:** The talk makes explicit a principle that scales to other automated analysis approaches: *false positive reduction is the bottleneck*. Finding bugs at scale is not about finding more signals — it is about making each signal actionable. Every fuzzer, taint analyzer, and static analysis tool faces the same constraint.

---

### A Decade of Windows Kernel Privilege Escalation
**Speaker:** j00ru | **Year:** 2016
**URL:** conference recording (search "j00ru decade kernel privilege escalation")

**Content:** Historical survey of Windows kernel LPE techniques from NT4 through Windows 10 era. Covers: NULL page exploitation, GDI bitmap elevation technique, token stealing via kernel write primitives, win32k attack surface evolution, mitigation history (SMEP, SMAP, KASLR, HVCI).

**Why read it:** The best single resource for understanding *why* each mitigation was introduced and what attack it was designed to close. Essential context for understanding modern kernel exploitation constraints.

---

### Breaking Protected Processes
**Speaker:** Alex Ionescu | **Conference:** REcon 2015
**URL:** Search "Ionescu REcon 2015 Protected Processes"

**Content:** Protected Processes and Protected Process Light (PPL) — the Windows mechanism that prevents SYSTEM-level processes from fully controlling LSASS, antivirus processes, and DRM processes. Covers: the PP/PPL trust hierarchy, signer trust levels, how PPL prevents `OpenProcess` with full access from working even as SYSTEM.

**Why read it:** PPL bypass is a research area (itm4n has PPL bypass work; Elastic Security Labs has PPL-related research). Understanding the protection model is prerequisite to understanding the attacks.

---

## Key Conference Venues

| Venue | Focus | Where to find |
|-------|-------|---------------|
| Black Hat USA/Europe | Cutting edge research; strong kernel/Windows track | https://www.blackhat.com/html/archives.html |
| DEF CON | Wide range; many Windows research talks | https://media.defcon.org/ |
| BlueHat | Microsoft-organized; Windows-focused; Microsoft engineers + external researchers | https://www.microsoft.com/en-us/msrc/bluehat-conference |
| OffensiveCon | Exploitation-focused; high technical depth | https://www.offensivecon.org/ |
| REcon | Reverse engineering + internals deep dives | https://recon.cx/ |
| Infiltrate | Exploitation methodology; more offensive focus | https://infiltratecon.com/ |

---

## Academic Papers

### Relevant Papers

**Exploiting the Windows Kernel — Phrack series**
- **URL:** http://phrack.org/
- **Content:** Classic kernel exploitation theory. Historically important for establishing the conceptual vocabulary.

**"Windows 8 Kernel Memory Protections Bypass"**
- Pool header safe unlinking bypass. Documents techniques used against Windows 8 pool hardening.

**Tarjei Mandt — "Kernel Pool Exploitation on Windows 7"**
- **Year:** 2011 (DEF CON 19)
- **Content:** The original systematic treatment of Windows kernel pool exploitation. Covers pool chunk layout, freelist manipulation, pool overflow exploitation chain. The pre-Segment Heap reference.

**Project Zero Technical Issue Reports**
- **URL:** https://bugs.chromium.org/p/project-zero/issues/list?q=windows
- **Format:** Each issue is a mini-paper — root cause, PoC code, disclosure timeline. Forshaw's issues are particularly detailed.
- **Value:** Raw research before the blog write-up. Often contains more technical detail than the sanitized blog post.

---

## Reading a Conference Talk as a Researcher

When reading/watching a talk, extract:

1. **What is the vulnerability class?** (Not the specific CVE — the class)
2. **How was it discovered?** (Manual code review? Fuzzing? Systematic enumeration? Pattern-matching?)
3. **What is the exploitation chain?** (Vulnerability → primitive → SYSTEM or sandbox escape)
4. **What did the patch do?** (Point fix or root cause fix? Are variants likely?)
5. **What methodology generalizes?** (Could you apply this methodology to find similar bugs in a different component?)

Talks that only give you #1 and #3 are less valuable than talks that give you #2 and #5.

---

## References

- [R-1] Bochspwn Reloaded (BH 2017) — j00ru — https://j00ru.vexillium.org/talks/blackhat-usa-bochspwn-reloaded-detecting-kernel-memory-disclosure/
- [R-2] Forshaw DEF CON 25 Object Manager — James Forshaw — https://www.tiraniddo.dev/
- [R-3] Windows Exploitation Tricks (2018) — James Forshaw / PZ — https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html
- [R-4] The Pool Is Dead — Shafir/Ionescu — https://windows-internals.com/
- [R-5] One I/O Ring to Rule Them All — Yarden Shafir — https://windows-internals.com/one-io-ring-to-rule-them-all-a-new-attack-primitive-on-windows-11/
- [R-6] j00ru Registry Research (BlueHat 2023) — https://j00ru.vexillium.org/talks/bluehat-exploring-the-windows-registry-as-a-powerful-lpe-attack-surface/
- [R-7] Black Hat Archives — https://www.blackhat.com/html/archives.html
- [R-8] DEF CON Media — https://media.defcon.org/
