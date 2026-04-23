# Windows Security Research Vault — Index

> **Mission:** Research-grade knowledge base for Windows security researchers — from OS internals foundations through elite-level vulnerability research. Covers Local Privilege Escalation (LPE), sandbox escapes, kernel exploitation, and the full bug-hunting methodology pipeline.
>
> **Structure:** One chapter = one file. Each chapter is synthesized knowledge with curated references at the end — not a link list.

---

## Navigation

```
resource/
├── 00_index.md                    ← You are here
│
├── ch01-foundations.md            ← NT executive, processes, memory, pool, IRP, SRM
├── ch02-debugging.md              ← WinDbg, TTD, ProcMon, ETW, System Informer
├── ch03-security-model.md         ← Tokens, ACLs, integrity levels, UAC, AppContainer
├── ch04-object-manager.md         ← Object namespace, symbolic links, handle tables, TOCTOU
├── ch05-rpc-com-alpc.md           ← RPC, COM security, ALPC, named pipes, auth coercion
├── ch06-filesystem.md             ← NTFS, oplocks, reparse points, hard links, filter drivers
├── ch07-services-installers.md    ← SCM, Windows Installer, BITS, Task Scheduler, WER
├── ch08-bug-classes.md            ← Arb file write, Potato family, DLL hijack, weak ACLs
├── ch09-exploit-primitives.md     ← File move/rename/delete primitives, I/O Ring, token steal
├── ch10-kernel-win32k.md          ← Segment heap, pool exploitation, Win32k, KASLR, HEVD
├── ch11-patch-diff.md             ← BinDiff, Diaphora, patch analysis workflow, root cause
├── ch12-variant-hunting.md        ← CodeQL, Jackalope, WTF, feature interaction methodology
├── ch13-cve-case-studies.md       ← 8 deep CVE analyses: itm4n, Naceri, PrintSpoofer, Win32k
├── ch14-researchers-and-blogs.md  ← Forshaw, itm4n, decoder, j00ru, Shafir — arcs and method
├── ch15-github-and-tools.md       ← NtObjectManager, symboliclink-tools, HEVD, RpcView, etc.
├── ch16-talks-and-papers.md       ← Bochspwn, DEF CON 25, I/O Ring, Pool is Dead — methodology
├── ch17-labs-and-exercises.md     ← 25+ structured hands-on labs, Tiers 1–6
└── ch18-reporting-and-bounty.md   ← MSRC, ZDI, CVSS scoring, disclosure, reputation building
```

---

## Priority Reading — Start Here

If you are new to Windows security research, read in this order:

| Priority | Chapter | Why First |
|----------|---------|-----------|
| 1 | ch01-foundations | Everything else assumes this mental model |
| 2 | ch03-security-model | The primary attack surface is the security model |
| 3 | ch02-debugging | You cannot research without observability tools |
| 4 | ch08-bug-classes | Know the vocabulary before studying techniques |
| 5 | ch04-object-manager | Symlink attacks underlie most modern LPE chains |
| 6 | ch09-exploit-primitives | How you convert a bug into SYSTEM |
| 7 | ch13-cve-case-studies | Concrete examples crystallize the abstract |
| 8 | ch14-researchers-and-blogs | Understand the researchers whose work you will read |

---

## Chapter Summaries

### ch01 — Foundations
NT executive subsystem map (Ob/Se/Ps/Mm/Io/Cm/Ex/Ke/Hal), ring model reality (integrity levels, VBS/VTL), EPROCESS/ETHREAD structure, handle tables, pool allocator (NonPagedPoolNx, PagedPool, pool tags, feng shui concept), virtual memory (VAD tree, PTEs, guard pages, section objects), IRP lifecycle, Security Reference Monitor access check algorithm. WinDbg one-liners for all of the above. Cross-reference table: structure → bug class.

### ch02 — Debugging & Observability
WinDbg kernel debugging setup (KDNET), essential command categories, TTD (Time Travel Debugging) — recording, replaying, traveling through execution. ProcMon — what it logs, how to interpret for bug hunting. ETW architecture, SilkETW. System Informer for live token/handle inspection. Debugging workflow: from symptom to root cause.

### ch03 — Windows Security Model
Token anatomy (user SID, groups, privileges, integrity level, impersonation level, restricted tokens). Security Descriptor binary layout (DACL/SACL, inheritable ACEs). Access check algorithm step-by-step. MIC/integrity levels. UAC auto-elevation, COM elevation moniker, UAC bypass attack surface. Impersonation levels. AppContainer and LPAC. SeImpersonatePrivilege as the key to potato exploits. NtObjectManager PowerShell usage.

### ch04 — Object Manager & Namespace
Namespace tree (\, \Device, \BaseNamedObjects, \Sessions, \KnownDlls). Object headers (_OBJECT_HEADER TypeIndex XOR encoding). Handle tables and granted access bits. Symbolic link types table (6 types, privilege required, redirection level, creation API). Directory object DACL attacks. ObpLookupObjectName resolution. Device map redirection. Oplock+junction TOCTOU pattern.

### ch05 — RPC / COM / ALPC / Named Pipes
4-layer IPC stack. RPC architecture (IDL, NDR marshaling, transport layers). RPC endpoint enumeration (RpcView, NtObjectManager). Security callbacks. ALPC port hierarchy (connection/server/communication ports), message attributes. COM activation flow. COM security model (activation/launch/access permissions, surrogate processes). Named pipe squatting + ImpersonateNamedPipeClient. Authentication coercion interfaces table (MS-RPRN, PetitPotam/MS-EFSR, MS-DFSNM). PrintNightmare root cause.

### ch06 — Filesystem & File Operations
IRP pipeline with security check timing. MFT structure (ADS, reparse points, $OBJECT_ID). NTFS ACL evaluation. Reparse point binary format. Comparison table: junction vs symlink vs hard link vs oplock use. BaitAndSwitch step-by-step. Arbitrary write → DLL hijack chain. NtSetInformationFile rename trick. Filter driver minifilter altitude and bypass surface.

### ch07 — Services, Installers & Updaters
SCM architecture (service types, accounts: LocalSystem/LocalService/NetworkService/virtual). Weak service permission patterns. Windows Installer (MSI) architecture and repair flow. InstallerFileTakeOver technique step-by-step. Task Scheduler as LPE vector. BITS LPE pattern (CVE-2020-0787). WER as file write primitive. Print Spooler architecture. FullPowers / privilege restoration. Attack surface comparison table per component.

### ch08 — Bug Classes
Eight classes with definition, root cause, how to find, canonical CVEs, tools: (1) Arb file write/move/delete, (2) Junction+oplock TOCTOU, (3) Token impersonation / Potato family (HotPotato → GodPotato evolution), (4) RPC/COM/named pipe boundary bugs, (5) Object manager namespace abuse, (6) DLL hijacking / search order, (7) Weak registry ACLs, (8) Kernel memory corruption (brief). Master bug class → technique → primitive → CVE mapping table.

### ch09 — Exploit Primitives
File operation primitives (NtSetInformationFile FileRenameInformation, MoveFileEx MOVEFILE_DELAY_UNTIL_REBOOT, CreateHardLink, arb file delete → DLL hijack). Timing/race primitives (oplock types as race window). Kernel primitives (I/O Ring, PTE manipulation, token replacement). KASLR bypass state (NtQuerySystemInformation, current realistic options). Authentication coercion primitives table. Handle table spray. Chaining primitives to SYSTEM.

### ch10 — Kernel & Win32k
Segment Heap internals (LFH vs VS vs backend allocators, pool metadata separation). Pool exploitation workflow (overflow → primitive → arbitrary write). Win32k.sys architecture (session pool, type confusion history). KASLR bypass techniques. I/O Ring exploitation on Windows 11 (IORING_BUFFER_INFO primitive). Token stealing shellcode pattern. Mitigations timeline (SMEP, SMAP, CET, VBS/HVCI, kernel CFG). HEVD as lab environment.

### ch11 — Patch Diff & Root Cause Analysis
Why patch diffing matters. Patch Tuesday workflow (MSRC advisory → extract MSU → diff). BinDiff usage. Diaphora vs BinDiff. WinDiff/winbindex. Root cause analysis workflow. Symbol-aided analysis. NtDiff syscall changes. Real example workflow from advisory to root cause to variant hypothesis.

### ch12 — Variant Hunting
Variant hunting mindset (patch as hypothesis). Forshaw's incomplete fix pattern. Attack surface enumeration methodology (NtObjectManager COM/RPC enumeration). CodeQL for Windows (dangerous pattern queries). Jackalope and WTF fuzzer setup. Semgrep rules for Windows C/C++. Registry weak ACL enumeration. Administrator Protection bypass series (2024-2025) as case study. Systematic variant discovery pipeline.

### ch13 — CVE Case Studies
8 deep case studies: CVE-2020-0668 (Service Tracing, itm4n), CVE-2020-0787 (BITS, itm4n), RpcEptMapper (itm4n), CVE-2021-41379/InstallerFileTakeOver (Naceri), PrintSpoofer/CVE-2020-1048 (itm4n), RoguePotato (decoder), CVE-2021-1732 Win32k in-the-wild (Project Zero analysis), PrintNightmare CVE-2021-1675/34527. For each: root cause, exploitation chain, patch analysis, variant hunter findings.

### ch14 — Researchers & Blogs
Profiles of Forshaw, itm4n, decoder/Cocomazzi, j00ru, Yarden Shafir, Alex Ionescu — with research arcs, methodology, how to read their work. Decoder catalog including the full Potato arc through Server 2025 NTLM changes. j00ru registry research arc (50+ CVEs). Tier 1/2/3 blog list. Corporate research team feeds. How to follow efficiently.

### ch15 — GitHub & Tools
Annotated repository registry: sandbox-attacksurface-analysis-tools, symboliclink-testing-tools, PrivescCheck, PrintSpoofer, RpcView, Sysinternals, HEVD, impacket, jackalope, WTF, System Informer, SharpUp/Seatbelt. Organized by category: research tooling, exploitation labs, enumeration, protocol tools, fuzzing. Trust level and primary use for each.

### ch16 — Talks & Papers
Methodology-defining talks: Bochspwn (BH 2013), Bochspwn Reloaded (BH 2017), DEF CON 25 Object Manager, Windows Exploitation Tricks 2018, The Pool Is Dead, I/O Ring primitive (2022). j00ru registry series (BlueHat 2023 → OffensiveCon 2024). How to read a conference talk as a researcher. Key conference venues.

### ch17 — Labs & Exercises
VM setup requirements. 25+ structured labs across 6 tiers: (1) Fundamentals (WinDbg, TTD, ProcMon, token inspection), (2) Security Model (ACL analysis, impersonation, UAC), (3) Bug Class Reproduction (PrintSpoofer, service tracing, junction+oplock, DLL hijacking), (4) Kernel Exploitation (HEVD stack overflow, pool overflow), (5) Patch Diffing, (6) Variant Hunting (COM enumeration, attack surface mapping). Documentation template.

### ch18 — Reporting & Bounty
MSRC security boundaries (what qualifies and what doesn't). Submission checklist and timeline. ZDI comparison. Vulnerability report structure (8-section template). CVSS v3.1 scoring patterns for common LPE scenarios. Coordinated disclosure (90-day standard). In-the-wild escalation path. MSRC severity ratings. Building a public research track record.

---

## Anti-Noise Rules

Before adding any resource or reading something new, ask:

> "Does this help me think more clearly about Windows trust boundaries, attack surfaces, and primitive chains — or does it just tell me what to do?"

**Excluded categories:**
- Enumeration tools without explanation (WinPEAS output without understanding the security model behind it)
- Outdated exploit code for patched bugs without methodology context
- Blog posts that reproduce existing PoCs without root cause analysis
- CVE lists without technical depth

**The test for a talk or blog post:**
1. Does it explain *why* the bug exists (not just *what* to run)?
2. Does it explain the *methodology* used to find it?
3. Can you apply the methodology to find something new?

If the answer to all three is "no," treat it as historical context, not primary learning material.

---

## Learning Path by Role

### "I want to understand Windows internals before touching exploits"
ch01 → ch02 → ch03 → ch04 → ch06 → ch05 → then ch07

### "I understand internals, I want to find LPE bugs"
ch03 → ch08 → ch04 → ch07 → ch09 → ch11 → ch12 → ch13

### "I want to do kernel exploitation"
ch01 → ch10 → ch09 → ch17 (Tier 4 labs) → ch11 → ch16

### "I found a bug and want to report it"
ch18 (start here) → ch11 (root cause analysis) → ch13 (how prior writeups are structured)

### "I want to understand the research landscape"
ch14 → ch16 → ch13 → then read primary sources

---

*Last updated: 2026-04-23 | Vault version: 2.0 (single-chapter redesign)*
