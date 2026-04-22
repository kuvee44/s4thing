# TOP MUST-READS — Revised Canon
## Ruthlessly culled. 30 primary + 20 secondary = 50 real reads.
## If it's not here, it belongs in section-specific RESOURCES.md files, not in the canon.

> The original "100" list was a collection. This is a canon. The difference is that every item here is worth your time. Every item dropped is either redundant, shallow, or better learned through a superior resource.

---

# PRIMARY READING — 30 Entries

## S-TIER (8 entries) — Irreplaceable. These define the field.

---

## #1 — Windows Security Internals [S-TIER]
- **Author:** James Forshaw
- **URL:** https://nostarch.com/windows-security-internals
- **Tier:** S-TIER
- **Scores:** depth 5 | originality 5 | research value 5 | variant-hunting 5 | primitive/root-cause 5 | re-read 5
- **Why it earns its place:** There is no other book that synthesizes the Windows security model at this depth. Forshaw does not explain the API surface — he explains *why* the primitives work the way they do: token duplication, impersonation semantics, integrity level bypass paths, COM security architecture, AppContainer attack surface, sandbox escape methodology. This is decades of Project Zero internalized and written down. Nothing published before or after replaces it.
- **What shifts in the reader:** You stop thinking in terms of "what functions can I call" and start thinking in terms of "what security invariants can be broken." The mental model shifts from procedural to structural — you reason about security boundaries, not exploitation steps.
- **When in the learning path:** Stage 1 (first read, foundations) and Stage 3 (return after practical work to understand what you missed the first time).
- **Labels:** [CANON] [S-TIER] [FOUNDATIONAL] [ROOT-CAUSE] [PRIMITIVE] [REREAD]

---

## #2 — Windows Internals Part 1 (7th Edition) [S-TIER]
- **Author:** Pavel Yosifovich, Alex Ionescu, Mark E. Russinovich, David A. Solomon
- **URL:** https://www.microsoftpressstore.com/store/windows-internals-part-1-9780735684188
- **Tier:** S-TIER
- **Scores:** depth 5 | originality 4 | research value 5 | variant-hunting 4 | primitive/root-cause 5 | re-read 5
- **Why it earns its place:** The canonical reference for Windows internals architecture. Chapter 7 (Security) alone is worth the price — it's the only accurate public documentation of token internals, privilege checking, security descriptor evaluation, and access check algorithm at the kernel level. Without this, you're guessing at the mechanism underlying every vulnerability you study.
- **What shifts in the reader:** You gain a stable mental map of the Windows kernel — the object manager, I/O system, virtual memory, security model, executive subsystems — that makes every subsequent research paper click immediately instead of requiring catch-up.
- **When in the learning path:** Stage 1 — read before anything else. Reference constantly at Stage 2–4.
- **Labels:** [CANON] [S-TIER] [FOUNDATIONAL] [ROOT-CAUSE] [REREAD]

---

## #3 — Windows Exploitation Tricks Series (all posts) [S-TIER]
- **Author:** James Forshaw / Google Project Zero
- **URL:** https://googleprojectzero.blogspot.com/search/label/Windows (filter: "Exploitation Tricks" series)
- **Tier:** S-TIER
- **Scores:** depth 5 | originality 5 | research value 5 | variant-hunting 5 | primitive/root-cause 5 | re-read 4
- **Why it earns its place:** These posts invented the vocabulary that the entire field now uses: symbolic link planting, named pipe squatting, NTFS junction abuse, CreateProcess token capture, fake handle tables. Each post is not a writeup of a single CVE — it's a demonstration of an *attack primitive*. Learning these is learning the alphabet of Windows LPE. Every arbitrary file write bug, every impersonation bug, every service account escape traces to one or more of these primitives.
- **What shifts in the reader:** You stop reading PoC code and start seeing attack primitives. Any new bug you encounter, you immediately ask: "which primitive does this enable?" and you know the answer.
- **When in the learning path:** Stage 2 — after Windows Internals foundation, before diving into individual CVEs.
- **Labels:** [CANON] [S-TIER] [PRIMITIVE] [VARIANT-HUNTING] [REREAD] [LAB-WORTHY]

---

## #4 — sandbox-attacksurface-analysis-tools + NtObjectManager [S-TIER]
- **Author:** James Forshaw / Google Project Zero
- **URL:** https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools
- **Tier:** S-TIER
- **Scores:** depth 5 | originality 5 | research value 5 | variant-hunting 5 | primitive/root-cause 5 | re-read 5
- **Why it earns its place:** This is not "a tool" — it's a research platform. NtObjectManager exposes the Windows NT object namespace, security descriptors, token manipulation, COM interfaces, and process security attributes as a PowerShell interface. The only way to understand symbolic link attack surface is to enumerate it with this. The only way to understand what AppContainer can actually reach is to query it with this. Researchers who don't know this toolkit are doing Windows research blind.
- **What shifts in the reader:** You stop relying on documentation and start querying the live system. Every security boundary becomes something you can enumerate and probe rather than something you read about.
- **When in the learning path:** Stage 2 and ongoing — install early, use constantly.
- **Labels:** [CANON] [S-TIER] [PRIMITIVE] [VARIANT-HUNTING] [LAB-WORTHY] [REREAD]

---

## #5 — symboliclink-testing-tools [S-TIER]
- **Author:** James Forshaw / Google Project Zero
- **URL:** https://github.com/googleprojectzero/symboliclink-testing-tools
- **Tier:** S-TIER
- **Scores:** depth 5 | originality 5 | research value 5 | variant-hunting 5 | primitive/root-cause 4 | re-read 3
- **Why it earns its place:** Symbolic link planting is involved in a substantial fraction of all Windows LPE bugs involving file operations. This toolkit is the canonical implementation of every symbolic link technique: NTFS junctions, object manager symlinks, mount point reparse combinations, CreateFile redirect, registry symlinks. Reading the source teaches you more about Windows object namespace semantics than any documentation. Using it in the lab is required to understand what "arbitrary file write" bugs actually enable.
- **What shifts in the reader:** You understand exactly how an arbitrary file write primitive is converted into a privileged file overwrite. The gap between "I can write a file" and "I have SYSTEM" becomes a sequence of concrete steps you understand deeply.
- **When in the learning path:** Stage 2, immediately after Windows Exploitation Tricks series.
- **Labels:** [CANON] [S-TIER] [PRIMITIVE] [VARIANT-HUNTING] [LAB-WORTHY]

---

## #6 — Time Travel Debugging (TTD) [S-TIER]
- **Author:** Microsoft
- **URL:** https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/time-travel-debugging-overview
- **Tier:** S-TIER
- **Scores:** depth 4 | originality 5 | research value 5 | variant-hunting 5 | primitive/root-cause 5 | re-read 3
- **Why it earns its place:** TTD changes what vulnerability research is. The ability to record execution and step backward eliminates the "reproduce the bug 50 times hoping to catch it" problem. For race condition research, uninitialized memory bugs, and complex multi-step vulnerability chains, TTD reduces analysis time by an order of magnitude. The ability to query the trace with LINQ-style expressions to find all accesses to a memory address is a research superpower. This is the single biggest productivity multiplier in the toolset.
- **What shifts in the reader:** You stop thinking about debugging as "set a breakpoint and hope" and start thinking about it as "record once, analyze forever." Complex bugs that would take weeks to understand become tractable in hours.
- **When in the learning path:** Stage 2 — learn this before you start serious CVE reproduction.
- **Labels:** [CANON] [S-TIER] [LAB-WORTHY] [REREAD]

---

## #7 — Bochspwn Reloaded [S-TIER]
- **Author:** Mateusz "j00ru" Jurczyk / Google Project Zero
- **URL:** https://googleprojectzero.blogspot.com/2018/03/bochspwn-reloaded-detecting-kernel-memory.html — full paper: https://j00ru.vexillium.org/papers/2018/bochspwn-reloaded.pdf
- **Tier:** S-TIER
- **Scores:** depth 5 | originality 5 | research value 5 | variant-hunting 5 | primitive/root-cause 5 | re-read 4
- **Why it earns its place:** Bochspwn Reloaded is the foundational paper on whole-system taint analysis for kernel uninitialized memory disclosure bugs. j00ru found hundreds of Windows kernel memory disclosure bugs by instrumenting the entire kernel with Bochs and tracking uninitialized memory reads. This paper defines how you systematically find an entire class of bugs rather than hunting for individual instances. It is also the best public treatment of the uninitialized kernel memory disclosure class as a vulnerability category.
- **What shifts in the reader:** You internalize the distinction between finding individual bugs and finding bug *classes*. You start thinking about "what instrumentation would I need to find everything of this type" rather than "how do I find the next one manually."
- **When in the learning path:** Stage 3 — after you understand kernel internals basics. Returns value on every re-read as your background deepens.
- **Labels:** [CANON] [S-TIER] [ROOT-CAUSE] [VARIANT-HUNTING] [HISTORICAL] [REREAD]

---

## #8 — PrintSpoofer — Abusing Impersonation Privileges [S-TIER]
- **Author:** Clément Labro (itm4n)
- **URL:** https://itm4n.github.io/printspoofer-abusing-impersonation-privileges/
- **Tier:** S-TIER
- **Scores:** depth 5 | originality 5 | research value 5 | variant-hunting 5 | primitive/root-cause 5 | re-read 4
- **Why it earns its place:** PrintSpoofer is the canonical modern treatment of impersonation privilege abuse. While the Potato family documented the DCOM/OXID activation path, PrintSpoofer identifies a completely distinct and more reliable primitive: abusing the spooler's named pipe creation to force a SYSTEM token over a pipe you control. The writeup explains the full analysis process — from initial observation, to pipe server mechanics, to SeImpersonatePrivilege semantics — as a worked example of how to turn a single observation into a complete LPE chain. It also directly obsoletes RoguePotato for most scenarios.
- **What shifts in the reader:** You understand impersonation at the token level, not just as "a thing that Potatoes do." The writeup teaches the analysis methodology as much as the technique — you see how to go from "this service connects to a named pipe" to a full working exploit.
- **When in the learning path:** Stage 2 — after Windows Internals Chapter 7 and before studying the Potato family.
- **Labels:** [CANON] [S-TIER] [PRIMITIVE] [ROOT-CAUSE] [VARIANT-HUNTING] [LAB-WORTHY] [REREAD]

---

# A-TIER PRIMARY (22 entries) — Required. No excuses.

---

## #9 — Windows Internals Part 2 (7th Edition) [A-TIER]
- **Author:** Pavel Yosifovich, Alex Ionescu, Mark E. Russinovich, David A. Solomon
- **URL:** https://www.microsoftpressstore.com/store/windows-internals-part-2-9780135462409
- **Tier:** A-TIER
- **Scores:** depth 5 | originality 3 | research value 4 | variant-hunting 3 | primitive/root-cause 4 | re-read 4
- **Why it earns its place:** Part 2 covers the subsystems Part 1 defers: I/O manager in depth, file systems, networking stack, crash dump analysis, boot architecture, and the remaining executive subsystems. Essential for understanding Windows file system security semantics (critical for LPE), driver loading architecture, and system calls at the kernel level. Less immediately actionable than Part 1 but required reading for anyone doing serious driver or kernel research.
- **What shifts in the reader:** You develop a complete picture of Windows rather than knowing security well and being weak on the surrounding architecture. I/O manager internals, filter driver stacks, and the MiniFilter model become navigable.
- **When in the learning path:** Stage 2–3, after Part 1 is internalized.
- **Labels:** [CANON] [A-TIER] [FOUNDATIONAL] [ROOT-CAUSE]

---

## #10 — tiraniddo.dev blog (complete archive) [A-TIER]
- **Author:** James Forshaw
- **URL:** https://www.tiraniddo.dev/
- **Tier:** A-TIER
- **Scores:** depth 5 | originality 5 | research value 5 | variant-hunting 5 | primitive/root-cause 5 | re-read 4
- **Why it earns its place:** This blog is the primary publication venue for Forshaw's research that didn't end up in the book. Posts cover: COM security model edge cases, Windows object namespace security, ALPC message handling, token impersonation nuances, AppContainer capability enumeration, and dozens of specific CVE root causes. Every post is a clinic in how to reason about security boundaries. Read the complete archive chronologically — the progression of his thinking over 10 years is itself instructive.
- **What shifts in the reader:** You develop the ability to read the Windows documentation with suspicion — to notice when a description is incomplete, when a security invariant is asserted without being proven, when two described behaviors create a gap that can be exploited.
- **When in the learning path:** Stage 2 ongoing — subscribe to the feed, read new posts immediately.
- **Labels:** [CANON] [A-TIER] [PRIMITIVE] [ROOT-CAUSE] [VARIANT-HUNTING] [REREAD]

---

## #11 — j00ru.vexillium.org blog (kernel and Win32k posts) [A-TIER]
- **Author:** Mateusz "j00ru" Jurczyk
- **URL:** https://j00ru.vexillium.org/
- **Tier:** A-TIER
- **Scores:** depth 5 | originality 5 | research value 5 | variant-hunting 5 | primitive/root-cause 5 | re-read 4
- **Why it earns its place:** j00ru's Win32k and kernel posts are the canonical record of Windows kernel vulnerability research from someone who found hundreds of bugs over a decade. Posts cover: Win32k object type confusion, kernel race conditions, uninitialized data in kernel-to-user copy paths, GDI object exploitation, syscall table research. The research methodology demonstrated — systematic fuzzing, differential analysis, class-level thinking — is as valuable as the individual bug findings.
- **What shifts in the reader:** You develop an appreciation for the Win32k attack surface as a distinct research domain requiring specialized knowledge. You stop thinking of kernel bugs as rare exotic finds and start thinking of them as systematic categories to audit.
- **When in the learning path:** Stage 3 — after kernel internals foundation.
- **Labels:** [CANON] [A-TIER] [ROOT-CAUSE] [VARIANT-HUNTING] [HISTORICAL] [REREAD]

---

## #12 — itm4n.github.io blog (complete) [A-TIER]
- **Author:** Clément Labro (itm4n)
- **URL:** https://itm4n.github.io/
- **Tier:** A-TIER
- **Scores:** depth 5 | originality 4 | research value 5 | variant-hunting 5 | primitive/root-cause 4 | re-read 4
- **Why it earns its place:** itm4n produces the best worked-example LPE research publicly available. Every post shows the complete analysis path: initial hypothesis, Windows API investigation, privilege checking semantics, exploitation mechanics, patch analysis. His Windows Installer series is the definitive public treatment of MSI-based LPE. His token privilege series is required reading before studying any impersonation-based technique.
- **What shifts in the reader:** You learn to write research. itm4n's posts are a master class in showing your work — each step is explained at a level where a reader can reproduce it, not just understand it abstractly.
- **When in the learning path:** Stage 2 onwards — read new posts immediately, work through the archive systematically.
- **Labels:** [CANON] [A-TIER] [PRIMITIVE] [VARIANT-HUNTING] [LAB-WORTHY] [REREAD]

---

## #13 — decoder.cloud blog (complete) [A-TIER]
- **Author:** Andrea Pierini (decoder)
- **URL:** https://decoder.cloud/
- **Tier:** A-TIER
- **Scores:** depth 5 | originality 4 | research value 5 | variant-hunting 4 | primitive/root-cause 4 | re-read 3
- **Why it earns its place:** decoder is the primary researcher on DCOM activation and OXID resolver abuse for LPE. The blog documents the internal mechanism of how DCOM activation works, how the OXID resolution process creates impersonation opportunities, and how each "Potato" variant exploits different aspects of this. Understanding this lineage — from Juicy through Rotten to Rogue to Local — requires reading decoder's blog, not just using the tools.
- **What shifts in the reader:** You understand DCOM security architecture as an attack surface category, not just a collection of named exploits. You can reason about whether DCOM-based impersonation will work in a given constrained environment.
- **When in the learning path:** Stage 2–3, after understanding impersonation fundamentals from PrintSpoofer.
- **Labels:** [CANON] [A-TIER] [PRIMITIVE] [ROOT-CAUSE] [VARIANT-HUNTING]

---

## #14 — Process Monitor (ProcMon) [A-TIER]
- **Author:** Sysinternals / Microsoft
- **URL:** https://learn.microsoft.com/en-us/sysinternals/downloads/procmon
- **Tier:** A-TIER
- **Scores:** depth 4 | originality 3 | research value 5 | variant-hunting 5 | primitive/root-cause 3 | re-read 2
- **Why it earns its place:** ProcMon is the starting point for nearly every file system and registry LPE investigation. Privileged processes that read from user-writable locations, services that create predictable named pipes, installers that touch user-controlled paths — all of these surface immediately in a ProcMon trace filtered by ACCESS DENIED or a specific target process. Knowing how to design a ProcMon capture strategy (boot-time logging, kernel stack filtering, path filters, privilege context filtering) is a research skill that separates researchers who find things from those who don't.
- **What shifts in the reader:** You develop a systematic surface enumeration mindset. Rather than guessing where bugs might be, you observe what privileged processes actually do and look for invariant violations.
- **When in the learning path:** Stage 1 — install immediately, learn filtering capabilities before anything else.
- **Labels:** [CANON] [A-TIER] [LAB-WORTHY] [VARIANT-HUNTING]

---

## #15 — System Informer (formerly Process Hacker 3) [A-TIER]
- **Author:** winsiderss
- **URL:** https://systeminformer.sourceforge.io/ — GitHub: https://github.com/winsiderss/systeminformer
- **Tier:** A-TIER
- **Scores:** depth 4 | originality 4 | research value 5 | variant-hunting 4 | primitive/root-cause 3 | re-read 2
- **Why it earns its place:** System Informer is the research-grade process and system inspection tool. Unlike Task Manager, it exposes security context: token integrity levels, privilege lists, impersonation state, handle tables, loaded modules with their full paths, service configurations, and network connections. The source code is a reference implementation of many NT API calls that have minimal documentation. Researchers use this daily for understanding process security context and verifying exploitation state.
- **What shifts in the reader:** You stop working blind. Security context — tokens, privileges, integrity levels, impersonation state — becomes visible in real-time rather than requiring debugger inspection.
- **When in the learning path:** Stage 1 — install alongside ProcMon.
- **Labels:** [CANON] [A-TIER] [LAB-WORTHY]

---

## #16 — WinDbg + Official Documentation [A-TIER]
- **Author:** Microsoft
- **URL:** https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools — Docs: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/
- **Tier:** A-TIER
- **Scores:** depth 5 | originality 3 | research value 5 | variant-hunting 3 | primitive/root-cause 4 | re-read 4
- **Why it earns its place:** WinDbg is not optional for serious Windows research. Kernel debugging, crash dump analysis, extension commands (dt, !analyze, !token, !address), symbol loading, TTD integration — these capabilities have no substitute. The documentation is significantly better than its reputation suggests, particularly the extension command reference and the kernel debugging walkthroughs. Mastery of WinDbg is a prerequisite for any kernel-level work.
- **What shifts in the reader:** The Windows kernel becomes inspectable rather than opaque. Crash dumps become analyzable. "Why did this privilege check fail" has an answer you can derive rather than guess.
- **When in the learning path:** Stage 1–2 — start learning WinDbg basics while reading Windows Internals, so you can verify what you read against a live kernel.
- **Labels:** [CANON] [A-TIER] [FOUNDATIONAL] [LAB-WORTHY] [REREAD]

---

## #17 — InstallerFileTakeOver [A-TIER]
- **Author:** Abdelhamid Naceri (halov / klinix5)
- **URL:** https://github.com/klinix5/InstallerFileTakeOver — writeup: https://halov.medium.com/
- **Tier:** A-TIER
- **Scores:** depth 4 | originality 5 | research value 5 | variant-hunting 5 | primitive/root-cause 5 | re-read 3
- **Why it earns its place:** InstallerFileTakeOver demonstrates two distinct lessons. First: the Windows Installer elevated rollback file mechanism is a well-designed target — it touches the file system as SYSTEM in response to user-controlled installation paths. Second, and more importantly: Naceri dropped a working bypass *on the same day* Microsoft published a patch, demonstrating that the fix was addressing the symptom (the specific code path) rather than the root cause (the underlying semantic vulnerability in rollback file handling). This is the canonical modern example of patch analysis revealing incomplete fixes.
- **What shifts in the reader:** You stop thinking of patches as endpoints and start treating them as hypotheses about root cause that may be wrong. You develop the habit of reading patch diffs and asking "what invariant was actually violated and does this change fully restore it?"
- **When in the learning path:** Stage 3 — after understanding Windows Installer mechanics from itm4n's series.
- **Labels:** [CANON] [A-TIER] [PATCH-DIFF] [VARIANT-HUNTING] [ROOT-CAUSE]

---

## #18 — Rotten Potato [A-TIER] [HISTORICAL]
- **Author:** foxglovesecurity
- **URL:** https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/
- **Tier:** A-TIER
- **Scores:** depth 4 | originality 5 | research value 4 | variant-hunting 4 | primitive/root-cause 4 | re-read 2
- **Why it earns its place:** Rotten Potato is the historical root of the entire Potato impersonation family. It is the first documented exploitation of DCOM activation combined with NTLM relay to impersonate SYSTEM from a SeImpersonatePrivilege context. Reading the original is necessary to understand what the later variants (Juicy, Rogue, Local) were actually improving on, and therefore to understand the root cause that all of them share. Read this, then trace the lineage forward — the progression teaches how an attack primitive evolves as defenses mature.
- **What shifts in the reader:** You understand the attack as a *family* rooted in a single semantic property of the Windows impersonation model. You can predict what future variants will look like.
- **When in the learning path:** Stage 2 — after PrintSpoofer (so you understand impersonation first), before deep-diving the DCOM variants.
- **Labels:** [A-TIER] [HISTORICAL] [PRIMITIVE] [ROOT-CAUSE]

---

## #19 — RoguePotato [A-TIER]
- **Author:** Andrea Pierini (decoder) and Simone Onofri
- **URL:** https://decoder.cloud/2020/05/11/no-more-juicy-potato-old-story-welcome-rogued-potato/ — GitHub: https://github.com/antonioCoco/RoguePotato
- **Tier:** A-TIER
- **Scores:** depth 4 | originality 4 | research value 4 | variant-hunting 4 | primitive/root-cause 4 | re-read 2
- **Why it earns its place:** RoguePotato is the answer to the question "how do you do DCOM impersonation after Microsoft patched the localhost OXID resolution path?" It demonstrates how the attack adapts when a specific mechanism is blocked: redirect the OXID resolver to a remote host you control, relay the authentication back, still achieve impersonation. The writeup is a precise root-cause analysis of what Juicy Potato did versus what the patch fixed versus what remained exploitable.
- **What shifts in the reader:** You understand patch bypass analysis as a research discipline: read the patch, understand what it actually prevents, enumerate what paths remain open.
- **When in the learning path:** Stage 2–3, in the Potato lineage sequence.
- **Labels:** [A-TIER] [PRIMITIVE] [VARIANT-HUNTING] [PATCH-DIFF]

---

## #20 — LocalPotato [A-TIER]
- **Author:** Andrea Pierini (decoder) and Antonio Cocomazzi
- **URL:** https://decoder.cloud/2023/02/13/localpotato/ — GitHub: https://github.com/decoder-it/LocalPotato
- **Tier:** A-TIER
- **Scores:** depth 4 | originality 5 | research value 5 | variant-hunting 5 | primitive/root-cause 5 | re-read 3
- **Why it earns its place:** LocalPotato (CVE-2023-21746) is the most recent major evolution of the Potato family and demonstrates that the underlying root cause — NTLM authentication with SYSTEM-level impersonation via a locally controlled service — was never fully patched. This bug exploits NTLM authentication on a local DCOM interface by triggering Windows Security Center service to authenticate over a socket you control, then cross-session relay. The root cause analysis is the most rigorous of the Potato series.
- **What shifts in the reader:** You understand that "the Potato class is patched" is not a correct statement — it's a class of bugs rooted in a semantic property, and new instances continue to emerge. You develop judgment about when a bug class is "fixed" versus "temporarily blocked."
- **When in the learning path:** Stage 3 — after Rotten Potato and RoguePotato.
- **Labels:** [A-TIER] [PRIMITIVE] [VARIANT-HUNTING] [ROOT-CAUSE] [PATCH-DIFF]

---

## #21 — HEVD (HackSys Extreme Vulnerable Driver) [A-TIER]
- **Author:** HackSysTeam
- **URL:** https://github.com/hacksysteam/HackSysExtremeVulnerableDriver
- **Tier:** A-TIER
- **Scores:** depth 4 | originality 4 | research value 5 | variant-hunting 3 | primitive/root-cause 3 | re-read 3
- **Why it earns its place:** HEVD is the only high-quality purpose-built training target for Windows kernel exploitation. It covers stack overflow, pool overflow, use-after-free, type confusion, integer overflow, null pointer dereference, and more — all deliberately vulnerable, all tractable to exploit development without requiring a 0-day. Working through HEVD exploitation exercises is the required practical foundation before attempting to exploit real kernel bugs. The accompanying community writeups (on GitHub) are a secondary reading list in themselves.
- **What shifts in the reader:** Kernel exploitation stops being abstract. You have working exploits for multiple vulnerability classes, you understand the kernel debugging workflow, and you've developed the muscle memory for kernel shellcode and token stealing.
- **When in the learning path:** Stage 2–3 — parallel to Windows Internals reading.
- **Labels:** [CANON] [A-TIER] [LAB-WORTHY] [FOUNDATIONAL]

---

## #22 — BinDiff [A-TIER]
- **Author:** Google / Zynamics
- **URL:** https://www.zynamics.com/bindiff.html — GitHub: https://github.com/google/bindiff
- **Tier:** A-TIER
- **Scores:** depth 4 | originality 4 | research value 5 | variant-hunting 5 | primitive/root-cause 4 | re-read 2
- **Why it earns its place:** Patch Tuesday variant hunting requires binary diffing. BinDiff performs function-level matching between binary versions — before and after a patch — and shows what changed with high fidelity. The ability to read a Patch Tuesday bulletin, identify the patched binary, diff it against the prior version, understand the changed code, and reason about what the patch failed to address is a core research workflow. BinDiff is the industry-standard tool for this.
- **What shifts in the reader:** Patch Tuesday becomes a monthly research opportunity rather than an administrative event. Every patched CVE is a potential variant-hunting exercise.
- **When in the learning path:** Stage 3 — after you understand how to read and reason about Windows code.
- **Labels:** [CANON] [A-TIER] [PATCH-DIFF] [VARIANT-HUNTING] [LAB-WORTHY]

---

## #23 — Diaphora [A-TIER]
- **Author:** Joxean Koret
- **URL:** https://github.com/joxeankoret/diaphora
- **Tier:** A-TIER
- **Scores:** depth 4 | originality 4 | research value 5 | variant-hunting 5 | primitive/root-cause 3 | re-read 2
- **Why it earns its place:** Diaphora is the IDA/Ghidra plugin alternative to BinDiff with important advantages for certain workflows: it is open source (you can read and modify the matching algorithm), it integrates into the disassembler natively, and it produces diffing reports that are more granular for large binary changes. Using both BinDiff and Diaphora gives you two independent perspectives on the same patch, which surfaces changes that either tool alone might miss. Essential for serious patch analysis work.
- **What shifts in the reader:** You build a multi-tool patch analysis methodology. One tool's artifact is input to another's verification step.
- **When in the learning path:** Stage 3, alongside BinDiff.
- **Labels:** [A-TIER] [PATCH-DIFF] [VARIANT-HUNTING] [LAB-WORTHY]

---

## #24 — OleViewDotNet [A-TIER]
- **Author:** James Forshaw
- **URL:** https://github.com/tyranid/oleviewdotnet
- **Tier:** A-TIER
- **Scores:** depth 5 | originality 5 | research value 5 | variant-hunting 5 | primitive/root-cause 4 | re-read 3
- **Why it earns its place:** COM attack surface is vast, under-documented, and requires specialized tooling to enumerate. OleViewDotNet is the only tool that can enumerate COM server security descriptors, access permissions, and launch permissions at the granularity needed for security research. It can diff COM configurations between Windows versions, find COM servers running as higher-privilege accounts, and enumerate COM interfaces exposed across privilege boundaries. Without this, COM attack surface research is guesswork.
- **What shifts in the reader:** COM attack surface becomes enumerable and systematic. You develop the ability to identify COM-based attack surface candidates before reading any code.
- **When in the learning path:** Stage 2–3, alongside Forshaw's blog and Windows Security Internals COM chapters.
- **Labels:** [CANON] [A-TIER] [VARIANT-HUNTING] [LAB-WORTHY]

---

## #25 — MSRC Security Update Guide [A-TIER]
- **Author:** Microsoft Security Response Center
- **URL:** https://msrc.microsoft.com/update-guide/
- **Tier:** A-TIER
- **Scores:** depth 3 | originality 2 | research value 5 | variant-hunting 5 | primitive/root-cause 2 | re-read 5
- **Why it earns its place:** The Update Guide is not reading material — it's the primary source of record for every CVE Microsoft patches. Monthly ritual: review every Elevation of Privilege CVE, note the affected component, note the credited researcher, note the attack complexity and prerequisites. Use this to prioritize which binaries to diff each Patch Tuesday. Use the acknowledgment page to track new researcher names before they become well-known. The acknowledgment list is the most reliable early signal of who is currently finding things.
- **What shifts in the reader:** Patch Tuesday transforms from noise into a curated research signal. You develop a monthly review habit that keeps your research surface current.
- **When in the learning path:** Stage 1 — bookmark immediately. Review monthly from day one.
- **Labels:** [CANON] [A-TIER] [VARIANT-HUNTING] [REREAD]

---

## #26 — Windows Security Servicing Criteria [A-TIER]
- **Author:** Microsoft Security Response Center
- **URL:** https://www.microsoft.com/en-us/msrc/windows-security-servicing-criteria
- **Tier:** A-TIER
- **Scores:** depth 4 | originality 3 | research value 5 | variant-hunting 5 | primitive/root-cause 4 | re-read 3
- **Why it earns its place:** This document defines what Microsoft considers a security boundary, what they will patch as a security vulnerability, and what they consider by-design behavior. This is critical for researchers: if you find a bug that crosses a boundary Microsoft doesn't recognize, it won't be fixed or credited as a CVE. Reading this document teaches you to think about vulnerability research from the patching organization's perspective — which is necessary for predicting whether a finding will be accepted, for understanding why certain bugs aren't fixed, and for identifying gaps in Microsoft's security model.
- **What shifts in the reader:** You develop a vendor-perspective mental model alongside your attacker mental model. You understand why some excellent bugs get WONT-FIX responses and how to frame bugs to maximize their patching priority.
- **When in the learning path:** Stage 2 — before spending significant time on any single research target.
- **Labels:** [CANON] [A-TIER] [ROOT-CAUSE] [VARIANT-HUNTING]

---

## #27 — RpcView [A-TIER]
- **Author:** silverf0x (Jean-Marie Borello et al.)
- **URL:** https://github.com/silverf0x/RpcView
- **Tier:** A-TIER
- **Scores:** depth 4 | originality 5 | research value 5 | variant-hunting 5 | primitive/root-cause 3 | re-read 2
- **Why it earns its place:** RPC attack surface in Windows is enormous and largely unexplored compared to COM. RpcView enumerates all registered RPC interfaces, shows their endpoints, security descriptors, and allows interface browsing and IDL extraction. Given that a substantial number of Windows LPE CVEs in recent years have involved privileged RPC servers, the ability to systematically enumerate and audit RPC attack surface is undervalued. RpcView is the primary tool for this.
- **What shifts in the reader:** RPC stops being a black box and becomes a first-class attack surface category with systematic enumeration methodology.
- **When in the learning path:** Stage 3 — after COM fundamentals.
- **Labels:** [A-TIER] [VARIANT-HUNTING] [LAB-WORTHY]

---

## #28 — impacket [A-TIER]
- **Author:** Fortra (formerly Core Security)
- **URL:** https://github.com/fortra/impacket
- **Tier:** A-TIER
- **Scores:** depth 4 | originality 4 | research value 4 | variant-hunting 4 | primitive/root-cause 3 | re-read 2
- **Why it earns its place:** impacket's value for LPE research is primarily its clean Python implementations of Windows protocols: SMB, MSRPC, DCE/RPC, NTLM, Kerberos. Reading the source code of impacket's NTLM relay implementation teaches you the NTLM authentication flow more clearly than any documentation. For DCOM-based impersonation research and any work involving cross-machine authentication, understanding the protocol layer (not just the Windows API) is required.
- **What shifts in the reader:** You understand authentication protocols at the wire level, not just through Windows API calls. This enables analysis of cross-machine components and relay-based attacks without guessing at protocol details.
- **When in the learning path:** Stage 3 — when studying impersonation primitives that involve network protocols.
- **Labels:** [A-TIER] [LAB-WORTHY]

---

## #29 — windows-internals.com blog series [A-TIER]
- **Author:** Yarden Shafir (and collaborators) — windows-internals.com
- **URL:** https://windows-internals.com/
- **Tier:** A-TIER
- **Scores:** depth 5 | originality 5 | research value 5 | variant-hunting 4 | primitive/root-cause 5 | re-read 4
- **Why it earns its place:** This blog is the primary venue for post-Segment Heap Windows kernel exploitation research. "The Pool is Dead, Long Live the Pool" (Shafir + Ionescu) is the canonical treatment of Windows 10 20H2 kernel pool changes and their exploitation implications. The I/O Ring exploitation research is the most recent evolution of kernel LPE technique. Unlike most research blogs, windows-internals.com posts go from first principles, not from "here's a PoC."
- **What shifts in the reader:** You understand modern Windows kernel mitigations in depth — not as a list of things that exist, but as specific mechanisms with specific bypass conditions. Exploitation methodology shifts from "apply old techniques" to "understand the current model."
- **When in the learning path:** Stage 3–4 — after HEVD and kernel internals foundation.
- **Labels:** [CANON] [A-TIER] [ROOT-CAUSE] [PRIMITIVE] [REREAD]

---

## #30 — Project Zero blog (Windows posts) [A-TIER]
- **Author:** Google Project Zero team
- **URL:** https://googleprojectzero.blogspot.com/ (filter: Windows tag)
- **Tier:** A-TIER
- **Scores:** depth 5 | originality 5 | research value 5 | variant-hunting 5 | primitive/root-cause 5 | re-read 4
- **Why it earns its place:** Project Zero publishes the highest-quality public Windows security research, period. The Windows-tagged posts include: in-the-wild exploit chain analysis (which teaches what real attackers use), novel vulnerability class discoveries, toolchain research, and systematic methodology papers. Unlike most public security research, PZ posts are written with the primary goal of advancing field knowledge, not demonstrating researcher capability. The comments and variant analysis sections are secondary reading in themselves.
- **What shifts in the reader:** You develop a benchmark for research quality. After reading enough PZ posts, you can assess any other public research against a meaningful standard — and you'll raise your own bar accordingly.
- **When in the learning path:** Stage 2 and ongoing — new posts should be read immediately upon publication.
- **Labels:** [CANON] [A-TIER] [ROOT-CAUSE] [VARIANT-HUNTING] [PRIMITIVE] [REREAD]

---

---

# SECONDARY READING — 20 Entries
## Useful, relevant, but not primary path. Reference when needed.

Format: **Title** — *Author* — why it's here, when to consult it.

---

**#31 — GodPotato** — *BeichenDream* — https://github.com/BeichenDream/GodPotato
The most recent Potato variant, exploiting ImpersonateNamedPipeClient via an RPC endpoint. Understand the lineage, read the README and source for the specific mechanism. Not required reading — it's a tool, and the technique is a variation on established primitives. Consult when studying current impersonation surface; don't treat as a primary read.

**#32 — SweetPotato** — *CCob* — https://github.com/CCob/SweetPotato
Consolidates multiple Potato techniques (PrintSpoofer + EfsPotato + DCOM) into a single tool. Useful as a reference implementation showing how impersonation variants are unified. The source code is readable. Not primary reading because PrintSpoofer's writeup covers the conceptual foundations better.

**#33 — PrivescCheck** — *itm4n* — https://github.com/itm4n/PrivescCheck
The gold standard Windows LPE enumeration script. Keep as a tool reference, not a reading assignment. Understand what it checks by reading the source — the check categories are a good index of the LPE surface space. Required in the toolkit, not the reading list.

**#34 — Juicy Potato** [HISTORICAL] — *decoder / ohpe* — https://github.com/ohpe/juicy-potato
The first systematic implementation of DCOM OXID activation abuse for impersonation. The repository documentation is the primary reference for how it works and why it was patched. Historical importance: it defined the DCOM impersonation category. Read the documentation and the original blog post from a history-of-the-class perspective.

**#35 — PrintNightmare CVE-2021-1675** — *Multiple researchers* — https://github.com/cube0x0/CVE-2021-1675
The educational value here is not the exploit (which is obsolete) but the patch bypass history: three separate research teams found different variants within days of each other, and the initial Microsoft patch was incomplete. The story of how this vulnerability was disclosed, patched inadequately, and re-exploited is a case study in root-cause analysis failure. Read the GitHub issues on this repo and the public timeline, not just the PoC code.

**#36 — WinObj** — *Sysinternals/Microsoft* — https://learn.microsoft.com/en-us/sysinternals/downloads/winobj
The Windows NT object namespace viewer. Required for understanding what objects exist in the namespace before using symboliclink-testing-tools or NtObjectManager. Learn the namespace structure with WinObj first — it provides the visual map. Use regularly, not intensively.

**#37 — Process Explorer** — *Sysinternals/Microsoft* — https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer
Complements System Informer for security context visualization. The DLL view and handle view are useful when analyzing what a process has open. Use when System Informer's detail level isn't sufficient for a specific investigation.

**#38 — API Monitor** — *Rohitab* — http://www.rohitab.com/apimonitor
Runtime API call monitoring with argument capture. Valuable for understanding what API calls a privileged process makes during installation or service startup — surfaces attack surface that ProcMon file/registry events alone don't show. Use for dynamic analysis of Windows components when the specific API sequence matters.

**#39 — SilkETW** — *FuzzySecurity (b33f)* — https://github.com/mandiant/SilkETW
ETW (Event Tracing for Windows) consumer framework for security research. Use for monitoring specific kernel events, driver loads, process creation, RPC calls, and security audit events during research experiments. Understanding ETW is increasingly important for both offensive research and defense detection research. Read the documentation; use the tool.

**#40 — Jackalope Fuzzer** — *Google Project Zero* — https://github.com/googleprojectzero/Jackalope
PZ's mutation fuzzer, designed specifically for Windows targets including kernel drivers and user-mode components. If you're doing fuzzing-based research, Jackalope is the best starting point for Windows targets. Read the README and architecture documentation as a guide to coverage-guided fuzzing design for Windows.

**#41 — ReactOS Source (kernel/ntoskrnl)** — *ReactOS Project* — https://github.com/reactos/reactos
An open-source re-implementation of the Windows NT architecture. Useful as a reference implementation when you need to understand what a Windows kernel function should do at a semantic level, without reverse-engineering the closed-source binary. Not accurate for modern Windows version details, but extremely valuable for understanding base NT architecture. Use as a code reference alongside Windows Internals reading.

**#42 — Windows via C/C++ (5th Edition)** — *Jeffrey Richter* — ISBN: 0735624240
The best user-mode Windows programming book, covering handles, objects, memory management, DLL loading, thread synchronization, and job objects in depth. Required background for understanding the user-mode API surface that LPE research frequently abuses. Not a security book — read it to understand what the APIs actually do before exploiting them.

**#43 — OSR NT Insider** — *OSR Online* — https://www.osronline.com/article.cfm?id=569
The Windows driver development journal. Deep technical articles on the I/O manager, kernel pool, driver frameworks (WDF/WDM), filter drivers, and driver security. Not security research — driver development knowledge that becomes security research when you understand what driver code looks like when it's buggy. Subscribe and read Windows kernel articles as background.

**#44 — MSRC Blog** — *Microsoft* — https://msrc.microsoft.com/blog/
Microsoft's security response blog. Useful for understanding how Microsoft reasons about vulnerability classes, what mitigations they're investing in, and how they explain patched vulnerabilities. Read strategically: posts about Windows LPE mitigations and servicing criteria changes are high-value. Marketing-heavy posts are low-value.

**#45 — hijacklibs.net** — *Wietze Beukema* — https://hijacklibs.net/
Catalogues DLL hijacking opportunities in Windows signed executables. Useful as a reference inventory when researching DLL planting attacks. Not a reading assignment — a tool reference. Consult when investigating service or application attack surface for DLL-based LPE.

**#46 — Windows NT Rootkits** [HISTORICAL] — *Hoglund and Butler* — ISBN: 0764576429
Historical value only. Written for Windows XP/2003 — the specific techniques are long obsolete. Read it to understand the historical context of kernel rootkit research and how the threat model shaped current Windows kernel protections like PatchGuard, KMCS, and Secure Boot. Don't try to apply the techniques; do try to understand *why* they were possible and what mitigations were designed in response.

**#47 — WinPmem** — *Velocidex / Suiche* — https://github.com/Velocidex/WinPmem
Physical memory acquisition driver. Useful for memory forensics research and kernel memory analysis workflows. If you're doing work that requires physical memory access outside of a debugger context, this is the starting point. The driver source is also a clean example of a minimal Windows kernel driver.

**#48 — NtDiff** — *ntdiff.github.io* — https://ntdiff.github.io/
Tracks Windows NT syscall table changes between versions. Essential reference when researching whether a specific syscall or kernel interface changed after a security update. Use to quickly identify what kernel interfaces changed between a vulnerable and patched Windows version.

**#49 — WinDiff** — *Joe Bialek / jbialek* — https://github.com/jbialek/windiff (or similar)
Binary-level Windows version diff tool. Complements BinDiff for patch analysis workflows. Consult as a secondary verification when analyzing Patch Tuesday changes.

**#50 — SandboxEscaper PoC Archives** [HISTORICAL] — *Community preserved*
The community-archived PoC code from SandboxEscaper's 2018–2019 disclosure run. The techniques (arbitrary file write via Task Scheduler, WER arbitrary file delete, DiagHub) are patched but the pattern of bugs remains instructive. Use as a case study set for understanding how arbitrary file operations in privileged services become LPE primitives.

---

---

# ARCHIVE — Dropped From Primary Path

> These were in the original 100 list or considered for it. Specific reason given for each removal. Items here are not wrong to know — they're wrong to be in a *canon*.

---

**FuzzySecurity tutorial series (fuzzsecurity.com)** — Dropped because: beginner-to-intermediate framing, no original vulnerability research, no conceptual models that aren't better taught by primary-path resources. A useful starting point for someone who has never exploited anything; not useful for a researcher past Stage 1. itm4n's blog covers the same LPE categories with greater depth and original research.

**Generic "Windows LPE Checklist" blog posts** (various authors, HackTricks derivatives) — Dropped because: enumeration without internals understanding. These lists tell you *what* to check without explaining *why* the check reveals a vulnerability or how to analyze what you find. A researcher who learns LPE from a checklist cannot adapt when the checklist doesn't match the target. Learn from root-cause analysis (primary path) and use PrivescCheck as the tool, not a blog post.

**PayloadsAllTheThings — Windows section** (swisskyrepo) — Dropped because: reference dump with no analytical depth. An excellent bookmark for CTFs and pentests; not reading material for researchers. The value is in the primary sources linked, not in this aggregation. Go read the primary sources.

**SharpUp / PowerUp** (HarmJ0y / GhostPack) — Dropped because: these are tools, not reading material. PowerUp's check list is useful to understand as an index of LPE surface categories, but the appropriate reading for each category is the original research, not a PowerShell script's comments. These belong in the toolkit section.

**SweetPotato (as primary reading)** — Dropped from primary to secondary because: once you understand PrintSpoofer and the DCOM Potato lineage from their source materials, SweetPotato is an implementation convenience, not a conceptual advance. The original research is in PrintSpoofer (itm4n) and the DCOM series (decoder). SweetPotato combines them; it doesn't improve them.

**Various vendor threat intelligence reports** (CrowdStrike, Mandiant, Sophos, etc. on specific malware families using LPE) — Dropped because: security marketing with technically thin content. These reports describe *that* a technique was used in the wild; they rarely explain *how* the vulnerability works at an internals level or *why* it was exploitable. The exceptions are when the same team publishes actual root-cause research (PZ, MSTIC in-depth posts) — those stay in the primary path or appear in the Project Zero entry.

**Windows Defender Exploit Guard / Attack Surface Reduction documentation** — Dropped because: defensive configuration documentation is not research reading material. Understand the mitigations exist; read about them when they're relevant to a specific bypass; don't read documentation as research practice.

**Windows Privilege Escalation Guide (TotalChaos/rebootuser)** — Dropped because: aggregates known techniques at a surface level. No original analysis. A good reference for pentesters; not appropriate as research reading.

**Explainshell / command documentation references** — Not applicable to this list but illustrative of what gets cut: tooling documentation that isn't generating conceptual insight.

**Metasploit module source for Windows LPE modules** — Dropped because: Metasploit implementations typically lag original research by months to years and often implement simplified versions of the original technique. Read the original research, not the framework implementation.

**Blog posts about specific CTF Windows exploitation challenges** — Dropped because: CTF infrastructure rarely resembles production Windows security models. Exceptions exist (Pwn2Own-adjacent research that surfaces in CTF format) but these belong in a dedicated CTF resources section if they belong anywhere.

**"Windows Red Team Cheat Sheet" aggregations** — Dropped because: same as checklist problem above. Aggregated technique lists without the underlying conceptual models are anti-canon — they give the false impression of knowledge.

**OST (Offensive Security Training) course materials** — Dropped because: commercial training has a different optimization target (student throughput, not research depth). The primary path resources teach the same material at greater depth.

**Windows kernel exploit templates / one-click exploit frameworks** — Dropped because: using pre-built exploitation frameworks builds technique execution ability, not technique understanding. A researcher needs to be able to write the exploit from first principles, not run someone else's.

**Most conference talks (DEF CON / Black Hat) without accompanying written paper** — Dropped as standalone references because: talks that don't have a written paper leave the depth in the presenter's head. Follow the researcher's blog (primary path) and read the paper if one exists. The talk is a marketing vehicle for the research; the blog post is the research.

**SecWiki / windowsexploit.com aggregations** — Dropped because: link collections are not reading. They are indexes. An index of research is useful exactly once (to discover primary sources) and then the primary sources are what you read.

---

*Canon last revised: 2026-04-22. Promote resources to primary only when they demonstrably change how a researcher thinks — not just what they know.*
