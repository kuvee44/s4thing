# S-TIER ONLY
## The Short List. Read Everything Here. Read It Again.

---

- Title: Windows Security Internals
- Author / Organization: James Forshaw (Google Project Zero) / No Starch Press, 2023
- URL: https://nostarch.com/windows-security-internals
- Resource type: Book (technical, ~900 pages)
- Tier: S-TIER
- Scores:
  - Technical depth: 5/5
  - Originality: 5/5
  - Research value: 5/5
  - Variant-hunting value: 5/5
  - Primitive/root-cause value: 5/5
  - Re-read value: 5/5
- Historical or current: Current (2023; covers Windows 11 security model)
- Why it deserves S-TIER: This is the only resource that systematically treats Windows as an adversarial security architecture rather than a neutral operating system. Forshaw walks through token structures, security descriptors, impersonation, COM activation, AppContainer, and the kernel trust hierarchy not as implementation details but as a designed boundary system — and then shows, repeatedly, how those boundaries have been violated. No other resource maps the attack surface with this level of structural completeness. The NtObjectManager integration means concepts are immediately testable. A reader who owns this book and its tooling can interrogate any Windows component without needing a second reference.
- What it changes in the reader: Reader stops asking "can I do X to escalate?" and begins asking "what security check would have to fail for X to work, and what controls that check?" This is the fundamental shift from technique-follower to researcher. The mental model of Windows as a collection of named trust boundaries — each with a defined enforcement point — is installed by this book and cannot be acquired any other way as efficiently.
- Best use: Primary reading, Chapter 2–5 first (token model, impersonation, access check mechanics). Return to specific chapters before researching new attack surfaces. Read the AppContainer and COM chapters before any sandboxing or COM research.
- Related bug classes / primitives: Token impersonation abuse, security descriptor misconfiguration, COM activation escalation, AppContainer escape, handle inheritance attacks, named pipe squatting, DACL manipulation
- What level of researcher benefits most: Mid-level researchers who understand exploitation mechanics but haven't yet internalized the security model that exploitation violates. Senior researchers will find it clarifies assumptions they've been making informally for years.
- Notes: The PowerShell examples using NtObjectManager are not optional exercises — they are how the book teaches. Run them. The book's companion GitHub repo has additional scripts. Do not read this as a passive text.

---

- Title: Windows Internals, Part 1 (7th Edition)
- Author / Organization: Pavel Yosifovich, Alex Ionescu, Mark Russinovich, David Solomon / Microsoft Press, 2017
- URL: https://www.microsoftpressstore.com/store/windows-internals-part-1-9780735684188
- Resource type: Book (technical reference, ~800 pages)
- Tier: S-TIER
- Scores:
  - Technical depth: 5/5
  - Originality: 4/5
  - Research value: 5/5
  - Variant-hunting value: 4/5
  - Primitive/root-cause value: 5/5
  - Re-read value: 5/5
- Historical or current: Current (7th ed. covers Windows 10; core concepts structurally unchanged in Windows 11)
- Why it deserves S-TIER: This is the load-bearing structure of all Windows research. The process model, virtual memory architecture, object manager, I/O subsystem, and kernel dispatcher exist in every other security resource as implicit assumptions. Without this book, readers are building on inference and approximation. With it, every other resource — including Forshaw's — clicks into place. The irreplaceability is not just conceptual: Part 1 contains the reference-level description of how the kernel object manager handles naming, how the I/O manager dispatches IRPs, and how the memory manager manages section objects. These are not topics with better alternatives.
- What it changes in the reader: Installs the base mental model that everything else plugs into. The shift is from treating Windows as magic — a system where things happen — to treating it as an engineered system with knowable behavior. Every subsequent security resource stops being a list of tricks and starts being a set of statements about which invariants the OS failed to uphold.
- Best use: Not a cover-to-cover read for most purposes. Process and thread chapters (Ch. 1–4) first, then Object Manager (Ch. 8), then I/O (Ch. 6), then Memory (Ch. 5). Return to specific chapters when encountering unfamiliar subsystems in research. Chapter 3 on processes and Chapter 8 on objects are the highest-density sections for security research.
- Related bug classes / primitives: Kernel object lifetime attacks, pool allocator vulnerabilities, IRP-based attacks, section object abuse, named object squatting, driver object model attacks
- What level of researcher benefits most: Everyone, but most transformative for researchers who came up through CTF or red-team tooling without formal Windows internals grounding. Without this, research is hypothesis-generating. With it, research is hypothesis-testing.
- Notes: Part 2 covers storage, networking, and diagnostics — important but not in the same category. If forced to choose, Part 1 exclusively. The Ionescu contributions on kernel security architecture are particularly dense and worth focused study.

---

- Title: Windows Exploitation Tricks (complete series)
- Author / Organization: James Forshaw / Google Project Zero
- URL: https://googleprojectzero.blogspot.com/search/label/Windows%20Exploitation%20Tricks
- Resource type: Blog post series (5+ technical posts, 2017–2018)
- Tier: S-TIER
- Scores:
  - Technical depth: 5/5
  - Originality: 5/5
  - Research value: 5/5
  - Variant-hunting value: 5/5
  - Primitive/root-cause value: 5/5
  - Re-read value: 5/5
- Historical or current: Historical (2017–2018) but structurally current — the primitive taxonomy described remains the operating framework for Windows LPE research
- Why it deserves S-TIER: Each post in this series defines one or more exploit primitives with root cause and maps them directly to real CVE patterns. This is not a list of techniques — it is a taxonomy. Forshaw establishes the vocabulary that serious Windows LPE research uses: arbitrary file write primitive, arbitrary directory creation primitive, NTFS junction chains, COM elevation pivot. These are not names he invented for the post — they are names that stuck because the analysis was correct and complete. The series is the intellectual foundation that makes variant hunting systematic rather than luck-dependent.
- What it changes in the reader: Reader stops classifying bugs by their CVE description ("this is a use-after-free in win32k") and starts classifying them by what primitive they provide ("this gives me an arbitrary write into a privileged path"). The CVE is an event. The primitive is the class. Understanding the difference is the difference between CVE tourism and research.
- Best use: Read in full as a series, in publication order. Then use as a reference classification system: when encountering any new bug, map it to the primitive taxonomy before doing anything else. The arbitrary directory creation and arbitrary file write posts are the most re-read; do not skip the COM elevation moniker post.
- Related bug classes / primitives: Arbitrary file write → privileged install path escalation, arbitrary directory creation → junction planting, NtSetInformationFile FileRenameInformation primitive, hard link / junction chains, COM elevation moniker abuse, RPC misconfiguration
- Individual posts of highest value:
  - Abusing Arbitrary File Writes (2018): https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html
  - Abusing Arbitrary Directory Creation (2017): https://googleprojectzero.blogspot.com/2017/08/windows-exploitation-tricks-abusing.html
  - Abusing the COM Elevation Moniker: https://googleprojectzero.blogspot.com/2017/09/abusing-com-elevation-moniker.html
  - Exploiting a Misconfigured RPC Interface: https://googleprojectzero.blogspot.com/2019/12/calling-local-windows-rpc-servers-from.html
  - NtSetInformationFile rename primitive (embedded in 2018 post above)
- What level of researcher benefits most: Intermediate and above. Beginners will read it as technique; intermediate researchers will read it as methodology; senior researchers will use it as a checklist for variant hunting.
- Notes: Do not read individual posts in isolation. The power is in how they relate to each other as a system. The comment threads on the Google Project Zero blog also contain follow-up analysis from other researchers.

---

- Title: sandbox-attacksurface-analysis-tools (NtObjectManager)
- Author / Organization: James Forshaw / Google Project Zero
- URL: https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools
- Resource type: Research tool / PowerShell module + C# library
- Tier: S-TIER
- Scores:
  - Technical depth: 5/5
  - Originality: 5/5
  - Research value: 5/5
  - Variant-hunting value: 5/5
  - Primitive/root-cause value: 5/5
  - Re-read value: 5/5
- Historical or current: Current (actively maintained as of 2025)
- Why it deserves S-TIER: This is not a document — it is a research instrument. NtObjectManager exposes the Windows security model as a scriptable object: access checks, security descriptor enumeration, impersonation chains, token privilege analysis, named object browsing, RPC interface enumeration. No other tool makes the Windows security model this legible. The source code is the most detailed available documentation of how Windows security primitives behave at the NT layer. Forshaw built this to do his own research — the fact that it is public is an extraordinary resource transfer.
- What it changes in the reader: Reader gains the ability to run precise access checks against real objects, enumerate security descriptors across the system, trace impersonation paths programmatically, and reproduce the exact conditions under which a privilege boundary fails. The shift is from reading about the Windows security model to actively interrogating it. Every claim about how Windows access control works can now be tested in a REPL.
- Best use: Install NtObjectManager via the PowerShell Gallery (Install-Module NtObjectManager). Begin by reproducing examples from Windows Security Internals — they are designed to work together. Use Get-NtToken, Get-NtObjectSecurity, Get-AccessibleFile, Test-NtTokenImpersonation as primary research verbs. The source code (C#) is worth reading alongside usage.
- Related bug classes / primitives: All impersonation-related research, named object squatting, security descriptor auditing, AppContainer boundary analysis, token privilege research, COM security, RPC surface enumeration
- What level of researcher benefits most: Immediately useful at intermediate level; becomes a daily research instrument at senior level. Without it, researching Windows access control is manual and error-prone.
- Notes: The repository contains multiple tools beyond NtObjectManager: EditSection (section object viewer), TokenViewer, NtApiDotNet (the underlying .NET library). The NtApiDotNet library is directly usable in C# research tooling. Repository README and the books examples are the fastest entry points.

---

- Title: symboliclink-testing-tools
- Author / Organization: James Forshaw / Google Project Zero
- URL: https://github.com/googleprojectzero/symboliclink-testing-tools
- Resource type: Research tool / C++ toolset
- Tier: S-TIER
- Scores:
  - Technical depth: 5/5
  - Originality: 5/5
  - Research value: 5/5
  - Variant-hunting value: 5/5
  - Primitive/root-cause value: 5/5
  - Re-read value: 4/5
- Historical or current: Current (link primitives remain the dominant Windows LPE primitive class)
- Why it deserves S-TIER: This is the lab environment for the most important class of Windows LPE primitive. The source code is the documentation. CreateSymlink, CreateMountPoint, CreateHardLink, the directory junction tools — these are not convenience wrappers. They expose the exact Windows APIs and oplock/race conditions that turn arbitrary file write primitives into working LPE chains. Understanding how these tools work at the source level is equivalent to understanding the primitive at the implementation level. No other toolset provides this combination of utility and transparency.
- What it changes in the reader: Reader stops theorizing about junction attacks and starts constructing them. More importantly, the source code shows the error cases — the conditions under which junctions fail, where races are introduced, what the CreateOptions flags mean for directory object creation. This is the difference between a researcher who can use a technique and one who can debug why it failed in a specific edge case.
- Best use: Read the source before using the tools. CreateSymlink.cpp and the junction creation code are the most instructive. Use in combination with a kernel debugger (WinDbg) attached to a test VM to watch object creation live. Pair with NtObjectManager to verify the resulting object state.
- Related bug classes / primitives: NTFS junction attacks, object manager symbolic link attacks, oplock-based race exploitation, directory planting, NtSetInformationFile rename chains, file system link primitive composition
- What level of researcher benefits most: Most transformative for intermediate researchers who understand the primitive conceptually but have not implemented it. The source code answers the questions that no blog post does.
- Notes: The README describes basic usage but does not explain the primitives. Read the Forshaw exploitation tricks posts first; use this tool as the implementation of what those posts describe.

---

- Title: Time Travel Debugging (TTD)
- Author / Organization: Microsoft (WinDbg team)
- URL: https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/time-travel-debugging-overview
- Resource type: Debugging technology + official documentation
- Tier: S-TIER
- Scores:
  - Technical depth: 5/5
  - Originality: 5/5
  - Research value: 5/5
  - Variant-hunting value: 5/5
  - Primitive/root-cause value: 5/5
  - Re-read value: 3/5
- Historical or current: Current (TTD ships with WinDbg Preview; actively developed)
- Why it deserves S-TIER: Deterministic record-and-replay debugging changes the epistemology of root cause analysis. The question is no longer "what sequence of events led here?" with all the imprecision that implies — it is "step backward from this crash and read the precise instruction that established the corrupted state." For patch diffing (locate the patch, record execution through both versions, compare call sequences), race condition analysis (replay with different thread scheduling assumptions), and LPE root cause work (exactly where did privilege boundary enforcement fail?), nothing else provides this capability. TTD is the reason Windows-specific vulnerability research can be more precise than Linux work despite Windows having less source access.
- What it changes in the reader: Reader stops treating root cause analysis as archaeological reconstruction from crash dumps and starts treating it as deterministic navigation through a recorded execution. The shift is from asking "what happened?" to asking "at exactly which instruction did this invariant break, and what was the call stack?" This precision compounds: every root cause analysis done with TTD produces a more complete understanding than one done without it.
- Best use: Install WinDbg Preview from the Microsoft Store. Record traces of vulnerable processes with `ttd.exe -out trace.run -launch target.exe`. The LINQ-based query interface (`dx`) against TTD traces is the killer feature — use it to search for specific memory writes, function calls, or exception states across the full execution history. The TTD Travel Log is more useful than breakpoints for first-pass crash analysis.
- Related bug classes / primitives: All classes benefit — particularly useful for: use-after-free (walk backward from the invalid access to the free, then forward to the reuse), race conditions (observe exact interleaving), privilege boundary analysis (trace impersonation token state transitions)
- What level of researcher benefits most: Immediately useful for anyone doing root cause work. Transformative for researchers doing patch diff analysis or trying to understand complex race conditions. The learning curve is in the WinDbg `dx` query language, which is worth investing in.
- Notes: TTD requires WinDbg Preview (not classic WinDbg). Works only on 64-bit Windows for 64-bit and 32-bit targets. Recording has overhead (~2x slowdown, more for I/O-intensive processes). The Microsoft TTD team has published several deep-dive blog posts on TTD use for vulnerability analysis — worth reading alongside the official docs.

---

- Title: Bochspwn / Bochspwn Reloaded
- Author / Organization: Mateusz "j00ru" Jurczyk / Google Project Zero
- URL: https://j00ru.vexillium.org/ (papers section); Black Hat 2017 talk + paper
- Resource type: Research paper + conference talk (Black Hat USA 2017)
- Tier: S-TIER
- Scores:
  - Technical depth: 5/5
  - Originality: 5/5
  - Research value: 5/5
  - Variant-hunting value: 5/5
  - Primitive/root-cause value: 5/5
  - Re-read value: 5/5
- Historical or current: Historical (2013 original, 2017 Reloaded) but methodologically current — the systematic coverage-directed approach is the template for any class-level kernel research
- Why it deserves S-TIER: Bochspwn Reloaded is not a list of bugs. It is the methodological template for systematic kernel bug class discovery. The insight — instrument the kernel at the hypervisor level, define a class of unsafe behavior (double-fetch / kernel-to-user pointer dereference under race), and scan for it exhaustively — led to over 30 Windows kernel vulnerabilities in a single research campaign. The paper shows exactly how to go from "I have a hypothesis about a bug class" to "I have found every instance of that bug class in the kernel." This is the difference between artisanal vulnerability research and industrial-scale variant hunting.
- What it changes in the reader: Reader understands what systematic coverage-directed kernel research looks like, as opposed to ad-hoc bug hunting. More concretely: the reader learns how to build a pipeline from primitive identification → class formalization → instrumented scan → automated triage. This methodology applies to any new primitive class. The paper teaches how to find all bugs of a type, not just one.
- Best use: Read the Black Hat 2017 paper before the talk (the paper has more technical depth). Then read the original Bochspwn paper (2013) for the historical foundation. Focus on: the instrumentation architecture, the race detection algorithm, and the triage methodology. The source code (bochspwn-reloaded on GitHub) is secondary to the conceptual framework.
- Related bug classes / primitives: Double-fetch vulnerabilities, time-of-check-time-of-use (TOCTOU) in kernel-userspace interfaces, ProbeForRead/Write bypass patterns, kernel stack disclosure via uninitialized memory reads
- What level of researcher benefits most: Intermediate and senior researchers. Beginners will not yet have enough kernel context to apply the methodology. Senior researchers use this as validation that systematic class-level research is achievable and worth the infrastructure investment.
- Notes: The bochspwn-reloaded source code is on GitHub at https://github.com/googleprojectzero/bochspwn-reloaded. j00ru's blog (j00ru.vexillium.org) contains additional posts on kernel pool exploitation and Win32k research that complement this paper at A-tier.

---

- Title: PrintSpoofer — Abusing Impersonation Privileges on Windows 10
- Author / Organization: itm4n (Clément Labro)
- URL: https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/
- Resource type: Technical blog post (long-form, single topic)
- Tier: S-TIER
- Scores:
  - Technical depth: 5/5
  - Originality: 4/5
  - Research value: 5/5
  - Variant-hunting value: 5/5
  - Primitive/root-cause value: 5/5
  - Re-read value: 4/5
- Historical or current: Historical (2020) but structurally current — the impersonation primitive it describes survives service accounts to this day
- Why it deserves S-TIER: This is the cleanest single blog post that shows the complete anatomy of a privilege boundary violation from first principles through working exploitation. It identifies the surface (SeImpersonatePrivilege on service accounts), traces the authentication flow (how the named pipe server triggers a SYSTEM token), explains exactly which OS behavior is being abused (the PrintSpooler forcing a connection), delivers the exploit, and explicitly reasons about why Microsoft's mitigation attempts failed in earlier potato variants. Every component of quality research writing is present: root cause, primitive identification, exploitation mechanics, variant thinking, and explicit failure mode analysis.
- What it changes in the reader: Reader sees for the first time what a complete research post looks like — not a PoC dump or a CVE summary, but a structured argument. The post implicitly teaches research methodology through its structure: it shows that the question "why does this work?" is distinct from "that it works," and that answering the former is what separates research from tool delivery. Reader starts expecting this structure from other posts and begins applying it to their own work.
- Best use: Read before starting any impersonation or token privilege research. Use as a structural template for writing research posts. Return to it when encountering any SeImpersonate/SeAssignPrimaryToken privilege context.
- Related bug classes / primitives: SeImpersonatePrivilege abuse, named pipe authentication coercion, token impersonation chain, print spooler coercion (precursor to PrintNightmare surface), service account privilege restriction bypass
- What level of researcher benefits most: Junior-to-intermediate researchers gain the most from the structural lesson. Intermediate researchers gain from the root cause analysis. Senior researchers use it as the canonical impersonation primitive reference.
- Notes: The accompanying tool (PrintSpoofer.exe) is secondary to the post. Read the post without running the tool on first pass. The itm4n blog as a whole is A-tier; this post alone is S-tier by the quality of its argumentation and completeness of analysis.

---

## Why This List Is Short

S-TIER is not "very good." It is transformative. A resource earns S-TIER when:
- Reading it changes how you frame problems, not just what you know
- You will notice new things on reread every year
- It cannot be replaced by anything else currently available
- Researchers who skip it are measurably weaker for having done so

Every resource above meets all four conditions. Most good resources meet zero or one. The test is not "is this technically excellent?" — it is "does reading this restructure the reader's mental model of Windows security?" A resource that teaches twenty techniques is A-tier. A resource that teaches you how to think about a class of problems is S-tier.

The list must stay short. Adding resources to it requires removing them from A-tier consideration and justifying why they meet all four conditions. When in doubt, A-tier.

---

## What's NOT Here (And Why)

These were considered for S-TIER and explicitly rejected:

**Windows Internals Part 2** — A-tier. Storage, networking, and diagnostics subsystems are important but supplementary to the core security model installed by Part 1. The transformation happens in Part 1; Part 2 extends the map without changing the terrain.

**Rotten Potato (foxglovesecurity)** — A-tier [HISTORICAL]. Identified the original impersonation primitive for COM SYSTEM coercion. Important and worth reading, but the PrintSpoofer post captures the essence more cleanly and with better analytical structure. PrintSpoofer shows root cause; Rotten Potato shows discovery.

**Juicy Potato** — A-tier [HISTORICAL]. Extends Rotten Potato to a wider set of COM servers. Derivative of the same primitive; educational but does not restructure thinking beyond what PrintSpoofer accomplishes.

**GodPotato / SweetPotato** — A-tier at best, B-tier tool. Useful exploitation chains, minimal research insight beyond the impersonation primitive already captured elsewhere.

**decoder.cloud blog (Andrea Pierini)** — A-tier. Consistently excellent, technically precise research on WinRM, EFS, token abuse, and credential access. Narrow scope by design — does not provide the system-wide perspective that earns S-tier. Essential reading but not transformative in the way Forshaw's work is.

**HEVD (HackSys Extreme Vulnerable Driver)** — A-tier practice resource. Exceptional for developing kernel exploitation skills in a controlled environment. Practice, not insight. Learning to exploit HEVD teaches technique; it does not teach the Windows security model.

**PrivescCheck (itm4n)** — B-tier tool. Excellent enumeration, zero research transformation. Produces output you then have to understand, which requires the primary resources in this list.

**BloodHound / SharpHound** — Out of scope for this vault's focus (Windows single-host security model and kernel research). A-tier for Active Directory / lateral movement research; not relevant here.

**j00ru.vexillium.org blog posts (non-Bochspwn)** — A-tier. Excellent kernel pool and Win32k research, but individual posts do not meet the bar that Bochspwn Reloaded does for systematic methodology. Read everything on the blog at A-tier.

**tiraniddo.dev blog (complete)** — A-tier as a body of work. The Exploitation Tricks series within it earns S-tier; the broader blog (Windows COM, AppContainer, token research posts) is indispensable A-tier reading. The distinction matters: S-tier requires every post in a collection to be transformative. The Exploitation Tricks series is; the broader blog has posts of varying impact.
