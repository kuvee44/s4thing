# Researchers to Follow — Windows LPE & Internals Canon
## Primary: Windows LPE / kernel exploitation / security model
## Secondary: Adjacent fields (valuable, different focus)

> Curated for bug hunters, not for general awareness. Every person in the primary section has directly advanced the methodology of finding Windows privilege escalation and kernel vulnerabilities. Researchers demoted to secondary are excellent — their focus is just not Windows LPE internals.

---

# PRIMARY TIER — Core LPE & Kernel Research

---

## James Forshaw | [@tiraniddo] | S-TIER
- **Affiliation:** Google Project Zero
- **Blog:** https://www.tiraniddo.dev/
- **GitHub:** https://github.com/tyranid — https://github.com/googleprojectzero
- **Primary research domain:** Windows COM security, object manager, token/impersonation model, sandbox escapes, AppContainer, symbolic links, security model architecture
- **Why they matter for bug hunting specifically:** Forshaw is the single most productive source of exploitable Windows security model findings in the field. He defines entire attack surface categories — COM security, symbolic link planting, object namespace attacks — that others then mine for variants. His tools (NtObjectManager, OleViewDotNet, symboliclink-testing-tools) are the primary research infrastructure for these categories. Reading his work first means you find the same bugs others find, but you understand them rather than just reproducing them.
- **Must-read work:**
  - Windows Security Internals (No Starch, 2023) — https://nostarch.com/windows-security-internals
  - "Windows Exploitation Tricks" series — https://googleprojectzero.blogspot.com/search/label/Windows
  - tiraniddo.dev complete blog archive — https://www.tiraniddo.dev/
  - sandbox-attacksurface-analysis-tools — https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools
  - symboliclink-testing-tools — https://github.com/googleprojectzero/symboliclink-testing-tools
- **What reading their work teaches you:** How to reason about Windows security boundaries at the primitive level — not "which API can I abuse" but "which semantic invariant is violated and why." Specifically: COM activation security, token impersonation semantics, NT object namespace as an attack surface, and access check algorithm internals.
- **Incomplete fix record:** Yes — notable cases. Multiple COM and symbolic link CVEs where variants emerged after patches. His blog often documents the incomplete-fix-to-bypass pattern explicitly.
- **Active:** Yes

---

## Mateusz "j00ru" Jurczyk | [@j00ru__] | S-TIER
- **Affiliation:** Google Project Zero
- **Blog:** https://j00ru.vexillium.org/
- **GitHub:** https://github.com/j00ru
- **Primary research domain:** Windows kernel, Win32k subsystem, kernel memory corruption, race conditions, fuzzing methodology, uninitialized memory disclosure
- **Why they matter for bug hunting specifically:** j00ru invented the whole-system taint analysis approach to finding kernel bugs (Bochspwn), found hundreds of Win32k vulnerabilities systematically, and published the research methodology alongside the findings. His work teaches how to approach kernel bug finding at a class level — how to design instrumentation that reveals entire categories rather than hunting for individual instances. Win32k research without reading j00ru is operating without the canonical reference.
- **Must-read work:**
  - Bochspwn Reloaded paper — https://j00ru.vexillium.org/papers/2018/bochspwn-reloaded.pdf
  - Win32k exploitation posts — https://j00ru.vexillium.org/
  - Windows kernel memory disclosure research — https://googleprojectzero.blogspot.com/ (j00ru-authored posts)
  - Syscall table research — https://j00ru.vexillium.org/syscalls/nt/64/
- **What reading their work teaches you:** How to design research infrastructure that finds bug classes rather than individual bugs. Specifically: whole-system dynamic analysis, taint tracking for uninitialized data, and Win32k object lifecycle as an exploitation target.
- **Incomplete fix record:** Yes — Win32k bugs in particular frequently had variants emerge after patching due to structural root causes not being addressed.
- **Active:** Yes (less frequent publication than historically, but still active at PZ)

---

## Clément Labro "itm4n" | [@itm4n] | A-TIER
- **Affiliation:** Independent (previously SCRT)
- **Blog:** https://itm4n.github.io/
- **GitHub:** https://github.com/itm4n
- **Primary research domain:** Windows service account exploitation, named pipe impersonation, Windows Installer LPE, UAC bypass, token privileges
- **Why they matter for bug hunting specifically:** itm4n produces the best public documentation of Windows LPE analysis methodology. PrintSpoofer is the canonical modern impersonation technique (supersedes the DCOM Potato family for most scenarios), and the writeup explains the discovery process, not just the exploit. His Windows Installer series is the most complete public treatment of MSI-based LPE. PrivescCheck is the most maintainable and well-reasoned LPE enumeration tool publicly available.
- **Must-read work:**
  - PrintSpoofer — https://itm4n.github.io/printspoofer-abusing-impersonation-privileges/
  - Windows Installer series — https://itm4n.github.io/ (multiple posts)
  - Token privileges for LPE series — https://itm4n.github.io/
  - PrivescCheck — https://github.com/itm4n/PrivescCheck
- **What reading their work teaches you:** How to write research — the complete analysis chain from initial observation through root cause to working exploit and patch analysis. Specifically: named pipe security semantics, Windows Installer rollback mechanism, token privilege exploitation.
- **Incomplete fix record:** Yes — InstallerFileTakeOver bypass documented; multiple Installer-class variants found.
- **Active:** Yes

---

## Andrea Pierini "decoder" | [@decoder_it] | A-TIER
- **Affiliation:** Independent
- **Blog:** https://decoder.cloud/
- **GitHub:** https://github.com/decoder-it — https://github.com/antonioCoco
- **Primary research domain:** DCOM activation, OXID resolver abuse, named pipe impersonation, Potato family LPE, NTLM relay in local contexts
- **Why they matter for bug hunting specifically:** decoder is the primary authority on DCOM activation-based impersonation attacks. The Potato lineage (Juicy → Rogue → Local) represents the systematic exploitation and re-exploitation of a single root cause in the DCOM activation + NTLM relay mechanism as each iteration of patches attempted to block specific code paths. Following this lineage is the best available case study in how variant-hunting works in practice.
- **Must-read work:**
  - RoguePotato — https://decoder.cloud/2020/05/11/no-more-juicy-potato-old-story-welcome-rogued-potato/
  - LocalPotato (CVE-2023-21746) — https://decoder.cloud/2023/02/13/localpotato/
  - DCOM/OXID research series — https://decoder.cloud/
  - RoguePotato GitHub — https://github.com/antonioCoco/RoguePotato
- **What reading their work teaches you:** DCOM activation security internals, NTLM authentication flow at the protocol level, and patch analysis methodology in practice — how to read a patch, understand what it actually prevents, and find what remains open.
- **Incomplete fix record:** Yes — the entire Potato lineage is evidence. Multiple DCOM/impersonation patches bypassed.
- **Active:** Yes

---

## Alex Ionescu | [@aionescu] | A-TIER
- **Affiliation:** CrowdStrike (previously Winsider Seminars & Solutions)
- **Blog:** http://www.alex-ionescu.com/
- **GitHub:** https://github.com/ionescu007
- **Primary research domain:** Windows kernel architecture, ALPC, Protected Processes, boot security, Hyper-V/VSM, Credential Guard, UEFI
- **Why they matter for bug hunting specifically:** Ionescu co-authored Windows Internals and has deeper architectural knowledge of the NT kernel than any public researcher. His ALPC research defined the attack surface of Windows inter-process communication for a generation of researchers. His boot security and VSM research is the primary public reference on modern Windows security features that constrain kernel exploitation — understanding them is required before attempting to bypass them.
- **Must-read work:**
  - Windows Internals Part 1 & 2 (co-author)
  - ALPC blog series — http://www.alex-ionescu.com/
  - "Breaking the Chain" (Protected Processes) — CanSecWest talk
  - Windows 10 Kernel Internals lecture series — YouTube (free)
- **What reading their work teaches you:** Windows kernel architecture as a whole system — not individual subsystems in isolation but how they interact and constrain each other. Specifically: ALPC security model, process isolation mechanisms, and the trust hierarchy from UEFI through kernel to user mode.
- **Incomplete fix record:** Unknown — primarily architectural research rather than individual CVE findings.
- **Active:** Less public recently; historical work remains essential.

---

## Yarden Shafir | [@yarden_shafir] | A-TIER
- **Affiliation:** SpecterOps (previously CrowdStrike)
- **Blog:** https://windows-internals.com/
- **GitHub:** https://github.com/yardenshafir
- **Primary research domain:** Windows kernel pool exploitation, Segment Heap, I/O Ring, modern kernel exploitation methodology
- **Why they matter for bug hunting specifically:** Shafir owns the current state-of-the-art in Windows kernel exploitation technique post-Segment Heap transition. "The Pool is Dead" redefined how kernel pool bugs are exploited on modern Windows. The I/O Ring exploitation research introduced a new kernel LPE primitive. Reading her work teaches you what kernel exploitation actually looks like on a hardened modern target, not on the legacy pool allocator.
- **Must-read work:**
  - "The Pool is Dead, Long Live the Pool" (with Ionescu) — https://windows-internals.com/
  - I/O Ring exploitation research — https://windows-internals.com/
  - Pool Party technique — conference talk + blog
  - windows-internals.com kernel posts archive
- **What reading their work teaches you:** Modern Windows kernel heap architecture and how it affects exploit reliability; how kernel LPE primitives evolve when mitigations are added; systematic exploitation methodology for post-Segment Heap Windows.
- **Incomplete fix record:** Unknown — primarily technique research rather than individual CVE reporting.
- **Active:** Yes

---

## Tarjei Mandt | [@kernelpool] | A-TIER [HISTORICAL — formative]
- **Affiliation:** Azimuth Security / various
- **Blog:** https://www.mista.nu/
- **GitHub:** Various
- **Primary research domain:** Windows kernel pool exploitation, Win32k, kernel heap internals
- **Why they matter for bug hunting specifically:** Mandt's "Kernel Pool Exploitation on Windows 7" (CanSecWest 2011) is the foundational paper that defined kernel pool exploitation methodology for a decade. Every pool exploitation technique that followed builds on this work. Win32k exploitation at Pwn2Own drove Windows kernel hardening decisions. Historical but formative — you cannot understand current kernel pool research without understanding what it was built to replace.
- **Must-read work:**
  - "Kernel Pool Exploitation on Windows 7" — CanSecWest 2011 — https://www.mista.nu/research/
  - Win32k vulnerability research publications — https://www.mista.nu/research/
- **What reading their work teaches you:** The historical kernel pool exploitation model — lookaside lists, overflow primitives, free list corruption — that current mitigations were designed to prevent. Essential context for understanding why modern techniques look the way they do.
- **Incomplete fix record:** N/A — historical research.
- **Active:** Archived / historical.

---

## Abdelhamid Naceri "halov / klinix5" | [@halov_] | A-TIER
- **Affiliation:** Independent
- **Blog:** https://halov.medium.com/
- **GitHub:** https://github.com/klinix5
- **Primary research domain:** Windows Installer LPE, arbitrary file write via elevated rollback, MSI vulnerability research
- **Why they matter for bug hunting specifically:** Naceri found InstallerFileTakeOver and, on the day Microsoft published the CVE-2021-41379 patch, dropped a working bypass demonstrating the fix addressed the symptom not the root cause. This is the clearest modern example of patch-analysis-as-research — not just finding the original bug but proving the fix is incomplete and finding the variant in real time. His research output is concentrated in Windows Installer/MSI mechanisms, which remain a persistent source of LPE bugs.
- **Must-read work:**
  - InstallerFileTakeOver + bypass — https://github.com/klinix5/InstallerFileTakeOver
  - Medium writeups on MSI mechanism analysis — https://halov.medium.com/
- **What reading their work teaches you:** Windows Installer elevated rollback mechanism at the API and filesystem level; how to analyze a patch and immediately identify whether the root cause was actually fixed.
- **Incomplete fix record:** Yes — by design. InstallerFileTakeOver bypass is the definitive example.
- **Active:** Yes (periodic research drops)

---

## SandboxEscaper | [Anonymous] | A-TIER [HISTORICAL]
- **Affiliation:** Independent (anonymous)
- **Blog:** https://sandboxescaper.blogspot.com/ (archived — use Wayback Machine)
- **GitHub:** https://github.com/SandboxEscaper (account deleted — community archives exist)
- **Primary research domain:** Arbitrary file write via privileged Windows components, Task Scheduler LPE, Windows Error Reporting abuse, DiagHub
- **Why they matter for bug hunting specifically:** Between 2018–2019, SandboxEscaper publicly released approximately 10 Windows LPE zero-days without disclosure. Historically significant for two reasons: the techniques introduced (arbitrary file write via WER, DiagHub, Task Scheduler) became canonical LPE primitives that later researchers analyzed, extended, and found variants of; and the disclosure approach forced a community reckoning about responsible disclosure norms that's still relevant. Study the techniques with primary focus on *why* they worked — what property of the Windows service enabled the arbitrary file operation.
- **Must-read work:**
  - Archived PoC repositories (community mirrors)
  - CVE analysis posts from other researchers documenting the root causes
  - Task Scheduler LPE, DiagHub, WER arbitrary file delete techniques
- **What reading their work teaches you:** Arbitrary file write / delete as a first-class LPE primitive class; how privileged services that touch user-accessible paths create exploitable file operation sequences.
- **Incomplete fix record:** Yes — several releases were variants of incompletely patched prior bugs.
- **Active:** Archived / historical. Account deleted.

---

## Jonas Lyk | [@jonasLyk] | A-TIER
- **Affiliation:** Independent
- **Blog:** https://github.com/jonasLyk
- **GitHub:** https://github.com/jonasLyk
- **Primary research domain:** Windows LPE variants, file system bugs, MSRC patch completeness analysis, public patch bypass disclosure
- **Why they matter for bug hunting specifically:** Lyk's primary value to the field is real-time patch bypass discovery and transparent public disclosure. His Twitter/X feed functions as a live feed of "this patch is incomplete — here's the variant" findings. Following him closely during Patch Tuesday week surfaces bypass discoveries before they make it into formal write-ups. He represents the variant-hunting methodology applied continuously rather than as a one-time exercise.
- **Must-read work:**
  - Twitter/X posts @jonasLyk — patch bypass announcements
  - GitHub PoC repositories — https://github.com/jonasLyk
- **What reading their work teaches you:** How to approach Patch Tuesday as a variant-hunting exercise; how to quickly assess whether a fix fully addresses a root cause; how to publicly disclose bypass findings responsibly but promptly.
- **Incomplete fix record:** Yes — primary focus is documenting incomplete fixes.
- **Active:** Yes

---

## Valentina Palmiotti "chompie1337" | [@chompie1337] | A-TIER
- **Affiliation:** IBM Security X-Force
- **Blog:** https://www.ibm.com/security/blog + personal posts
- **GitHub:** https://github.com/chompie1337
- **Primary research domain:** Windows kernel exploitation, LPE research, exploitation methodology
- **Why they matter for bug hunting specifically:** Palmiotti's SMBGhost kernel exploitation (CVE-2020-0796) is a landmark modern kernel exploitation case study — a remotely triggered integer overflow in SMB that enables LPE via kernel arbitrary read/write primitives. The exploitation writeup is one of the best public examples of going from memory corruption primitive to full kernel control on a modern Windows target. Her conference presentations on exploitation methodology are concise and applicable.
- **Must-read work:**
  - SMBGhost kernel exploitation — https://github.com/chompie1337/SMBGhost_RCE_PoC (and associated writeup)
  - Conference presentations on kernel exploitation methodology
- **What reading their work teaches you:** Modern kernel exploitation workflow: from memory corruption primitive to kernel read/write to SYSTEM token. Specifically: how to exploit an integer overflow in a kernel network component on a post-Segment Heap target.
- **Incomplete fix record:** Unknown.
- **Active:** Yes

---

## Synacktiv Team | [@synacktiv] | A-TIER
- **Affiliation:** Synacktiv (France)
- **Blog:** https://www.synacktiv.com/publications
- **GitHub:** https://github.com/synacktiv
- **Primary research domain:** Windows kernel exploitation, Hyper-V/hypervisor research, driver security, sandbox escapes
- **Why they matter for bug hunting specifically:** Synacktiv consistently produces technically rigorous Windows kernel and hypervisor security research. Their Hyper-V research (multiple Pwn2Own wins) is the primary public reference for virtualization-layer Windows exploitation. Their kernel driver vulnerability research is systematic and publication-quality. They approach each target with the full research methodology — root cause, full exploit chain, full write-up — which makes their output directly usable as a learning reference.
- **Must-read work:**
  - Hyper-V vulnerability research — https://www.synacktiv.com/publications
  - Windows kernel driver exploitation posts — https://www.synacktiv.com/publications
  - Pwn2Own technical write-ups (post-contest)
- **What reading their work teaches you:** Full-chain kernel exploitation methodology on hardened targets; Hyper-V attack surface and exploitation; how to structure a research publication that communicates the full finding.
- **Incomplete fix record:** Unknown — primarily novel research rather than variant hunting.
- **Active:** Yes

---

## ZeroPeril Team | [@ZeroPeril] | A-TIER
- **Affiliation:** ZeroPeril Ltd. (UK)
- **Blog:** https://zeroperil.co.uk/blog/
- **GitHub:** https://github.com/ZeroPeril
- **Primary research domain:** COM LPE, Windows security model, less-studied Windows attack surface
- **Why they matter for bug hunting specifically:** ZeroPeril finds COM-based and Windows component LPE bugs in targets that are less heavily audited than the core OS components Forshaw focuses on. Their research fills in the gaps — COM servers and Windows components that receive less attention from the large research teams. Multiple CVEs across Windows components that weren't well-audited.
- **Must-read work:**
  - Blog posts on COM attack surface and LPE — https://zeroperil.co.uk/blog/
- **What reading their work teaches you:** How to apply COM attack surface enumeration methodology to less-studied components; that the "obvious" targets aren't the only sources of LPE bugs.
- **Incomplete fix record:** Unknown.
- **Active:** Yes (intermittent)

---

## Jann Horn | [@tehjh] | A-TIER
- **Affiliation:** Google Project Zero
- **Blog:** https://googleprojectzero.blogspot.com/ (Jann Horn-authored posts)
- **GitHub:** https://github.com/thejh
- **Primary research domain:** Race conditions, kernel security, memory safety bugs — primarily Linux but with directly applicable Windows methodology
- **Why they matter for bug hunting specifically:** Horn's race condition research (Dirty COW, Project Zero kernel posts) defines the current methodology for finding and exploiting time-of-check-time-of-use (TOCTOU) and similar concurrency bugs. While much of his published work is Linux-focused, the race condition analysis techniques — finding races through code audit, triggering them reliably, exploiting them — are directly applicable to Windows. His analysis methodology for complex multi-component interaction bugs is unmatched.
- **Must-read work:**
  - Project Zero race condition posts — https://googleprojectzero.blogspot.com/
  - Kernel memory safety research — https://googleprojectzero.blogspot.com/
  - speculative execution side-channel research (Spectre/Meltdown co-discoverer)
- **What reading their work teaches you:** Race condition analysis methodology — how to identify concurrent access patterns in kernel code that create exploitable windows; how to build reliable triggering conditions for timing-dependent bugs.
- **Incomplete fix record:** Yes — race condition bugs frequently have incomplete fixes due to the difficulty of fully closing concurrency windows.
- **Active:** Yes

---

## Max Van Amerongen | [@maxpl0it] | A-TIER
- **Affiliation:** Independent / F-Secure (previously)
- **Blog:** https://blog.maxpl0it.com/
- **GitHub:** https://github.com/maxpl0it
- **Primary research domain:** Windows LPE, kernel vulnerability research, exploit development
- **Why they matter for bug hunting specifically:** Van Amerongen is an underrated Windows LPE and kernel researcher who produces technically rigorous CVE write-ups and exploitation research. His work covers both user-mode LPE techniques and kernel exploitation, with particular attention to the full exploit development chain rather than just the vulnerability discovery. His blog posts are detailed and show the complete analysis path from bug to reliable exploit.
- **Must-read work:**
  - Windows LPE vulnerability write-ups — https://blog.maxpl0it.com/
  - Kernel vulnerability research posts — https://blog.maxpl0it.com/
- **What reading their work teaches you:** Full-chain exploit development methodology on Windows; how to approach kernel bug exploitation when you have a vulnerability but need to build a reliable exploit primitive.
- **Incomplete fix record:** Unknown.
- **Active:** Yes

---

## Markus Gaasedelen | [@gaasedelen] | A-TIER
- **Affiliation:** Ret2 Systems
- **Blog:** https://blog.ret2.io/
- **GitHub:** https://github.com/gaasedelen
- **Primary research domain:** Kernel pool exploitation, heap research, fuzzing, exploitation tooling
- **Why they matter for bug hunting specifically:** Gaasedelen's research on kernel heap exploitation and fuzzing methodology is technically deep and practically applicable. His work on coverage-guided fuzzing and kernel pool exploitation gives researchers tools and techniques for both finding bugs and exploiting them. The Tenet time-travel analysis plugin and other research tooling he's contributed extend the Windows research infrastructure available to the community.
- **Must-read work:**
  - Kernel pool exploitation research — https://blog.ret2.io/
  - Coverage-guided fuzzing methodology posts
  - Tenet (time-travel trace plugin) — https://github.com/gaasedelen/tenet
- **What reading their work teaches you:** Modern kernel heap exploitation on current Windows targets; fuzzing infrastructure design for kernel targets; trace-based vulnerability analysis.
- **Incomplete fix record:** Unknown.
- **Active:** Yes

---

## Bryan Alexander "dronesec" | [@dronesec] | A-TIER
- **Affiliation:** Independent
- **Blog:** https://blog.dronesec.pw/
- **GitHub:** https://github.com/dronesec
- **Primary research domain:** Windows service exploitation, service account abuse, SCM attack surface
- **Why they matter for bug hunting specifically:** Alexander has done consistent, focused research on Windows service attack surface — service binary path hijacking, service configuration vulnerabilities, SCM (Service Control Manager) attack surface. This is an LPE category that receives less systematic research attention than token abuse or kernel bugs, and Alexander is the primary researcher covering it in depth.
- **Must-read work:**
  - Windows service exploitation posts — https://blog.dronesec.pw/
  - SCM attack surface research
- **What reading their work teaches you:** Windows service security model from the security descriptor and configuration perspective; how service account privileges and binary paths create LPE vectors; SCM as an attack surface category.
- **Incomplete fix record:** Unknown.
- **Active:** Intermittent

---

## Netanel Ben-Simon | [@NatanBenSimon] | A-TIER
- **Affiliation:** Various
- **Blog:** Various (GitHub + conference publications)
- **GitHub:** https://github.com/NetanelBenSimon
- **Primary research domain:** Windows kernel CVEs, kernel vulnerability research
- **Why they matter for bug hunting specifically:** Ben-Simon has reported multiple Windows kernel CVEs and contributes to advancing kernel vulnerability research methodology. His work covers kernel attack surface categories that are less heavily published on, making his findings representative of active hunting in less-audited areas.
- **Must-read work:**
  - CVE write-ups and research publications — GitHub + conference talks
- **What reading their work teaches you:** Kernel vulnerability discovery in less-audited Windows components; systematic audit methodology for kernel attack surface.
- **Incomplete fix record:** Unknown.
- **Active:** Yes

---

---

# SECONDARY TIER — Valuable Adjacent Research (Not Core LPE Focus)

> These researchers are excellent. Their work is not here because it's inferior — it's here because their focus is adjacent to Windows LPE internals rather than central to it. Follow them if their domain is relevant to your current research.

---

## Benjamin Delpy "gentilkiwi" | [@gentilkiwi] | Secondary
- **Affiliation:** Independent
- **Blog:** https://blog.gentilkiwi.com/
- **GitHub:** https://github.com/gentilkiwi
- **Primary research domain:** Windows credential security, LSASS, NTLM/Kerberos internals, SSP, Mimikatz
- **Why secondary:** Delpy's research focus is post-exploitation credential theft — what you do *after* you have SYSTEM or equivalent access. Mimikatz is the canonical post-exploitation credential tool, and his LSASS/SSP research is irreplaceable for that domain. But the bug-finding methodology and technical focus are primarily about extracting credentials from a system you already control, not about finding the LPE bugs that get you there. Follow if credential security and post-exploitation are in scope; don't expect LPE research methodology from this stream.
- **Key work:** Mimikatz — https://github.com/gentilkiwi/mimikatz

---

## Will Schroeder "harmj0y" | [@harmj0y] | Secondary
- **Affiliation:** SpecterOps
- **Blog:** https://blog.harmj0y.net/
- **GitHub:** https://github.com/HarmJ0y (GhostPack org)
- **Primary research domain:** Active Directory security, Kerberos abuse, .NET offensive tooling, GhostPack
- **Why secondary:** Schroeder's research is authoritative on Active Directory and Kerberos attack techniques — an entirely different attack surface than Windows LPE internals. Rubeus, SharpUp, Seatbelt are excellent tools; Kerberoasting and domain trust attacks are real and important. But the research methodology (auditing AD configuration, understanding Kerberos protocol semantics) is distinct from the kernel/object manager/token internals focus of the primary list. Follow if AD and lateral movement are in scope.
- **Key work:** GhostPack — https://github.com/GhostPack

---

## Matthieu Suiche | [@msuiche] | Secondary
- **Affiliation:** Magnet Forensics
- **Blog:** https://blog.comae.io/ — https://msuiche.net/
- **GitHub:** https://github.com/msuiche
- **Primary research domain:** Windows memory forensics, physical memory acquisition, hibernation file format, bootkit research
- **Why secondary:** Suiche's work is essential for memory forensics and incident response research — hibernation file analysis, physical memory acquisition (WinPmem), bootkit detection. The research requires deep Windows internals knowledge and is technically rigorous. But the application is forensics and detection, not offensive LPE. Follow if your research intersects with memory forensics, digital forensics, or Windows boot security.
- **Key work:** WinPmem — https://github.com/Velocidex/WinPmem

---

## Casey Smith "subtee" | [@subtee] | Secondary
- **Affiliation:** Various (previously Red Canary)
- **Blog:** http://subt0x10.blogspot.com/
- **GitHub:** https://github.com/caseysmithrc
- **Primary research domain:** AppLocker/WDAC bypass, LOLBins, code execution via trusted Windows binaries
- **Why secondary:** Smith's research is foundational for defense evasion and application control bypass — an important attack surface, but not Windows LPE internals. LOLBins/LOLBAS research (Squiblydoo, msbuild, wmic, certutil) is useful for understanding execution environments and bypass techniques, but finding new LOLBins requires a different skill set than finding kernel or impersonation LPE bugs. Follow if defense evasion and application allowlisting bypass are in scope.
- **Key work:** LOLBAS project — https://lolbas-project.github.io/

---

## FuzzySecurity "b33f" | [@fuzzysec] | Secondary
- **Affiliation:** WithSecure (previously F-Secure Labs)
- **Blog:** https://www.fuzzysecurity.com/
- **GitHub:** https://github.com/FuzzySecurity
- **Primary research domain:** Windows post-exploitation, ETW security research, PowerShell tooling, tutorial-level LPE techniques
- **Why secondary:** b33f's tutorial series is the canonical starting point for beginners — structured, reproducible, good pedagogy. SilkETW is a genuinely useful research tool for ETW-based telemetry and detection research. But the research is not at the primary-tier level for LPE internals: the privilege escalation tutorials cover known techniques without original root-cause analysis, and the technical depth is appropriate for intermediate researchers rather than advanced bug hunters. The ETW research is adjacent to LPE rather than central to it.
- **Key work:** SilkETW — https://github.com/mandiant/SilkETW

---

---

## How to Actually Use This List

**1. Work through the primary list in publication order, not follow order.**
For each researcher, start with their oldest published research and work forward chronologically. The progression of Forshaw's thinking from 2014 to 2024, j00ru's Win32k work from 2011 to 2019, itm4n's LPE research from 2018 to present — reading in sequence teaches you how the field evolved, which is more valuable than knowing the current state without the context of how it was reached.

**2. Watch MSRC Security Update Guide acknowledgments weekly during Patch Tuesday cycle.**
New names appearing in the MSRC acknowledgment page — especially with multiple CVEs across a short period — are new researchers actively finding things. Add them to your follow list before they become widely known. This is how you find the next generation of primary-tier researchers before the community catches up. Cross-reference acknowledgment names against GitHub and Twitter/X to find their publication venues.

**3. Check OffensiveCon and BlueHat CFP accepted talks before the conference — not after.**
Review the accepted talk list when it's announced. If a talk title mentions a Windows LPE technique, kernel primitive, or component you don't recognize, that's a research gap you should investigate *before* the talk is published. Use the two months between CFP announcement and conference to do your own analysis of what the title suggests, then compare against the actual presentation. This builds research intuition and ensures you're not just consuming finished research.

**4. Follow j00ru's GitHub directly for paper releases — don't wait for blog aggregators.**
j00ru's academic-style papers (Bochspwn, Win32k research) appear on his GitHub or website before they're widely circulated. Watch the repository and site directly. Similarly, Forshaw's tool repositories (sandbox-attacksurface-analysis-tools, symboliclink-testing-tools) get commits that often predate blog posts explaining the new capabilities — reading the commit messages and diff is a secondary research feed that surfaces new attack surface before it's written up formally.

---

*Canon last revised: 2026-04-22. Primary tier requires: direct Windows LPE/kernel/security model research, original findings, published methodology. Secondary tier: excellent work, adjacent focus.*
