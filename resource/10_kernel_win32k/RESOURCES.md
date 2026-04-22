# Kernel & Win32k Resources — Windows Security Research

> Category: Kernel exploitation, Win32k, driver research, pool internals
> Tags used: [FOUNDATIONAL] [MUST-READ] [LAB-WORTHY] [HISTORICAL]

---

## Foundational References

---

- **Title:** Windows Internals Part 1 & 2 (7th Edition)
- **Author / Organization:** Pavel Yosifovich, Alex Ionescu, Mark Russinovich, David Solomon
- **URL:** https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals
- **Resource type:** Book (technical reference)
- **Topic tags:** Kernel architecture, process manager, memory manager, object manager, I/O manager, executive, security reference monitor, handles, tokens, threads, Win32k
- **Difficulty:** Intermediate → Advanced
- **Historical or current:** Current (7th edition targets Windows 10)
- **Trust level:** HIGH — written by Microsoft engineers and acknowledged kernel experts
- **Why it matters:** This is the definitive reference for Windows kernel architecture. Any serious kernel security research requires understanding the structures, subsystems, and mechanisms described here. The security reference monitor, token model, handle table, and object manager chapters are directly required reading before any privilege escalation or kernel exploitation research.
- **What it teaches:** Executive object types and lifecycle; process and thread internals; virtual memory management (VAD, PTE, pool); I/O request packet (IRP) handling; the security reference monitor and access check algorithm; handle table implementation; kernel synchronization primitives; kernel pool allocation internals.
- **Best use:** Read sequentially for foundational understanding. When researching a specific bug class (e.g., pool exploitation), return to the relevant chapter with a live kernel debugger to observe the described structures in practice. Keep both volumes accessible during all kernel research.
- **Related bug classes / primitives:** All kernel vulnerability classes — foundational context for every kernel primitive
- **Suggested next resource:** HEVD for hands-on kernel exploitation; WinDbg documentation for observing described structures live
- **Notes:** Mandatory. No substitute. The kernel chapters are deep enough to directly support exploit development. Part 2 covers Win32k, I/O, and advanced topics. [FOUNDATIONAL]

---

- **Title:** Bochspwn Reloaded — Detecting Kernel Memory Disclosure with x86 Emulation
- **Author / Organization:** j00ru (Mateusz Jurczyk) / Google Project Zero
- **URL:** https://j00ru.vexillium.org/talks/blackhat17-bochspwn-reloaded/
- **Resource type:** Conference paper + talk (Black Hat USA 2017) + research tool
- **Topic tags:** Kernel memory disclosure, taint tracking, x86 emulation, Bochs, KASLR defeat, information leaks, kernel stack disclosure, uninitialized memory
- **Difficulty:** Advanced
- **Historical or current:** Historical (2017) — methodology remains highly relevant
- **Trust level:** HIGH — j00ru is one of the world's foremost Windows kernel security researchers
- **Why it matters:** Bochspwn Reloaded is a landmark in systematic kernel vulnerability discovery. By running the Windows kernel inside a modified Bochs x86 emulator with taint tracking, j00ru could automatically detect any uninitialized kernel memory that was copied to user space — a class of bug that defeats KASLR and can leak kernel pointers. The paper discovered dozens of previously unknown kernel memory disclosure vulnerabilities. The methodology — systematic, automated, emulation-based taint tracking — is a model for scalable vulnerability research.
- **What it teaches:** How taint tracking works at the instruction level; why uninitialized kernel stack/pool memory leaks defeat KASLR; x86 emulation with Bochs as a research platform; systematic vulnerability discovery methodology; how kernel-to-user memcpy operations can leak sensitive data; structure padding bytes as a disclosure source.
- **Best use:** Read the full paper and watch the conference talk. Study the original Bochspwn paper (2013) first for context, then Reloaded. Understand the taint tracking approach deeply — it is directly applicable to other emulation-based research methodologies.
- **Related bug classes / primitives:** Kernel memory disclosure, KASLR bypass, uninitialized memory, information leaks, kernel pointer disclosure
- **Suggested next resource:** j00ru's earlier Bochspwn paper (2013); KASLR bypass technique survey; "Windows Kernel Exploitation" resources for using leaked pointers
- **Notes:** j00ru's research site (vexillium.org) contains multiple landmark papers. This is among the most influential kernel research publications from the 2010s. [MUST-READ]

---

- **Title:** Win32k.sys Vulnerability Research — j00ru & Others
- **Author / Organization:** j00ru (Mateusz Jurczyk), Tavis Ormandy / Google Project Zero; various CVE researchers
- **URL:** https://googleprojectzero.blogspot.com/ (search Win32k); https://j00ru.vexillium.org/
- **Resource type:** Research blog posts / CVE analysis collection
- **Topic tags:** Win32k, GDI, USER objects, kernel pool, NULL pointer dereference, type confusion, Win32k shadow table, kernel attack surface
- **Difficulty:** Advanced
- **Historical or current:** Ongoing (Win32k vulnerabilities continue to be discovered)
- **Trust level:** HIGH
- **Why it matters:** Win32k.sys is historically the single most exploited kernel component in Windows. It handles the entire windowing system (USER objects, GDI, DWM interaction) and runs in kernel mode despite handling unprivileged user input. The attack surface is enormous and has yielded hundreds of CVEs over two decades, including in-the-wild exploits used by nation-state actors. Understanding Win32k architecture is essential for any kernel security researcher.
- **What it teaches:** Win32k architecture (WNDOBJ, DCOBJ, SURFOBJ, USER heap); how GDI object callbacks create kernel exploitation opportunities; Win32k NULL pointer dereference patterns; the desktop heap and session space; how Win32k's kernel/user boundary creates attack surface; why restricting Win32k from sandboxes (Win32k lockdown) is a critical mitigation.
- **Best use:** Start with j00ru's CVE analysis posts. Pick specific CVEs from Win32k and use WinDbg to study the vulnerable structure. Use the HEVD lab environment to understand kernel exploitation fundamentals before attacking Win32k directly.
- **Related bug classes / primitives:** NULL pointer dereference, type confusion, use-after-free, kernel pool corruption, callback exploitation — all in Win32k context
- **Suggested next resource:** CVE-2021-1732 analysis (in-the-wild Win32k exploit); Windows Internals Chapter on Win32k (Part 2)
- **Notes:** Win32k is being restricted (Win32k lockdown in sandboxed processes) — understand both the legacy attack surface and the ongoing mitigation work. Multiple researchers have published excellent analysis; search Project Zero blog specifically for Win32k entries.

---

- **Title:** HEVD — HackSys Extreme Vulnerable Driver
- **Author / Organization:** HackSysTeam (Ashfaq Ansari et al.)
- **URL:** https://github.com/hacksysteam/HackSysExtremeVulnerableDriver
- **Resource type:** Intentionally vulnerable kernel driver + exploit lab
- **Topic tags:** Kernel exploitation, IOCTL, stack overflow, heap overflow, use-after-free, pool corruption, null pointer dereference, type confusion, race conditions, token stealing
- **Difficulty:** Advanced
- **Historical or current:** Current (includes Windows 10/11 exercises)
- **Trust level:** HIGH
- **Why it matters:** The definitive kernel exploitation training environment. Covers every major kernel vulnerability class in a single, controlled, well-documented package. No other resource provides this depth and breadth for kernel exploitation practice.
- **What it teaches:** IOCTL dispatch and kernel driver architecture; stack overflow in kernel context with SMEP bypass; heap/pool corruption and exploitation; use-after-free in kernel; null pointer dereference exploitation; type confusion; integer overflow; race conditions; token stealing shellcode; ROP chains for kernel DEP bypass.
- **Best use:** Two-machine kernel debugging setup (KDNET). Install HEVD on the target VM. Work through each vulnerability class. Write your own exploits. Use WinDbg with TTD for exploit development. Cross-reference with Windows Internals for theory.
- **Related bug classes / primitives:** Every major kernel vulnerability class
- **Suggested next resource:** Yarden Shafir's pool exploitation research; "I/O Ring to Rule Them All" for modern Windows 11 primitives
- **Notes:** Mandatory for kernel exploitation learning. [LAB-WORTHY] [MUST-READ for kernel exploitation]

---

## Kernel Exploitation Techniques

---

- **Title:** Windows Kernel Shellcodes on Windows 10
- **Author / Organization:** Matteo Malvica
- **URL:** https://www.matteomalvica.com/blog/2019/07/06/windows-kernel-shellcodes/
- **Resource type:** Blog post series
- **Topic tags:** Kernel shellcode, token stealing, SYSTEM token, KTHREAD, EPROCESS, PsInitialSystemProcess, kernel exploitation
- **Difficulty:** Advanced
- **Historical or current:** Historical (2019) — token stealing concept remains foundational
- **Trust level:** HIGH
- **Why it matters:** The token-stealing shellcode is the canonical kernel exploitation payload for privilege escalation. This post series explains it clearly: walk the EPROCESS list, find the SYSTEM process token, copy it to the current process. Understanding this primitive is required before studying more advanced payloads.
- **What it teaches:** EPROCESS structure layout; how the kernel process list is walked; KTHREAD → KPROCESS → EPROCESS relationships; token field offset in EPROCESS; how to write position-independent kernel shellcode; how to return cleanly from a kernel exploit payload.
- **Best use:** Study alongside WinDbg — use the debugger to inspect EPROCESS structures while reading the post. Implement the shellcode yourself. Test with HEVD as the vulnerability trigger.
- **Related bug classes / primitives:** Kernel shellcode, token stealing, privilege escalation via kernel primitive
- **Suggested next resource:** HEVD for the vulnerability trigger; Windows Internals for EPROCESS structure theory
- **Notes:** Some offsets are Windows-version-specific. The methodology is timeless even if specific offsets change. Essential foundational material.

---

- **Title:** One I/O Ring to Rule Them All — A New Attack Primitive on Windows 11
- **Author / Organization:** Yarden Shafir / Windows Internals Blog
- **URL:** https://windows-internals.com/one-io-ring-to-rule-them-all-a-new-attack-primitive-on-windows-11/
- **Resource type:** Research blog post
- **Topic tags:** I/O Ring, Windows 11, kernel read/write primitive, pool spray, arbitrary R/W, kernel exploitation, modern primitives
- **Difficulty:** Advanced
- **Historical or current:** Current (Windows 11 era technique)
- **Trust level:** HIGH — Yarden Shafir is one of the most respected Windows kernel researchers active today
- **Why it matters:** Demonstrates how new Windows APIs (I/O Ring, introduced in Windows 11) can be abused as powerful exploitation primitives. The I/O Ring structure provides a kernel read/write primitive with significant exploitation advantages. This is a landmark post for understanding modern Windows 11 kernel exploitation and how new APIs introduce new attack surface.
- **What it teaches:** I/O Ring API design and kernel implementation; how kernel structures for new APIs can be abused as primitives; modern pool spray techniques on Windows 11; how to convert a limited corruption into a useful read/write primitive; the evolution of kernel exploitation primitives across Windows versions.
- **Best use:** Study after understanding HEVD fundamentals and Windows pool internals. Use WinDbg on a Windows 11 VM to inspect IoRing structures while reading the post. Follow up with Yarden's related posts on pool exploitation.
- **Related bug classes / primitives:** Arbitrary kernel R/W primitive, pool spray, kernel exploitation on Windows 11
- **Suggested next resource:** Yarden Shafir's other Windows Internals posts; pool internals research (Alex Ionescu, Corentin Bayet)
- **Notes:** Required reading for anyone doing kernel exploitation research on Windows 11 targets. Yarden Shafir's blog (windows-internals.com) is among the best active sources for Windows kernel research.

---

- **Title:** KASLR Bypass Techniques Survey
- **Author / Organization:** Multiple researchers — Yarden Shafir (primary); j00ru (Bochspwn); Alex Ionescu; various CVE researchers
- **URL:** https://windows-internals.com/ ; https://j00ru.vexillium.org/ ; https://googleprojectzero.blogspot.com/
- **Resource type:** Research blog posts / CVE analysis (distributed)
- **Topic tags:** KASLR, kernel ASLR bypass, information disclosure, kernel pointer leak, NtQuerySystemInformation, GDI bitmap, Win32k, kASLR defeat
- **Difficulty:** Advanced
- **Historical or current:** Current (KASLR bypass remains an active research area)
- **Trust level:** HIGH
- **Why it matters:** KASLR (Kernel Address Space Layout Randomization) is a primary mitigation against kernel exploitation. Bypassing it is required before writing an arbitrary kernel write exploit. A comprehensive survey of how KASLR has been bypassed — from NtQuerySystemInformation leaks to GDI bitmap tricks to memory disclosure CVEs — teaches both the historical mitigations and the ongoing cat-and-mouse.
- **What it teaches:** How KASLR is implemented on Windows; why information leaks defeat it; historical bypass techniques (NtQuerySystemInformation pre-patch, GDI bitmap, desktop heap); modern approaches via uninitialized memory (Bochspwn class); why KASLR bypass is increasingly dependent on a separate memory disclosure bug; kernel pointer encoding (nt!ObHeaderCookie).
- **Best use:** Chronologically study the evolution: pre-KASLR era → NtQuerySystemInformation era → GDI tricks era → post-patch → modern disclosure bugs. Use WinDbg to observe KASLR in action (kd> .formats nt!NtoskrnlBase).
- **Related bug classes / primitives:** Information disclosure, KASLR bypass, kernel pointer leak, NtQuerySystemInformation, uninitialized memory
- **Suggested next resource:** Bochspwn Reloaded for systematic disclosure discovery; specific CVE analyses for individual bypass techniques
- **Notes:** No single resource covers all of this — requires reading across multiple blogs and CVE analyses. The Windows Internals blog has the most concentrated modern treatment.

---

- **Title:** Windows Kernel Pool Internals and Pool Exploitation
- **Author / Organization:** Alex Ionescu (ReactOS / Winsider); Corentin Bayet; Yarden Shafir; Tarjei Mandt
- **URL:** https://windows-internals.com/ ; Tarjei Mandt's DEF CON 19 paper (pool exploitation, 2011)
- **Resource type:** Research papers + blog posts
- **Topic tags:** Kernel pool, lookaside lists, pool chunks, pool overflow, pool spray, heap feng shui, Windows 10+ pool, segment heap in kernel
- **Difficulty:** Advanced
- **Historical or current:** Current (segment heap in kernel changed pool exploitation significantly; ongoing research)
- **Trust level:** HIGH
- **Why it teaches:** Pool exploitation is fundamental to most kernel vulnerability exploitation. Understanding pool chunk layout, lookaside lists, and how Windows allocates/frees kernel memory is required before any pool-based exploit development. The introduction of the segment heap in Windows 10 version 2004 significantly changed pool exploitation methodology.
- **What it teaches:** Pool chunk header structure; pool type taxonomy (Paged, NonPaged, NonPagedNx); Windows 7/8/10 pool differences; pre-segment-heap pool exploitation (corrupt pool chunk headers); post-segment-heap exploitation (new primitives required); pool spray techniques; how to reliably groom pool layout for exploitation.
- **Best use:** Study Tarjei Mandt's 2011 paper for historical context, then study the post-Windows-10-2004 material for the current state. Use WinDbg commands (!pool, !poolused) to observe pool state during HEVD exercises.
- **Related bug classes / primitives:** Pool overflow, use-after-free in pool, pool spray, heap feng shui, kernel heap exploitation
- **Suggested next resource:** "One I/O Ring to Rule Them All" for modern exploitation primitives that replaced legacy pool techniques; HEVD pool exercises
- **Notes:** The shift to segment heap in kernel was a major mitigation. Ensure you study both pre- and post-segment-heap techniques to understand the current exploitation landscape.

---

- **Title:** CVE-2021-1732 — Win32k In-the-Wild Kernel Exploitation Analysis
- **Author / Organization:** Discovered by DBAPP Security (China); analyzed by multiple researchers including Project Zero
- **URL:** https://googleprojectzero.blogspot.com/2021/01/analysis-and-deep-dive-into-cve-2021.html
- **Resource type:** CVE analysis / in-the-wild exploit analysis
- **Topic tags:** Win32k, in-the-wild exploit, type confusion, kernel exploitation, APT, 0-day, SYSTEM escalation
- **Difficulty:** Advanced
- **Historical or current:** Historical (patched February 2021) — analysis value is permanent
- **Trust level:** HIGH — analyzed by Project Zero
- **Why it matters:** CVE-2021-1732 was used in the wild by an advanced threat actor before disclosure. The exploit demonstrates a sophisticated Win32k type confusion bug exploited through careful Win32k object manipulation. Project Zero's analysis is exceptionally detailed and provides a full walkthrough of how the exploit works end-to-end, including the Win32k object that was confused, the primitive achieved, and how it was weaponized.
- **What it teaches:** Real-world Win32k exploitation methodology; how type confusion in kernel objects is exploited; the exploit development workflow for in-the-wild kernel exploits; Win32k USER object structure abuse; how exploits are engineered for reliability.
- **Best use:** Read Project Zero's analysis completely. Use WinDbg on a pre-patch VM to follow along with the described structures. Study the patch to understand what was fixed. Use as a template for your own Win32k vulnerability analysis methodology.
- **Related bug classes / primitives:** Type confusion, Win32k, in-the-wild exploitation, USER objects, SYSTEM escalation
- **Suggested next resource:** Other in-the-wild Win32k CVE analyses; Win32k lockdown research (understanding why Microsoft restricts Win32k from sandboxes)
- **Notes:** One of the best-documented real-world kernel exploits available for study. Required reading for anyone researching Win32k or kernel exploitation in general.

---

- **Title:** Kernel Token Exploitation — Token Stomping and Token Manipulation
- **Author / Organization:** Multiple researchers — Alex Ionescu, Forshaw, various kernel exploitation researchers
- **URL:** https://windows-internals.com/ ; https://googleprojectzero.blogspot.com/
- **Resource type:** Blog posts + research papers (distributed)
- **Topic tags:** Token exploitation, token stomping, token integrity, SeDebugPrivilege, privilege enablement, kernel token structure
- **Difficulty:** Advanced
- **Historical or current:** Current (core technique remains valid)
- **Trust level:** HIGH
- **Why it matters:** Beyond simple token stealing, advanced kernel exploitation uses token manipulation to enable specific privileges, modify integrity levels, or craft tokens with custom capabilities. Understanding the TOKEN structure in depth — its privilege array, group list, integrity level — is required for precision kernel exploit payloads.
- **What it teaches:** TOKEN structure in kernel memory; how privileges are stored and checked; how to enable disabled privileges from kernel context; token integrity level manipulation; token group SID list manipulation; the difference between token stealing and token manipulation; restrictions on token operations.
- **Best use:** Use WinDbg to inspect live TOKEN structures (!token command). Study how AccessChk reports privileges and how those match the TOKEN bitfield. Implement token manipulation in HEVD exploit payloads.
- **Related bug classes / primitives:** Token manipulation, privilege escalation, integrity level bypass, kernel post-exploitation
- **Suggested next resource:** Windows Internals security chapter; NtObjectManager PowerShell module for user-mode token inspection
- **Notes:** Often combined with other techniques — token manipulation is frequently the post-exploitation step after achieving a kernel write primitive.

---

- **Title:** Kernel Module Tampering Protection Research
- **Author / Organization:** Yarden Shafir / Windows Internals Blog
- **URL:** https://windows-internals.com/
- **Resource type:** Research blog posts
- **Topic tags:** Kernel integrity, module tampering, KPP (PatchGuard), DSE (Driver Signature Enforcement), HVCI, kernel mitigations
- **Difficulty:** Advanced
- **Historical or current:** Current
- **Trust level:** HIGH
- **Why it matters:** Understanding kernel integrity mitigations (PatchGuard, DSE, HVCI) is essential for kernel security research. These mitigations prevent attackers from patching kernel code, loading unsigned drivers, and modifying critical kernel structures. Knowing what they protect — and historically how they've been bypassed — defines the current kernel exploitation challenge.
- **What it teaches:** How PatchGuard monitors kernel integrity; Driver Signature Enforcement implementation; HVCI (Hypervisor-Protected Code Integrity) and its implications; what kernel structures are protected vs. unprotected; historical bypass techniques (DSE bypass, PatchGuard bypass); why HVCI raises the exploitation bar significantly.
- **Best use:** Study the mitigation landscape before attempting kernel exploitation research. Understand which mitigations are active on your test VM (secureboot status, HVCI mode). Reference when determining exploit technique feasibility on specific targets.
- **Related bug classes / primitives:** Kernel integrity bypass, DSE bypass, PatchGuard, HVCI circumvention
- **Suggested next resource:** Yarden Shafir's LiveCloudKd research for secure kernel research approaches; Satoshi Tanda's HVCI research
- **Notes:** These mitigations define the modern kernel exploitation landscape. Critical context for all current kernel security work.

---

- **Title:** SecKernel Research with LiveCloudKd
- **Author / Organization:** Yarden Shafir / Windows Internals Blog
- **URL:** https://windows-internals.com/
- **Resource type:** Research blog post + tool
- **Topic tags:** Secure kernel, VTL1, Virtual Trust Level, Hyper-V, LiveCloudKd, kernel debugging under VBS, Virtualization Based Security
- **Difficulty:** Advanced (requires understanding of VBS/Hyper-V)
- **Historical or current:** Current
- **Trust level:** HIGH
- **Why it matters:** With Virtualization-Based Security (VBS) and Virtual Trust Levels (VTL), modern Windows has a "Secure Kernel" running in VTL1 that is isolated from the normal kernel (VTL0). Understanding this architecture is required to fully grasp the current security model. LiveCloudKd enables kernel debugging of VTL0 without disabling integrity protections — valuable for research on production-like configurations.
- **What it teaches:** VBS and VTL architecture; what the Secure Kernel (SecureKernel.exe) protects; how HVCI uses VTL1 to protect kernel code; LiveCloudKd operation (kernel debugging via Hyper-V partition inspection); limitations of kernel exploitation under VBS; the new attack surface VTL transitions create.
- **Best use:** Study after having a solid foundation in normal kernel debugging. Set up a Hyper-V environment to explore VBS and LiveCloudKd. Understand how VTL1 protections change the exploitation model.
- **Related bug classes / primitives:** VTL transitions, VBS bypass, Secure Kernel attack surface, HVCI bypass
- **Suggested next resource:** Microsoft's VBS architecture documentation; Alex Ionescu's Hyper-V and VBS research
- **Notes:** Cutting-edge research topic. Required for understanding the full modern Windows security architecture. Yarden Shafir is among the few researchers who have published detailed analysis of the Secure Kernel.

---

- **Title:** Kernel Driver Attack Surface — IOCTL Handler Research
- **Author / Organization:** Multiple researchers (James Forshaw, Satoshi Tanda, Aleksa Sarić, others)
- **URL:** https://googleprojectzero.blogspot.com/ ; https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools
- **Resource type:** Research methodology + blog posts
- **Topic tags:** IOCTL, kernel driver, attack surface, DeviceIoControl, buffer validation, ProbeForRead, ProbeForWrite, IRQL
- **Difficulty:** Advanced
- **Historical or current:** Current
- **Trust level:** HIGH
- **Why it matters:** Third-party kernel drivers are among the most significant ongoing sources of Windows kernel vulnerabilities. They run at ring 0 with minimal memory safety, handle untrusted input from user mode, and often lack the rigorous development processes applied to the Windows kernel itself. Systematic IOCTL research is one of the most productive avenues for kernel vulnerability discovery.
- **What it teaches:** How IOCTL dispatch works (IRP_MJ_DEVICE_CONTROL); buffer I/O vs direct I/O vs neither; ProbeForRead/ProbeForWrite and TOCTOU attacks; DeviceIoControl from user mode; how to enumerate exposed device objects; techniques for fuzzing IOCTL handlers; signed driver vulnerability research constraints; LSASS plugin and anti-cheat driver vulnerabilities.
- **Best use:** Use sandbox-attacksurface-analysis-tools to enumerate device objects accessible from a given context. Select a driver to research. Reverse engineer its IOCTL dispatch in Ghidra/IDA. Look for missing validation, TOCTOU issues, and arithmetic errors on size parameters. Fuzz with Driver Fuzzer or IOCTL fuzzing tools.
- **Related bug classes / primitives:** IOCTL buffer overflow, IOCTL TOCTOU, ProbeForRead bypass, integer overflow in size parameters, NULL pointer deref via malformed IOCTL
- **Suggested next resource:** HEVD for practice; Microsoft documentation on kernel I/O architecture; specific driver CVE analyses
- **Notes:** Signed (but vulnerable) third-party drivers are a significant current threat — BYOVD (Bring Your Own Vulnerable Driver) is an active attack technique. Understanding this surface is critical.

---

- **Title:** NtUserThunkedMenuItemInfo and Related Win32k Kernel Stability Research
- **Author / Organization:** j00ru (Mateusz Jurczyk) / Google Project Zero
- **URL:** https://bugs.chromium.org/p/project-zero/issues/list?q=win32k (historical Project Zero tracker)
- **Resource type:** CVE / bug reports + crash analysis
- **Topic tags:** Win32k, NtUser syscalls, menu items, kernel crash, DoS, NULL pointer, Win32k attack surface breadth
- **Difficulty:** Advanced
- **Historical or current:** Historical (individual bugs patched; attack surface methodology is evergreen)
- **Trust level:** HIGH
- **Why it matters:** j00ru's systematic enumeration of Win32k kernel stability issues demonstrated the breadth and depth of the Win32k attack surface. Even "simple" DoS bugs reveal how input validation is handled in Win32k and which code paths are reached from user mode via specific syscalls. These bugs are also starting points for deeper investigation (DoS today, exploit tomorrow).
- **What it teaches:** Win32k syscall enumeration methodology; how menu item, region, and GDI operations reach kernel code; how to approach systematic testing of a large kernel API surface; the relationship between stability bugs and exploitable conditions; Win32k's enormous syscall count and diverse object types.
- **Best use:** Study j00ru's Project Zero bug reports for Win32k. Use as examples of how to document kernel crash analysis. Use as starting points for studying the Win32k object types involved.
- **Related bug classes / primitives:** Win32k DoS, null pointer, input validation failures, kernel crash, potential exploit root causes
- **Suggested next resource:** Win32k CVE-2021-1732 analysis for exploitation development; j00ru's other Win32k research
- **Notes:** j00ru filed an enormous number of Win32k bugs over his career at Project Zero. Even resolved bugs are valuable study material. The Win32k attack surface remains underexplored relative to its size.

---
