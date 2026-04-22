# GitHub & Code Resources — Windows Security Research

> Category: Repositories, Tools, PoC Collections
> Trust levels: HIGH / MEDIUM-HIGH / MEDIUM / CAUTION
> Tags used: [MUST-READ] [LAB-WORTHY] [FOUNDATIONAL] [HISTORICAL] [PATCH-DIFF]

---

## Research Tooling (High Trust)

---

- **Title:** sandbox-attacksurface-analysis-tools
- **Author / Organization:** James Forshaw / Google Project Zero
- **URL:** https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools
- **Resource type:** Open-source toolkit / PowerShell module
- **Topic tags:** Windows security, access control, tokens, RPC, named pipes, sandboxes, security descriptors, object manager
- **Difficulty:** Intermediate → Advanced
- **Historical or current:** Current (actively maintained)
- **Trust level:** HIGH
- **Why it matters:** This is the single most important research toolkit for Windows security. James Forshaw (Google Project Zero) built it over years of deep Windows internals work. NtObjectManager alone replaces dozens of ad-hoc scripts and gives you programmatic access to nearly every Windows security-relevant API from PowerShell. It is the reference implementation for how to enumerate and analyze Windows security primitives.
- **What it teaches:** Token structure and manipulation; security descriptor parsing and ACL analysis; named pipe creation, enumeration, and impersonation testing; Windows object manager namespace traversal; RPC endpoint enumeration and fuzzing support; low-level NT object operations (handles, duplicates, inheritance); sandbox escapes through misconfigured objects; AppContainer and Low IL research.
- **Best use:** Set up in a Windows VM. Explore every submodule. Use NtObjectManager in PowerShell ISE or VS Code with the module loaded. Cross-reference with the Forshaw blog series at googleprojectzero.blogspot.com. Ideal for hands-on labs targeting access control issues, token impersonation, and object namespace attacks.
- **Related bug classes / primitives:** Token impersonation, impersonation-level bypass, named pipe squatting, object directory squatting, security descriptor misconfiguration, handle inheritance bugs, sandbox escapes
- **Suggested next resource:** James Forshaw's Project Zero blog — most tools were written to research specific bug classes covered in those posts
- **Notes:** Maintenance is active. Forshaw pushes updates whenever new primitives or techniques emerge. The PowerShell module (NtObjectManager) is published to the PowerShell Gallery. Trust is unconditional: this is production-grade research software from one of the top Windows security researchers in the world. Do not skip the documentation inside the module — the comment-based help is thorough. [MUST-READ] [LAB-WORTHY]

---

- **Title:** symboliclink-testing-tools
- **Author / Organization:** James Forshaw / Google Project Zero
- **URL:** https://github.com/googleprojectzero/symboliclink-testing-tools
- **Resource type:** Open-source toolkit (C++, archived)
- **Topic tags:** Symbolic links, junctions, mount points, hardlinks, OPLOCKs, TOCTOU, file system security
- **Difficulty:** Intermediate
- **Historical or current:** Historical (archived, no new updates — but concepts remain fully relevant)
- **Trust level:** HIGH
- **Why it matters:** This repo defines the tooling vocabulary for Windows symlink-based attacks. Before Forshaw published these tools, symlink/junction/mount-point research was fragmented and poorly understood. Every significant symlink-based LPE in the past decade traces its methodology here. Understanding these primitives is mandatory for bug hunting in any component that touches the filesystem as SYSTEM.
- **What it teaches:** NTFS junction creation and abuse; object manager symbolic link creation; hardlink behavior and abuse; OPLOCK-based TOCTOU race conditions; how the Windows object namespace differs from the NTFS namespace; crossing privilege boundaries via filesystem primitives; CreateFile behavior under races.
- **Best use:** Study the source of each tool to understand what API calls it makes and why. Then use the tools in a VM to reproduce known CVEs that rely on these primitives (e.g., Windows Installer, MSI repair, DACL-overwrite bugs). Pair with Forshaw's "Windows Exploitation Tricks" blog series.
- **Related bug classes / primitives:** TOCTOU, arbitrary file write → LPE, mount point abuse, junction-based redirect, OPLOCK timing, hardlink-based DACL overwrite
- **Suggested next resource:** Forshaw's "Windows Exploitation Tricks: Exploiting Arbitrary File Writes for Local Elevation of Privilege" — https://googleprojectzero.blogspot.com/
- **Notes:** Archived in 2021 but the techniques remain standard. The tools work on modern Windows (some minor compatibility notes apply). Extremely high educational value. [FOUNDATIONAL] [LAB-WORTHY]

---

- **Title:** PrivescCheck
- **Author / Organization:** itm4n
- **URL:** https://github.com/itm4n/PrivescCheck
- **Resource type:** PowerShell enumeration script
- **Topic tags:** Privilege escalation, enumeration, misconfigurations, service binaries, DLL hijacking, scheduled tasks, token privileges
- **Difficulty:** Beginner → Intermediate
- **Historical or current:** Current (actively maintained)
- **Trust level:** HIGH
- **Why it matters:** The most well-structured, educational Windows LPE enumeration tool available. Unlike offensive-first tools, itm4n documents every check with clear explanations of what it looks for and why it matters. Reading the source code is as valuable as running it — each function teaches a real attack vector.
- **What it teaches:** Service binary writable path checks; unquoted service paths; DLL hijacking opportunities; AlwaysInstallElevated; stored credentials in registry/files; token privileges that enable LPE (SeImpersonatePrivilege, SeDebugPrivilege, etc.); UAC configuration weaknesses; scheduled task misconfigurations.
- **Best use:** Run on a test VM first to understand baseline output. Then read every check function in the source to understand the underlying Windows behavior being enumerated. Use as a study guide for "what misconfigurations exist on Windows."
- **Related bug classes / primitives:** Service path misconfigurations, DLL hijacking, token privilege abuse, credential exposure, UAC bypass
- **Suggested next resource:** itm4n's blog at https://itm4n.github.io/ — each major check in PrivescCheck has a corresponding deep-dive post
- **Notes:** Clean code, well-commented, actively updated. itm4n is a trusted and prolific Windows security researcher. The repo is both a tool and a curriculum. [LAB-WORTHY]

---

- **Title:** PrintSpoofer
- **Author / Organization:** itm4n
- **URL:** https://github.com/itm4n/PrintSpoofer
- **Resource type:** PoC exploit (C++)
- **Topic tags:** Named pipe impersonation, SeImpersonatePrivilege, token impersonation, print spooler, SYSTEM escalation
- **Difficulty:** Intermediate
- **Historical or current:** Current (technique remains valid on unpatched systems; educational value is permanent)
- **Trust level:** HIGH
- **Why it matters:** Demonstrates a clean, well-documented approach to exploiting SeImpersonatePrivilege via named pipe impersonation. The accompanying blog post is one of the best explanations of how named pipe impersonation actually works at the API level. Essential for understanding the Potato family of exploits and their evolution.
- **What it teaches:** How SeImpersonatePrivilege enables SYSTEM token capture; how named pipe servers can impersonate connecting clients; the role of the print spooler's back-connect behavior; how this differs from earlier Potato techniques; CreateNamedPipe / ConnectNamedPipe / ImpersonateNamedPipeClient APIs.
- **Best use:** Read the blog post first: https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/. Then read the source code. Reproduce in a lab. Compare with GodPotato/SweetPotato to understand the evolution of the technique.
- **Related bug classes / primitives:** Named pipe impersonation, token impersonation, SeImpersonatePrivilege, print spooler attack surface
- **Suggested next resource:** GodPotato and SweetPotato for the broader Potato lineage; RpcView for understanding the RPC surface print spooler exposes
- **Notes:** Exceptionally clean PoC with educational intent. The blog post is mandatory reading. [LAB-WORTHY]

---

- **Title:** RpcView
- **Author / Organization:** silverf0x and contributors
- **URL:** https://github.com/silverf0x/RpcView
- **Resource type:** GUI research tool (C++)
- **Topic tags:** RPC, DCOM, attack surface, endpoint enumeration, interface research
- **Difficulty:** Intermediate
- **Historical or current:** Current (maintained with community contributions)
- **Trust level:** HIGH
- **Why it matters:** RPC is one of the largest and most under-researched attack surfaces in Windows. Every Windows service exposes RPC interfaces. RpcView lets you enumerate every registered RPC endpoint, view interface UUIDs, inspect procedure counts, and understand what services are reachable from which security contexts. Indispensable for identifying what to attack before you attack it.
- **What it teaches:** Windows RPC architecture; MIDL-generated server stubs; ALPC vs TCP vs named pipe RPC transports; how to identify accessible RPC interfaces from restricted contexts; COM/DCOM relationship to RPC; how sandbox-attacksurface-analysis-tools' RPC client generation builds on this surface area.
- **Best use:** Run on a research VM. Use alongside NtObjectManager's RPC tooling (from sandbox-attacksurface-analysis-tools). When reading Forshaw's RPC research, use RpcView to follow along by inspecting the same interfaces on your own machine.
- **Related bug classes / primitives:** RPC authentication bypass, ALPC-based escalation, COM/DCOM interface abuse, impersonation via RPC
- **Suggested next resource:** Forshaw's RPC research on Project Zero blog; NDR (Network Data Representation) protocol documentation
- **Notes:** Somewhat niche but essential for serious Windows research. Trust is high — legitimate research tool used by major researchers. Binary releases available for convenience.

---

- **Title:** Sysinternals Suite
- **Author / Organization:** Mark Russinovich / Microsoft
- **URL:** https://learn.microsoft.com/en-us/sysinternals/
- **Resource type:** Official toolset (Process Monitor, Process Explorer, Autoruns, AccessChk, Handle, PsExec, Sigcheck, Sysmon, LiveKD, etc.)
- **Topic tags:** System internals, debugging, observability, access control, handles, tokens, process analysis, file system monitoring
- **Difficulty:** Beginner → Advanced (tools vary widely)
- **Historical or current:** Current (Microsoft-maintained since acquisition)
- **Trust level:** HIGH
- **Why it matters:** The original, authoritative toolset for understanding what Windows is doing at the system level. Every Windows security researcher uses these tools daily. AccessChk alone has identified thousands of privilege escalation vectors. ProcMon is essential for any dynamic analysis of file/registry/process/network activity.
- **What it teaches:** How to observe system activity at the API call level (ProcMon); how to analyze process tokens, handles, and threads (Process Explorer); how to enumerate object permissions (AccessChk); how to understand startup and persistence (Autoruns); how to filter and analyze Sysmon telemetry for research and detection.
- **Best use:** Learn AccessChk deeply — it is the fastest way to find misconfigured ACLs on services, registry keys, and files. Use ProcMon with filters to trace what happens during installations, repairs, or service operations. Combine with sandbox-attacksurface-analysis-tools for comprehensive analysis.
- **Related bug classes / primitives:** Service misconfiguration, ACL weakness, handle leaks, token visibility, persistence mechanisms
- **Suggested next resource:** "Windows Internals" books for understanding what the tools are showing you at the kernel level
- **Notes:** Unconditional trust. These are Microsoft-signed, official tools. Required foundational knowledge for all Windows security work. [FOUNDATIONAL]

---

## LPE Exploit Collections

---

- **Title:** InstallerFileTakeOver
- **Author / Organization:** Abdelhamid Naceri (klinix5)
- **URL:** https://github.com/klinix5/InstallerFileTakeOver
- **Resource type:** PoC exploit (C++)
- **Topic tags:** Windows Installer, MSI, arbitrary file write, LPE, rollback, tempdir races
- **Difficulty:** Advanced
- **Historical or current:** Historical (patched) — educational value is high
- **Trust level:** MEDIUM-HIGH
- **Why it matters:** Demonstrates a sophisticated class of Windows Installer vulnerabilities where the MSI engine's rollback/repair mechanisms can be abused to achieve arbitrary file write as SYSTEM. Naceri discovered multiple variants of this class, making it an excellent case study for variant hunting methodology.
- **What it teaches:** Windows Installer internals (rollback files, temp file handling); how SYSTEM-level write operations during installation can be redirected; junction/symlink abuse during installer operations; why this class of bug kept recurring despite patches; reading patch diffs to find incomplete fixes.
- **Best use:** Study alongside Naceri's blog posts and disclosures. Use as a patch-diff exercise: compare the patched vs unpatched DLL to understand what was fixed. Use as a template for hunting similar bugs in other installer engines (MSIX, AppX, Chocolatey, etc.).
- **Related bug classes / primitives:** Arbitrary file write → LPE, MSI rollback abuse, junction-based redirect, TOCTOU in installer temp files
- **Suggested next resource:** "Windows Exploitation Tricks: Exploiting Arbitrary File Writes" (Forshaw); Naceri's other disclosures for the variant pattern
- **Notes:** Naceri published multiple variants after incomplete patches — ideal case study for variant hunting methodology. [LAB-WORTHY] [PATCH-DIFF]

---

- **Title:** GodPotato
- **Author / Organization:** BeichenDream
- **URL:** https://github.com/BeichenDream/GodPotato
- **Resource type:** PoC exploit (C#)
- **Topic tags:** Token impersonation, SeImpersonatePrivilege, DCOM, SYSTEM escalation, Potato family
- **Difficulty:** Intermediate
- **Historical or current:** Current
- **Trust level:** MEDIUM
- **Why it matters:** Represents the latest generation of Potato-style exploits, claiming to work on Windows Server 2012–2022. Useful for understanding how the technique evolved to bypass mitigations added against earlier Potatoes. Good for understanding what Windows Server environments still expose via SeImpersonatePrivilege.
- **What it teaches:** Evolution of token impersonation techniques; how DCOM activation can be coerced to create impersonatable tokens; why SeImpersonatePrivilege is dangerous in service accounts; differences from PrintSpoofer and SweetPotato.
- **Best use:** Educational/reproduction in a controlled lab. Understand the underlying mechanism rather than using it as a tool. Compare source with PrintSpoofer and SweetPotato to understand the lineage.
- **Related bug classes / primitives:** Token impersonation, SeImpersonatePrivilege, DCOM coerce, SYSTEM token capture
- **Suggested next resource:** PrintSpoofer (itm4n) for a cleaner, more documented implementation; SweetPotato for technique comparison
- **Notes:** Use for educational reproduction only. Less thoroughly documented than itm4n's work. Medium trust — functional but not extensively peer-reviewed at the implementation level. Treat as educational/reproduction PoC.

---

- **Title:** SweetPotato
- **Author / Organization:** CCob
- **URL:** https://github.com/CCob/SweetPotato
- **Resource type:** PoC exploit (C#)
- **Topic tags:** Token impersonation, Potato family, DCOM, named pipe, SeImpersonatePrivilege, multiple technique aggregation
- **Difficulty:** Intermediate
- **Historical or current:** Current (maintained)
- **Trust level:** MEDIUM
- **Why it matters:** Aggregates multiple Potato techniques (RoguePotato, PrintSpoofer, EfsPotato) into a single framework. Useful for understanding how different activation coercion vectors (DCOM, named pipes, EFS) all converge on the same impersonation primitive. Good reference architecture for how to build a multi-technique exploitation framework.
- **What it teaches:** Multiple token impersonation vectors and their differences; which techniques apply under which conditions; why technique diversity matters when defenders block specific named pipe or DCOM behaviors; C# interop with Win32 APIs for token manipulation.
- **Best use:** Use in a lab to compare which vectors succeed under different service account configurations. Study the source to understand how each technique is implemented under the hood. Do not use offensively outside authorized testing.
- **Related bug classes / primitives:** Token impersonation, named pipe squatting, DCOM coerce, EFS coerce, SeImpersonatePrivilege
- **Suggested next resource:** itm4n's blog for deeper understanding of individual techniques; RpcView for understanding the DCOM surface being abused
- **Notes:** Combines techniques — good for breadth understanding. Trust is medium; code quality varies by technique module. Educational/reproduction use only.

---

- **Title:** SharpUp
- **Author / Organization:** GhostPack / Will Schroeder (harmj0y)
- **URL:** https://github.com/GhostPack/SharpUp
- **Resource type:** C# enumeration tool
- **Topic tags:** Privilege escalation, enumeration, misconfigurations, service paths, AlwaysInstallElevated, registry
- **Difficulty:** Beginner → Intermediate
- **Historical or current:** Current
- **Trust level:** HIGH
- **Why it matters:** GhostPack is a trusted research collective. SharpUp is the C# equivalent of PowerUp — same checks but as a compiled .NET assembly, useful when PowerShell is restricted. More importantly, the source code serves as a clean reference implementation for each misconfiguration class it checks.
- **What it teaches:** C# implementation of common LPE checks; how to enumerate service paths programmatically; registry key permission checks; token privilege enumeration via .NET; how to detect AlwaysInstallElevated.
- **Best use:** Read source code as a learning exercise. Compare with PrivescCheck (PowerShell) to understand the same concepts in two different implementations. Useful for understanding what detection signatures look for in post-exploitation tooling.
- **Related bug classes / primitives:** Service path misconfigurations, registry ACL weaknesses, token privilege abuse, AlwaysInstallElevated
- **Suggested next resource:** PrivescCheck (itm4n) for more comprehensive coverage; GhostPack's other tools (Rubeus, Seatbelt) for the broader picture
- **Notes:** GhostPack tools are among the most trusted in offensive security research. Clean, well-structured C# code. [HIGH TRUST]

---

- **Title:** PowerUp (part of PowerSploit)
- **Author / Organization:** PowerShellMafia / Matt Graeber, Will Schroeder
- **URL:** https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc
- **Resource type:** PowerShell script
- **Topic tags:** Privilege escalation, PowerShell, service misconfigurations, token privileges, AlwaysInstallElevated, legacy
- **Difficulty:** Beginner → Intermediate
- **Historical or current:** Historical (PowerSploit is archived; no longer maintained)
- **Trust level:** MEDIUM
- **Why it matters:** PowerUp was the foundational Windows LPE enumeration script that defined the standard checklist for misconfigurations. Even though it is archived, nearly every subsequent enumeration tool (SharpUp, PrivescCheck) is based on or compared against its methodology. Understanding what it checks is foundational knowledge.
- **What it teaches:** The canonical list of Windows LPE misconfigurations; how PowerShell can enumerate Windows security settings; service path, registry, and file permission checks; historical context for how LPE research evolved.
- **Best use:** Read as a historical reference to understand where modern tools come from. Do not use in active engagements — prefer PrivescCheck or SharpUp for maintained alternatives. Useful for understanding detection engineering for these technique classes.
- **Related bug classes / primitives:** Service path misconfigurations, registry ACL weaknesses, AlwaysInstallElevated, token privilege abuse
- **Suggested next resource:** PrivescCheck for a modern, maintained replacement with better documentation
- **Notes:** Archived. Use for historical context and concept understanding only. The PowerSploit project as a whole is no longer maintained. Many checks are still conceptually valid but the implementation may miss newer Windows behaviors. [HISTORICAL]

---

- **Title:** Seatbelt
- **Author / Organization:** GhostPack / Will Schroeder
- **URL:** https://github.com/GhostPack/Seatbelt
- **Resource type:** C# enumeration tool
- **Topic tags:** System enumeration, post-exploitation, tokens, credentials, Chrome/browser data, system configuration, audit
- **Difficulty:** Intermediate
- **Historical or current:** Current (actively maintained)
- **Trust level:** HIGH
- **Why it matters:** Seatbelt is a comprehensive system enumeration tool that goes far beyond LPE checks. It collects a broad picture of the system state useful for post-exploitation research: token privileges, LSA settings, AppLocker rules, WSUS configuration, credential manager data, and dozens more. Essential for understanding what information is accessible from a given privilege level.
- **What it teaches:** What data is accessible to different token levels on Windows; how AppLocker and WDAC configuration can be detected; LSA protection settings; how to enumerate privilege escalation opportunities across many dimensions simultaneously; C# system enumeration patterns.
- **Best use:** Run in a lab VM and study the output categories. Use to understand what a post-exploitation framework collects and why. Cross-reference individual checks with Windows documentation to understand what API calls gather each piece of data.
- **Related bug classes / primitives:** Post-exploitation, credential access, token privilege enumeration, security configuration weaknesses
- **Suggested next resource:** GhostPack's other tools; MITRE ATT&CK technique catalog for mapping enumerated data to TTP categories
- **Notes:** Extremely comprehensive. GhostPack quality — clean, well-structured code. High trust. [LAB-WORTHY]

---

## Kernel / Driver Research

---

- **Title:** HEVD — HackSys Extreme Vulnerable Driver
- **Author / Organization:** HackSysTeam (Ashfaq Ansari et al.)
- **URL:** https://github.com/hacksysteam/HackSysExtremeVulnerableDriver
- **Resource type:** Intentionally vulnerable kernel driver + exploit lab
- **Topic tags:** Kernel exploitation, IOCTL, stack overflow, heap overflow, use-after-free, pool corruption, race conditions, null pointer dereference, type confusion, Windows driver security
- **Difficulty:** Advanced (kernel exploitation fundamentals required)
- **Historical or current:** Current (maintained, includes Windows 10/11 variants)
- **Trust level:** HIGH — intentionally vulnerable driver for controlled lab use
- **Why it matters:** HEVD is the de facto standard kernel exploitation training environment. Every major class of Windows kernel vulnerability — stack overflow, integer overflow, heap overflow, UAF, null pointer, type confusion, race conditions — is represented with a working vulnerable implementation. The accompanying exploit examples demonstrate real techniques (token stealing, shellcode, ROP). No other resource provides this breadth in a single controlled package.
- **What it teaches:** Windows kernel debugging setup with WinDbg; IOCTL dispatch mechanism and kernel driver architecture; each major kernel vulnerability class with a concrete implementation; kernel shellcode (token stealing, process privilege escalation); ROP chain construction for kernel DEP bypass; pool exploitation techniques; working with kernel addresses; SMEP bypass techniques.
- **Best use:** Set up a two-machine kernel debugging environment (VM as target, host with WinDbg connected via KDNET). Install HEVD on the VM. Work through each vulnerability class systematically. Write your own exploits before looking at the examples. Use TTD (Time Travel Debugging) to record exploit attempts and step through them.
- **Related bug classes / primitives:** Stack overflow, heap overflow, use-after-free, pool corruption, null pointer dereference, type confusion, integer overflow, race conditions — all in kernel context
- **Suggested next resource:** "Windows Kernel Programming" (Pavel Yosifovich); Yarden Shafir's kernel research posts; pool exploitation research by Alex Ionescu
- **Notes:** The gold standard for kernel exploitation training. INSTALL THIS. Work through it methodically. The repo includes exploits for multiple Windows versions showing how techniques evolve across OS updates. Extremely high educational value. [MUST-READ for kernel exploitation] [LAB-WORTHY]

---

- **Title:** awesome_windows_logical_bugs
- **Author / Organization:** sailay1996
- **URL:** https://github.com/sailay1996/awesome_windows_logical_bugs
- **Resource type:** Curated resource list / PoC collection
- **Topic tags:** Logical bugs, LPE, Windows security, curated list, PoC links
- **Difficulty:** Intermediate
- **Historical or current:** Partially current (last updates vary)
- **Trust level:** MEDIUM
- **Why it matters:** Aggregates links to LPE research, PoCs, and writeups that are otherwise scattered across blogs, GitHub, and conference proceedings. Useful as a starting point for discovering researchers and bug classes. The "logical bugs" framing focuses on design/logic flaws rather than memory corruption — an important and often underappreciated category.
- **What it teaches:** The breadth of logical LPE bug classes; which researchers to follow; how to find PoCs for known vulnerabilities; what Windows components have historically been productive research targets.
- **Best use:** Use as a directory to find primary sources. Do not treat linked PoCs as tools; treat them as pointers to research to study. Verify each linked resource independently.
- **Related bug classes / primitives:** Logical privilege escalation, UAC bypass, design flaws, access control weaknesses
- **Suggested next resource:** Primary sources linked in the collection — especially Forshaw, Naceri, and Yarden Shafir references
- **Notes:** Curation quality is reasonable but uneven. Some links may be stale. Medium trust — valuable as a directory but verify before relying on any specific resource. Not a substitute for primary sources.

---

- **Title:** Windows-Kernel-Exploits
- **Author / Organization:** SecWiki
- **URL:** https://github.com/SecWiki/windows-kernel-exploits
- **Resource type:** Historical exploit collection (binaries + source where available)
- **Topic tags:** Kernel exploits, historical CVEs, MS-numbered vulnerabilities, LPE
- **Difficulty:** Intermediate
- **Historical or current:** Historical (no new content; collection ends around 2021)
- **Trust level:** CAUTION
- **Why it matters:** Provides a consolidated archive of historical Windows kernel exploits from MS10 through MS20 era. Useful for studying how kernel exploitation evolved and for setting up historical CVE reproduction labs. Understanding these exploits is valuable context for current research.
- **What it teaches:** Historical Windows kernel vulnerability landscape; how specific CVEs were exploited; evolution of kernel exploitation techniques; what kernel patches addressed (useful for patch diff exercises on historical vulnerabilities).
- **Best use:** Historical study and CVE reproduction only. Identify specific CVEs of interest, study the associated patch from Microsoft, then compare to the exploit to understand what was fixed. Do NOT use unmodified binaries from this repo in any context — verify all code independently.
- **Related bug classes / primitives:** Historical kernel vulnerabilities, Win32k, kernel object manager, token manipulation
- **Suggested next resource:** HEVD for current kernel exploitation practice; official Microsoft security advisories (MSRC) for original disclosure details
- **Notes:** CAUTION — many binaries are pre-compiled and their provenance cannot be verified. Several exploits are outdated and will not work on modern Windows. Use only in isolated research VMs. Verify source code before trusting any binary. Historical collection only. Do not treat as a current exploitation toolkit.

---

- **Title:** Windows-Local-Privilege-Escalation-Cookbook
- **Author / Organization:** nickvourd
- **URL:** https://github.com/nickvourd/Windows-Local-Privilege-Escalation-Cookbook
- **Resource type:** Educational lab cookbook / reference guide
- **Topic tags:** LPE, lab guide, service misconfigurations, DLL hijacking, token privileges, UAC, scheduled tasks, registry
- **Difficulty:** Beginner → Intermediate
- **Historical or current:** Current
- **Trust level:** HIGH
- **Why it matters:** Provides structured, reproducible lab environments for each major LPE technique. The "cookbook" format means each entry includes a lab setup, reproduction steps, detection guidance, and remediation notes — making it valuable for both offensive and defensive learning.
- **What it teaches:** Hands-on reproduction of each LPE technique in a controlled environment; how to configure a vulnerable lab VM; what defensive controls prevent each technique; systematic coverage of the LPE landscape.
- **Best use:** Use as a structured curriculum. Set up each lab environment sequentially. After reproducing a technique, read the corresponding detection/prevention section to understand the defensive perspective.
- **Related bug classes / primitives:** Service path misconfigurations, DLL hijacking, token privilege abuse, UAC bypass, registry weaknesses, scheduled tasks
- **Suggested next resource:** PrivescCheck to automate the discovery of the same misconfigurations the cookbook teaches manually
- **Notes:** Well-organized and actively maintained. Good for structured self-study. High educational value for both offense and defense. [LAB-WORTHY]

---

- **Title:** WinPwn
- **Author / Organization:** S3cur3Th1sSh1t
- **URL:** https://github.com/S3cur3Th1sSh1t/WinPwn
- **Resource type:** Automated PowerShell exploitation script
- **Topic tags:** Post-exploitation, automation, LPE, credential harvesting, AMSI bypass, PowerShell
- **Difficulty:** Intermediate
- **Historical or current:** Current (maintained)
- **Trust level:** MEDIUM
- **Why it matters:** Demonstrates how LPE and post-exploitation techniques can be chained and automated. Useful for understanding the offensive automation landscape and for studying how techniques are combined in practice. The source code shows how individual primitives are orchestrated into a workflow.
- **What it teaches:** PowerShell-based exploitation automation; AMSI bypass techniques; how individual LPE checks are combined; what a realistic post-exploitation workflow looks like.
- **Best use:** Educational review of source code only. Study which techniques are chained and in what order. Use in isolated lab environments. Do not use offensively outside authorized testing.
- **Related bug classes / primitives:** Post-exploitation, credential harvesting, LPE automation, AMSI bypass
- **Suggested next resource:** Individual technique sources (itm4n, GhostPack) for deeper understanding of specific techniques chained here
- **Notes:** Medium trust. Automated offensive tool — treat with appropriate caution. Educational value is in understanding the automation and chaining logic, not the tool itself.

---

- **Title:** impacket
- **Author / Organization:** Fortra (formerly SecureAuth / Core Security)
- **URL:** https://github.com/fortra/impacket
- **Resource type:** Python library / protocol implementation
- **Topic tags:** SMB, RPC, DCOM, Kerberos, NTLM, LDAP, DCE/RPC, Windows network protocols, authentication, relay attacks
- **Difficulty:** Intermediate → Advanced
- **Historical or current:** Current (very actively maintained)
- **Trust level:** HIGH
- **Why it matters:** Impacket is the foundational Python library for Windows network protocol research. SMB, Kerberos, NTLM, LDAP, DCE/RPC — all implemented in pure Python with source you can read, modify, and learn from. Every major Windows network protocol attack in the past decade has an impacket-based PoC. Understanding the impacket codebase means understanding how these protocols work at the wire level.
- **What it teaches:** SMB protocol internals (packet structure, authentication handshakes); Kerberos ticket handling (AS-REQ, TGS-REQ, Pass-the-Ticket, Pass-the-Hash); NTLM authentication and relay attacks; DCE/RPC protocol structure; LDAP interaction with Active Directory; how to implement protocol clients and servers in Python for research purposes.
- **Best use:** Set up a Windows lab with an Active Directory environment. Use impacket scripts (secretsdump, psexec, getTGT, etc.) to understand what each does, then read the corresponding source code. Modify scripts to test edge cases. Build custom protocol interactions for specific research questions.
- **Related bug classes / primitives:** NTLM relay, Kerberoasting, AS-REP roasting, Pass-the-Hash, Pass-the-Ticket, DCE/RPC vulnerabilities, SMB bugs
- **Suggested next resource:** Responder (for relay setup); BloodHound (for AD attack path analysis); official Kerberos RFC and MS-KILE for protocol specification
- **Notes:** Among the most important tools in Windows network security research. Fortra maintains it actively. The codebase is large but well-organized. High trust — industry standard, used by virtually every Windows security researcher. [LAB-WORTHY]

---

## Analysis and Reverse Engineering Tools

---

- **Title:** System Informer (Process Hacker 3)
- **Author / Organization:** wj32 (original), SystemInformer community, now with Winsider Seminars & Solutions
- **URL:** https://github.com/winsiderss/systeminformer
- **Resource type:** GUI system analysis tool (C)
- **Topic tags:** Process analysis, token viewer, handle viewer, kernel memory, driver enumeration, ETW, thread analysis, security descriptor viewer
- **Difficulty:** Intermediate
- **Historical or current:** Current (replaces Process Hacker)
- **Trust level:** HIGH
- **Why it matters:** System Informer provides deeper visibility into Windows internals than any other GUI tool, including Sysinternals. It shows kernel object handles, token structure, thread impersonation levels, memory protection details, and driver information in a way that makes Windows security research significantly more efficient. The source code is also a masterclass in undocumented Windows API usage.
- **What it teaches:** Real-time token and privilege inspection; handle leak detection; impersonation level visualization; kernel object relationships; memory region analysis and permissions; driver and service enumeration; ETW provider configuration.
- **Best use:** Keep running during all lab work. Use the handle view to understand resource ownership during exploit development. Use the token view to verify impersonation operations. Study the source code to understand how to query undocumented kernel structures from user mode.
- **Related bug classes / primitives:** Token inspection, handle analysis, impersonation verification, kernel structure exploration
- **Suggested next resource:** WinDbg for kernel-level visibility that goes beyond what System Informer provides
- **Notes:** Replaces the unmaintained Process Hacker. The source code itself is educational — it shows how to use NT native APIs properly. High trust. [LAB-WORTHY]

---

- **Title:** pe-sieve
- **Author / Organization:** hasherezade
- **URL:** https://github.com/hasherezade/pe-sieve
- **Resource type:** PE analysis and memory scanning tool (C++)
- **Topic tags:** PE analysis, process hollowing detection, memory scanning, malware analysis, shellcode detection, PE anomaly detection
- **Difficulty:** Intermediate → Advanced
- **Historical or current:** Current (actively maintained)
- **Trust level:** HIGH
- **Why it matters:** hasherezade is one of the most respected malware analysts in the field. pe-sieve can detect process hollowing, shellcode injection, PE implants, and other in-memory anomalies by comparing in-memory PE images against their on-disk counterparts. For security researchers, it is both a detection tool and a deep lesson in PE file format internals.
- **What it teaches:** PE file structure (section headers, IAT, relocations); how process hollowing and reflective DLL injection work and what artifacts they leave; in-memory PE scanning techniques; how to detect common code injection methods programmatically; PE anomaly detection heuristics.
- **Best use:** Use to analyze suspicious processes in malware research VMs. Also use as a learning tool: inject a known payload via shellcode injection, then use pe-sieve to observe the detection. Study the source to understand how each anomaly type is detected.
- **Related bug classes / primitives:** Code injection, process hollowing, reflective DLL injection, shellcode, PE manipulation, defense evasion analysis
- **Suggested next resource:** hasherezade's libpeconv (underlying PE library); hollows_hunter (companion tool); malconv for static PE analysis
- **Notes:** hasherezade maintains an ecosystem of high-quality, well-documented security tools. This is her flagship project. High trust. Excellent for malware research and defense engineering. [LAB-WORTHY]

---
