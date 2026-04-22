# Conference Talks, Papers & Slides — Windows Security

> High-value conference presentations, academic papers, and research slide decks
> covering Windows security internals, privilege escalation, kernel exploitation,
> and related topics.
> Organized by topic cluster with quality tags.

---

## Tags

| Tag | Meaning |
|-----|---------|
| `[MUST-READ]` | Essential — do not skip this |
| `[FOUNDATIONAL]` | Background knowledge prerequisite |
| `[HISTORICAL]` | Older but architecturally relevant |
| `[CURRENT]` | Recent (2022+), addresses modern mitigations |
| `[KERNEL]` | Kernel-level exploitation |
| `[LPE]` | Local privilege escalation |
| `[AUTH]` | Authentication / Kerberos / NTLM |

---

## Cluster 1: Object Manager, Symbolic Links & File Operations

---

### "Abusing Windows Symbolic Links"
- **Presenter:** James Forshaw
- **Conference:** DEF CON 23 (2015)
- **URL:** https://media.defcon.org/DEF%20CON%2023/DEF%20CON%2023%20presentations/DEFCON-23-James-Forshaw-Abusing-Windows-Symbolic-Links.pdf
- **Why essential:**
  This is *the* foundational talk on Windows symbolic link abuse. Forshaw provides a
  comprehensive taxonomy of every symbolic link type in Windows (NTFS reparse points,
  object manager symlinks, junction points, mount points, hardlinks) and explains
  when each can be used to redirect privileged operations to attacker-controlled paths.
  Every subsequent file operation LPE builds on the primitives introduced here.
  The associated tools (CreateSymlink, SetOpLock) are still used today.
- **Key concepts:** Object namespace symlinks, NTFS junction, mount point, hard link,
  reparse points, oplocks for races, SetOpLock primitive
- **Follow-up:** Forshaw's blog posts on symbolic link planting (2019+), NtObjectManager toolkit
- **Tags:** `[MUST-READ]` `[FOUNDATIONAL]` `[LPE]`

---

### "Symbolic Link Following Bugs in Windows"
- **Presenter:** James Forshaw
- **Conference / Source:** Project Zero blog (2015–ongoing), OffensiveCon
- **URL:** https://www.tiraniddo.dev/ (search "symbolic link")
- **Why essential:**
  Follow-up research expanding the DEF CON 23 talk into a comprehensive exploitation
  framework. Introduces the concept of "symlink planting" as a systematic attack
  class and documents the NtObjectManager toolkit for identifying vulnerable paths.
- **Tags:** `[MUST-READ]` `[LPE]`

---

## Cluster 2: Token Security & Impersonation

---

### "Attacking Windows Tokens"
- **Presenter:** James Forshaw
- **Conference / Source:** OffensiveCon 2019 + tiraniddo.dev blog series
- **URL:** https://www.tiraniddo.dev/ (tag: tokens)
- **Why essential:**
  Deep technical analysis of the Windows token security model — token types
  (primary vs. impersonation), impersonation levels, token handle duplication,
  privilege manipulation, and how attackers exploit the token system for LPE.
  Covers both the theory (NT security model) and practical exploitation paths.
- **Key concepts:** Impersonation levels (Identify/Impersonate/Delegate/Anonymous),
  `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`, token handle inheritance,
  token universe (primary, impersonation, restricted tokens)
- **Tags:** `[MUST-READ]` `[FOUNDATIONAL]` `[LPE]`

---

### "Getting Windows Tokens the Hard Way"
- **Presenter:** James Forshaw
- **Conference / Source:** BlueHat / NDC Security / tiraniddo.dev
- **URL:** https://www.tiraniddo.dev/
- **Why essential:**
  Explores non-obvious ways to obtain privileged tokens on Windows — beyond the
  classic ImpersonateNamedPipeClient path. Covers OpenProcess token handles,
  secondary logon, token privileges manipulation, and token universe edge cases.
- **Tags:** `[MUST-READ]` `[LPE]`

---

### "From Service Account to SYSTEM — Named Pipe Impersonation"
- **Presenter:** Clément Labro (itm4n)
- **Conference / Source:** itm4n.github.io blog series (2020)
- **URL:** https://itm4n.github.io/printspoofer-abusing-impersonation-privileges/
- **Why essential:**
  The definitive explanation of PrintSpoofer and the named pipe impersonation
  technique class. Explains not just the PrintSpoofer exploit but the general
  methodology for inducing privileged services to connect to attacker-controlled
  named pipes, with analysis of UNC path parsing in the Spooler service.
- **Tags:** `[MUST-READ]` `[LPE]`

---

## Cluster 3: Windows Sandbox & Attack Surface

---

### "The Windows Sandbox Attack Surface"
- **Presenter:** James Forshaw
- **Conference:** Black Hat USA 2012
- **URL:** https://www.blackhat.com/html/bh-us-12/bh-us-12-briefings.html
- **Why essential:**
  One of the most comprehensive analyses of the Chrome sandbox (and Windows sandbox
  model generally) ever published. Maps all the kernel and user-mode surfaces available
  to sandboxed processes and systematically identifies which can be exploited for
  sandbox escape. Foundational for browser security and any Windows sandbox research.
- **Follow-up:** Forshaw's ongoing Project Zero sandbox escape research
- **Tags:** `[FOUNDATIONAL]` `[HISTORICAL]`

---

## Cluster 4: Kernel Memory Disclosure & Fuzzing

---

### "Bochspwn Reloaded: Detecting Kernel Memory Disclosure with x86 Emulation"
- **Presenter:** Mateusz Jurczyk (j00ru)
- **Conference:** Black Hat USA 2017
- **URL:** https://j00ru.vexillium.org/talks/
- **Paper:** https://j00ru.vexillium.org/papers/2017/bochspwn_reloaded.pdf
- **Why essential:**
  Describes a hypervisor-level taint tracking system that discovered hundreds of
  previously unknown kernel-to-user memory disclosure vulnerabilities in Windows.
  By running Windows inside a modified QEMU/Bochs and tracking which kernel memory
  was copied to user space without being fully initialized, Jurczyk found kernel
  info disclosure bugs at scale that manual analysis would never find.
  Essential reading for anyone interested in Windows kernel fuzzing methodology.
- **Key concepts:** Taint tracking, kernel pool metadata disclosure, `ProbeForRead/Write`,
  uninitialized struct padding leaks in syscall output buffers
- **Follow-up:** Bochspwn original (2012), j00ru's win32k research
- **Tags:** `[MUST-READ]` `[KERNEL]` `[FOUNDATIONAL]`

---

## Cluster 5: I/O Ring & Modern Kernel Exploitation

---

### "One I/O Ring to Rule Them All: A Heap-Based Exploit Primitive"
- **Presenter:** Yarden Shafir
- **Conference:** Black Hat USA 2022 / various
- **URL:** https://windows-internals.com/one-i-o-ring-to-rule-them-all/
- **Why essential:**
  Identifies a novel kernel exploitation primitive in the Windows I/O Ring API
  (introduced in Windows 11) that provides an arbitrary kernel read/write capability
  without requiring a traditional memory corruption bug. The I/O Ring structure,
  when corrupted via a heap out-of-bounds or UAF bug, allows attackers to read/write
  arbitrary kernel addresses. This rapidly became a standard tool in kernel exploit chains.
- **Key concepts:** I/O Ring API, `IORING_BUFFER_INFO`, kernel heap primitive, arbitrary R/W
- **Tags:** `[MUST-READ]` `[KERNEL]` `[CURRENT]`

---

### "KASLR: Analysis and Bypass"
- **Presenter:** Yarden Shafir
- **Conference / Source:** windows-internals.com (2021)
- **URL:** https://windows-internals.com/kaslr-analysis-and-bypass/
- **Why essential:**
  Comprehensive analysis of Windows KASLR implementation — what it randomizes,
  what it doesn't, and multiple bypass techniques. Required reading before attempting
  kernel exploitation on modern Windows systems.
- **Tags:** `[MUST-READ]` `[KERNEL]` `[CURRENT]`

---

## Cluster 6: Windows Kernel Exploitation Internals

---

### "Windows Kernel Exploitation" — Tarjei Mandt series
- **Presenter:** Tarjei Mandt (Azimuth Security)
- **Conference:** SyScan / Hack in the Box (2011–2013)
- **URL:** https://mista.nu/research/
- **Why essential:**
  Classic series on Windows kernel pool exploitation — pool internals, overflow exploitation,
  ListEntry overwrite → code execution. Pre-modern-mitigations but the fundamental
  techniques remain architecturally instructive for understanding what mitigations protect against.
- **Key concepts:** Windows kernel pool (lookaside, non-paged, paged), freelist corruption,
  pool header overwrite, safe unlinking
- **Tags:** `[FOUNDATIONAL]` `[HISTORICAL]` `[KERNEL]`

---

### "SMBGhost (CVE-2020-0796) — Full RCE Exploit Chain"
- **Presenter:** Valentina Palmiotti (chompie1337)
- **Conference / Source:** Published full exploit (2021)
- **URL:** https://github.com/chompie1337/SMBGhost_RCE_PoC
- **Why essential:**
  One of the most detailed public Windows kernel exploit chains released in recent years.
  The write-up and code demonstrate pool grooming, heap spray, and reliable kernel
  arbitrary write exploitation on Windows 10. Essential for understanding modern
  kernel exploit engineering.
- **Tags:** `[MUST-READ]` `[KERNEL]`

---

## Cluster 7: Windows Authentication

---

### "Kerberos Attacks Deep Dive" — Will Schroeder & Lee Christensen
- **Presenter:** Will Schroeder (@harmj0y), Lee Christensen (@tifkin_)
- **Conference:** DerbyCon / BSides (various years)
- **URL:** https://blog.harmj0y.net/ / https://www.slideshare.net/harmj0y
- **Why essential:**
  The most comprehensive practitioner-facing coverage of Kerberos attack techniques —
  Kerberoasting, AS-REP Roasting, Silver Ticket, Golden Ticket, Unconstrained Delegation,
  S4U abuse. These talks form the conceptual backbone of modern AD pentesting.
- **Tags:** `[MUST-READ]` `[AUTH]` `[FOUNDATIONAL]`

---

### "The NTLM Relay Attack Compendium"
- **Presenter:** Multiple — Laurent Gaffie (@PythonResponder), Dirk-jan Mollema (@dirkjanm)
- **Conference / Source:** DEF CON, blog posts, Impacket documentation
- **URL:** https://blog.skullsecurity.org/ / https://dirkjanm.io/
- **Why essential:**
  NTLM relay remains one of the most reliable lateral movement / privilege escalation
  paths in Windows environments. These resources cover relay mechanics, SMB/HTTP/LDAP
  relay targets, NTLM downgrade, and defenses.
- **Tags:** `[MUST-READ]` `[AUTH]`

---

## Cluster 8: COM & RPC Internals

---

### "COM Internals and Security"
- **Presenter:** Alex Ionescu
- **Conference:** REcon 2014
- **URL:** https://recon.cx/2014/schedule/events/12.html
- **Why essential:**
  Deep technical coverage of COM activation, marshaling, CLSID resolution, DCOM
  security model, and how COM's complex security surface has been exploited for
  privilege escalation. Foundation for understanding any COM-based LPE.
- **Tags:** `[FOUNDATIONAL]` `[HISTORICAL]`

---

### "Exploiting Windows RPC" — James Forshaw
- **Presenter:** James Forshaw
- **Conference / Source:** tiraniddo.dev blog + various talks
- **URL:** https://www.tiraniddo.dev/ (tag: rpc)
- **Why essential:**
  Analysis of Windows RPC security model, how RPC interfaces handle impersonation
  and access control, and how to find vulnerable RPC endpoints. Foundation for
  understanding PrintNightmare and dozens of other RPC-surface CVEs.
- **Tags:** `[FOUNDATIONAL]`

---

## Cluster 9: Windows Privilege Escalation Tutorials

---

### "Windows Privilege Escalation Fundamentals"
- **Author:** FuzzySecurity (b33f)
- **Source:** fuzzysecurity.com tutorial series
- **URL:** https://www.fuzzysecurity.com/tutorials/16.html
- **Why essential:**
  The most comprehensive introductory tutorial series on Windows privilege escalation
  for practitioners. Covers weak service permissions, unquoted service paths,
  DLL hijacking, registry misconfigurations, scheduled task abuse, always-install-elevated,
  and more — each with manual and automated techniques. Required reading for anyone
  new to Windows LPE.
- **Tags:** `[MUST-READ]` `[FOUNDATIONAL]` `[LPE]`

---

## Cluster 10: Hypervisor & VBS Research

---

### "Attacking the Hypervisor: Hyper-V Security" — Various
- **Presenters:** Nico Economou & Enrique Nissim (Core Security), various BlueHat presenters
- **Conference:** BlueHat, OffensiveCon, various
- **URL:** https://www.coresecurity.com/core-labs/articles / https://www.synacktiv.com/publications.html
- **Why essential:**
  Covers Hyper-V partition isolation, hypercall attack surface, VMBus exploitation,
  and VTL0↔VTL1 boundary attacks relevant to VBS/HVCI bypass research.
- **Tags:** `[KERNEL]` `[CURRENT]`

---

### "Administrator Protection Bypass Research"
- **Source:** Google Project Zero (2024–2025)
- **URL:** https://projectzero.google/
- **Why essential:**
  Research on Windows 11 24H2's Administrator Protection feature — UAC successor
  that isolates admin tokens. Project Zero's analysis reveals bypass techniques
  and architectural weaknesses in the new model.
- **Tags:** `[CURRENT]` `[LPE]`

---

## Cluster 11: Process Injection & Payload Delivery

---

### "Windows Process Injection Techniques"
- **Author:** Various (endgame.com, Adam Chester @_xpn_, SpecterOps)
- **Conference / Source:** DEF CON, blog posts
- **URL:** https://blog.xpnsec.com/ / https://posts.specterops.io/
- **Why essential:**
  Comprehensive survey of Windows process injection techniques — DLL injection,
  thread hijacking, APC injection, process hollowing, module stomping, ghost-writing,
  early-bird APC, NtCreateSection + NtMapViewOfSection. Essential for understanding
  how malware and offensive tooling operate in Windows process space.
- **Tags:** `[FOUNDATIONAL]`

---

## Quick Reference: Talks by Topic

| Topic | Best Talk | Presenter |
|-------|-----------|-----------|
| Symbolic links (all types) | DEF CON 23 | Forshaw |
| Token impersonation | OffensiveCon 2019 | Forshaw |
| Named pipe LPE | itm4n blog (2020) | itm4n |
| Kernel pool exploitation | SyScan 2011-2013 | Tarjei Mandt |
| I/O Ring kernel primitive | Black Hat 2022 | Yarden Shafir |
| KASLR bypass | windows-internals.com | Yarden Shafir |
| Kernel memory disclosure | Black Hat 2017 | j00ru |
| Kerberos attacks | DerbyCon | harmj0y + tifkin_ |
| NTLM relay | DEF CON / blog | PythonResponder, dirkjanm |
| COM internals | REcon 2014 | Alex Ionescu |
| Windows LPE tutorial | fuzzysecurity.com | FuzzySecurity |
| Process injection survey | DEF CON / blogs | Multiple |
| Hyper-V attack surface | BlueHat / OffensiveCon | Multiple |
