# Windows Security Researchers & Blogs

> Curated profiles of the most significant researchers in Windows security internals,
> privilege escalation, kernel exploitation, and vulnerability research.
> Last updated: 2025

---

## Reading Priority

| Tag | Meaning |
|-----|---------|
| `[MUST-READ]` | Essential — read before anything else in this category |
| `[FOUNDATIONAL]` | Background knowledge that underpins many other techniques |
| `[HISTORICAL]` | Older but still architecturally relevant |
| `[ACTIVE]` | Researcher is currently publishing |

---

## Researcher Profiles

---

### James Forshaw

- **Blog/Site:** https://www.tiraniddo.dev/
- **Focus area:** Windows security internals — object manager, access tokens, RPC/ALPC, COM, sandbox architecture, object namespace, symbolic links, security descriptors
- **Why they matter:**
  The single most impactful Windows security researcher alive. Forshaw has discovered
  hundreds of Windows local privilege escalation vulnerabilities through systematic
  analysis of the Windows object model, token system, and inter-process communication
  mechanisms. He authored the *Windows Security Internals* book (No Starch Press, 2024),
  which is the definitive technical reference for offensive and defensive Windows security.
  His `sandbox-attacksurface-analysis-tools` (SAAT) suite is the standard toolkit for
  Windows security assessment. Works at Google Project Zero.
- **Must-read posts:**
  - *Windows Exploitation Tricks* series (entire series) — https://www.tiraniddo.dev/ (tag: exploitation-tricks)
  - *Symbolic Link Planting Attacks* — https://www.tiraniddo.dev/2019/08/
  - *Abusing Access Tokens for UAC Bypasses* — https://www.tiraniddo.dev/2017/05/
  - *The Definitive Guide to Windows ALPC* — https://www.tiraniddo.dev/2019/10/
  - *Obscure Windows File Sharing Tricks* — https://www.tiraniddo.dev/2023/
  - *NtObjectManager and the Object Manager Namespace* — extensive SAAT blog coverage
  - *Token Impersonation and Security* — multiple posts across years
  - *COM Security* — multiple posts
  - *Windows Sandbox Attack Surface* — Black Hat 2012 + follow-up posts
- **GitHub:** https://github.com/tyranid
  - Key repos: `sandbox-attacksurface-analysis-tools`, `NtObjectManager`, `oleviewdotnet`
- **Twitter/X:** @tiraniddo
- **Book:** *Windows Security Internals* (No Starch Press, 2024) — https://nostarch.com/windows-security-internals
- **Tags:** `[MUST-READ]` `[ACTIVE]` `[FOUNDATIONAL]`

---

### Clément Labro (itm4n)

- **Blog/Site:** https://itm4n.github.io/
- **Focus area:** Windows local privilege escalation — services, named pipes, impersonation, token manipulation, Windows internals from an offensive angle
- **Why they matter:**
  Labro is responsible for `PrintSpoofer` (CVE-2020-1048/pipe impersonation), which
  became one of the most widely used LPE primitives in post-exploitation frameworks.
  His `PrivescCheck` PowerShell tool is the de-facto standard for automated Windows
  privilege escalation enumeration. His blog posts are exceptionally well-written
  and combine theory with reproducible PoC code — ideal for learning the *why*
  behind each technique, not just the *how*.
- **Must-read posts:**
  - *PrintSpoofer — Abusing Impersonation Privileges on Windows 10 and Server 2019* — https://itm4n.github.io/printspoofer-abusing-impersonation-privileges/
  - *Windows Named Pipes & Impersonation* — https://itm4n.github.io/windows-namedpipes-internals/
  - *PrivescCheck — Enumerate Privilege Escalation Paths* — https://itm4n.github.io/privesccheck/
  - *From the Sandbox to the System: Attacking Windows Services* — multiple posts
  - *RpcEptMapper Registry Key Permissions EoP* — https://itm4n.github.io/windows-server-netman-dll-hijacking/
  - *DLL Hijacking in Windows Services* — multiple posts
  - *AlwaysInstallElevated: Still Alive in 2021* — itm4n.github.io
- **GitHub:** https://github.com/itm4n
  - Key repos: `PrivescCheck`, `PrintSpoofer`, `FullPowers`, `PPLdump`
- **Twitter/X:** @itm4n
- **Tags:** `[MUST-READ]` `[ACTIVE]`

---

### Decoder (Andrea Pierini)

- **Blog/Site:** https://decoder.cloud/
- **Focus area:** Token impersonation, Potato exploit family, SeImpersonatePrivilege / SeAssignPrimaryTokenPrivilege abuse, Windows authentication internals, NTLM relay variants
- **Why they matter:**
  Pierini (often credited as "decoder_it" or working in collaboration with other
  researchers) is the primary author behind the Potato exploit lineage — from
  RottenPotato through SweetPotato, RoguePotato, and LocalPotato. Each generation
  exploited increasingly subtle aspects of COM activation, NTLM authentication,
  and token impersonation to escalate from service accounts to SYSTEM. His work
  fundamentally shaped the post-exploitation meta around SeImpersonatePrivilege.
- **Must-read posts:**
  - *RoguePotato — Another Potato to get SYSTEM privileges* — https://decoder.cloud/2020/05/11/
  - *LocalPotato* — https://decoder.cloud/2023/01/28/localpotatowhen-swapping-the-context-leads-you-to-system/
  - *SeRelabelPrivilege — Some Privileges that could allow LPE* — https://decoder.cloud/2019/11/12/
  - *Sweet Potato* — collaboration post with itm4n
  - *Abusing Token Privileges for Windows Local Privilege Escalation* — multiple posts
- **GitHub:** https://github.com/decoder-it
  - Key repos: `RoguePotato`, `LocalPotato`, `juicy-potato` (co-author)
- **Twitter/X:** @decoder_it
- **Tags:** `[MUST-READ]` `[ACTIVE]`

---

### Yarden Shafir

- **Blog/Site:** https://windows-internals.com/
- **Focus area:** Windows kernel internals — I/O Ring, KASLR bypass techniques, kernel exploitation mitigations, thread pool internals, Windows security features (SecKernel, CET, XFG)
- **Why they matter:**
  Shafir is one of the leading voices on modern Windows kernel internals and
  exploitation. Her research on I/O Ring (published 2022) identified a new primitive
  for kernel reads/writes without needing traditional UAF primitives. She co-maintains
  the *Windows Internals* community blog alongside Alex Ionescu and Pavel Yosifovich.
  Her work bridges the gap between academic kernel security research and practical
  exploitation technique development.
- **Must-read posts:**
  - *One I/O Ring to Rule Them All: A Heap-Based Exploit Primitive* — https://windows-internals.com/one-i-o-ring-to-rule-them-all/
  - *KASLR: Analysis and Bypass* — https://windows-internals.com/kaslr-analysis-and-bypass/
  - *SecKernel and Secure Kernel Research* — windows-internals.com series
  - *A Deep Dive Into the I/O Ring* — follow-up to I/O Ring exploit primitive
  - *Kernel Exploitation — Expanding the Attack Surface* — various posts
- **GitHub:** https://github.com/yardenshafir
  - Key repos: `IoRingReadFile`, `WinObjEx64` (contributor), kernel research PoCs
- **Twitter/X:** @yarden_shafir
- **Tags:** `[MUST-READ]` `[ACTIVE]`

---

### Jann Horn (Google Project Zero)

- **Blog/Site:** https://googleprojectzero.blogspot.com/
- **Focus area:** Kernel exploitation, race conditions, browser sandbox escapes, speculative execution vulnerabilities, memory safety
- **Why they matter:**
  Horn is responsible for some of the most technically sophisticated vulnerability
  research published in the last decade, including co-discovery of Spectre/Meltdown
  and multiple Linux/Windows kernel race condition exploits. While primarily focused
  on Linux, his techniques for race condition exploitation, double-fetch bugs, and
  kernel memory disclosure translate directly to Windows kernel research. His
  Project Zero write-ups are mandatory reading for anyone pursuing kernel-level work.
- **Must-read posts (Windows-relevant):**
  - *Exploiting race conditions on Android* — race condition methodology applicable to Windows
  - *Windows Kernel Pool Spraying* — (various Project Zero posts)
  - *Issue tracker: Windows bugs* — https://bugs.chromium.org/p/project-zero/issues/list?q=windows
  - *Spectre/Meltdown* — co-discovery posts on Project Zero blog
- **GitHub:** https://github.com/thejh (personal research)
- **Twitter/X:** @thejh
- **Tags:** `[FOUNDATIONAL]` `[ACTIVE]`

---

### Mateusz "j00ru" Jurczyk

- **Blog/Site:** https://j00ru.vexillium.org/
- **Focus area:** Windows kernel vulnerability research, win32k subsystem, syscall table analysis, fuzzing (Bochspwn), kernel memory disclosure, font/graphics attack surface
- **Why they matter:**
  Jurczyk has published more Windows kernel vulnerability research than almost any
  other researcher outside of Microsoft. His *Bochspwn* and *Bochspwn Reloaded*
  projects discovered hundreds of kernel-to-user memory disclosure bugs across
  Windows by tracking memory access patterns at the hypervisor level. He maintains
  the most comprehensive Windows syscall tables publicly available. His win32k
  research remains relevant because the attack surface is still present despite
  Win32k lockdown efforts.
- **Must-read posts:**
  - *Bochspwn Reloaded: Detecting Kernel Memory Disclosure with x86 Emulation* — Black Hat USA 2017
  - *Windows Kernel Reference Count Vulnerabilities* — j00ru.vexillium.org
  - *Taking care of win32k* — multiple research posts
  - *Syscall tables* — https://j00ru.vexillium.org/syscalls/nt/64/
  - *Windows fonts attack surface* — kernel path through kernel32/gdi32
- **GitHub:** https://github.com/j00ru
  - Key repos: `bochspwn-reloaded`, `win32k-bugs`, syscall table data
- **Twitter/X:** @j00ru
- **Tags:** `[MUST-READ]` `[ACTIVE]`

---

### Alex Ionescu

- **Blog/Site:** https://windows-internals.com/ (co-author and contributor)
- **Focus area:** Windows kernel internals, NT architecture, hypervisor (Hyper-V), Windows boot process, security features (Isolated User Mode, VTL, Secure Kernel), kernel structures and undocumented APIs
- **Why they matter:**
  Ionescu is the co-author of the *Windows Internals* book series (editions 6 and 7)
  alongside Mark Russinovich and David Solomon — the foundational reference for
  all Windows internals research. His personal research focuses on hypervisor security,
  Isolated User Mode (IUM), Windows Secure Kernel, and Virtualization-Based Security
  (VBS). He has given landmark talks at REcon, Black Hat, and BlueHat that remain
  essential references for anyone working at the kernel or hypervisor layer.
- **Must-read posts/talks:**
  - *COM: Internals and Security* — REcon 2014
  - *To The Bone* — Black Hat USA 2016 (Windows 10 RS1 security features)
  - *Esoteric Hooks* — DEF CON / various (Windows hooking internals)
  - *Windows Internals* book — editions 6 and 7 (co-authored)
  - *Hyper-V Internals* — various conference talks
- **GitHub:** https://github.com/ionescu007
  - Key repos: `HyperPlatform`, `SpecuCheck`, `RecursiveIoRings`
- **Twitter/X:** @aionescu
- **Tags:** `[FOUNDATIONAL]` `[ACTIVE]`

---

### Pavel Yosifovich (zodiacon)

- **Blog/Site:** https://scorpiosoftware.net/
- **Focus area:** Windows kernel programming, driver development, process and thread internals, tools (Process Hacker/System Informer contributor), debugging and reverse engineering
- **Why they matter:**
  Yosifovich is the most prolific author of *practical* Windows kernel programming
  content. His books (*Windows Kernel Programming*, *Windows System Programming*,
  *Hands-On System Programming with C++*) make kernel concepts accessible to
  practitioners. He contributes to System Informer (formerly Process Hacker) and
  develops custom tools for kernel visibility. Indispensable as a bridge between
  internals theory and working code.
- **Must-read posts:**
  - *Windows Kernel Programming* (book) — Leanpub / Packt
  - *Kernel Pool Internals* — scorpiosoftware.net posts
  - *Object Manager Internals* — blog post series
  - *Driver development tutorial series* — scorpiosoftware.net
- **GitHub:** https://github.com/zodiacon
  - Key repos: `WindowsKernelProgrammingBook`, `TotalPE2`, `KDU` (co-author)
- **Twitter/X:** @zodiacon
- **Tags:** `[FOUNDATIONAL]` `[ACTIVE]`

---

### Abdelhamid Naceri (klinix5 / halov)

- **Blog/Site:** GitHub and Twitter primary — no dedicated blog as of 2024
- **Focus area:** Windows local privilege escalation 0-days, Windows Installer (MSI) internals, file operation races, arbitrary file move/write primitives
- **Why they matter:**
  Naceri gained notoriety for discovering and (controversially) publicly releasing
  multiple Windows LPE 0-days in rapid succession in 2021, including
  *InstallerFileTakeOver* (arbitrary file move via Windows Installer repair mechanism)
  and a bypass for Microsoft's patch for CVE-2021-41379. His research highlighted
  systemic weaknesses in Windows Installer's privileged file operations and the
  difficulty of fully patching file operation primitives.
- **Must-read posts/repos:**
  - *InstallerFileTakeOver* — https://github.com/klinix5/InstallerFileTakeOver [MUST-READ]
  - *CVE-2021-41379 bypass* — public Twitter disclosure + GitHub PoC
  - *Various unpatched 0-day disclosures* — GitHub and Twitter threads 2021-2022
- **GitHub:** https://github.com/klinix5
- **Twitter/X:** @Abdelhamid_hac (verify current handle)
- **Tags:** `[MUST-READ]` `[ACTIVE]`

---

### SandboxEscaper (historical anonymous researcher)

- **Blog/Site:** Defunct — archived content only
- **Focus area:** Windows LPE 0-days — Task Scheduler, Windows Installer, print operations, file operations, DACL manipulation
- **Why they matter:**
  Between 2018 and 2019, SandboxEscaper publicly released approximately six Windows
  LPE 0-days without coordinated disclosure, causing significant disruption. The
  techniques — particularly those involving Task Scheduler's SchRpcSetSecurity and
  file operation race conditions — introduced important primitives that influenced
  subsequent research. The CVEs (including CVE-2018-8440, CVE-2019-0841,
  CVE-2019-1069) are now patched but remain architecturally instructive.
- **Must-read (archived PoCs/writeups):**
  - *CVE-2018-8440* — Task Scheduler ALPC LPE (original disclosure)
  - *CVE-2019-0841* — Windows AppX Deployment Service DACL override
  - *CVE-2019-1069* — Task Scheduler popen() race
  - Archive: https://github.com/SandboxEscaper (archived repos)
- **GitHub:** https://github.com/SandboxEscaper (archived)
- **Twitter/X:** N/A (account deleted)
- **Tags:** `[HISTORICAL]` `[FOUNDATIONAL]`

---

### Jonas Lyk

- **Blog/Site:** Twitter/X primary — https://twitter.com/jonasLyk
- **Focus area:** Windows security misconfigurations, file and registry permission weaknesses, UAC bypasses, icacls/ACL research, HiveNightmare / SeriousSAM
- **Why they matter:**
  Lyk discovered *HiveNightmare* (CVE-2021-36934 / SeriousSAM) — a Windows 11
  misconfiguration where SYSTEM registry hive files (SAM, SECURITY, SYSTEM) were
  readable by all authenticated users due to incorrect ACLs introduced by Volume
  Shadow Copy. This allowed any local user to extract password hashes. A good
  example of high-impact bugs found through configuration analysis rather than
  complex memory corruption.
- **Must-read:**
  - *HiveNightmare / SeriousSAM discovery thread* — Twitter, July 2021
  - *CVE-2021-36934* — Microsoft Security Advisory
  - *ACL research threads* — ongoing Twitter posts on permission misconfigurations
- **GitHub:** https://github.com/GossiTheDog (collaborator context)
- **Twitter/X:** @jonasLyk
- **Tags:** `[ACTIVE]`

---

### Filip Dragovic

- **Blog/Site:** GitHub primary — https://github.com/boku7 (note: verify; Filip Dragovic CVE PoCs also at https://github.com/drtychai)
- **Focus area:** Windows kernel exploit PoCs, LPE CVE proof-of-concept implementations, driver vulnerabilities
- **Why they matter:**
  Dragovic has published high-quality exploit PoC implementations for Windows LPE
  CVEs including win32k bugs, making them accessible for security research and
  verification. His PoC code is often the first public working implementation
  after a patch, providing a valuable reference for understanding exploit techniques
  in practice.
- **Must-read repos:**
  - Various Windows LPE CVE PoCs on GitHub — search CVE tags
  - *CVE-2021-1732* PoC implementation — win32k EoP exploited in the wild
- **GitHub:** https://github.com/boku7 / https://github.com/drtychai (research PoCs)
- **Twitter/X:** @filip_dragovic (verify current handle)
- **Tags:** `[ACTIVE]`

---

### Valentina Palmiotti (chompie1337)

- **Blog/Site:** https://github.com/chompie1337 and Twitter primary
- **Focus area:** Windows kernel exploitation — win32k vulnerabilities, heap spray techniques, browser sandbox escapes, memory corruption exploitation
- **Why they matter:**
  Palmiotti has published high-quality Windows kernel exploit development content,
  including detailed exploit chains for win32k vulnerabilities. She is particularly
  strong on the engineering side of exploit development — pool grooming, heap spray,
  achieving reliable primitives. Her public write-ups and talks are unusually detailed
  and technically deep.
- **Must-read:**
  - *SMBGhost (CVE-2020-0796) RCE exploit* — published full exploit chain
  - *win32k kernel exploitation threads* — Twitter research threads
  - *Windows kernel pool internals for exploitation* — conference talks
- **GitHub:** https://github.com/chompie1337
  - Key repos: `SMBGhost_RCE_PoC`, kernel research tools
- **Twitter/X:** @chompie1337
- **Tags:** `[MUST-READ]` `[ACTIVE]`

---

### Eduardo Blázquez & Tarlogic Security Team

- **Blog/Site:** https://www.tarlogic.com/blog/
- **Focus area:** Windows authentication protocol internals — Kerberos, NTLM, Active Directory, BloodHound-compatible attack paths, Kerberoasting, Pass-the-Hash/Ticket
- **Why they matter:**
  Tarlogic's research team has produced thorough analyses of Windows authentication
  mechanisms at the protocol level, making their blog one of the best resources for
  understanding *why* techniques like Pass-the-Ticket, Silver/Golden Ticket, and
  NTLM relay work at the network and cryptographic level rather than just how to
  run them in tools.
- **Must-read posts:**
  - *Kerberos Authentication Internals* series — tarlogic.com/blog
  - *NTLM Relay Attacks* — detailed technical breakdowns
  - *BloodHound attack path analysis* — methodology posts
  - *Ticket abuse techniques* — Kerberoasting, AS-REP roasting deep dives
- **GitHub:** https://github.com/Tarlogic (team org)
- **Twitter/X:** @TarlogicSec / @EduardoBl4zquez
- **Tags:** `[ACTIVE]`

---

### Synacktiv Research Team (including Cédric Mouheb)

- **Blog/Site:** https://www.synacktiv.com/publications.html
- **Focus area:** Windows kernel and hypervisor security, VBS/HVCI bypass research, driver signing bypass, Hyper-V attack surface, firmware security
- **Why they matter:**
  Synacktiv consistently produces some of the most technically advanced Windows
  kernel and hypervisor security research in the industry. Their publications cover
  areas like Virtualization-Based Security (VBS), HVCI bypass techniques, Hyper-V
  partition isolation, and kernel driver attack surfaces that few other teams
  publish on openly.
- **Must-read posts:**
  - *Bypassing HVCI with a vulnerable driver* — synacktiv.com
  - *Hyper-V attack surface research* — synacktiv.com publications
  - *Windows kernel driver research* — multiple publications
  - *UEFI and firmware attack surface* — synacktiv.com
- **GitHub:** https://github.com/synacktiv
- **Twitter/X:** @Synacktiv
- **Tags:** `[MUST-READ]` `[ACTIVE]`

---

## Additional Notable Researchers

| Researcher | Handle | Focus | Key Resource |
|-----------|--------|-------|-------------|
| Will Schroeder | @harmj0y | AD, Kerberos, BloodHound | https://blog.harmj0y.net/ |
| Benjamin Delpy | @gentilkiwi | Mimikatz, LSASS, Kerberos | https://blog.gentilkiwi.com/ |
| Mark Russinovich | @markrussinovich | Windows Internals (book), Sysinternals | https://techcommunity.microsoft.com/t5/windows-blog-archive/ |
| FuzzySecurity (b33f) | @FuzzySec | Windows exploitation tutorials | https://www.fuzzysecurity.com/tutorials/16.html |
| GhostPack / SpecterOps | various | AD offensive tooling | https://github.com/GhostPack |
| Thiago Mayllart | @thiagomxst | Windows internals, process injection | GitHub + Twitter |
| Connor McGarr | @33y0re | Windows kernel exploitation | https://connormcgarr.github.io/ |
| Red Team Notes (Cas van Cooten) | @chvancooten | Pentest tradecraft | https://www.chvancooten.nl/ |
| Adam Chester | @_xpn_ | Process injection, payload dev | https://blog.xpnsec.com/ |

---

## Aggregator / Community Resources

- **Windows Security Blog (MSRC):** https://msrc.microsoft.com/blog/
- **Project Zero Issue Tracker (Windows):** https://bugs.chromium.org/p/project-zero/issues/list?q=windows
- **Windows Internals community blog:** https://windows-internals.com/
- **NtDoc (undocumented NT API reference):** https://ntdoc.m417z.com/
- **Syscall tables (j00ru):** https://j00ru.vexillium.org/syscalls/nt/64/
- **LOLBAS (living off the land binaries):** https://lolbas-project.github.io/
- **GTFOBins Windows equivalent:** https://github.com/api0cradle/UltimateAppLockerByPassList
