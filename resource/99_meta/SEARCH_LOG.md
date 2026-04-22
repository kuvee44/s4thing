# Search Log — Windows Security Research Knowledge Base

## Collection Date: 2026-04-22

---

## Search Strategy Overview

The collection was conducted in structured waves, starting with canonical landmarks and expanding outward by topic, researcher, and tool category. The strategy prioritized depth-first coverage of high-signal sources before breadth-first expansion to secondary sources.

---

## Wave 1 — Foundational Landmarks

**Goal:** Identify the must-read books, papers, and canonical resources that any Windows security researcher would cite.

**Queries used:**
- "Windows security research essential books"
- "Windows internals book security"
- "Windows security internals James Forshaw"
- "Windows kernel exploitation reference"
- "mandatory reading Windows LPE research"

**High-signal results:**
- Windows Internals Parts 1 & 2 (Yosifovich et al.) — confirmed as universal citation
- Windows Security Internals (Forshaw, 2023) — confirmed as the definitive security-focused book
- Windows Kernel Programming (Yosifovich) — confirmed for driver/kernel track
- ReactOS as open-source reference implementation — confirmed

**Sources checked:**
- amazon.com (book catalog)
- nostarch.com (Windows Security Internals)
- microsoftpressstore.com (Windows Internals)
- University security course syllabi (multiple)

---

## Wave 2 — Researcher Blogs and Primary Sources

**Goal:** Identify the most active and high-signal researcher blogs.

**Queries used:**
- "best Windows security research blogs 2024"
- "tiraniddo.dev symbolic links windows"
- "itm4n windows privilege escalation blog"
- "j00ru windows kernel research"
- "decoder windows potato exploit"
- "Google Project Zero Windows research"
- "Alex Ionescu Windows blog"

**High-signal sources found:**
- tiraniddo.dev — highest signal; every post is high value; Forshaw's COM/token/symlink work
- itm4n.github.io — consistently excellent LPE research
- j00ru.vexillium.org — best kernel/Win32k content
- decoder.cloud — DCOM/potato expertise
- googleprojectzero.blogspot.com — gold standard for writeup quality and depth
- ionescu007.github.io — ALPC, kernel security
- windows-internals.com (Yarden Shafir) — kernel pool/exploitation

**Sources checked:**
- tiraniddo.dev (all indexed posts)
- itm4n.github.io (all posts)
- j00ru.vexillium.org (blog index)
- decoder.cloud (blog index)
- googleprojectzero.blogspot.com (Windows label)
- alex-ionescu.com (blog + talks)
- windows-internals.com (Shafir posts)

---

## Wave 3 — Bug Classes and Techniques

**Goal:** Map the full taxonomy of Windows LPE bug classes with canonical resources for each.

**Queries used:**
- "Windows arbitrary file write privilege escalation"
- "junction symlink oplock TOCTOU Windows LPE"
- "Potato exploit variants Windows"
- "PrintSpoofer PrintNightmare analysis"
- "Windows Installer MSI privilege escalation"
- "Windows COM privilege escalation"
- "Windows object manager namespace exploit"
- "Windows token impersonation vulnerability"
- "SeImpersonatePrivilege exploit"
- "Windows service weak permissions LPE"

**High-signal results:**
- foxglovesecurity.com — Token privileges post, Hot Potato
- itm4n PrintSpoofer — best single post for impersonation bugs
- Naceri/klinix5 GitHub — InstallerFileTakeOver as canonical MSI LPE
- UACME (hfiref0x) — comprehensive UAC bypass catalog
- ohpe/juicy-potato — canonical DCOM potato reference
- decoder-it/RoguePotato — modern OXID technique
- forshaw's symboliclink-testing-tools — canonical junction/oplock research

**Sources checked:**
- foxglovesecurity.com (all posts)
- github.com/ohpe/juicy-potato
- github.com/decoder-it/RoguePotato
- github.com/itm4n/PrintSpoofer
- github.com/klinix5/InstallerFileTakeOver
- github.com/hfiref0x/UACME
- googleprojectzero.blogspot.com (symlink / junction label)

---

## Wave 4 — GitHub Code and Tooling

**Goal:** Identify essential GitHub repositories for tooling and PoC code.

**Queries used:**
- "Windows privilege escalation GitHub repos"
- "Windows kernel exploitation training driver GitHub"
- "Windows LPE enumeration script GitHub"
- "Windows security research tools GitHub"
- "NtObjectManager windows security"
- "HEVD hacksys vulnerable driver"
- "Windows kernel fuzzer GitHub"

**High-signal repos found:**
- googleprojectzero/sandbox-attacksurface-analysis-tools — essential tooling
- hacksysteam/HackSysExtremeVulnerableDriver — training standard
- itm4n/PrivescCheck — best enumeration tool
- GhostPack organization (harmj0y) — complete offensive .NET suite
- 0vercl0k/wtf — kernel fuzzer
- hfiref0x/UACME — UAC bypass catalog
- BeichenDream/GodPotato — modern potato
- googleprojectzero/jackalope — coverage fuzzer
- googleprojectzero/symboliclink-testing-tools — junction/oplock toolkit

**Sources checked:**
- github.com/topics/windows-privilege-escalation
- github.com/topics/windows-security
- github.com/topics/kernel-exploitation
- github.com search: "windows lpe" sorted by stars
- github.com/googleprojectzero (all repos)
- github.com/GhostPack (all repos)

---

## Wave 5 — Conference Talks and Papers

**Goal:** Identify landmark conference talks and academic papers.

**Queries used:**
- "DEF CON James Forshaw Windows talks"
- "Black Hat Windows kernel exploitation 2019 2020 2021 2022"
- "Bochspwn j00ru Black Hat paper"
- "Windows pool exploitation talk Yarden Shafir"
- "REcon Windows security talks"
- "Infiltrate Windows sandbox escape"

**High-signal talks found:**
- DEF CON 25 — Forshaw object namespace talk
- DEF CON 27 — Forshaw Windows exploitation 2019
- Black Hat 2017 — Bochspwn Reloaded (j00ru)
- Hex Rays 2020 — Pool is Dead (Shafir/Ionescu)
- Various BlueHat sessions on kernel mitigations

**Sources checked:**
- youtube.com (DEF CON/Black Hat official channels)
- github.com/tiraniddo (for slide repos)
- j00ru.vexillium.org (publications/papers section)
- conference archives: defcon.org, blackhat.com

---

## Wave 6 — MSRC and Official Sources

**Goal:** Identify essential official Microsoft documentation.

**Queries used:**
- "Windows security servicing criteria MSRC"
- "MSRC bug bounty Windows"
- "Microsoft Windows security features documentation"
- "Windows token impersonation MSDN"
- "Windows security descriptor MSDN"

**High-signal official sources found:**
- learn.microsoft.com/windows/security/security-servicing-criteria — critical for scoping
- msrc.microsoft.com/bugbounty — bounty terms
- learn.microsoft.com/windows/win32/secauthz/ — access control reference
- learn.microsoft.com/windows-hardware/drivers/debugger/time-travel-debugging — TTD docs
- sysinternals.microsoft.com — full tool suite documentation

---

## Wave 7 — Reporting and Disclosure

**Goal:** Identify resources for the full disclosure → bounty pipeline.

**Queries used:**
- "MSRC vulnerability submission guide"
- "Zero Day Initiative submission process"
- "writing vulnerability reports guide"
- "CVSS scoring vulnerability"
- "coordinated disclosure best practices"
- "HackerOne Windows vulnerability"

**High-signal sources found:**
- msrc.microsoft.com (submission portal + FAQ)
- zerodayinitiative.com/advisories/disclosure_policy/
- first.org/cvss (CVSS v3.1 calculator and specification)
- hackerone.com/microsoft (program policy)
- bugcrowd.com (vulnerability rating taxonomy)

---

## High-Signal Sources (Summary — By Tier)

### Tier 1 (Check Every New Post)
1. tiraniddo.dev
2. googleprojectzero.blogspot.com (Windows tag)
3. itm4n.github.io
4. j00ru.vexillium.org
5. windows-internals.com (Yarden Shafir)

### Tier 2 (Check Monthly)
6. decoder.cloud
7. zeroperil.co.uk/blog
8. synacktiv.com/publications
9. msrc.microsoft.com/blog
10. blog.gentilkiwi.com

### Tier 3 (Periodic Reference)
11. fuzzysecurity.com
12. harmj0y.net (retired/archived)
13. blog.harmj0y.net (archived)
14. ionescu007.github.io

---

## Diminishing Returns Notes

- **UAC bypass techniques:** After UACME (60+ methods), new techniques are increasingly narrow edge cases. Covered sufficiently.
- **Potato variants:** After God/Bad/EfsPotato, new variants offer marginal novelty. Technique fundamentals are well covered.
- **General LPE tutorials:** High volumes of low-quality tutorials found after ~10 searches — filtered aggressively.
- **Academic papers:** Few highly relevant papers outside Bochspwn and a handful of conference proceedings. Most depth is in practitioner blogs, not academic venues.
- **CTF writeups:** Many involve Windows challenges but methodology is often incomplete or contrived. Excluded most.

---

## Sources Excluded

| Source | Reason for Exclusion |
|--------|---------------------|
| Medium.com (generic security posts) | Low quality, mostly rehashing known techniques without depth |
| Hacking blogs with no original research | SEO-optimized content, no novel analysis |
| Old book editions (pre-6th ed. Windows Internals) | Superseded by 7th edition |
| Offensive-security course materials | Paywalled and surface-level |
| CTF writeups (most) | Contrived scenarios, not directly applicable to real Windows research |
| Vendor blog posts without technical depth | Marketing, not research |
| Outdated Metasploit module writeups | No root cause analysis, just tooling instructions |
| GitHub repos with <100 stars and no known author | Cannot verify quality or trust level |

---

## Search Queries Used (Full List)

```
# Books and foundational
"Windows security internals book"
"Windows internals seventh edition"
"Windows kernel programming book"

# Researcher blogs
"tiraniddo blog windows"
"itm4n github windows"
"j00ru windows kernel"
"decoder cloud potato windows"
"yarden shafir windows kernel"
"Alex Ionescu windows internals blog"

# Bug classes
"Windows arbitrary file write LPE"
"junction symlink TOCTOU privilege escalation"
"named pipe impersonation windows"
"potato exploit variants"
"Windows COM privilege escalation"
"Windows object manager exploit"
"Windows token impersonation LPE"
"SeImpersonatePrivilege SYSTEM"
"Windows installer MSI privilege escalation"
"Windows service weak permissions"
"DLL hijacking Windows service"
"Windows scheduled task privilege escalation"

# Kernel
"Windows kernel exploitation tutorial"
"HEVD hacksys vulnerable driver"
"Windows pool exploitation windows 10"
"Win32k exploitation history"
"Windows kernel fuzzer"
"loldrivers vulnerable driver"

# Tools
"NtObjectManager windows security"
"PrivescCheck windows"
"SharpUp GhostPack"
"SilkETW windows"
"symboliclink-testing-tools"
"WTF kernel fuzzer windows"
"jackalope fuzzer Google"

# CVEs
"PrintNightmare root cause analysis"
"InstallerFileTakeOver CVE-2021-41379"
"PrintSpoofer CVE-2020-1030"
"CLFS vulnerability Windows kernel"
"SandboxEscaper CVEs analysis"

# Talks and papers
"DEF CON Windows security talks James Forshaw"
"Black Hat Windows kernel exploitation"
"Bochspwn kernel memory disclosure"
"Windows pool is dead talk"
"IO ring exploitation Windows 11"

# Reporting
"MSRC vulnerability submission"
"Windows security servicing criteria"
"ZDI submission guide"
"CVSS scoring vulnerability report"
"coordinated disclosure policy"
```

---

## Next Collection Wave (Planned)

### Priority Topics for Next Update
1. **Windows 11 24H2 security changes** — new mitigations and attack surface changes
2. **CLFS vulnerability series** — deeper coverage of CLFS kernel bugs (ransomware operators' favorite)
3. **VBS/HVCI bypass research** — emerging area as more systems enable HVCI
4. **Hyper-V attack surface** — growing body of research from Synacktiv, ZDI
5. **Windows ARM64 security** — different instruction set, different gadgets, different mitigations
6. **CET shadow stack bypass techniques** — as CET adoption increases
7. **Azure / cloud Windows attack surface** — cloud-specific LPE vectors
8. **NTLM relay 2024–2025 research** — updated techniques post-RemotePotato/NTLM signing changes

### Sources to Check in Next Wave
- Full archive of all BlueHat conference talks (Microsoft's internal security conference)
- NCC Group technical blog — consistent quality for Windows research
- Exodus Intelligence blog (if public posts)
- TrendMicro ZDI blog (public advisories)
- CISA KEV (Known Exploited Vulnerabilities) — for in-the-wild Windows bugs
- VUSec (Vrije Universiteit Amsterdam) — for speculative execution and hardware-based bugs
