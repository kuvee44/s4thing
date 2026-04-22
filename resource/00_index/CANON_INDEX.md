# Canon Index — Windows Security Research Vault
## Only S-TIER and A-TIER resources. Everything else is in the archive.
## Last Updated: 2026-04-22

---

## How to Use This Index

S-TIER resources are read multiple times, in full, with active tooling. Return to them annually. They do not expire. A-TIER resources are read once thoroughly, with careful notes; return to specific chapters or posts when the topic surfaces in active research. Do not treat A-TIER as optional — a gap here means your mental model has holes. Use the layers below as a reading order, not a priority ranking. The layers are sequential because later layers assume knowledge installed by earlier ones.

---

## LAYER 0: Before Everything Else

Set up your research environment before opening any book. These tools are not optional extras — without them, reading the foundational texts is passive and theoretical.

| Resource | Tier | URL | Action Required |
|---|---|---|---|
| Windows 10/11 VM with kernel debugging enabled | PREREQUISITE | — | Configure WinDbg kernel debugging over network/pipe before anything else |
| WinDbg Preview | PREREQUISITE TOOL | https://aka.ms/windbg/download | Install from Microsoft Store; this is the modern version; do not use classic WinDbg as your primary |
| NtObjectManager (NtApiDotNet) | A-TIER TOOL | https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools | `Install-Module NtObjectManager` in PowerShell; verify with `Get-NtToken` |
| System Informer (formerly Process Hacker) | A-TIER TOOL | https://systeminformer.sourceforge.io/ | Install, run as Administrator, explore Security tab on process handles — this is your live object model viewer |
| WinObj (Sysinternals) | A-TIER TOOL | https://learn.microsoft.com/en-us/sysinternals/downloads/winobj | Browse the object namespace (\BaseNamedObjects, \Sessions, \KnownDlls) before reading Chapter 8 of Windows Internals |
| Process Monitor (ProcMon) | A-TIER TOOL | https://learn.microsoft.com/en-us/sysinternals/downloads/procmon | Configure filter profiles before research sessions; learn to filter by PID and Result column immediately |

---

## LAYER 1: Foundational Canon

Read in this order. Each entry assumes the prior is complete.

1. **Windows Internals, Part 1 (7th Ed.)** — S-TIER
   - Authors: Yosifovich, Ionescu, Russinovich, Solomon
   - URL: https://www.microsoftpressstore.com/store/windows-internals-part-1-9780735684188
   - Reading order: Ch. 1–4 (process/thread model), Ch. 8 (Object Manager), Ch. 6 (I/O subsystem), Ch. 5 (memory). Do not read linearly — the book is a reference, not a narrative.
   - Why first: All subsequent security-layer reasoning requires accurate kernel object model knowledge. Reading Forshaw before this means reading security analysis on a shaky foundation.

2. **Windows Security Internals** — S-TIER
   - Author: James Forshaw
   - URL: https://nostarch.com/windows-security-internals
   - Reading order: Ch. 2–5 first (token model, access checks, impersonation), then COM, AppContainer, sandbox chapters.
   - Why second: Forshaw explicitly builds on the internals foundation. His security model analysis references kernel structures that Part 1 defines. Reading this after Part 1 means everything clicks. Reading it before means inferring half the substrate.

3. **Windows Internals, Part 2 (7th Ed.)** — A-TIER
   - Authors: Yosifovich, Ionescu, Russinovich, Solomon
   - URL: https://www.microsoftpressstore.com/store/windows-internals-part-2-9780135462331
   - Reading order: Storage and filesystem (Ch. 11–12), networking (Ch. 13), diagnostics (Ch. 14). Read storage before any filesystem-based LPE research.
   - Why third: Supplements Part 1 without replacing it. Storage chapter is required before any NTFS-based junction/symlink research. Less dense with security implications than Part 1, but not skippable.

---

## LAYER 2: Security Model Canon

Resources that illuminate Windows trust architecture specifically, beyond what the internals books cover.

| Resource | Tier | URL | One-line value |
|---|---|---|---|
| tiraniddo.dev — complete blog | A-TIER | https://www.tiraniddo.dev/ | Every post advances the reader's security model; includes original research on token privilege, AppContainer, COM trust, and sandboxing not found elsewhere |
| Project Zero blog — Windows posts | A-TIER | https://googleprojectzero.blogspot.com/search/label/Windows | Forshaw, Jurczyk, and colleagues publishing research-grade posts; filter for Windows label only |
| MSRC Security Update Guide | A-TIER REFERENCE | https://msrc.microsoft.com/update-guide/ | Ground truth for patch scope; use with BinDiff/Diaphora for patch analysis; not reading material but essential research infrastructure |
| OleViewDotNet (Forshaw) | A-TIER TOOL | https://github.com/tyranid/oleviewdotnet | The only tool that makes COM activation paths and security descriptors fully legible; required before any COM surface research |
| RpcView | A-TIER TOOL | https://github.com/silverf0x/RpcView | Enumerate registered RPC interfaces with security information; use before researching any service that exposes local RPC |

---

## LAYER 3: Primitive + Bug Class Canon

Exploitation technique resources ordered for progressive understanding. Each entry assumes Layer 1 and 2 complete.

| Resource | Tier | URL | One-line value |
|---|---|---|---|
| Windows Exploitation Tricks series (Forshaw) | **S-TIER** | https://googleprojectzero.blogspot.com/search/label/Windows%20Exploitation%20Tricks | The primitive taxonomy; read all posts in publication order |
| PrintSpoofer — Abusing Impersonation Privileges (itm4n) | **S-TIER** | https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/ | Complete anatomy of a privilege boundary violation; the structural template for research writing |
| itm4n.github.io — complete blog | A-TIER | https://itm4n.github.io/ | Consistent high-quality research on impersonation, token abuse, service account exploitation; every post is worth reading |
| decoder.cloud — complete blog | A-TIER | https://decoder.cloud/ | WinRM, EFS, token abuse, local authentication; narrow but technically precise; essential for credential-path research |
| InstallerFileTakeOver (Naceri / klinix9) | A-TIER | https://github.com/klinix5/InstallerFileTakeOver | Demonstrates Windows Installer service arbitrary file write primitive; read source and analysis post together |
| Rotten Potato (foxglovesecurity) | A-TIER [HISTORICAL] | https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/ | Original identification of COM SYSTEM impersonation coercion; historical foundation for the potato family |
| Juicy Potato | A-TIER [HISTORICAL] | https://github.com/ohpe/juicy-potato | Extended Rotten Potato to broader COM server set; read as evolution of the primitive, not as a current technique |
| RoguePotato | A-TIER | https://github.com/antonioCoco/RoguePotato | Adapted impersonation primitive post-Juicy Potato mitigations; documents exactly what changed and why |
| LocalPotato | A-TIER | https://www.localpotato.com/localpotato/Home.html | NTLM reflection in NTFS transactions — novel primitive distinct from impersonation chain; read the blog post, not just the tool |
| GodPotato | A-TIER | https://github.com/BeichenDream/GodPotato | Latest impersonation chain; minimal novel analysis but documents current-state Windows 11 compatibility; A-tier tool, C-tier writing |
| j00ru.vexillium.org — kernel and Win32k posts | A-TIER | https://j00ru.vexillium.org/ | See Layer 6 for specifics; included here for cross-reference |

---

## LAYER 4: Researcher Tools Canon

Tools that function as research instruments, not exploit deliverers. Tier rating reflects research value, not exploitation utility.

| Resource | Tier | URL | Research use |
|---|---|---|---|
| sandbox-attacksurface-analysis-tools (NtObjectManager) | **S-TIER** | https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools | Scriptable access check engine, security descriptor enumeration, impersonation testing; primary research instrument for all access-control work |
| symboliclink-testing-tools | **S-TIER** | https://github.com/googleprojectzero/symboliclink-testing-tools | Lab environment for all link primitive classes; source code is documentation |
| OleViewDotNet | A-TIER TOOL | https://github.com/tyranid/oleviewdotnet | COM activation surface enumeration and security analysis |
| RpcView | A-TIER TOOL | https://github.com/silverf0x/RpcView | RPC interface enumeration with security metadata |
| System Informer | A-TIER TOOL | https://systeminformer.sourceforge.io/ | Process/handle/token live inspection; open source, readable |
| WinObj (Sysinternals) | A-TIER TOOL | https://learn.microsoft.com/en-us/sysinternals/downloads/winobj | Object namespace browser; essential for named object research |
| Process Monitor (ProcMon) | A-TIER TOOL | https://learn.microsoft.com/en-us/sysinternals/downloads/procmon | Filesystem/registry/process access tracing; indispensable for LPE chain reconstruction |
| impacket | A-TIER TOOL | https://github.com/fortra/impacket | Python network protocol library; primary tool for SMB/Kerberos/NTLM protocol research and testing |
| HEVD (HackSys Extreme Vulnerable Driver) | A-TIER PRACTICE | https://github.com/hacksysteam/HackSysExtremeVulnerableDriver | Structured kernel exploitation practice environment; every major kernel primitive class has an implemented vulnerable function |

---

## LAYER 5: Debugging & Investigation Canon

| Resource | Tier | URL | Priority |
|---|---|---|---|
| Time Travel Debugging (TTD) | **S-TIER** | https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/time-travel-debugging-overview | Highest priority; install WinDbg Preview and record your first trace before reading any crash analysis |
| WinDbg official documentation | A-TIER | https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/ | Reference-level; use for command syntax and extension documentation; the `dx` command documentation is essential for TTD query work |
| Process Monitor (ProcMon) — Sysinternals | A-TIER TOOL | https://learn.microsoft.com/en-us/sysinternals/downloads/procmon | Already listed in Layer 4; cross-reference here for debugging workflow integration |
| WinDbg TTD — dx query language reference | A-TIER | https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/dx-provider-objects | The LINQ-over-execution-trace capability is TTD's most powerful feature; this documentation unlocks it |

---

## LAYER 6: Kernel & Win32k Canon

For researchers working the kernel attack surface. Assumes Layers 1–5 complete.

| Resource | Tier | URL | Scope |
|---|---|---|---|
| Bochspwn / Bochspwn Reloaded (j00ru, Black Hat 2017) | **S-TIER** | https://j00ru.vexillium.org/ (papers); https://github.com/googleprojectzero/bochspwn-reloaded | Systematic kernel double-fetch and TOCTOU discovery methodology; methodological template, not a bug list |
| j00ru.vexillium.org — Win32k and kernel pool posts | A-TIER | https://j00ru.vexillium.org/ | Kernel pool exploitation, Win32k attack surface, GPU driver research; high density, requires kernel debugging proficiency |
| HEVD | A-TIER PRACTICE | https://github.com/hacksysteam/HackSysExtremeVulnerableDriver | Stack overflow, pool overflow, use-after-free, type confusion — all in a debuggable environment; build and exploit before researching real drivers |
| Windows Internals Part 1 — Chapter 5 (Memory) | A-TIER (chapter) | (see Layer 1) | Pool allocator internals; required before any pool-based kernel exploitation research |

---

## LAYER 7: Patch Diff & Variant Hunting Canon

| Resource | Tier | URL | Use |
|---|---|---|---|
| BinDiff (Zynamics / Google) | A-TIER TOOL | https://www.zynamics.com/bindiff.html | Binary function-level diff between patched and unpatched DLLs; primary tool for patch analysis |
| Diaphora | A-TIER TOOL | https://github.com/joxeankoret/diaphora | Open-source IDA Pro diffing plugin; BinDiff alternative with scripting capability; use when BinDiff licensing is unavailable |
| MSRC Security Update Guide | A-TIER REFERENCE | https://msrc.microsoft.com/update-guide/ | Identify patch scope and affected components before running BinDiff; cross-reference CVE with KB article and affected binary |
| Windows Exploitation Tricks series (Forshaw) | **S-TIER** | (see Layer 3) | Cross-referenced here: the variant-hunting mental model is in this series |
| Project Zero blog — Windows vulnerability posts | A-TIER | https://googleprojectzero.blogspot.com/search/label/Windows | Published root cause analyses serve as variant-hunting templates; read any Project Zero Windows post with the question "what is the class here?" |

---

## A-TIER COMPLETE LIST BY TOPIC

| Title | Author | URL | Topic | Why A-tier |
|---|---|---|---|---|
| Windows Internals Part 2 (7th Ed.) | Yosifovich, Ionescu, Russinovich, Solomon | https://www.microsoftpressstore.com/store/windows-internals-part-2-9780135462331 | Kernel internals (storage, networking) | Essential supplement to Part 1; less security-dense but required for filesystem-based research |
| WinDbg Official Documentation | Microsoft | https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/ | Debugging | Reference standard; `dx` language documentation especially |
| Process Monitor (ProcMon) | Sysinternals / Microsoft | https://learn.microsoft.com/en-us/sysinternals/downloads/procmon | Dynamic analysis tool | Best visibility into filesystem/registry access patterns; required for LPE chain reconstruction |
| System Informer (Process Hacker 3) | wj32, dmex | https://systeminformer.sourceforge.io/ | Process/handle/token inspection | Open source; readable implementation of Windows security object inspection |
| itm4n.github.io (complete blog) | Clément Labro (itm4n) | https://itm4n.github.io/ | Privilege escalation, token abuse, impersonation | Consistently structured, root-cause-first research posts; every entry is worth reading |
| decoder.cloud (complete blog) | Andrea Pierini | https://decoder.cloud/ | Credential access, WinRM, EFS, local auth | Technically precise, narrow scope; essential for credential-path and local auth research |
| j00ru.vexillium.org (kernel/Win32k posts) | Mateusz Jurczyk | https://j00ru.vexillium.org/ | Kernel exploitation, Win32k, pool allocator | Deep kernel research from one of the most capable Windows kernel researchers; Bochspwn Reloaded is S-tier but the broader blog is A-tier |
| tiraniddo.dev (complete blog) | James Forshaw | https://www.tiraniddo.dev/ | COM, AppContainer, token model, sandbox | Every post advances the security model; Exploitation Tricks series is S-tier but broader blog is A-tier |
| Project Zero Blog — Windows posts | Google Project Zero | https://googleprojectzero.blogspot.com/search/label/Windows | Multiple — varies by author | Published research-grade posts from Forshaw, Jurczyk, and colleagues; filter to Windows label |
| Rotten Potato | foxglovesecurity | https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/ | Impersonation / COM coercion | Original SYSTEM impersonation via COM; historical foundation |
| Juicy Potato | ohpe team | https://github.com/ohpe/juicy-potato | Impersonation / COM coercion | Extends Rotten Potato; read as primitive evolution documentation |
| RoguePotato | antonioCoco | https://github.com/antonioCoco/RoguePotato | Impersonation post-mitigation | Post-mitigation adaptation; documents exactly what changed |
| LocalPotato | @decoder_it | https://www.localpotato.com/localpotato/Home.html | NTLM reflection / NTFS transaction | Novel primitive; blog post required alongside tool |
| GodPotato | BeichenDream | https://github.com/BeichenDream/GodPotato | Impersonation chain (Windows 11) | Current-state compatibility; minimal analysis; A-tier as completeness record |
| InstallerFileTakeOver | Naceri (klinix9) | https://github.com/klinix5/InstallerFileTakeOver | Arbitrary file write / Windows Installer | Clean demonstration of installer service primitive |
| BinDiff | Zynamics / Google | https://www.zynamics.com/bindiff.html | Patch diffing | Industry-standard binary diff for patch analysis |
| Diaphora | Joxean Koret | https://github.com/joxeankoret/diaphora | Patch diffing | Open-source IDA diff alternative; scripting-capable |
| HEVD | HackSys Team | https://github.com/hacksysteam/HackSysExtremeVulnerableDriver | Kernel exploitation practice | Structured vulnerable driver covering all major primitive classes; practice, not insight |
| RpcView | silverf0x | https://github.com/silverf0x/RpcView | RPC surface analysis | Interface enumeration with security metadata |
| impacket | fortra | https://github.com/fortra/impacket | Network protocol research | SMB/Kerberos/NTLM/DCE-RPC implementation and tooling |
| OleViewDotNet | James Forshaw | https://github.com/tyranid/oleviewdotnet | COM security analysis | Makes COM activation paths and DACLs legible; required for COM surface research |
| MSRC Security Update Guide | Microsoft | https://msrc.microsoft.com/update-guide/ | Patch tracking / research targeting | Ground truth for patch scope; use with BinDiff |
| WinDbg TTD — dx query language reference | Microsoft | https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/dx-provider-objects | Debugging / TTD | Unlocks LINQ-over-trace capability in TTD |
| sandbox-attacksurface-analysis-tools | James Forshaw / Google Project Zero | https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools | Security model analysis (tool) | S-TIER tool; listed here for completeness |
| symboliclink-testing-tools | James Forshaw / Google Project Zero | https://github.com/googleprojectzero/symboliclink-testing-tools | Link primitive research (tool) | S-TIER tool; listed here for completeness |
