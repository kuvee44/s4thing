# Chapter 14 — Researchers, Blogs & Research Arcs

> This chapter profiles the primary researchers whose work defines Windows security research. For each researcher, the goal is not just a link — it is understanding their **methodology**, their **research arc**, and what a new finding from them signals. Reading their work as a unified body, not a list of blog posts, is what separates oriented reading from noise collection.

---

## Tier 1 — Core Windows Security Research

### James Forshaw (tiraniddo)

**Blog:** https://www.tiraniddo.dev/
**GitHub / Tools:** https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools
**Employer:** Google Project Zero
**Focus:** Windows security model, COM/DCOM, object manager namespace, sandbox escapes, token internals

**Research arc:** Forshaw is the authoritative source on the Windows security model as a whole. His work is distinctive because he does not just find bugs — he builds tools to *enumerate attack surface* systematically. His NtObjectManager PowerShell toolkit lets anyone explore the same surfaces he researches.

His core research threads:
- **Object manager namespace attacks:** Symbolic links, directory object DACLs, device map redirection. Culminated in DEF CON 25 talk "Abusing the NT Object Manager Namespace." The key insight: the object namespace is not just storage — it is a privilege boundary with misconfigurations.
- **COM/DCOM security:** An entire blog series analyzing every COM security layer — activation permissions, launch permissions, access permissions, impersonation levels, elevation moniker. Each post maps a distinct attack surface. Essential before doing any COM-related LPE or sandbox escape research.
- **Arbitrary write exploitation:** The canonical "Windows Exploitation Tricks" blog series (2017–2018) — arbitrary file write to SYSTEM, directory creation to file read, NtSetInformationFile rename primitive. These posts created the vocabulary for Windows LPE exploitation chains.
- **Token and security descriptor internals:** His book (Windows Security Internals, 2023) consolidated 15+ years of research into a single authoritative reference.
- **Sandbox escapes:** Numerous Chrome/Edge sandbox escapes via Windows object manager, COM, and token bugs.

**How to read him:** The blog search is poor. Use Google `site:tiraniddo.dev [topic]`. Start with the DEF CON 25 talk for object manager. Read the "Windows Exploitation Tricks" label on the Project Zero blog for exploitation techniques.

---

### itm4n (Clément Labro)

**Blog:** https://itm4n.github.io/
**GitHub:** https://github.com/itm4n/
**Focus:** Windows LPE from a services/installers/token perspective; also UAC research and PrivescCheck

**Research arc:** itm4n is the most systematically practical LPE researcher. His work follows a consistent pattern: pick a Windows component that runs as SYSTEM, trace all file/registry/pipe operations with ProcMon, find one that can be influenced from a low-privilege context, exploit it.

Key publications:
- **PrintSpoofer (2020):** Named pipe squatting — catching the spooler's authentication via a crafted named pipe name, using `ImpersonateNamedPipeClient` to get a SYSTEM token. Made named pipe impersonation mainstream as a reliable SeImpersonatePrivilege escalation path.
- **CVE-2020-0668 (Service Tracing):** Windows service tracing writes to a log path stored in a HKLM registry key — but the key is writable by low-privileged users. Change the log path to an attacker-controlled junction, trace any service, trigger an arbitrary file write as SYSTEM.
- **CVE-2020-0787 (BITS):** BITS service RPC interface performs file operations without impersonating the caller — missing `ImpersonateClient()` call before `MoveFile()`. Junction redirect converts this into arbitrary file move as SYSTEM.
- **RpcEptMapper registry exploit:** The `HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper\Performance` key is writable by low-privileged users — allows registering a WMI Performance Counter DLL that gets loaded by WMI as SYSTEM.
- **CDPSvc DLL hijacking:** CDPSvc (Connected Devices Platform) runs as SYSTEM and is co-hosted with other services in the same svchost.exe — allows "token kidnapping" by injecting a DLL that then impersonates the SYSTEM token in the shared process.
- **FullPowers:** LocalService and NetworkService tokens have reduced privileges compared to what those accounts should have — task scheduler can be used to recover the full privilege set, enabling further escalation.
- **PrivescCheck:** PowerShell enumeration tool that checks for all the common LPE patterns — weak service permissions, token privileges, DLL hijacking paths, hot fixes, etc. Used as both an audit tool and a teaching resource.

**How to read him:** Start with PrintSpoofer to understand the named pipe impersonation pattern. Then read the CVE-2020-0668 post to understand the ProcMon → registry ACL → junction chain. These two posts cover the two most reusable LPE building blocks in his catalog.

---

### decoder / Andrea Pierini (splinter_code)

**Blog:** https://decoder.cloud/
**GitHub:** https://github.com/antonioCoco
**Focus:** Authentication coercion, NTLM relay mechanics, potato-family token impersonation, SeRelabelPrivilege

**Research arc:** Cocomazzi's work is best understood as a single extended research program. The connecting thread: *enumerate all Windows components that initiate authentication flows on behalf of privileged identities, and redirect those flows.*

The arc with direct references:

**1. Juicy Potato (2018)**
- **URL:** https://decoder.cloud/2018/01/13/potato-and-tokens/ (original analysis)
- **PoC:** https://github.com/ohpe/juicy-potato
- DCOM activation service (`rpcss!CRpcResolver::ClientResolveOXID`) initiates NTLM authentication as SYSTEM to resolve OXID references. Attacker registers a local COM server at the OXID endpoint — captures SYSTEM's NTLM auth — uses `ImpersonateNamedPipeClient` to get a SYSTEM-level token. Required: `SeImpersonatePrivilege` (IIS/SQL service contexts).

**2. RoguePotato (2020)**
- **URL:** https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/
- **PoC:** https://github.com/antonioCoco/RoguePotato
- Microsoft added loopback restriction: DCOM no longer contacts `127.0.0.1` OXID resolvers. Bypass: attacker routes OXID resolution via a `socat` relay to an external address that bounces back to local. The DCOM call traverses the network restriction by appearing to come from a non-loopback address. Same NTLM capture — different routing.

**3. LocalPotato / CVE-2023-21746 (2023)**
- **URL:** https://decoder.cloud/2023/01/05/localrelay/
- **CVE:** CVE-2023-21746 (patched January 2023)
- Abandons DCOM entirely. Operates at SSPI level. Two local processes can initiate NTLM against each other using the standard SSPI API (`InitializeSecurityContext` / `AcceptSecurityContext`). The AUTHENTICATE message from a Medium-IL process can be reflected to a SYSTEM-level named pipe server locally. This bypasses EPA (Extended Protection for Authentication) that blocks *network* NTLM relay because EPA checks are absent for local SSPI exchanges.

**4. Post-LocalPotato reflection analysis (Nov 2025)**
- **URL:** https://decoder.cloud/2025/11/local-ntlm-reflection-revisited/
- The CVE-2023-21746 patch blocked the specific code path. The structural property — NTLM between local processes using network-authentication-identical challenge-response semantics — was not addressed architecturally. Post maps remaining unpatched local SSPI authentication flows and conditions under which they retain exploit potential.

**5. NTLM→Kerberos relay survey (Apr 2025)**
- **URL:** https://decoder.cloud/2025/04/ntlm-kerberos-relay-comprehensive/
- Most comprehensive single reference on the relay attack space. Covers: NTLM handshake (challenge/response mechanics), all defensive mitigations (MIC — Message Integrity Code, EPA — Extended Protection for Authentication, channel binding, SMB signing enforcement), Kerberos relay (KrbRelayUp — RBCD-based), Shadow Credentials (manipulating `msDS-KeyCredentialLink`), S4U2Self/S4U2Proxy abuse. Includes decision tree: given an authentication coercion primitive, which relay paths are viable under which mitigation configurations.

**6. Windows Server 2025 NTLM changes (Feb 2026)**
- **URL:** https://decoder.cloud/2026/02/server2025-ntlm-changes/
- Documents Server 2025 enabling LDAP channel binding by default for all DCs (previously opt-in). Impact on impacket relay chains (`ntlmrelayx`), Responder, and tools that depend on LDAP relay. Also covers EPA expansion to additional services and updated SMB signing defaults.

**7. LmCompatibilityLevel and PDC trap (Apr 2026)**
- **URL:** https://decoder.cloud/2026/04/lmcompat-pdc-trap/
- Non-obvious interaction: when `LmCompatibilityLevel` ≤ 2 on a domain-joined workstation and authentication passes through the PDC Emulator for pass-through, NTLMv1 challenge-response can be coerced even when clients are configured to send NTLMv2 only — due to how the PDC Emulator normalizes the compatibility level during pass-through. Enables NTLMv1 cracking (known-plaintext for DES; hashcat mask attacks feasible in hours).

**Key insight from this arc:** When one relay/reflection path is closed, the structural property that enables it is not fully removed. Methodology: enumerate privileged components that authenticate, map all mitigation checkpoints per path, find paths where verification of caller identity is absent. The patch cadence confirms this: Microsoft consistently issues point fixes. That is how a researcher goes from JuicyPotato (2018) to still finding viable paths in 2026.

**SeRelabelPrivilege research:**
- **URL:** https://decoder.cloud/2019/11/12/windows-serelabelprivilege/
- Undernoticed privilege: allows raising an object's mandatory integrity label (normally you can only lower it). Some AV/EDR products grant this privilege. If an attacker lands in a process with SeRelabelPrivilege, they can raise a Low IL object to High IL — converting what looks like a constrained context into a full elevation primitive.

---

### j00ru (Mateusz Jurczyk)

**Blog:** https://j00ru.vexillium.org/
**Syscall tables:** https://j00ru.vexillium.org/syscalls/nt/
**Employer:** Google Project Zero
**Focus:** Kernel exploitation methodology, taint-based fuzzing (Bochspwn), Win32k, Windows registry kernel subsystem

**Research arc:** j00ru's distinguishing feature is building tools that find bugs *at scale* rather than finding individual bugs manually.

- **Bochspwn (BH 2013):** First systematic tool-driven approach to finding a kernel vulnerability class. Instruments Bochs x86 emulator to log all kernel memory accesses. Pattern: same user-mode address read twice without lock between reads = double-fetch TOCTOU. Found bugs present since NT4 era.
- **Bochspwn Reloaded (BH 2017):** Same framework, new pattern — *taint tracking*. Mark uninitialized bytes; detect if any tainted byte reaches a user-mode copy destination. Found ~30 kernel infoleak vulnerabilities. Critical for KASLR bypass work.
- **Bochspwn Revolutions (Infiltrate 2018):** Engineering refinements — better false positive reduction, taint persistence across function calls, pool taint on realloc cycles.
- **Registry kernel subsystem (BlueHat IL 2023):** Identified the Windows Configuration Manager (registry kernel code) as a systematically underexplored attack surface. Features with complex interactions: hive format, symbolic links, transactions (TxR), virtualization, predefined handles, layered keys. **35+ CVEs** from this phase. Core pattern: *feature interaction bugs* — each feature individually correct, combinations produce unvalidated code paths.
- **Registry exploitation (OffensiveCon 2024):** Exploitation companion. New bug class discovered during exploitation: hive-based memory corruption — cell map entries corrupted to yield arbitrary kernel read/write primitive architecturally different from pool heap corruption. **50+ CVEs** total by this point.
- **Registry confused deputies return (CONFidence 2024):** Variant hunting confirmation — same confused deputy class (predefined handle coercion, transaction+symlink, virtualization bypass) found again after initial patches. Point fixes, not root cause remediation.

**The methodology lesson:** j00ru doesn't find 1 bug; he finds 30–50. Reason: *subsystem selection* (pick underexplored complex subsystem) + *feature interaction enumeration* (test all combinations) + *exploitation research as discovery* (hard-to-exploit bug → find structural primitive nearby). Compare this to standard "read interesting function, find one bug" approach.

**Key publications with direct references:**

- **Bochspwn (BH 2013):** https://j00ru.vexillium.org/talks/blackhat-usa-bochspwn-identifying-0-days-via-memory-access-analysis/
- **Bochspwn Reloaded (BH 2017):** https://j00ru.vexillium.org/talks/blackhat-usa-bochspwn-reloaded-detecting-kernel-memory-disclosure/
- **Bochspwn Revolutions (Infiltrate 2018):** https://j00ru.vexillium.org/talks/infiltrate-bochspwn-revolutions/
- **Registry BlueHat IL 2023:** https://j00ru.vexillium.org/talks/bluehat-exploring-the-windows-registry-as-a-powerful-lpe-attack-surface/
- **Registry OffensiveCon 2024:** https://j00ru.vexillium.org/talks/offensivecon-practical-exploitation-of-windows-registry-vulnerabilities/
- **Registry REcon 2024:** https://j00ru.vexillium.org/talks/recon-peeling-back-the-windows-registry-layers/
- **Registry CONFidence 2024:** https://j00ru.vexillium.org/talks/confidence-windows-registry-deja-vu-the-return-of-confused-deputies/

**Syscall table resource:** https://j00ru.vexillium.org/syscalls/nt/ — NT and Win32k syscall numbers across all Windows versions from NT 3.1 to current. Essential for: finding new syscalls added in specific builds (new code = less audited), sandbox bypass research (win32k table = exact filter set), variant hunting across versions.

---

### Yarden Shafir

**Blog:** https://windows-internals.com/
**Focus:** Kernel pool internals, Windows 11 kernel exploitation, I/O Ring, kernel mitigations

**Key works:**
- **"The Pool is Dead, Long Live the Pool"** (with Ionescu): Transition from NT heap pool to Segment Heap in Windows 10 2004+. Documents why old pool overflow techniques broke and what the new allocation architecture looks like.
- **I/O Ring exploitation (2022):** Windows 11 introduced user-mode I/O Ring (similar to Linux io_uring). A UAF or OOB in the I/O Ring buffer registration can provide full kernel read/write primitive via the `IORING_BUFFER_INFO` array. Landmark primitive for Windows 11 kernel exploitation.
- **Kernel module tampering protection and LiveCloudKd research:** Hypervisor-protected kernel module integrity, VBS/HVCI security analysis.

---

### Alex Ionescu

**Blog:** https://windows-internals.com/ (contributor), conference talks
**Focus:** Windows internals, ALPC, boot process, VBS/Hypervisor architecture, kernel security features

**Key works:**
- **Co-author: Windows Internals 7th ed.**
- **ALPC research:** First public deep-dive into Advanced Local Procedure Call internals — port objects, connection model, message types, security context propagation.
- **Boot security and Secure Boot internals**
- **Windows mitigations:** EMET architecture, CFG design, VBS/HVCI threat model

---

### Connor McGarr

**Blog:** https://connormcgarr.github.io/
**Focus:** Windows kernel exploitation technique engineering, pool internals, CVE-to-exploit pipelines

**Key works:**
- Practical kernel exploitation posts — detailed step-by-step from bug to SYSTEM, covering pool feng shui for Segment Heap era, token stomping code patterns.
- I/O Ring follow-on analysis.

---

## Tier 2 — High Value (Windows + Adjacent)

| Researcher | Blog | Specialty |
|-----------|------|-----------|
| Google Project Zero team | https://googleprojectzero.blogspot.com/ | Multi-researcher; Forshaw, j00ru, Jann Horn, Tavis Ormandy |
| Pavel Yosifovich | https://scorpiosoftware.net/ | Kernel internals, driver development, Windows Internals book co-author |
| Adam Chester (xpn) | https://blog.xpnsec.com/ | Process injection, credential access, offensive .NET |
| Will Schroeder (harmj0y) | https://blog.harmj0y.net/ | Active Directory, Kerberos, GhostPack tooling |
| Benjamin Delpy | https://blog.gentilkiwi.com/ | Mimikatz, LSASS, credential extraction |
| Synacktiv team | https://www.synacktiv.com/publications.html | Windows vulns, car security, diverse research |
| MDSec | https://www.mdsec.co.uk/knowledge-centre/research/ | Red team tooling, COM research, process injection |
| SpecterOps | https://posts.specterops.io/ | Active Directory attack/defense, BloodHound, GhostPack |

---

## Tier 3 — Historical / Archived (Still Relevant)

| Researcher | Resource | Notes |
|-----------|---------|-------|
| FuzzySecurity (b33f) | https://www.fuzzysecurity.com/ | Windows post-exploitation, ETW usage, exploit development tutorials |
| SandboxEscaper | https://github.com/SandboxEscaper | 2018–2019 LPE 0-days; historical but excellent for understanding task scheduler, error reporting attack surfaces |
| Phrack archives | http://phrack.org/ | Classic kernel exploitation theory |

---

## Corporate / Team Research Feeds

| Source | URL | Signal Value |
|--------|-----|-------------|
| MSRC Blog | https://msrc.microsoft.com/blog/ | Microsoft's defensive perspective; root cause summaries for critical CVEs |
| Microsoft Security Blog | https://www.microsoft.com/security/blog/ | Threat intelligence, Active Directory attack analysis |
| Elastic Security Labs | https://www.elastic.co/security-labs/ | PPL bypass, LSASS access, kernel telemetry |
| Outflank | https://outflank.nl/blog/ | Red team tradecraft, Windows offensive techniques |
| NCC Group | https://research.nccgroup.com/ | Windows vulns, RPC/DCOM research, varied |
| Project Zero Issue Tracker | https://bugs.chromium.org/p/project-zero/issues/list?q=windows | Raw bug reports with PoC before blog write-ups appear |

---

## How to Follow Efficiently

**RSS feeds (priority order):**
1. https://googleprojectzero.blogspot.com/feeds/posts/default (all PZ posts)
2. https://www.tiraniddo.dev/ (RSS via Feedburner or direct)
3. https://itm4n.github.io/feed.xml
4. https://windows-internals.com/feed/

**Non-RSS signals:**
- MSRC Update Guide released second Tuesday each month: https://msrc.microsoft.com/update-guide/
- Project Zero issue tracker (before blog posts): https://bugs.chromium.org/p/project-zero/issues/list
- j00ru's vexillium blog for talks: https://j00ru.vexillium.org/

---

## References

- [R-1] tiraniddo.dev — James Forshaw — https://www.tiraniddo.dev/
- [R-2] itm4n.github.io — Clément Labro — https://itm4n.github.io/
- [R-3] decoder.cloud — Antonio Cocomazzi — https://decoder.cloud/
- [R-4] windows-internals.com — Shafir / Ionescu / Yosifovich — https://windows-internals.com/
- [R-5] j00ru.vexillium.org — Mateusz Jurczyk — https://j00ru.vexillium.org/
- [R-6] Google Project Zero Blog — https://googleprojectzero.blogspot.com/
- [R-7] Project Zero Issue Tracker — https://bugs.chromium.org/p/project-zero/issues/list
