# 05 · RPC / COM / ALPC / Named Pipes — RESOURCES.md

> **Section purpose:** Cover the Inter-Process Communication (IPC) mechanisms that form the largest attack surface in the Windows privilege boundary ecosystem. RPC, COM, ALPC, and Named Pipes are simultaneously the plumbing of Windows services and the richest seam for privilege escalation, lateral movement, and sandbox escape vulnerabilities.

---

## Table of Contents

1. [RPC — Remote Procedure Call](#1-rpc--remote-procedure-call)
2. [ALPC — Advanced Local Procedure Call](#2-alpc--advanced-local-procedure-call)
3. [COM — Component Object Model](#3-com--component-object-model)
4. [Named Pipes](#4-named-pipes)
5. [Authentication Coercion via RPC](#5-authentication-coercion-via-rpc)
6. [Tooling](#6-tooling)

---

## 1. RPC — Remote Procedure Call

---

### Entry 1.1

- **Title:** Finding and Exploiting Windows RPC Vulnerabilities (Tyranid's Lair)
- **Author / Organization:** James Forshaw / Google Project Zero
- **URL:** https://www.tiraniddo.dev/ *(search "RPC" — multiple posts; key: "Calling Local Windows RPC Servers from .NET", "Enumerating Windows RPC Servers")*
- **Resource type:** Blog series / tool documentation
- **Topic tags:** `RPC` `Windows-RPC` `MSRPC` `NtObjectManager` `endpoint-enumeration` `LPE` `attack-surface`
- **Difficulty:** Advanced
- **Historical or current:** Current (2019–2024 posts remain technically accurate)
- **Trust level:** ⭐⭐⭐⭐⭐ — Forshaw is the primary Windows IPC security researcher; posts are research primary sources
- **Why it matters:** Forshaw's RPC series established the methodology for systematic Windows RPC attack surface analysis. Before these posts, RPC research required expensive reverse engineering tools. The NdObjectManager/.NET approach democratized RPC server enumeration and client stub generation, enabling a generation of researchers to find RPC bugs systematically.
- **What it teaches:**
  - How to enumerate running RPC servers and their interfaces using `ncalrpc`, `ncacn_np`, `ncacn_ip_tcp` endpoints
  - How to call RPC methods from .NET/PowerShell using NtApiDotNet generated stubs
  - How to identify RPC interfaces that run as SYSTEM or elevated contexts
  - Security descriptor analysis for RPC endpoints: who can call what
  - Methodology: enumerate → generate client → fuzz → trace access checks
- **Best use:** Read all RPC-tagged posts on tiraniddo.dev in chronological order. Run the enumeration examples on a live Windows system alongside reading.
- **Related bug classes / primitives:** RPC Endpoint Security, Token Impersonation via RPC, ALPC Transport, COM/DCOM
- **Suggested next resource:** Entry 1.4 (NtObjectManager tools) and Entry 1.5 (FindRunningRPCServer)
- **Notes:** The `NtApiDotNet` library (part of sandbox-attacksurface-analysis-tools) is required to follow the blog examples. Install via `Install-Module NtObjectManager` in PowerShell.

---

### Entry 1.2

- **Title:** ALPC — Advanced Local Procedure Call (Windows Internals)
- **Author / Organization:** Mark Russinovich, Alex Ionescu, David Solomon, Andrea Allievi / Microsoft Press
- **URL:** *Windows Internals, Part 1 (8th edition), Chapter 8 — I/O System; and Chapter 3 for ALPC*; supplemental: https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools
- **Resource type:** Book (foundational reference) + tool supplemental
- **Topic tags:** `ALPC` `IPC` `Windows-internals` `kernel` `FOUNDATIONAL` `LPE` `RPC-transport`
- **Difficulty:** Advanced
- **Historical or current:** Current (ALPC design is stable; security implications evolve)
- **Trust level:** ⭐⭐⭐⭐⭐ — Microsoft Press; Ionescu is the co-author of the ALPC implementation
- **Why it matters:** ALPC is the kernel-level IPC primitive underlying all RPC calls, COM inter-process calls, and many Windows service communications. Understanding ALPC at the kernel level (port objects, connection objects, message queues, view sections) is necessary to understand the full stack from RPC API call down to kernel object.
- **What it teaches:**
  - ALPC port objects: server port, connection port, communication port hierarchy
  - Message types: datagram, synchronous request/reply, asynchronous
  - ALPC security: port security descriptor controls who can connect
  - View sections: shared memory mapped via ALPC for large data transfer
  - How ALPC is used as the RPC transport for `ncalrpc` and COM DCOM calls
  - ALPC debugging: `!alpc` WinDbg extension
- **Best use:** Read Windows Internals Chapter 3 (or the ALPC chapter in your edition) before studying RPC-level attacks. Understanding the underlying transport explains why certain security boundaries are where they are.
- **Related bug classes / primitives:** RPC Security, ALPC Port Objects, COM IPC, Kernel Object Security
- **Suggested next resource:** Entry 1.1 (Forshaw RPC blog) to see practical security implications; Entry 3.9 (Sudo/ALPC security)
- **Notes:** Alex Ionescu gave several deep-dive talks on ALPC security at SyScan and Recon — search for "Ionescu ALPC" on YouTube. The `!alpc` WinDbg kernel debugger extension is essential for live analysis.

---

### Entry 1.3

- **Title:** COM Internals (Windows Internals, Part 1)
- **Author / Organization:** Mark Russinovich et al. / Microsoft Press
- **URL:** *Windows Internals, Part 1, Chapter 9 — Management Mechanisms (COM section)*
- **Resource type:** Book (foundational reference)
- **Topic tags:** `COM` `DCOM` `COM-internals` `Windows-internals` `FOUNDATIONAL` `activation` `marshaling`
- **Difficulty:** Intermediate–Advanced
- **Historical or current:** Current
- **Trust level:** ⭐⭐⭐⭐⭐
- **Why it matters:** COM is the architectural foundation of Windows services, shell extensions, UAC elevation, update mechanisms, and much of the Win32 API surface. Without understanding COM internals — activation, marshaling, security descriptors, apartment threading — COM-based security research is guesswork.
- **What it teaches:**
  - COM activation: how `CoCreateInstance` resolves CLSIDs to DLL/EXE servers via the registry
  - COM threading models: STA, MTA, free-threaded — and their security implications
  - DCOM transport: how `ncacn_ip_tcp`/`ncacn_np` DCOM activations work over the wire and locally
  - COM security: `LaunchPermission`, `AccessPermission`, `AuthenticationLevel`, `ImpersonationLevel`
  - In-process vs. out-of-process server activation and DLL surrogate (`dllhost.exe`)
  - COM object identity, reference counting, marshaling proxies/stubs
- **Best use:** Read before any COM-based bug research. Then use `OleViewDotNet` (Entry 6.2) to explore live COM registrations with the internals model in mind.
- **Related bug classes / primitives:** COM Elevation, DCOM LPE, UAC Bypass via COM, DLL Surrogate Hijacking
- **Suggested next resource:** Entry 3.8 (COM IRundown injection), Entry 1.1 (RPC layer beneath DCOM)
- **Notes:** The COM chapter in Windows Internals 7th/8th edition is more detailed than earlier editions. Alex Ionescu's "COM+ Internals" talk at Recon is a strong supplemental.

---

### Entry 1.4

- **Title:** NtObjectManager / sandbox-attacksurface-analysis-tools — RPC & COM Research Toolkit
- **Author / Organization:** James Forshaw / Google Project Zero
- **URL:** https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools
- **Resource type:** Open-source tool suite (PowerShell module + .NET libraries)
- **Topic tags:** `RPC` `COM` `ALPC` `attack-surface` `enumeration` `access-check` `NtObjectManager` `lab-tools`
- **Difficulty:** Intermediate (to use PowerShell API); Advanced (to read .NET source)
- **Historical or current:** Current (actively maintained)
- **Trust level:** ⭐⭐⭐⭐⭐ — Project Zero; the de facto research toolkit for this domain
- **Why it matters:** This is the single most important tooling repository for Windows IPC security research. It provides: COM/DCOM/RPC/ALPC enumeration, access check analysis, security descriptor parsing, token analysis, and full .NET interop with NT native APIs. No serious Windows IPC research is done without it.
- **What it teaches:**
  - How to enumerate all COM servers, their CLSIDs, and their security configurations
  - How to programmatically check whether a process can call a specific RPC endpoint
  - How to generate and call RPC stub code from .NET
  - ALPC port enumeration and security descriptor analysis
  - Access check simulation: `Get-AccessibleKey`, `Get-AccessibleFile`, etc.
- **Best use:** Install via PowerShell Gallery (`Install-Module NtObjectManager`) and explore interactively. Read Forshaw's blog posts while using the tools to reproduce the examples live.
- **Related bug classes / primitives:** All RPC/COM/ALPC/Named Pipe attack research; Token Analysis; Sandbox Analysis
- **Suggested next resource:** Entry 1.5 (FindRunningRPCServer); OleViewDotNet (https://github.com/tyranid/oleviewdotnet)
- **Notes:** `OleViewDotNet` (separate repo, same author) is the GUI companion for COM analysis. `Get-RpcServer`, `Get-RpcEndpoint`, and `Get-RpcClient` are the key RPC cmdlets to master.

---

### Entry 1.5

- **Title:** Finding Running RPC Server Information (Tyranid's Lair, 2022)
- **Author / Organization:** James Forshaw / Google Project Zero
- **URL:** https://www.tiraniddo.dev/ *(search "Finding Running RPC Server")*
- **Resource type:** Blog post
- **Topic tags:** `RPC` `endpoint-enumeration` `NtObjectManager` `ALPC` `attack-surface-mapping`
- **Difficulty:** Intermediate
- **Historical or current:** Current (2022)
- **Trust level:** ⭐⭐⭐⭐⭐
- **Why it matters:** This post demonstrates how to enumerate *all currently running* RPC servers and their exposed interfaces from unprivileged code using only ALPC enumeration. This enables systematic attack surface mapping without requiring a network connection or elevated access.
- **What it teaches:**
  - Using `Get-RpcServer` with `-ParseProcess` to extract interfaces from loaded modules
  - The NtApiDotNet approach to reading ALPC port objects to find RPC endpoint registrations
  - How to correlate running RPC interfaces with their security descriptors
  - Building a methodology for RPC server auditing: enumerate → identify high-privilege servers → check ACLs → fuzz interfaces
- **Best use:** Hands-on: run the PowerShell examples on a live system and build an inventory of exposed RPC interfaces. Cross-reference with PrintNightmare (Entry 5.1) and EfsRpc (Entry 5.2) as known-exploitable examples.
- **Related bug classes / primitives:** RPC Attack Surface, ALPC Enumeration, Interface Discovery
- **Suggested next resource:** Entry 1.6 (RPC Firewall for defense side); Entry 5.1 (PrintNightmare as a case study)
- **Notes:** The enumeration technique uses `NtObjectManager` version 2.0+. If interfaces show `AuthenticationLevel = None` or `AuthenticationLevel = Connect`, they may be callable without credentials — prioritize those.

---

### Entry 1.6

- **Title:** RPC Firewall — RPC Attack Surface Reduction and Monitoring
- **Author / Organization:** Zero Networks (OMRI security)
- **URL:** https://github.com/zeronetworks/rpcfirewall
- **Resource type:** Open-source tool + blog posts
- **Topic tags:** `RPC` `defense` `attack-surface-reduction` `monitoring` `RPC-firewall` `logging`
- **Difficulty:** Intermediate
- **Historical or current:** Current (actively maintained)
- **Trust level:** ⭐⭐⭐⭐ — Zero Networks published research-backed tool; widely deployed
- **Why it matters:** RPC Firewall provides granular RPC call filtering and logging that Windows itself does not offer. For researchers, it is invaluable for: (1) understanding which RPC interfaces are called during privilege escalation attempts, (2) building detections for known attacks, (3) reducing attack surface in hardened environments.
- **What it teaches:**
  - How to filter RPC calls by interface UUID, method opnum, caller process, or security context
  - The internal mechanism: a RPC runtime filter hook
  - How RPC Firewall detects and blocks PrintNightmare, PetitPotam, and coercion attacks at the RPC layer
  - The relationship between RPC interfaces and their attack potential (any interface callable by non-admin that triggers a SYSTEM operation)
- **Best use:** Deploy in a lab alongside attack PoCs. Enable verbose logging and observe RPC call chains during exploitation. Use to build custom detections.
- **Related bug classes / primitives:** Authentication Coercion, RPC Attack Surface, Lateral Movement
- **Suggested next resource:** Entry 5.1 (PrintNightmare) and Entry 5.2 (PetitPotam) — use RPC Firewall to observe these attacks
- **Notes:** RPC Firewall is also a detection data source for SIEM/EDR. The companion blog posts from Zero Networks explain the filtering logic and threat model.

---

## 2. ALPC — Advanced Local Procedure Call

---

### Entry 2.1

- **Title:** Sudo on Windows — ALPC Port Security Research
- **Author / Organization:** James Forshaw / Google Project Zero
- **URL:** https://www.tiraniddo.dev/ *(search "sudo windows" or "ALPC security" — 2024 posts)*
- **Resource type:** Blog post(s)
- **Topic tags:** `ALPC` `sudo-for-windows` `LPE` `port-security` `2024`
- **Difficulty:** Advanced
- **Historical or current:** Current (2024)
- **Trust level:** ⭐⭐⭐⭐⭐
- **Why it matters:** When Microsoft introduced "sudo for Windows" in Windows 11, Forshaw analyzed its ALPC port security. This represents a current, real-world example of ALPC security analysis — how a new privileged IPC endpoint was designed, what its security descriptor allows, and whether an unprivileged process can abuse it.
- **What it teaches:**
  - How to analyze a new ALPC port: security descriptor, message format, expected callers
  - The threat model for privileged IPC endpoints — who should be able to connect?
  - Why ALPC port security descriptors matter and how to check them with NtObjectManager
  - Forshaw's methodology for rapidly assessing new privileged IPC mechanisms
- **Best use:** Read after understanding ALPC fundamentals (Entry 1.2). Demonstrates the practical analysis process on a current Windows feature.
- **Related bug classes / primitives:** ALPC Port Security, LPE, Privileged IPC
- **Suggested next resource:** Entry 1.4 (NtObjectManager for lab reproduction)
- **Notes:** The "sudo for Windows" research was published circa 2024 — check tiraniddo.dev for the full post. The broader lesson: any new Windows feature that introduces an ALPC/RPC endpoint is a research target.

---

## 3. COM — Component Object Model

---

### Entry 3.1

- **Title:** Relaying Kerberos Authentication from DCOM
- **Author / Organization:** James Forshaw / Google Project Zero
- **URL:** https://www.tiraniddo.dev/ *(search "Kerberos DCOM relay" — 2024)*
- **Resource type:** Blog post
- **Topic tags:** `DCOM` `Kerberos` `relay` `authentication-coercion` `LPE` `lateral-movement` `2024`
- **Difficulty:** Advanced
- **Historical or current:** Current (2024)
- **Trust level:** ⭐⭐⭐⭐⭐
- **Why it matters:** Demonstrates that DCOM activation can be used to coerce Kerberos authentication from a target machine, analogous to how MS-RPRN/MS-EFSR coerce NTLM. This opens DCOM as a coercion vector in environments where NTLM is restricted but Kerberos relay is possible (e.g., RBCD / S4U attacks).
- **What it teaches:**
  - How DCOM activation triggers Kerberos authentication when connecting to remote machines
  - The specific DCOM activation patterns that trigger outbound authentication
  - How to relay the resulting Kerberos ticket for Resource-Based Constrained Delegation (RBCD) attacks
  - The network-level behavior: what Wireshark shows during a DCOM coercion
- **Best use:** Advanced — requires solid Kerberos relay background. Read alongside Kerberos delegation resources.
- **Related bug classes / primitives:** Authentication Coercion, Kerberos Relay, RBCD, DCOM
- **Suggested next resource:** Entry 5.1–5.3 for other coercion methods; Kerberos relay literature (impacket, krbrelayx)
- **Notes:** Published in 2024 — represents a new dimension of the authentication coercion problem. Compare with PrivExchange and other coercion techniques.

---

### Entry 3.2

- **Title:** COM IRundown::DoCallback Injection
- **Author / Organization:** MDSec Research
- **URL:** https://www.mdsec.co.uk/research/ *(search "IRundown DoCallback")* + https://googleprojectzero.blogspot.com/ (Forshaw original research)
- **Resource type:** Blog post / research paper
- **Topic tags:** `COM` `IRundown` `DoCallback` `process-injection` `DCOM` `elevation`
- **Difficulty:** Advanced
- **Historical or current:** Current
- **Trust level:** ⭐⭐⭐⭐ — MDSec is a reputable research firm; technique independently verified
- **Why it matters:** `IRundown::DoCallback` is an undocumented COM runtime interface that allows injecting a callback into any process that has COM initialized. When a SYSTEM process (e.g., a COM server running as SYSTEM) has COM initialized, this can be used as a process injection primitive without calling `CreateRemoteThread` or other noisy APIs.
- **What it teaches:**
  - The `IRundown` COM interface: its role in COM object cleanup and why it accepts arbitrary callbacks
  - How to locate COM-initialized processes via ALPC port enumeration
  - The RPC call sequence to invoke `DoCallback` in a target process
  - Why this technique evades many EDR hooks that only monitor `CreateRemoteThread`, `WriteProcessMemory`, etc.
- **Best use:** After understanding COM internals (Entry 1.3) and NtObjectManager enumeration (Entry 1.4). Requires reverse engineering of `combase.dll`.
- **Related bug classes / primitives:** Process Injection, COM Internals, ALPC, SYSTEM Token Acquisition
- **Suggested next resource:** Entry 1.3 (COM Internals), Entry 2.1 (ALPC research)
- **Notes:** The attack was partially mitigated but remains partially functional. Check latest EDR detections — this technique is known to AV/EDR vendors and signatures exist.

---

## 4. Named Pipes

*(Cross-reference with 08_bug_classes Entry 4.1 for named pipe impersonation details)*

---

### Entry 4.1

- **Title:** Named Pipe Security and Squatting Attacks — Overview
- **Author / Organization:** James Forshaw + itm4n + multiple CVE disclosures
- **URL:** https://www.tiraniddo.dev/ (search "named pipe") + https://itm4n.github.io/ (search "named pipe")
- **Resource type:** Blog posts / research collection
- **Topic tags:** `named-pipes` `pipe-squatting` `token-impersonation` `IPC` `LPE` `RPC-control`
- **Difficulty:** Intermediate
- **Historical or current:** Current
- **Trust level:** ⭐⭐⭐⭐⭐
- **Why it matters:** Named pipes are the IPC transport for RPC `ncacn_np`, SMB, SQL Server, and many Windows services. Understanding pipe security descriptors, squatting attacks, impersonation, and the `\RPC Control` directory is prerequisite knowledge for a large fraction of Windows LPE research.
- **What it teaches:**
  - Pipe DACL: who can open for read, write, or both
  - Impersonation level carried by a pipe token: identify, impersonate, delegate
  - Pipe squatting: creating `\\.\pipe\NAME` before a privileged service does
  - The `\RPC Control\` object directory trick: redirecting `\\.\pipe\NAME` via the NT namespace
  - How `ImpersonateNamedPipeClient` works and when it yields a usable token
- **Best use:** Use `pipelist.exe` (Sysinternals) and `Get-NtFile \\.\pipe\` (NtObjectManager) to inventory pipes on a live system. Look for pipes created by SYSTEM processes with permissive DACLs.
- **Related bug classes / primitives:** Token Impersonation, RPC Transport, SMB, Potato Exploits
- **Suggested next resource:** 08_bug_classes Entry 3.5 (PrintSpoofer as a named-pipe impersonation LPE)
- **Notes:** `Get-NtFile -Path \??\pipe -DirectoryAccess | Get-NtSecurityDescriptor` reveals pipe DACLs. Named pipes that allow `Everyone: ReadWrite` without a privileged impersonation level are squatting targets.

---

## 5. Authentication Coercion via RPC

---

### Entry 5.1

- **Title:** PrintNightmare — MS-RPRN Unauthorized RCE/LPE (CVE-2021-1675 / CVE-2021-34527)
- **Author / Organization:** Zhuowei Zhang, Qingyi Li, cube0x0 (PoC), Mimikatz team
- **URL:** https://github.com/cube0x0/CVE-2021-1675 + https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527
- **Resource type:** PoC + CVE advisory + multiple researcher writeups
- **Topic tags:** `MS-RPRN` `Print-Spooler` `RPC` `LPE` `RCE` `DLL-injection` `authentication-coercion` `CVE-2021-1675` `CVE-2021-34527`
- **Difficulty:** Intermediate
- **Historical or current:** Historical (patched); technique and coercion vector remain relevant
- **Trust level:** ⭐⭐⭐⭐⭐ — MSRC-confirmed; extensively reproduced
- **Why it matters:** PrintNightmare was arguably the highest-impact Windows vulnerability of 2021. The `MS-RPRN` interface's `RpcAddPrinterDriverEx` allowed unauthenticated domain users to install DLLs as SYSTEM on any machine running Print Spooler. Additionally, `MS-RPRN`'s `RpcRemoteFindFirstPrinterChangeNotification` became the canonical coercion primitive for forcing NTLM/Kerberos authentication from remote machines.
- **What it teaches:**
  - How the MS-RPRN RPC interface works: its authentication requirements (domain user is sufficient), exposed methods
  - The DLL injection path: `RpcAddPrinterDriverEx` → SYSTEM loads arbitrary DLL
  - The coercion path: `FindFirstPrinterChangeNotification` → target machine connects back to attacker
  - Why disabling Print Spooler (`Stop-Service Spooler`) became the primary mitigation
  - How coercion-based attacks chain into NTLM relay (ntlmrelayx) or Kerberos RBCD attacks
- **Best use:** Run in a lab with impacket's `ntlmrelayx` to observe the coercion → relay → DA chain end-to-end. Compare to Entry 5.2 (PetitPotam) for the NTLM-only coercion variant.
- **Related bug classes / primitives:** Authentication Coercion, NTLM Relay, RPC Security, DLL Injection
- **Suggested next resource:** Entry 5.2 (PetitPotam), Entry 5.3 (coercion interfaces survey)
- **Notes:** Even after patching, the MS-RPRN coercion primitive (`FindFirstPrinterChangeNotification`) remains available from authenticated domain users — only the DLL injection path was fully patched. RPC Firewall (Entry 1.6) can block the coercion.

---

### Entry 5.2

- **Title:** PetitPotam — EFSRPC Authentication Coercion (CVE-2021-36942)
- **Author / Organization:** topotam (Gilles Lionel)
- **URL:** https://github.com/topotam/PetitPotam + https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942
- **Resource type:** PoC + CVE advisory
- **Topic tags:** `MS-EFSR` `EfsRpcOpenFileRaw` `authentication-coercion` `NTLM-relay` `RPC` `LPE` `domain-escalation` `unauthenticated`
- **Difficulty:** Intermediate
- **Historical or current:** Historical (partial patch); unauthenticated coercion partially fixed; authenticated coercion remains
- **Trust level:** ⭐⭐⭐⭐⭐ — Widely reproduced; CVE-confirmed
- **Why it matters:** PetitPotam demonstrated that the MS-EFSR (Encrypting File System Remote Protocol) interface's `EfsRpcOpenFileRaw` method could be called unauthenticated to force any Windows machine to authenticate to an attacker. When chained with NTLM relay to AD CS (Active Directory Certificate Services), it produced a complete unauthenticated domain compromise primitive. Triggered a wave of coercion research.
- **What it teaches:**
  - How `EfsRpcOpenFileRaw` triggers outbound authentication from the server
  - The NTLM relay chain: coerce → relay to AD CS HTTP endpoint → certificate request → pass-the-certificate → domain admin
  - Why unauthenticated RPC calls are uniquely dangerous
  - The partial Microsoft patch (authentication requirement added) and why authenticated coercion remains a problem
  - Broader coercion methodology: any RPC method that causes the server to open a UNC path triggers authentication
- **Best use:** Lab with impacket `ntlmrelayx` + Certipy (AD CS tool). Observe the full chain. Then study the partial patch to understand what was and wasn't fixed.
- **Related bug classes / primitives:** Authentication Coercion, NTLM Relay, AD CS Abuse, RPC Security
- **Suggested next resource:** Entry 5.3 (other coercion interfaces); AD CS abuse resources
- **Notes:** The authenticated variant (valid domain user required) of EfsRpc coercion was NOT fully patched and remains usable. RPC Firewall can block specific EFS opnums. Multiple tools (Coercer, DFSCoerce) generalize this pattern.

---

### Entry 5.3

- **Title:** Authentication Coercion Interface Survey — MS-EFSR, MS-RPRN, MS-DFSNM, MS-FSRVP, MS-EVEN6
- **Author / Organization:** p0dalirius + various researchers
- **URL:** https://github.com/p0dalirius/Coercer + https://github.com/ly4k/Certipy (AD CS context)
- **Resource type:** Tool + survey research
- **Topic tags:** `authentication-coercion` `MS-EFSR` `MS-RPRN` `MS-DFSNM` `MS-FSRVP` `coercion-survey` `NTLM-relay` `Kerberos-relay`
- **Difficulty:** Intermediate
- **Historical or current:** Current (Coercer actively maintained and updated)
- **Trust level:** ⭐⭐⭐⭐ — p0dalirius is a well-regarded researcher; tool is extensively tested in the field
- **Why it matters:** The Coercer tool systematizes the discovery and exploitation of authentication coercion bugs across all known Windows RPC interfaces. It documents which interface/method combinations trigger authentication, from which account, and with what authentication type (NTLM vs Kerberos). Essential reference for both offensive research and defensive enumeration.
- **What it teaches:**
  - Full survey of coercible RPC interfaces as of 2023–2024
  - The pattern common to all coercion bugs: method accepts UNC path → server connects to UNC → authenticates
  - How to test a specific interface for coercibility
  - Differences between coercion methods: some require domain auth, some are unauthenticated, some produce NTLM only vs Kerberos-capable
  - Defense: which interfaces can be blocked via RPC Firewall without breaking functionality
- **Best use:** Run Coercer in assessment mode to enumerate available coercion methods in a lab domain. Compare findings to RPC Firewall rules.
- **Related bug classes / primitives:** Authentication Coercion, NTLM Relay, Kerberos Relay, AD CS Abuse
- **Suggested next resource:** Entry 1.6 (RPC Firewall for defense), Entry 3.1 (Kerberos DCOM relay)
- **Notes:** "DFSCoerce" (MS-DFSNM) and "ShadowCoerce" (MS-FSRVP) were discovered after PetitPotam following the pattern established by p0dalirius's research. The methodology is now: read the MS-* protocol spec → look for methods accepting UNC paths → test.

---

## 6. Tooling

---

### Entry 6.1

- **Title:** RpcView — RPC Endpoint Visualization and Decompilation
- **Author / Organization:** silverf0x / Jean-Marie Borello
- **URL:** https://github.com/silverf0x/RpcView
- **Resource type:** Open-source tool
- **Topic tags:** `RPC` `tooling` `endpoint-enumeration` `reverse-engineering` `IDL-decompilation`
- **Difficulty:** Intermediate
- **Historical or current:** Current (maintained with Windows 10/11 support)
- **Trust level:** ⭐⭐⭐⭐ — Widely used in the research community; open source
- **Why it matters:** RpcView is the graphical UI for RPC endpoint enumeration and IDL decompilation on Windows. It reads the in-memory RPC server data structures to recover interface UUIDs, procedure tables, and security configurations, and can generate approximate IDL for any registered interface — without symbols.
- **What it teaches:**
  - How to visually enumerate all running RPC servers and their interfaces
  - How the IDL decompiler reconstructs method signatures from RPC server data
  - Identifying interfaces by UUID and correlating with Microsoft protocol documentation (MS-RPRN etc.)
  - The RPC runtime data structures (RPC_SERVER_INTERFACE, MIDL_SERVER_INFO, etc.)
- **Best use:** Run alongside NtObjectManager for cross-validation. Use IDL decompiler output as a starting point for custom RPC client code. Compare to Forshaw's NdApiDotNet output.
- **Related bug classes / primitives:** RPC Attack Surface, Interface Discovery, Protocol Reverse Engineering
- **Suggested next resource:** Entry 1.4 (NtObjectManager for scripted analysis); Entry 1.1 (Forshaw RPC blog)
- **Notes:** RpcView may need to run as administrator to access all server data. Combine with Process Monitor RPC tracing for a complete picture.

---

### Entry 6.2

- **Title:** impacket — Python RPC/SMB/Kerberos Toolkit
- **Author / Organization:** Fortra (formerly SecureAuth / Core Security) + community
- **URL:** https://github.com/fortra/impacket
- **Resource type:** Open-source library + collection of offensive scripts
- **Topic tags:** `impacket` `RPC` `SMB` `DCOM` `Kerberos` `NTLM` `Python` `tooling` `lab-tools`
- **Difficulty:** Intermediate (to use scripts); Advanced (to write custom RPC clients)
- **Historical or current:** Current (actively maintained)
- **Trust level:** ⭐⭐⭐⭐⭐ — Industry standard; used by every serious Windows security researcher
- **Why it matters:** impacket is the Python implementation of nearly every Windows network protocol (SMB, RPC, DCOM, Kerberos, NTLM, LDAP, etc.). It is simultaneously a research toolkit, an exploitation framework, and a learning resource. Understanding the impacket source is equivalent to understanding the protocols themselves.
- **What it teaches:**
  - MS-RPC over SMB and TCP transport implementation
  - NTLM authentication state machine: `NtlmClient`, `NtlmServer`, relay implementation
  - Kerberos ticket handling: AS-REQ, TGS-REQ, S4U2Self, S4U2Proxy
  - DCOM activation: `DCOMConnection`, `IWbemServices`, etc.
  - SMB2 dialect negotiation and session setup
  - `ntlmrelayx`: the NTLM relay chain used with PrintNightmare, PetitPotam, and other coercions
- **Best use:** Clone the repo and read the `impacket/` library source for the protocols you're studying. Run the example scripts with Wireshark to observe the on-wire behavior. Custom RPC clients can be built by adapting `examples/rpcdump.py` patterns.
- **Related bug classes / primitives:** NTLM Relay, Authentication Coercion, Kerberos Relay, DCOM, SMB
- **Suggested next resource:** Entry 5.1–5.3 (coercion attacks that use ntlmrelayx)
- **Notes:** `secretsdump.py`, `ntlmrelayx.py`, `getST.py` (S4U2), and `wmiexec.py` are the most study-worthy scripts. The `impacket/krb5/` module is the best open-source Kerberos implementation for learning the protocol.

---

*Last updated: 2026-04-22 · Maintained as part of the windows-research-vault*
