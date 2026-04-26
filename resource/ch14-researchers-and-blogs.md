# Chapter 14 — Researchers, Blogs & Research Arcs

> This chapter profiles the primary researchers whose work defines Windows security research. For each researcher, the goal is not just a link — it is understanding their **methodology**, their **research arc**, and what a new finding from them signals. Reading their work as a unified body, not a list of blog posts, is what separates oriented reading from noise collection.
>
> The structure is deliberately asymmetric: researchers with deep, analyzable methodology arcs get full sections. Those with narrower or more recent catalogs get compressed coverage. Depth is proportional to methodological density, not to fame.

> **Navigation:** Researcher profiles link to their relevant work covered in: ch13 (CVE case studies), ch16 (talks), ch15 (tools they maintain).

---

## Tier 1 — Core Windows Security Research

### James Forshaw (tiraniddo)

**Blog:** https://www.tiraniddo.dev/
**Project Zero Blog posts:** https://googleprojectzero.blogspot.com/ (search "Forshaw")
**GitHub / Tools:** https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools
**Employer:** Google Project Zero
**Focus:** Windows security model, COM/DCOM, object manager namespace, sandbox escapes, token internals, AppContainer

**Research arc:**

Forshaw is the authoritative source on the Windows security model as a complete system. His work is distinctive in a way that is not immediately obvious: he does not primarily find individual bugs — he builds *tools that enumerate attack surfaces*, then finds bugs from the surface map. NtObjectManager (PowerShell) and the broader `sandbox-attacksurface-analysis-tools` toolkit are not byproducts of his research — they are the core methodology. The bugs come from having a complete, queryable map of the object namespace, COM registrations, token structures, and security descriptor configurations.

This approach is fundamentally different from reading source code or tracing syscalls manually. It means that anyone using NtObjectManager can re-run the same enumeration he runs. The attack surface does not disappear when a specific bug is patched — it remains enumerable, and the *next* misconfiguration will appear in the same query results.

**Core research threads with specific publications:**

**Thread 1: Object manager namespace as attack surface**

The object namespace (`\`, `\Device`, `\BaseNamedObjects`, `\Sessions\N\BaseNamedObjects`) is not a passive storage system — it is a privilege boundary with its own ACLs, its own link resolution semantics, and its own trust model. Forshaw was the first to systematically characterize it as an *attack surface*.

Key posts in this thread:
- **"Abusing the NT Object Manager Namespace" (DEF CON 25, 2017):** The foundational talk. Demonstrates that directory objects in the namespace have DACLs, that weak DACLs on `\BaseNamedObjects\Local\` allow low-privilege processes to create symbolic links that redirect named-object lookups for other processes. Shows device map redirection (`\??\` resolution path is per-process and modifiable). This is the primary conceptual reference for all subsequent symlink-based LPE work.
- **"Symbolic Link Confusion" (Project Zero blog):** Detailed breakdown of the six types of Windows symbolic links (NTFS junction, NTFS symlink, object manager symlink, DosDevice symlink, registry symlink, WNF state name symlink), the privilege required to create each, and which are useful for TOCTOU attacks. URL: https://googleprojectzero.blogspot.com/2015/08/windows-10hh-symbolic-link-mitigations.html
- **Device map and drive letter redirection:** Drive letters are resolved through `\??\DosDevices\C:` links in the process's device map object. The device map can be replaced. This allows redirecting `C:\Windows\System32` lookups to attacker-controlled paths without touching any NTFS symlinks.

**Thread 2: COM/DCOM security model**

COM has a layered security model (activation permissions, launch permissions, access permissions, impersonation level, elevation moniker, surrogate process identity) that most researchers treat as a black box. Forshaw mapped every layer with individual blog posts.

Key posts:
- **"COM in Sixty Seconds" series (tiraniddo.dev):** Working backwards from observed behavior, each post in this series isolates one COM security parameter and tests its boundaries. Not just documentation — each post includes PowerShell to reproduce the check.
- **"Calling Local Windows RPC Servers from .NET" (tiraniddo.dev):** Explains how to call local RPC interfaces from managed code without a full IDL/client stub. Used to enumerate ALPC interfaces. URL: https://www.tiraniddo.dev/2019/12/calling-local-windows-rpc-servers-from.html
- **"Sharing a Logon Session a Little Too Much" (Project Zero blog):** Token impersonation level confusion in COM activation — a COM object activating in a shared logon session could impersonate another user's token. URL: https://googleprojectzero.blogspot.com/2019/04/sharing-logon-session-little-too-much.html
- **COM elevation moniker attack surface:** The `Elevation:Administrator!new:{CLSID}` moniker instantiates a COM object in an elevated context. If the COM object exposes dangerous methods (file operations, process launch, service registration), any user can call them. Forshaw built tooling to enumerate all CLSIDs registered for elevation and test each one.

**Thread 3: Windows exploitation primitives ("Windows Exploitation Tricks" series)**

This Project Zero blog series (2017–2018) defined the vocabulary and technique set for a generation of LPE research.

Key posts with URLs:
- **"Windows Exploitation Tricks: Exploiting Arbitrary File Writes for Local Elevation of Privilege" (2018):**
  URL: https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html
  The canonical reference. Covers: `NtSetInformationFile FileRenameInformation` (file rename as arbitrary move primitive), `MoveFileEx MOVEFILE_DELAY_UNTIL_REBOOT` (delayed move executed at boot before DACLs are enforced on most paths), the junction + oplock TOCTOU pattern (BaitAndSwitch — set oplock on directory, privileged process opens directory, oplock fires, you swap the junction target, release oplock, privileged process writes to your chosen location). Then: converting the write to code execution via DLL hijacking, service binary replacement, or `WindowsApps\` manipulation.
- **"Windows Exploitation Tricks: Arbitrary Directory Creation to Arbitrary File Read" (2017):**
  URL: https://googleprojectzero.blogspot.com/2017/08/windows-exploitation-tricks-arbitrary.html
  An arbitrary directory creation primitive (SYSTEM creates a directory at an attacker-chosen path) can be converted to file read via hardlink creation. The trick: NTFS hardlinks can be created to files the creator doesn't own if the creator has a handle to the file. A SYSTEM-created directory can be manipulated via junction so that the hardlink points to a sensitive file (SAM, SYSTEM hive), then read by the low-privilege user who created the junction.
- **"Windows Exploitation Tricks: Exploiting Arbitrary Object Directory Creation for Local Elevation of Privilege" (2018):**
  URL: https://googleprojectzero.blogspot.com/2018/08/windows-exploitation-tricks-exploiting.html
  If a privileged process can be induced to create an object namespace directory at an attacker-controlled path (e.g., device map entry, named object), the attacker can pre-populate that namespace path with a symlink object. When the privileged process resolves a name through that directory, it follows the attacker's symlink.

**Thread 4: Token and security descriptor internals**

- **"Sharing a Logon Session a Little Too Much" (linked above):** The logon session SID in tokens, how sharing a logon session between processes at different privilege levels creates covert channels.
- **"You Can't Contain Me! Analyzing and Exploiting an Elevation of Privilege Vulnerability in Docker for Windows" (tiraniddo.dev):** Container isolation via object manager namespace — Windows containers use separate namespace sessions, and namespace escapes are viable sandbox escape vectors. URL: https://www.tiraniddo.dev/2018/03/you-cant-contain-me-analyzing-and.html
- **Windows Security Internals (book, No Starch 2023):** The definitive synthesized reference. Covers every concept that appears across his blog posts in systematic depth. URL: https://nostarch.com/windows-security-internals. If you read only one book in this vault, read this one.

**Thread 5: Sandbox escapes and AppContainer**

Many of Forshaw's Project Zero bugs are AppContainer or sandbox escapes. The pattern: AppContainer processes have access to objects marked `ALL APPLICATION PACKAGES` (S-1-15-2-1). LPAC (Less Privileged AppContainer) removes even that grant. Objects that grant `ALL APPLICATION PACKAGES: WRITE` but have not been updated for LPAC are escape vectors.

**How to read him:**
- Blog search is poor. Use: `site:tiraniddo.dev [topic]` and `site:googleprojectzero.blogspot.com forshaw [topic]`
- Start with the DEF CON 25 talk slides for object manager
- Read "Windows Exploitation Tricks" in full before touching any arbitrary-write LPE research
- The Project Zero issue tracker has raw bugs before blog posts: https://bugs.chromium.org/p/project-zero/issues/list?q=owner:forshaw

**2024–2025 updates:**

**"The COM-Back" — COM Activation Mechanism Analysis (Project Zero, January 2025)**
URL: https://googleprojectzero.blogspot.com/2025/01/the-com-back.html

Deep dive into how `CoCreateInstance` elevation works at the kernel/user boundary. Forshaw traces the full activation path: client calls `CoCreateInstance` with `CLSCTX_ACTIVATE_AAA_AS_IU` or an elevation moniker → `rpcss.dll` activation service receives the request → activation service creates an elevated COM process → the resulting token and process identity depend on the exact CLSID registration, LaunchPermission, RunAs value, and whether the CLSID is registered in HKLM or HKCU. The vulnerability class: certain CLSID registrations allow the activating user to influence the resulting token's integrity level or the impersonation context of the elevated server.

Key finding: COM activation elevation involves a kernel-side logon session lookup that can be confused by manipulating the logon session context from a Medium IL process. The specifics involve how `rpcss!CActivationPropertiesIn::SetRequestedImpersonationLevel` interacts with the activation security check — a class of confused deputy bugs at the activation layer.

**Windows Registry — COM Activation Vulnerability (Project Zero 2024)**

A separate registry-ACL-based COM activation vulnerability: certain CLSID entries under `HKCU\Software\Classes\CLSID\` can shadow HKLM entries at COM activation time due to the user-hive merge during key resolution. A Medium IL process that creates a CLSID entry in `HKCU` matching a legitimate elevated CLSID causes the activation service to load the user-specified InprocServer32 in an elevated activation context.

**NtObjectManager v2.x (2024) — VTL/VBS inspection cmdlets**
GitHub: https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools

New cmdlets in the 2024 release cycle add VTL (Virtual Trust Level) inspection capabilities: `Get-NtVirtualTrustLevel`, `Get-NtSecureKernelObject`, and updated `Get-NtToken` that reports Isolated LSA token provenance. Useful for mapping the VTL0/VTL1 attack surface and understanding what Secure World objects are exposed to normal kernel mode.

> **Forshaw's tools:** ch15 §Cat1 (NtObjectManager, sandbox-attacksurface-analysis-tools). **His talks:** ch16 §Tier1 (Object Manager talk).

---

### itm4n (Clément Labro)

**Blog:** https://itm4n.github.io/
**GitHub:** https://github.com/itm4n/
**Focus:** Windows LPE from a services/installers/token perspective; UAC; PrivescCheck

**Research arc:**

itm4n is the most systematically practical LPE researcher in the Windows space. His methodology is explicit and highly reusable: pick a Windows component that runs as SYSTEM, use ProcMon to trace *all* file, registry, and pipe operations it performs, then find one operation that a low-privilege user can influence — either by controlling the destination (via junction or symlink), controlling the registry key that names the destination, or by being the client the service communicates with. The attack surface is the gap between "who this operation runs as" and "who controls this operation's parameters."

This methodology does not require a debugger or source code. It requires ProcMon and knowledge of which ACLs are misconfigured.

**Key publications with technical depth:**

**PrintSpoofer / CVE-2020-1048 (2020)**
URL: https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/

The Print Spooler adds named pipe paths for new printers. The pipe path is predictable and partially attacker-controlled. By registering a printer with a carefully crafted UNC path, an attacker can cause the spooler to connect to an attacker-controlled named pipe. The spooler connects at `Impersonation` level. The attacker calls `ImpersonateNamedPipeClient()` and receives a SYSTEM-level impersonation token.

What makes this significant beyond just the bug: it was the first reliable named pipe impersonation path for `SeImpersonatePrivilege` escalation that worked without the DCOM/NTLM complexity of Potato variants. After Juicy/Rogue Potato, most known `SeImpersonatePrivilege` paths involved DCOM — PrintSpoofer demonstrated that the Print Spooler itself is an authentication coercion primitive.

**CVE-2020-0668 — Windows Service Tracing (2020)**
URL: https://itm4n.github.io/windows-server-netman-dll-hijacking/
(Root CVE post): https://itm4n.github.io/cve-2020-0668-windows-service-tracing-eop/

The Windows service tracing mechanism logs service activity to a file. The log file path is configurable via a HKLM registry key. The key (`HKLM\SOFTWARE\Microsoft\Tracing\`) is writable by any user in the `NT AUTHORITY\NETWORK` group — which includes all network-facing service contexts. An attacker sets the log path to `C:\attacker-controlled-junction\filename`. Creates a junction at that path pointing to a target directory (e.g., `C:\Windows\System32\`). Enables tracing for any service. The SYSTEM-level tracing code creates the log file at the junction destination, writing to `C:\Windows\System32\filename`. Now an arbitrary file exists in System32. The second stage converts this to DLL hijacking or service binary replacement.

The ProcMon trace that found this: itm4n filtered for `CreateFile` operations by SYSTEM-level processes where the path contained a user-writable segment. This is the exact methodology — not source code review, not speculation. Filter → find → verify ACL → exploit.

**CVE-2020-0787 — BITS (Background Intelligent Transfer Service) (2020)**
URL: https://itm4n.github.io/bits-eop-addedit-file/

BITS is an RPC service that transfers files on behalf of requesting processes. It has an `AddFile`/`EditFile` RPC call where the caller provides source and destination paths. The BITS service performs the actual file operation — but *without calling `ImpersonateClient()` first*. This means the file operation runs as SYSTEM regardless of who called the RPC method. If you can supply a junction-redirected destination path, you get arbitrary file write/move as SYSTEM.

The root cause here is the classic "missing impersonation" pattern (see ch08). Every privileged service that performs file operations should call `ImpersonateClient()` before the operation and `RevertToSelf()` after. BITS omitted this for `MoveFile`. ProcMon confirmed the missing impersonation because the move operation appeared under the BITS process token, not the caller's token.

**RpcEptMapper Registry Exploit (2020)**
URL: https://itm4n.github.io/windows-registry-rpceptmapper-eop/

`HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper\Performance` is a registry key that allows registering a WMI Performance Counter DLL. WMI queries this key and loads the specified DLL in the WMI service context (SYSTEM). The key is writable by low-privilege users — this is a permissions oversight, not an intentional design. An attacker writes a `Performance` subkey with a `Library` value pointing to an attacker-controlled DLL. Next time WMI is queried for performance counters (or the attacker triggers it explicitly), WMI loads the DLL as SYSTEM.

This technique is significant because it requires no file operation primitives, no TOCTOU races, no impersonation of a client — it is a purely registry-ACL-driven DLL hijack.

**CDPSvc and Token Kidnapping (2021)**
URL: https://itm4n.github.io/cdpsvc-eop/

Connected Devices Platform Service (CDPSvc) runs as SYSTEM and is hosted in a shared `svchost.exe` along with other services. The svchost.exe process token is SYSTEM. An attacker who can load a DLL into CDPSvc's svchost.exe (via DLL hijacking — CDPSvc loads from directories the attacker can write to) inherits the SYSTEM token in the same process. The DLL can then call `OpenProcessToken(GetCurrentProcess(), ...)` and receive SYSTEM directly — no impersonation needed, because the process's own token is already SYSTEM.

**FullPowers (2020)**
URL: https://itm4n.github.io/fullpowers-restoring-service-account-privileges/
PoC: https://github.com/itm4n/FullPowers

`LocalService` and `NetworkService` tokens as they exist on a running service have reduced privileges — fewer than the account is actually entitled to by default. The reason: SCM (Service Control Manager) creates a restricted token for the service. Task Scheduler, by contrast, creates processes with the full token for the account. An attacker who is already running as `LocalService` or `NetworkService` can schedule a task under their own account identity — Task Scheduler creates the task process with the *full* token, which may include `SeImpersonatePrivilege` that was stripped from the service context. Now the attacker has `SeImpersonatePrivilege` and can use PrintSpoofer or GodPotato to get SYSTEM.

**PrivescCheck**
URL: https://github.com/itm4n/PrivescCheck

PowerShell enumeration tool. Checks: weak service binary permissions, writable service registry keys, PATH DLL hijacking opportunities, unquoted service paths, token privileges, hot fix inventory, scheduled task permissions, LSA settings. Used both as an audit tool and as a reading reference — each check in the source is an explanation of why that misconfiguration is a vulnerability.

**How to read him:**
- Start with PrintSpoofer → CVE-2020-0668 → CVE-2020-0787 in that order. Those three posts cover the three most reusable building blocks: named pipe impersonation, registry ACL + junction, missing impersonation in file move.
- His GitHub hosts working PoC for everything. Read the source alongside the post — the code is clear.
- PrivescCheck source is itself a learning resource; each enumeration function documents what it is looking for and why it matters.

**2024–2025 updates:**

**CVE-2025-21204 — Windows Update Installer Symlink Bypass for Administrator Protection**
URL: https://itm4n.github.io/cve-2025-21204-windows-update-installer-symlink/

Discovery and writeup of a symlink bypass in the Windows Update installer component that affects Administrator Protection — the JIT (Just-In-Time) elevation model introduced in Windows 11 24H2. Administrator Protection separates a user's standard token from a temporary elevated token generated on demand. The vulnerability: the installer's file operation logic follows junction points and NTFS symlinks during a specific update-application phase where the process runs with an intermediate privilege level. A low-privilege user can pre-position a symlink in the update staging path, causing the privileged installer to write to an attacker-chosen path.

Significance: Administrator Protection was designed as a replacement for the standard UAC elevation model. Finding a bypass in its very first generation (before wide deployment) is methodologically significant — itm4n applied the same ProcMon-based service tracing approach to a new Windows 11 component that most researchers had not yet examined.

**Administrator Protection JIT Token Bypass Series (2024–2025)**
URL: https://itm4n.github.io/ (search "Administrator Protection")

A multi-post series examining how the JIT token mechanism for Administrator Protection can be abused. The JIT mechanism creates a temporary elevated token scoped to a specific operation (UAC prompt), then destroys it after the operation completes. The research traces how the temporary token is handed to the calling process and what window exists between token creation and destruction for a racing attacker. Detailed analysis of the `ConsentUI.exe` interaction and the token security attributes that gate JIT elevation.

**PPL Process Enumeration with NtObjectManager (collaboration with Forshaw)**

itm4n demonstrated how NtObjectManager's `Get-NtProcess -Access 0` combined with `Get-NtProcessMitigationPolicy` provides a complete enumeration of PPL-protected process levels without requiring any elevated privileges. The technique reads publicly accessible kernel object attributes to map the PPL level (`PS_PROTECTED_TYPE`, `PS_PROTECTED_SIGNER`) of every running process — useful for pre-exploitation reconnaissance to understand which LSASS protection level is in play.

> **itm4n's tools:** ch15 §Cat1 (PrivescCheck), ch15 §Cat3 (SharpToken). **His CVEs:** ch13 §13.5 (PrintSpoofer), ch08 §6 (WinSxS DLL planting).

---

### decoder / Antonio Cocomazzi (splinter_code)

**Blog:** https://decoder.cloud/
**GitHub:** https://github.com/antonioCoco
**Focus:** Authentication coercion, NTLM relay mechanics, potato-family token impersonation, SeRelabelPrivilege

**Research arc:**

Cocomazzi's entire body of work is best understood as a single extended research program with one connecting thread: *find every Windows component that initiates authentication flows on behalf of privileged identities, and redirect those flows to an attacker-controlled endpoint*. Authentication coercion is a privilege escalation primitive — if you can cause SYSTEM to authenticate to you, and that authentication is at `Impersonation` level, you receive a SYSTEM impersonation token.

The arc spans from DCOM (2018) to SSPI (2023) to Kerberos relay analysis (2025) — each chapter driven by the previous chapter's mitigations.

**The arc with direct technical references:**

**1. Juicy Potato (2018)**
URL: https://decoder.cloud/2018/01/13/potato-and-tokens/
PoC: https://github.com/ohpe/juicy-potato

The DCOM activation service (`rpcss.dll`) resolves OXID (Object eXporter IDentifier) references by contacting the registered OXID endpoint. When activating a COM object, the activation service initiates NTLM authentication as SYSTEM to the OXID resolver address. An attacker who controls a local COM server at the OXID endpoint receives SYSTEM's NTLM authentication challenge-response. Capture that authentication → relay it to a local named pipe → call `ImpersonateNamedPipeClient()` → SYSTEM impersonation token.

Prerequisites: `SeImpersonatePrivilege` (standard for IIS application pool identities, MSSQL service, any `NetworkService`/`LocalService` account).

The specific DCOM CLSID used determines which security context performs the OXID resolution. Juicy Potato included a list of CLSIDs organized by their activation context (which ones activate as SYSTEM vs. as the calling user).

**2. RoguePotato (2020)**
URL: https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/
PoC: https://github.com/antonioCoco/RoguePotato

Microsoft patched Juicy Potato by adding a loopback restriction: the DCOM activation service would no longer contact OXID resolvers at `127.0.0.1`. This closed the "register a fake OXID resolver on localhost" path.

Bypass: route the OXID resolution through a `socat` TCP relay on an external machine (or even on the same machine but on a different interface). The DCOM service sees an external IP, not `127.0.0.1`, and contacts it. The external relay bounces the connection back to local. Same authentication capture, different routing geometry.

The key insight: the loopback restriction was a point fix on address comparison — it did not address the structural property that DCOM's OXID resolution initiates NTLM authentication as a privileged identity. As long as OXID resolution could be routed externally, the authentication could be captured.

**3. LocalPotato / CVE-2023-21746 (2023)**
URL: https://decoder.cloud/2023/01/05/localrelay/
CVE: CVE-2023-21746 (patched January 2023 Patch Tuesday)

After Microsoft tightened DCOM restrictions further, Cocomazzi pivoted away from DCOM entirely. The new angle: SSPI (Security Support Provider Interface) — the Windows authentication API layer.

Two local processes can negotiate NTLM with each other using the standard SSPI calls (`InitializeSecurityContext` on the client side, `AcceptSecurityContext` on the server side). The NTLM exchange between two local processes uses the same challenge-response format as network NTLM. Critically: EPA (Extended Protection for Authentication) — the mitigation that prevents network NTLM relay by binding authentication to the TLS channel — is not enforced for local SSPI exchanges. The kernel-mode NTLM implementation does not check channel binding tokens for loopback sessions.

This means a Medium-IL process can initiate an NTLM authentication as itself, and that authentication message can be reflected to a SYSTEM-level named pipe server locally — bypassing EPA entirely. The result: SYSTEM impersonation token without touching DCOM.

**4. Post-LocalPotato reflection analysis (November 2025)**
URL: https://decoder.cloud/2025/11/local-ntlm-reflection-revisited/

The CVE-2023-21746 patch blocked the specific code path that LocalPotato used. Cocomazzi's analysis post-patch: the structural property that made LocalPotato work — NTLM between local processes using the same challenge-response semantics as network NTLM, without EPA enforcement — was not architecturally addressed. The patch added a point check for the specific token reflection path.

The post maps remaining local SSPI flows: specific named pipe server implementations that accept NTLM locally without enforcing authentication binding, service-specific SSPI configurations where the server-side EPA policy is `Optional` rather than `Required`. These create remaining windows where local reflection retains escalation potential.

**5. NTLM→Kerberos relay comprehensive survey (April 2025)**
URL: https://decoder.cloud/2025/04/ntlm-kerberos-relay-comprehensive/

The most complete single document on the relay attack space as of 2025. Coverage:
- NTLM handshake mechanics (NEGOTIATE → CHALLENGE → AUTHENTICATE, where each mitigation checkpoint appears in the exchange)
- MIC (Message Integrity Code) — HMAC-MD5 over all three NTLM messages; prevents message tampering but does not prevent relay if the relay happens transparently
- EPA — channel binding token embedded in the AUTHENTICATE message; binds the authentication to the specific TLS session so a relay to a different TLS connection fails the binding check
- SMB signing — prevents relay to SMB targets by requiring each SMB packet to be signed with the session key, which the relay attacker cannot derive without the NT hash
- Kerberos relay via KrbRelayUp: Resource-Based Constrained Delegation (RBCD) — attacker with `GenericWrite` on a machine account creates a new machine account, sets RBCD from that new account to the target, uses S4U2Self/S4U2Proxy to obtain a service ticket as any domain user, including a DA
- Shadow Credentials: manipulating `msDS-KeyCredentialLink` on a target computer/user account to add attacker-controlled key credentials, then using PKINIT to authenticate as that account without knowing the password
- Decision tree: given a specific coercion primitive (PrintSpooler, PetitPotam/EFSR, MS-DFSNM, etc.) and a specific target service, which mitigations are in play and which relay paths remain viable

**6. Windows Server 2025 NTLM changes (February 2026)**
URL: https://decoder.cloud/2026/02/server2025-ntlm-changes/

Server 2025 ships with LDAP channel binding enforced by default for all Domain Controllers (previously: available but opt-in). This breaks the most common impacket `ntlmrelayx` chain: coerce authentication → relay to LDAP on DC → create new computer account or set RBCD. The relay now fails the channel binding check.

The post documents the impact on specific tool chains and configurations: `ntlmrelayx --no-smb-server`, Responder + relay, the exact conditions under which LDAP relay still works (when a DC has not yet been updated, or when channel binding is misconfigured). Also covers the EPA expansion to additional Windows services (LDAPS, HTTP with Negotiate) and updated SMB signing defaults for domain-joined machines.

**7. LmCompatibilityLevel and PDC Emulator trap (April 2026)**
URL: https://decoder.cloud/2026/04/lmcompat-pdc-trap/

Non-obvious interaction in domain authentication. When `LmCompatibilityLevel ≤ 2` on a domain-joined workstation and authentication is forwarded to the PDC Emulator for pass-through authentication (which happens when the authenticating DC cannot verify the credentials locally), the PDC Emulator normalizes the compatibility level during the NTLM pass-through — and under specific conditions, this normalization allows NTLMv1 challenge-response to be extracted even when the client is configured for NTLMv2 only.

Practical impact: NTLMv1 responses are breakable with known-plaintext attacks. The DES encryption used in NTLMv1 is feasible to crack with hashcat mask attacks within hours on GPU hardware. This creates a NTLMv1 downgrade path that survives `LmCompatibilityLevel = 5` on clients if the PDC Emulator condition is met.

**SeRelabelPrivilege research (2019)**
URL: https://decoder.cloud/2019/11/12/windows-serelabelprivilege/

Undernoticed privilege. `SeRelabelPrivilege` allows raising an object's mandatory integrity label — normally you can only lower it (you can always demote an object below your own IL, but cannot raise it above your IL without this privilege). Some AV/EDR products grant `SeRelabelPrivilege` to their service processes or user-mode components. If an attacker lands in a process that has this privilege, they can raise a Low-IL object's label to High IL, converting what looks like an IL-constrained escalation path into a full write primitive.

**Key structural insight from this entire arc:** Microsoft's patch cadence for authentication relay bugs is point-fix driven. Each specific coercion+relay+reflection path gets a targeted fix. The structural property — that Windows uses NTLM with the same challenge-response semantics in both network and local contexts, making authentication messages portable — is not and cannot easily be addressed architecturally without breaking compatibility. This is why Cocomazzi finds new relay paths 8 years after the original Potato.

---

### j00ru (Mateusz Jurczyk)

**Blog:** https://j00ru.vexillium.org/
**Syscall tables:** https://j00ru.vexillium.org/syscalls/nt/
**Employer:** Google Project Zero
**Focus:** Kernel exploitation methodology, taint-based fuzzing (Bochspwn), Win32k, Windows registry kernel subsystem

**Research arc:**

j00ru's distinguishing feature is *scale*. Where most researchers find 1–5 bugs in a research engagement, j00ru finds 30–50. The reason is not superior code reading skill — it is methodological: he builds tools that define a vulnerability class as a detectable pattern, then runs those tools systematically across the entire kernel rather than auditing one function at a time. The Bochspwn series is the canonical example of this approach.

**Bochspwn (Black Hat USA 2013)**
URL: https://j00ru.vexillium.org/talks/blackhat-usa-bochspwn-identifying-0-days-via-memory-access-analysis/

First demonstration of tool-driven systematic kernel vulnerability class discovery. The Bochs x86 CPU emulator is extended to log every memory access the kernel makes — physical address, virtual address, access type (read/write), calling context (which thread, which syscall). From this trace, j00ru extracts a pattern: *double-fetch* — the same user-mode address is read twice by the kernel within a single syscall dispatch without an appropriate lock between reads.

**Why double-fetch is a vulnerability class:** Kernel code frequently reads a value from user memory to validate it (e.g., `len <= MAX`), then reads the same value again to use it (e.g., `memcpy(dst, src, len)`). The attacker controls the user-mode page. A second thread running concurrently can modify `len` between the two reads — after validation but before use. If the modified value is larger than `MAX`, a heap or stack overflow occurs.

**The methodological innovation:** This is the first proof that vulnerability classes can be defined as temporal memory access patterns and detected mechanically across the entire kernel. The Bochs instrumentation intercepts every memory access in the emulated CPU and checks if the current access matches the pattern (same VA, read type, within the same syscall dispatch). No source code needed. Bugs found in NT4-era code that had survived undetected for 15+ years — not because they were subtle, but because no one had looked systematically.

Scale: multiple double-fetch bugs across `nt!NtXxx` syscall handlers, win32k, and driver code. Several had SYSTEM-level exploit chains.

**Bochspwn Reloaded (Black Hat USA 2017)**
URL: https://j00ru.vexillium.org/talks/blackhat-usa-bochspwn-reloaded-detecting-kernel-memory-disclosure/

Same Bochs framework, new vulnerability class: *kernel information disclosure via uninitialized memory*. The pattern:
1. The kernel allocates a stack frame or pool buffer
2. Some fields are written, some are not (union fields, padding, partially-populated arrays)
3. The uninitialized bytes are copied to a user-mode output buffer via `RtlCopyMemory`, `NtQuerySystemInformation`, an IOCTL return buffer, etc.
4. The user-mode caller receives those bytes — which may contain kernel pointers from previous uses of that memory, defeating KASLR

The detection mechanism: shadow memory. A parallel bitmap tracks whether each physical byte has ever been written since allocation. Any write to a user-mode address from a "tainted" (never-written) kernel byte is flagged.

**Why this matters post-KASLR (2017 context):** KASLR (Kernel Address Space Layout Randomization) was the primary mitigation against kernel exploitation at this point. Leaking a kernel pointer breaks KASLR and is a prerequisite for reliable kernel exploit chains. The Bochspwn Reloaded approach found ~30 infoleak bugs — structural sources of pointer leaks in `NtQuerySystemInformation` return structures, GDI object metadata, win32k font handler output buffers.

**Structural lesson:** Infoleaks are not one-off bugs — they arise from structural patterns in how C code handles structs:
- Padding bytes between fields (compiler inserts alignment padding that is never written by application code)
- Union members (union field `A` is initialized for one code path, field `B` for another; if full union size is copied, the unused field leaks)
- Partially-filled arrays (array of 10 elements, only 6 are written, all 10 are copied)

Manual variant search: `RtlCopyMemory` / `memcpy` calls where the source is a struct with explicit padding or tagged union layout. Still valid as a manual code review pattern post-2017.

**Bochspwn Revolutions (Infiltrate 2018)**
URL: https://j00ru.vexillium.org/talks/infiltrate-bochspwn-revolutions/

Engineering refinements to the Bochspwn framework that improved scalability:
- **Cross-boundary taint persistence:** Bochspwn 2013 tracked taint only within a single syscall dispatch function. Revolutions extends taint tracking across function call boundaries — if a function copies tainted data into a struct field and returns, the taint follows the struct to subsequent operations. This found double-fetch patterns that span multiple function calls.
- **Pool reallocation taint:** When a pool block is freed and reallocated to a different caller, Revolutions checks whether the new caller writes all bytes before reading them. Bytes from the previous allocation that are not overwritten retain their taint — a form of use-after-free information leak at pool reuse time.
- **False positive reduction:** The bottleneck in automated bug finding is false positive management. Revolutions documents the heuristics needed to filter intentional uses of uninitialized memory (PRNG seeding via stack noise, compiler-optimized loop unrolling patterns, `_mm_undefined_ps()` intrinsics). The lesson: *actionable signal requires false positive suppression*. More signals without suppression produces noise, not bugs.

Additional double-fetch bugs found in code paths that crossed DPC (Deferred Procedure Call) boundaries — impossible to detect with single-syscall-scope taint.

**Registry kernel subsystem series (2023–2024)**

j00ru's registry research represents the methodological evolution: from tool-driven instrumentation (Bochspwn) to systematic subsystem-level feature interaction enumeration.

The Configuration Manager (`cm.sys`, `nt!CmpXxx` functions) is the kernel subsystem that implements the Windows registry. It is large (hundreds of functions), has multiple complex features that interact with each other, and has historically received almost no public security attention. The registry research series treats it as a single complex attack surface rather than a collection of individual functions.

Features with complex security-relevant interactions:
- **Hive symbolic links** (`REG_LINK` values): A registry key value of type `REG_LINK` causes key lookups to follow a symlink to another key path. Low-privilege users can create `REG_LINK` values in some hive locations.
- **Registry transactions (TxR)**: The kernel supports transactional registry operations via KTM (Kernel Transaction Manager). A transaction can be created, keys modified within it, then either committed or rolled back. Transactions introduce isolation and versioning semantics.
- **Key virtualization**: UAC registry virtualization redirects writes to `HKLM\SOFTWARE\...` from non-elevated processes to `HKCU\Software\Classes\VirtualStore\...`. The mapping and redirection logic is in the kernel.
- **Predefined handles**: `HKEY_CLASSES_ROOT`, `HKEY_CURRENT_USER`, `HKEY_LOCAL_MACHINE` etc. are not real handles — they are pre-defined constants that the kernel resolves to real hive paths per-process. The resolution logic is in `CmOpenHiveFiles` and related code.
- **Layered keys** (Windows 10+): Registry key composition for container isolation. Multiple hive "layers" are composited into a single logical key view.

**The core bug class:** *Confused deputy / privilege boundary confusion*. A low-privilege caller passes a handle (predefined handle, transaction handle, or symlink) to a registry API. That handle is resolved through a privileged code path without re-checking the caller's security context. The registry operation proceeds with the caller's handle but the kernel's elevated privilege. Each feature (symlinks, transactions, virtualization, predefined handles, layered keys) adds a new resolution layer — each layer is a potential trust boundary crossing that the kernel must validate.

**Talk-by-talk breakdown:**

*BlueHat IL 2023:* Attack surface introduction. Establishes why the Configuration Manager is underexplored (complexity, lack of public research, multiple interacting features). Introduces the confused deputy class. First wave of CVEs from systematic feature interaction enumeration.

*OffensiveCon 2024:* Exploitation companion. The key new contribution: **hive-based memory corruption** as a primitive architecturally distinct from pool heap corruption. The registry stores all its data in "hive" files (`SYSTEM`, `SOFTWARE`, `SAM`, `NTUSER.DAT`) mapped into kernel memory. Within each hive, data is accessed via a cell map — an array of pointers that translates hive-internal cell offsets to kernel virtual addresses. If a bug allows corrupting a cell map entry (pointing it to an arbitrary kernel VA), subsequent registry operations that dereference that entry perform reads or writes at the arbitrary VA. This is kernel arbitrary read/write via the registry's own data structures — bypasses Segment Heap metadata protections entirely because it does not involve pool heap management at all.

*REcon 2024:* Hive binary format deep dive. Full analysis of `HBASE_BLOCK`, `HBIN` page structure, `_CM_KEY_NODE`, `_CM_KEY_VALUE`, cell allocation, and how the cell map provides O(1) offset→pointer translation. The most technically dense of the four talks — required reading before attempting to understand the hive-based corruption primitive.

*CONFidence 2024:* Variant hunting post-patch. After the initial CVE wave was patched, the same confused deputy pattern re-appeared in different code paths. Microsoft's fixes were consistently point fixes — blocking the specific function call path that the PoC exercised — rather than root-cause fixes that enforce privilege boundaries at the architectural layer (e.g., always revalidate the caller's security context after resolving any predefined handle). Variants were found by re-enumerating every code path that touches predefined handles, transactions, symlinks, or virtualization — the same enumeration that found the originals. **50+ CVEs total by the end of this series.**

**2024–2025 updates:**

**`NtQueryKey` Information Class Audit (2023–2024)**

Following the registry vulnerability series, j00ru extended the audit to every documented and undocumented `NtQueryKey` information class. Each information class returns a different structure — some include paths, some include security descriptors, some include internal cell offsets. The audit focused on three questions for each class: (1) Does it disclose kernel pointers? (2) Does it return data from an uninitialized buffer region? (3) Does it perform access checks on the key before returning sensitive fields? Several classes returned hive-internal metadata (cell offsets, internal reference counts) that, combined with the hive cell map primitive, could be used to infer kernel VA layout without a direct leak.

**Syscall Fuzzing Updates for Windows 11 — New Undocumented Syscall Discovery**
URL: https://j00ru.vexillium.org/syscalls/nt/

The Windows 11 2024 update cycle added new `NtXxx` syscalls to the NT table (additions visible in the version-by-version syscall table at j00ru's site). j00ru's fuzzing infrastructure was extended with updated structure definitions for new syscall parameter types introduced in recent builds. Specific findings from the new-syscall audit: several new syscalls dealing with kernel isolation (`NtCreateSecureObject`, class names anonymized until patch) reused parameter validation patterns from older syscalls without adapting the validation to the new object types, creating confused deputy surfaces in the new code.

**Syscall table resource**
URL: https://j00ru.vexillium.org/syscalls/nt/

NT and Win32k syscall numbers across every Windows version from NT 3.1 to current. Updated with each new build. Uses:
- Finding syscalls added in specific Windows versions: new syscalls = new code = less audited code
- Sandbox bypass research: the Win32k table is exactly what a win32k syscall filter (like Chrome's sandbox filter) blocks — cross-reference with the full table to find new syscalls the filter has not added yet
- Variant hunting across versions: if a syscall was added in Build X and later renamed or split, it may have missed a security fix that was applied to its predecessor

**Direct talk URLs:**
- Bochspwn BH 2013: https://j00ru.vexillium.org/talks/blackhat-usa-bochspwn-identifying-0-days-via-memory-access-analysis/
- Bochspwn Reloaded BH 2017: https://j00ru.vexillium.org/talks/blackhat-usa-bochspwn-reloaded-detecting-kernel-memory-disclosure/
- Bochspwn Revolutions Infiltrate 2018: https://j00ru.vexillium.org/talks/infiltrate-bochspwn-revolutions/
- Registry BlueHat IL 2023: https://j00ru.vexillium.org/talks/bluehat-exploring-the-windows-registry-as-a-powerful-lpe-attack-surface/
- Registry OffensiveCon 2024: https://j00ru.vexillium.org/talks/offensivecon-practical-exploitation-of-windows-registry-vulnerabilities/
- Registry REcon 2024: https://j00ru.vexillium.org/talks/recon-peeling-back-the-windows-registry-layers/
- Registry CONFidence 2024: https://j00ru.vexillium.org/talks/confidence-windows-registry-deja-vu-the-return-of-confused-deputies/

---

### Yarden Shafir

**Blog:** https://windows-internals.com/
**Twitter/X:** @yarden_shafir
**Employer:** CrowdStrike (previously SentinelOne)
**Focus:** Kernel pool internals, Windows 11 kernel exploitation, I/O Ring exploitation, kernel mitigations analysis, VBS/HVCI

**Research arc:**

Shafir's work sits at the intersection of kernel internals documentation and exploitation research. She writes at the level of detail normally reserved for Microsoft internal engineering documentation — full structure layouts, memory allocation mechanics, step-by-step primitive construction — and applies it to current exploitation research questions.

**Key publications with technical depth:**

**"The Pool Is Dead, Long Live the Pool" (with Alex Ionescu, 2020)**
URL: https://windows-internals.com/ (search "pool is dead")
Slides: https://github.com/yardenshafir/conference_talks

This paper documents the transition from the NT executive pool allocator (used since Windows NT 3.1) to the Segment Heap in Windows 10 2004 (20H1). The change broke virtually every pool exploitation technique that had been developed over the preceding decade.

**NT pool allocator (pre-2020):** Each pool allocation has a small header immediately preceding it containing `PoolType`, `BlockSize`, `PreviousSize`, `PoolTag`, and a pointer to the lookaside list. Overflowing a pool allocation corrupts the header of the next chunk. By controlling which header gets corrupted, attackers could perform pool header poisoning — redirecting the next `ExFreePool` call to a controlled location (classic "free-list overwrite" technique). Deterministic feng shui: fill the pool with controlled allocations to achieve predictable layout, then trigger the overflow.

**Segment Heap (Windows 10 2004+):**
- Pool headers are no longer stored adjacent to the allocation. Metadata (free list, size class information, backend state) is stored in a separate `SEGMENT_HEAP` structure, not inline with the allocation. Overflowing an allocation no longer directly reaches pool metadata.
- Free list randomization: the segment heap introduces randomized free list ordering for certain size classes. Deterministic layout predictions break.
- Multiple sub-allocators: Low Fragmentation Heap (LFH) handles small fixed-size allocations, Variable Size (VS) handles medium allocations, Backend handles large allocations. Each has different allocation semantics and different overflow behavior.
- What survives: Cross-cache attacks — an overflow into an allocation of type A can reach a physically adjacent allocation of type B if the heap layout places them together. This requires spraying allocations of type B around the target, which is possible but less deterministic. Use-after-free bugs are not affected by metadata separation — they still provide direct access to freed memory.

**Why this matters:** Any kernel pool exploitation research or exploit code written before Windows 10 2004 does not transfer to current systems without adaptation. The techniques in HEVD (which targets older Windows) need to be re-evaluated against the Segment Heap architecture.

**"One I/O Ring to Rule Them All: A New Attack Primitive on Windows 11" (2022)**
URL: https://windows-internals.com/one-io-ring-to-rule-them-all-a-new-attack-primitive-on-windows-11/

Windows 11 introduced `NtCreateIoRing`, `NtSubmitIoRing`, `NtQueryIoRingCapabilities` — a kernel-mode I/O ring analogous to Linux's `io_uring`. The user-mode API allows submitting batched I/O operations (read, write, `QueryDirectoryFile`, `RegisterBuffers`) through a shared ring buffer between user mode and kernel mode.

**The vulnerability class:** When a user-mode process registers buffers for I/O Ring operations (`IoRingRegisterBuffers`), the kernel stores references to those buffers in an `IORING_BUFFER_INFO` array. This array contains `{Buffer (kernel VA), Size}` entries. The kernel uses these entries to identify which kernel memory region corresponds to each registered buffer ID.

**The primitive construction:** If an attacker has *any* kernel bug that gives a single arbitrary write (OOB write, UAF write, type confusion write), they can overwrite one `IORING_BUFFER_INFO` entry to point `Buffer` to an arbitrary kernel VA and set `Size` to a large value. Then:
- Submit a read I/O to the corrupted buffer entry: kernel copies from the arbitrary kernel VA to a user-mode output buffer → **arbitrary kernel read**
- Submit a write I/O to the corrupted buffer entry: kernel copies from a user-mode input buffer to the arbitrary kernel VA → **arbitrary kernel write**

This converts a single-shot write-what-where into a full repeatable arbitrary read/write primitive, without additional bugs. The `IORING_BUFFER_INFO` array is the "stepping stone" that amplifies one weak write into complete kernel memory access.

**Significance:** Between 2022 and 2024, the I/O Ring primitive became the standard technique for Windows 11 kernel exploitation. Any 2022+ kernel exploit write-up that mentions "I/O Ring" is using this primitive. It effectively replaced the older bitmap-based arbitrary read/write techniques (GDI bitmap manipulation was patched; tagged pool-based primtives broke with Segment Heap) as the canonical post-corruption primitive.

**"LiveCloudKd and Hypervisor Analysis" research**

Shafir has published research on VBS (Virtualization-Based Security) internals and the LiveCloudKd technique — using Hyper-V virtualization infrastructure to gain access to the live kernel memory of a running VM from the host. This includes VTL0/VTL1 interaction (normal kernel vs. Secure World), HVCI (Hypervisor-Protected Code Integrity) enforcement mechanisms, and the security model that VBS-protected drivers operate under. Relevant for understanding the current upper bound on kernel exploitation (HVCI makes arbitrary code execution in the kernel much harder) and for research into the VTL1 attack surface.

**"Needle in a Needlestack" (OffensiveCon 2023)**
Research on finding rootkit activity in kernel memory by analyzing data structures from a forensic perspective. Covers: detecting hooked SSDT entries, finding hidden processes via EPROCESS walking vs. PspCidTable, detecting thread injection, analyzing kernel callbacks. Relevant for kernel forensics but also for understanding which kernel data structures are integrity-protected by HVCI vs. which remain modifiable.

**2024–2025 updates:**

**"Kernel Primitives in 2024" — WNF State as Kernel R/W Primitive**
URL: https://windows-internals.com/ (search "WNF 2024")

Research documenting Windows Notification Facility (WNF) state names as a new-generation kernel arbitrary read/write primitive, superseding I/O Ring in environments where I/O Ring has been partially mitigated. The WNF subscriber/publisher model allows user-mode processes to allocate `WNF_STATE_DATA` structures in kernel pool. A kernel bug that allows corrupting a `WNF_STATE_DATA.Header.AllocatedSize` or the data pointer transforms the WNF publish operation into a kernel-mode write to an arbitrary address. Similarly, subscribing with a corrupted state name handle and calling `ZwQueryWnfStateData` becomes a kernel read from an arbitrary address. The technique is notable because WNF state names have been in Windows since Windows 8 and the relevant kernel structures are well-documented via public symbols.

**Windows Internals Volume 3 (announced 2024)**
Co-authored with Pavel Yosifovich. The upcoming Volume 3 in the Windows Internals series (covering security architecture, virtualization, and the modern kernel stack in depth) was announced for publication. This will be the first new volume in the series specifically addressing VBS, HVCI, Secure Boot, and the Isolated User Mode stack at the same documentation depth as previous volumes.

**Hypervisor-Level Debugging and VTL1 Inspection**

Research into VTL1 (Secure World / Isolated LSA) inspection via the LiveCloudKd technique and extensions. Covers: using Hyper-V's virtual machine infrastructure to attach a kernel debugger to VTL1 (`SecureKernel.exe` + `Iums.dll`), enumerating VTL1 objects and their relationship to VTL0 kernel objects, and identifying the VTL1 attack surface (IUMDLL injection paths, Secure RPC channels, VTL1 syscall interface). This is the foundational research for anyone targeting the Secure World isolation boundary.

---

### Alex Ionescu

**Blog:** https://windows-internals.com/ (contributor)
**Twitter/X:** @aionescu
**Employer:** CrowdStrike (VP of EDR Strategy)
**Focus:** Windows internals documentation, ALPC, boot process and Secure Boot, VBS/Hypervisor architecture, kernel security features

**Research arc:**

Ionescu is primarily an *internals documentarian* rather than a vulnerability researcher — though the distinction matters less in a field where deeply understanding how something works is prerequisite to breaking it. His contributions are foundational: he mapped Windows subsystems that had never been publicly documented, wrote the book (literally — Windows Internals) that everyone else reads, and gave talks at conferences that established the vocabulary for subsequent research.

**ALPC internals (2011–2013)**

Before Ionescu's REcon 2011 talk, ALPC (Advanced Local Procedure Call — the modern replacement for LPC) was almost entirely undocumented. The port objects, connection model, message attribute types, and security context propagation were reverse-engineered and published for the first time. This is now the primary reference for any research involving ALPC-based IPC — which includes how COM, RPC over LRPC, and system service dispatch work internally.

Key references:
- REcon 2011: "nt!LpcRequestWaitReplyPortEx — The Story of the Undocumented System Call" — ALPC port objects, connection/server/communication port hierarchy, message attributes
- The ALPC structures documented in this work appear in WinDbg as `_ALPC_PORT`, `_ALPC_MESSAGE`, `_ALPC_PORT_ATTRIBUTES` — all from reverse engineering at that time, now partially reflected in public symbols

**Windows Internals book co-authorship**

Ionescu is co-author of Windows Internals 5th, 6th, and 7th editions (with Russinovich and Solomon). Chapter 7 (Security) of WI7 is the most complete publicly available documentation of the Windows security architecture. Chapter 2 (System Architecture) covers the executive subsystem map. These are canonical references throughout this vault.

**Boot security and Secure Boot internals**

Talks on Windows Secure Boot architecture, the Bootmgr/WinLoad trust chain, UEFI Secure Boot policy, BitLocker integration, and early-launch anti-malware (ELAM) drivers. Context for anyone researching the boot attack surface — bootkit detection evasion, UEFI firmware research.

**VBS/HVCI design**

Technical analysis of how VBS (Virtualization-Based Security) uses Hyper-V to protect kernel integrity. HVCI (Hypervisor-Protected Code Integrity) prevents non-Microsoft-signed kernel code from executing by enforcing that all kernel page table entries that are both writable and executable require VTL1 (Secure World) approval. The implication: arbitrary kernel code execution is significantly harder on HVCI-enabled systems — you can still read/write kernel memory (from a VTL0 kernel bug), but you cannot create new executable kernel pages without bypassing HVCI, which requires compromising VTL1.

**EMET architecture**

Analysis of Enhanced Mitigation Experience Toolkit (EMET) — the original user-mode exploit mitigation tool (DEP, ASLR, SEHOP, EAF, export table filtering). Historical but relevant for understanding what mitigations were added to the Windows kernel itself as EMET was sunset.

---

### Connor McGarr

**Blog:** https://connormcgarr.github.io/
**Focus:** Windows kernel exploitation technique engineering, pool feng shui, Segment Heap-era exploitation, CVE-to-exploit pipelines

**Research arc:**

McGarr occupies a specific niche: he takes a CVE or an exploitation primitive and writes the most complete publicly available step-by-step technical writeup of how to exploit it from start to SYSTEM. His posts are dense and methodical — not "here is the PoC," but "here is the annotated code at each stage of the exploitation chain, with the WinDbg commands to verify each step."

**Key publications:**

**"Exploit Development: Pool Corruption in the Age of Segment Heap" series**
URL: https://connormcgarr.github.io/pool-corruption-2/

Step-by-step kernel pool exploitation adapted for Windows 10 Segment Heap. Covers: understanding which pool type (NX non-paged, paged) a target allocation belongs to, spraying allocations to achieve controlled layout, cross-cache overflow mechanics (overflow from object type A into adjacent object type B), constructing a read primitive and write primitive from a controlled pool overflow in the Segment Heap era. Includes WinDbg verification at each step. The most practical reference for HEVD pool exploitation on modern Windows.

**"Exploit Development: Leveraging the I/O Ring for SYSTEM Privileges" (2022)**
URL: https://connormcgarr.github.io/ioring-exploits/

McGarr's follow-on implementation of Shafir's I/O Ring primitive, with full exploit code and step-by-step WinDbg trace. Demonstrates the complete chain: corrupt an `IORING_BUFFER_INFO` entry → use it for arbitrary kernel read to leak token address → use it for arbitrary write to replace token with SYSTEM token → create SYSTEM process. The code in this post is the reference implementation for the I/O Ring exploitation chain.

**Token stomping shellcode pattern**

Posts detailing the token replacement technique: given arbitrary kernel read/write, locate the current process's `_EPROCESS.Token`, locate SYSTEM's `_EPROCESS.Token` (via `PsInitialSystemProcess` exported symbol), overwrite current token with SYSTEM token. This is the standard privilege escalation payload for kernel exploits when arbitrary write is achieved. McGarr documents the full WinDbg inspection workflow for confirming the token swap worked.

---

## Tier 2 — High Value (Windows + Adjacent)

### Google Project Zero team

**URL:** https://googleprojectzero.blogspot.com/
**Issue tracker:** https://bugs.chromium.org/p/project-zero/issues/list?q=windows

Multi-researcher blog. For Windows research, the primary contributors are Forshaw and j00ru (both profiled above), plus:

- **Jann Horn:** Primarily Linux kernel and browser engine, but occasional Windows findings — notably cross-process handle table manipulation and speculative execution side channels (Spectre/Meltdown disclosure was joint PZ/Intel work)
- **Tavis Ormandy:** Primarily user-mode application vulnerabilities — antivirus engines, PDF parsers, decompression libraries — but Windows-hosted. His antivirus research (Sophos, Symantec, ESET) showed that code running with kernel-level access (AV drivers) frequently has exploitable parsing bugs.

**The issue tracker as a research resource:** Project Zero publishes bug reports 90 days after disclosure whether or not the vendor has patched. Each report includes root cause, often a PoC, and a timeline. Forshaw's issues in particular are detailed enough to reconstruct the vulnerability. The tracker frequently has technical detail that does not appear in the corresponding blog post.

### Pavel Yosifovich

**Blog:** https://scorpiosoftware.net/
**Focus:** Windows kernel internals, driver development, native API

Co-author of Windows Internals 7th edition. His blog covers kernel object internals, driver development techniques, and Windows native API behavior — at the implementation level (WinDbg traces, structure dumps), not just API documentation. Relevant as a complement to the security research-focused sources; his posts explain *how* kernel subsystems work, which is prerequisite to finding bugs in them.

### Adam Chester (xpn)

**Blog:** https://blog.xpnsec.com/

Process injection techniques (reflective DLL injection, module stomping, Early Bird APC injection), .NET CLR internals for offensive use, credential access. Heavy on Windows internals at the process level — EPROCESS, PEB, loader structures. Less vulnerability research, more technique engineering for post-exploitation.

### Will Schroeder (harmj0y)

**Blog:** https://blog.harmj0y.net/
**GhostPack:** https://github.com/GhostPack
**Focus:** Active Directory attack research, Kerberos protocol abuse, GhostPack tooling, ADCS

Will Schroeder's research arc is the most important single body of work on Active Directory offensive security. His output spans both the conceptual layer (how Kerberos actually works, what the protocol permits) and the tool layer (Rubeus, the reference implementation of everything Kerberos-related from an attacker's perspective).

**Key research threads:**

**Kerberoasting (2014–ongoing)**
URL: https://blog.harmj0y.net/powershell/kerberoasting-without-mimikatz/

Any authenticated domain user can request a Kerberos TGS (Ticket-Granting Service) ticket for any service account that has a `servicePrincipalName` (SPN) set. The TGS is encrypted with the service account's NTLM hash (RC4 by default, AES-256 if configured). The attacker takes the TGS offline and cracks it. If the service account has a weak password, the hash cracks to plaintext — giving credentials for the service account (which is often highly privileged). Will Schroeder popularized this attack and built the initial tooling. The key insight: no special privilege is required; any domain user can perform this request, because SPNs are publicly queryable from LDAP.

Variant: **AS-REP Roasting** — accounts with Kerberos pre-authentication disabled can be AS-REP roasted (request AS-REP for the account, extract the encrypted part, crack offline). Configured via the `DONT_REQUIRE_PREAUTH` account flag.

**Unconstrained Delegation Abuse**
Any machine account or service account with Unconstrained Delegation enabled (`TrustedForDelegation` flag in AD) stores the full TGT of any user who authenticates to it. If an attacker compromises a server with Unconstrained Delegation, they can extract TGTs from its memory using Mimikatz/Rubeus and use them to authenticate anywhere the TGT holder has access. Combined with PrinterBug coercion (MS-RPRN forcing a Domain Controller to authenticate to the compromised server), this becomes a path to Domain Admin.
- URL: https://blog.harmj0y.net/redteaming/not-a-security-boundary-breaking-forest-trusts/

**Constrained Delegation and S4U2Proxy**
URL: https://blog.harmj0y.net/activedirectory/s4u2pwnage/

Constrained Delegation allows a service to impersonate any user when contacting *specific* target services. The S4U2Self extension lets the service obtain a ticket to itself on behalf of any user (even without that user's TGT). S4U2Proxy then extends this to the configured target services. Attack path: compromise a service account with Constrained Delegation configured → use Rubeus S4U to get a ticket impersonating a domain admin → access the target service as domain admin.

Resource-Based Constrained Delegation (RBCD) — introduced in Windows Server 2012 — is more dangerous from an attacker's perspective: instead of requiring domain admin to configure delegation, the *target machine* controls who can delegate to it via `msDS-AllowedToActOnBehalfOfOtherIdentity`. Any principal with `GenericWrite` on a computer object can set RBCD to a machine they control, then impersonate any user to that computer. RBCD is the underpinning of KrbRelayUp (local privilege escalation) and "Wagging the Dog" (Elad Shamir's RBCD research).

**"Certified Pre-Owned" — ADCS attack classes (2021)**
URL: https://posts.specterops.io/certified-pre-owned-d95910965cd2 (whitepaper)
Co-authored with Andy Robbins.

The definitive reference on Active Directory Certificate Services (ADCS) offensive security. Catalogs ESC1–ESC8 (later extended to ESC13+) attack classes:
- **ESC1:** Certificate template allows `SubjectAltName` specified by requester AND Client Authentication EKU — any user can request a certificate for any other user (including Domain Admin) and authenticate as them
- **ESC3:** Certificate template for Certificate Request Agent + no enrollment restrictions — abuse to request certificates on behalf of any user
- **ESC4:** Writable certificate template ACL — user can modify template to enable ESC1
- **ESC6:** `EDITF_ATTRIBUTESUBJECTALTNAME2` flag on CA — enables SAN on all templates
- **ESC8:** NTLM relay to ADCS HTTP enrollment endpoint — relay a machine account's NTLM auth to ADCS, obtain a machine certificate, then use PKINIT to get a TGT
- **ESC9/ESC10:** Shadow credentials path via `GenericWrite` + ADCS

This paper fundamentally expanded the AD attack surface map; every AD pentest since 2021 runs ADCS enumeration as a standard step.

**Rubeus**
URL: https://github.com/GhostPack/Rubeus

C# implementation of Kerberos protocol operations directly against the Windows KDC (not using the Windows SSPI layer). Direct KDC communication gives more control and visibility than SSPI-based tools. Operations: AS-REQ/AS-REP (roasting, overpass-the-hash), TGS-REQ (Kerberoasting), S4U2Self, S4U2Proxy, PKINIT (certificate-based TGT), Pass-the-Ticket, Renew ticket, monitor for new logons. Source is the reference implementation for understanding what Kerberos requests actually look like on the wire.

### Benjamin Delpy (gentilkiwi)

**Blog:** https://blog.gentilkiwi.com/
**Mimikatz:** https://github.com/gentilkiwi/mimikatz

Author of Mimikatz. His blog covers the internals of Windows credential storage — LSASS memory structure, how WDigest/NTLM/Kerberos credentials are cached in memory, SSP (Security Support Provider) loading, the credential guard architecture. Reading his work explains *why* Mimikatz works the way it does — what structures it reads, why those structures are in LSASS's memory, and what protections (Credential Guard, PPL on LSASS) prevent credential access.

Key research:
- **WDigest credential caching:** WDigest stores plaintext credentials in LSASS memory (enabled by `UseLogonCredential = 1` in registry, or on older Windows by default). Delpy mapped the exact LSASS memory structures where WDigest stores them — `wdigest!l_LogSessList` linked list of `WDIGEST_CREDENTIALS` nodes with plaintext password field.
- **Kerberos ticket extraction:** `sekurlsa::tickets` dumps Kerberos tickets from LSASS memory. The tickets are extracted from `kerberos!KerbLogonSessionTable` structures. Understanding this is prerequisite to understanding Rubeus's `dump` command.
- **DPAPI master key extraction:** DPAPI (Data Protection API) uses user-specific master keys stored in `%APPDATA%\Microsoft\Protect\`. The master key is derived from the user's password. Delpy documented how to extract master keys from LSASS (`dpapi::masterkey /rpc`) — this unlocks all DPAPI-protected secrets (browser passwords, certificates, RDP credentials).
- **Credential Guard architecture:** Windows Credential Guard moves LSA credential storage into VTL1 (Isolated LSA). Delpy documented what this protects (NTLM hashes, Kerberos TGTs) and what it does not protect (DPAPI blobs remain in VTL0, Kerberos service tickets remain in VTL0, TGTs accessible to processes with SeDebugPrivilege via Isolated LSA RPC interface in some configs).

---

### Synacktiv

**URL:** https://www.synacktiv.com/publications.html
**Focus:** COM/DCOM attack surface, Windows driver vulnerabilities, Hyper-V guest-to-host, EDR bypass

French offensive security firm with a consistently high-quality publication record. Their Windows research is notable for targeting less-explored surfaces: hypervisor attack surface, Windows driver security, and COM security that goes beyond the standard examples.

**Notable research:**

**Hyper-V guest-to-host research**
URL: https://www.synacktiv.com/publications/escaping-from-hyper-v-in-vmwp-exe (representative; search synacktiv.com for "Hyper-V")

Synacktiv has published multiple Hyper-V guest-to-host escape vulnerabilities — targeting `vmwp.exe` (Virtual Machine Worker Process, the host-side component that handles VM device emulation). `vmwp.exe` runs at medium IL on the host but handles untrusted input from the VM guest. Vulnerabilities here allow a VM guest to execute code in `vmwp.exe` on the host, then escalate from `vmwp.exe` to SYSTEM on the host via standard LPE. The research demonstrates why Hyper-V isolation boundaries are harder to maintain than simple process isolation.

**COM/DCOM security research**
Synacktiv has produced detailed analyses of COM server implementations that expose dangerous methods to low-privilege clients — focusing specifically on DCOM servers registered in HKLM with launch/activation permissions that allow guest/everyone access. Their methodology: enumerate all DCOM servers, filter for those with permissive launch permissions (using NtObjectManager), then enumerate their exposed interfaces for dangerous method patterns (file write, process creation, service manipulation).

**EDR bypass research**
Research on Windows EDR (Endpoint Detection & Response) architecture — specifically targeting ELAM (Early Launch Anti-Malware) drivers, ETW (Event Tracing for Windows) consumer manipulation, and callback-based detection suppression. Context for understanding both the defensive infrastructure and how attackers circumvent it.

---

### SpecterOps

**URL:** https://posts.specterops.io/
**Focus:** Active Directory attack/defense, BloodHound, ADCS, GhostPack

BloodHound development and Active Directory attack research. SpecterOps is one of the few organizations where offensive capability (finding new AD attack paths) directly drives defensive tooling (BloodHound models those paths). Their research arc:

**BloodHound / SharpHound**
URL: https://github.com/BloodHoundAD/BloodHound

BloodHound represents a methodological shift in AD attack path analysis. Before BloodHound, AD attacks were enumerated manually or with point tools. BloodHound collects AD data (users, groups, GPOs, ACLs, local admin sessions, trust relationships) via SharpHound, ingests it into Neo4j, then uses graph theory to find attack paths that are not obvious from any single data point. Key insight: `Domain Admin` reachability is a graph problem — the question is not "can I attack this server directly" but "is there any path from my current position to Domain Admin through any combination of ACL edges, session edges, and group membership edges."

Current BloodHound Community Edition (CE) vs Enterprise — CE is the free open-source version; Enterprise is the commercial version with attack path prioritization. For research purposes, CE is sufficient.

**ADCS "Certified Pre-Owned" paper (2021)**
URL: https://posts.specterops.io/certified-pre-owned-d95910965cd2

Co-authored by Will Schroeder and Andy Robbins. See Will Schroeder section above for detailed ESC breakdown. The significance from SpecterOps's perspective: this paper opened an entirely new attack surface in environments that were otherwise well-hardened against traditional AD attacks. Environments that had addressed Kerberoasting, delegation abuse, and lateral movement via sessions still had exploitable ADCS configurations in the majority of cases.

**Elastic Security Labs**

**URL:** https://www.elastic.co/security-labs/
**Focus:** PPL bypass, LSASS access techniques, kernel telemetry, EDR detection research

Elastic's security research lab publishes at the intersection of offensive technique discovery and defensive detection. Their Windows research focuses on techniques that bypass or evade EDR products — which means they document the techniques in enough detail to build detection logic, and that same detail is useful for understanding the techniques offensively.

**Key areas:**
- **PPL bypass:** Multiple publications on Protected Process Light bypass techniques for LSASS access. The techniques exploit signed but vulnerable kernel drivers (BYOVD — Bring Your Own Vulnerable Driver) to load unsigned code at kernel level and remove PPL protection. Specific coverage: abusing `iqvw64e.sys` (Intel driver), `gdrv.sys`, other vulnerable signed drivers for PPL bypass via kernel memory manipulation.
  URL: https://www.elastic.co/security-labs/protecting-lsass-anti-cheat-driver (and related posts)
- **Direct system call (syscall) evasion:** Techniques where user-mode code bypasses NTDLL hooks (placed by EDR products) by invoking syscalls directly — using `syswhispers` patterns or dynamically extracting syscall numbers from NTDLL. Elastic documented both the technique and how to detect it via ETW kernel events.
- **ETW (Event Tracing for Windows) as telemetry:** Posts on what ETW providers capture about process injection, handle duplication, token manipulation — showing exactly which ETW events are the signals that EDR products use for detection. Useful for understanding what defensive visibility exists against each technique.
- **LSASS access patterns:** Enumeration of every technique for accessing LSASS memory (MiniDumpWriteDump, direct memory read via `ReadProcessMemory`, `PssCaptureSnapshot`, shadow copy access, Comsvcs.dll, custom LSA plugins) with corresponding ETW/kernel callback signals.

**2024 additions from Elastic Security:**
- **Pool Party detection (2024):** Research on detecting the "Pool Party" process injection family (which uses Windows thread pool internals rather than `CreateRemoteThread` / APC injection). Elastic documented the kernel-side artifacts that each Pool Party variant leaves — `WORK_QUEUE_ITEM` structures in kernel pool, worker thread registry changes in the process's thread pool state — and built YARA/eBPF-style rules targeting those structures.
- **Kernel callback nullification detection:** Paper on how rootkits suppress EDR visibility by zeroing or replacing kernel callbacks (`PsSetCreateProcessNotifyRoutine`, `PsSetCreateThreadNotifyRoutine`, `PsSetLoadImageNotifyRoutine`). Elastic documented the detection primitive: comparing the callback array at `PspCreateProcessNotifyRoutine` etc. (accessible via public symbol) to expected signatures, flagging nullified or replaced entries as indicators of compromise.
- **YARA rules for kernel rootkit detection:** Published YARA rule set targeting known kernel rootkit signatures in memory: FudModule v2 (appid.sys abuse), POORTRY/STONESTOP drivers, Netfilter-based traffic redirectors. The rules focus on PE header indicators in kernel-mapped memory that legitimate drivers don't exhibit.

---

### Tavis Ormandy (taviso) — extended profile

**Blog / Project Zero:** https://googleprojectzero.blogspot.com/ (search "Ormandy")
**Twitter/X:** @taviso
**Employer:** Google Project Zero
**Focus:** User-mode application vulnerabilities, antivirus engine research, browser engines, occasional Windows kernel

Ormandy's primary research terrain is user-mode application security (PDF parsers, compression libraries, antivirus emulation engines, browser components). His Windows-specific contribution is less in terms of volume and more in terms of methodological influence: his antivirus vulnerability research (Sophos, Symantec, Kaspersky, ESET, Trend Micro) established the framework for treating AV engines as high-privilege attack surfaces. AV products run with kernel-mode drivers (high IL + kernel access) and parse untrusted content (malware samples, attachments) in a high-privilege context — combining *maximum privilege* with *maximum exposure to untrusted input*.

**Key Windows-relevant research:**

**Antivirus engine vulnerabilities (2016–ongoing)**
Ormandy's AV research consistently found that parsing complex file formats (PE, SWF, compressed archives, emulated x86 code) in a SYSTEM-level process creates critical attack surface. Specific classes:
- Emulated x86 code execution in AV emulation engines with logic bugs in the emulation (e.g., unhandled opcodes that bypass the sandboxed execution context and execute arbitrary code in the emulation host's context — SYSTEM)
- Overflow bugs in compressed file parser code (LZMA, ZIP, RAR) run in-process by AV scanners
- `NtProtectVirtualMemory` interactions where AV-placed hooks in low-level Windows APIs create injection-compatible code paths accessible to unprivileged processes

**2024: Windows Kernel Type Confusion in `ntoskrnl.exe` (P0 issue)**

A Windows kernel type confusion vulnerability found via systematic audit of kernel object type handling in `ObpXxx` (Object Manager) code paths. The bug involves incorrect type validation when a handle is used for an operation that expects a specific object type — the kernel trusts an object type field that can be influenced by a user-mode caller under specific race conditions. P0 issue published under the standard 90-day deadline policy.

**Why his write-ups are uniquely valuable:**
Ormandy's root cause analysis documents are exceptionally complete. Each write-up includes: the exact code path (with function names), the mitigating conditions that prevent exploitation in certain configurations, and always a working PoC. The PoC-first methodology means each report has immediate reproducibility.

---

### SafeBreach Labs

**URL:** https://www.safebreach.com/research/
**Focus:** Windows kernel exploit detection, BYOVD techniques, in-the-wild vulnerability analysis, detection evasion research

SafeBreach Labs produces security research that straddles the boundary between offensive technique discovery and defensive detection — their "Hall of Shame" series catalogues vulnerabilities in security products themselves.

**Key research 2024:**

**CVE-2024-38193 — `afd.sys` (Ancillary Function Driver) Analysis**
URL: https://www.safebreach.com/research/cve-2024-38193-afd-sys/ (search SafeBreach site)

`afd.sys` (Ancillary Function Driver for WinSock) is a kernel-mode driver that handles socket operations. CVE-2024-38193 is a use-after-free in the socket management code — specifically in the handling of socket address structure reuse during `connect()` cancellation. SafeBreach's analysis documents: the vulnerable code path (AF_INET socket setup → async connect → cancellation while kernel holds reference to stack-allocated address structure), the exploitation primitive (UAF on a kernel pool object whose type can be influenced by the socket type family), and the detection signatures (unusual `afd.sys` call sequences via ETW network events).

This CVE was exploited in the wild by Lazarus Group (attributed by Microsoft and Avast). The SafeBreach analysis provides the most technically complete public root cause documentation.

**"Hall of Shame" — Security Product Vulnerabilities 2024**
SafeBreach continued their research into vulnerabilities in security products (EDR drivers, AV kernel components, DLP tools) that can be abused as BYOVD (Bring Your Own Vulnerable Driver) vectors. The research establishes: (1) the specific IOCTL interface the vulnerable driver exposes, (2) the kernel operation that can be triggered via the IOCTL without elevation (arbitrary mapped memory read/write, process termination without handle privilege check), (3) the signature for detecting the BYOVD abuse via kernel callback monitoring.

**Windows kernel exploitation for detection evasion research**
Published research on how kernel-level code can suppress EDR telemetry specifically: removing process creation callbacks by overwriting the callback array, disabling ETW providers at the kernel level via `EtwpDebuggerData` manipulation, and clearing the `_EPROCESS.SeAuditProcessCreationInfo` field to suppress process creation audit events. Each technique is paired with detection guidance.

---

### Zscaler ThreatLabz

**URL:** https://www.zscaler.com/blogs/security-research
**Focus:** APT group exploit analysis, in-the-wild kernel exploits, FudModule tracking, exploit telemetry

Zscaler ThreatLabz occupies a unique position in the Windows security research ecosystem: they have visibility into enterprise traffic that allows detecting in-the-wild kernel exploit deployment before the vulnerability is publicly known, and they produce deep technical analyses of APT-used exploits.

**Key research 2024:**

**FudModule v2 Analysis — CVE-2024-21338 (`appid.sys`)**
URL: https://www.zscaler.com/blogs/security-research/fudmodule-v2-lazarus-appid (search ThreatLabz)

FudModule is a Lazarus Group rootkit that uses kernel vulnerability exploitation to disable EDR products at the kernel callback level. Version 1 (2022) used CVE-2022-21882 (Win32k kernel elevation). Version 2 (2024) pivoted to CVE-2024-21338 — a vulnerability in `appid.sys` (Windows Application Identity service driver). The vulnerability: `appid.sys` exposes an IOCTL interface that is callable without elevated privileges. One IOCTL handler performs a kernel memory operation using a user-supplied pointer without proper validation, allowing a Medium IL process to write to an arbitrary kernel address.

The ThreatLabz analysis of FudModule v2 documents the full exploitation chain: IOCTL call sequence to trigger the primitive, use of the arbitrary write to overwrite kernel callback array entries for process/thread/image-load notifications (the callbacks that EDR products use to monitor process activity), the resulting "silent" process creation that generates no EDR alerts. This is the most complete public documentation of FudModule v2's kernel mechanism.

**APT28 / Lazarus Group Windows Exploit Telemetry 2024**
ThreatLabz published telemetry-driven reports on CVE-2024-38193 (`afd.sys`, Lazarus) and CVE-2024-49039 (Task Scheduler, attributed to RomCom APT initially then re-attributed). These reports include: the delivery chain (how the exploit was packaged into a malware dropper), the victim targeting pattern (industries, geographies), and the post-exploitation behavior (which EDR callbacks were disabled, what lateral movement tools were dropped after kernel access was achieved).

**In-the-Wild Kernel Exploit Telemetry Reports**
Quarterly reports tracking which kernel CVEs are being actively exploited in the wild, which APT groups are associated with specific exploits, and which Windows versions/patch levels are most frequently targeted. Useful as a prioritization signal: if an LPE CVE appears in ThreatLabz telemetry, it is being operationalized and understanding it becomes more urgent.

---

### ESET Research

**URL:** https://www.welivesecurity.com/
**GitHub:** https://github.com/eset/
**Focus:** APT group tracking, exploit chain analysis, rootkit detection, Windows-targeted malware campaigns

ESET Research is one of the most prolific sources of in-depth APT exploit analysis. Their Windows security research is typically driven by malware samples encountered during threat intelligence operations, producing detailed reverse engineering reports of real-world exploits.

**Key research 2024:**

**RomCom APT — CVE-2024-49039 (Task Scheduler) + Firefox 0-day Chain**
URL: https://www.welivesecurity.com/en/eset-research/romcom-exploits-firefox-and-windows/ (and follow-on posts)

ESET Research was the first to publicly document the RomCom APT exploit chain that combined CVE-2024-9680 (Firefox use-after-free, critical, CVSS 9.8) with CVE-2024-49039 (Windows Task Scheduler privilege escalation) for a sandbox-escaping, OS-level persistent compromise chain — all without user interaction beyond visiting a malicious webpage.

Technical breakdown of CVE-2024-49039 (the Windows component):
- The Windows Task Scheduler service (`schedsvc.dll` / `taskschd.dll`) exposes an RPC interface
- A specific RPC method performs a file operation using a path that can be influenced by an AppContainer process via junction manipulation
- The Task Scheduler service runs at SYSTEM privilege with no AppContainer restriction
- The exploit uses the Firefox renderer sandbox escape (CVE-2024-9680) to gain code execution in AppContainer, then uses CVE-2024-49039 to escape the AppContainer entirely and elevate to SYSTEM

Why this chain is architecturally significant: it demonstrates that zero-interaction browser exploitation combined with a Windows LPE can produce a full-privilege implant from a single visited URL, on a fully patched Windows 10/11 system at the time of exploitation (before Microsoft's November 2024 patch).

**Lazarus Group Windows Exploitation Campaign 2024**
ESET tracked multiple Lazarus Group campaigns using kernel exploits for privilege escalation and EDR bypass. Technical analysis covers: the dropper mechanism (signed but trojanized installer), the kernel exploit (CVE-2024-38193 in one campaign, BYOVD in another), and the rootkit payload that disables security tooling post-exploitation. ESET's analysis is often the first public detailed documentation of newly-discovered Lazarus tooling.

**Sandworm APT Windows Exploitation 2024**
Analysis of Sandworm (Russian GRU) operations targeting Windows infrastructure, including exploitation of Windows authentication protocols for lateral movement and data exfiltration. Sandworm's 2024 Windows campaigns are notable for combining credential theft (NTLM relay, Kerberos ticket abuse) with physical infrastructure compromise.

---

## Tier 2.5 — Active Directory & Domain Research

### Elad Shamir

**Blog:** https://shenaniganslabs.io/
**Twitter/X:** @elad_shamir
**Focus:** Kerberos delegation, RBCD, Shadow Credentials, Active Directory ACL abuse

Elad Shamir is the primary researcher responsible for articulating Resource-Based Constrained Delegation (RBCD) as a general-purpose privilege escalation primitive. His "Wagging the Dog" paper is one of the most consequential offensive AD research contributions of the 2018–2022 period.

**"Wagging the Dog: Abusing Resource-Based Constrained Delegation to Attack Active Directory" (2019)**
URL: https://shenaniganslabs.io/2019/01/28/Wagging-the-Dog.html

The key observation: RBCD (`msDS-AllowedToActOnBehalfOfOtherIdentity`) is configured on the *target* machine, not by a domain admin. Any principal with `GenericWrite`, `WriteDacl`, `WriteProperty` (on the specific attribute), or `GenericAll` on a computer object can set RBCD on that computer. This means:

1. Attacker has `GenericWrite` on `TARGETPC$` (found via BloodHound ACL enumeration)
2. Attacker creates or controls a machine account `ATTACKERPC$` (or any account with an SPN)
3. Attacker sets `msDS-AllowedToActOnBehalfOfOtherIdentity` on `TARGETPC$` to allow delegation from `ATTACKERPC$`
4. Attacker uses S4U2Self + S4U2Proxy via Rubeus to request a ticket to any service on `TARGETPC$` impersonating any user (e.g., Administrator)
5. Attacker now has a service ticket to `TARGETPC$` as Administrator → pass-the-ticket → full access to `TARGETPC$`

The paper also documents: using RBCD for local privilege escalation (when you have write access to your own machine account from a local context — this is the basis for KrbRelayUp), and RBCD abuse via NTLM relay (relay a machine account's NTLM to LDAP, set RBCD on that machine, then use S4U).

**Shadow Credentials (2021)**
URL: https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab

Shamir discovered that `msDS-KeyCredentialLink` attribute (used by Windows Hello for Business and similar PKINIT-based passwordless authentication) can be manipulated by any principal with `GenericWrite` on the target account. The attack: write an attacker-controlled public key to `msDS-KeyCredentialLink` on the target user/computer, then use PKINIT with the corresponding private key to authenticate as that account — obtaining a TGT and NTLM hash without ever knowing the account's password. The `msDS-KeyCredentialLink` write is silent (no password change), making this a stealthy path to account compromise.

Tool: **Whisker** (https://github.com/eladshamir/Whisker) — C# implementation of shadow credentials attack.

---

### Andy Robbins

**Blog:** https://posts.specterops.io/ (SpecterOps blog)
**Twitter/X:** @_wald0
**Focus:** BloodHound methodology, Active Directory attack path enumeration, ADCS

Andy Robbins is BloodHound's primary architect from a methodology standpoint. His contributions are less about finding new bugs and more about formalizing the *methodology* for AD attack path analysis — turning what was informal tribal knowledge ("check group memberships, check sessions, check ACLs") into a formal graph problem.

**"An ACE Up the Sleeve: Designing Active Directory DACL Backdoors" (2017)**
URL: https://www.blackhat.com/docs/us-17/wednesday/us-17-Robbins-An-ACE-Up-The-Sleeve-Designing-Active-Directory-DACL-Backdoors-wp.pdf

Co-authored with Will Schroeder. The paper that established ACL-based AD backdoors and attack paths as a first-class attack surface. Before this paper, most AD attacks focused on credentials and tickets. This paper documented: which ACL rights on which AD object types enable which attacks, the complete mapping of `GenericAll/GenericWrite/WriteDacl/WriteOwner/AllExtendedRights` on users, groups, computers, GPOs, domain objects to their attacker implications.

This is why BloodHound models ACL edges — the paper provided the taxonomy. Every `GenericWrite → Computer → RBCD` path in BloodHound traces back to this foundational work.

**"Certified Pre-Owned" (2021)**
URL: https://posts.specterops.io/certified-pre-owned-d95910965cd2

Co-authored with Will Schroeder. See Will Schroeder section above.

---

### Charlie Clark (exploitph)

**Blog:** https://exploit.ph/
**Focus:** Kerberos protocol internals, PAC manipulation, advanced Kerberos attacks

Charlie Clark's work sits at a deeper protocol layer than most AD research — he analyzes the Kerberos protocol specification itself and finds discrepancies between what the specification says, what Windows implements, and what Windows accepts from clients.

**Diamond Tickets (2022)**
URL: https://exploit.ph/diamond-tickets.html

A **golden ticket** forges a TGT by encrypting it with the KRBTGT hash. Detection: the PAC contains data that doesn't match what the KDC would have generated (missing or mismatched fields). A **diamond ticket** modifies an *existing legitimate TGT* (obtained from the KDC) rather than forging one from scratch. The modifications (privilege extensions, group additions) are applied to the PAC *after* the KDC signs it, by using the KRBTGT key to re-sign. Because the base ticket is legitimate, many of the anomaly checks that detect golden tickets fail. The diamond ticket technique requires the KRBTGT hash but produces a ticket that blends with legitimate traffic better.

**Sapphire Tickets (2022)**
URL: https://exploit.ph/sapphire-tickets.html

Extension of diamond ticket concept. Instead of forging the KRBTGT-encrypted portion, sapphire tickets use S4U2Self + U2U (User-to-User authentication) to obtain a valid PAC for any user from the KDC itself, then inject that legitimate PAC into a forged ticket. The PAC is genuinely KDC-issued, making detection harder still.

**PAC manipulation research**
The Kerberos PAC (Privilege Attribute Certificate) contains the user's group memberships and security identifier information, used for access checks on Windows. Clark's research examines the validation of PAC contents — specifically, when DCs validate PAC signatures vs. when they trust the contents uncritically. This maps directly to Kerberos privilege escalation via PAC modification.

**S4U delegation chain analysis**
Clark has published detailed analysis of S4U2Self and S4U2Proxy protocol mechanics — specifically examining edge cases where the delegation constraint checks can be bypassed or the impersonation chain can be extended beyond intended scope. His blog is the most technically precise source for understanding what the KDC actually validates vs. what it trusts.

---

### hasherezade

**Blog:** https://hshrzd.wordpress.com/ and https://github.com/hasherezade
**Twitter/X:** @hasherezade
**Focus:** PE file analysis, process injection techniques, malware internals, Windows loader internals

hasherezade's work is adjacent to security research but essential for understanding the lower layers of Windows execution — specifically how PE files are loaded, how process injection techniques work at the API and memory level, and how malware leverages Windows internals.

**PE-sieve and process memory analysis**
URL: https://github.com/hasherezade/pe-sieve

PE-sieve scans a running process's memory and compares loaded modules against their on-disk counterparts. Detects: hooks in NTDLL/kernel32 (placed by EDR products or malware), hollowed processes (where the original PE is replaced in memory), module stomping (where a loaded DLL's memory is overwritten), shellcode injection (memory regions with execute permission that don't correspond to loaded modules), reflective DLL injection (DLL loaded without going through the normal loader).

**Why this matters for security research:** Understanding what PE-sieve detects reveals what process injection leaves as forensic artifacts. The tool's detection logic is effectively a catalog of injection technique signatures.

**Process injection technique catalog**
URL: https://github.com/hasherezade/process_overwriting, https://github.com/hasherezade/process_doppelganging

hasherezade has implemented reference PoCs for multiple injection techniques:
- **Process hollowing:** Create process in suspended state, unmap original PE, map malicious PE
- **Process doppelgänging:** Use NTFS transactions to load a PE from a transacted file that is rolled back after loading — the loaded image doesn't correspond to any file on disk
- **Process overwriting:** Overwrite the image of a suspended process's main module in memory with a different PE — more stealthy than hollowing because the process is not suspended for long and the PEB isn't modified in the same ways

**Windows loader internals**
Her blog posts on how the Windows PE loader maps sections, resolves imports, handles TLS callbacks, and interacts with the PEB (Process Environment Block) are the best practical references for understanding what injection techniques do at the loader level — what they change in `_PEB_LDR_DATA`, what `InLoadOrderModuleList` contains post-injection, which entries appear in task manager vs which don't.

---

| Researcher | Resource | Notes |
|-----------|---------|-------|
| FuzzySecurity (b33f) | https://www.fuzzysecurity.com/ | Windows post-exploitation tutorials from 2013–2018. Dated for current systems but excellent for understanding how exploit techniques evolved: stack overflows in kernel drivers, GDI bitmap technique, token stealing methodology. Read for historical context and to understand what the current mitigations closed. |
| SandboxEscaper | https://github.com/SandboxEscaper | 2018–2019 LPE 0-days dropped publicly without vendor notice. Targets: Task Scheduler `SchRpcSetSecurity` (arbitrary DACL write as SYSTEM), Windows Error Reporting (WER) arbitrary file delete, Print Spooler `ReadFile` bug. Each is historically instructive for the attack surface: task scheduler's internal file operations and WER's crash file handling are surfaces itm4n later also found bugs in. |
| Phrack archives | http://phrack.org/ | Classic kernel exploitation theory. Phrack 68 ("MoVP" pool exploitation series) is still the reference for NT pool heap exploitation concepts even though the specific techniques are now obsolete. Read for conceptual foundations before reading "The Pool Is Dead." |
| Tarjei Mandt | DEF CON 19 paper | "Kernel Pool Exploitation on Windows 7" — the pre-Segment Heap canonical pool exploitation reference. Pool chunk layout, freelist manipulation, exploitation chain. Same relationship to current techniques as Phrack 68 — foundational but not directly applicable to modern Windows. |

---

## Corporate / Team Research Feeds

| Source | URL | What to extract |
|--------|-----|----------------|
| MSRC Blog | https://msrc.microsoft.com/blog/ | Microsoft's defensive perspective; root cause summaries for Critical CVEs; Patch Tuesday summaries that occasionally disclose which component was affected |
| Microsoft Security Blog | https://www.microsoft.com/security/blog/ | Threat intelligence; in-the-wild exploitation reports; analysis of APT techniques that reveal what primitives attackers are using |
| Microsoft MSTIC | https://www.microsoft.com/security/blog/topic/microsoft-threat-intelligence/ | APT group attribution reports; in-the-wild exploit documentation for Lazarus, Volt Typhoon, Sandworm; FudModule rootkit series 2024 |
| Elastic Security Labs | https://www.elastic.co/security-labs/ | PPL bypass techniques (LSASS protection), kernel telemetry research, detection engineering that reveals attacker technique detail; Pool Party and kernel callback nullification detection (2024) |
| Outflank | https://outflank.nl/blog/ | Red team tradecraft; Windows offensive techniques at the implementation level — process injection, EDR bypass, offensive driver use |
| NCC Group Research | https://research.nccgroup.com/ | Windows RPC/DCOM research, driver vulnerability research, varied but generally high quality |
| Project Zero Issue Tracker | https://bugs.chromium.org/p/project-zero/issues/list?q=windows | Raw bug reports with PoC, often before the corresponding blog post. Check this weekly for new Windows disclosures. |
| MSRC Acknowledgments | https://msrc.microsoft.com/update-guide/acknowledgement | Track who found what, which components they are finding bugs in, and which researchers have recently been active. The acknowledgment page is a leading indicator of where vulnerability research is concentrated. |
| SafeBreach Labs | https://www.safebreach.com/research/ | BYOVD technique analysis, CVE-2024-38193 (`afd.sys`) root cause, EDR evasion at kernel level, detection signature research |
| Zscaler ThreatLabz | https://www.zscaler.com/blogs/security-research | In-the-wild kernel exploit telemetry, FudModule v2 analysis, APT28/Lazarus exploit tracking, quarterly threat reports |
| ESET Research | https://www.welivesecurity.com/ | APT campaign analysis with deep exploit technical detail; RomCom CVE-2024-49039 chain, Lazarus kernel rootkit tracking, Sandworm Windows operations |
| Kaspersky GReAT | https://securelist.com/ | CVE-2024-30051 DWM UAF discovery and in-the-wild analysis, APT 0-day fingerprinting methodology, Windows exploit attribution via shellcode signatures |
| Trend Micro ZDI | https://www.zerodayinitiative.com/blog/ | Monthly Patch Tuesday technical deep dives; CVE-2024-38100 and CVE-2024-49039 acquisitions; component-level detail missing from MSRC advisories |

---

## Corporate Research Teams 2024 Updates

The corporate team feeds listed in the table above all had notable 2024 contributions worth tracking individually. What follows is a structured update on the most technically significant output per feed.

### Microsoft MSTIC (Microsoft Threat Intelligence Center)

**URL:** https://www.microsoft.com/security/blog/topic/microsoft-threat-intelligence/

**2024 highlights:**
- **Lazarus Group / FudModule v2 tracking:** MSTIC published one of the definitive attribution reports linking CVE-2024-21338 (`appid.sys`) exploitation to Lazarus Group's "Diamond Sleet" and "Citrine Sleet" clusters. The report documents the delivery mechanism (trojanized trading software), the FudModule v2 rootkit component (kernel callback suppression), and the post-exploitation toolchain (BLINDINGCAN, COPPERHEDGE backdoors). This report is the primary source for the `appid.sys` exploit's APT attribution context.
- **Volt Typhoon living-off-the-land techniques:** Extended analysis of Volt Typhoon (Chinese state-sponsored) using built-in Windows tools (`wmic`, `netsh`, `reg`, `nltest`) for lateral movement and credential harvesting. Key finding: attackers are deliberately avoiding loading any non-Microsoft binaries to evade EDR behavioral detection — all operations performed via signed Windows tools. This drives the defensive research question: which Windows-native tools are being abused and what are their detectable behavioral signatures?

### Google Project Zero

**URL:** https://googleprojectzero.blogspot.com/

**2024 highlights:**
- **COM activation research series:** Forshaw's COM activation vulnerability research (detailed in his section above) produced multiple P0 issues in 2024–2025. The issues are accessible via the tracker filtered by `component:Windows, owner:forshaw` and include root cause detail that often exceeds the corresponding blog posts.
- **Windows kernel audits:** Combined effort from Forshaw and other P0 researchers on Windows kernel object type confusion and handle validation. Specific findings in the object namespace and token inheritance code paths. Check the tracker for issues labeled `Windows-Kernel` filed 2024.
- **90-day policy impact 2024:** P0 issued 14 Windows-related reports in 2024 under the 90-day deadline. Of those, 4 were published with active PoC before vendor patch (deadline exceeded). The publication of pre-patch PoC for Windows LPE bugs drove emergency out-of-band patches in two cases — useful for tracking which CVEs had forced response.

### Trend Micro Zero Day Initiative (ZDI)

**URL:** https://www.zerodayinitiative.com/blog/ and https://www.zerodayinitiative.com/advisories/

**2024 highlights:**
- **CVE-2024-38100 (Windows File Explorer LPE):** ZDI acquisition and public advisory for a Windows File Explorer privilege escalation. The vulnerability is in the Explorer shell's handling of compressed archive preview — an OOB condition in a COM-based shell extension that runs at the Explorer process's privilege level (Medium IL / user context for standard Explorer, elevated for administrator Explorer). ZDI's advisory includes the vulnerable function name and crash context.
- **CVE-2024-49039 (Task Scheduler) acquisition:** ZDI acquired CVE-2024-49039 before ESET publicly documented its in-the-wild exploitation. The ZDI advisory timeline is useful for cross-referencing when a vulnerability was known to vendors vs. when it appeared in the wild (the gap is often a signal about how quickly APTs are integrating newly patched vulnerabilities).
- **Patch Tuesday "Deep Dive" posts:** ZDI publishes monthly analysis of the most technically significant CVEs in each Patch Tuesday. For Windows LPE bugs, these posts often provide the component name and call stack context that Microsoft's MSRC advisories omit. Useful for identifying which month's patches are worth deeper investigation.

### Kaspersky GReAT (Global Research & Analysis Team)

**URL:** https://securelist.com/

**2024 highlights:**
- **CVE-2024-30051 — DWM (Desktop Window Manager) Use-After-Free:** Kaspersky GReAT discovered CVE-2024-30051 in `dwmcore.dll` (Desktop Window Manager), a UAF vulnerability triggered during window message processing. The UAF occurs when a window is destroyed during a specific DWM rendering callback, leaving a dangling pointer in the DWM composition pipeline. Kaspersky documented that this vulnerability was being exploited in the wild by the QakBot malware distribution infrastructure as an LPE component — combined with a user-mode RAT dropper to achieve persistent SYSTEM-level access. The Kaspersky write-up includes the spray technique used to control the UAF object reuse.
- **APT tracking via 0-day fingerprinting (2024):** GReAT published a methodology paper on tracking APT groups through their exploit code signatures — specifically, which NtXxx syscalls they call, how they implement their pool spray routines, and which Windows version checks they embed. The finding: different APT groups have identifiable "coding styles" for their kernel exploit shellcode that persist across vulnerability classes, making cross-CVE attribution possible even when the vulnerability itself differs.
- **Windows 0-day in Patch Tuesday attribution (ongoing):** Kaspersky's "APT-0day tracker" regularly publishes pre- or post-patch analyses of Windows CVEs that were exploited in the wild, including attribution to APT groups and timeline reconstruction. This is one of the most consistent sources of in-the-wild Windows exploitation tracking alongside ESET.

---

## How to Build a Reading Workflow

### The problem with ad-hoc reading

Reading security research without a system produces a collection of disconnected techniques rather than a model of Windows security. The goal is to build a mental model of the security architecture — where trust boundaries are, what the OS assumes about who controls what, and where those assumptions can be violated. Individual blog posts contribute to that model only if they are read in context.

### Recommended workflow

**Step 1: Follow active signals first, not volume**

Priority RSS feeds:
1. `https://googleprojectzero.blogspot.com/feeds/posts/default` — all PZ posts
2. `https://itm4n.github.io/feed.xml` — itm4n posts
3. `https://windows-internals.com/feed/` — Shafir/Ionescu/Yosifovich
4. `https://decoder.cloud/` — Cocomazzi
5. `https://j00ru.vexillium.org/` — j00ru (post frequency: low but signal density is very high)

**Step 2: Track the MSRC Update Guide monthly**

Released the second Tuesday of each month: https://msrc.microsoft.com/update-guide/

For each Critical or Important Windows LPE/EoP CVE:
- Read the component (`Windows Common Log File System Driver`, `Windows Print Spooler`, `Windows Kernel`)
- Search for corresponding acknowledgments — that tells you whose research this is
- In the days after Patch Tuesday, expect blog posts from the finders

**Step 3: Use the Project Zero issue tracker proactively**

Before blog posts appear: https://bugs.chromium.org/p/project-zero/issues/list?q=windows

Filter by `status:Fixed` (bugs patched but perhaps not yet written up). Forshaw's issues are detailed enough to understand the bug class immediately.

**Step 4: Read researcher catalogs as unified bodies**

Do not read individual blog posts in isolation. When starting a new researcher, read their 5–10 most important posts in chronological order. The arc is the methodology. Individual posts are examples.

---

## References

[R-1] James Forshaw (tiranid) — GitHub: https://github.com/tyranid | Blog: https://tyranid.github.io/

[R-2] itm4n (Clément Labro) — Blog: https://itm4n.github.io/ | GitHub: https://github.com/itm4n

[R-3] decoder (Antonio Cocomazzi) — Blog: https://decoder.cloud/ | GitHub: https://github.com/antonioCoco

[R-4] j00ru (Mateusz Jurczyk) — Blog: https://j00ru.vexillium.org/ | GitHub: https://github.com/j00ru

[R-5] Yarden Shafir — Blog: https://windows-internals.com/ | Twitter: @yarden_shafir

[R-6] Alex Ionescu — Blog: https://www.alex-ionescu.com/ | GitHub: https://github.com/ionescu007

[R-7] Connor McGarr — Blog: https://connormcgarr.github.io/

[R-8] Google Project Zero — Blog: https://googleprojectzero.blogspot.com/ | GitHub: https://github.com/googleprojectzero

[R-9] SafeBreach Labs — Blog: https://www.safebreach.com/blog/

[R-10] Zscaler ThreatLabz — Blog: https://www.zscaler.com/blogs/security-research

[R-11] ESET Research — WeLiveSecurity: https://www.welivesecurity.com/

[R-12] Elastic Security Research — Blog: https://www.elastic.co/security-labs/

[R-13] Kaspersky GReAT — Securelist: https://securelist.com/

[R-14] Microsoft MSTIC — Security Blog: https://www.microsoft.com/en-us/security/blog/topic/threat-intelligence/

[R-15] Synacktiv — Blog: https://www.synacktiv.com/en/publications
- [R-37] Microsoft MSTIC — https://www.microsoft.com/security/blog/topic/microsoft-threat-intelligence/
