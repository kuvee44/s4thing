# Chapter 14 — Researchers, Blogs & Research Arcs

> This chapter profiles the primary researchers whose work defines Windows security research. For each researcher, the goal is not just a link — it is understanding their **methodology**, their **research arc**, and what a new finding from them signals. Reading their work as a unified body, not a list of blog posts, is what separates oriented reading from noise collection.
>
> The structure is deliberately asymmetric: researchers with deep, analyzable methodology arcs get full sections. Those with narrower or more recent catalogs get compressed coverage. Depth is proportional to methodological density, not to fame.

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

Active Directory attack research. Kerberos attack paths (Kerberoasting, ASREPRoasting, unconstrained delegation abuse, constrained delegation S4U2Proxy), BloodHound graph-based attack path analysis, GhostPack tooling (Rubeus, Seatbelt, SharpUp). Relevant as the primary source for understanding how Windows domain authentication works from an attacker's perspective — complements the local authentication/relay work from decoder's blog.

### Benjamin Delpy (gentilkiwi)

**Blog:** https://blog.gentilkiwi.com/
**Mimikatz:** https://github.com/gentilkiwi/mimikatz

Author of Mimikatz. His blog covers the internals of Windows credential storage — LSASS memory structure, how WDigest/NTLM/Kerberos credentials are cached in memory, SSP (Security Support Provider) loading, the credential guard architecture. Reading his work explains *why* Mimikatz works the way it does — what structures it reads, why those structures are in LSASS's memory, and what protections (Credential Guard, PPL on LSASS) prevent credential access.

### Synacktiv

**URL:** https://www.synacktiv.com/publications.html

French offensive security firm with a strong publication record. Windows-relevant research: COM/DCOM attack surface, Windows driver vulnerabilities, hypervisor research (Hyper-V guest-to-host), mobile/automotive security. Quality is consistently high; each publication includes root cause and exploitation detail.

### SpecterOps

**URL:** https://posts.specterops.io/

BloodHound development and Active Directory attack research. Primary contributions: documenting attack paths in AD that BloodHound now models (ACL-based paths like `WriteOwner`, `GenericWrite`, `WriteDacl` on AD objects), ADCS (Active Directory Certificate Services) abuse (ESC1–ESC8 attack classes, documented in the "Certified Pre-Owned" paper), GhostPack tooling.

---

## Tier 3 — Historical / Archived (Methodology Still Relevant)

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
| Elastic Security Labs | https://www.elastic.co/security-labs/ | PPL bypass techniques (LSASS protection), kernel telemetry research, detection engineering that reveals attacker technique detail |
| Outflank | https://outflank.nl/blog/ | Red team tradecraft; Windows offensive techniques at the implementation level — process injection, EDR bypass, offensive driver use |
| NCC Group Research | https://research.nccgroup.com/ | Windows RPC/DCOM research, driver vulnerability research, varied but generally high quality |
| Project Zero Issue Tracker | https://bugs.chromium.org/p/project-zero/issues/list?q=windows | Raw bug reports with PoC, often before the corresponding blog post. Check this weekly for new Windows disclosures. |
| MSRC Acknowledgments | https://msrc.microsoft.com/update-guide/acknowledgement | Track who found what, which components they are finding bugs in, and which researchers have recently been active. The acknowledgment page is a leading indicator of where vulnerability research is concentrated. |

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

- [R-1] tiraniddo.dev — James Forshaw — https://www.tiraniddo.dev/
- [R-2] Google Project Zero Blog — https://googleprojectzero.blogspot.com/
- [R-3] sandbox-attacksurface-analysis-tools — Forshaw/Project Zero — https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools
- [R-4] Windows Security Internals — Forshaw, No Starch 2023 — https://nostarch.com/windows-security-internals
- [R-5] itm4n.github.io — Clément Labro — https://itm4n.github.io/
- [R-6] PrivescCheck — itm4n — https://github.com/itm4n/PrivescCheck
- [R-7] decoder.cloud — Antonio Cocomazzi — https://decoder.cloud/
- [R-8] RoguePotato PoC — antonioCoco — https://github.com/antonioCoco/RoguePotato
- [R-9] j00ru.vexillium.org — Mateusz Jurczyk — https://j00ru.vexillium.org/
- [R-10] NT/Win32k syscall tables — j00ru — https://j00ru.vexillium.org/syscalls/nt/
- [R-11] windows-internals.com — Shafir / Ionescu / Yosifovich — https://windows-internals.com/
- [R-12] I/O Ring exploitation — Yarden Shafir — https://windows-internals.com/one-io-ring-to-rule-them-all-a-new-attack-primitive-on-windows-11/
- [R-13] connormcgarr.github.io — Connor McGarr — https://connormcgarr.github.io/
- [R-14] Project Zero Issue Tracker (Windows) — https://bugs.chromium.org/p/project-zero/issues/list?q=windows
- [R-15] MSRC Acknowledgments — https://msrc.microsoft.com/update-guide/acknowledgement
