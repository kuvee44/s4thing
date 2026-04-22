# 03 — Windows Security Model: Resource List

> **Section purpose:** Master the Windows security model — tokens, security descriptors,
> access control, integrity levels, impersonation, UAC, AppContainer, and credentials.
> This is the primary attack surface for privilege escalation vulnerabilities.
>
> **Prerequisites:** Completion of section 01 (Foundations) is strongly recommended.
> At minimum, understand processes, threads, handles, and kernel objects before starting here.

---

## Resource Index

| # | Title | Type | Priority | Tag |
|---|-------|------|----------|-----|
| S-001 | Windows Security Internals (Forshaw) | Book | PRIMARY | FOUNDATIONAL MUST-READ |
| S-002 | Access Control in Windows (MS Docs) | Documentation | HIGH | REFERENCE |
| S-003 | James Forshaw — Token Internals Research | Blog/Research | HIGH | PROJECT-ZERO |
| S-004 | Integrity Levels and UAC (MS Docs) | Documentation | HIGH | REFERENCE |
| S-005 | Windows Privilege Constants (MS Docs) | Documentation | MEDIUM | REFERENCE |
| S-006 | AppContainer and Sandbox Internals | Blog/Research | HIGH | PROJECT-ZERO |
| S-007 | NtObjectManager / sandbox-attacksurface-tools | Tool / Source | HIGH | LAB-WORTHY |
| S-008 | Security Descriptor Deep Dive | Blog/Research | HIGH | PROJECT-ZERO |
| S-009 | SeImpersonatePrivilege and Token Impersonation | Blog/Research | HIGH | PRACTICAL |
| S-010 | Windows Credentials and LSA | Documentation | MEDIUM | REFERENCE |

---

## Detailed Entries

---

### S-001 — Windows Security Internals

- **Title:** Windows Security Internals: A Deep Dive into Windows Authentication, Authorization, and Auditing
- **Author / Organization:** James Forshaw (Google Project Zero)
- **URL:** https://nostarch.com/windows-security-internals
  - Publisher: No Starch Press, 2023 | ISBN: 978-1-7185-0125-5
  - Companion tools: https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools
- **Resource type:** Book (primary reference for this entire section)
- **Topic tags:** `tokens` `security-descriptors` `DACL` `SACL` `ACE` `access-check` `impersonation` `integrity-levels` `UAC` `AppContainer` `LPAC` `LSA` `Kerberos` `NTLM` `COM-security` `object-security` `auditing` `privileges`
- **Difficulty:** Advanced
- **Historical or current:** Current — Windows 10/11, 2023
- **Trust level:** ★★★★★ — Forshaw has reported 400+ Windows vulnerabilities; this is the definitive security model reference
- **Why it matters:**
  The entire Windows privilege escalation attack surface is defined by the security model: who can impersonate whom, which processes can open which handles, how integrity levels constrain access, and how UAC mediates privilege transitions. This book is the single most important resource for Windows EoP research.
- **What it teaches:**
  - **Tokens:** Structure, user SID, group SIDs, privileges, default DACL, logon session, impersonation level, restricted SIDs, low-box (AppContainer) token
  - **Security Descriptors:** Binary layout, owner, group, DACL, SACL, self-relative vs. absolute form
  - **ACEs:** Allow, Deny, Audit ACE structure; inheritance; conditional ACEs (SDDL condition expressions)
  - **Access Check Algorithm:** Full walk of `SeAccessCheck` / `SeAccessCheckWithHint`; SACL auditing; object inheritance
  - **Mandatory Integrity Control:** Integrity levels (Untrusted/Low/Medium/High/System/Protected); policy flags (NO_WRITE_UP etc.); how MIC interacts with DACL
  - **UAC:** Auto-elevation heuristics, COM elevation moniker, UAC bypass attack surface taxonomy
  - **Impersonation:** Identity/Impersonation/Delegation/Anonymous levels; thread token vs. process token; impersonation on named pipes; NtImpersonateThread
  - **AppContainer:** Package SID, capability SIDs, LPAC, child AppContainer, how access checks handle AppContainer tokens
  - **Authentication:** LSA architecture, credential providers, Kerberos ticket flow, NTLM challenge-response, Pass-the-Hash/Pass-the-Ticket concepts
  - **COM Security:** Activation security, launch/access permissions, surrogate processes, COM elevation
- **Best use:**
  Read alongside live PowerShell sessions with NtObjectManager. Run every lab exercise. Use `Show-NtSecurityDescriptor`, `Get-NtToken`, `Test-NtTokenPrivilege` to verify what the book explains. Return to specific chapters when analyzing any EoP CVE.
- **Related bug classes / primitives:**
  `SeImpersonatePrivilege EoP` `token impersonation attack` `UAC bypass` `ACL misconfiguration` `integrity level bypass` `AppContainer escape` `COM activation abuse` `Potato attacks` `HiveNightmare` (ACL on registry hive) `PrintSpoofer`
- **Suggested next resource:** S-007 (NtObjectManager tooling) to apply concepts; S-003 (token internals research) for deeper Project Zero dive
- **Notes:**
  - DRM-free PDF available directly from No Starch Press
  - All examples use the author's own NtObjectManager PowerShell module
  - Directly applicable to understanding most Windows EoP CVEs from 2018–present

---

### S-002 — Access Control in Windows (Microsoft Documentation)

- **Title:** Access Control — Windows Security Documentation
- **Author / Organization:** Microsoft
- **URL:** https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control
  - Security Identifiers: https://learn.microsoft.com/en-us/windows/win32/secauthz/security-identifiers
  - Access Tokens: https://learn.microsoft.com/en-us/windows/win32/secauthz/access-tokens
  - Security Descriptors: https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptors
  - ACL (DACL/SACL): https://learn.microsoft.com/en-us/windows/win32/secauthz/access-control-lists
  - Access Rights and Access Masks: https://learn.microsoft.com/en-us/windows/win32/secauthz/access-rights-and-access-masks
- **Resource type:** Official documentation (online reference)
- **Topic tags:** `access-control` `security-identifiers` `SID` `access-tokens` `security-descriptors` `DACL` `SACL` `ACE` `access-mask` `generic-rights` `specific-rights`
- **Difficulty:** Intermediate
- **Historical or current:** Current — continuously maintained by Microsoft
- **Trust level:** ★★★★★ — Official source; the authoritative definition of documented behavior
- **Why it matters:**
  This is the official definition of the Windows access control model. Use alongside S-001 to verify documented behavior and find the authoritative API signatures and semantic definitions.
- **What it teaches:**
  - SID format, well-known SIDs (S-1-5-18 = SYSTEM, S-1-5-32-544 = Administrators, etc.)
  - Access token structure at the Win32 API level (vs. kernel-level in S-001)
  - Security descriptor format and Win32 manipulation functions
  - ACL and ACE structure, ordering rules (Deny before Allow), inheritance
  - Access mask format: generic rights mapping to specific rights, standard rights, object-specific rights
  - `AccessCheck()` function and how to use it programmatically
  - Security descriptor definition language (SDDL)
- **Best use:**
  Use as reference while reading S-001. Cross-check API documentation when writing tools or analyzing code. The SDDL reference is especially useful for quickly parsing security descriptor strings in WinObj, Registry editor, or logs.
- **Related bug classes / primitives:**
  `ACE ordering attack` `generic rights expansion` `DACL inheritance abuse` `SD ownership manipulation`
- **Suggested next resource:** S-008 (Security Descriptor Deep Dive) for researcher perspective on SD vulnerabilities
- **Notes:**
  - SDDL quick reference: https://learn.microsoft.com/en-us/windows/win32/secauthz/security-descriptor-string-format
  - Well-known SIDs reference: https://learn.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
  - The "How DACLs Control Access to an Object" flowchart on this page is worth printing

---

### S-003 — James Forshaw — Token Internals Research (Project Zero)

- **Title:** Token Internals Research — Project Zero Blog Series
- **Author / Organization:** James Forshaw / Google Project Zero
- **URL:**
  - Project Zero blog: https://googleprojectzero.blogspot.com/ (search "Forshaw token")
  - "Sharing a Logon Session a Little Too Liberally" (2019): https://googleprojectzero.blogspot.com/2019/04/sharing-logon-session-little-too.html
  - "Windows Exploitation Tricks: Exploiting Arbitrary File Writes for Local Elevation of Privilege" (2018): https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html
  - "No Pain, No Gain: Advances in Windows Exploit Development" (Infiltrate 2019)
  - tyraniddo.dev (personal blog): https://tyraniddo.dev/
- **Resource type:** Research blog posts / conference papers
- **Topic tags:** `token-impersonation` `logon-session` `impersonation-level` `NtImpersonateThread` `token-duplication` `CreateProcessWithTokenW` `SeImpersonatePrivilege` `restricted-token` `write-restricted-token`
- **Difficulty:** Advanced to Expert
- **Historical or current:** Current (posts from 2015–2023 remain highly relevant)
- **Trust level:** ★★★★★ — Primary source; Forshaw discovered and reported most of these issues
- **Why it matters:**
  Forshaw's research posts explain the token security model with a level of detail that no official documentation approaches. His posts on logon session sharing, token impersonation, and write-restricted tokens document behaviors that directly enable privilege escalation techniques.
- **What it teaches:**
  - Token duplication: OpenProcessToken + DuplicateToken + impersonation levels
  - Logon session sharing: how processes share credentials across impersonation boundaries
  - Write-to-read token escalation: how write primitives can escalate to token theft
  - NtImpersonateThread and its security implications
  - Impersonation token → primary token conversion
  - The precise conditions under which `SeImpersonatePrivilege` enables SYSTEM token access
- **Best use:**
  Read after completing S-001. Use Forshaw's posts to deepen understanding of specific attack primitives. Excellent case studies for understanding CVE disclosure → root cause → fix.
- **Related bug classes / primitives:**
  `NtImpersonateThread abuse` `logon session race` `token duplication escalation` `write primitive → token steal` `constrained delegation abuse`
- **Suggested next resource:** S-006 (AppContainer internals) or S-009 (SeImpersonatePrivilege)
- **Notes:**
  - tyraniddo.dev is Forshaw's personal blog — subscribe to RSS for new posts
  - His GitHub (https://github.com/tyranid) contains PoC tools for many techniques
  - Cross-reference with CVE writeups — Forshaw typically publishes detailed bug analyses 90 days after report

---

### S-004 — Integrity Levels and UAC (Microsoft Documentation)

- **Title:** Mandatory Integrity Control and User Account Control Documentation
- **Author / Organization:** Microsoft
- **URL:**
  - Mandatory Integrity Control: https://learn.microsoft.com/en-us/windows/win32/secauthz/mandatory-integrity-control
  - How UAC Works: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/how-it-works
  - UAC Architecture: https://learn.microsoft.com/en-us/windows/security/application-security/application-control/user-account-control/
  - Integrity Level SIDs: built-in SIDs S-1-16-0 through S-1-16-20480
- **Resource type:** Official documentation
- **Topic tags:** `MIC` `integrity-levels` `UAC` `elevation` `auto-elevation` `split-token` `filtered-token` `linked-token` `medium-integrity` `high-integrity` `IL-policy` `NO_WRITE_UP` `NO_READ_UP` `NO_EXECUTE_UP`
- **Difficulty:** Intermediate
- **Historical or current:** Current
- **Trust level:** ★★★★☆ — Official, but UAC specifics are not fully documented; S-001 fills the gaps
- **Why it matters:**
  Mandatory Integrity Control (MIC) and UAC are two of the most attacked components of the Windows security model. Understanding their mechanics is required to understand UAC bypass techniques, integrity level escalation attacks, and how medium-to-high escalation bugs work.
- **What it teaches:**
  - Integrity level SIDs and how they are embedded in tokens
  - MIC policy: NO_WRITE_UP (default), NO_READ_UP, NO_EXECUTE_UP flags
  - How MIC check is performed during access check (comes before DACL check)
  - UAC split-token mechanism: medium-integrity filtered token + linked high-integrity token
  - Auto-elevation: which executables auto-elevate (manifest, directory, digital signature checks)
  - UAC virtualization: registry and file system virtualization for legacy apps
  - COM elevation moniker: `CoCreateInstanceAsAdmin`
- **Best use:**
  Read the "How UAC Works" article carefully. Draw a diagram of the split-token model. Then read UAC bypass techniques (Matt Nelson / enigma0x3 posts) to understand what went wrong.
- **Related bug classes / primitives:**
  `UAC bypass` `auto-elevation abuse` `DLL hijacking in auto-elevated process` `COM elevation abuse` `integrity level write-up` `medium-to-high escalation`
- **Suggested next resource:** S-001 Chapter on UAC for deeper coverage; then study UAC bypass CVEs
- **Notes:**
  - Well-known UAC bypass researcher: Matt Nelson (enigma0x3) — https://enigma0x3.net/
  - UAC bypass techniques documented at: https://github.com/hfiref0x/UACME (UACME project)
  - Important: UAC is not a security boundary by Microsoft's definition. Bypassing UAC is a "defense in depth" issue, not a security vulnerability, per Microsoft policy.

---

### S-005 — Windows Privilege Constants

- **Title:** Windows Privilege Constants — Security API Documentation
- **Author / Organization:** Microsoft
- **URL:** https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants
  - AdjustTokenPrivileges: https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-adjusttokenprivileges
  - LookupPrivilegeValue: https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-lookupprivilegevaluea
- **Resource type:** Official documentation (reference)
- **Topic tags:** `privileges` `SeImpersonatePrivilege` `SeDebugPrivilege` `SeAssignPrimaryTokenPrivilege` `SeTcbPrivilege` `SeBackupPrivilege` `SeRestorePrivilege` `SeCreateTokenPrivilege` `SeLoadDriverPrivilege`
- **Difficulty:** Beginner to Intermediate
- **Historical or current:** Current
- **Trust level:** ★★★★★ — Authoritative definitions
- **Why it matters:**
  Windows privileges are a key attack primitive. Many privilege escalation chains terminate by abusing a powerful privilege held by the target process. `SeImpersonatePrivilege` is the classic example (Potato attacks). `SeDebugPrivilege` enables reading any process's memory. `SeLoadDriverPrivilege` enables loading arbitrary kernel drivers.
- **What it teaches:**
  - Complete list of Windows privileges with official descriptions
  - Which privileges are required for which operations
  - The privilege LUID system
  - How to enumerate, enable, and check privileges programmatically
- **Best use:**
  Use as a lookup table when analyzing processes or planning escalation chains. For each privilege held by a service or privileged process, consider: what does this enable? Can it be abused?
- **Related bug classes / primitives:**
  - `SeImpersonatePrivilege` → Potato attack family (PrintSpoofer, RoguePotato, GodPotato)
  - `SeDebugPrivilege` → Process memory read/write → token stealing
  - `SeLoadDriverPrivilege` → Arbitrary driver load → kernel code execution
  - `SeBackupPrivilege` → Read any file (bypass DACL) → SAM/SYSTEM hive dump
  - `SeRestorePrivilege` → Write any file (bypass DACL) → DLL planting
  - `SeCreateTokenPrivilege` → Create arbitrary token → SYSTEM
  - `SeTcbPrivilege` → Act as part of OS → unrestricted token creation
  - `SeAssignPrimaryTokenPrivilege` → Assign primary token to process
- **Suggested next resource:** S-009 (SeImpersonatePrivilege deep dive)
- **Notes:**
  - Privilege abuse cheat sheet:
    ```
    SeImpersonatePrivilege    → SYSTEM via named pipe impersonation (Potato)
    SeDebugPrivilege          → Read LSASS → dump credentials
    SeLoadDriverPrivilege     → Load vulnerable/malicious driver
    SeBackupPrivilege         → Read SAM/SYSTEM hives → credential dump
    SeRestorePrivilege        → Overwrite system files → persistence
    SeCreateTokenPrivilege    → Forge tokens (very rare to find)
    SeTcbPrivilege            → Full TCB → essentially SYSTEM
    ```
  - Check privileges held by services: `sc qprivs <service>`
  - Enumerate own token privileges: `whoami /priv`

---

### S-006 — AppContainer and Sandbox Internals

- **Title:** AppContainer and Less Privileged AppContainer (LPAC) Internals
- **Author / Organization:** James Forshaw / Google Project Zero (primary); Microsoft documentation (secondary)
- **URL:**
  - Forshaw AppContainer blog: https://googleprojectzero.blogspot.com/ (search "AppContainer")
  - "Digging into AppContainer Isolation" (2019): https://googleprojectzero.blogspot.com/2019/09/digging-into-appcontainer-isolation.html
  - MS Docs AppContainer: https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation
  - LPAC: https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-least-privilege
  - Capability SIDs: https://learn.microsoft.com/en-us/windows/win32/secauthz/capability-security-identifiers
- **Resource type:** Research blog posts + official documentation
- **Topic tags:** `AppContainer` `LPAC` `sandbox` `package-SID` `capability-SID` `sandbox-escape` `named-object-isolation` `device-namespace` `Win32k-lockdown` `broker-process` `IPC-security`
- **Difficulty:** Advanced
- **Historical or current:** Current — AppContainer is the primary browser and Store app sandbox model
- **Trust level:** ★★★★★ — Forshaw primary; MSDN secondary
- **Why it matters:**
  AppContainer is the sandbox used by Microsoft Edge (legacy), Edge (Chromium renderer, partially), UWP apps, and Windows Store apps. LPAC is used by Edge GPU and Network processes. Understanding AppContainer isolation is required for sandbox escape research.
- **What it teaches:**
  - AppContainer token structure: low-box token flag, package SID, capability SIDs
  - How the access check algorithm handles low-box tokens: the "Capability Check"
  - Package SID computation from package family name
  - Named object isolation: AppContainer gets its own object directory (`\Sessions\X\AppContainerNamedObjects\<PackageSid>\`)
  - File system and registry virtualization
  - Capability SIDs: what `internetClient`, `picturesLibrary`, `lpacCom`, etc. grant access to
  - LPAC: additional restrictions on top of AppContainer; use for high-value sandboxes
  - Sandbox escape attack surfaces: broker IPC, COM servers accessible from AppContainer, object namespace, filesystem
  - Win32k lockdown (syscall filtering for AppContainer processes)
- **Best use:**
  Read Forshaw's "Digging into AppContainer Isolation" post first, then supplement with MSDN. Essential for anyone researching browser or Windows Store app sandbox escapes.
- **Related bug classes / primitives:**
  `AppContainer escape` `capability bypass` `broker IPC vulnerability` `COM server accessible from sandbox` `object directory squatting` `LPAC bypass`
- **Suggested next resource:** S-007 (NtObjectManager for exploring AppContainer namespaces) and section 04 (Object Manager Namespace)
- **Notes:**
  - Use `Get-NtToken -Current` and inspect `AppContainer` flag and `Capabilities` in NtObjectManager
  - Process Monitor is useful for tracing what an AppContainer process can and cannot access
  - Edge (Chromium) uses a more complex multi-process model; LPAC applies to GPU/Network processes

---

### S-007 — NtObjectManager / sandbox-attacksurface-analysis-tools

- **Title:** sandbox-attacksurface-analysis-tools (NtObjectManager PowerShell Module + Analysis Tools)
- **Author / Organization:** James Forshaw / Google Project Zero
- **URL:** https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools
  - NtObjectManager on PSGallery: `Install-Module NtObjectManager`
  - Documentation: https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools/wiki
- **Resource type:** Open-source tool / PowerShell module (LAB-WORTHY)
- **Topic tags:** `NtObjectManager` `security-descriptor-analysis` `token-inspection` `object-manager` `ACL-analysis` `AppContainer-analysis` `sandbox-escape-research` `named-pipe-security` `privilege-checking` `access-check`
- **Difficulty:** Intermediate (PowerShell familiarity required)
- **Historical or current:** Current — actively maintained
- **Trust level:** ★★★★★ — Written by the author of Windows Security Internals; indispensable tool
- **Why it matters:**
  NtObjectManager provides a PowerShell interface to the Windows NT native API and security infrastructure. It makes visible what Windows Explorer and the standard tools hide: exact security descriptors, token contents, object manager internals, AppContainer analysis. It is the primary research tool for Windows security model investigation.
- **What it teaches / enables:**
  - **Token inspection:** `Get-NtToken`, `Get-NtTokenPrivilege`, `Test-NtTokenPrivilege`, `Get-NtTokenGroup`
  - **Security descriptor analysis:** `Get-NtSecurityDescriptor`, `Show-NtSecurityDescriptor`, `Set-NtSecurityDescriptor`
  - **Access check simulation:** `Test-NtAccessMask`, `Get-AccessibleObject`
  - **Object manager navigation:** `Get-NtObject`, `Get-NtDirectory`, `Get-NtSymbolicLink`
  - **AppContainer analysis:** `Get-AppContainerProfile`, `Test-NtToken -AppContainer`
  - **Named pipe security:** `Get-NtFile -PipeName`, security descriptor inspection
  - **Process and handle analysis:** `Get-NtProcess`, `Get-NtHandle`
  - **Accessible resource enumeration:** `Get-AccessibleProcess`, `Get-AccessibleFile`, `Get-AccessibleKey`
- **Best use:**
  Install immediately: `Install-Module NtObjectManager -Scope CurrentUser`. Use alongside every chapter of S-001. Run `Get-AccessibleProcess` as a low-privilege user to find processes you can open for attack. Run `Get-AccessibleFile` to find world-writable system paths.
- **Related bug classes / primitives:**
  Everything in the security model section — this tool is used to discover and verify all of them
- **Suggested next resource:** Work through S-001 with this tool open; or use to investigate any specific CVE's root cause
- **Notes:**
  - Key commands for initial exploration:
    ```powershell
    # Inspect current token
    $tok = Get-NtToken -Current
    $tok | Get-NtTokenPrivilege
    $tok | Get-NtTokenGroup
    $tok.IntegrityLevel

    # Find accessible processes
    Get-AccessibleProcess -AccessRights GenericWrite

    # Explore object manager
    ls NtObject:\  # Drive provider maps to object manager namespace
    Get-NtObject -Path \Device\NamedPipe

    # Check security descriptor
    Get-NtSecurityDescriptor -Path C:\Windows\System32\config\SAM -TypeName File |
      Show-NtSecurityDescriptor
    ```
  - The `AccessCheck` cmdlet replicates the exact Windows access check algorithm in PowerShell

---

### S-008 — Security Descriptor Deep Dive (Project Zero Research)

- **Title:** Security Descriptor Internals and Vulnerability Research
- **Author / Organization:** James Forshaw / Google Project Zero (primary)
- **URL:**
  - "Windows Exploitation Tricks: Arbitrary Directory Creation to Arbitrary File Read" (2019): https://googleprojectzero.blogspot.com/2019/03/windows-exploitation-tricks-arbitrary.html
  - "A Year in the Life of Project Zero: Windows" (various posts)
  - "Sharing a Logon Session a Little Too Liberally": https://googleprojectzero.blogspot.com/2019/04/sharing-logon-session-little-too.html
  - "Calling Local Windows RPC Servers from Non-Elevated Processes" (2019): https://googleprojectzero.blogspot.com/2019/01/calling-local-windows-rpc-servers-from.html
  - Project Zero issue tracker: https://bugs.chromium.org/p/project-zero/issues/list?q=windows+security+descriptor
- **Resource type:** Research blog posts (curated collection)
- **Topic tags:** `security-descriptor` `DACL-misconfiguration` `SD-inheritance` `object-security` `owner-privileges` `write-owner-exploit` `write-DACL-exploit` `NULL-DACL` `world-readable` `world-writable`
- **Difficulty:** Advanced
- **Historical or current:** Current
- **Trust level:** ★★★★★ — Primary research source
- **Why it matters:**
  Many Windows privilege escalation vulnerabilities are "just" security descriptor misconfigurations — a service running as SYSTEM with a world-writable directory, a COM server with overly permissive launch permissions, a registry key with WRITE_OWNER allowed to standard users. Forshaw's research shows how to find and exploit these systematically.
- **What it teaches:**
  - How to enumerate security descriptors on all object types
  - WRITE_DACL / WRITE_OWNER abuse: if you can modify a SD, you can grant yourself access
  - NULL DACL: no DACL = allow everyone (security descriptor without a DACL is fully permissive)
  - Inherited ACE attacks: a parent directory with a misconfigured inheritable ACE poisons all children
  - Owner semantics: the owner can always read and write the DACL regardless of the DACL content
  - SD attacks on specific object types: named pipes, COM servers, registry keys, directories, services
- **Best use:**
  Study alongside `Get-AccessibleObject` and `Get-AccessibleFile` from NtObjectManager. Use to develop a methodology for SD auditing of Windows components.
- **Related bug classes / primitives:**
  `DACL misconfiguration` `WRITE_OWNER escalation` `WRITE_DACL escalation` `NULL DACL` `directory traversal + SD inheritance` `COM activation permission abuse` `service binary path hijacking` (via world-writable dir)
- **Suggested next resource:** S-007 (NtObjectManager to automate SD auditing)
- **Notes:**
  - `icacls` and `Get-Acl` are the user-mode tools; `Get-NtSecurityDescriptor` gives kernel-level detail
  - PowerSploit's `Find-PathDLLHijack` and similar tools operationalize SD misconfiguration discovery
  - Project Zero issue tracker is a goldmine for real vulnerability examples with root cause analysis

---

### S-009 — SeImpersonatePrivilege and Token Impersonation Research

- **Title:** SeImpersonatePrivilege Exploitation — Decoder.cloud, itm4n, and Related Research
- **Author / Organization:** Andrea Pierini (decoder.cloud), Clément Labro (itm4n), James Forshaw (Project Zero)
- **URL:**
  - itm4n blog: https://itm4n.github.io/
  - itm4n - PrintSpoofer: https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/
  - itm4n - RoguePotato: https://jlajara.gitlab.io/Potatoes_Windows_Privesc (aggregated)
  - Decoder.cloud: https://decoder.cloud/
  - Rotten/Juicy/Sweet/Rogue/God Potato evolution: https://github.com/BeichenDream/GodPotato
  - Hot Potato (2016): https://foxglovesecurity.com/2016/01/16/hot-potato/
  - UACME project: https://github.com/hfiref0x/UACME
- **Resource type:** Research blog posts + PoC tools
- **Topic tags:** `SeImpersonatePrivilege` `token-impersonation` `named-pipe-impersonation` `NTLM-relay` `SYSTEM-impersonation` `Potato-attacks` `PrintSpoofer` `RoguePotato` `GodPotato` `service-account-escalation`
- **Difficulty:** Intermediate to Advanced
- **Historical or current:** Current — Potato attack family continues to evolve
- **Trust level:** ★★★★☆ — Highly practical; well-documented PoC tools; itm4n and decoder are respected researchers
- **Why it matters:**
  `SeImpersonatePrivilege` is held by virtually every Windows service account (IIS AppPool, SQL Server, etc.). The Potato attack family demonstrates that any process holding this privilege can escalate to SYSTEM via named pipe impersonation. This is one of the most operationally relevant Windows privilege escalation techniques.
- **What it teaches:**
  - Why service accounts hold `SeImpersonatePrivilege` (by design — they need to impersonate clients)
  - Named pipe impersonation: create a pipe, coerce SYSTEM to connect, call `ImpersonateNamedPipeClient`
  - NTLM relay via DCOM/RPC coercion (Hot Potato, Rotten Potato)
  - Print Spooler coercion: `RpcRemoteFindFirstPrinterChangeNotificationEx` forces SYSTEM authentication
  - Evolution: Hot Potato → Rotten Potato → Juicy Potato → Sweet Potato → PrintSpoofer → RoguePotato → GodPotato
  - Why each variant was needed (mitigations applied to previous versions)
  - Windows authentication coercion via various DCOM/RPC interfaces
- **Best use:**
  Study in sequence: understand `SeImpersonatePrivilege` semantics (S-005 + S-001), then read Hot Potato, then follow the Potato evolution chronologically to understand the cat-and-mouse with mitigations.
- **Related bug classes / primitives:**
  `SeImpersonatePrivilege` `named-pipe impersonation` `NTLM relay` `DCOM activation coercion` `print spooler abuse` `service account escalation`
- **Suggested next resource:** Study S-001 Chapter on impersonation for the theoretical foundation, then study SpoolSample and PetitPotam for coercion technique evolution
- **Notes:**
  - Lab this immediately: deploy in a Windows VM, grab a service account shell (IIS, SQL), run GodPotato
  - Key coercion techniques for impersonation: Print Spooler (SpoolSample), PetitPotam, DFSCoerce, ShadowCoerce
  - In 2022–2023, MS began restricting Print Spooler and LSARPC coercion — newer tools work around this
  - Reference: https://github.com/topotam/PetitPotam (LSARPC coercion)

---

### S-010 — Windows Credentials and LSA (Microsoft Documentation + Research)

- **Title:** Windows Credentials Architecture and Local Security Authority
- **Author / Organization:** Microsoft (primary); SecureAuth/Gentilkiwi (secondary)
- **URL:**
  - Windows Authentication Architecture: https://learn.microsoft.com/en-us/windows-server/security/windows-authentication/windows-authentication-architecture
  - LSASS Process Security: https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection
  - Credential Guard: https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/
  - Mimikatz documentation: https://github.com/gentilkiwi/mimikatz/wiki
  - Geoff Chappell on LSA: https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/se/
- **Resource type:** Documentation + tool documentation + research
- **Topic tags:** `LSA` `LSASS` `credentials` `Kerberos` `NTLM` `credential-guard` `DPAPI` `SAM` `NTDS.dit` `credential-dumping` `pass-the-hash` `pass-the-ticket` `protected-process-light`
- **Difficulty:** Intermediate to Advanced
- **Historical or current:** Current
- **Trust level:** ★★★★☆ — Official docs for architecture; Mimikatz docs are practical ground truth for credential operations
- **Why it matters:**
  Credential theft and lateral movement depend entirely on understanding how Windows stores and uses credentials. LSASS is the most attacked Windows process (credentials stored in memory). Credential Guard (VBS-based protection) changed the game significantly. Understanding both the attack surface and the defenses is essential.
- **What it teaches:**
  - LSA (Local Security Authority) architecture: LSASS process, LSA Server, authentication packages
  - NTLM authentication: challenge-response, NTHash storage in SAM, pass-the-hash
  - Kerberos: TGT/TGS flow, ticket caching in LSASS, pass-the-ticket, golden/silver tickets
  - DPAPI (Data Protection API): master key derivation, credential storage for browsers, RDP
  - Credential Guard: VTL1 isolation of Kerberos tickets and NTLM credentials
  - Protected Process Light (PPL): LSASS as PPL to prevent memory reading
  - Credential dumping mitigations: PPL + Credential Guard defense combination
  - SAM and NTDS.dit: offline credential extraction
- **Best use:**
  Read the architecture docs first, then follow with Mimikatz's wiki to understand the practical attack side. Study Credential Guard bypass research to understand the VBS attack surface.
- **Related bug classes / primitives:**
  `credential dumping` `LSASS memory read` `pass-the-hash` `pass-the-ticket` `DPAPI decryption` `SAM extraction` `PPL bypass` `Credential Guard bypass` `Golden Ticket`
- **Suggested next resource:** Study VBS (Virtualization-Based Security) architecture for Credential Guard bypasses; or move to section 06 (Lateral Movement)
- **Notes:**
  - Mimikatz commands:
    ```
    sekurlsa::logonpasswords   ; dump credentials from LSASS memory
    lsadump::sam               ; dump SAM hashes
    kerberos::list             ; list Kerberos tickets
    sekurlsa::pth              ; pass-the-hash
    ```
  - PPL bypass research: https://blog.slowerzs.net/posts/lsass-ppt-bypass/ and Elastic research
  - HiveNightmare (CVE-2021-36934): SAM hive ACL misconfiguration → all users can read SAM → NT hashes

---

## Security Model Attack Surface Map

```
Windows Security Model Attack Surface
════════════════════════════════════════════════════════════

Token Layer
├── Impersonation level bypass → get Impersonation/Delegation when only Identification available
├── SeImpersonatePrivilege → Potato attacks → SYSTEM
├── SeDebugPrivilege → LSASS memory read
├── SeCreateTokenPrivilege → forge arbitrary token
└── Token attribute manipulation (via NtSetInformationToken in limited cases)

Integrity Level / UAC Layer
├── UAC bypass → elevate medium → high without UAC dialog
├── Auto-elevation abuse → DLL hijacking in elevated process
└── Integrity level write-up → bypass MIC policy

AppContainer Layer
├── Capability bypass → access resource not granted by capability
├── Broker IPC vulnerability → escalate from AppContainer
├── COM server accessible from AppContainer
└── Object namespace isolation bypass

Security Descriptor / ACL Layer
├── DACL misconfiguration → world-writable system object
├── WRITE_DACL abuse → grant self access
├── WRITE_OWNER abuse → take ownership → grant self access
├── NULL DACL → fully accessible
└── Inherited ACE poison

Authentication / Credentials Layer
├── LSASS memory dump (requires SeDebugPrivilege or PPL bypass)
├── SAM hive extraction (HiveNightmare style)
├── Pass-the-Hash / Pass-the-Ticket
├── NTLM relay / coercion
└── DPAPI decryption
```

---

## Quick Reference: Essential PowerShell Commands

```powershell
# Install NtObjectManager
Install-Module NtObjectManager -Scope CurrentUser

# Token inspection
$tok = Get-NtToken -Current
$tok.IntegrityLevel          # Integrity level
$tok | Get-NtTokenPrivilege  # All privileges
$tok | Get-NtTokenGroup      # All groups including SIDs
$tok.AppContainer            # Is AppContainer?

# Find accessible processes with write access (privesc candidates)
Get-AccessibleProcess -AccessRights GenericWrite

# Find world-writable registry keys
Get-AccessibleKey -Win32Path HKLM:\ -AccessRights WriteKey -AllUsers

# Find world-writable files in system paths
Get-AccessibleFile -Win32Path C:\Windows\ -Recurse -AccessRights WriteData

# Show security descriptor
Get-NtSecurityDescriptor -Path \Device\NamedPipe -TypeName NamedPipe |
  Show-NtSecurityDescriptor

# Simulate access check
$sd = Get-NtSecurityDescriptor -Win32Path C:\Windows\System32
Test-NtAccessMask -SecurityDescriptor $sd -Access GenericWrite -Token $tok
```

---

*Last updated: 2026-04-22 | Section: 03_windows_security_model*
