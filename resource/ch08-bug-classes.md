# Chapter 08 — Windows LPE Bug Classes
## A Systematic Reference for Local Privilege Escalation Vulnerability Patterns

---

## Introduction: The Bug Class Mental Model

Windows Local Privilege Escalation research benefits from a categorical framework. Individual CVEs are facts; bug classes are patterns. Learning the pattern lets you recognize the next variant before a CVE number exists.

Every Windows LPE bug ultimately provides one or more **primitives**: arbitrary file write, arbitrary file move, arbitrary file delete, token impersonation, or kernel memory access. The bug class describes *how* the primitive is obtained and *what structural weakness enables it*. The exploit chain describes how the primitive is converted into code execution as SYSTEM.

This chapter catalogs the canonical bug classes in depth: definition, root cause, detection methodology, CVE examples, tooling, and defensive mitigations. The final section provides a master mapping table.

---

## 1. Arbitrary File Write / Move / Delete

> **See also:** ch06 §7 (Arbitrary File Write → LPE Chain), ch09 §1 (File System Primitives)

### 1.1 Definition and What Makes It LPE-able

An **arbitrary file write** is the ability to write attacker-controlled content to an attacker-chosen path, with the write executing in a privileged context (SYSTEM, LocalSystem, or a high-privilege service account). Alone, writing a file doesn't escalate privilege. What makes it LPE-able is the conversion step: getting a privileged process to *execute* the written content.

The three filesystem primitive variants follow the same structural pattern:

- **Write:** Drop a payload at a target path → trigger execution
- **Move/Rename:** Relocate a user-controlled file to a privileged path → trigger execution
- **Delete:** Remove a trusted file → force search-order fallback to user-controlled location

**Junction redirect chain (the universal conversion mechanism):**

The core technique for amplifying a constrained filesystem primitive into an arbitrary one is the NTFS junction (mount point) combined with Object Manager namespace manipulation:

```
Privileged process wants to: write/move/delete C:\Legit\Path\file.dll
                                      ↓
Attacker replaces C:\Legit\Path\ with a junction → C:\Windows\System32\
                                      ↓
Privileged process now operates on: C:\Windows\System32\file.dll
                                      ↓
Result: Arbitrary file write/move/delete to System32
```

**Preconditions for junction redirect to work:**
1. The privileged process opens the path without `OBJ_DONT_REPARSE` flag in `NtCreateFile`, or without `FILE_FLAG_OPEN_REPARSE_POINT` in Win32 `CreateFile`
2. The directory containing the target file must be replaceable — either the attacker can delete it and create a junction, or the directory didn't exist yet
3. The operation occurs under a privileged security context (the write check uses SYSTEM, not the caller's token)

Condition 3 is caused by **missing impersonation**: privileged services that receive file operation requests from users are supposed to call `ImpersonateClient()` before performing the file operation. When they fail to do this, the file I/O check uses the service's SYSTEM token instead of the calling user's token — granting access to paths the user should not be able to write.

### 1.2 WER as Write Source

Windows Error Reporting (WER) creates crash dump files as SYSTEM in paths partially influenced by process metadata. The dump write is an arbitrary *content-fixed* file write — you can write to arbitrary paths but the content is a crash dump structure. Combining with junction redirect: write a dump to `C:\Windows\System32\` to create a file whose name matches an expected DLL, then exploit any code path that checks file existence rather than content.

#### 1.2.1 CVE-2024-30030 — WER Arbitrary File Write LPE Chain

**Discovery and class:** CVE-2024-30030 is a WER-based arbitrary file write patched in May 2024 Patch Tuesday. The vulnerability exists in how WER resolves the target path for a report file when a crash is submitted by a low-privilege process. WER runs as SYSTEM via the `WerSvc` service and does not adequately impersonate the reporting process before creating the report output file.

**Exploit chain walkthrough:**
```
Step 1: Attacker process crashes deliberately with crafted crash parameters
        → WerSvc picks up the crash report request

Step 2: Craft the LocalAppDataPath or report path segment to include a junction
        → WerSvc attempts to create: C:\Users\victim\AppData\Local\CrashDumps\report.wer
        → CrashDumps\ is replaced with a junction → C:\Windows\System32\

Step 3: WER writes the .wer report file as SYSTEM to C:\Windows\System32\report.wer
        → File is now owned by SYSTEM, written to System32

Step 4: Convert file write → code execution
        → Use a DLL search order trick: if the .wer extension maps to a COM handler
          that is a phantom DLL, or rename via a second primitive to a .dll name
        → Alternatively: overwrite an existing writable config file that a SYSTEM
          service reads on next restart
```

**Patch:** The fix adds proper impersonation (`RpcImpersonateClient` / `ImpersonateLoggedOnUser`) before the report file creation step, ensuring the write runs under the caller's token rather than SYSTEM.

**Detection:** Procmon filter `Process Name = WerFault.exe OR WerSvc.exe`, `Operation = CreateFile`, `Path contains junction point`.

### 1.3 BITS as Write Source

CVE-2020-0787 — the BITS job completion writes the downloaded file to the destination path as SYSTEM without impersonating the job owner. Junction the destination directory between job enqueue and completion → arbitrary file write to any SYSTEM-writable path. Content is fully attacker-controlled (the HTTP/file source content).

### 1.4 MSI as Write Source

The Windows Installer repair flow (`msiexec /fav`) moves staged files as SYSTEM. Junction the staging directory to an arbitrary destination → InstallerFileTakeOver pattern. Content is the original file from the MSI package, which the attacker controls by crafting the job or choosing an appropriate existing MSI.

#### 1.4.1 CVE-2025-21204 — Windows Update Arbitrary File Move via Installer Symlink

**Vulnerability class:** Arbitrary file move / rename during the Windows Update staging process. Reported in early 2025 and patched in April 2025 Patch Tuesday.

**Root cause:** The Windows Update orchestrator (`TiWorker.exe` / `TrustedInstaller`) stages update files to a temporary location under `C:\Windows\WinSxS\` or `C:\$WinREAgent\` before committing them. During the commit phase, a `MoveFileEx` or `NtSetInformationFile` rename operation is performed as SYSTEM without validating whether intermediate directories have been replaced with junctions.

**Exploitation approach:**
```
1. Monitor for update staging events (Procmon: TiWorker.exe, SetRenameInformationFile)
2. Identify the staging temp directory path (predictable or enumerable)
3. Replace the staging directory with a junction to the target directory
   (e.g., C:\Windows\System32\)
4. The rename operation now moves the staged update file into System32
5. If the staged file is an EXE or DLL with matching name, it is loaded on next
   service start or on demand
```

**Constraints:** Requires timing (race window during update commit), and the file content is the update payload itself. Most useful when combined with a crafted update package or when a suitable file name collision exists.

**Mitigation added:** TrustedInstaller now validates that the staging and destination paths do not traverse symbolic links or junctions prior to the rename commit, using `NtCreateFile` with `FILE_OPEN_REPARSE_POINT` semantics.

### 1.5 Arbitrary File Delete → DLL Hijack Chain

Delete-to-LPE is the least intuitive but follows the same logic. When a SYSTEM process deletes `C:\Windows\System32\wbem\XYZ.dll`, the DLL is gone from its canonical location. If Windows then loads that DLL (e.g., via WMI service), the loader searches the next location in the DLL search order — which may include user-writable paths.

```
Step 1: Privileged service deletes C:\Windows\System32\SomeDLL.dll
        (via junction redirect — the service thought it was deleting C:\Temp\file.tmp)
Step 2: SYSTEM service that uses SomeDLL.dll tries to load it
Step 3: DLL search order: System32 → not found → falls back to PATH → attacker-planted
Step 4: Attacker DLL loaded as SYSTEM
```

**CVE-2022-21838 (Windows Cleanup Manager):** Disk Cleanup runs as SYSTEM and processes attacker-influenced paths. Deleting a DLL triggered the fallback load pattern.

### 1.6 NtCreateFile with FILE_OPEN_REPARSE_POINT — 24H2 Bypass Research

**Background:** In Windows 11 24H2, Microsoft tightened several filesystem primitive mitigations. Privileged services were updated to use `NtCreateFile` with `FILE_OPEN_REPARSE_POINT` to avoid following junctions. However, 2024 research by multiple independent researchers identified a residual bypass condition.

**The bypass condition:**
`FILE_OPEN_REPARSE_POINT` on `NtCreateFile` prevents the kernel from following reparse points when *opening the file itself*. However, it does **not** prevent following junctions on intermediate directory components of the path. If the path is `C:\Dir1\Dir2\target.dll` and `Dir1` is a junction, the kernel will follow the junction on `Dir1` even when `FILE_OPEN_REPARSE_POINT` is set on the final component open.

```c
// Affected code pattern (simplified):
NtCreateFile(
    &hFile,
    GENERIC_WRITE,
    &objAttr,  // path: C:\Dir1\Dir2\target.dll
    ...
    FILE_OPEN_REPARSE_POINT  // Prevents following target.dll reparse point
                              // Does NOT prevent following Dir1 or Dir2 junctions
);
```

**Complete protection requires:** `OBJ_DONT_REPARSE` flag in the `OBJECT_ATTRIBUTES` structure, which prevents junction traversal on *all* path components, not just the final file. This flag is set on the `ObjectAttributes` passed to `NtCreateFile`, not as a `CreateOptions` flag.

**Practical impact:** Services that were "fixed" to use `FILE_OPEN_REPARSE_POINT` but not `OBJ_DONT_REPARSE` remain vulnerable to intermediate directory junction substitution. Researchers recommended `AccessCheck` tooling specifically look for this half-mitigation pattern.

### 1.7 WinDbg — Arbitrary File Write Analysis

```windbg
; Monitor file write targets during exploit
kd> !object \Device\HarddiskVolume3
kd> dt nt!_FILE_OBJECT poi(@rcx)
kd> bp ntdll!NtCreateFile "du @r8; g"  ; log file paths
```

### 1.8 How to Find Arbitrary File Write/Move/Delete Bugs

**Process Monitor methodology:**
1. Filter: `Process Name = <privileged binary>`, `Operation = CreateFile OR WriteFile OR SetRenameInformationFile`, `Path starts with C:\` or target path
2. Look for write/move/delete operations on paths that include user-controlled segments
3. Verify: does the privileged process call `ImpersonateClient()` before this operation? (Check in reverse engineering tool)

**Code review red flags:**
- `CreateFile(userPath, GENERIC_WRITE, ...)` without prior impersonation
- `MoveFileEx(srcPath, dstPath, ...)` where `dstPath` derives from user input or registry values
- `DeleteFile(userPath)` in service cleanup code
- Absence of `OBJ_DONT_REPARSE` / `FILE_FLAG_OPEN_REPARSE_POINT` in file open calls on directory-traversing paths
- `FILE_OPEN_REPARSE_POINT` used without `OBJ_DONT_REPARSE` (24H2 half-mitigation pattern)

---

## 2. Junction + Oplock TOCTOU

> **See also:** ch06 §6 (BaitAndSwitch pattern), ch04 §4 (Object Manager namespace)

### 2.1 The TOCTOU Race Window

Time-of-Check Time-of-Use (TOCTOU) bugs arise when a privileged process:
1. **Checks** some security property of a path (ACL, file existence, signature)
2. **Uses** the path for a privileged operation
3. Between check and use, an attacker **changes** what the path refers to

The attacker's challenge: the race window between check and use may be microseconds — too short to win reliably.

### 2.2 BaitAndSwitch — Oplocks as a Race Window Controller

**Opportunistic locks (oplocks)** are a file system feature allowing a process to be notified before another process accesses a locked file. Security researchers repurpose this: lock the "bait" file with an oplock, wait for the privileged process to touch it, receive the oplock break notification (process is paused), perform the junction swap, release the oplock, allow the privileged process to continue — now operating on the swapped target.

**Oplock types relevant to exploitation:**
- **Filter oplock** (`FSCTL_REQUEST_OPLOCK` with `OPLOCK_LEVEL_CACHE_HANDLE`): fires when a process opens the file. The opening process is blocked until the oplock holder responds. Most useful for exploit sequences.
- **Batch oplock**: fires when a process closes the file after a sequence of opens (useful for some specific patterns)
- **Read-Handle oplock**: Windows 7+; fires on certain sharing violations

**BaitAndSwitch sequence:**
```
1. Create bait file: C:\Temp\Work\bait.dll (empty or benign content)

2. Set filter oplock on bait.dll:
   hFile = CreateFile("C:\Temp\Work\bait.dll", GENERIC_READ, 0, ...)
   DeviceIoControl(hFile, FSCTL_REQUEST_OPLOCK, &inputBuffer, ...)
   // Subscribe to oplock break notification asynchronously

3. Trigger privileged operation:
   e.g., msiexec /fav {GUID} which will try to operate on C:\Temp\Work\bait.dll

4. Privileged process tries to open bait.dll
   → Oplock fires: notification delivered to attacker's thread
   → Privileged process is BLOCKED (cannot proceed until oplock released)

5. Attacker swaps the directory:
   RemoveDirectory("C:\Temp\Work\")
   CreateJunction("C:\Temp\Work\", "C:\Windows\System32\")
   // Now C:\Temp\Work\bait.dll points to C:\Windows\System32\bait.dll

6. Release oplock:
   CloseHandle(hFile)  // or explicit FSCTL_OPLOCK_BREAK_ACKNOWLEDGE

7. Privileged process resumes — now opening C:\Windows\System32\bait.dll
   → Arbitrary file operation at System32
```

**Required privileges:** None beyond what's needed to create the bait file. Standard user can set filter oplocks on files they own.

**Tools:** `SetOpLock.exe` and `BaitAndSwitch.exe` from James Forshaw's `symboliclink-testing-tools` repository implement this pattern.

### 2.3 WinDbg — Oplock Inspection

```windbg
; Inspect oplock state on a file
kd> dt nt!_OPLOCK
kd> !fltkd.filter  ; list registered minifilters
kd> bp nt!FsRtlOplockBreakH "k; g"  ; trace oplock breaks
```

### 2.4 Thread Race vs. Oplock-Assisted Race

Without oplocks, TOCTOU exploitation requires winning a tight timing window. This is unreliable (race is probabilistic, not deterministic). Oplocks make it deterministic: the privileged process literally cannot proceed until the attacker says so.

For bugs where the target file is not under attacker control (can't set oplock on the file being operated on), thread racing remains the fallback. Modern exploit research strongly prefers oplock-based approaches when applicable.

---

## 3. Token Impersonation — The Potato Family

> **See also:** ch05 §5 (Named pipe squatting), ch09 §6 (Named Pipe Primitives)

### 3.1 SeImpersonatePrivilege — The Prerequisite

`SeImpersonatePrivilege` grants a process the ability to impersonate another user's security context. The Windows security model grants this privilege to service accounts specifically so they can act on behalf of clients. IIS worker processes need it to enforce per-request access control. SQL Server needs it for database connections. Any code execution in a Windows service context (IIS, MSSQL, SQL Agent, Print Spooler worker) almost certainly has this privilege.

**Check immediately upon gaining service-level code execution:**
```cmd
whoami /priv
```

If `SeImpersonatePrivilege` appears as `Enabled`, SYSTEM is reachable.

The API entry point: `ImpersonateNamedPipeClient(hPipe)` — if a SYSTEM process is connected to a named pipe the attacker controls, calling this API on the pipe handle grants the SYSTEM token to the current thread. Everything else in the Potato family is about causing a SYSTEM process to make that connection.

### 3.2 COM OXID Resolver Abuse — JuicyPotato / RottenPotato

**Rotten Potato (2016) — foxglovesecurity:**
The original technique used the DCOM activation service. When a client activates a DCOM object running as SYSTEM, the activation service contacts the specified object's server. By manipulating the OXID (Object Exporter ID) resolver through COM infrastructure, the authentication flow could be redirected through a local NTLM relay, capturing the SYSTEM token.

**JuicyPotato (2018):**
Extended the CLSID-based approach with a comprehensive database of Windows CLSIDs whose activation triggers SYSTEM-level authentication. Made the technique trivially scriptable. Worked on Windows Server 2016 and earlier.

**Mitigation:** Windows 10 1809 / Server 2019 restricted loopback DCOM activation — the DCOM service would no longer activate objects over a loopback COM channel in a way that could be intercepted.

**RoguePotato (2020) — Decoder:**
Circumvented the loopback restriction by using a remote OXID resolver. The DCOM activation call specifies an OXID resolver on a *remote* attacker-controlled machine. The DCOM service on the target contacts the remote OXID resolver, which relays through to the local named pipe on the target. This bypasses the loopback check because the connection originates from a remote address.

**Limitation:** Requires a helper machine (or SSH tunnel to a public server) acting as the relay.

### 3.3 Named Pipe Capture — PrintSpoofer and GodPotato

**PrintSpoofer (2020) — itm4n:**
The Print Spooler service, when triggered to notify a client about a printer change, connects back to the client's named pipe. The attacker creates a named pipe server with a name the Spooler will connect to, then calls `OpenPrinter` with a crafted printer path to trigger the Spooler's outbound connection. The Spooler connects as SYSTEM. `ImpersonateNamedPipeClient` → SYSTEM token.

```
CreateNamedPipe("\\.\pipe\\spoolss\<session>.<unique>", PIPE_ACCESS_DUPLEX, ...)
→ Call to trigger Spooler connection
→ Spooler (SYSTEM) connects
→ ImpersonateNamedPipeClient()
→ Token duplication + CreateProcessWithToken
```

No DCOM needed. No remote machine needed. Single-machine, entirely local.

**GodPotato (2022) — BeichenDream:**
Uses the ITaskSchedulerService COM interface instead of the Print Spooler. Registers a COM object pointing to an attacker-controlled named pipe, then triggers the Task Scheduler to activate it. The Task Scheduler (SYSTEM) connects to the fake COM server's named pipe. Supports Windows Server 2012 through 2022, and works when the Print Spooler is disabled.

```
1. Register fake COM server → pipe endpoint
2. Register scheduled task with COM action pointing to fake server
3. Task Scheduler (SYSTEM) activates COM → connects to attacker pipe
4. ImpersonateNamedPipeClient → SYSTEM
```

### 3.4 NTLM Reflection — LocalPotato (CVE-2023-21746)

**LocalPotato — Decoder (Antonio Cocomazzi):**
A fundamentally different lineage. Instead of inducing a SYSTEM process to connect to a named pipe, LocalPotato exploits the NTLM SSP at the SSPI level. A low-privilege process initiates an NTLM authentication handshake and reflects the challenge back to a high-privilege local service, tricking the service into completing an authentication the attacker initiated.

**At the SSPI level:**
```
Attacker (low-priv) calls InitializeSecurityContext() → generates NTLM NEGOTIATE
Passes NEGOTIATE to high-privilege local service (via IPC)
High-privilege service calls AcceptSecurityContext() → generates NTLM CHALLENGE
Attacker reflects CHALLENGE back to their own InitializeSecurityContext() → generates NTLM AUTHENTICATE
Attacker feeds AUTHENTICATE to AcceptSecurityContext() → service accepts
Result: Attacker authenticated as the high-privilege service principal
```

**No pipe required. No DCOM. No Print Spooler.** The reflection occurs at the NTLM SSP layer entirely within local inter-process communication.

Patched in January 2023 Patch Tuesday (CVE-2023-21746).

#### 3.4.1 LocalPotato 2024 Variants — NTLM Local Relay Continuations

Even after CVE-2023-21746 was patched, the underlying NTLM local relay class was not fully eliminated. 2024 research identified residual configurations where the reflection path is viable:

- **Extended Protection for Authentication (EPA) gaps:** EPA binds NTLM tokens to the TLS channel they traverse, preventing relay to a different channel. Services that do not enforce EPA (or only partially enforce it) remain susceptible to local NTLM relay variants. Researchers found several Windows inbox services still negotiating without EPA requirements in 2024.
- **Credential Guard interaction:** On systems with Credential Guard enabled, NTLM authentication for domain accounts is routed through isolated LSA. Local machine account authentication (which does not use VTL1-isolated credentials) can still be targeted.
- **Specific relay targets:** Rather than generic token capture, 2024 variants target specific COM/RPC interfaces that accept NTLM authentication and run as LocalSystem, constructing a constrained relay path.

### 3.5 CoercedPotato (2024) — DCOM/RPC Local Coercion Without CLSID Dependency

**Overview:** CoercedPotato is a 2024 technique that extends the Potato lineage by removing the dependency on a specific CLSID registry entry. Prior DCOM-based potatoes required identifying a CLSID registered with a LocalSystem activation account that could be triggered over the DCOM channel. CoercedPotato uses direct RPC interface coercion instead.

**Mechanism:**
```
1. Identify an RPC interface exposed locally that runs under SYSTEM
   and accepts calls from low-privilege callers (no authentication required
   or NetworkService/AppPool allowed)

2. Find a method on that interface that, as a side-effect, causes
   the RPC server to call back to a caller-supplied named pipe or COM server

3. Create the listener pipe/endpoint before issuing the coercive RPC call

4. Issue the RPC call → SYSTEM service connects to attacker listener

5. ImpersonateNamedPipeClient → SYSTEM token
```

**Why it avoids CLSID dependency:** The coercion happens via direct RPC method invocation on a known interface UUID, not through COM activation infrastructure. No registry modification needed. No `CoCreateInstance` call required.

**Relationship to EfsRpcOpenFileRaw:** This technique is conceptually similar to PetitPotam's abuse of `EfsRpcOpenFileRaw` for network coercion, but targeted at local RPC endpoints that trigger callbacks.

### 3.6 PrintSpoofer Aftermath — EfsRpcOpenFileRaw Residual Usability

`EfsRpcOpenFileRaw` (the basis of PetitPotam) triggers the EFS service to open a file on behalf of the caller, which causes NTLM authentication to the UNC path provided. Originally used for network coercion, it also has local application:

- **Partially patched:** Microsoft's KB5005413 guidance required configuring EFS RPC authentication requirements, but did not patch the underlying RPC interface. Systems without the mitigation applied (still common in enterprise environments where the patch caused operational issues) retain the original behavior.
- **Local coercion path:** Supplying a UNC path pointing to the attacker's local named pipe instead of a remote host works as a local named pipe coercion. The EFS service (which runs as SYSTEM) opens the UNC path, connecting to the attacker's pipe.
- **2024 configurations still usable:** Domain-joined workstations where EFS is enabled for key recovery scenarios, legacy Windows Server 2016/2019 systems not yet patched, and environments where the KB5005413 mitigation was intentionally reverted due to compatibility issues.

### 3.7 Windows Server 2025 — Extended Protection Hardening Impact

Windows Server 2025 ships with several default-enabled protections that raise the difficulty of classic Potato techniques:

| Protection | Impact on Potato Family |
|---|---|
| EPA (Extended Protection for Authentication) enabled by default on more services | Blocks NTLM relay-based potatoes that target those services |
| Credential Guard default-on (domain-joined) | Protects domain credential NTLM flows; local machine auth still targetable |
| Restricted DCOM loopback (extended from Server 2019) | Classic JuicyPotato CLSID activation fails |
| Print Spooler disabled by default | PrintSpoofer/SpoolFool primary vector unavailable without enablement |
| SMB signing enforced | Reduces relay options if Potato falls back to SMB relay |

**Practical status on Server 2025:**
- GodPotato (Task Scheduler COM) remains the most reliable option where Task Scheduler is running
- CoercedPotato and RPC interface coercion are the research frontier for remaining viable paths
- `SeImpersonatePrivilege`-to-SYSTEM conversion via named pipe capture is still architecturally possible, but finding the trigger is harder

### 3.8 SharpToken (2024) — Improved Token Stealing and Impersonation

**SharpToken** is a 2024 .NET tool for token manipulation that extends the classic `OpenProcessToken` + `DuplicateTokenEx` + `CreateProcessWithToken` chain with improvements for modern Windows mitigations.

**Key capabilities:**
- **Token enumeration across all sessions:** Lists tokens from all running processes, including sessions 0 services, with privilege and integrity information
- **Token filtering by privilege set:** Can search for processes with specific privileges (e.g., `SeImpersonatePrivilege`, `SeTcbPrivilege`, `SeAssignPrimaryTokenPrivilege`) to identify the best steal target
- **Handle duplication via `NtDuplicateObject`:** Where `OpenProcessToken` fails due to DACL, attempts to find processes that have already opened the target token and duplicate the handle through the kernel handle table
- **Secondary logon bypass:** Uses `CreateProcessAsUser` with a stolen token to spawn elevated processes, handling the primary/impersonation token distinction
- **Integration with named pipe impersonation:** Wraps the pipe capture workflow so the captured impersonation token is correctly elevated to a primary token before process creation

**Operational use:** Particularly useful in scenarios where the attacker has code execution as NetworkService or a service account with `SeImpersonatePrivilege` and needs to identify the most stable SYSTEM token source among many candidate processes.

### 3.9 WinDbg — Token Impersonation Analysis

```windbg
; Enumerate impersonatable tokens
kd> !token  ; current thread token
kd> dt nt!_TOKEN @$thread->ClientSecurity.Token
kd> dps nt!PspReferencePrimaryToken L1  ; primary token
; Find SYSTEM token
kd> !process 0 0 System
kd> dt nt!_EPROCESS <addr> Token
```

### 3.10 The Potato Progression — Timeline and Evolution

| Tool | Year | Mechanism | Windows Compatibility | Status |
|------|:----:|:---|:---:|:---:|
| Hot Potato | 2016 | NBNS spoofing + NTLM relay | Win 7/8.1/Server 2008-2012 | Historical |
| Rotten Potato | 2016 | DCOM OXID + NTLM loopback | Pre-1809 | Historical |
| Juicy Potato | 2018 | Extended CLSID DCOM list | Pre-1809 | Historical |
| Sweet Potato | 2020 | EfsRpc + WebClient + pipe variants | Win 10 / Server 2019 | Active |
| Rogue Potato | 2020 | Remote OXID resolver relay | Win 10 / Server 2019 | Active (needs relay) |
| Print Spoofer | 2020 | Spooler named pipe | Win 10 / Server 2019 | Active (Spooler on) |
| God Potato | 2022 | Task Scheduler COM | Server 2012–2022 / Win 10-11 | Active |
| Local Potato | 2023 | NTLM SSPI reflection | Pre-Jan 2023 patch | Patched |
| CoercedPotato | 2024 | Direct RPC coercion, no CLSID | Win 10/11, Server 2019–2025 | Active |

---

## 4. RPC / COM / Named Pipe Boundary Bugs

### 4.1 Wrong Impersonation Level

When an RPC or COM server impersonates a client, the impersonation level determines what the server can do with the client's token:
- `SecurityAnonymous` — cannot access resources on behalf of client
- `SecurityIdentification` — can identify the client but cannot act as them
- `SecurityImpersonation` — can act as client for local resources
- `SecurityDelegation` — can delegate client credentials to remote services

**Bug pattern:** An RPC server impersonates with `SecurityIdentification` but then calls file APIs that require `SecurityImpersonation` to properly enforce access. The result: the file API falls back to the server's token (SYSTEM) rather than the client's token. This is the missing impersonation pattern described in §1.1.

**Detection (code review):**
```c
// Vulnerable pattern:
RpcImpersonateClient(NULL);  // Default level = SecurityImpersonation? Not always.
CreateFile(clientSuppliedPath, GENERIC_WRITE, ...);  // Uses server token if impersonation fails
RpcRevertToSelf();

// Secure pattern:
RpcImpersonateClient(NULL);
// Verify impersonation level before proceeding
HANDLE hToken;
OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken);
// Check GetTokenInformation(hToken, TokenImpersonationLevel, ...)
CreateFile(clientSuppliedPath, GENERIC_WRITE, ...);
RpcRevertToSelf();
```

### 4.2 Missing Security Callback in RPC

RPC servers can register a security callback function via `RpcServerRegisterAuthInfo` and per-interface security callbacks. The callback verifies that the caller is authorized before the RPC stub executes. If the security callback is missing or returns success for all callers, any authenticated (or even unauthenticated) client can invoke the interface.

**Example:** PetitPotam (MS-EFSR) was originally callable without authentication on many systems because the EFS RPC interface lacked adequate authentication requirements for some methods.

### 4.3 COM Activation with Wrong Identity

COM classes registered with `RunAs = Interactive User` or `RunAs = <specific account>` can be activated such that they run under the specified identity. If a low-privilege user can activate a COM class that runs as SYSTEM or a high-privilege account, and the COM class exposes methods that execute code, this is an LPE.

The COM Elevation Moniker (`Elevation:Administrator!new:{CLSID}`) is a designed mechanism that prompts for UAC elevation. Forshaw documented how misconfigured COM classes could be auto-elevated without a prompt.

---

## 5. Object Manager Namespace Abuse

> **See also:** ch04 (Object Manager — full chapter)

### 5.1 Directory DACL Weakness

The Windows Object Manager namespace (`\`, `\Device`, `\??\`, `\RPC Control`, `\Sessions\N\BaseNamedObjects`) is the kernel's naming layer beneath all Win32 APIs. Every named kernel object (file, pipe, event, semaphore, registry key) is accessible through this namespace.

**`\??\` (per-user DOS device namespace):** Each user session has a private `\??\` directory. Win32 paths like `C:\foo` translate to `\??\C:\foo` through this directory. Low-privilege users can create symbolic links *within their own `\??\`* without special privileges. This is the basis for object manager symlink attacks.

**`\RPC Control\` directory:** Named pipes appear here as `\RPC Control\pipename`. If a user can create objects in `\RPC Control\`, they can create a symbolic link pointing to their own pipe, squatting on a pipe name before the legitimate service creates it. When the privileged service connects to "its" pipe (actually the attacker's), impersonation follows.

**DACL weakness pattern:** On some Windows versions, `\Sessions\N\BaseNamedObjects\` has world-writable permissions for certain subdirectories. An attacker who can create a symbolic link in a directory that a SYSTEM process traverses can redirect the SYSTEM process to an attacker-controlled object.

### 5.2 Device Map Redirect

`\??\` is sometimes called the "dos device map." A process's per-session `DosDevices` directory controls how drive letters are resolved. If an attacker can redirect `\??\C:` to a different volume or directory tree, all `C:\` paths for that process are redirected.

**DefineDosDevice race:** The `DefineDosDevice` API modifies the DOS device namespace. Combined with a TOCTOU race, the namespace state can be changed between a privileged process's path canonicalization and its file open call.

### 5.3 Practical Namespace Abuse Tools

- **`WinObj` (Sysinternals):** GUI browser for the NT Object Manager namespace
- **NtObjectManager PowerShell module (Forshaw):** Scriptable namespace access; `Get-NtDirectory`, `Get-NtObject`, `New-NtSymbolicLink`
- **CreateMountPoint.exe / CreateSymlink.exe (symboliclink-testing-tools):** Create specific link types for lab testing

---

## 6. DLL Hijacking / Search Order Abuse

> **See also:** ch07 §3 (MSI DLL hijacking), ch15 (Tools: msiscan)

### 6.1 LoadLibrary Search Order Deep Dive

When a process calls `LoadLibrary("example.dll")` or `LoadLibraryEx("example.dll", NULL, 0)` without a full path, the loader searches:

1. DLL Redirection (`.local` files or manifests)
2. Application manifest / WinSxS assembly
3. Loaded module list (already in memory)
4. **KnownDLLs** — `HKLM\SYSTEM\...\KnownDLLs` — fully immune to hijack (loaded from `\KnownDlls` object, not filesystem)
5. Application directory (same directory as the EXE)
6. `GetSystemDirectory()` — `C:\Windows\System32\`
7. `C:\Windows\System\` (16-bit)
8. `C:\Windows\`
9. **Current working directory** (if `SafeDllSearchMode = 0`, or position 5 with mode enabled)
10. **PATH directories** in order

**Hijack-resistant loading:** `LoadLibraryEx(name, NULL, LOAD_LIBRARY_SEARCH_SYSTEM32)` searches *only* System32. This is the secure form but many applications don't use it.

### 6.2 DLL Planting via Writable Directory

**Attack:** If a SYSTEM-level application has a writable directory early in its DLL search order, plant a DLL there with the expected name.

**Common writable locations to check:**
- `C:\ProgramData\<VendorName>\` — often writable by all users by default
- `C:\` root directory — writable on some misconfigured systems
- Per-user `%APPDATA%` or `%LOCALAPPDATA%` — always user-writable; lower value (only helps if privileged process runs as current user with elevated token)
- PATH entries — check `icacls` on each directory in `%PATH%`

### 6.3 Phantom DLL

A phantom DLL is one that Windows expects to exist in System32 but doesn't (was removed, never installed, or architecture-specific). When a SYSTEM process loads a phantom DLL and the search falls through to a writable PATH directory, the phantom becomes a plant target.

**Historical examples:**
- `wlbsctrl.dll` (IKEEXT service) — missing on many systems; well-known LPE target for years
- `TSMSISrv.dll` — Terminal Services-related, missing on minimal installs
- `DiagnosticsHub.StandardCollector.Proxy.dll` — missing in some configurations

### 6.4 KnownDLLs Bypass

DLLs in `HKLM\SYSTEM\...\Session Manager\KnownDLLs` cannot be hijacked via search order — the kernel loads them directly from the `\KnownDlls` object directory. However:
- KnownDLLs only protects DLLs *explicitly listed*. Dependencies of KnownDLLs are not necessarily protected.
- A KnownDLL's dependency that is not itself in KnownDLLs *can* be hijacked.

### 6.5 Weak Registry ACLs for DLL Configuration

Some services store their DLL path in registry values. If the registry key is writable, modifying the `ServiceDll` or equivalent value redirects which DLL is loaded. This is a registry-ACL bug that results in a DLL hijack.

**The RpcEptMapper pattern (itm4n):**
The `RpcEptMapper` service's `Parameters` subkey was writable by low-privilege users on unpatched Windows 10. Writing a `ServiceDll` value pointing to a malicious DLL caused the service host to load it as SYSTEM on next service restart.

### 6.6 WinSxS DLL Planting (2024 Research — itm4n Style)

The Windows Side-by-Side (WinSxS) assembly store (`C:\Windows\WinSxS\`) contains versioned copies of system DLLs. Research published in 2024 identified a DLL planting pathway through WinSxS that is distinct from standard search order hijacking.

**Mechanism:**
```
1. Identify a COM server or application that uses SxS activation to load a
   specific assembly version (via manifest <assemblyIdentity> tags)

2. The SxS loader resolves the assembly directory inside WinSxS, then loads
   DLLs from that assembly directory

3. If the assembly directory has incorrect ACLs (user-writable), plant a DLL
   with the expected component name inside the assembly folder

4. When the COM server activates, it loads the assembly — DLL is loaded
   from the attacker-planted copy in the assembly directory
```

**Key finding:** Several WinSxS assembly directories (particularly older compatibility assemblies) had directory ACLs that permitted `Authenticated Users: Modify`. This allowed placing a DLL inside the assembly that would be loaded in preference to the correct version.

**itm4n tooling:** The `WinSxS DLL Hijacking Finder` (Powershell script) enumerates WinSxS assembly directories for writable ACLs and cross-references against COM server registrations that activate with SxS context.

### 6.7 COMDLLSurrogate Hijacking — dllhost.exe Target

**Background:** COM out-of-process servers can run via `dllhost.exe /Processid:{CLSID}` using the DLL surrogate mechanism. When a client activates an in-proc COM server that is configured to run out-of-process (via `DllSurrogate` registry value), `dllhost.exe` hosts the COM DLL in a separate process.

**DLL hijack surface:** `dllhost.exe` itself resides in System32, but its search path for the activated COM DLL follows the standard `LoadLibrary` order for the DLL specified in `InprocServer32`. If:
- The COM server DLL path in the registry points to a non-System32 location
- Or the DLL name is relative (no full path), causing search order traversal

...then planting a DLL at the appropriate search order position causes it to be loaded when the surrogate activates.

**2024 research focus:** Auto-elevated COM objects (those with `AutoApproval` or registered in the COM Elevation Moniker approved list) that use DLL surrogates were examined. Several were found where the DLL load path was relative, and the application directory was user-writable.

**Detection:**
```powershell
# Find COM servers with relative DLL paths in InprocServer32
Get-ChildItem "HKLM:\SOFTWARE\Classes\CLSID" -Recurse |
    Where-Object { $_.Name -match "InprocServer32" } |
    Get-ItemProperty | Where-Object { $_."(default)" -notmatch "^[A-Za-z]:\\" -and
                                       $_."(default)" -ne "" }
```

### 6.8 Phantom DLL Hijacking in Auto-Elevated COM Objects (2024)

Auto-elevated COM objects are CLSID registrations that Windows will instantiate at high integrity without a UAC prompt, provided they pass the elevation validation checks. The validation is based on the COM class's registered executable/DLL being signed by Microsoft and residing in protected paths.

**2024 research finding:** Several auto-elevated COM classes load secondary DLLs (helper/plugin DLLs) via `LoadLibrary` calls within their initialization code. These secondary DLLs are not themselves part of the elevated COM class registration and thus not subject to the same path validation. If a secondary DLL is a phantom (not present on the system) or has a relative load path with a user-writable directory in the search order, it becomes a hijack target that executes at high integrity.

**Exploitation sequence:**
```
1. Identify auto-elevated COM CLSID (AppID with AutoApproval = 1 or
   listed in approved elevation moniker list)

2. Activate the COM object (UAC auto-approves, high integrity process starts)

3. The high-integrity process loads secondary DLL via relative LoadLibrary

4. Attacker has pre-planted the phantom DLL in a user-writable PATH directory

5. DLL loads at high integrity → UAC bypass achieved
```

**Note:** This is primarily a UAC bypass (medium → high integrity), not a full LPE to SYSTEM. However, when chained with a SYSTEM-level escalation, it enables the full chain from standard user to SYSTEM.

### 6.9 msiscan — Detection for DLL Hijack MSI Patterns

**msiscan** is a 2024 tool for analyzing MSI installer packages to identify DLL hijacking opportunities embedded in the installer's file extraction and execution logic.

**What it detects:**
- MSI `CustomAction` entries that execute DLLs from `TEMP` directories without full path specification
- MSI `File` table entries where extracted DLL paths are in user-writable staging locations
- MSI repair sequences (`AdminInstall`, `REINSTALL` flags) that re-extract DLLs to user-controlled paths
- MSI `AppSearch` / `RegLocate` sequences that locate DLLs via user-writable registry paths

**Usage pattern:**
```bash
msiscan.exe /path /i target.msi /report output.html
# Output: list of potentially hijackable DLL operations with severity ratings
```

**Integration:** msiscan is designed to complement PrivescCheck's runtime scanning with static analysis of installer packages, useful when auditing software distribution for enterprise deployment.

---

## 7. Weak Registry ACLs

### 7.1 Service Image Path Override

**Root cause:** `HKLM\SYSTEM\CurrentControlSet\Services\<name>` is writable by non-admin users.

**Impact:** Modify `ImagePath` to point to attacker binary → service restart → SYSTEM code execution.

**Detection:**
```powershell
# Check all service registry keys for non-admin write access
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" | ForEach-Object {
    $acl = Get-Acl $_.PSPath
    $badACE = $acl.Access | Where-Object {
        $_.IdentityReference -notmatch "SYSTEM|Administrators|TrustedInstaller|CREATOR OWNER" -and
        $_.RegistryRights -match "FullControl|SetValue|WriteKey|CreateSubKey"
    }
    if ($badACE) { $_.Name }
}
```

### 7.2 RpcEptMapper WMI Provider DLL Pattern

**The specific vulnerability discovered by itm4n:**
The `HKLM\SYSTEM\CurrentControlSet\Services\RpcEptMapper` and `HKLM\SYSTEM\CurrentControlSet\Services\Dnscache` registry keys had `KEY_WRITE` access for `NT AUTHORITY\NETWORK SERVICE` on some Windows versions.

By creating the `Parameters` subkey and setting `ServiceDll` to an attacker-controlled DLL path, the next service restart caused the `svchost.exe` hosting RpcEptMapper to load the malicious DLL. Since RpcEptMapper runs in a `svchost.exe` instance as LocalSystem, this is a SYSTEM DLL load.

**Why this is architecturally significant:** The vulnerability is in the **registry ACL of an existing legitimate service key**, not in new key creation. Standard tooling (`PrivescCheck`) specifically checks for this pattern.

### 7.3 Medium Integrity Key Writability

Windows' integrity level system (Mandatory Integrity Control) assigns integrity labels to objects. Registry keys under `HKLM` are HIGH integrity. Service keys should be HIGH integrity. However, if a registry key has an incorrect integrity label (MEDIUM), a medium-integrity process can write to it.

This is a distinct check from DACL — even if the DACL allows write, the integrity label check must also pass. Conversely, even if the integrity label allows write, the DACL check must pass. Both must be set correctly.

### 7.4 RpcEptMapper Variant Discovery Post-2021 — Remaining Writable Keys

After the original RpcEptMapper vulnerability was patched and ACLs corrected, subsequent research continued to identify service keys with writable `Parameters` subkeys or writable `ServiceDll` / `ImagePath` values. The methodology for finding them remained the same; the question is whether new third-party software, update packages, or OS updates inadvertently re-introduce weak ACLs.

**Post-2021 findings:**
- Third-party security software (AV, EDR agents) frequently installs service keys with world-readable `Parameters` subkeys that sometimes include writable ACEs
- Cloud agent services (monitoring, management) installed on cloud VMs have been found with writable `ServiceDll` values under `HKLM\SYSTEM\CurrentControlSet\Services\<agentname>`
- Windows feature updates on some SKUs have been observed resetting ACLs on certain service subtrees to more permissive states

**Current methodology:** Run `PrivescCheck -Extended` on any target; the registry ACL module checks all `HKLM\SYSTEM\CurrentControlSet\Services` subtrees for non-admin writability, including subkeys.

### 7.5 CVE Pattern — HKLM\SYSTEM\CurrentControlSet Service Key Weak ACLs

Several CVEs in the 2023-2024 timeframe follow the pattern of a Windows inbox service whose `HKLM\SYSTEM\CurrentControlSet\Services\<name>` key or a subkey has an incorrectly permissive ACL.

**Pattern characteristics:**
- The vulnerable key is typically a subkey of an inbox service (`Parameters`, `Security`, or a vendor-specific subkey)
- The writable ACE grants write access to `Authenticated Users`, `NETWORK SERVICE`, or `Everyone`
- Exploitation requires creating or modifying a `ServiceDll` or `ImagePath` value and waiting for service restart, or triggering a restart via a service-specific management API

**Detection targeting this pattern specifically:**
```powershell
# Focused check on ServiceDll and ImagePath values in Parameters subkeys
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" |
    ForEach-Object {
        $paramPath = $_.PSPath + "\Parameters"
        if (Test-Path $paramPath) {
            $acl = Get-Acl $paramPath
            $acl.Access | Where-Object {
                $_.IdentityReference -match "Authenticated Users|Everyone|NETWORK SERVICE|Users" -and
                $_.RegistryRights -match "SetValue|WriteKey|FullControl"
            } | ForEach-Object { "$($_.PSPath): $($_.IdentityReference) → $($_.RegistryRights)" }
        }
    }
```

### 7.6 RegistryHive Hardening in Windows 11 24H2

Windows 11 24H2 introduced additional restrictions on registry security descriptor modification. The `SetSecurityInfo` API (which sets DACLs and SACLs on registry keys) now has additional validation when called on keys under `HKLM\SYSTEM\CurrentControlSet\Services`.

**Specific hardening:**
- Calls to `SetSecurityInfo` on service keys by non-`TrustedInstaller` processes are logged via ETW (`Microsoft-Windows-Security-Auditing`)
- Certain service keys are now flagged as "protected" in the kernel's registry key object, causing write attempts to fail with `STATUS_ACCESS_DENIED` even for processes holding `SeRestorePrivilege`
- The `RegSetKeySecurity` / `RegSetKeySecurityEx` kernel path validates that the calling token has not been restricted (restricted tokens, which many service accounts use, cannot modify service key security descriptors)

**Impact on exploitation:** Tooling that previously "fixed" weak ACLs as part of an install/repair flow (some malware and post-exploitation frameworks) is blocked from doing so on 24H2. Auditing ACL changes to service keys is now more reliable.

### 7.7 Tooling — AccessChk64 v6.15+ with Service Key Filters

Sysinternals `AccessChk64` version 6.15 (released 2024) added new filtering capabilities relevant to service key auditing:

```cmd
# List all service keys writable by non-admin users (v6.15+ syntax)
accesschk64.exe -kwsu "Authenticated Users" HKLM\SYSTEM\CurrentControlSet\Services
accesschk64.exe -kwsu "Users" HKLM\SYSTEM\CurrentControlSet\Services

# New in v6.15: -filter flag for specific right patterns
accesschk64.exe -kwsu -filter "KEY_SET_VALUE|KEY_WRITE|KEY_CREATE_SUB_KEY" \
    "Authenticated Users" HKLM\SYSTEM\CurrentControlSet\Services

# Recursive check including subkeys (Parameters, Security, etc.)
accesschk64.exe -kwsur "Users" HKLM\SYSTEM\CurrentControlSet\Services
```

**v6.15 improvements over prior versions:**
- Correctly handles virtualized registry keys (previously some virtual keys appeared writable when they were not)
- Supports filtering by specific access rights rather than just showing all writable keys
- Output now includes the integrity level label of each key, making MEDIUM-labeled HKLM keys immediately visible

---

## 8. Kernel Memory Corruption — Overview

> **See also:** ch10 (Kernel/Win32k — full chapter), ch09 §3 (Kernel Primitives)

*(Detailed treatment in Chapter 10; this section provides the taxonomy.)*

### 8.1 Pool Overflow

Windows kernel memory is managed in pool regions (paged pool, non-paged pool, session pool). A pool overflow occurs when a kernel operation writes beyond the allocated chunk boundary, overwriting adjacent pool headers or object data.

**Classic exploitation:** If the adjacent chunk contains a function pointer or kernel object (e.g., a work queue entry, an MDL, a dispatch table pointer), overwriting it with attacker-controlled data can redirect execution to a shellcode/token-stomp routine.

**Modern mitigations:** Windows 10 20H1+ introduced **pool isolation** (separate pools for different object types), making cross-type exploitation much harder. The encoded pool headers (`POOL_HEADER` with a checksum) make header corruption detectable.

### 8.2 Use-After-Free (UAF)

A kernel UAF occurs when a kernel object is freed but a dangling reference remains. If the attacker can reclaim the freed memory with attacker-controlled content before the dangling reference is used, arbitrary type confusion or data corruption follows.

**Window of exploitation:** Between the free and the use, the attacker must win a race to allocate replacement content in the freed slot. Handle table spraying (allocating many handles to fill the pool region) is a common stabilization technique.

**Win32k UAF history:** The win32k subsystem had dozens of UAF bugs in GDI objects (2014–2020). The `tagBITMAPOBJ`, `tagPALETTE`, and `tagSURFOBJ` structures were frequently the target. Win32k isolation (restricting Win32k syscalls in sandboxed processes) and pool isolation have significantly raised the bar.

### 8.3 Type Confusion

Type confusion occurs when the kernel treats a memory region as one object type while the content was placed there as a different type. The attacker controls the semantic interpretation of the data.

**Example:** A kernel array of function pointers that can be populated with data from a different allocation — if the kernel calls `array[index]()`, attacker-controlled data at that address becomes an instruction pointer.

### 8.4 Double-Fetch

A double-fetch vulnerability occurs when the kernel reads a user-mode value twice (once for validation, once for use), and the user-mode value changes between reads. This is the kernel analog of TOCTOU.

**Example:** Kernel driver validates a length field from user-mode buffer, then reads the length again for a memory copy. If the length changes between reads (via another thread), the copy can overflow.

### 8.5 Pool Party — 2024 Primitive Updates Post-CNG Patch

**Background:** Pool Party is a set of Windows thread pool exploitation techniques published in 2023 by SafeBreach researchers. The original techniques abused Windows thread pool worker factories and I/O completion objects to achieve arbitrary code execution from a constrained write primitive. Microsoft partially addressed the original Pool Party variants with the CNG (Cryptography Next Generation) service patch.

**2024 post-patch research:**
Following the CNG-related mitigations, researchers identified several new Pool Party primitive variants that bypass the specific protections added:

- **`TP_POOL` object corruption via alternate path:** The original Pool Party relied on corrupting the callback pointer in a `TP_WORK` object. Post-patch, the `TP_WORK` allocations are in an isolated pool type. The 2024 variant targets `TP_CALLBACK_ENVIRON_V3` stack-allocated callback environments that reference heap-allocated `TP_POOL` objects. These are not in the isolated pool and retain the original corruption primitive.
- **I/O completion queue injection:** A new variant uses the `NtSetIoCompletion` syscall to inject a fake completion packet with an attacker-controlled callback pointer into a legitimate I/O completion port used by a privileged process. This does not require pool corruption — it is an API-level injection.
- **Timer object abuse:** Corrupting the callback in a `TP_TIMER` object (timer-based thread pool tasks) was found viable when the `TP_TIMER` is allocated in the standard paged pool rather than the isolated pool. Some kernel components allocate timer pool objects using the non-isolated allocator.

**Detection status:** The 2024 Pool Party variants are not consistently detected by EDR products that focus on the original Pool Party IOCs (specifically `TP_WORK` callback corruption patterns).

### 8.6 AFD.sys UAF — CVE-2024-38193 (Lazarus Group)

**CVE-2024-38193** is a use-after-free vulnerability in `afd.sys` (Ancillary Function Driver for WinSock), the kernel driver underlying Windows socket operations. Patched in August 2024 Patch Tuesday.

**Vulnerability details:**
- The UAF occurs in the handling of `SIO_GET_EXTENSION_FUNCTION_POINTER` IOCTL processing combined with a concurrent socket close operation
- A reference counting error allows a socket object to be freed while a pointer to it remains in a pending completion structure
- The freed socket object's memory is reallocatable by the attacker with controlled content
- The callback in the completion structure is invoked, now pointing into attacker-controlled data

**Exploitation by Lazarus Group:**
The vulnerability was actively exploited by North Korea's Lazarus Group (APT38) prior to the patch. The group used it as part of a multi-stage exploit chain targeting financial institutions and crypto exchanges. The kernel-mode code execution obtained was used to disable security products (BYOVD-style, using the kernel access rather than a vulnerable driver) and escalate from sandboxed/low-privilege contexts.

**Significance:** AFD.sys is a core networking component loaded on virtually every Windows system, making this vulnerability universally applicable regardless of which optional features are enabled.

**Post-patch research:** The specific reference counting path was patched; however, AFD.sys's socket object lifecycle management remains a research area due to the complexity of asynchronous socket operations and their interaction with kernel pool allocation.

### 8.7 WinDbg — Kernel Memory Analysis

```windbg
; Pool spray verification
kd> !poolused 2  ; show paged pool by tag
kd> !pool <address> 2  ; detail on specific chunk
kd> dt nt!_POOL_HEADER <addr>
; AFD.sys UAF analysis
kd> !devobj \Device\Afd
kd> bp afd!AfdPoll "k 5; g"
```

### 8.8 GDI Object Type Confusion — Win32k Continued Attack Surface (2024)

Despite Win32k isolation (which prevents sandboxed processes from issuing Win32k syscalls) and decades of hardening, Win32k remains an active LPE attack surface for unsandboxed processes (service contexts, interactive user sessions outside sandboxes).

**2024 Win32k research themes:**

**MANDT (Microsoft Advanced Notification Developer Tools) GDI handle table abuse:**
The GDI handle table (`GDI_HANDLE_TABLE`) maps GDI handles to kernel objects. Type confusion bugs arise when the type field in a handle table entry can be manipulated via a non-type-checked operation path. If an attacker can change a `TYPE_BITMAP` entry to `TYPE_PALETTE` (or vice versa), and then invoke GDI operations that assume the type, the kernel operates on the wrong structure layout.

**2024 specific findings:**
- Several `NtGdiXxx` syscalls were found to not re-validate the handle type after locking the associated object, creating a TOCTOU window where the type can be changed between validation and use
- `GreCreateDIBitmapInternal` had a type confusion path with `HPALETTE` handles in some configurations
- The session pool allocation for GDI objects was found to have gaps in the pool isolation scheme for certain legacy GDI compatibility paths

**Tooling:** `win32k_fuzz` (various researchers) targets NtGdi syscalls with handle type confusion payloads; available on GitHub.

### 8.9 KASLR Bypass via NtQuerySystemInformation Leak — 2024 Variants

Kernel Address Space Layout Randomization (KASLR) randomizes the base address of the kernel and drivers on each boot. A KASLR bypass is required for any kernel exploit that needs to calculate absolute addresses (e.g., to overwrite specific kernel data structures or gadget ROP chains).

**Traditional bypass (pre-2023):** `NtQuerySystemInformation(SystemModuleInformation)` returns kernel module base addresses to low-privilege callers — this was the most reliable KASLR bypass and was allowed until Windows 10 RS1 (Anniversary Update) restricted it to administrators only.

**2024 variant approaches:**

1. **`NtQuerySystemInformation(SystemHandleInformation)` → kernel object address leak:**
   Handle information includes the kernel address of the object backing each handle. Low-privilege processes can enumerate their own handles; the kernel addresses are visible. An attacker allocates a known object type (e.g., event, semaphore), queries its kernel address via handle information, and uses the offset from the object to the kernel base to defeat KASLR.
   - **Status:** Still functional on Windows 11 23H2 and 24H2 for certain information classes; Microsoft has been progressively restricting which classes leak addresses

2. **`NtQueryObject(ObjectTypeInformation)` → type object address:**
   Object type objects (like `ExEventObjectType`) have fixed offsets from the kernel base. If a type object's address is leaked, the kernel base is computable.

3. **`EnumDeviceDrivers` / `EnumProcessModules` residual leaks:**
   Some user-mode APIs backed by `NtQuerySystemInformation` sub-classes still return kernel addresses on certain Windows versions or to callers with specific token attributes.

4. **Timing side-channels (PTE probe):**
   By probing access timing to specific virtual address ranges, an attacker can infer which ranges are mapped (kernel code present) versus unmapped. This does not give the exact base but narrows the entropy from 256 possible positions (on some configs) to a small set.

**Current hardening status:** Windows 11 24H2 restricts more `SystemInformation` classes than prior versions; however, at least one reliable address leak path remained viable per 2024 research publications (specific class not named for responsible disclosure reasons).

---

## 9. Master Bug Class → Technique → Primitive → CVE Mapping

> **See also:** ch13 (CVE case studies matching each bug class). ch17 §Labs 9–15 (reproduction labs for each class).

| Bug Class | Technique | Primitive | Key CVE(s) | Tool |
|-----------|-----------|-----------|-----------|------|
| Arbitrary File Write | BITS missing impersonation | Arb. file write | CVE-2020-0787 | itm4n PoC |
| Arbitrary File Write | WER crash dump path | Constrained file write | Forshaw research | symboliclink-testing-tools |
| Arbitrary File Write | WER report path (2024) | Arb. file write | CVE-2024-30030 | PoC (post-patch) |
| Arbitrary File Move | MSI repair junction | Arb. file move | CVE-2021-41379 | InstallerFileTakeOver |
| Arbitrary File Move | NtSetInformationFile | Arb. file rename | Multiple MSI CVEs | NtApiDotNet |
| Arbitrary File Move | Windows Update installer symlink | Arb. file move | CVE-2025-21204 | Research PoC |
| Arbitrary File Delete | Disk Cleanup junction | Arb. file delete | CVE-2022-21838 | Manual |
| Junction + Oplock TOCTOU | BaitAndSwitch | Controlled TOCTOU | CVE-2018-8440 | BaitAndSwitch.exe |
| Junction + Oplock TOCTOU | Task Scheduler ALPC | DACL write arb. | CVE-2018-8440 | SandboxEscaper PoC |
| Token Impersonation | DCOM OXID | Token capture | N/A (design) | JuicyPotato |
| Token Impersonation | DCOM OXID (remote relay) | Token capture | N/A | RoguePotato |
| Token Impersonation | Spooler named pipe | Token capture | N/A | PrintSpoofer |
| Token Impersonation | Task Scheduler COM | Token capture | N/A | GodPotato |
| Token Impersonation | NTLM SSPI reflection | Token capture | CVE-2023-21746 | LocalPotato |
| Token Impersonation | RPC interface coercion | Token capture | N/A | CoercedPotato |
| RPC/COM boundary | EFS RPC no auth | NTLM coercion | CVE-2021-36942 | PetitPotam |
| RPC/COM boundary | Spooler AddPrinterDriver | SYSTEM DLL load | CVE-2021-1675 | PrintNightmare |
| Object Manager | \RPC Control squatting | Pipe redirection | Multiple | symboliclink-testing-tools |
| DLL Search Order | Missing DLL / phantom | SYSTEM DLL load | Multiple | PrivescCheck |
| DLL Search Order | PATH writable dir | SYSTEM DLL load | Multiple | PrivescCheck |
| DLL Search Order | WinSxS assembly planting | SYSTEM DLL load | N/A (2024) | WinSxS Hijack Finder |
| DLL Search Order | COMDLLSurrogate hijack | High-integ DLL load | N/A (2024) | msiscan |
| DLL Search Order | Auto-elevated COM phantom | UAC bypass + exec | N/A (2024) | Manual |
| Weak Registry ACL | Service ImagePath write | SYSTEM binary exec | N/A | PrivescCheck |
| Weak Registry ACL | ServiceDll value write | SYSTEM DLL load | N/A (RpcEptMapper) | PrivescCheck |
| Weak Registry ACL | Parameters subkey create | SYSTEM DLL load | 2023-2024 pattern | AccessChk64 v6.15 |
| Kernel Pool Overflow | Pool adjacent overwrite | Kernel code exec | Multiple CVEs | Kernel debugger |
| Kernel UAF | Win32k GDI objects | Kernel R/W | Multiple CVEs | WinDbg |
| Kernel UAF | AFD.sys socket object | Kernel code exec | CVE-2024-38193 | WinDbg |
| Kernel Type Confusion | Object type mismatch | Kernel code exec | Multiple CVEs | WinDbg |
| Kernel Type Confusion | GDI handle type swap | Kernel R/W | 2024 research | win32k_fuzz |
| Kernel Info Leak | NtQuerySystemInformation | KASLR bypass | N/A (design) | Custom |
| Thread Pool Injection | Pool Party variants | Code exec in privileged process | N/A (2024) | SafeBreach research |

---

## 10. Common Mitigations and Coverage

| Mitigation | Bug Classes Addressed | How to Verify |
|------------|:---|:---|
| `OBJ_DONT_REPARSE` in kernel file opens | Junction/symlink redirect on write/move/delete | Code review; search for `NtCreateFile` without this flag |
| Caller impersonation before file I/O | Missing impersonation (BITS, WER, MSI) | `GetTokenInformation` + `TokenImpersonationLevel` check |
| Path canonicalization before operation | TOCTOU via path manipulation | Code review; `GetFinalPathNameByHandle` usage |
| Restrict `SeImpersonatePrivilege` | All Potato variants | `sc qc <service>` / token privilege audit |
| Disable Print Spooler | PrintSpoofer + PrintNightmare coercion | `Get-Service Spooler` |
| Remove world-write from DLL search paths | DLL search order hijacking | `icacls` on PATH entries |
| Code signing for loaded DLLs | DLL hijacking (partial) | `Get-AuthenticodeSignature` on loaded modules |
| `AlwaysInstallElevated = 0` | MSI elevation abuse | Registry query |
| KnownDLLs coverage | Phantom DLL attacks (partial) | Review `HKLM\...\KnownDLLs` contents |
| Pool isolation (Win10 20H1+) | Kernel pool overflow cross-type | Windows version check |
| HVCI (VBS-based) | Kernel shellcode injection | `msinfo32` → Virtualization Based Security |
| Win32k syscall filtering (AppContainer) | Win32k UAF/overflow | Process mitigation policy |
| Extended Protection for Authentication (EPA) | NTLM local relay (LocalPotato variants) | `Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\*` for EPA config |
| RegistryHive hardening (24H2) | Registry ACL manipulation | Windows version + ETW audit events |

---

## 11. Bug Class Taxonomy Update (2024-2025)

> **See also:** ch12 §1 (Variant hunting mindset), ch13 (CVE case studies)

The foundational bug classes (file primitive abuse, token impersonation, registry ACL, kernel memory corruption) remain active. However, 2024-2025 research has produced several new or significantly elevated categories that deserve independent classification.

### 11.1 New and Emerging Classes

#### VBS/VTL Escape — Trust Boundary Violation Between VTL0 and VTL1

**Class definition:** Virtualization Based Security (VBS) partitions the processor into Virtual Trust Levels. VTL0 is the normal OS; VTL1 is the Secure Kernel hosting Isolated User Mode (IUM) processes. A VTL escape bug allows code running in VTL0 (even as SYSTEM) to violate the trust boundary and affect execution in VTL1 or read VTL1-protected secrets.

**Why it is a new class (not just kernel LPE):** Classic kernel LPE achieves SYSTEM in VTL0. VTL escape achieves code execution *above* the normal SYSTEM level, in a trust domain specifically designed to be opaque to SYSTEM. The target is Credential Guard (protecting domain credentials in VTL1) or the Secure Kernel itself.

**Known VTL escape attack surfaces:**
- Hypercall interface (TLFS calls from VTL0 Hyper-V): validation errors in Hyper-V's hypercall dispatch allow VTL0-SYSTEM to influence VTL1 memory mapping
- Shared memory regions (VMCS/VPID structures, shared device memory): if a VTL0-controlled device driver maps memory that VTL1 reads, forging device-originated data can affect VTL1 logic
- IUM syscall surface: IUM processes communicate with VTL0 via specific secure channels; bugs in the channel validation allow VTL0 to forge IUM messages

**CVE examples:** No public full-chain VTL escape PoC exists as of early 2025; partial primitives have appeared in Hyper-V CVEs (CVE-2024-21407, CVE-2024-21408 — Hyper-V remote code execution affecting hypervisor layer).

**Detection:** Extremely difficult from within VTL0. VTL1 has its own monitoring capabilities via the Secure Kernel; EDR agents in VTL0 have limited visibility into VTL1 state.

#### Administrator Protection Bypass (New for 24H2)

**Class definition:** Windows 11 24H2 introduced **Administrator Protection**, a new mode where even accounts in the Administrators group run as standard users by default. A temporary elevated token is created only when needed (similar to UAC but architecturally different — the elevated token is a separate, short-lived identity, not a split-token). An Administrator Protection bypass allows a process running without elevation to obtain the elevated administrator token without the user approving the elevation prompt.

**Why it is new:** Prior to 24H2, UAC bypass was the relevant class. UAC bypasses work by getting an auto-elevated COM object or a signed Microsoft binary to run high-integrity code without a prompt. Administrator Protection uses a stronger token isolation model; some UAC bypass techniques do not work against it.

**Emerging attack surface:**
- Auto-elevation COM objects that are in the approved list for UAC may not be re-approved for Administrator Protection — but some are
- The temporary elevated token creation mechanism (via `CredUI.dll` or secure desktop UAC prompt interaction) may have timing vulnerabilities
- Applications that call `ShellExecute` with `runas` verb and are in auto-approved lists

**Research status:** Administrator Protection was released in 24H2 Preview; active bypass research began in late 2024. As of early 2025, several partial bypasses affecting specific auto-elevated objects have been reported to Microsoft but not fully disclosed.

#### Kernel Callback Nullification (FudModule-Style DKOM)

**Class definition:** Direct Kernel Object Manipulation (DKOM) that targets Windows security infrastructure callbacks rather than process token structures. Rather than modifying `EPROCESS.Token` (classic token stealing), this class nullifies or replaces kernel callbacks used by security products (ETW providers, `PsSetCreateProcessNotifyRoutine` callbacks, minifilter callbacks).

**FudModule (Lazarus Group, 2022-2024):**
The FudModule rootkit, attributed to Lazarus Group, demonstrated DKOM-based security product disabling via a vulnerable driver (BYOVD — Bring Your Own Vulnerable Driver). The technique:
```
1. Load vulnerable legitimate kernel driver (Dell, Intel, MSI — signed, not in blocklist)
2. Use driver's exposed IOCTL to achieve arbitrary kernel read/write
3. Locate kernel callback arrays:
   - PspCreateProcessNotifyRoutine[] — process creation callbacks (AV hooks here)
   - PspLoadImageNotifyRoutine[] — image load callbacks (EDR hooks here)
   - ObRegisterCallbacks table — object operation callbacks (AV uses for handle protection)
4. Nullify specific entries (or replace with NOOP stub)
5. Security product's kernel callbacks are now silently disabled
6. Proceed with intrusion; no detection
```

**2024 updates:**
- FudModule updated to target ETW (Event Tracing for Windows) provider enable flags in the kernel, disabling specific security-relevant ETW channels at the kernel level
- Technique now targets `EtwpRegistrationTable` to nullify specific ETW registrations
- `PatchGuard` (KPP) periodically checks some of these structures; updated FudModule variants use timing to nullify callbacks only transiently (re-enable before PatchGuard check)

**Detection from user mode:** Nearly impossible without a hypervisor-level monitor or Secure Kernel attestation. VBS-enabled systems with HVCI can detect driver loading but not DKOM after load.

#### Data-Only Kernel Attacks (No Code Execution Required)

**Class definition:** Achieving the attacker's goal (privilege escalation, persistence, defense evasion) by modifying kernel data structures without ever executing attacker-supplied code. The attacker uses an arbitrary kernel write primitive to modify data, not to inject a code payload.

**Why this matters for defenses:** Most kernel exploit mitigations (SMEP, SMAP, HVCI, CET-IBT, KDP) prevent *code* injection or *control flow* hijacking. None prevent modification of data that the kernel legitimately reads and acts upon.

**Common data-only targets:**

| Target Structure | Field | Effect |
|---|---|---|
| `EPROCESS.Token` | Token pointer | Classic token stealing — elevate process to SYSTEM |
| `EPROCESS.ActiveProcessLinks` | Flink/Blink | Unlink process from list (hide from Task Manager) |
| `_DRIVER_OBJECT.MajorFunction[]` | IRP dispatch table | Redirect driver I/O handlers |
| ETW registration flags | Enable bits | Disable specific ETW channels |
| Security callback arrays | Callback pointers | Nullify security product hooks (FudModule) |
| `_TOKEN.Privileges.Enabled` | Privilege bitfield | Enable any privilege without SE* API |
| `_TOKEN.IntegrityLevel` | Mandatory label | Downgrade or upgrade integrity level |

**Why "no code execution" matters:** HVCI prevents new unsigned code from executing in the kernel. An attacker who can only execute signed code (even via ROP using kernel gadgets) might be blocked by CET-IBT. Data-only attacks bypass all of these because the attacker's goal is achieved by the *kernel's own code* reading modified data — no attacker code runs.

### 11.2 Bug Class Taxonomy Table (2024-2025)

| Class | Example CVE / Technique | Primary Mitigation | Detection Method | Difficulty (1-5) |
|-------|------------------------|-------------------|-----------------|:----------------:|
| Arbitrary File Write (missing impersonation) | CVE-2024-30030 (WER), CVE-2020-0787 (BITS) | `OBJ_DONT_REPARSE` + caller impersonation | Procmon junction + write combo | 2 |
| Arbitrary File Move (installer) | CVE-2025-21204, CVE-2021-41379 | TrustedInstaller symlink validation | ETW installer event tracing | 3 |
| Junction + Oplock TOCTOU | CVE-2018-8440 pattern | `OBJ_DONT_REPARSE` | Procmon oplock + junction event pair | 3 |
| Token Impersonation (named pipe) | PrintSpoofer, GodPotato | Disable Spooler; RPC auth requirements | Pipe creation + ImpersonateNamedPipeClient audit | 2 |
| Token Impersonation (DCOM coercion) | CoercedPotato (2024) | RPC interface authentication; EPA | RPC interface access audit | 3 |
| NTLM Local Relay | CVE-2023-21746 (LocalPotato) + 2024 variants | EPA; `NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY` | NTLM relay detection on loopback | 3 |
| DLL Search Order / Phantom | WinSxS planting, COMDLLSurrogate | `LOAD_LIBRARY_SEARCH_SYSTEM32`; WinSxS ACL hardening | Procmon DLL load path audit | 2 |
| DLL Search Order / Auto-elevated COM | Phantom in auto-elevated COM (2024) | Auto-elevation list review; full-path DLL loads | COM activation + LoadLibrary audit | 3 |
| Weak Registry ACL | RpcEptMapper variant; 2024 service key CVEs | Correct ACL on service keys; 24H2 hardening | AccessChk64 v6.15 audit | 2 |
| Kernel Pool Corruption | Pool Party variants post-CNG (2024) | Pool isolation; safe unlinking | Kernel pool integrity monitor | 4 |
| Kernel UAF | CVE-2024-38193 (AFD.sys, Lazarus) | Reference counting hardening; pool isolation | WinDbg pool validation; ETW | 4 |
| Kernel Type Confusion | Win32k GDI 2024 research | Handle type re-validation; Win32k isolation | Win32k syscall monitoring | 4 |
| KASLR Bypass (info leak) | NtQuerySystemInformation variants (2024) | Restrict info classes to admin; KLDR randomization | Audit NtQuerySystemInformation callers | 3 |
| VBS/VTL Escape | CVE-2024-21407 (Hyper-V); research primitives | HVCI; Hyper-V patch currency | Secure Kernel attestation; hypervisor telemetry | 5 |
| Administrator Protection Bypass | 24H2 auto-elevation bypass research | Approved elevation list review; patch | Secure desktop event audit | 4 |
| Kernel Callback Nullification (DKOM) | FudModule (Lazarus 2024); ETW nullification | HVCI; KDP for callback arrays; blocklist | Kernel callback array integrity monitoring | 4 |
| Data-Only Kernel Attack | Token DKOM; privilege bit manipulation | KDP (Kernel Data Protection) for specific structures | Hypervisor memory integrity monitoring | 4 |

---

## References

[R-1] James Forshaw — *Abusing the NT Object Manager Namespace* (SyScan 2015) — https://github.com/tyranid/SyScan2015-AbusedNTObjectManager

[R-2] itm4n — *PrintSpoofer: Abusing Impersonation Privileges on Windows 10 and Server 2019* — https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/

[R-3] decoder / splinter_code — *RoguePotato: from LOCAL/NETWORK SERVICE to SYSTEM* — https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/

[R-4] James Forshaw — *Windows Exploitation Tricks: Exploiting Arbitrary File Writes for Local Elevation of Privilege* — https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html

[R-5] Antonio Cocomazzi (splinter_code) — *CoercedPotato: Local Privilege Escalation via DCOM/RPC Coercion* (2024) — https://github.com/antonio-morales/CoercedPotato

[R-6] Clément Labro (itm4n) — *Bypassing LSA Protection (PPL) via CVE-2024-26218* — https://itm4n.github.io/

[R-7] James Forshaw — *NtObjectManager PowerShell Module: Enumerating Accessible Named Objects* — https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools

[R-8] HEVD — HackSys Extreme Vulnerable Driver — https://github.com/hacksysteam/HackSysExtremeVulnerableDriver

[R-9] SafeBreach Labs — *CVE-2024-38193: Windows AFD.sys UAF Analysis* — https://www.safebreach.com/blog/

[R-10] Avast Threat Intelligence — *Lazarus and the FudModule Rootkit: CVE-2024-21338* — https://decoded.avast.io/janvojtesek/lazarus-and-the-fudmodule-rootkit-beyond-byovd-with-an-admin-to-kernel-zero-day

[R-11] Microsoft MSRC — *CVE-2024-30051 Windows DWM Core Library Elevation of Privilege* — https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-30051

[R-12] Bryan Alexander / Drovorub — *Pool Party: 8 Novel Process Injection Techniques* — https://www.safebreach.com/research/process-injection-using-windows-thread-pools/

[R-13] UACME — Defeating Windows User Account Control — https://github.com/hfiref0x/UACME

[R-14] PrivescCheck — Privilege Escalation Enumeration Script for Windows — https://github.com/itm4n/PrivescCheck
