# Chapter 08 — Windows LPE Bug Classes
## A Systematic Reference for Local Privilege Escalation Vulnerability Patterns

---

## Introduction: The Bug Class Mental Model

Windows Local Privilege Escalation research benefits from a categorical framework. Individual CVEs are facts; bug classes are patterns. Learning the pattern lets you recognize the next variant before a CVE number exists.

Every Windows LPE bug ultimately provides one or more **primitives**: arbitrary file write, arbitrary file move, arbitrary file delete, token impersonation, or kernel memory access. The bug class describes *how* the primitive is obtained and *what structural weakness enables it*. The exploit chain describes how the primitive is converted into code execution as SYSTEM.

This chapter catalogs the canonical bug classes in depth: definition, root cause, detection methodology, CVE examples, tooling, and defensive mitigations. The final section provides a master mapping table.

---

## 1. Arbitrary File Write / Move / Delete

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

### 1.3 BITS as Write Source

CVE-2020-0787 — the BITS job completion writes the downloaded file to the destination path as SYSTEM without impersonating the job owner. Junction the destination directory between job enqueue and completion → arbitrary file write to any SYSTEM-writable path. Content is fully attacker-controlled (the HTTP/file source content).

### 1.4 MSI as Write Source

The Windows Installer repair flow (`msiexec /fav`) moves staged files as SYSTEM. Junction the staging directory to an arbitrary destination → InstallerFileTakeOver pattern. Content is the original file from the MSI package, which the attacker controls by crafting the job or choosing an appropriate existing MSI.

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

### 1.6 How to Find Arbitrary File Write/Move/Delete Bugs

**Process Monitor methodology:**
1. Filter: `Process Name = <privileged binary>`, `Operation = CreateFile OR WriteFile OR SetRenameInformationFile`, `Path starts with C:\` or target path
2. Look for write/move/delete operations on paths that include user-controlled segments
3. Verify: does the privileged process call `ImpersonateClient()` before this operation? (Check in reverse engineering tool)

**Code review red flags:**
- `CreateFile(userPath, GENERIC_WRITE, ...)` without prior impersonation
- `MoveFileEx(srcPath, dstPath, ...)` where `dstPath` derives from user input or registry values
- `DeleteFile(userPath)` in service cleanup code
- Absence of `OBJ_DONT_REPARSE` / `FILE_FLAG_OPEN_REPARSE_POINT` in file open calls on directory-traversing paths

---

## 2. Junction + Oplock TOCTOU

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

### 2.3 Thread Race vs. Oplock-Assisted Race

Without oplocks, TOCTOU exploitation requires winning a tight timing window. This is unreliable (race is probabilistic, not deterministic). Oplocks make it deterministic: the privileged process literally cannot proceed until the attacker says so.

For bugs where the target file is not under attacker control (can't set oplock on the file being operated on), thread racing remains the fallback. Modern exploit research strongly prefers oplock-based approaches when applicable.

---

## 3. Token Impersonation — The Potato Family

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

### 3.5 The Potato Progression — Timeline and Evolution

| Tool | Year | Mechanism | Windows Compatibility | Status |
|------|:----:|:---|:---:|:---:|
| Hot Potato | 2016 | NBNS spoofing + NTLM relay | Win 7/8.1/Server 2008-2012 | Historical |
| Rotten Potato | 2016 | DCOM OXID + NTLM loopback | Pre-1809 | Historical |
| Juicy Potato | 2018 | Extended CLSID DCOM list | Pre-1809 | Historical |
| Sweet Potato | 2020 | EfsRpc + WebClient + pipe variants | Win 10 / Server 2019 | Active |
| Rogue Potato | 2020 | Remote OXID resolver relay | Win 10 / Server 2019 | Active (needs relay) |
| Print Spoofer | 2020 | Spooler named pipe | Win 10 / Server 2019 | Active |
| God Potato | 2022 | Task Scheduler COM | Server 2012–2022 / Win 10-11 | Active |
| Local Potato | 2023 | NTLM SSPI reflection | Pre-Jan 2023 patch | Patched |

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

---

## 8. Kernel Memory Corruption — Overview

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

---

## 9. Master Bug Class → Technique → Primitive → CVE Mapping

| Bug Class | Technique | Primitive | Key CVE(s) | Tool |
|-----------|-----------|-----------|-----------|------|
| Arbitrary File Write | BITS missing impersonation | Arb. file write | CVE-2020-0787 | itm4n PoC |
| Arbitrary File Write | WER crash dump path | Constrained file write | Forshaw research | symboliclink-testing-tools |
| Arbitrary File Move | MSI repair junction | Arb. file move | CVE-2021-41379 | InstallerFileTakeOver |
| Arbitrary File Move | NtSetInformationFile | Arb. file rename | Multiple MSI CVEs | NtApiDotNet |
| Arbitrary File Delete | Disk Cleanup junction | Arb. file delete | CVE-2022-21838 | Manual |
| Junction + Oplock TOCTOU | BaitAndSwitch | Controlled TOCTOU | CVE-2018-8440 | BaitAndSwitch.exe |
| Junction + Oplock TOCTOU | Task Scheduler ALPC | DACL write arb. | CVE-2018-8440 | SandboxEscaper PoC |
| Token Impersonation | DCOM OXID | Token capture | N/A (design) | JuicyPotato |
| Token Impersonation | DCOM OXID (remote relay) | Token capture | N/A | RoguePotato |
| Token Impersonation | Spooler named pipe | Token capture | N/A | PrintSpoofer |
| Token Impersonation | Task Scheduler COM | Token capture | N/A | GodPotato |
| Token Impersonation | NTLM SSPI reflection | Token capture | CVE-2023-21746 | LocalPotato |
| RPC/COM boundary | EFS RPC no auth | NTLM coercion | CVE-2021-36942 | PetitPotam |
| RPC/COM boundary | Spooler AddPrinterDriver | SYSTEM DLL load | CVE-2021-1675 | PrintNightmare |
| Object Manager | \RPC Control squatting | Pipe redirection | Multiple | symboliclink-testing-tools |
| DLL Search Order | Missing DLL / phantom | SYSTEM DLL load | Multiple | PrivescCheck |
| DLL Search Order | PATH writable dir | SYSTEM DLL load | Multiple | PrivescCheck |
| Weak Registry ACL | Service ImagePath write | SYSTEM binary exec | N/A | PrivescCheck |
| Weak Registry ACL | ServiceDll value write | SYSTEM DLL load | N/A (RpcEptMapper) | PrivescCheck |
| Kernel Pool Overflow | Pool adjacent overwrite | Kernel code exec | Multiple CVEs | Kernel debugger |
| Kernel UAF | Win32k GDI objects | Kernel R/W | Multiple CVEs | WinDbg |
| Kernel Type Confusion | Object type mismatch | Kernel code exec | Multiple CVEs | WinDbg |

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

---

## References

[R-1] Windows Exploitation Tricks: Exploiting Arbitrary File Writes for LPE — James Forshaw — https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html

[R-2] symboliclink-testing-tools — James Forshaw / Google Project Zero — https://github.com/googleprojectzero/symboliclink-testing-tools

[R-3] Rotten Potato — Privilege Escalation from Service Accounts to SYSTEM — foxglovesecurity — https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/

[R-4] Juicy Potato — Andrea Pierini, Giuseppe Trotta — https://ohpe.it/juicy-potato/

[R-5] RoguePotato — No More JuicyPotato — Decoder.cloud — https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/

[R-6] PrintSpoofer: Abusing Impersonation Privileges on Windows 10 and Server 2019 — itm4n — https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/

[R-7] Windows Registry Rpceptmapper Exploit — itm4n — https://itm4n.github.io/windows-registry-rpceptmapper-exploit/

[R-8] Local Potato (CVE-2023-21746) — Decoder.cloud — https://www.decoder.cloud/2023/02/15/local-potato/
