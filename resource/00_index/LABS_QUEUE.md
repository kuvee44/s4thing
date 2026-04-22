# Labs Queue — Windows Security Research

> Each lab here produces a specific, testable insight about a primitive, trust boundary, or root cause. If a lab doesn't produce an answer to its success question, it wasn't completed — it was run.

---

## P1 — Core Foundation Labs

These must be completed before any other labs. Every downstream lab assumes this infrastructure and knowledge is present.

---

### LAB: KDNET Kernel Debugging Setup
**Priority:** P1
**Primitive / Boundary taught:** Kernel-level observation — the substrate for all dynamic analysis of security-relevant code paths
**Setup:**
- Two machines or VMs (debugger + debuggee)
- Windows 10/11 on debuggee, WinDbg Preview on debugger
- Network connectivity between them (host-only adapter in VM environment)
- `bcdedit /debug on` and `bcdedit /dbgsettings net hostip:<ip> port:<port>` on debuggee
**Task:**
1. Configure KDNET on the debuggee
2. Attach WinDbg from debugger host
3. Break into kernel with Ctrl+Break
4. Run `!process 0 0` and find your own process in the list
5. Set a software breakpoint on `nt!NtCreateFile`
6. Trigger a `CreateFile` from userspace, observe the breakpoint hit
7. Read `dt nt!_IO_STACK_LOCATION @esp` (x86) or appropriate argument register (x64) at the breakpoint
8. Read the filename being opened from the `ObjectAttributes` argument

**Success question:** At the moment `NtCreateFile` is called to open `C:\Windows\System32\kernel32.dll`, what is the value of `DesiredAccess` and how is the filename stored in memory?

**Failure signal:** If you cannot answer without re-running the lab, the breakpoint mechanics are not yet internalized. You are using the tool, not thinking with it.

**Next lab:** NtCreateFile full call trace

---

### LAB: Token Anatomy Survey
**Priority:** P1
**Primitive / Boundary taught:** Token structure — the kernel data structure that access check decisions are made against; the target and source of impersonation attacks
**Setup:**
- WinDbg attached to live kernel (KDNET) or kernel dump
- Test system with a variety of process types running (services, GUI apps, elevated processes, restricted tokens)
**Task:**
1. For each of the following 10 process categories, find a running process and run `!token` on its token:
   - SYSTEM service (e.g., `lsass.exe`)
   - Network service (e.g., `svchost.exe -k NetworkService`)
   - Elevated admin (UAC elevated)
   - Standard user GUI app
   - Restricted token process (e.g., `audiodg.exe`)
   - Impersonating thread (find one in `lsass.exe` or `RpcSs`)
   - Sandboxed process (AppContainer)
   - Low integrity process (IE Protected Mode or similar)
   - Medium integrity process
   - A process you created with `CreateRestrictedToken`
2. For each token, write out: User SID, Groups (all of them), Privileges (names + attributes), Impersonation level, Integrity level, Token source
3. Explain in writing what each field means for access decisions

**Success question:** Why can a thread holding an `Impersonation`-level token from a SYSTEM process not open `\\.\pipe\protected_pipe` if the pipe's DACL grants access only to SYSTEM? What kernel check enforces this?

**Failure signal:** If you cannot explain the impersonation level check without referencing the books, token anatomy is memorized but not understood.

**Next lab:** Object namespace exploration

---

### LAB: Object Namespace Exploration
**Priority:** P1
**Primitive / Boundary taught:** NT object namespace as the substrate for all named object security — pipes, sections, semaphores, device objects; the attack surface for object squatting
**Setup:**
- WinObj (Sysinternals) on test system
- `NtObjectManager` PowerShell module installed (`Install-Module NtObjectManager`)
- Admin rights for full namespace traversal
**Task:**
1. Open WinObj, navigate the full namespace tree. Understand what lives under: `\`, `\Device`, `\BaseNamedObjects`, `\Sessions\0\BaseNamedObjects`, `\Sessions\1\BaseNamedObjects`, `\GLOBAL??`, `\KnownDlls`, `\RPC Control`
2. Use `Get-NtObject -Path \BaseNamedObjects` to enumerate named objects
3. Find 5 named pipes in the namespace and read their security descriptors with `Get-NtSecurityDescriptor`
4. Find 3 section objects and read their DACLs
5. Use `Get-NtSymbolicLink` to trace one symbolic link from `\GLOBAL??` to its target
6. Identify at least one named object with a NULL DACL (everyone has full control)
7. Use `New-NtDirectory -Path \BaseNamedObjects\TestDir` to create a directory object; observe what security descriptor it receives by default

**Success question:** If a SYSTEM service creates `\\.\pipe\mysvc_pipe` and a Medium integrity attacker creates a directory object at `\BaseNamedObjects\mysvc_pipe` first, what happens? What Windows version/build changed this behavior, and what is the current protection mechanism?

**Failure signal:** Not knowing what a Shadow Directory is or why it was introduced means the lab produced navigation skills, not the security insight.

**Next lab:** NtCreateFile call trace

---

### LAB: NtCreateFile Full Call Trace
**Priority:** P1
**Primitive / Boundary taught:** The path from Win32 `CreateFile` to filesystem IRP — understanding every security check that happens in between and where redirection (e.g., reparse points) can alter the path
**Setup:**
- WinDbg with KDNET attached to live kernel
- x64 Windows 10 or 11 debuggee
- A simple test program that calls `CreateFile` on a known path
**Task:**
1. Set a breakpoint on `nt!NtCreateFile`
2. Trigger `CreateFile("C:\\test\\file.txt", GENERIC_READ, ...)`
3. At the breakpoint, read all arguments: `DesiredAccess`, `ObjectAttributes`, `ShareAccess`, `CreateDisposition`, `CreateOptions`
4. Step through the call to `nt!ObOpenObjectByName` → `nt!IopParseDevice` → `nt!IoCallDriver`
5. Identify where the security check (`SeAccessCheck`) is called in the IRP path
6. Set a breakpoint on `nt!SeAccessCheck`. Observe: what token is used? What security descriptor is checked against?
7. Observe the IRP arriving at the filesystem driver (`ntfs!NtfsFsdCreate` or `fastfat!FatFsdCreate`)
8. Now repeat with a path that has a reparse point. Observe where `IO_REPARSE_TAG_MOUNT_POINT` is handled.

**Success question:** At what point in the `NtCreateFile` path is the calling thread's token compared against the file's security descriptor? If the call stack shows the file is opened by a thread impersonating a different token, which token is used in the `SeAccessCheck` call?

**Failure signal:** If you cannot describe the exact function where the token is read from and compared, you observed the call but didn't understand what you were watching.

**Next lab:** ProcMon installer repair trace

---

### LAB: ProcMon Installer Repair Trace
**Priority:** P1
**Primitive / Boundary taught:** Windows Installer repair as a SYSTEM-context file operation trigger — the attack surface foundation for InstallerFileTakeOver and its variants
**Setup:**
- Test VM (snapshot before)
- Process Monitor (ProcMon) — Sysinternals
- Any installed MSI-based application (e.g., Python, Git for Windows, 7-Zip)
- ProcMon configured with filter: `Process Name is msiexec.exe`
**Task:**
1. Start ProcMon capture
2. Run `msiexec /fa {ProductCode}` (use `wmic product get name,identifyingNumber` to find a product code) — this forces a full repair
3. Stop ProcMon capture after repair completes
4. Filter for: `Operation is WriteFile` AND `User is NT AUTHORITY\SYSTEM`
5. For each SYSTEM write, record: full path, caller in call stack, whether path is under user-writable directory
6. Filter for: `Operation is CreateFile` AND `Result is NAME NOT FOUND` AND `User is NT AUTHORITY\SYSTEM`
7. These "not found" entries are locations where a missing file is sought — potential plant locations
8. For the 3 most interesting SYSTEM writes, trace the call stack in ProcMon. Which MSI component triggered them?

**Success question:** Name two file paths that `msiexec /fa` writes to as SYSTEM where the parent directory path is influenced by registry keys or MSI properties that a normal user can modify. Explain why this matters.

**Failure signal:** If you found SYSTEM file writes but cannot explain how an attacker would redirect one of them, you collected data without extracting the attack insight.

**Next lab:** PrintSpoofer API trace

---

## P2 — Bug Class Foundation Labs

These build the exploitation intuition for the core LPE primitive families. Each one produces a pattern card, not just a working PoC.

---

### LAB: PrintSpoofer Named Pipe Impersonation
**Priority:** P2
**Primitive / Boundary taught:** Named pipe impersonation as an LPE primitive — the full chain from pipe creation to token acquisition with `SeImpersonatePrivilege`
**Setup:**
- Windows 10 test VM with `SeImpersonatePrivilege` (run as service or use `FullPowers.exe` to obtain it)
- WinDbg attached (KDNET or user-mode)
- PrintSpoofer source code — read before running
- A second test: a custom C program that creates a named pipe and calls `ImpersonateNamedPipeClient`
**Task:**
1. Read PrintSpoofer source code completely before running anything. Map each function to an API call.
2. Set a breakpoint on `ImpersonateNamedPipeClient` in user-mode WinDbg
3. Run PrintSpoofer. At the breakpoint, read the token before and after the impersonation call
4. After running, build your own minimal version: create a named pipe with a name that matches the spooler's pattern, trigger the spooler connection, call `ImpersonateNamedPipeClient`, verify the token with `OpenThreadToken` + `GetTokenInformation`
5. For the spooler connection: trace in ProcMon which exact Windows component connects to the pipe and as which user
6. Answer: what happens if `SeImpersonatePrivilege` is not held? What API call fails, and what error code does it return?

**Success question:** Why does the PrintSpoofer technique require a named pipe with a specific naming pattern (`\\.\pipe\something\pipe\spoolss`)? What does the pipe path format tell the spooler about where to connect, and what is the kernel mechanism that enforces this naming?

**Failure signal:** If you cannot explain the pipe naming without looking it up, and cannot describe what `SeImpersonatePrivilege` actually allows at the kernel level vs. what happens without it, the lab produced PoC familiarity, not primitive understanding.

**Next lab:** Named pipe DACL enumeration

---

### LAB: Named Pipe DACL Survey
**Priority:** P2
**Primitive / Boundary taught:** Named pipe security descriptors as an enumerable attack surface — understanding which pipes are reachable from limited contexts and which are squattable
**Setup:**
- `NtObjectManager` PowerShell module
- Test system with multiple services running
- Standard user account for testing access
**Task:**
1. Enumerate all named pipes: `Get-NtNamedPipe | ForEach-Object { Get-NtSecurityDescriptor $_.Name }`
2. For each pipe, record: name, owner, DACL entries, whether authenticated users / everyone has write access
3. Find pipes with NULL DACL (everyone full access)
4. Find pipes owned by SYSTEM where low-privilege users have write access (potential squatting surface)
5. Find pipes where the DACL allows `FILE_CREATE_PIPE_INSTANCE` to limited users (allows a second server instance)
6. For the 3 most interesting candidates: document who creates the pipe, at what point in service startup, and whether a race window exists between service start and pipe creation

**Success question:** If a service creates a named pipe at `\\.\pipe\MyService\control` with a 50ms window between service start and pipe creation, and the DACL allows authenticated users to create instances — what does an attacker need to win the race, and what primitive do they gain if they succeed?

**Failure signal:** If you found permissive DACLs but cannot explain how `FILE_CREATE_PIPE_INSTANCE` access enables impersonation, the enumeration produced a list but not an attack model.

**Next lab:** BaitAndSwitch junction + oplock

---

### LAB: BaitAndSwitch Junction + Oplock TOCTOU
**Priority:** P2
**Primitive / Boundary taught:** TOCTOU (time-of-check/time-of-use) via junction redirection — how a race window between security check and file operation use enables redirection to an attacker-controlled path
**Setup:**
- Windows 10/11 test VM
- `symboliclink-testing-tools` (James Forshaw) — NtApiDotNet / oplock utilities
- A test harness: a privileged service (or simulated SYSTEM process) that performs: open directory, check it's safe, write a file into it
- Or use the `NtApiDotNet` sample for oplock + junction races
**Task:**
1. Understand what an opportunistic lock (oplock) is: read the MSDN docs for `DeviceIoControl(FSCTL_REQUEST_OPLOCK_INPUT)` before starting
2. Build the race setup:
   a. Create a directory `C:\Users\<user>\AppData\Local\TestDir`
   b. Acquire a BATCH oplock on the directory
   c. Wait for SYSTEM process to begin accessing it
   d. When oplock breaks (callback fires), replace the directory with a junction to `C:\Windows\System32\`
   e. Release oplock
3. Trigger a SYSTEM operation that writes to the directory (use a test harness if needed)
4. Verify that the SYSTEM write was redirected through the junction
5. Now: trace in WinDbg exactly where the path re-evaluation happens after the oplock break. What function? What flag would prevent the re-evaluation?

**Success question:** What is the `FILE_OPEN_REPARSE_POINT` flag in `CreateOptions`, and if the SYSTEM process opened the directory with this flag set, would the junction attack succeed? What about `FILE_OPEN_NO_RECALL`?

**Failure signal:** If you successfully redirected a write but cannot explain what the oplock provides that a pure timing race would not, you ran the exploit without understanding the primitive.

**Next lab:** InstallerFileTakeOver full reproduction

---

### LAB: InstallerFileTakeOver Full Reproduction
**Priority:** P2
**Primitive / Boundary taught:** Windows Installer repair → SYSTEM file write → junction redirect → arbitrary SYSTEM write — the full primitive chain from MSI trigger to exploitation
**Setup:**
- Windows 10 test VM (snapshot before)
- InstallerFileTakeOver PoC — read source before running
- ProcMon for tracing
- WinDbg (optional but recommended for junction tracing)
- An MSI that performs file repair (the PoC includes a test MSI)
**Task:**
1. Read InstallerFileTakeOver source completely before running
2. Trace the PoC with ProcMon: identify each SYSTEM file operation that is redirected
3. Build the components individually:
   a. Build a junction from a temp path to a target (e.g., `C:\Windows\System32\`)
   b. Trigger MSI repair independently and verify ProcMon shows SYSTEM write to the junction source
   c. Combine: trigger repair while junction is in place, verify SYSTEM writes land at junction target
4. Now: find a second MSI on your test system (not the PoC's test MSI) where the same technique would work. Document the candidate.
5. Identify what check the CVE-2021-41379 patch added. Run the patched version. Does the patch block your second-MSI candidate?

**Success question:** What specific Windows Installer behavior allows an unprivileged user to trigger a SYSTEM file write to a user-controlled path, and what is the exact registry key or MSI property that controls the destination path used in the write?

**Failure signal:** If you cannot find a second candidate MSI and explain whether the patch blocks it, you reproduced the PoC but didn't extract the pattern.

**Next lab:** Variant hunting — MSI surface enumeration

---

### LAB: TTD Security Event Recording and Replay
**Priority:** P2
**Primitive / Boundary taught:** Temporal investigation for security events — using TTD to trace the exact sequence of operations leading to a token creation, impersonation transition, or privilege check
**Setup:**
- Windows 10/11 with TTD support (Insider or Pro/Enterprise with WinDbg Preview)
- WinDbg Preview
- A target scenario: UAC elevation, or a named pipe impersonation event
**Task:**
1. Attach TTD to `consent.exe` during a UAC prompt (or attach to a process before it performs an impersonation)
2. Record the full execution
3. In the TTD recording:
   a. Find the call to `NtCreateToken` or `NtDuplicateToken` that creates the elevated token
   b. Navigate backward from that call to find what validated the request
   c. Find every call to `SeAccessCheck` in the recording and read its arguments
4. Use TTD queries: `dx @$cursession.TTD.Calls("ntdll!NtCreateToken")` to find all token creation calls
5. For each token creation: read the input parameters and the resulting token handle
6. Navigate to 10 instructions before the token creation. What function called it? What decision was made?

**Success question:** In a UAC elevation TTD trace, at what exact function call does the decision "this process is allowed to elevate" get made, and what is the input to that decision? What would an attacker need to control to influence that decision?

**Failure signal:** If you used TTD to observe the trace but cannot navigate backward from an event to its cause, you used TTD as a logging tool, not an investigation tool.

**Next lab:** LocalPotato NTLM reflection trace

---

### LAB: COM Server Security Descriptor Enumeration
**Priority:** P2
**Primitive / Boundary taught:** COM activation surface — which COM servers can be activated by limited users, and which ones perform privileged operations after activation
**Setup:**
- `OleViewDotNet` — James Forshaw
- `NtObjectManager` PowerShell module
- Test system with standard user account
**Task:**
1. Launch OleViewDotNet as standard user
2. Enumerate all registered COM servers
3. Filter for servers where `LaunchPermission` is absent (inherits machine default) or explicitly grants `Everyone` or `Authenticated Users` launch rights
4. For each candidate: read the `AccessPermission` as well — can a standard user not only launch but also call methods on it?
5. Use `NtObjectManager`: `Get-ComClassEntry | Where-Object { $_.LaunchPermission -eq $null }` to enumerate programmatically
6. For 3 candidates that have no LaunchPermission: attempt to activate them as a standard user with `New-ComObject`
7. For any successfully activated COM server: use ProcMon to trace what file operations it performs during activation and method calls

**Success question:** If a COM server has no `LaunchPermission` set and runs as a LocalSystem surrogate, and it impersonates its caller during a file operation — what token does the file operation execute under, and what privilege does the attacker need to escalate from that impersonation to SYSTEM?

**Failure signal:** If you found activatable COM servers but cannot explain why `SeImpersonatePrivilege` is the bridge from "I can activate a SYSTEM COM server" to "I can run code as SYSTEM," the enumeration was academic.

**Next lab:** RoguePotato OXID resolver trace

---

### LAB: RoguePotato OXID Resolver Trace
**Priority:** P2
**Primitive / Boundary taught:** DCOM OXID resolver as an impersonation trigger — understanding how DCOM's distributed activation mechanism can be abused to obtain a SYSTEM impersonation token
**Setup:**
- Windows 10 test VM
- RoguePotato source and pre-built binary — read source before running
- WinDbg (user-mode)
- ProcMon
- `SeImpersonatePrivilege` (run as a service account)
**Task:**
1. Read RoguePotato source. Identify the OXID resolver step: what is an OXID, what is the OXID resolver, and why does the exploit redirect it?
2. Set a breakpoint on `RpcSsImpersonateClient` in the WinDbg session for the RoguePotato process
3. Run RoguePotato. At the breakpoint, read the impersonated token
4. Trace in ProcMon: which system process contacts the fake OXID resolver? What is the source port and destination port of the DCOM activation request?
5. Read the RPC call stack at the `RpcSsImpersonateClient` breakpoint: what RPC interface and method is being invoked?
6. Answer: why does DCOM's OXID resolution involve impersonating the activating client, and what security model assumption does this exploit?

**Success question:** What is the specific DCOM operation that causes the SYSTEM process to contact a user-controlled OXID resolver, and what is the security decision that allows the subsequent impersonation to succeed? How is this different from the PrintSpoofer trigger mechanism?

**Failure signal:** If you ran RoguePotato and got SYSTEM but cannot explain what an OXID resolver is and why redirecting it causes a SYSTEM process to contact your server, the primitive is not understood.

**Next lab:** LocalPotato NTLM reflection

---

### LAB: Windows Installer SYSTEM Operation Surface via ProcMon + TTD
**Priority:** P2
**Primitive / Boundary taught:** Windows Installer's SYSTEM context file operation surface as an enumerable attack pattern — not just CVE-2021-41379 but the class of MSI-triggered SYSTEM file operations
**Setup:**
- ProcMon
- WinDbg with TTD
- 5+ different MSI-installed applications on test VM
- Standard user account
**Task:**
1. For each of 5 installed applications, run `msiexec /fa {ProductCode}` with ProcMon capturing
2. For each, record every `WriteFile` and `CreateFile` operation under `NT AUTHORITY\SYSTEM` context
3. Identify which write paths are under or influenced by user-writable locations (temp directories, HKCU registry paths used to determine install path, etc.)
4. Record a TTD trace of the most interesting repair sequence. Navigate to the SYSTEM write in TTD. Read the call stack: what MSI engine function initiated the write?
5. For the most interesting candidate: determine whether the write path is controlled by an MSI property stored in the HKLM `Installer` key, and whether a standard user can modify that key

**Success question:** For the most interesting candidate you found, describe the complete chain: what user-controlled input influences the SYSTEM write path, what the write does, and what an attacker could write to gain code execution.

**Failure signal:** All 5 applications have SYSTEM writes that land only in protected directories with no user-influenceable paths. If this is the case, document why (which MSI feature is using protected paths) and try 5 more applications.

**Next lab:** Variant hunting — MSI surface enumeration (P3)

---

### LAB: Named Pipe Impersonation — Custom Implementation
**Priority:** P2
**Primitive / Boundary taught:** The exact API sequence for named pipe impersonation from first principles — not using a PoC but building the primitive yourself
**Setup:**
- Visual Studio or MSVC build tools
- Windows 10/11 test VM
- WinDbg (user-mode)
**Task:**
1. Write a C program: pipe server that calls `ImpersonateNamedPipeClient` after a client connects
2. Write a second C program: pipe client that connects and writes data
3. In the server: after impersonation, call `OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken)` and print the impersonated user with `GetTokenInformation`
4. Verify it works with a client connecting as a different user
5. Now: modify the server to run as a SYSTEM service (use `sc create` + a service wrapper or use `PsExec -s`)
6. Connect to the pipe as a standard user. Verify the server impersonates the standard user
7. Now reverse: what if the server is a standard user and the client is SYSTEM? What does `ImpersonateNamedPipeClient` return? What is the impersonated token's level?
8. Answer: what `SeImpersonatePrivilege` check does `ImpersonateNamedPipeClient` perform, and at what impersonation level does the resulting token arrive?

**Success question:** If your pipe server runs as a standard user (no `SeImpersonatePrivilege`), a SYSTEM process connects to it, and you call `ImpersonateNamedPipeClient` — what is the impersonation level of the resulting token, and what can you do with it?

**Failure signal:** If you cannot answer the success question from the experiment, the lab was not run with sufficient rigor. The answer is observable directly from the experiment output.

**Next lab:** PrintSpoofer variant search

---

## P3 — Advanced Research Labs

These labs produce research-grade output. The success criteria for each is a written analysis, not a working exploit.

---

### LAB: HEVD Stack Overflow → SYSTEM Token Steal
**Priority:** P3
**Primitive / Boundary taught:** Kernel exploit skeleton — the pattern of userspace-to-kernel primitive, `EPROCESS` traversal, token pointer overwrite; the foundation for understanding all Windows kernel LPE
**Setup:**
- Windows 10 VM (1903 or earlier for simpler SMEP/SMAP situation, or modern with ROP chain)
- HEVD (HackSys Extreme Vulnerable Driver) installed
- WinDbg kernel attached
- C exploit skeleton
**Task:**
1. Read HEVD's `StackOverflow.c` source completely
2. Trigger the overflow from userspace, observe the crash in WinDbg kernel debugger
3. Identify the stack frame layout: how many bytes to the return address?
4. Build a shellcode that: (a) walks the `EPROCESS` `ActiveProcessLinks` list, (b) finds the SYSTEM process by `UniqueProcessId == 4`, (c) copies the SYSTEM `Token` pointer to the current process
5. Handle SMEP: either use a kernel ROP chain to disable SMEP (CR4 manipulation) or use a kernel function pointer to trampoline into shellcode mapped as executable kernel memory
6. Verify: after exploit, `whoami` returns `SYSTEM`
7. In WinDbg, set a breakpoint on your shellcode and verify the token swap operation at the kernel level

**Success question:** At the exact instruction where you overwrite the current process's `Token` pointer, what is the value being written (address of SYSTEM `_EX_FAST_REF` token pointer), and why must the reference count bits be handled correctly?

**Failure signal:** If you got SYSTEM but had to copy someone else's shellcode without understanding the token reference count bits or the `EPROCESS` list traversal, the lab produced a result but not the insight.

**Next lab:** HEVD pool overflow with segment heap grooming

---

### LAB: HEVD Pool Overflow — Segment Heap Grooming (Win10 20H1+)
**Priority:** P3
**Primitive / Boundary taught:** Modern Windows kernel pool exploitation — how the segment heap invalidates traditional pool spray techniques and what controlled grooming requires
**Setup:**
- Windows 10 20H1 or later (segment heap for kernel pool is enabled)
- HEVD pool overflow module
- WinDbg kernel attached
- Reference: Yarden Shafir's "Windows Heap Exploitation" research
**Task:**
1. Attempt a traditional pool spray on the HEVD pool overflow (spray `_OBJECT_TYPE` objects, overflow into them). Observe why this fails on 20H1+.
2. Read the segment heap vs. NT heap differences in kernel mode. Identify: what are segments? What is the backend vs. frontend allocator?
3. Build a grooming approach: use a controllable kernel allocation (pipe attributes, registry key data, or another HEVD object) to fill the pool segment before triggering the overflow
4. Corrupt a target structure. Identify which kernel object is a reliable corruption target on current Windows versions.
5. Achieve controlled code execution or a token steal via the corrupted structure
6. Document: what grooming primitive did you use, how many allocations does it require, and what is the failure mode if the pool is not deterministically groomed?

**Success question:** Why does spraying `_OBJECT_TYPE` objects work on Windows 7/8 but not on Windows 10 20H1+? What specific segment heap behavior breaks the traditional spray, and what property must a grooming primitive have to be reliable on the segment heap?

**Failure signal:** If you used a write-up's exact grooming primitive without being able to explain the segment heap property that makes it work, the lab did not transfer the exploitation primitive — it transferred the recipe.

**Next lab:** Patch diff — any recent CVE

---

### LAB: Patch Diff — CVE-2021-41379 (InstallerFileTakeOver)
**Priority:** P3
**Primitive / Boundary taught:** Patch reading as research — understanding what invariant a patch enforces, whether it is sufficient, and what variant angle it leaves open
**Setup:**
- Pre-patch `msi.dll` from Windows 10 October 2021 (pre-November patch)
- Post-patch `msi.dll` from November 2021 cumulative update
- BinDiff (Zynamics) or Diaphora
- IDA or Ghidra for reading diff output
**Task:**
1. Obtain both versions (Windows Update Catalog or snapshot archives)
2. Load both in IDA/Ghidra, export BinDiff databases
3. Run BinDiff, sort by similarity descending (find changed functions)
4. Identify the function(s) changed by the patch
5. Read the pre-patch version: what check is absent?
6. Read the post-patch version: what check was added? Write it as a pseudocode condition
7. Read the Naceri bypass disclosure. Find the bypass path in the post-patch binary. Why does the bypass work?
8. Write a root cause analysis in Project Zero format: exact function, missing condition, patch assessment, variant angle

**Success question:** What is the exact condition the November 2021 patch adds, and why does the Naceri bypass work despite the patch? Write this as: "The patch checks X but does not check Y, and the bypass achieves Z by exploiting the absence of Y."

**Failure signal:** If you can describe what code changed but cannot state whether the fix is sufficient and why, you read the patch but didn't analyze it.

**Next lab:** Variant hunting — MSI surface enumeration

---

### LAB: Patch Diff — Arbitrary Recent CVE
**Priority:** P3
**Primitive / Boundary taught:** Patch diffing as a repeatable workflow applicable to any Windows subsystem, not just known bug classes
**Setup:**
- Any CVE from the last 6 months affecting a Windows binary (Win32k, kernel, or a user-mode service)
- Pre-patch and post-patch binaries
- BinDiff or Diaphora
- IDA or Ghidra
**Task:**
1. Select a CVE from the most recent Patch Tuesday advisory
2. Obtain pre-patch and post-patch binary
3. Run BinDiff — time yourself. Target: identified changed function within 30 minutes
4. Read the patch. Write the root cause in one sentence
5. Assess completeness: does the patch fix the specific trigger, or does it fix the underlying invariant? What variant angle remains?
6. Write a 3-paragraph root cause analysis: (1) what the bug is, (2) what the patch does, (3) whether the fix is sufficient

**Success question:** For your chosen CVE: what is the root cause (one sentence), what did the patch add (one sentence), and what variant angle does the patch leave open (one sentence)?

**Failure signal:** If the root cause is written as a description of behavior rather than a missing invariant, the analysis is not yet at research quality. A root cause is a condition, not a description.

**Next lab:** Variant hunting — post-patch surface enumeration

---

### LAB: Variant Hunting — Post-InstallerFileTakeOver MSI Surface
**Priority:** P3
**Primitive / Boundary taught:** Variant discovery methodology — using tool-based enumeration to find the next instance of a known primitive, not the PoC author's instance
**Setup:**
- Test VM with 10+ MSI-installed applications
- ProcMon
- PowerShell with HKLM Installer key access
- InstallerFileTakeOver knowledge from reproduction lab
**Task:**
1. Build a systematic enumeration: `wmic product get name,identifyingNumber,installlocation` — get all installed MSI products
2. For each product, query the `HKLM\SOFTWARE\Classes\Installer\Products\{GUID}\SourceList` key — find the cached MSI path
3. Write a PowerShell script that: for each installed MSI, extracts the file table and identifies files installed to paths that include a user-controllable component
4. For candidates, run `msiexec /fa {GUID}` with ProcMon and verify SYSTEM writes to the candidate path
5. For the most interesting candidate: determine whether the CVE-2021-41379 patch blocks the vector. Run the test
6. Document: candidate name, file table entry, SYSTEM write path, patch status

**Success question:** Did you find a candidate that meets all criteria: (1) triggers a SYSTEM file write during repair, (2) the write path has a user-influenceable component, (3) the November 2021 patch does not block it? If not, what is the closest candidate you found and why does the patch block it?

**Failure signal:** If you stopped at "ran ProcMon on 3 applications and found no candidates" without building the systematic enumeration, you did not do variant hunting. Variant hunting is a methodology, not a manual survey.

**Next lab:** CodeQL pattern for privileged file operations

---

### LAB: CodeQL / Semgrep Pattern for Privileged File Operations
**Priority:** P3
**Primitive / Boundary taught:** Static analysis as a variant hunting multiplier — finding instances of a primitive class in source code at scale without manual review
**Setup:**
- CodeQL CLI + Windows-related CodeQL packs, OR Semgrep with custom rules
- ReactOS source code (as Windows API proxy) — `github.com/reactos/reactos`
- Reference: the InstallerFileTakeOver primitive (privileged file write without reparse point check)
**Task:**
1. Define the pattern: "a function that writes to a path derived from user-controlled input without setting `FILE_OPEN_NO_RECALL` or `FILE_OPEN_REPARSE_POINT` in the `CreateOptions`"
2. Write a CodeQL query or Semgrep rule that matches this pattern
3. Run against ReactOS source
4. For each hit: assess manually — is the write privileged? Is the path user-controllable? Is there a reparse point check?
5. Document: query/rule code, number of hits, number of false positives, number of true candidates
6. For the most interesting true candidate: write a one-paragraph analysis of exploitability

**Success question:** What is the false positive rate of your pattern, and what source of false positives did you have to filter? What specific syntactic or semantic property would reduce the false positive rate?

**Failure signal:** If your pattern found 0 hits or 100% false positives, the pattern definition needs revision. Document what the pattern needs to capture that it currently does not.

**Next lab:** Full variant hunting report

---

### LAB: LocalPotato NTLM Reflection Trace in WinDbg
**Priority:** P3
**Primitive / Boundary taught:** Local NTLM reflection as an impersonation primitive distinct from DCOM-based Potato variants — understanding the SSPI-level mechanics
**Setup:**
- Windows 10 test VM
- LocalPotato source code — read completely before running
- WinDbg (user-mode, attached to LocalPotato process)
- ProcMon for SSPI call observation
**Task:**
1. Read LocalPotato source. Identify: what SSPI functions are called, in what order, with what parameters?
2. Set breakpoints on: `AcquireCredentialsHandleW`, `InitializeSecurityContextW`, `AcceptSecurityContext`
3. Run LocalPotato. At each breakpoint, read arguments and return values
4. Trace the NTLM challenge/response exchange in WinDbg memory reads: find the NTLM `NEGOTIATE`, `CHALLENGE`, `AUTHENTICATE` messages in memory
5. Identify the exact point where the reflection succeeds: which call results in a context that can be impersonated?
6. Answer: why is a loopback NTLM authentication "reflected" rather than "forwarded"? What is the difference between NTLM reflection to the local machine vs. reflection to a remote machine, and why does the former work without NTLM relay protections blocking it?

**Success question:** What SSPI function call in LocalPotato results in an impersonatable security context, and what would `ImpersonateSecurityContext` return if called from a context without `SeImpersonatePrivilege`?

**Failure signal:** If you cannot explain how NTLM reflection differs from NTLM relay, or cannot identify which SSPI call produces the usable token, the trace was observed but not analyzed.

**Next lab:** Full Potato family comparison — write one paragraph distinguishing Rotten, Rogue, Sweet, and Local Potato by their trigger mechanism (not by name)

---

### LAB: PrintSpoofer Variant — Unexplored Named Pipe Surface
**Priority:** P3
**Primitive / Boundary taught:** Variant recognition — applying the PrintSpoofer template to unexplored Windows services to find unreported instances of the named pipe impersonation primitive
**Setup:**
- Test VM with ProcMon, NtObjectManager, WinDbg
- Standard user account + one account with `SeImpersonatePrivilege`
- The PrintSpoofer primitive understanding from P2 lab
**Task:**
1. Enumerate all Windows services that create named pipes: `Get-NtNamedPipe | Where-Object { $_.Name -like "*" }` — correlate with `Get-Process` and service list
2. Filter for services running as SYSTEM or NetworkService
3. For each candidate service, determine: does it connect outbound to a named pipe whose name it constructs from controllable input? Or does it create a pipe server and accept connections? These are different primitives.
4. For services that connect outbound: can a limited user pre-create a pipe server at the target name?
5. For the most interesting candidate: attempt to trigger a connection as SYSTEM to a user-controlled pipe. Verify impersonation works.
6. Document: service name, pipe name pattern, trigger mechanism, whether impersonation token is SYSTEM, whether this is already documented/patched

**Success question:** Name one Windows service (not the Spooler) that connects to a named pipe whose name a limited user can influence, and describe the exact trigger mechanism.

**Failure signal:** If you searched manually without building a systematic enumeration, or stopped after finding no candidates in 30 minutes without refining the search criteria, the methodology was not applied.

**Next lab:** Full variant hunting report (combine findings from all P3 variant labs into one document)

---

### LAB: MoveFileEx Delayed Reboot → DLL Plant Chain
**Priority:** P3
**Primitive / Boundary taught:** File move primitive weaponization — converting a constrained "move file as SYSTEM" capability into a persistent code execution primitive via reboot-triggered DLL plant
**Setup:**
- Windows 10 test VM
- A test harness that provides one `MoveFileEx(src, dst, MOVEFILE_DELAY_UNTIL_REBOOT)` call as SYSTEM (simulate this with PsExec -s or a test service)
- Target: plant a DLL in `C:\Windows\System32\` that will be loaded by a service on reboot
**Task:**
1. Understand `MOVEFILE_DELAY_UNTIL_REBOOT`: what registry key stores the pending move? Read the registry entry after calling the API.
2. Build the chain: (a) identify a DLL search order hijack target in a SYSTEM service that starts at boot, (b) plant a test DLL using the delayed move, (c) reboot, (d) verify DLL loads
3. Read the registry entry under `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations` before and after the reboot
4. Identify: what process processes this registry entry at boot, and can a limited user read but not write this key?
5. Build a second variant: use `NtSetInformationFile` with `FileRenameInformation` from a SYSTEM context to achieve the same result without the reboot requirement. What are the access requirements?

**Success question:** What is the exact registry key that stores pending file moves, what process processes it during boot, and what is the earliest boot phase at which your planted DLL could be loaded?

**Failure signal:** If you planted a DLL but don't know what reads the `PendingFileRenameOperations` key or at what boot phase, the primitive chain was executed but the mechanism was not understood.

**Next lab:** Arbitrary file delete → DLL plant (compare required conditions to file move variant)

---

### LAB: Patch Tuesday Monitoring Cycle
**Priority:** P3
**Primitive / Boundary taught:** Patch analysis as a repeatable research workflow — from Microsoft advisory to root cause analysis to variant hunting angle in a single structured pass
**Setup:**
- MSRC Security Update Guide account
- BinDiff or Diaphora
- IDA or Ghidra
- Windows Update Catalog for obtaining patched binaries
**Task:**
Conduct one complete Patch Tuesday cycle:
1. On Patch Tuesday, read all advisories tagged "Elevation of Privilege" for Windows
2. For each EoP advisory: classify the bug class from the advisory text alone
3. Select the 2 most interesting EoP CVEs
4. For each: obtain pre- and post-patch binary, run BinDiff, identify changed functions
5. For each: write root cause analysis (exact function, missing condition, patch assessment)
6. For each: identify the variant hunting angle the patch leaves open
7. Produce a structured report: advisory → binary → diff → root cause → variant angle

**Success question:** For your two chosen CVEs, can you state (without reference): the binary that was patched, the function that changed, the missing condition pre-patch, and one variant hunting angle each?

**Failure signal:** If the patch analysis took more than 4 hours per CVE, the tooling and methodology need refinement. The bottleneck is usually binary acquisition — automate this.

**Next lab:** Variant hunting based on the most interesting variant angle found in this lab

---

### LAB: Kernel Integrity and SMEP/SMAP Bypass Awareness
**Priority:** P3
**Primitive / Boundary taught:** Modern kernel mitigations as constraints on exploitation chains — understanding SMEP, SMAP, HVCI, and kernel CFG as constraints that must be reasoned about before selecting a primitive chain
**Setup:**
- WinDbg kernel attached
- Windows 10/11 VM with various mitigation states
- HEVD for controlled experimentation
**Task:**
1. Check SMEP/SMAP status: read `CR4` in WinDbg: `r cr4`. Interpret the bits.
2. Check HVCI status: `!sysinfo cpuinfo` and verify if VBS is active
3. Attempt to map executable shellcode in userspace and jump to it from kernel context (with HEVD overflow trigger): observe the SMEP fault
4. Build a ROP chain using kernel .text gadgets to disable SMEP before jumping to userspace shellcode (if HVCI is off)
5. If HVCI is on: understand why ROP chain against kernel .text is not sufficient. What does HVCI add on top of SMEP?
6. Document: for each mitigation (SMEP, SMAP, HVCI, kCFG), what exploit technique does it block, and what technique bypasses or works despite it?

**Success question:** On a Windows 11 system with HVCI enabled, what exploitation primitive against a kernel vulnerability would NOT be blocked by HVCI, and why?

**Failure signal:** If you can describe what SMEP does but cannot explain why HVCI makes CR4 manipulation via ROP ineffective, the mitigation model is incomplete.

**Next lab:** I/O Ring exploitation primitives (Yarden Shafir research)

---

### LAB: Arbitrary File Delete → Privilege Escalation Chain
**Priority:** P3
**Primitive / Boundary taught:** Arbitrary file delete as an LPE primitive — converting a SYSTEM file deletion into code execution via folder creation → DLL plant
**Setup:**
- Test harness providing one arbitrary `DeleteFile` call as SYSTEM
- Windows 10/11 test VM
- Reference: ZDI blog on arbitrary file delete primitives
**Task:**
1. Start with premise: you can cause `C:\Windows\System32\<any filename>` to be deleted as SYSTEM
2. Build the chain: (a) delete `C:\Windows\System32\<service DLL that is missing from some configurations>`, (b) observe DLL search order fallback, (c) plant replacement DLL in a user-controlled search path, (d) trigger service restart
3. Find a second approach: delete a directory, then race to recreate it as a junction before SYSTEM re-creates it, then redirect a SYSTEM write into the junction target
4. For each approach: document exactly what must exist and what must not exist for the chain to work

**Success question:** What is the DLL search order for a service running as SYSTEM when its original DLL path is deleted? Does the search order differ between a service with and without a full DLL path specified in the service registry key?

**Failure signal:** If you found the chain works in theory but didn't verify it end-to-end with a test DLL that logs its load, the primitive chain is hypothetical, not validated.

---

### LAB: Access Check Algorithm Walk-Through in WinDbg
**Priority:** P3 (should be done as part of Stage 1, but listed here for researchers who skipped it)
**Primitive / Boundary taught:** The exact decision logic of `SeAccessCheck` — where security decisions happen and what inputs control them
**Setup:**
- WinDbg with kernel attached
- A test C program that opens a file with specific access rights
**Task:**
1. Set a breakpoint on `nt!SeAccessCheck`
2. Trigger a file open with `GENERIC_READ` from your test program
3. At the breakpoint, read all arguments: `SecurityDescriptor`, `SubjectContext`, `DesiredAccess`, `PreviouslyGrantedAccess`, `Privileges`, `GenericMapping`
4. Step through the function: follow each branch decision (privilege check, DACL check, each ACE evaluation)
5. Identify: which ACE in the DACL grants access? What happens if you remove it?
6. Modify a DACL with `NtObjectManager` to explicitly deny access, then re-trigger the open. Follow the deny ACE evaluation path.
7. Try the same with a SYSTEM token impersonating a standard user: which token does `SeAccessCheck` use?

**Success question:** In `SeAccessCheck`, when the subject context includes an impersonation token, from which thread/process is the token read, and what happens if the impersonation level is `SecurityIdentification`?

**Failure signal:** If you can describe the outcome of the access check but cannot trace the code path that produces it, the result is known but the mechanism is not.

---

## Lab Advancement Notes

Labs within a priority tier can be done in parallel where they don't share setup. Labs across tiers should generally be done in order — a P3 lab that references a P2 primitive assumes the P2 lab's insight is already internalized, not just that the PoC ran.

The success questions are the unit tests for these labs. If you cannot answer a success question from memory a week after running the lab, the lab needs to be re-run with more deliberate observation.
