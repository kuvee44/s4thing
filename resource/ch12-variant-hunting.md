# Chapter 12: Variant Hunting — Methodology, Tools, and Case Studies

> **Scope**: This chapter covers the complete variant hunting methodology — from the
> mindset shift required to see patches as research directions, through systematic attack
> surface enumeration, static analysis tools (CodeQL, Semgrep), fuzzing infrastructure
> (Jackalope, WTF), and the Administrator Protection bypass series as a live case study
> in systematic variant discovery.

---

## 12.1 The Variant Hunting Mindset

### 12.1.1 A Patch Is a Hypothesis

When Microsoft issues a security patch, they are implicitly making a hypothesis: "this
change fixes the vulnerability." Variant hunting asks: **is that hypothesis correct and
complete?**

A patch is complete only if it satisfies all five criteria from Chapter 11:
1. Addresses the root cause (not just the PoC trigger)
2. Covers all call sites
3. Fixes the right layer
4. Does not introduce new bugs
5. Handles edge cases

When a patch fails any criterion, exploitation of the same root cause via a different
path becomes likely. This is the structural foundation of variant hunting: **the root
cause of one bug defines the search space for more bugs**.

The mindset shift:
- **Bug finder**: "I found a bug, wrote a PoC, reported it, done."
- **Variant hunter**: "I found a bug. Now I understand a class. Where else does this
  class appear? Where did Microsoft fix symptoms without addressing root cause? What
  other code shares the same dangerous pattern?"

Every serious Windows security researcher — Project Zero, itm4n, Naceri, j00ru — operates
in the variant hunter mode. The result is not one CVE; it is a series.

### 12.1.2 Forshaw's Incomplete Fix Pattern

James Forshaw's body of work at Project Zero is the canonical reference for variant
hunting in practice. The recurring pattern he exploits:

> **Fix one check → same root cause elsewhere**

Specific documented pattern types:

**Pattern 1: Single Call Site Fixed, Others Missed**

Microsoft fixes the function that the PoC called, but the same root cause exists
in sibling functions, alternate code paths, or different callers of the same
underlying vulnerable function.

Example: Windows Installer rollback abuse. Naceri found that when Microsoft fixed
the `MsiExec /repair` path, the rollback path (`MsiExec /f`) called the same
file-write primitive with the same missing validation. Multiple CVEs resulted.

**Pattern 2: Surface-Level Fix Without Root Cause**

The patch prevents the exact exploitation technique demonstrated in the PoC but
not the underlying design assumption that enables the bug class.

Example: UAC/Administrator Protection bypass variants. The specific bypass PoC
triggers a specific code path; the fix prevents that exact path. But the underlying
assumption (that certain COM activation patterns cannot be triggered by low-privilege
callers) remains incorrect, and different COM CLSIDs or activation sequences still work.

**Pattern 3: Wrong Layer Fix**

The vulnerable function is called by many callers. Microsoft adds a check in one
caller (the PoC path) rather than in the vulnerable function itself.

Example: A kernel function that performs a file write without impersonation is called
by five RPC methods. The patch adds impersonation only to the one RPC method the PoC
used. The other four remain exploitable via different clients.

**Pattern 4: Regression — Previously Fixed Bug Reintroduced**

A security fix in Windows version N is not forward-ported, or a refactor in version
N+1 removes the check. This produces a regression that re-opens a previously patched vulnerability.

Detection: Track the vulnerable function across builds using BinDiff or NtDiff. Check
whether security checks that existed in build N are present in build N+1.

---

## 12.2 Enumerating Attack Surface Systematically

### 12.2.1 The Attack Surface Taxonomy

Windows LPE attack surface stratifies into seven main surfaces. For each, the researcher
has a specific enumeration methodology:

| Surface | Core Question | Primary Tool |
|---|---|---|
| Services with privileged file ops | Does a SYSTEM service write to a path derived from user-controlled registry values? | ProcMon + AccessChk + NtObjectManager |
| Named pipe impersonation | Does a world-writable named pipe server impersonate before privileged operations? | NtObjectManager + ProcMon |
| COM servers with impersonation | Does an accessible SYSTEM COM server perform privileged operations while impersonating? | OleViewDotNet + NtObjectManager |
| MSI repair / installer abuse | Does MSI repair write to user-writable paths under SYSTEM? | Orca + ProcMon + NtObjectManager |
| RPC interfaces with UNC paths | Do SYSTEM RPC methods accept UNC paths that trigger NTLM auth? | RpcView + Coercer + NtObjectManager |
| Registry kernel surface | Do registry feature interactions create confused deputy conditions? | WinDbg + CmRegisterCallback |
| DLL search order | Do SYSTEM services load DLLs from user-writable PATH directories? | ProcMon (NAME NOT FOUND filter) |

### 12.2.2 NtObjectManager — COM Server Enumeration

James Forshaw's `sandbox-attacksurface-analysis-tools` PowerShell module (`NtObjectManager`)
is the most powerful enumeration toolkit for Windows security research:

```powershell
# Install
Install-Module NtObjectManager -Scope CurrentUser
Import-Module NtObjectManager

# Files writable by current user
Get-AccessibleFile -Path "C:\ProgramData" -Recurse |
    Where-Object { $_.MaximumGrantedAccess -match "WriteData|AppendData" }

# Registry keys writable by current user in HKLM
Get-AccessibleKey -Path "HKLM:\SYSTEM\CurrentControlSet\Services" -Recurse |
    Where-Object { $_.MaximumGrantedAccess -match "SetValue|CreateSubKey" }

# Named pipes accessible/writable by current user
Get-AccessibleNamedPipe | ForEach-Object {
    $sd = $_.SecurityDescriptor
    if ($sd) {
        $worldWritable = $sd.Dacl | Where-Object {
            $_.Sid.ToString() -match "S-1-1-0|S-1-5-11" -and
            ($_.Mask -band 0x40000000)  # GenericWrite
        }
        if ($worldWritable) { Write-Output "PERMISSIVE: $($_.Name)" }
    }
}

# COM objects accessible for launch by current user
$clsids = Get-ChildItem "HKLM:\SOFTWARE\Classes\CLSID"
foreach ($clsid in $clsids) {
    try {
        $sd = Get-ComObjectSecurityDescriptor -Clsid $clsid.PSChildName `
              -Type LaunchPermission -ErrorAction Stop
        $accessible = Test-NtAccessMask -SecurityDescriptor $sd -Access 3
        if ($accessible) {
            Write-Output "Accessible: $($clsid.PSChildName)"
        }
    } catch {}
}

# Directories writable by current user
Get-AccessibleDirectory -Path "C:\" -Recurse |
    Where-Object { $_.MaximumGrantedAccess -match "WriteData|AddFile" }
```

### 12.2.3 RPC Endpoint Enumeration

```powershell
# NtObjectManager RPC endpoint enumeration
Import-Module NtObjectManager

# Enumerate all RPC endpoints registered on the system
Get-RpcEndpoint | ForEach-Object {
    Write-Output "$($_.InterfaceId) v$($_.InterfaceVersion) @ $($_.BindingString)"
}

# Get server client for a specific interface
$client = Get-RpcClient -InterfaceId "6bffd098-a112-3610-9833-46c3f87e345a" `
          -EndpointPath "\pipe\spoolss"
```

**RpcView** (`https://www.rpcview.org`): GUI tool for inspecting RPC servers. Key workflow:
1. Launch RpcView → shows all registered RPC servers with their interfaces
2. Click a server → see all registered RPC interfaces
3. Click an interface → see all methods with parameter types (decompiled from NDR)
4. Look for methods with string parameters named `ServerName`, `UncPath`, `FilePath`,
   `MachineName`, `RemoteName` — these are potential auth coercion vectors

**itm4n's RPC methodology** (from PetitPotam research):
1. Load the target RPC server DLL in IDA/Ghidra
2. Find `MIDL_SERVER_INFO` structure → dispatch table → individual method handlers
3. Trace each handler: does it call `CreateFile`, `WNetAddConnection2`, or any UNC-path
   construction from the method's string parameters?
4. If yes: write a raw RPC client stub (using NDR encoding) to test authentication
   without installing the service

### 12.2.4 Service Registry ACL Enumeration

```powershell
# Find all SYSTEM services with writable registry keys for low-priv users
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" | ForEach-Object {
    $keyPath = $_.PSPath
    try {
        $acl = Get-Acl -Path $keyPath
        $writableEntries = $acl.Access | Where-Object {
            $_.IdentityReference -match "Users|Authenticated Users|Everyone|INTERACTIVE" -and
            $_.AccessControlType -eq "Allow" -and
            ($_.RegistryRights -match "FullControl|SetValue|CreateSubKey|WriteKey")
        }
        if ($writableEntries) {
            Write-Output "WRITABLE SERVICE KEY: $($_.Name)"
            $writableEntries | ForEach-Object {
                Write-Output "  -> $($_.IdentityReference): $($_.RegistryRights)"
            }
        }
    } catch {}
}
```

Specifically for the RpcEptMapper/WMI Performance Counter vector (itm4n's methodology):
```cmd
; Sysinternals AccessChk — find services where Users can create subkeys
accesschk.exe -kvuqsw "Authenticated Users" HKLM\System\CurrentControlSet\Services /accepteula
```

---

## 12.3 CodeQL for Windows Variant Hunting

### 12.3.1 What CodeQL Provides

CodeQL is a semantic code analysis platform. Unlike Semgrep (syntactic pattern matching),
CodeQL builds a relational database of the code's structure, control flow, and data flow,
and allows queries over this database using the QL query language.

For variant hunting: CodeQL can answer questions like "find all functions where user-controlled
data flows into a size argument of an allocation call without first passing through
a bounds-check function."

### 12.3.2 Setup

```bash
# Install CodeQL CLI
# Download from: https://github.com/github/codeql-cli-binaries/releases

# Download CodeQL standard library packs
codeql pack download codeql/cpp-queries
codeql pack download codeql/cpp-all

# Create a CodeQL database from C/C++ source
codeql database create mydb \
    --language=cpp \
    --command="make -C /path/to/source"

# Run a query
codeql query run my_query.ql --database=mydb --output=results.bqrs

# View results
codeql bqrs decode results.bqrs --format=text
```

### 12.3.3 Writing Variant Hunting Queries

**Template: Missing impersonation check before privileged operation**

```ql
import cpp
import semmle.code.cpp.controlflow.Guards

// Find RPC server functions that call a file operation without
// first calling RpcImpersonateClient or CoImpersonateClient

class RpcImpersonateCall extends FunctionCall {
    RpcImpersonateCall() {
        this.getTarget().getName() = "RpcImpersonateClient" or
        this.getTarget().getName() = "CoImpersonateClient" or
        this.getTarget().getName() = "ImpersonateNamedPipeClient"
    }
}

class FileWriteCall extends FunctionCall {
    FileWriteCall() {
        this.getTarget().getName() = "CreateFileW" or
        this.getTarget().getName() = "CreateFileA" or
        this.getTarget().getName() = "MoveFileExW" or
        this.getTarget().getName() = "CopyFileExW"
    }
}

from FileWriteCall writeCall, Function f
where
    // The file write call is in a function
    writeCall.getEnclosingFunction() = f and
    // There is no RpcImpersonateClient call that dominates this file write
    not exists(RpcImpersonateCall impCall |
        impCall.getEnclosingFunction() = f and
        impCall.getBasicBlock().dominates(writeCall.getBasicBlock())
    )
select writeCall, f.getName(), "File operation without preceding impersonation in " + f.getName()
```

**Template: TOCTOU pattern — check before use with no atomicity**

```ql
import cpp
import semmle.code.cpp.dataflow.DataFlow

// Find cases where a path string is first passed to an existence check,
// then to a file creation function, with possible modification in between

class PathCheckCall extends FunctionCall {
    PathCheckCall() {
        this.getTarget().getName() = "PathFileExistsW" or
        this.getTarget().getName() = "GetFileAttributes" or
        this.getTarget().getName() = "PathIsDirectoryW"
    }
}

class PathUseCall extends FunctionCall {
    PathUseCall() {
        this.getTarget().getName() = "CreateFileW" or
        this.getTarget().getName() = "CreateDirectoryW"
    }
}

from PathCheckCall checkCall, PathUseCall useCall, Expr pathArg
where
    // Same path string is used in both check and use
    DataFlow::localFlow(DataFlow::exprNode(checkCall.getArgument(0)),
                        DataFlow::exprNode(useCall.getArgument(0))) and
    // Check comes before use in execution order
    checkCall.getBasicBlock().getASuccessor+() = useCall.getBasicBlock()
select checkCall, useCall, "Potential TOCTOU: path checked then used without atomicity"
```

**Template: Null security descriptor — missing ACL on new object**

```ql
import cpp

// Find calls to CreateMutexExW/CreateEventExW/CreateSemaphoreExW with NULL
// security attributes — objects accessible to Everyone

class NullSecAttrCreate extends FunctionCall {
    NullSecAttrCreate() {
        this.getTarget().getName().matches("Create%Ex%") and
        this.getArgument(0).(NullValue*) = _
    }
}

from NullSecAttrCreate call
select call, "Kernel object created with NULL security attributes"
```

### 12.3.4 GitHub Security Lab Query Repository

The GitHub Security Lab (`https://securitylab.github.com/`) publishes CodeQL queries
used in their own vulnerability research. The `codeql/cpp-queries` pack contains:
- `Security/CWE/CWE-119/` — buffer overflow patterns
- `Security/CWE/CWE-362/` — race condition (TOCTOU) patterns
- `Security/CWE/CWE-476/` — NULL pointer dereference
- `Security/CWE/CWE-416/` — use-after-free

Study these queries before writing your own — they demonstrate correct CodeQL idiom
for common vulnerability classes.

---

## 12.4 Semgrep Rules for Windows C/C++ Patterns

Semgrep is faster than CodeQL but less semantically deep. It is ideal as a first-pass
scanner — find candidates quickly, verify with deeper analysis.

### 12.4.1 Rules for Common Windows Vulnerability Patterns

```yaml
# Find LoadLibrary without absolute path (DLL hijacking candidate)
rules:
  - id: loadlibrary-no-absolute-path
    patterns:
      - pattern: LoadLibrary($PATH)
      - pattern-not: LoadLibrary("C:\\...")
      - pattern-not: LoadLibrary(L"C:\\...")
    message: "LoadLibrary with potentially non-absolute path — DLL hijacking candidate"
    languages: [cpp, c]
    severity: WARNING

  # Find CreateFile without FILE_FLAG_OPEN_REPARSE_POINT on user-supplied paths
  - id: createfile-no-reparse-check
    pattern: |
        CreateFile($PATH, $ACCESS, $SHARE, $SA, $CREATION, $FLAGS, $TEMPLATE)
    pattern-not: |
        CreateFile($PATH, ..., $FLAGS | FILE_FLAG_OPEN_REPARSE_POINT, ...)
    message: "CreateFile without FILE_FLAG_OPEN_REPARSE_POINT — potential symlink follow"
    languages: [cpp, c]
    severity: WARNING

  # Find MoveFileEx without path validation (arbitrary file move candidate)
  - id: movefileex-privileged-context
    pattern: MoveFileEx($SRC, $DST, ...)
    message: "MoveFileEx call — verify path validation when running in elevated context"
    languages: [cpp, c]
    severity: INFO

  # Find RpcImpersonateClient calls missing after RPC entry point
  - id: rpc-method-no-impersonation
    pattern: |
        $RETTYPE $FUNC($HANDLE hBinding, ...) {
            ...
            CreateFile(...)
            ...
        }
    pattern-not: |
        $RETTYPE $FUNC($HANDLE hBinding, ...) {
            ...
            RpcImpersonateClient(...)
            ...
            CreateFile(...)
            ...
        }
    message: "RPC method creates file without RpcImpersonateClient — verify impersonation"
    languages: [cpp]
    severity: WARNING
```

```bash
# Run Semgrep on Windows source tree
semgrep --config my-rules.yaml --lang cpp C:\path\to\source\

# Use the Semgrep registry (thousands of pre-written rules)
semgrep --config "p/microsoft" --lang cpp .

# Focus on security rules
semgrep --config "p/security-audit" --lang cpp .
```

---

## 12.5 Jackalope Fuzzer Setup for Windows Targets

Jackalope (`https://github.com/googleprojectzero/jackalope`) is Google Project Zero's
coverage-guided fuzzer for Windows, using TinyInst for instrumentation.

### 12.5.1 Architecture

```
Jackalope
├── TinyInst (code coverage via DBI — Dynamic Binary Instrumentation)
│   ├── Instruments the target module at the basic block level
│   └── Reports new coverage to Jackalope for corpus management
├── Fuzzer core (mutation engine)
│   ├── Selects input from corpus
│   ├── Mutates (bit flip, byte replacement, splicing, dictionary)
│   └── Feeds mutated input to target harness
└── Target harness (researcher-written)
    ├── Calls DeviceIoControl / target function / target API
    ├── Passes fuzzed data as input
    └── Returns to fuzzer (or crashes → finding recorded)
```

### 12.5.2 IOCTL Fuzzing Setup

```cpp
// Minimal IOCTL fuzzing harness (harness.cpp)
#include <windows.h>
#include <cstdio>

int APIENTRY WinMain(HINSTANCE, HINSTANCE, LPSTR lpCmdLine, int) {
    // lpCmdLine is the fuzzed input file path (Jackalope passes "@@")
    // Read fuzzed input
    HANDLE hInput = CreateFileA(lpCmdLine, GENERIC_READ, 0, NULL,
                                OPEN_EXISTING, 0, NULL);
    if (hInput == INVALID_HANDLE_VALUE) return 1;

    DWORD fileSize = GetFileSize(hInput, NULL);
    BYTE* inputBuf = (BYTE*)malloc(fileSize);
    DWORD read;
    ReadFile(hInput, inputBuf, fileSize, &read, NULL);
    CloseHandle(hInput);

    // Open target driver
    HANDLE hDriver = CreateFileA("\\\\.\\TargetDriver",
                                 GENERIC_READ | GENERIC_WRITE,
                                 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hDriver == INVALID_HANDLE_VALUE) { free(inputBuf); return 1; }

    // Send fuzzed input as IOCTL input buffer
    BYTE outputBuf[0x1000];
    DWORD bytesReturned;
    DeviceIoControl(hDriver, TARGET_IOCTL_CODE,
                    inputBuf, fileSize,
                    outputBuf, sizeof(outputBuf),
                    &bytesReturned, NULL);

    CloseHandle(hDriver);
    free(inputBuf);
    return 0;
}
```

```bash
# Run Jackalope with TinyInst coverage on target module
jackalope.exe \
    -in corpus\ \
    -out findings\ \
    -t 5000 \                  # timeout per input (ms)
    -coverage_modules HEVD.sys \
    -target_module harness.exe \
    -target_method WinMain \
    -- harness.exe @@           # @@ replaced by Jackalope with corpus file path
```

**Corpus seeding**: Create a small set of valid IOCTL inputs as the initial corpus.
Jackalope will mutate these to explore new code paths. Include inputs for each known
IOCTL code to maximize coverage from the start.

---

## 12.6 WTF — Windows Kernel Fuzzing Framework

WTF (`https://github.com/0vercl0k/wtf`) is a distributed, snapshot-based fuzzer for
Windows, designed for kernel fuzzing where attaching a standard fuzzer is impractical.

### 12.6.1 Core Architecture

WTF operates on **VM snapshots**:
1. Take a snapshot of a Windows VM at a specific point in execution (before entering
   the code path to fuzz)
2. WTF restores the snapshot for each fuzzing iteration
3. The fuzzer mutates memory regions mapped as input to the target function
4. Execute until the target returns or crashes
5. Record crashes; restore snapshot for next iteration

This snapshot-based approach allows fuzzing:
- Kernel code directly (ring 0 execution)
- Code paths that are difficult to reach from user mode via normal APIs
- Code paths that require specific initialization state

### 12.6.2 WTF Setup Outline

```bash
# Prerequisites:
# - Windows kernel VM with VirtIO drivers (QEMU recommended)
# - KVM with nested virtualization enabled
# - WTF build environment (Visual Studio + Python)

# Step 1: Prepare target VM snapshot
# - Boot target Windows VM
# - Reach the execution point just before the vulnerable function
# - Take snapshot with QEMU: savevm fuzzing_snapshot

# Step 2: Create WTF target module
# targets/target_name/target_name.cc defines:
# - Init(): set up fuzzing state
# - InsertTestcase(uint8_t *Buffer, size_t Size): write fuzzed input to memory
# - Restore(): clean up after each iteration

# Step 3: Run fuzzer
wtf fuzz --name target_name --state snapshot_dir/ --input corpus/
```

### 12.6.3 WTF vs Jackalope: When to Use Each

| Scenario | WTF | Jackalope |
|---|---|---|
| Kernel code fuzzing | ✓ Ideal (snapshot-based) | Difficult (requires ring-3 harness) |
| User-mode driver IOCTL | Possible | ✓ Ideal (TinyInst instrumentation) |
| Complex initialization state | ✓ Snapshot captures it | Must re-initialize each run |
| Fast iteration rate | Moderate (snapshot restore) | Fast (process restart) |
| Coverage granularity | Basic block (requires symbol map) | Basic block (live instrumentation) |
| Remote/distributed fuzzing | ✓ Built-in | Manual coordination needed |

---

## 12.7 Registry Weak ACL Enumeration Methodology

Based on j00ru's registry kernel research and itm4n's RpcEptMapper discovery:

### 12.7.1 Systematic Enumeration

```powershell
# Method 1: AccessChk for all services keys
accesschk.exe -kvuqsw "Authenticated Users" HKLM\System\CurrentControlSet\Services /accepteula
accesschk.exe -kvuqsw "Users" HKLM\System\CurrentControlSet\Services /accepteula

# Method 2: NtObjectManager comprehensive registry scan
Import-Module NtObjectManager

Get-AccessibleKey -Path "HKLM:\SYSTEM\CurrentControlSet\Services" -Recurse |
    Where-Object { $_.MaximumGrantedAccess -match "SetValue|CreateSubKey|WriteKey" } |
    Select-Object Name, MaximumGrantedAccess

# Method 3: PrivescCheck automated report
. .\PrivescCheck.ps1
Invoke-PrivescCheck -Extended -Report privesc_report -Format HTML
```

### 12.7.2 Testing the Performance Counter DLL Load Vector

For each service key where standard users can create subkeys (following itm4n's
RpcEptMapper methodology):

```powershell
# For a candidate service key, check if Performance subkey can be created
$serviceName = "RpcEptMapper"  # or other candidate
$perfKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName\Performance"

try {
    New-Item -Path $perfKeyPath -ErrorAction Stop
    Write-Output "SUCCESS: Can create Performance subkey for $serviceName"
    # Next: set Library value, trigger WMI query, observe DLL load
} catch {
    Write-Output "FAILED: Cannot create Performance subkey for $serviceName"
}
```

### 12.7.3 Tracing with CmRegisterCallback

In a kernel debugging session, WMI performance counter access can be traced:
```windbg
; Break on registry callback operations
bp nt!CmCallCallBacks "k; g"

; More specific: break on NtQueryKey for Performance classes
bp nt!NtQueryKey ".if poi(@rsp+0x28) == 0x12 {k} .else {g}"

; Watch for wmiprvse.exe loading DLLs from registry-derived paths
bp nt!NtLoadKey "!process -1 0; k; g"
```

---

## 12.8 The Administrator Protection Bypass Variant Series (2024–2025)

### 12.8.1 Background

Administrator Protection (AdminProtection or "Limited User Account 2.0") is Microsoft's
replacement for UAC, introduced in Windows 11 24H2 (October 2024). The design goal:
provide a stronger privilege boundary than UAC by:

- Generating a new isolated admin token (not linked to the user's session token)
- Requiring explicit approval for every elevation, not just first-time binaries
- Blocking token inheritance attacks that UAC was vulnerable to

### 12.8.2 Project Zero's Systematic Variant Discovery

Within months of AdminProtection's release, Project Zero researchers systematically
enumerated its bypass surface. The methodology:

**Phase 1: Threat model the new feature**

AdminProtection works by:
1. Low-privilege process requests elevation via `ShellExecute` with `runas` verb
2. Windows creates an isolated admin token via AppInfo service
3. Caller receives the elevated process; the admin token has no direct link to the caller's session

**Attack hypotheses**:
- Can a low-privilege caller obtain the admin token directly without UI prompt?
- Can a low-privilege caller inject into the elevated process before it hardens?
- Can the AppInfo service's token generation be manipulated?
- Are there COM objects that activate in admin context without requiring the prompt?
- Can token inheritance bypass the isolation?

**Phase 2: Enumerate all code paths that produce admin tokens**

Not just the documented `ShellExecute` path — any path through which the AppInfo
service or any SYSTEM component creates an elevated token. Each path is a bypass
candidate if the caller can trigger it without going through the elevation prompt UI.

**Phase 3: Test each hypothesis**

Project Zero documented 9+ distinct bypass techniques, each representing a different
code path that either:
- Produced an admin token without prompting, or
- Allowed a low-privilege caller to manipulate the elevated process before it reduced privileges

### 12.8.3 Why This Is the Model Variant Hunting Case Study

The AdminProtection bypass series demonstrates every principle of systematic variant hunting:

1. **New feature = new attack surface**: Microsoft introduced a new security boundary
   with complex implementation. Complexity in security boundaries creates bugs.

2. **Root cause abstraction**: The root cause is not any single bypass — it is the
   architectural challenge of implementing a new privilege boundary on top of an existing
   system with many pre-existing token/process creation code paths. Any of those code
   paths that create elevated tokens without AdminProtection's new verification becomes a bypass.

3. **Systematic enumeration**: Rather than finding one bypass and stopping, Project Zero
   enumerated the entire bypass surface by following the threat model systematically.

4. **Incomplete fix pattern**: Each patch closed one bypass path. The next bypass used
   a different path. This is the expected pattern when a root cause is architectural rather
   than a specific missing check.

5. **Velocity of variants**: 9+ variants in the first year of the feature's existence.
   This is consistent with historical patterns for new Windows security features
   (UAC had similar variant rates in its first years).

---

## 12.9 Building a Fuzzing → Triage → Root Cause Pipeline

### 12.9.1 Pipeline Architecture

```
Seed corpus generation
        ↓
Fuzzing (Jackalope / WTF)
        ↓
Crash collection
        ↓
Deduplication (stack hash, crash address)
        ↓
Automated crash triage
  ├── !exploitable (WinDbg extension) — classify exploitability
  ├── GFlags / Page Heap — catch heap corruption earlier
  └── Stack trace analysis — identify crash type and location
        ↓
Manual root cause analysis
  ├── Reproduce minimum crash input
  ├── Identify vulnerable code path in IDA/Ghidra
  ├── Understand root cause (missing check, type confusion, etc.)
  └── Assess exploitability
        ↓
Variant hunting
  ├── CodeQL/Semgrep query from root cause pattern
  ├── Cross-reference other callers of vulnerable function
  └── Test variant hypotheses
```

### 12.9.2 !exploitable WinDbg Extension

```windbg
; Load !exploitable (MS Research tool — MSEC.dll)
.load msec.dll

; Run on crash
!exploitable

; Output classifications:
; EXPLOITABLE — high confidence exploitable crash (control of RIP/RSP, write-what-where)
; PROBABLY_EXPLOITABLE — moderate confidence
; PROBABLY_NOT_EXPLOITABLE — DoS-level crash
; UNKNOWN — insufficient information

; Combine with GFlags for heap page heap to catch pool corruption earlier
; On target VM:
gflags.exe +hpa <process_name>  ; user mode page heap
gflags.exe /k +hpa              ; kernel mode page heap
```

### 12.9.3 Crash Deduplication Strategy

For high-volume kernel fuzzing, crashes must be deduplicated before manual analysis:

1. **Hash the crash stack trace** (top 3-5 frames, excluding fuzzer harness frames)
2. **Cluster by crash address** (same kernel address = likely same bug)
3. **Priority by classification**: EXPLOITABLE > PROBABLY_EXPLOITABLE > DoS
4. **Minimize the crashing input**: binary search the input to find the smallest
   input that still crashes → easier root cause analysis

### 12.9.4 Variant Hunting Integration

After root cause analysis:

1. **Write a CodeQL/Semgrep query** capturing the root cause pattern
2. **Run the query** against the full target codebase (all Windows binaries if source available,
   or binary search in IDA/Ghidra for common patterns)
3. **Test each candidate** — does the candidate location share the root cause?
4. **Document results**: confirmed variants, ruled-out candidates (with reasoning),
   fix completeness assessment

---

## 12.10 Variant Hunting Tools Summary

### 12.10.1 Comprehensive Tool Reference

| Tool | Type | Best For | URL |
|---|---|---|---|
| NtObjectManager | PowerShell module | Windows object ACL enumeration | github.com/googleprojectzero/sandbox-attacksurface-analysis-tools |
| OleViewDotNet | GUI | COM server security descriptor analysis | github.com/tyranid/oleviewdotnet |
| RpcView | GUI | RPC endpoint enumeration, NDR decompilation | rpcview.org |
| Jackalope | Fuzzer | Coverage-guided IOCTL/API fuzzing | github.com/googleprojectzero/jackalope |
| WTF | Fuzzer | Snapshot-based kernel fuzzing | github.com/0vercl0k/wtf |
| CodeQL | SAST | Semantic variant scanning on source | codeql.github.com |
| Semgrep | SAST | Fast syntactic pattern matching | semgrep.dev |
| PrivescCheck | Enum | Automated LPE misconfiguration audit | github.com/itm4n/PrivescCheck |
| Coercer | Enum | Auth coercion RPC interface testing | github.com/p0dalirius/Coercer |
| ProcMon | Dynamic | File/registry/network operation tracing | learn.microsoft.com/sysinternals |
| AccessChk | Enum | ACL checking for files/registry/services | learn.microsoft.com/sysinternals |
| BinDiff | Binary diff | Patch analysis, changed function identification | zynamics.com/bindiff.html |

### 12.10.2 Variant Hunting Checklist

After finding a bug:
- [ ] Root cause identification: what is the fundamental flaw (not the symptom)?
- [ ] Call site enumeration: how many other code paths share this root cause?
- [ ] Fix quality assessment: does the fix address root cause or just the PoC path?
- [ ] Related API scan: what other APIs in the same component do similar operations?
- [ ] Cross-component scan: do other Windows components have similar patterns?
- [ ] Historical variants: has this class appeared before? What were the previous fixes?

After analyzing a patch:
- [ ] Fix completeness: does the fix cover all call sites?
- [ ] Root cause fix: is the fix at the root cause level or symptomatic?
- [ ] Bypass potential: can the fix be bypassed via different input or code path?
- [ ] Sibling check: are there sibling functions with the same bug unfixed?
- [ ] Version regression: was this bug present before and a previous fix reverted?

Systematic scan:
- [ ] CodeQL query: can the root cause pattern be expressed as a CodeQL query?
- [ ] Semgrep rule: can it be expressed as a fast pattern-matching rule?
- [ ] Binary pattern search: what IDA/Ghidra search would find similar code?
- [ ] Symbol-guided search: what function names suggest similar operations?

---

## References

[R-1] Project Zero Variant Hunting Methodology
  — Google Project Zero — https://googleprojectzero.blogspot.com/

[R-2] CodeQL — Semantic Code Analysis
  — GitHub / Microsoft — https://codeql.github.com/

[R-3] Jackalope — Coverage-Guided Fuzzer
  — Google Project Zero — https://github.com/googleprojectzero/jackalope

[R-4] WTF — Snapshot-Based Windows Fuzzer
  — 0vercl0k — https://github.com/0vercl0k/wtf

[R-5] sandbox-attacksurface-analysis-tools (NtObjectManager)
  — James Forshaw / Google Project Zero — https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools

[R-6] Semgrep — Fast Static Analysis
  — Semgrep Inc. — https://semgrep.dev/

[R-7] Bochspwn Reloaded — Automated Kernel Variant Discovery
  — j00ru / Google Project Zero — https://j00ru.vexillium.org/talks/blackhat17-bochspwn-reloaded/
