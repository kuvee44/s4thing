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

### 12.3.5 CodeQL 2024 Updates and Migration Notes

**Improved C++ query performance (2024)**

CodeQL 2024 releases introduced significant performance improvements for large C++
codebases. Key changes relevant to Windows research:
- Incremental database builds: re-run only on changed translation units (useful for
  tracking Windows Insider builds)
- Improved `DataFlow::Configuration` API replaced by the new `DataFlow::Module` approach
  in CodeQL v2.15+; older query syntax still works but shows deprecation warnings

**LGTM shutdown — migration to GitHub Code Scanning**

LGTM.com was shut down in **March 2024**. All analysis now happens via:
- GitHub Code Scanning (for repositories hosted on GitHub)
- CodeQL CLI (local / CI analysis, recommended for closed-source work)
- VS Code CodeQL extension for interactive query development

For Windows research against proprietary binaries and driver source obtained via
bug bounty / partner programs, the CLI workflow is the only viable option:

```bash
# Recommended local workflow post-LGTM
codeql database create win_driver_db \
    --language=cpp \
    --command="msbuild /t:Build /p:Configuration=Release driver.sln" \
    --source-root=C:\driver_source\

# Analyze with a query suite
codeql database analyze win_driver_db \
    codeql/cpp-queries:Security/ \
    --format=sarif-latest \
    --output=results.sarif
```

**CodeQL for Win32k syscall filtering — `NtUserGetMessage` variant class**

The Win32k syscall allow-list (introduced as a sandbox mitigation) creates an
interesting variant class: any Win32k syscall reachable from low-IL processes that
is not on the allow-list but still executes represents an incomplete filter.
A CodeQL query to enumerate such candidates against the Win32k source:

```ql
import cpp

// Find Win32k kernel entry stubs that are NOT in the syscall filter table
// (requires Win32k source or partially-reversed symbols)

class Win32kSyscallStub extends Function {
    Win32kSyscallStub() {
        // Win32k user-mode entry stubs share a naming convention
        this.getName().matches("NtUser%") or
        this.getName().matches("NtGdi%")
    }
}

class SyscallFilterEntry extends StringLiteral {
    SyscallFilterEntry() {
        // The filter table is typically an array of string constants
        // or an enum; adapt to actual implementation
        this.getParent*().(ArrayAggregateLiteral).getType().getName() = "SYSCALL_FILTER_ENTRY"
    }
}

from Win32kSyscallStub stub
where
    // Stub is not referenced in the filter table
    not exists(SyscallFilterEntry entry |
        entry.getValue() = stub.getName()
    )
select stub, "Win32k syscall stub potentially absent from filter table: " + stub.getName()
```

**MSRC open-sourced CodeQL queries (2024)**

In 2024, MSRC published a set of CodeQL queries used internally for Windows driver
vulnerability research. These are available in the
`microsoft/Windows-Driver-Developer-Supplemental-Tools` repository on GitHub.
Key queries to study:
- `DriverPortability/` — driver compatibility checks
- `Likely Bugs/Memory Management/` — pool allocation patterns without size validation
- `Likely Bugs/UninitializedPtrField/` — uninitialized pointer fields in kernel structs

```bash
# Clone and use MSRC's driver query pack
git clone https://github.com/microsoft/Windows-Driver-Developer-Supplemental-Tools
cd Windows-Driver-Developer-Supplemental-Tools

# Run the Windows driver security queries against your database
codeql database analyze win_driver_db \
    windows-driver-developer-supplemental-tools/codeql/windows-drivers/queries/ \
    --format=sarif-latest \
    --output=driver_results.sarif
```

**CodeQL database creation for Windows kernel drivers (cross-compile workflow)**

Building a CodeQL database for a Windows kernel driver from a Linux/WSL2 host requires
a cross-compilation harness. The key challenge: `codeql database create` must intercept
the actual compiler invocations to extract compilation units.

```bash
# On WSL2 — cross-compile workflow using MSVC via wine or a build VM
# Option 1: Build inside a Windows VM, extract the DB, analyze on Linux
#   (codeql databases are platform-independent after creation)

# Option 2: Use the CodeQL "indirect build tracer" for MSVC
# Set CodeQL trace environment before invoking msbuild
export CODEQL_EXTRACTOR_CPP_TRAP_DIR=/tmp/codeql_traps
export CODEQL_EXTRACTOR_CPP_SOURCE_ARCHIVE_DIR=/tmp/codeql_src

# Then run the build inside a Windows environment with CodeQL tracing active:
# %CODEQL_HOME%\tools\win64\trace\codeql-win64.exe msbuild driver.sln

# After build completes, finalize the database
codeql database finalize win_driver_db

# Practical tip: use GitHub Actions with a Windows runner for automated
# driver database creation as part of CI
```

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

### 12.5.3 Jackalope/TinyInst 2024 Updates — Windows 11 Compatibility

TinyInst received several significant updates through 2024 to improve Windows 11
compatibility:

- **ARM64 support**: TinyInst now supports coverage instrumentation on Windows ARM64,
  enabling fuzzing on Surface Pro X / ARM64 devices where some driver attack surface
  differs from x64
- **Windows 11 22H2/23H2 compatibility fixes**: Several issues with module loading
  order and instrumentation of modules loaded via the new loader path in 22H2 were
  resolved
- **`-patch_return_addresses` flag**: New flag to patch return addresses for better
  indirect call coverage on modern Windows CFG-protected binaries

```bash
# Updated Jackalope invocation for Windows 11 targets
jackalope.exe \
    -in corpus\ \
    -out findings\ \
    -t 5000 \
    -coverage_modules target.sys \
    -target_module harness.exe \
    -target_method WinMain \
    -patch_return_addresses \         # Better CFG-protected module coverage
    -instrument_modules_on_load \     # Handle late-loaded modules
    -- harness.exe @@
```

### 12.5.4 Coverage-Guided RPC Interface Fuzzing with `NdrClientCall2` Hooking

RPC interfaces present a large and often under-fuzzed attack surface. The challenge:
RPC clients generate NDR-encoded buffers that must be structurally valid for the server
to even reach interesting code. Jackalope can be paired with an `NdrClientCall2`
hooking harness to get coverage-guided fuzzing of RPC server handlers.

**Approach**: Hook `NdrClientCall2` in the target RPC client DLL to intercept the NDR
buffer before transmission. Jackalope mutates the raw NDR bytes with coverage feedback
from the server-side handler.

```cpp
// RPC fuzzing harness skeleton using NdrClientCall2 interception
#include <windows.h>
#include <rpc.h>
#include <rpcndr.h>

// The NDR stub descriptor for the target interface
// (extracted from the compiled RPC client stub using IDA/Ghidra)
extern const MIDL_STUB_DESC TargetInterface_StubDesc;

int APIENTRY WinMain(HINSTANCE, HINSTANCE, LPSTR lpCmdLine, int) {
    // Read fuzzed NDR payload from Jackalope-provided file
    HANDLE hInput = CreateFileA(lpCmdLine, GENERIC_READ, 0, NULL,
                                OPEN_EXISTING, 0, NULL);
    DWORD size = GetFileSize(hInput, NULL);
    BYTE* ndrBuf = (BYTE*)malloc(size);
    DWORD read;
    ReadFile(hInput, ndrBuf, size, &read, NULL);
    CloseHandle(hInput);

    // Bind to the RPC server endpoint directly
    RPC_BINDING_HANDLE hBinding = NULL;
    RpcStringBindingCompose(NULL,
        (RPC_WSTR)L"ncalrpc",
        NULL,
        (RPC_WSTR)L"target_endpoint",
        NULL,
        (RPC_WSTR*)&szBinding);
    RpcBindingFromStringBinding((RPC_WSTR)szBinding, &hBinding);

    // Invoke the target RPC method with fuzzed NDR buffer
    // Method index 0 as example — enumerate all methods for full coverage
    __try {
        NdrClientCall2(
            &TargetInterface_StubDesc,
            &TargetInterface_ProcFormatString[METHOD_OFFSET_0],
            hBinding,
            ndrBuf   // fuzzed method-specific data
        );
    } __except(EXCEPTION_EXECUTE_HANDLER) {}

    RpcBindingFree(&hBinding);
    free(ndrBuf);
    return 0;
}
```

### 12.5.5 Jackalope for COM Server Fuzzing — `IDispatch::Invoke` Coverage

COM automation servers that expose `IDispatch` are accessible from low-IL contexts
and represent a significant attack surface. Jackalope can fuzz `IDispatch::Invoke`
calls with coverage feedback from the COM server process.

```cpp
// COM IDispatch fuzzing harness
#include <windows.h>
#include <oleauto.h>

int APIENTRY WinMain(HINSTANCE, HINSTANCE, LPSTR lpCmdLine, int) {
    CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);

    // Read fuzzed VARIANT argument data
    HANDLE hInput = CreateFileA(lpCmdLine, GENERIC_READ, 0, NULL,
                                OPEN_EXISTING, 0, NULL);
    DWORD size = GetFileSize(hInput, NULL);
    BYTE* inputBuf = (BYTE*)malloc(size);
    DWORD read;
    ReadFile(hInput, inputBuf, size, &read, NULL);
    CloseHandle(hInput);

    // Instantiate target COM server (out-of-proc, so COM server is the fuzzing target)
    IDispatch* pDisp = NULL;
    CLSID clsid;
    // Target CLSID — enumerate accessible COM servers with OleViewDotNet
    CLSIDFromString(L"{TARGET-CLSID-HERE}", &clsid);
    CoCreateInstance(clsid, NULL, CLSCTX_LOCAL_SERVER,
                     IID_IDispatch, (void**)&pDisp);

    if (pDisp) {
        // Build DISPPARAMS from fuzzed input
        VARIANTARG varg;
        VariantInit(&varg);
        varg.vt = VT_BSTR;
        // Use first 'size' bytes as a BSTR argument
        varg.bstrVal = SysAllocStringByteLen((LPCSTR)inputBuf, size);

        DISPPARAMS params = { &varg, NULL, 1, 0 };
        VARIANT result;
        VariantInit(&result);

        // Fuzz DISPID 0 (default method) — enumerate all DISPIDs for full coverage
        __try {
            pDisp->Invoke(0, IID_NULL, LOCALE_USER_DEFAULT,
                          DISPATCH_METHOD, &params, &result, NULL, NULL);
        } __except(EXCEPTION_EXECUTE_HANDLER) {}

        SysFreeString(varg.bstrVal);
        VariantClear(&result);
        pDisp->Release();
    }

    free(inputBuf);
    CoUninitialize();
    return 0;
}
```

**Coverage target**: Specify the COM server EXE/DLL (not the harness) as
`-coverage_modules` in Jackalope. TinyInst will instrument the out-of-process COM
server for coverage feedback:

```bash
jackalope.exe \
    -in corpus_com\ \
    -out findings_com\ \
    -t 10000 \
    -coverage_modules comserver.dll \
    -target_module com_harness.exe \
    -target_method WinMain \
    -- com_harness.exe @@
```

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

### 12.6.4 WTF 2024 Status — Windows 11 22H2/23H2 Support

WTF has been actively maintained through 2024 with explicit support for newer Windows
targets:

- **Windows 11 22H2 and 23H2** snapshot compatibility verified; the snapshot format
  and VMCS handling were updated to account for changes in Hyper-V enlightenments
  present in newer builds
- **Bochs backend updated** to handle new MSRs introduced in 22H2 that caused snapshot
  restore failures on older WTF versions
- **Symbol loading improvements**: WTF now handles PDB loading for Windows 11 23H2
  kernel symbols via the updated `bxcpu` backend

```bash
# Verify WTF snapshot compatibility with your Windows 11 target
wtf bochscpu --name check_snapshot --state /path/to/snapshot/ --input /dev/null \
    --limit 1 --verbose
# Expected: snapshot loads, executes 1 instruction, exits cleanly
```

### 12.6.5 New WTF Modules: `ntfs_fuzzer.cc` and `alpc_fuzzer.cc`

The WTF repository gained two significant new fuzzer modules in 2024:

**`ntfs_fuzzer.cc`** — Snapshot-based fuzzer for the NTFS driver (`ntfs.sys`):
- Takes a snapshot with a mounted NTFS volume at the point `NtCreateFile` is called
- Mutates the on-disk NTFS metadata (MFT records, index entries, attribute lists)
  by patching the virtual disk image between iterations
- Has been used to discover several NTFS parsing bugs; approach is directly transferable
  to other file system drivers (`refs.sys`, `exfat.sys`)

```cpp
// ntfs_fuzzer.cc target skeleton
bool InsertTestcase(const uint8_t *Buffer, const size_t BufferSize) {
    // Write fuzzed NTFS sector data to the snapshot's virtual disk
    // at offset corresponding to the MFT record being parsed
    const uint64_t MftOffset = g_State.TargetMftOffset;
    if (!g_Backend->VirtWriteDirty(MftOffset, Buffer,
                                   std::min(BufferSize, (size_t)0x400))) {
        return false;
    }
    return true;
}
```

**`alpc_fuzzer.cc`** — Snapshot-based fuzzer for ALPC message handling:
- Snapshot is taken in the kernel at the `AlpcpReceiveMessage` entry point
- Mutates the ALPC message buffer (port message header + message body) directly
  in kernel memory
- Useful for finding vulnerabilities in ALPC-based IPC between SYSTEM services

### 12.6.6 WTF + Hyper-V Isolation for Kernel Fuzzing

For targets that require actual hardware virtualization (nested VMs, Hyper-V
hypercalls), WTF supports a Hyper-V backend that runs the fuzzing VM inside Hyper-V
rather than Bochs:

```bash
# Hyper-V backend — requires Windows host with Hyper-V enabled
# Create snapshot using the Hyper-V checkpoint mechanism
# (WTF docs: https://github.com/0vercl0k/wtf/blob/master/docs/hyperv-backend.md)

wtf run --name alpc_fuzz \
    --state snapshot_hyperv/ \
    --input corpus_alpc/ \
    --backend hyperv \          # Use Hyper-V instead of Bochs emulation
    --limit 10000
```

**Advantage over Bochs backend**: Near-native execution speed for hardware-dependent
code paths. The trade-off is that Hyper-V does not support all coverage instrumentation
modes that Bochs does (no instruction-level tracing).

### 12.6.7 Performance Comparison: WTF vs kAFL for Windows Kernel Targets

kAFL (originally from Intel, now maintained at https://github.com/IntelLabs/kAFL)
is an alternative snapshot-based kernel fuzzer that uses Intel PT for coverage.
Comparison for Windows kernel targets:

| Metric | WTF (Bochs) | WTF (Hyper-V) | kAFL (Intel PT) |
|---|---|---|---|
| Iterations/sec (simple handler) | ~5,000–15,000 | ~50,000–200,000 | ~30,000–150,000 |
| Coverage granularity | Basic block (emulated) | Basic block (Intel PT) | Edge coverage (Intel PT) |
| Windows 11 support | Yes (verified 23H2) | Yes | Partial (requires custom kernel) |
| Snapshot fidelity | High (full CPU state) | High | High |
| Setup complexity | Medium | High | High |
| Distributed fuzzing | Built-in | Built-in | Manual (AFL++ compatible) |
| Hardware dependency | None (emulated) | Intel/AMD VT-x | Intel PT required |

**Practical guidance**: For initial exploration and portability, start with WTF (Bochs).
When iteration rate becomes the bottleneck and hardware with Intel PT is available,
kAFL or WTF (Hyper-V) provides a 10–50x improvement.

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

### 12.8.4 CVE-2025-21204 — Administrator Protection Bypass via Windows Update Symlink

**Vulnerability**: `TiWorker.exe` (the Windows Update worker process, running as SYSTEM)
writes files to `C:\Config.Msi` without checking whether the path has been replaced by
a junction or symlink.

**Root cause analysis (itm4n)**:

itm4n's analysis of CVE-2025-21204 identified the following exploitation chain:
1. `TiWorker.exe` creates or writes rollback/logging files to `C:\Config.Msi\` during
   a Windows Update or MSI installation operation
2. The path construction in `TiWorker.exe` does not call `NtCreateFile` with
   `FILE_FLAG_OPEN_REPARSE_POINT` — it follows symlinks and junctions transparently
3. A low-privilege attacker who can create `C:\Config.Msi` before the update operation
   (or replace it with a junction) can redirect the SYSTEM write to an arbitrary path
4. This achieves an arbitrary file write as SYSTEM, which can be escalated to full
   code execution via DLL planting or service binary replacement

**`TiWorker.exe` file operation enumeration for variants**:

```powershell
# Monitor TiWorker.exe file operations with ProcMon filter
# ProcMon filter: Process Name is TiWorker.exe AND Operation is WriteFile OR CreateFile
# Look for:
#   - Paths under C:\ that are not fully qualified as C:\Windows\...
#   - Paths containing user-writable intermediate directories
#   - Paths that do not use FILE_FLAG_OPEN_REPARSE_POINT

# ETW-based monitoring (no ProcMon required)
$session = New-EtwTraceSession -Name "TiWorkerTrace" -LogFileName "C:\tiworker.etl"
Add-EtwTraceProvider -SessionName "TiWorkerTrace" `
    -Guid "{9b79ee97-b5c5-45d0-8af3-7b82e9e91d84}" `  # Microsoft-Windows-Kernel-File
    -Level 4 `
    -MatchAnyKeyword 0x10  # KERNEL_FILE_KEYWORD_FILEIO_WRITE

Start-Process "C:\Windows\System32\TiWorker.exe" -ArgumentList "-embedding"
# Trigger Windows Update check
Start-Sleep 30
Stop-EtwTraceSession -Name "TiWorkerTrace"

# Analyze the ETL for writes outside C:\Windows\
tracerpt C:\tiworker.etl -o tiworker_report.xml
```

**Variant discovery methodology**: The key insight from CVE-2025-21204 is that any
`TiWorker.exe` file write operation to a path that:
1. Is not under `C:\Windows\` or `C:\Program Files\`
2. Does not use `FILE_FLAG_OPEN_REPARSE_POINT`
3. Occurs when the target directory can be raced or pre-created by a low-privilege user

...is a candidate for a symlink-based privilege escalation variant.

**Detection via ETW**:

```powershell
# Detect junction/symlink creation followed by TiWorker write
# Using Microsoft-Windows-Security-Auditing provider

# Event 4663: Object Access — filter for TiWorker.exe and NtCreateSymbolicLinkObject
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id = 4663
} | Where-Object {
    $_.Properties[1].Value -match "TiWorker" -or
    $_.Properties[6].Value -match "Config.Msi"
} | Select-Object TimeCreated, Message

# Alternative: ETW trace for NtCreateSymbolicLinkObject by low-IL processes
# combined with subsequent TiWorker.exe write operations to same path
$filterScript = {
    $_.ProviderName -eq "Microsoft-Windows-Kernel-File" -and
    $_.Message -match "Config.Msi"
}
```

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

## 12.11 CVE-2024-21338 Variant Class Analysis

### 12.11.1 Background: The `appid.sys` Exploit Class

CVE-2024-21338 was a Windows AppLocker kernel driver (`appid.sys`) vulnerability
exploited in the wild by the Lazarus Group (DPRK). The exploitation technique involved
an IOCTL interface in `appid.sys` that was callable from user mode at medium IL, leading
to a kernel memory corruption vulnerability.

The significance for variant hunting: this bug demonstrated that Windows security
drivers — processes and drivers that are PPL-protected (Protected Process Light) or
otherwise have elevated trust — can expose IOCTL interfaces callable from less-privileged
contexts. The IOCTL handler may perform operations that assume the caller has already
been validated by a higher-level check that does not apply at the kernel IOCTL level.

### 12.11.2 The Attack Pattern: PPL-Protected Drivers with Accessible IOCTLs

The `appid.sys` pattern:
1. Driver is PPL-protected (its process cannot be tampered from non-PPL code)
2. Driver registers a device (`\Device\AppID`) accessible from user mode at medium IL
3. The IOCTL handler at `IOCTL_APPID_*` performs kernel operations without sufficient
   bounds checking on attacker-controlled input
4. Memory corruption in kernel pool → privilege escalation

**Why this creates a variant class**: Windows security drivers must be callable from
the processes they protect — which means they must expose IOCTL interfaces. But the
callers are constrained (only the security product's user-mode agent calls them), so
the IOCTL handlers are not written with the same adversarial input assumptions as
general kernel interfaces.

### 12.11.3 Enumerating IOCTL Interfaces on PPL Processes

The research methodology for finding similar drivers:

```powershell
# Step 1: Enumerate devices accessible from medium IL
Import-Module NtObjectManager

# List all device objects and their security descriptors
Get-NtObject -Path "\Device" -DirectoryOnly | ForEach-Object {
    try {
        $obj = Get-NtObject -Path "\Device\$($_.Name)" -ErrorAction Stop
        $sd = $obj.SecurityDescriptor
        # Check if readable/writable by medium IL (standard users)
        $access = Test-NtAccessMask -SecurityDescriptor $sd `
                  -Access 0xC0000000 `  # GENERIC_READ | GENERIC_WRITE
                  -ProcessIntegrity Medium
        if ($access) {
            Write-Output "ACCESSIBLE: \Device\$($_.Name)"
        }
        $obj.Close()
    } catch {}
}
```

```powershell
# Step 2: Cross-reference with PPL/security driver list
$securityDrivers = @(
    "appid.sys",    # AppLocker — CVE-2024-21338 (patched)
    "cng.sys",      # Cryptography Next Generation
    "ci.dll",       # Code Integrity
    "ksecdd.sys",   # Kernel Security Support Provider
    "fvevol.sys",   # BitLocker (Full Volume Encryption)
    "wdboot.sys",   # Windows Defender Boot Driver
    "hvsimp.sys",   # Hypervisor-protected Code Integrity
    "peauth.sys"    # Protected Environment Authentication
)

# Check which security drivers expose accessible device objects
foreach ($driver in $securityDrivers) {
    $driverName = [System.IO.Path]::GetFileNameWithoutExtension($driver)
    Get-NtObject -Path "\Device" -DirectoryOnly | Where-Object {
        $_.Name -match $driverName
    } | ForEach-Object {
        Write-Output "Security driver device: \Device\$($_.Name) (from $driver)"
    }
}
```

### 12.11.4 IOCTL Handler Analysis Methodology

For each accessible device associated with a security driver:

**Step 1: Extract IOCTL codes via IDA/Ghidra**

The dispatch table for IRP_MJ_DEVICE_CONTROL lists the IOCTL handler. Enumerate
all IOCTL codes by finding the `switch` statement or dispatch table in the handler:

```python
# IDA Python script to enumerate IOCTL codes from a driver's dispatch function
import idaapi
import idautils

def find_ioctl_codes(dispatch_func_ea):
    """
    Walk the IRP_MJ_DEVICE_CONTROL handler looking for comparison
    instructions against IOCTL code constants.
    """
    ioctl_codes = []
    for insn in idautils.FuncItems(dispatch_func_ea):
        if idc.print_insn_mnem(insn) in ('cmp', 'sub'):
            op2 = idc.get_operand_value(insn, 1)
            # IOCTL codes follow the CTL_CODE macro pattern:
            # Bits 31-16: Device type, bits 15-14: Access, bits 13-2: Function, bits 1-0: Method
            if 0x00220000 <= op2 <= 0x0022FFFF or \
               0x00040000 <= op2 <= 0x0004FFFF:
                ioctl_codes.append(op2)
                print(f"IOCTL code candidate: 0x{op2:08X} at 0x{insn:X}")
    return ioctl_codes
```

**Step 2: WinDbg trace each IOCTL handler for memory operations**

```windbg
; Set up IOCTL handler breakpoint
bp \Device\TargetDriver!IrpMjDeviceControl

; When hit, log the input buffer and length
.printf "IOCTL: 0x%x, InputLen: 0x%x\n", \
    poi(@rsp+0x28),   ; IoControlCode
    poi(@rsp+0x30)    ; InputBufferLength

; Enable pool tagging to catch pool corruptions
!gflag +hpa
!pool

; Break on pool corruption detection
bp nt!ExFreePoolWithTag ".if (poi(@rcx+0x100) != poi(@rcx)) {.echo CORRUPTION; k} .else {g}"
```

### 12.11.5 Candidate Drivers for the `appid.sys` Variant Class

Based on the methodology above, the following drivers represent research candidates
(as of H1 2024 — some may have been patched in H2 2024):

| Driver | Device Object | IOCTL Surface | Notes |
|---|---|---|---|
| `cng.sys` | `\Device\CNG` | Key management, RNG | Accessible from medium IL; complex IOCTL interface |
| `ksecdd.sys` | `\Device\KsecDD` | LSA/SSPI operations | Used by LSASS; IOCTL handlers handle sensitive crypto buffers |
| `fvevol.sys` | `\Device\FveVol` | BitLocker volume ops | Callable during pre-boot auth setup |
| `ci.dll` | (kernel component, no direct device) | Code integrity checks | Exposed via NtSetSystemInformation class |

**Note**: MSRC acknowledged several variants in this class and issued patches in the
H2 2024 Patch Tuesday cycles (specific CVE numbers not confirmed at time of writing;
check MSRC advisory portal for `appid.sys` variant class bulletins).

### 12.11.6 Responsible Research Approach

Given that these are security drivers with active protections:
1. Conduct all testing in an isolated VM with kernel debugging enabled
2. Use WTF snapshot fuzzing rather than live system testing (avoids corrupting the
   host's security state)
3. Report findings to MSRC before publication; the IOCTL interfaces in security drivers
   are not publicly documented, so independent discovery is achievable

---

## 12.12 LLM-Assisted Variant Hunting (2024–2025 Emerging Technique)

### 12.12.1 Overview and Current State

Large Language Models (LLMs) began appearing in practical Windows security research
workflows in 2024. The application is not autonomous vulnerability discovery — current
LLMs lack the symbolic reasoning required for reliable bug-finding — but rather as a
force multiplier for specific subtasks in the variant hunting pipeline.

The primary use cases where LLMs add demonstrable value:
1. **Decompiled code triage**: Ranking candidate functions by likelihood of containing
   a specific vulnerability pattern
2. **Crash report summarization**: Converting raw WinDbg crash output into structured
   summaries for deduplication
3. **Documentation generation**: Producing structured analysis notes from IDA/Ghidra
   comments and disassembly

### 12.12.2 LLM for Decompiled Code Review

The workflow for using GPT-4 or Claude for decompiled code review:

```python
#!/usr/bin/env python3
"""
LLM-assisted decompiled function triage.
Input: list of decompiled functions (from IDA Hex-Rays or Ghidra decompiler)
Output: ranked list of functions by vulnerability likelihood
"""

import anthropic
import json

SYSTEM_PROMPT = """You are a Windows kernel security researcher reviewing decompiled C code.
For each function, identify potential vulnerability patterns:
- Missing bounds checks on size parameters before memcpy/memmove
- Missing NULL checks on pointer parameters before dereference
- Integer overflow in size calculations (multiplication before allocation)
- Use of user-supplied pointers in kernel context without ProbeForRead/Write
- Missing impersonation before privileged file/registry operations

Respond with JSON: {"risk": "high|medium|low", "pattern": "<pattern name>", "reason": "<1 sentence>"}
"""

def triage_function(decompiled_code: str) -> dict:
    client = anthropic.Anthropic()
    response = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=256,
        system=SYSTEM_PROMPT,
        messages=[{
            "role": "user",
            "content": f"Review this decompiled kernel function:\n\n```c\n{decompiled_code}\n```"
        }]
    )
    try:
        return json.loads(response.content[0].text)
    except json.JSONDecodeError:
        return {"risk": "unknown", "pattern": "", "reason": response.content[0].text}

# Example: triage a batch of Ghidra-decompiled functions
if __name__ == "__main__":
    import sys
    functions = json.load(open(sys.argv[1]))  # {"name": str, "code": str}[]
    results = []
    for fn in functions:
        result = triage_function(fn["code"])
        result["name"] = fn["name"]
        results.append(result)
        print(f"{fn['name']}: {result['risk']} — {result['pattern']}")

    # Sort by risk: high → medium → low
    priority = {"high": 0, "medium": 1, "low": 2, "unknown": 3}
    results.sort(key=lambda r: priority.get(r["risk"], 3))
    json.dump(results, open("triage_results.json", "w"), indent=2)
```

**Important caveats**:
- LLMs operate on text without symbolic context: they cannot track pointer provenance,
  understand Windows kernel data structures, or reason about control flow graphs
- False positive rate is high (30–60% in practice) — LLM triage reduces the candidate
  set, it does not confirm vulnerabilities
- Use as a first-pass filter before manual review, not as a standalone verdict

### 12.12.3 LLM as Triage Layer for Jackalope Crash Reports

Jackalope crash reports consist of a stack trace, crash address, and crash context.
Processing hundreds of crashes manually for deduplication and preliminary severity
assessment is time-consuming. LLMs can assist:

```python
#!/usr/bin/env python3
"""
LLM-assisted Jackalope crash triage.
Reads WinDbg crash dumps from Jackalope findings directory,
produces structured JSON summary for each unique crash.
"""

import anthropic
import os
import subprocess

CRASH_TRIAGE_PROMPT = """Analyze this WinDbg crash output from a Windows kernel fuzzer.
Provide:
1. Crash type (heap corruption, null deref, stack overflow, use-after-free, other)
2. Likely exploitability (exploitable, probably exploitable, probably not, unknown)
3. Crash location (kernel module + function if identifiable from stack trace)
4. Suggested deduplication key (3-4 most relevant stack frames)

Format: JSON with keys: crash_type, exploitability, location, dedup_key, summary
"""

def analyze_crash(crash_log: str) -> dict:
    client = anthropic.Anthropic()
    response = client.messages.create(
        model="claude-haiku-4-5",   # Use Haiku for cost efficiency on bulk triage
        max_tokens=512,
        messages=[{
            "role": "user",
            "content": f"{CRASH_TRIAGE_PROMPT}\n\nCrash log:\n```\n{crash_log}\n```"
        }]
    )
    import json
    try:
        return json.loads(response.content[0].text)
    except json.JSONDecodeError:
        return {"crash_type": "parse_error", "summary": response.content[0].text}

def process_jackalope_findings(findings_dir: str):
    crashes = []
    for root, dirs, files in os.walk(findings_dir):
        for f in files:
            if f.endswith(".txt") or f.endswith(".log"):
                log_path = os.path.join(root, f)
                with open(log_path) as fh:
                    crash_log = fh.read()
                result = analyze_crash(crash_log)
                result["file"] = f
                crashes.append(result)
                print(f"Triaged: {f} -> {result.get('exploitability', '?')} / {result.get('crash_type', '?')}")
    return crashes
```

### 12.12.4 Limitations of LLM-Based Variant Hunting

| Limitation | Impact | Mitigation |
|---|---|---|
| No symbolic context | Cannot track pointer provenance across function calls | Use only for single-function triage; verify with IDA/Ghidra |
| No data structure knowledge | Windows kernel structs (EPROCESS, KTHREAD, etc.) are opaque | Provide struct definitions in the prompt; partial improvement |
| High false positive rate | 30–60% of "high risk" flags are false positives | Treat as candidate filter, always verify manually |
| Token context limits | Large functions exceed context window | Chunk at logical boundaries (loops, conditionals) |
| No cross-call analysis | Cannot reason about calling context or permissions | Provide caller context manually if critical |
| Training data cutoff | Novel 2024+ vulnerability classes may be underrepresented | Supplement with few-shot examples of the target pattern |

### 12.12.5 Microsoft's AI-Assisted Security Research Program (2024)

In 2024, Microsoft announced expanded use of AI in their internal Security Response
Center workflows:
- **CyberSecEval** benchmarks were published for evaluating LLM security capabilities
- **Microsoft Security Copilot** (formerly Security Copilot, now Microsoft Copilot for
  Security) was made generally available in April 2024, with integrations into MSRC
  triage workflows
- Microsoft Research published papers on using LLMs for fuzzing guidance (seed selection
  and mutation strategy improvement), though primarily for user-mode targets

The practical implication for independent researchers: Microsoft's internal triage
velocity is increasing, which means the window between bug discovery and patch is
likely to compress further. Variant hunting efficiency improvements matter more.

### 12.12.6 The DBRIDA Technique: Differential Binary Review with AI Assistance

**DBRIDA** (Differential Binary Review with Integrated AI Assistance) is an emerging
technique for patch analysis that combines:
1. **BinDiff** for identifying changed functions between patched and unpatched builds
2. **Hex-Rays / Ghidra decompilation** of the changed functions
3. **LLM analysis** of the decompiled diff to identify what security check was added
4. **Automated variant generation**: prompt the LLM to describe the root cause and
   suggest other code patterns that might share the same root cause

```python
#!/usr/bin/env python3
"""
DBRIDA: Differential Binary Review with AI Assistance
Workflow:
1. Run BinDiff to get list of changed functions between old/new build
2. Decompile changed functions with IDA Hex-Rays
3. LLM analysis: what security check was added?
4. LLM variant suggestion: where else might this pattern appear?
"""

import anthropic
import json

DBRIDA_PROMPT = """You are analyzing a security patch applied to a Windows kernel binary.
You are given the decompiled pseudocode of a function BEFORE and AFTER the patch.

Tasks:
1. Identify what security check or validation was added/changed in the patch
2. Describe the root cause in one sentence (what was the bug class?)
3. Suggest 3-5 other function name patterns that might share this root cause
   (based on naming conventions in Windows kernel: Nt*, Zw*, Ex*, Rtl*, etc.)
4. Write a one-line Semgrep-style pattern description for the vulnerable pattern

Format: JSON with keys: patch_description, root_cause, variant_candidates, semgrep_hint
"""

def analyze_patch_diff(before_code: str, after_code: str) -> dict:
    client = anthropic.Anthropic()
    response = client.messages.create(
        model="claude-opus-4-5",
        max_tokens=1024,
        messages=[{
            "role": "user",
            "content": (
                f"{DBRIDA_PROMPT}\n\n"
                f"BEFORE (vulnerable):\n```c\n{before_code}\n```\n\n"
                f"AFTER (patched):\n```c\n{after_code}\n```"
            )
        }]
    )
    try:
        return json.loads(response.content[0].text)
    except json.JSONDecodeError:
        return {"root_cause": response.content[0].text}
```

**Example DBRIDA output** for a hypothetical patch:
```json
{
  "patch_description": "Added ProbeForRead check on user-supplied pointer before kernel dereference",
  "root_cause": "Kernel function dereferenced attacker-controlled pointer without validating it lies in user address space",
  "variant_candidates": [
    "NtUserGetMessage",
    "NtUserPeekMessage",
    "NtUserMsgWaitForMultipleObjectsEx",
    "NtUserWaitForInputIdle",
    "NtUserCallMsgFilter"
  ],
  "semgrep_hint": "Kernel function accepting PMESSAGE parameter that dereferences it without ProbeForRead"
}
```

The `variant_candidates` list from DBRIDA feeds directly into a targeted static
analysis pass (CodeQL or IDA scripting), converting LLM output into actionable
research leads.

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

[R-8] Windows Driver Developer Supplemental Tools (MSRC CodeQL queries)
  — Microsoft — https://github.com/microsoft/Windows-Driver-Developer-Supplemental-Tools

[R-9] CVE-2024-21338 — AppLocker AppID Driver LPE
  — MSRC Advisory — https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21338

[R-10] CVE-2025-21204 — Administrator Protection Bypass (TiWorker symlink)
  — itm4n analysis — https://itm4n.github.io/

[R-11] kAFL — Hardware-Assisted Kernel Fuzzing
  — Intel Labs — https://github.com/IntelLabs/kAFL

[R-12] Microsoft Copilot for Security — GA Announcement (April 2024)
  — Microsoft — https://www.microsoft.com/en-us/security/blog/
