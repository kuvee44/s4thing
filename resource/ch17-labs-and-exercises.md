# Chapter 17 — Labs & Exercises

> Theory without practice is incomplete. This chapter provides a structured lab curriculum for Windows security research — organized by tier, with setup instructions, tool requirements, learning objectives, and documentation templates. Labs progress from tool familiarity to kernel exploitation to variant discovery.

---

## Lab Environment Setup

### Required Virtual Machines

| VM Name | OS Version | Purpose | Network |
|---------|-----------|---------|---------|
| `win10-research` | Windows 10 22H2 (latest patches) | Primary research VM | Host-only |
| `win10-vuln` | Windows 10 1903 (unpatched) | Historical CVE reproduction | Isolated (no internet) |
| `win11-research` | Windows 11 22H2 | Modern kernel labs | Host-only |
| `winserver-lab` | Windows Server 2019 | Service/RPC/COM labs | Host-only |
| `win10-debuggee` | Windows 10 22H2 | Kernel debug target (KDNET) | Internal switch only |
| `win10-debugger` | Windows 10 22H2 | WinDbg host for kernel debugging | Internal switch only |

**Hardware:** 16GB RAM minimum (32GB recommended for running debugger pair simultaneously); SSD recommended for kernel debugging responsiveness.

**Hypervisor:** Hyper-V on Windows host recommended (nested virtualization for KDNET). VMware Workstation also works well. VirtualBox is usable but limited for kernel debugging.

### Required Tools

```powershell
# Sysinternals (download from learn.microsoft.com/en-us/sysinternals/)
# Install to C:\tools\sysinternals\:
#   procmon.exe, process explorer, winobj.exe, accesschk.exe, autoruns.exe, psexec.exe

# Debugging
winget install Microsoft.WinDbg          # WinDbg Preview
# x64dbg: https://x64dbg.com/

# Security Research
# System Informer: https://github.com/winsiderss/systeminformer/releases

# PowerShell modules
Install-Module NtObjectManager           # Forshaw's NT object toolkit
Install-Module PowerSploit               # Research use

# Reversing
# Ghidra: https://ghidra-sre.org/
# IDA Free: https://hex-rays.com/ida-free/
# BinDiff: https://github.com/google/bindiff/releases

# Build environment
# Visual Studio Community: https://visualstudio.microsoft.com/
# WDK: https://learn.microsoft.com/en-us/windows-hardware/drivers/download-the-wdk

# Research repositories (clone to C:\tools\)
git clone https://github.com/itm4n/PrivescCheck
git clone https://github.com/GhostPack/SharpUp       # build with VS
git clone https://github.com/GhostPack/Seatbelt       # build with VS
git clone https://github.com/hacksysteam/HackSysExtremeVulnerableDriver
git clone https://github.com/googleprojectzero/symboliclink-testing-tools
git clone https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools
```

### Safety Rules

1. **Isolation first.** Exploit code runs only in VMs with no network connection to production systems.
2. **Snapshot before every exercise.** Revert if something goes wrong.
3. **Never run unsigned binaries from unknown sources.** Always compile from reviewed source.
4. **Kernel labs:** Disable automatic restart on BSOD (`sysdm.cpl` → Advanced → Startup and Recovery → uncheck "Automatically restart") so you can read STOP codes.
5. **KDNET debugging:** Breaking in WinDbg pauses the entire debuggee VM — plan investigation steps before breaking.

---

## Lab Progression

```
Tier 1: Fundamentals        → WinDbg setup, ProcMon, token inspection
    ↓
Tier 2: Security Model      → Token manipulation, NtObjectManager, ACL analysis
    ↓
Tier 3: Bug Class Repro     → PrintSpoofer, service tracing, junction + oplock
    ↓
Tier 4: Kernel Exploitation → HEVD stack overflow, pool overflow, UAF
    ↓
Tier 5: Patch Diffing       → BinDiff workflow, root cause analysis
    ↓
Tier 6: Variant Hunting     → COM enumeration, PrivescCheck + custom follow-up
```

---

## Tier 1 — Fundamentals (Labs 1–5)

### Lab 1 — WinDbg Kernel Debugging Setup (KDNET)

**Objective:** Set up a kernel debugging pair (debugger VM ↔ debuggee VM) and perform basic kernel inspection.

**Prerequisites:** Two VMs, Hyper-V internal switch

**Setup steps:**
```
On debuggee VM (win10-debuggee):
1. Enable KDNET:
   bcdedit /dbgsettings net hostip:<debugger_ip> port:50000 key:1.2.3.4
   bcdedit /debug on
   Restart

On debugger VM (win10-debugger):
2. Open WinDbg Preview
3. File → Attach to Kernel → Net
4. Port: 50000, Key: 1.2.3.4
5. Wait for connection (may take 30-60 seconds after debuggee boot)
```

**Exercises:**
```windbg
; List all running processes
!process 0 0

; Dump EPROCESS for a specific process (use address from !process output)
dt nt!_EPROCESS <address>

; Find and dump the current process token
dt nt!_TOKEN poi(poi(@$prcb+0x8)+0x4b8)&~0xf)

; Browse the object namespace root
!object \

; Dump an object header
!object \Device\Null

; Check pool health
!poolused 2

; Inspect a handle in a target process
!handle 0 0xf <pid>
```

**Success criteria:** Can break in, list processes, dump EPROCESS, and browse the object namespace from WinDbg.

---

### Lab 2 — Time Travel Debugging (TTD) — Record and Replay a Crash

**Objective:** Record a process execution with TTD, cause an intentional exception, and replay to find the root cause.

**Setup:**
```
WinDbg Preview → File → Launch Executable (record)
→ Select target executable
→ Check "Record with Time Travel Debugging"
→ Run program → close or crash
→ TTD recording saved as .run file
```

**Exercises:**
```windbg
; After opening a .run file:

; Go to the beginning of the recording
!tt 0

; Step forward one instruction
p

; Go to a specific position (frame:instruction notation)
!tt 64:0

; Search backward for the last write to a register
!tt -b:r rip

; Find when a specific memory address was last written
ba w4 <address>
!tt -b:m <address>

; Travel to the point of an access violation
g                          ; run forward until the AV
!position               ; see current TTD position
!tt -                   ; go backward one position
```

**Success criteria:** Can record a process, cause an exception, and use TTD to travel backward to the instruction that caused the fault.

---

### Lab 3 — ProcMon Trace of a Service's File/Registry Operations

**Objective:** Trace all file and registry operations of the Windows Installer service during a repair operation. Identify write operations to paths the user can influence.

**Setup:**
- Clear ProcMon filter, add filter: `Process Name is msiexec.exe` + `Result is SUCCESS`
- Set ProcMon to capture File System and Registry events
- Start capture

**Exercise:**
```
1. Find any installed MSI-based application (check Add/Remove Programs)
2. Right-click → Repair (or run: msiexec /fa <ProductCode>)
3. Let repair run, then stop ProcMon capture
4. Filter for:
   - WriteFile operations to paths containing AppData or temp directories
   - RegSetValue to HKLM paths that are non-admin writable
   - CreateFile with OPEN_ALWAYS that creates new files
5. For each interesting write operation, check: is the parent directory writable by a low-privilege user?
```

**What to look for:** File operations to paths where the parent directory is writable — these are candidates for junction redirection. Registry writes to HKLM keys that may have weak ACLs.

**Success criteria:** Can interpret ProcMon output and identify at least one file/registry operation that could potentially be influenced by a low-privilege attacker.

---

### Lab 4 — WinObj — Exploring the NT Object Namespace

**Objective:** Browse the NT object namespace, understand its structure, and find objects with weak DACLs.

**Tools:** WinObj (Sysinternals), NtObjectManager PowerShell module

**Exercises:**

```powershell
# With NtObjectManager:
Import-Module NtObjectManager

# Browse the root namespace
ls NtObject:\

# List contents of important directories
ls NtObject:\Device
ls NtObject:\BaseNamedObjects
ls NtObject:\Sessions\1\BaseNamedObjects

# Check DACLs on a directory object
$dir = Get-NtDirectory \BaseNamedObjects
Get-NtSecurityDescriptor $dir | Format-List

# Find object directories writable by Everyone or low-privilege users
$dirs = Get-NtChildItem NtObject:\ -Recurse -Directory
foreach ($d in $dirs) {
    $sd = Get-NtSecurityDescriptor $d -ErrorAction SilentlyContinue
    if ($sd) {
        $dacl = $sd.Dacl
        # Check for World/Everyone write permissions
    }
}

# List all named pipes
ls NtObject:\Device\NamedPipe | ft Name, NtTypeName
```

**Success criteria:** Can enumerate the namespace, read security descriptors on objects, and identify any objects with overly permissive DACLs.

---

### Lab 5 — Token Analysis with System Informer and NtObjectManager

**Objective:** Inspect token details of multiple processes at different integrity levels, understand privilege differences.

**Exercises:**

```powershell
Import-Module NtObjectManager

# Get your current token
$token = Get-NtToken -Primary
$token | Format-List User, Groups, Privileges, IntegrityLevel, ImpersonationLevel

# Get a SYSTEM process token (if running as admin)
$proc = Get-NtProcess -Name "lsass.exe"
$token = Get-NtToken -Process $proc -Duplicate
$token | Format-List User, Privileges, IntegrityLevel

# Check all privileges
Get-NtToken | Select-Object -ExpandProperty Privileges | ft Name, Flags

# Find processes with SeImpersonatePrivilege
Get-NtProcess | Where-Object {
    $t = Get-NtToken -Process $_ -ErrorAction SilentlyContinue
    $t -and ($t.Privileges | Where-Object { $_.Name -eq "SeImpersonatePrivilege" -and $_.Flags -band 2 })
}
```

**In System Informer:**
- Double-click any process → Token tab
- Compare: a service process (SYSTEM), your cmd.exe (Medium), notepad.exe (Medium)
- Find a Low-integrity process (Edge/Chrome renderer)

**Success criteria:** Can read and interpret token details including integrity level, privilege list, and impersonation level for any process.

---

## Tier 2 — Security Model (Labs 6–8)

### Lab 6 — NtObjectManager: ACL Analysis and Weak Permission Discovery

**Objective:** Use NtObjectManager to systematically find objects with DACLs that allow low-privilege write.

**Exercise:**

```powershell
Import-Module NtObjectManager

# Check all services for binary path ACLs writable by standard user
Get-Service | ForEach-Object {
    $svc = $_
    $reg = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)" -ErrorAction SilentlyContinue
    if ($reg.ImagePath) {
        $path = $reg.ImagePath -replace '"', '' -split ' ' | Select-Object -First 1
        if (Test-Path $path) {
            $acl = Get-Acl $path -ErrorAction SilentlyContinue
            $acl.Access | Where-Object {
                $_.IdentityReference -match "Everyone|Users|Authenticated" -and
                $_.FileSystemRights -match "Write|Modify|FullControl"
            } | ForEach-Object {
                [PSCustomObject]@{Service=$svc.Name; Path=$path; Identity=$_.IdentityReference; Rights=$_.FileSystemRights}
            }
        }
    }
}
```

**Also run:** PrivescCheck in full mode:
```powershell
. C:\tools\PrivescCheck\PrivescCheck.ps1
Invoke-PrivescCheck -Extended
```

---

### Lab 7 — Impersonation Levels: Anonymous vs. Impersonation vs. Delegation

**Objective:** Observe the difference between impersonation levels using NtObjectManager.

**Exercise:**

```powershell
Import-Module NtObjectManager

# Create an impersonation token at each level
$base_token = Get-NtToken -Primary
$anon_token = $base_token.DuplicateToken([NtApiDotNet.SecurityImpersonationLevel]::Anonymous)
$imp_token = $base_token.DuplicateToken([NtApiDotNet.SecurityImpersonationLevel]::Impersonation)
$deleg_token = $base_token.DuplicateToken([NtApiDotNet.SecurityImpersonationLevel]::Delegation)

# Try to open a file using each impersonation token
# Then try to open a network resource (delegation only can authenticate remotely)

# Key point: SeImpersonatePrivilege allows impersonating a client via named pipe.
# Without it, you can only impersonate at Identification level.
```

---

### Lab 8 — Integrity Levels and UAC Bypass Test

**Objective:** Test the effect of integrity level restrictions on file and registry access.

**Exercise:**
1. Open two cmd.exe windows: one standard (Medium IL), one elevated (High IL)
2. Try to write to `C:\Windows\System32\` from Medium — expect ACCESS_DENIED
3. Try to write to `HKLM\SOFTWARE\` from Medium — expect ACCESS_DENIED
4. Confirm success from High
5. Use `icacls` and `accesschk` to verify the ACL differences:

```cmd
icacls C:\Windows\System32
accesschk.exe -d C:\Windows\System32
accesschk.exe -kd HKLM\SOFTWARE
```

6. Look at `HKCU\SOFTWARE` — writable from Medium. Understand why COM Object Hijacking uses HKCU writes.

---

## Tier 3 — Bug Class Reproduction (Labs 9–15)

### Lab 9 — Reproduce PrintSpoofer

**Objective:** Reproduce named pipe impersonation on Windows 10 (patched or unpatched — note which builds are vulnerable).

**Prerequisites:**
- A process running with SeImpersonatePrivilege (simulate by running as a service account, or use a MSSQL or IIS process if available)
- PrintSpoofer.exe compiled from https://github.com/itm4n/PrintSpoofer

**Steps:**
1. Confirm target has SeImpersonatePrivilege: `whoami /priv`
2. Run: `PrintSpoofer.exe -i -c cmd`
3. In the new cmd: `whoami` — should show `NT AUTHORITY\SYSTEM`

**Understanding the code:**
- Open `PrintSpoofer.cpp` in Visual Studio
- Find: `CreateNamedPipe(\\\\.\\pipe\\...\\pipe\\spoolss, ...)` — the crafted pipe name
- Find: `ImpersonateNamedPipeClient(hPipe)` — the impersonation call
- Find: `CreateProcessWithTokenW` — how the elevated process is spawned

**Success criteria:** Reproduce the privilege escalation AND understand each line of the PoC.

---

### Lab 10 — Junction + Oplock TOCTOU (BaitAndSwitch)

**Objective:** Implement the BaitAndSwitch pattern manually using Forshaw's tools.

**Tools:** `SetOpLock.exe`, `CreateJunction.exe` from symboliclink-testing-tools

**Exercise (conceptual demo):**

```
Scenario: Write a file to a path, then redirect it to a different destination

1. Create: C:\temp\targetdir\ (will be the "bait" directory)
2. Create: C:\temp\realdir\ (will be the actual destination after swap)
3. SetOpLock.exe on C:\temp\targetdir\ (batch oplock on directory)
4. In another window, do: type file.txt > C:\temp\targetdir\output.txt
   → This triggers the oplock, execution pauses

5. In the first window:
   → Remove C:\temp\targetdir\
   → CreateJunction.exe C:\temp\targetdir C:\temp\realdir

6. Release the oplock
7. The write continues → lands in C:\temp\realdir\output.txt instead
```

**Real research context:** Replace "your own file write" with a privileged service's write operation that you've identified via ProcMon.

---

### Lab 11 — Weak Service Permissions (Service Binary Path ACL)

**Objective:** Find a service binary with writable path, replace binary, trigger service restart → code execution as SYSTEM.

**On `win10-vuln` (older, potentially misconfigured):**

```cmd
:: Find services with writable binary paths
accesschk.exe -wuvc "Authenticated Users" * /accepteula
accesschk.exe -wuvc Everyone * /accepteula

:: OR use PrivescCheck
:: Look for "ModifiableServiceFiles" findings

:: Once found:
:: 1. Replace binary with a reverse shell or cmd payload
:: 2. Restart the service:
sc stop <ServiceName>
sc start <ServiceName>
:: OR reboot if service is auto-start
```

---

### Lab 12 — Named Pipe Enumeration and Squatting Research

**Objective:** Enumerate named pipes, check DACLs, identify pipes writable by low-privilege users.

```powershell
Import-Module NtObjectManager

# List all named pipes
$pipes = ls NtObject:\Device\NamedPipe
$pipes | ft Name

# Check DACLs on each pipe
foreach ($pipe in $pipes) {
    try {
        $sd = Get-NtSecurityDescriptor $pipe.FullPath -TypeName namedpipe
        $world_write = $sd.Dacl.Ace | Where-Object {
            $_.Sid.Name -match "World|Everyone|Users" -and
            $_.Mask -band 0x40000000  # GENERIC_WRITE
        }
        if ($world_write) {
            Write-Host "WRITABLE: $($pipe.FullPath)"
        }
    } catch {}
}
```

**Research value:** Find pipes where a low-privilege process could create a server-side handle before the legitimate privileged service — pipe squatting.

---

### Lab 13 — DLL Hijacking in a Windows Service

**Objective:** Find a service that loads a DLL from a writable directory.

```
1. Use ProcMon with filter: Operation=LoadImage AND Path=NOT_FOUND (missing DLL)
   → Filter: Process Name is the service process
   → Start the service (or trigger a function)
   → Note "NAME NOT FOUND" results for DLL loads

2. For each missing DLL, check if the search path includes a writable directory:
   - Application directory (if writable)
   - System PATH entries (check each for write permission)
   - Current directory (if service is in a writable dir)

3. Plant DLL with the missing name in the first writable directory in the search order
4. DLL payload: MessageBox or cmd.exe with the service's identity (SYSTEM)
```

---

## Tier 4 — Kernel Exploitation (Labs 16–20)

### Lab 16 — HEVD Setup and Stack Overflow

**Objective:** Set up HEVD and exploit the stack overflow vulnerability to get SYSTEM from user mode.

**Setup:**
```
On debuggee VM (KDNET configured):
1. Enable test signing: bcdedit /set testsigning on (reboot)
2. Copy HEVD.sys + OSRUSBFX2.sys to C:\Windows\System32\drivers\
3. Install driver:
   sc create HEVD type= kernel start= demand binpath= C:\Windows\System32\drivers\HEVD.sys
4. Verify: sc query HEVD (should show STOPPED; start with: sc start HEVD)
```

**Exploit the stack overflow (IOCTL 0x222003):**

```c
// User-mode exploit skeleton (C):
HANDLE hDevice = CreateFile("\\\\.\\HackSysExtremeVulnerableDriver", ...);

// Stack overflow: send a buffer larger than the kernel stack allocation
// Overflow past the return address
// Payload: token stealing shellcode

// Classic token stealing shellcode (x64 Windows 10):
// 1. Walk KPCR → CurrentThread → EPROCESS
// 2. Walk EPROCESS.ActiveProcessLinks to find System (PID 4)
// 3. Copy System.Token to CurrentProcess.Token
// 4. Return cleanly (restore stack, IRETQ)

char shellcode[] = {
    // mov rax, gs:[0x188]  ; current KTHREAD
    0x65, 0x48, 0x8B, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00,
    // ... token stealing shellcode
};
```

**WinDbg during exploit:**
```windbg
bp HEVD!TriggerStackOverflow
; When hit: inspect the stack, set up to trace the RIP control
; After shellcode: !process 0 0 to verify SYSTEM token on current process
```

---

### Lab 17 — HEVD Pool Overflow

**Objective:** Exploit the HEVD NonPagedPool overflow, demonstrating pool feng shui to achieve arbitrary write.

**Conceptual steps:**
1. Identify: overflow `N` bytes into adjacent pool allocation
2. Survey: which pool objects fit in the next slot AND provide a useful primitive if partially overwritten?
3. Spray: fill the pool with controllable allocations to achieve predictable layout
4. Overflow: corrupt the adjacent object's fields (e.g., function pointer, pointer in a linked list)
5. Trigger: cause the corrupted object to be used → control flow hijack or arbitrary write

**Key insight for Segment Heap (Windows 10 2004+):** The adjacent slot approach is harder — pool headers are separated from data. Focus on use-after-free scenarios or cross-cache attacks instead.

---

## Tier 5 — Patch Diffing (Labs 21–23)

### Lab 21 — Download and Diff a Patch Tuesday Advisory

**Objective:** Pick a recent Windows LPE advisory from MSRC, extract the patched binary, and BinDiff it against the previous version.

**Steps:**
```
1. Visit https://msrc.microsoft.com/update-guide/ → find a "Windows LPE" CVE
2. Note the affected DLL/EXE (often listed in the advisory or findable via security blogs)
3. Download the update MSU:
   - Use Windows Update Catalog: https://catalog.update.microsoft.com/
   - Extract: expand /F:* <msu file> . → expand /F:* <cab file> .
   - Find the patched DLL
4. Get the previous version from: https://winbindex.m417z.com/ (or a snapshot VM)
5. Open both in Ghidra or IDA
6. Run BinDiff: Tools → BinDiff → Diff databases
7. Navigate to "Low Similarity" function matches → the patched function
8. Read the diff: what check was added? What code path changed?
```

**Questions to answer:**
- What exact check was missing or incorrect in the vulnerable version?
- Is the fix a point fix (this one code path) or a systematic fix (the entire pattern)?
- Are there adjacent code paths that have the same root cause?

---

## Tier 6 — Variant Hunting (Labs 24–27)

### Lab 24 — COM Server Enumeration with NtObjectManager

**Objective:** Enumerate all COM servers registered to run as SYSTEM or elevated, identify ones accessible from low-privilege callers.

```powershell
Import-Module NtObjectManager

# Get all COM classes
$classes = Get-ComClassEntry -All

# Filter for classes that run in a privileged context
$elevated = $classes | Where-Object {
    $_.LocalServer -ne $null -and
    ($_.RunAs -eq "Interactive User" -or $_.RunAs -match "SYSTEM")
}

# For each elevated class, check the launch and access permissions
foreach ($cls in $elevated) {
    $sd = Get-ComSecurityDescriptor -ClassEntry $cls -SecurityType Launch -ErrorAction SilentlyContinue
    if ($sd) {
        $world = $sd.Dacl.Ace | Where-Object { $_.Sid.Name -match "Everyone|Users" }
        if ($world) {
            Write-Host "Accessible: $($cls.Name) [$($cls.Clsid)]"
        }
    }
}
```

**Research value:** A COM server that runs as SYSTEM and is activatable by low-privilege callers is a candidate for:
- COM impersonation abuse (if it calls back to the activating process's token)
- DCOM Potato variants (if it initiates network authentication during activation)

---

### Lab 25 — ProcMon-Based Attack Surface Mapping for a Target Service

**Objective:** Map the complete file/registry/pipe attack surface of a Windows service.

**Process:**
1. Start ProcMon with filter for the target service process name
2. Start + operate the service in all its normal modes (start, stop, configure, use its functionality)
3. Stop capture and analyze:
   - File: look for writes to paths with weak parent DACLs, reads from user-writable locations
   - Registry: look for reads from HKCU or HKLM with weak ACLs
   - Network: look for outbound authentication (potential coercion target)
   - Process: look for child process creation (DLL injection via process creation)
4. For each finding, assess: can a low-privilege attacker influence this path?

---

## Lab Documentation Template

For every completed lab, record:

```markdown
## Lab: [Name]
**Date:** YYYY-MM-DD
**VM:** win10-research / win10-vuln / etc.
**Time taken:** X hours

### What I Did
[Step-by-step notes, including dead ends]

### Key Observations
- [Observation 1]
- [Observation 2]

### What I Learned
[New concept or technique you understand now, in your own words]

### Questions Raised
[What does this lab make you want to investigate further?]

### Variants/Extensions
[Ideas for applying this technique to other targets]
```

---

## References

- [R-1] HEVD — HackSysTeam — https://github.com/hacksysteam/HackSysExtremeVulnerableDriver
- [R-2] symboliclink-testing-tools — Forshaw/PZ — https://github.com/googleprojectzero/symboliclink-testing-tools
- [R-3] sandbox-attacksurface-analysis-tools — Forshaw/PZ — https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools
- [R-4] PrivescCheck — itm4n — https://github.com/itm4n/PrivescCheck
- [R-5] PrintSpoofer — itm4n — https://github.com/itm4n/PrintSpoofer
- [R-6] WinDbg docs — Microsoft — https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/
- [R-7] MSRC Update Guide — Microsoft — https://msrc.microsoft.com/update-guide/
