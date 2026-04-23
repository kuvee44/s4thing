# Chapter 02 — Debugging and Observability

> **Scope:** WinDbg setup and essential commands, Time Travel Debugging (TTD), Process Monitor,
> ETW architecture with SilkETW, System Informer, and a complete LPE debugging workflow from
> symptom to root cause.
> **Target audience:** Security researcher actively doing kernel exploit development or
> vulnerability research on Windows.
> **Lab requirement:** Two-VM KDNET setup (target + debugger host), WinDbg Preview installed.

---

## 1. WinDbg Setup — Kernel Debugging via KDNET

### Why Two Machines (or Two VMs)?

Interactive kernel debugging requires an external debugger. When a breakpoint is hit, the target
machine halts completely — including its own WinDbg session if you tried to use one. Two-machine
setup (or two VMs on the same host) is the standard: the **target VM** runs the code under
investigation; the **debugger host** (usually your physical machine or a second VM) runs WinDbg
Preview and controls the session.

### Target VM Configuration

Run as Administrator on the target VM:

```cmd
:: Enable kernel debugging
bcdedit /debug on

:: Configure KDNET (network kernel debugging)
:: Replace <host_ip> with your debugger machine's IP
bcdedit /dbgsettings net hostip:<host_ip> port:50000 key:1.2.3.4

:: Verify settings
bcdedit /dbgsettings

:: Optional: disable automatic reboot on crash (capture the BSOD screen)
wmic recoveros set AutoReboot = False

:: Optional: configure full memory dump for crash analysis
wmic recoveros set DebugInfoType = 1
```

Reboot the target VM. During boot it will wait for the debugger to attach.

### Debugger Host — WinDbg Preview Connection

1. Install **WinDbg Preview** from the Microsoft Store (free).
2. Open WinDbg Preview → **File** → **Attach to kernel** → **Net** tab
3. Set Port: `50000`, Key: `1.2.3.4`
4. Click OK — WinDbg will break in as soon as the target boots.

### Symbol Configuration (critical — do this first)

```windbg
; Configure the Microsoft symbol server (do this every fresh WinDbg session)
.sympath srv*C:\Symbols*https://msdl.microsoft.com/download/symbols

; Force symbol reload
.reload /f

; Verify: should show nt symbols loaded
lm m nt
x nt!KiSystemCall64

; Add symbols for a locally built driver
.sympath+ C:\path\to\driver\symbols
.reload /f
```

**Symbol quality matters:** Without symbols, `k` (call stack) shows raw addresses. With symbols,
it shows readable function names. Always ensure `nt`, `ntdll`, and your target module have
symbols loaded before investigating a bug.

### Initial Verification Commands

```windbg
; After connecting — verify target OS
vertarget

; Check what's loaded
lm

; Break into the kernel manually (Ctrl+Break in WinDbg, or run this then g)
; List all processes
!process 0 0

; Dump kernel information
!pcr
version
```

### VM Snapshot Workflow for Exploit Development

1. Configure the target VM to a known clean state
2. Enable kernel debugging and connect WinDbg
3. **Take a VM snapshot** (this is your reset point)
4. Load your exploit or driver
5. When the VM crashes or you want to restart: revert to snapshot
6. Reconnect WinDbg (the connection re-establishes after reboot)

This loop — snapshot → exploit → crash → revert → iterate — is the standard kernel exploit
development workflow. Without snapshots, every BSOD costs 5 minutes of manual reset time.

---

## 2. Essential WinDbg Command Categories

### Setup and Configuration

```windbg
.sympath srv*C:\Symbols*https://msdl.microsoft.com/download/symbols
.reload /f                      ; force symbol reload
.load <ext.dll>                 ; load WinDbg extension by path
lm                              ; list loaded modules
lm m nt*                        ; filter module list by pattern
vertarget                       ; target OS version
version                         ; debugger version
```

### Execution Control

```windbg
g                               ; go (continue execution)
p                               ; step over (source line)
t                               ; step into (source line)
gu                              ; go up (step out of current function)
pa <addr>                       ; step to address (step over calls)
ta <addr>                       ; trace to address (step into calls)
wt                              ; watch and trace (shows call tree + instruction count)
.restart                        ; restart target
.detach                         ; detach from target
```

### Breakpoints

```windbg
bp <addr>                       ; software breakpoint at address
bp nt!NtCreateFile              ; breakpoint at named symbol
bu nt!NtCreateFile              ; unresolved (deferred) breakpoint — set before symbol loads
bm nt!Rtl*                      ; breakpoint matching wildcard pattern
bp /1 <addr>                    ; one-shot breakpoint (auto-removes after first hit)

; Hardware breakpoints (do not require code modification — essential for read-only code)
ba r4 <addr>                    ; read watchpoint on 4 bytes at addr
ba w4 <addr>                    ; write watchpoint on 4 bytes
ba e1 <addr>                    ; execute breakpoint (1 byte)

bl                              ; list all breakpoints
bc *                            ; clear all breakpoints
bd <n>                          ; disable breakpoint n
be <n>                          ; enable breakpoint n
```

### Registers and Stack

```windbg
r                               ; show all registers
r rax                           ; show specific register
r rip=<addr>                    ; set register to value
k                               ; call stack (compact)
kv                              ; call stack with parameters
kb                              ; call stack with params (verbose)
kn                              ; call stack with frame numbers
.frame <n>                      ; switch to stack frame n
dv                              ; local variables in current frame
```

### Memory Display

```windbg
dd <addr>                       ; display DWORDs (4-byte)
dq <addr>                       ; display QWORDs (8-byte)
dp <addr>                       ; display pointer-sized values
db <addr>                       ; display bytes (hex + ASCII)
dc <addr>                       ; display DWORDs + ASCII characters
du <addr>                       ; display Unicode string
da <addr>                       ; display ASCII string
dps <addr> L<n>                 ; display pointers with symbol names
dt nt!_EPROCESS <addr>          ; display typed structure
dt -r nt!_TOKEN <addr>          ; display structure recursively (expand sub-structs)
dt nt!_TOKEN <addr> Privileges  ; display only specific field
```

### Memory Search and Write

```windbg
s -d <start> L<len> <pattern>   ; search for DWORD value
s -b <start> L<len> <bytes>     ; search for byte sequence
s -u <start> L<len> "string"    ; search for Unicode string
s -a <start> L<len> "string"    ; search for ASCII string

ed <addr> <value>               ; write DWORD to address
eq <addr> <value>               ; write QWORD to address
eb <addr> <b1> [<b2> ...]       ; write individual bytes
```

### Process and Thread

```windbg
!process 0 0                    ; all processes (brief: PID, name, address)
!process 0 f                    ; all processes (full: threads, handles, etc.)
!process <addr> 7               ; specific process with all threads
.process /p <addr>              ; switch process context (enables reading its memory)
!thread                         ; current thread
!thread <addr> f                ; full thread info
.thread <addr>                  ; switch thread context
!peb                            ; process environment block
!teb                            ; thread environment block
!handle                         ; handles for current process
!handle 0 f                     ; all handles with full detail
```

### Token and Security

```windbg
!token                          ; current thread/process token
!token <addr>                   ; token at specific address
dt nt!_TOKEN <addr>             ; raw token structure dump
!acl <addr>                     ; display ACL entries
!sid <addr>                     ; display SID as string (e.g., S-1-5-18)
!sd <addr>                      ; display full security descriptor
```

### Pool and Heap

```windbg
!pool <addr>                    ; pool block info for this address
!poolused                       ; pool usage by tag (all pools)
!poolused 4 <tag>               ; pool used for specific tag, NonPagedPool
!poolfind <tag> 0               ; find all NonPagedPool blocks with tag
!poolfind <tag> 1               ; find all PagedPool blocks with tag
!heap                           ; heap information
!heap -a <heap_addr>            ; all heap allocations
```

### Object Manager and Kernel Analysis

```windbg
!object \                       ; root of object namespace
!object \Device                 ; device directory
!object \BaseNamedObjects       ; named objects directory
!objtype                        ; list all registered object types
!idt                            ; interrupt descriptor table
!gdt                            ; global descriptor table
!pcr                            ; processor control region (KPCR)
!irql                           ; current IRQL
!locks                          ; kernel locks held
!vm                             ; virtual memory statistics
!address <addr>                 ; memory region attributes
!vtop <pagedirbase> <addr>      ; virtual to physical address translation
```

---

## 3. Time Travel Debugging (TTD)

### What TTD Is and Why It Changes Everything

TTD records the complete execution trace of a process (user-mode) or the entire system
(kernel TTD). The recording captures every instruction executed, every memory read/write,
and every register state. After recording, you replay the trace in WinDbg and can navigate
**forward and backward** through execution — freely jumping to any point in time.

**The paradigm shift:** Traditional debugging requires you to reproduce the bug, predict where
to set a breakpoint, and catch the bug as it happens. With TTD:
1. Record the program until it crashes or misbehaves.
2. Open the trace — it replays deterministically from the recording.
3. Set a breakpoint at the crash location, run to it.
4. Step **backward** to find when the corruption occurred.
5. Use memory queries to find when any address was last written.

This is transformative for race conditions, use-after-free bugs, and heap corruption where the
crash site is far from the root cause.

### Recording — User Mode TTD

```cmd
:: Record a process from launch (WinDbg Preview must be installed)
:: Method 1: WinDbg Preview -> File -> Launch executable with TTD
:: Method 2: Command line
ttd.exe -out C:\traces\myapp.run myapp.exe [args]

:: Attach to a running process and record
ttd.exe -out C:\traces\myapp.run -attach <pid>

:: WinDbg command: start recording current process
.ttd record
```

After recording, TTD produces a `.run` file. Open it in WinDbg Preview:
- **File** → **Open trace file** → select `.run`
- WinDbg loads the trace and positions at the beginning of the recorded range.

### Recording — Kernel TTD

Kernel TTD requires either:
- Windows Insider Preview builds with the feature enabled, or
- Azure virtual machines with the kernel TTD feature flag set.

It captures the entire kernel execution, not just a single user-mode process. Far more powerful
but also far larger traces. Standard workflow for kernel security research uses user-mode TTD
against the user-mode component of a vulnerability, with traditional WinDbg for the kernel side.

### TTD Playback Commands

```windbg
; === FORWARD/BACKWARD NAVIGATION ===
g                               ; run forward (as normal)
g-                              ; run backward to previous breakpoint/event
p                               ; step over forward
p-                              ; step over backward
t                               ; step into forward
t-                              ; step into backward
gu                              ; step out (run to caller) forward
gu-                             ; step out backward

; === POSITION NAVIGATION ===
!tt 0                           ; jump to beginning of trace
!tt 100                         ; jump to end of trace
!tt 50                          ; jump to 50% through the trace
!tt A:B                         ; jump to specific position (sequence:steps format)

; === CURRENT POSITION ===
dx @$curposition                ; current TTD position (sequence and steps)
dx @$curposition.SeekTo()       ; navigate to this position (useful in scripts)

; === CALLS QUERY — find every call to a function ===
dx @$cursession.TTD.Calls("ntdll!NtCreateFile")
dx @$cursession.TTD.Calls("ntdll!NtCreateFile")[0]
dx @$cursession.TTD.Calls("ntdll!NtCreateFile")[0].@"TimeStart".SeekTo()

; === MEMORY QUERY — find when an address was written ===
; Find all writes to a 4-byte region at address 0x12345678
dx @$cursession.TTD.Memory(0x12345678, 0x1234567C, "w")

; Find all accesses (read or write)
dx @$cursession.TTD.Memory(0x12345678, 0x1234567C, "rw")

; Get the last write before current position
dx @$cursession.TTD.Memory(0x12345678, 0x1234567C, "w").Last()

; Navigate to the moment of that write
dx @$cursession.TTD.Memory(0x12345678, 0x1234567C, "w").Last().@"TimeStart".SeekTo()

; === SESSION OBJECT EXPLORATION ===
dx @$cursession.TTD                         ; TTD session root
dx @$cursession.TTD.Lifetime                ; full trace time range
dx @$cursession.TTD.Threads                 ; all threads in the trace
dx @$cursession.TTD.Modules                 ; all loaded modules during trace
```

### TTD Workflow for a Use-After-Free Bug

1. **Record:** Run the vulnerable program until it crashes (access violation on freed memory).
2. **Load trace:** WinDbg opens at the beginning.
3. **Navigate to crash:** `!tt 100` to end, then `g-` to run backward to the AV exception.
4. **Identify the freed memory address:** Note the crashing address (e.g., `0xdeadbeef12345678`).
5. **Find the free:** `dx @$cursession.TTD.Memory(addr, addr+8, "w")` — find all writes to this
   location; the UAF free will show up as a `HeapFree` or similar writing the free list pointer.
6. **Navigate to free time:** `.SeekTo()` on the last write.
7. **Walk the call stack:** `k` at that moment shows who freed the object.
8. **Find the stale reference:** Search forward for the read that uses the freed address.

### TTD Workflow for a Race Condition

1. **Record:** Run the vulnerable code multiple times until the race triggers.
2. **When the race causes a crash:** The trace captures both threads.
3. **Identify the racing address:** Note the address involved.
4. **Query all accesses:** `dx @$cursession.TTD.Memory(addr, addr+size, "rw")`
5. **Sort by time:** The query returns events sorted by sequence number.
6. **Find the interleaveing:** Two threads accessing without proper synchronization will appear
   as interleaved reads/writes at timestamps that are close but from different thread IDs.
7. **Navigate to each access:** `.SeekTo()` to inspect context.

---

## 4. Process Monitor — System Call Level Tracing

### What ProcMon Captures

Process Monitor (ProcMon) sits in the kernel via a minifilter driver and ETW, capturing:

| Event Category | What Is Recorded |
|----------------|-----------------|
| **File System** | Create/open/read/write/rename/delete on files and directories |
| **Registry** | Open/create/query/set/delete on registry keys and values |
| **Network** | TCP/UDP connect/send/receive/disconnect |
| **Process/Thread** | Process and thread create/exit, image loads |

Each event record includes: timestamp, process name + PID, operation name, path, result code
(STATUS_SUCCESS, NAME_NOT_FOUND, ACCESS_DENIED, etc.), and a detail string. Stack traces are
captured optionally (with performance impact).

### Reading ProcMon Output for Bug Hunting

The most important field is **Result** — the NTSTATUS code returned. Key result values:

| Result | Meaning for Bug Hunting |
|--------|------------------------|
| `NAME NOT FOUND` | File/registry path looked up but doesn't exist → DLL hijacking candidate |
| `PATH NOT FOUND` | Intermediate directory doesn't exist |
| `ACCESS DENIED` | Access was attempted and rejected by ACL |
| `SUCCESS` | Operation succeeded |
| `BUFFER OVERFLOW` | Buffer was too small (common in registry queries) |
| `NO MORE FILES` | Directory enumeration complete |

**Stack traces:** Enable via Options → Enable Stack Traces. Each event gets a full call stack,
allowing you to trace which code initiated the operation. Essential for understanding whether a
suspicious access comes from attacker-controlled code or a system component.

### ProcMon Filter Recipes

Filters are the core skill. Without effective filtering, ProcMon output is overwhelming — a
busy system generates thousands of events per second.

```
Filter syntax: Category | Operation | Condition | Value

; === DLL HIJACKING HUNT ===
; Find all DLL lookups that fail (potential hijack paths)
Process Name  is  <target.exe>        Include
Result        is  NAME NOT FOUND      Include
Path          ends with  .dll         Include

; === INSTALLER / REPAIR OPERATION RESEARCH ===
Process Name  is  msiexec.exe         Include
Operation     contains  Write         Include
Path          begins with  C:\Windows Include

; === NAMED PIPE MONITORING (for impersonation attack research) ===
Path          contains  \\.\pipe\     Include
Operation     contains  CreateFile    Include

; === REGISTRY LPE HUNT — AlwaysInstallElevated ===
Path          contains  HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer  Include

; === TOCTOU RESEARCH — temporary file access ===
Process Name  is  <service.exe>       Include
Operation     is  SetDispositionInformationFile   Include

; === FIND WORLD-WRITABLE SYSTEM PATHS ===
Process Name  is  <service.exe>       Include
Result        is  SUCCESS             Include
Path          begins with  C:\Windows Include
Operation     is  WriteFile           Include

; === SERVICE BINARY LOADING ===
Operation     is  Load Image          Include
Path          ends with  .dll         Include
Process Name  is  <service.exe>       Include
```

**ProcMon Boot Logging:** ProcMon can log events from system boot before the GUI loads.
Go to **Options** → **Enable Boot Logging** → reboot. On next startup, ProcMon captures from
the boot loader. Invaluable for startup-time vulnerabilities in services that run as SYSTEM
during initialization, before any user-mode monitoring tools are active.

### Correlating ProcMon With AccessChk

ProcMon tells you *what* was accessed; AccessChk tells you *whether it's vulnerable*:

```powershell
# ProcMon finds: notepad.exe -> CreateFile -> C:\ProgramData\Company\config.dll -> NAME NOT FOUND
# AccessChk: can a standard user write to C:\ProgramData\Company\ ?
accesschk.exe -d "C:\ProgramData\Company" -w
# If writable: plant config.dll there -> DLL hijacking LPE
```

---

## 5. ETW Architecture and SilkETW

### ETW Architecture Overview

Event Tracing for Windows (ETW) is the primary Windows telemetry infrastructure. Nearly every
security-relevant event has an ETW provider. ETW has three components:

```
Providers (event sources)
    |
    | events (structured binary blobs)
    ↓
Controller (session manager — logman.exe, xperf, custom code)
    |
    | creates/manages sessions, subscribes providers
    ↓
Session (ring buffer or direct file)
    |
    | events flow to consumers
    ↓
Consumer (SilkETW, EventLog, WPA, custom code)
    |
    | decode + analyze events
    ↓
Output (ETL file, JSON, EventLog, SIEM)
```

### ETW Providers Relevant to Security Research

| Provider Name | GUID | What It Logs |
|--------------|------|-------------|
| `Microsoft-Windows-Security-Auditing` | `54849625-5478-4994-A5BA-3E3B0328C30D` | Login events (4624, 4625), privilege use (4672), etc. |
| `Microsoft-Windows-Kernel-Process` | `22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716` | Process/thread create and exit |
| `Microsoft-Windows-Kernel-File` | `EDD08927-9CC4-4E65-B970-C2560FB5C521` | File system operations (create, read, write, delete) |
| `Microsoft-Windows-Kernel-Registry` | `70EB4F03-C1DE-4F73-A051-33D13D5413BD` | Registry operations |
| `Microsoft-Windows-Threat-Intelligence` | `F4E1897C-BB5D-5668-F1D8-040F4D8DD344` | Deep EDR telemetry (requires PPL process) |
| `Microsoft-Windows-RPC` | `6AD52B32-D609-4BE9-AE07-CE8DAE937E39` | RPC call tracing |
| `Microsoft-Windows-WinInet` | various | HTTP/HTTPS from WinInet (browser, Windows Update) |
| `Microsoft-Windows-LDAP-Client` | various | LDAP queries (domain enumeration detection) |

**Enumerating available providers:**

```cmd
:: List all providers on the system
logman query providers

:: List providers matching a pattern
logman query providers | findstr /i "kernel"

:: Get events for a specific provider
logman query providers "Microsoft-Windows-Kernel-Process"
```

### SilkETW Quick Start

SilkETW (Mandiant) wraps ETW consumption boilerplate and adds filtering, JSON output, and optional
YARA integration.

```cmd
:: Monitor kernel-mode process creation events, output to file
SilkETW.exe -t kernel -kk ImageLoad -ot file -p C:\output\imagelogs.json

:: Monitor user-mode process events (process/thread create)
SilkETW.exe -t user -pn Microsoft-Windows-Kernel-Process -ot file -p C:\output\proc.json

:: Monitor file operations
SilkETW.exe -t user -pn Microsoft-Windows-Kernel-File -ot file -p C:\output\files.json

:: Monitor registry operations  
SilkETW.exe -t user -pn Microsoft-Windows-Kernel-Registry -ot file -p C:\output\reg.json

:: Add YARA filtering (only log events matching YARA rule)
SilkETW.exe -t user -pn Microsoft-Windows-Kernel-Process -yrl C:\rules\suspicious.yar -ot file -p C:\output\filtered.json

:: Run as a persistent service (SilkService companion)
SilkService.exe
```

**JSON output format:** Each event is a JSON object with fields: provider name, event ID, opcode,
timestamp, process name, PID, TID, and provider-specific payload. Feed into `jq`, ElasticSearch,
or custom analysis scripts.

```bash
# Parse SilkETW output with jq — find all new process creations
cat proc.json | jq 'select(.EventId == 1) | {time: .Timestamp, name: .EventData.ImageName, pid: .EventData.ProcessId}'
```

### ETW as an Attack Surface — EDR Evasion Context

ETW is the telemetry backbone for most EDR products. Knowing what each provider captures informs
both detection engineering and evasion research:

- **ETW patching:** Malware patches `ntdll!EtwEventWrite` to return early, suppressing all ETW
  events from that process. This blinds EDRs relying on ETW for user-mode telemetry.
- **Provider disable:** An admin-level process can disable specific ETW sessions, degrading
  monitoring.
- **Microsoft-Windows-Threat-Intelligence provider:** Requires a PPL-level process to consume.
  This is how Windows Defender (MsMpEng.exe, a PPL) gets deep telemetry that normal EDR agents
  cannot access.

Understanding these mechanisms helps both attackers (evasion) and defenders (detection hardening).

---

## 6. System Informer for Live Token and Handle Inspection

System Informer (formerly Process Hacker 2, now maintained by Winsider Seminars) provides GUI
access to kernel data structures at a depth that no other non-debugger tool matches.

### Token Analysis Workflow

**Right-click any process → Properties → Token tab** shows:
- **User SID** and account name
- **Integrity level** (e.g., `Medium Mandatory Level`)
- **Impersonation level** (if thread is impersonating: Anonymous/Identification/Impersonation/Delegation)
- **Privileges list:** Each privilege with state — Enabled, Disabled, or Removed
- **Groups:** All SIDs in the token's groups array, including:
  - Standard groups (Administrators, Users, etc.)
  - Logon SID (S-1-5-5-X-Y)
  - Integrity level SID (S-1-16-8192 for Medium)
  - Capability SIDs (S-1-15-3-X for AppContainer)
- **Default DACL:** Security descriptor applied to objects created by this token

**Verification use case — exploit verification:**
After a kernel exploit that manipulates a process token, System Informer lets you visually confirm
that the targeted process now shows `SYSTEM` as the user and the integrity level has changed to
`System Mandatory Level`. No WinDbg commands needed for the sanity check.

### Handle Analysis Workflow

**Process → Handles tab** (or **View → System Handles** for all handles system-wide):

Columns: Handle value (hex), Type (Process, File, Section, Mutant, Event, etc.), Object address
(kernel VA), Granted Access (hex bitmask), Name (if named object).

**Filter techniques:**
- Filter by type `Section` to find memory-mapped file handles (potential section object attacks)
- Filter by type `Process` to find opened process handles (potential handle leak / stolen handle)
- Filter by type `File` with name ending in `.exe` or `.dll` to find open executable files
- Filter by name containing `\BaseNamedObjects` for named IPC objects

### Impersonation Check

**Select a thread → right-click → Inspect token:**
Shows the thread-level token (impersonation token), including the impersonation level. A thread
with impersonation level `Impersonation` or `Delegation` is actively impersonating another user.

**Research use case — Potato attack verification:** After running PrintSpoofer or a Potato variant,
check the target service's thread tokens. One thread should show impersonation level `Impersonation`
with the SYSTEM token — confirming the impersonation step succeeded before `CreateProcessWithToken`
is called.

### Memory Analysis

**Process → Properties → Memory tab** shows all virtual memory regions with:
- Base address, size, type (Image/Mapped/Private)
- Protection (PAGE_EXECUTE_READ, PAGE_READWRITE, etc.)
- Mapped file name (for image/file mappings)
- Commit state

**Research use case:** After a pool or heap spray, verify the spray succeeded by checking for
large contiguous regions of a specific protection in the target process. Correlate with WinDbg
`!address` and `!vad` output for cross-verification.

---

## 7. Debugging Workflow — From LPE Symptom to Root Cause

This section walks through a realistic debugging workflow for an LPE (Local Privilege Escalation)
primitive. The specific bug is generic — the workflow pattern is transferable.

### Scenario: "A service crashes when we send a malformed IOCTL"

**Goal:** Determine whether the crash is exploitable, identify the root cause, and develop a
controlled exploit primitive.

---

### Step 1 — Capture the Crash

Set up WinDbg kernel debugging (KDNET). In WinDbg, configure automatic crash analysis:

```windbg
; Configure first-chance exception handling
sxe av                          ; break on access violation
sxe bpe                         ; break on breakpoint

; Run and wait for the crash
g
```

Send the malformed IOCTL from user mode. The target service crashes. WinDbg breaks.

---

### Step 2 — Analyze the Crash Context

```windbg
; Where did we crash?
k                               ; call stack at crash site
r                               ; registers (note RIP, RSP, RAX, RCX)
!analyze -v                     ; automated crash analysis (read this carefully)

; What kind of crash?
; EXCEPTION_CODE: 0xC0000005 = MEMORY_ACCESS_VIOLATION
; READ_ADDRESS / WRITE_ADDRESS in !analyze output tells you direction

; Is it a null deref, heap corruption, or stack overflow?
!address <crashing_addr>        ; what memory region is this?
```

Output: the crash is at `driver!FooDispatchIoctl+0x1a8`, access violation writing to address
`0xffffffff00000000`. The crashing address is in non-canonical form — likely a corrupted pointer.

---

### Step 3 — Identify the Vulnerable Code Path

```windbg
; Get the full call stack
kv

; Disassemble around the crash site
ub <crash_rip>                  ; instructions before crash
u <crash_rip>                   ; instructions at/after crash

; What was the operation?
; Example: mov [rcx+0x18], rax  <- write to RCX+0x18
; RCX = corrupted pool object pointer
r rcx                           ; show the corrupted pointer value
```

The write target comes from a pool-allocated structure. The IRP's user input was used without
validation to compute an offset into a kernel pool object.

---

### Step 4 — Trace the Input to the Corruption

```windbg
; Find the IOCTL handler dispatch
u driver!FooDispatchIoctl

; Where does user input enter?
; Look for: MmProbeForRead, ProbeForRead, or direct access to Irp->AssociatedIrp.SystemBuffer
; Or: Parameters.DeviceIoControl.Type3InputBuffer (for METHOD_NEITHER — user VA directly)

; Set a breakpoint at the top of the IOCTL handler
bp driver!FooDispatchIoctl

; Re-run and inspect input at the breakpoint
g
; When it breaks:
r                               ; register state
dq rsp L8                       ; first 8 stack slots
dt nt!_IRP @rcx                 ; IRP structure (if rcx = Irp)
```

---

### Step 5 — Use TTD for Precise Root Cause Analysis

For deterministic root cause analysis, switch to TTD:

```cmd
:: Record the service process (or use WinDbg Preview -> Record -> attach to service)
ttd.exe -out C:\traces\service.run -attach <service_pid>
```

Then send the malformed IOCTL. After the crash, the trace captures everything.

```windbg
; Load the trace
; File -> Open trace file -> service.run

; Navigate to end (the crash)
!tt 100

; Run backward to the crash
g-

; When at the crash: find the corrupted pointer's last valid write
dx @$cursession.TTD.Memory(0xffffffff00000000 & ~0xfff, (0xffffffff00000000 & ~0xfff)+0x1000, "w")
; This will show the pool allocation that was corrupted

; Get the time of the last legitimate write
dx @$cursession.TTD.Memory(<pool_obj_addr>, <pool_obj_addr>+8, "w").Last()
dx @$cursession.TTD.Memory(<pool_obj_addr>, <pool_obj_addr>+8, "w").Last().@"TimeStart".SeekTo()

; Now we are at the moment just before the UAF/overflow
k                               ; who wrote to this location?
```

---

### Step 6 — Assess Exploitability

With root cause identified:

1. **Type of primitive:** Out-of-bounds write? Use-after-free? Integer overflow leading to OOB?
2. **Control over write value:** Can we control the value written? If yes — arbitrary write.
3. **Control over write target:** Can we control the destination? If yes — write-what-where.
4. **Adjacent allocation:** What lives adjacent in the pool? Pool spraying can place a controlled
   object (e.g., a fake `OBJECT_TYPE` with a poisoned function pointer table).

```windbg
; Inspect the pool region around the vulnerable allocation
!pool <vulnerable_alloc_addr>

; Find what's adjacent
!pool <vulnerable_alloc_addr + block_size>

; Look at pool header info
dt nt!_POOL_HEADER <pool_header_addr>
```

---

### Step 7 — Verify Token Manipulation Success

For a token-stealing exploit:

```windbg
; Before exploit: note the process token
!process 0 0 target_service.exe
!token (poi(<eprocess>+0x4b8) & ~0xf)
; Note: User SID, Integrity Level

; Run the exploit

; After exploit: re-check the token
!process 0 0 target_service.exe
!token (poi(<eprocess>+0x4b8) & ~0xf)
; Should now show: User = SYSTEM, IL = System
```

Simultaneously in System Informer: verify the target process now shows as running as SYSTEM with
System integrity level.

---

## 8. WinDbg Extensions for Security Research

### Mex Extension

Mex is a Microsoft-internal productivity extension made public. Install and explore:

```windbg
.load mex.dll
!mex.help                       ; list all available commands
!mex.crash                      ; automated crash analysis (often better than !analyze)
!mex.p                          ; process summary
!mex.t                          ; thread summary
!mex.us                         ; unique stacks (deduplicate thread stacks)
```

### DbgKit Extension

DbgKit provides structured views of kernel objects:

```windbg
.load dbgkit.dll
!dbgkit.process <addr>          ; process object with formatted fields
!dbgkit.thread <addr>           ; thread with security context
!dbgkit.token <addr>            ; token with privilege and group breakdown
```

### SwishDbgExt

Additional memory forensics commands:

```windbg
.load SwishDbgExt.dll
!ms_process                     ; process list with security context
!ms_drivers                     ; loaded drivers with verification status
!ms_checkcodecave               ; find code caves in loaded modules
```

---

## References

[R-1] WinDbg Official Documentation — https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/

[R-2] Time Travel Debugging (TTD) Overview — https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/time-travel-debugging-overview

[R-3] System Informer (source + releases) — https://github.com/winsiderss/systeminformer

[R-4] SilkETW (Mandiant ETW consumer framework) — https://github.com/mandiant/SilkETW

[R-5] Process Monitor Documentation — https://learn.microsoft.com/en-us/sysinternals/downloads/procmon

[R-6] Event Tracing for Windows (ETW) Portal — https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-portal
