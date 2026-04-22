# Debugging & Observability — Notes & WinDbg Cheatsheet

## WinDbg Command Cheatsheet

### Setup & Configuration
```
.sympath srv*C:\Symbols*https://msdl.microsoft.com/download/symbols
.reload /f                          — Force symbol reload
.load <ext.dll>                     — Load extension DLL
!load <ext>                         — Load extension (alternative)
lm                                  — List loaded modules
lm m nt*                            — List modules starting with nt
vertarget                           — Target OS version info
version                             — Debugger version
```

### Execution Control
```
g                                   — Go (continue)
p                                   — Step over (source line)
t                                   — Step into (source line)
pa <addr>                           — Step to address
ta <addr>                           — Trace to address
gu                                  — Go up (step out of function)
wt                                  — Watch and trace (call count)
.restart                            — Restart target
.detach                             — Detach from target
```

### Breakpoints
```
bp <addr>                           — Software breakpoint at address
bp <module>!<function>              — Breakpoint at named function
bu <module>!<function>              — Unresolved (deferred) breakpoint
bm nt!Rtl*                          — Breakpoint matching pattern
ba r4 <addr>                        — Hardware read watchpoint (4 bytes)
ba w4 <addr>                        — Hardware write watchpoint (4 bytes)
ba e1 <addr>                        — Hardware execute breakpoint (1 byte)
bl                                  — List breakpoints
bc *                                — Clear all breakpoints
be <n>                              — Enable breakpoint n
bd <n>                              — Disable breakpoint n
bp /1 <addr>                        — One-shot breakpoint
```

### Registers & Stack
```
r                                   — Show all registers
r rax                               — Show specific register
r rip=<addr>                        — Set register value
k                                   — Call stack
kv                                  — Call stack with parameters
kb                                  — Call stack with params (verbose)
kn                                  — Call stack with frame numbers
.frame <n>                          — Switch to stack frame n
dv                                  — Local variables in current frame
```

### Memory Display
```
dd <addr>                           — Display DWORDs (4-byte)
dq <addr>                           — Display QWORDs (8-byte)
dp <addr>                           — Display pointer-sized
db <addr>                           — Display bytes (hex + ASCII)
dc <addr>                           — Display DWORDs + ASCII
du <addr>                           — Display Unicode string
da <addr>                           — Display ASCII string
dps <addr> L<n>                     — Display pointers with symbols
dt <type> <addr>                    — Display type structure
dt nt!_EPROCESS <addr>              — Display EPROCESS at address
dt -r nt!_TOKEN <addr>              — Display TOKEN recursively
```

### Memory Search
```
s -d <start> L<len> <pattern>       — Search for DWORD pattern
s -b <start> L<len> <bytes>         — Search for byte pattern
s -u <start> L<len> "string"        — Search for Unicode string
```

### Memory Write
```
ed <addr> <value>                   — Write DWORD to address
eq <addr> <value>                   — Write QWORD to address
eb <addr> <byte> [<byte>...]        — Write bytes
```

### Process & Thread
```
!process 0 0                        — All processes (brief)
!process 0 f                        — All processes (full)
!process <addr> 7                   — Process + threads
.process /p <addr>                  — Switch process context
!thread                             — Current thread
!thread <addr> f                    — Full thread info
.thread <addr>                      — Switch thread context
!handle                             — Handles for current process
!handle 0 f                         — All handles (full)
!peb                                — Process environment block
!teb                                — Thread environment block
```

### Token & Security
```
!token                              — Current thread/process token
!token <addr>                       — Token at address
dt nt!_TOKEN <addr>                 — Token structure
!acl <addr>                         — Display ACL
!sid <addr>                         — Display SID
!sd <addr>                          — Display security descriptor
```

### Pool & Heap
```
!pool <addr>                        — Pool block info
!poolused                           — Pool usage by tag
!poolused 4 <tag>                   — Pool used for tag (Nonpaged)
!poolfind <tag> 0                   — Find all pool blocks with tag
!heap                               — Heap info
!heap -a <heap>                     — All heap allocations
```

### Object Manager
```
!object \                           — Root of object namespace
!object \Device                     — Device directory
!object \BaseNamedObjects           — Named objects
!objtype                            — List object types
dt nt!_OBJECT_HEADER <addr>         — Object header structure
dt nt!_OBJECT_TYPE <addr>           — Object type structure
```

### Kernel Analysis
```
!idt                                — Interrupt descriptor table
!gdt                                — Global descriptor table
!pcr                                — Processor control region (KPCR)
!prcb                               — Processor control block
!irql                               — Current IRQL
!locks                              — Kernel locks held
!vm                                 — Virtual memory stats
!address <addr>                     — Memory region info
!vtop <pagedirbase> <addr>          — Virtual to physical translation
```

---

## TTD (Time Travel Debugging) Commands

```
g-                                  — Run backward
t-                                  — Step backward (into)
p-                                  — Step backward (over)
gu-                                 — Go up backward

!tt <position>                      — Jump to TTD position
!tt 0                               — Jump to start of trace
!tt 100                             — Jump to end of trace

dx @$curposition                    — Current TTD position
dx @$cursession.TTD                 — TTD session object

; Find when memory address was written:
dx @$cursession.TTD.Memory(0xAddr, 0xAddr+4, "w")

; Find all calls to a function:
dx @$cursession.TTD.Calls("nt!NtCreateFile")

; Navigate to specific call:
dx @$cursession.TTD.Calls("nt!NtCreateFile")[0].@"TimeStart".SeekTo()
```

---

## KDNET Setup (Quick Reference)

On the **target VM** (run as Administrator):
```cmd
bcdedit /debug on
bcdedit /dbgsettings net hostip:<debugger_host_ip> port:50000 key:1.2.3.4
```

On the **debugger host** (WinDbg Preview):
- File → Connect to remote debugger
- Target type: Network
- Port: 50000
- Key: 1.2.3.4

After VM reboot, WinDbg should connect automatically.

**Verify**: In WinDbg, press Ctrl+Break → type `vertarget` → should show target OS version.

---

## ProcMon Filter Recipes

### DLL Hijacking Hunt
```
Process Name | is | <target.exe>
AND Result | is | NAME NOT FOUND
AND Path | ends with | .dll
```

### Installer File Operations
```
Process Name | is | msiexec.exe
AND Operation | contains | Write
AND Path | contains | C:\Windows\Temp
```

### Named Pipe Monitoring
```
Path | contains | \\.\pipe\
AND Operation | contains | CreateFile
```

### Registry LPE Hunt (AlwaysInstallElevated)
```
Path | contains | HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer
AND Operation | is | RegQueryValue
```

---

## ETW Security-Relevant Providers

| Provider Name | GUID | What It Logs |
|---|---|---|
| Microsoft-Windows-Security-Auditing | 54849625-5478-4994-A5BA-3E3B0328C30D | Security events (4624, 4625, etc.) |
| Microsoft-Windows-Kernel-Process | 22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716 | Process/thread create/exit |
| Microsoft-Windows-Kernel-File | EDD08927-9CC4-4E65-B970-C2560FB5C521 | File operations |
| Microsoft-Windows-Kernel-Registry | 70EB4F03-C1DE-4F73-A051-33D13D5413BD | Registry operations |
| Microsoft-Windows-Threat-Intelligence | F4E1897C-BB5D-5668-F1D8-040F4D8DD344 | EDR telemetry (requires PPL) |
| Microsoft-Windows-RPC | 6AD52B32-D609-4BE9-AE07-CE8DAE937E39 | RPC calls |

### SilkETW Quick Start
```cmd
SilkETW.exe -t kernel -kk ImageLoad -ot file -p C:\output\imagelogs.json
SilkETW.exe -t user -pn Microsoft-Windows-Kernel-Process -ot file -p C:\output\proc.json
```

---

## System Informer Quick Reference

### Token Analysis
- Right-click process → Properties → Token tab
- Shows: Integrity level, privileges (enabled/disabled/removed), groups, capabilities

### Handle Analysis
- View → System Handles (or select process → Handles tab)
- Filter by type: File, Section, Mutant, Event, Semaphore, Port

### Impersonation Check
- Select thread → Inspect token
- Shows: impersonation level (None/Anonymous/Identification/Impersonation/Delegation)

### Memory Analysis
- Right-click process → Properties → Memory tab
- Shows: all virtual regions, protection, type, mapped file name
