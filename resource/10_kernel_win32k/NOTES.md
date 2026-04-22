# Kernel & Win32k — Research Notes

## WinDbg Kernel Command Reference

### Basic Navigation
```
g                       — Go (continue execution)
p                       — Step over
t                       — Step into
gu                      — Go up (step out)
.reload /f              — Force symbol reload
lm                      — List loaded modules
lm m nt                 — Show nt (kernel) module
```

### Process and Thread Analysis
```
!process 0 0            — List all processes (brief)
!process 0 f            — List all processes (full)
!process <addr> 7       — Process with threads
.process /p <addr>      — Switch to process context
!thread                 — Current thread
!thread <addr> f        — Full thread details
```

### Token and Security
```
!token                  — Current process token
!token <addr>           — Specific token details
dt nt!_TOKEN <addr>     — Token structure
dt nt!_SEP_TOKEN_PRIVILEGES <addr> — Privilege bits
!acl <addr>             — Display ACL
```

### Memory Analysis
```
dd <addr>               — Display DWORDs
dq <addr>               — Display QWORDs
dp <addr>               — Display pointer-sized
db <addr>               — Display bytes
du <addr>               — Display Unicode string
da <addr>               — Display ASCII string
r                       — Registers
k                       — Call stack
kv                      — Call stack with params
kb                      — Call stack with params (verbose)
```

### Pool Analysis
```
!pool <addr>            — Pool block at address
!poolused               — Pool usage by tag
!poolfind <tag>         — Find pool blocks by tag
dt nt!_POOL_HEADER <addr>  — Pool header structure
```

### Object Manager
```
!object \               — Object directory root
!object \Device         — Device objects
!handle                 — Handle table for current process
!handle 0 f             — All handles (full)
dt nt!_OBJECT_HEADER <addr> — Object header
```

### Breakpoints
```
bp <addr>               — Software breakpoint
ba r4 <addr>            — Hardware read watchpoint (4 bytes)
ba w4 <addr>            — Hardware write watchpoint (4 bytes)
bl                      — List breakpoints
bc *                    — Clear all breakpoints
be <n>                  — Enable breakpoint
bd <n>                  — Disable breakpoint
```

### Kernel Structures (EPROCESS/KPROCESS)
```
dt nt!_EPROCESS <addr>
dt nt!_KPROCESS <addr>
dt nt!_ETHREAD <addr>
dt nt!_KTHREAD <addr>
!drvobj <addr>          — Driver object
!devobj <addr>          — Device object
```

---

## Win32k Key Facts

- Win32k.sys handles the entire Windows windowing system (USER objects, GDI) in kernel mode
- Attack surface: enormous (~1800+ syscalls)
- Historically the #1 most exploited kernel component
- Win32k lockdown: sandboxed processes can be restricted from calling Win32k syscalls
- KEY OBJECTS: WNDOBJ, DCOBJ (device context), SURFOBJ (surface), PDEVOBJ, REGION objects
- Desktop heap: shared memory between user mode and kernel mode — proximity to kernel data
- Session space: separate virtual address range per interactive session

## Pool Exploitation Notes (Windows 10+)

### Pre-Segment-Heap (< Win10 2004)
- Pool chunks have explicit POOL_HEADER structures
- Corruption of POOL_HEADER → kernel write primitive
- FreeLists and lookaside lists can be manipulated

### Post-Segment-Heap (>= Win10 2004)
- Segment heap replaced pool for NonPaged allocations
- POOL_HEADER corruption no longer directly gives a write primitive
- New techniques required: I/O Ring abuse, spraying controlled structures
- Key reference: "One I/O Ring to Rule Them All" (Yarden Shafir)

## KASLR Implementation Notes

- Kernel base randomized at boot: ~256 possible locations (9 bits entropy) on some versions
- Information leaks defeat KASLR: NtQuerySystemInformation (patched), GDI tricks (patched), uninitialized memory (Bochspwn class)
- Modern bypass requires a separate information disclosure vulnerability
- Kernel pointer encoding: ObHeaderCookie XORs object header pointers (partial protection)
- KASLR entropy has been incrementally improved across Windows versions

## Token Stealing Shellcode Structure

```asm
; Standard token stealing shellcode (x64)
; 1. Get current thread KPCR
; 2. Navigate KPCR → KPRCB → CurrentThread → EPROCESS
; 3. Walk EPROCESS.ActiveProcessLinks list
; 4. Find SYSTEM process (UniqueProcessId == 4)
; 5. Copy SYSTEM token to current process
; 6. Return cleanly (restore stack, iretq or ret depending on entry point)
```

Key EPROCESS offsets (Windows 10 x64 — verify with symbols for specific build):
- `UniqueProcessId`: +0x440
- `ActiveProcessLinks`: +0x448
- `Token`: +0x4b8

Always verify offsets with: `dt nt!_EPROCESS` in WinDbg for target build.
