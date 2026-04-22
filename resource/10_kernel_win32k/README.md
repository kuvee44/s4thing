# Kernel & Win32k — Quick Reference

> Section 10: Kernel architecture, Win32k, driver research, pool internals, kernel exploitation

## Summary

This section covers foundational and advanced resources for Windows kernel security research, from architectural references through hands-on exploitation practice and cutting-edge Windows 11 research.

## Entry Count

| Category | Count |
|---|---|
| Foundational References | 4 |
| Kernel Exploitation Techniques | 7 |
| Kernel Infrastructure | 4 |
| **Total** | **15** |

## Learning Path

```
Windows Internals Part 1 & 2 (theory)
         ↓
HEVD setup + WinDbg kernel debugging environment
         ↓
Work through HEVD vulnerability classes
         ↓
Bochspwn Reloaded (systematic research methodology)
         ↓
Win32k research (j00ru + CVE-2021-1732)
         ↓
Modern primitives (I/O Ring, pool exploitation on Win11)
         ↓
KASLR bypass survey
         ↓
Mitigations (PatchGuard, HVCI, VBS/SecKernel)
```

## Key Structures to Know in WinDbg

```
dt nt!_EPROCESS         — Process object
dt nt!_TOKEN            — Token structure
dt nt!_KTHREAD          — Thread/impersonation state
dt nt!_OBJECT_HEADER    — Object manager header
dt nt!_POOL_HEADER      — Pool chunk header (pre-segment-heap)
!token                  — Display current process token
!process 0 0            — All processes
!pool <addr>            — Pool chunk analysis
```

> See NOTES.md for extended WinDbg commands and kernel research notes.
> See RESOURCES.md for full entry details.
