# Debugging & Observability — Quick Reference

> Section 02: WinDbg, TTD, ProcMon, ETW, system analysis tools

## Summary

This section covers the complete debugging and observability toolkit for Windows security research — from primary kernel debugging (WinDbg) through system-level monitoring (ProcMon, ETW) and deep analysis tools (System Informer, pe-sieve).

## Entry Count

| Category | Count |
|---|---|
| Primary Debugging Tools | 5 |
| Kernel Debugging Infrastructure | 2 |
| WinDbg Extensions | 4 |
| System Monitoring & Telemetry | 3 |
| **Total** | **15** (+ 1 ProcMon Boot Logging sub-feature) |

## Tool Priority Matrix

| Tool | When to Use | Priority |
|---|---|---|
| WinDbg Preview | All kernel debugging, crash analysis | MUST-HAVE |
| TTD | Race conditions, UAF, heap corruption replay | MUST-HAVE |
| ProcMon | Dynamic analysis, DLL hijacking hunt, installer research | MUST-HAVE |
| System Informer | Token/handle/impersonation verification during research | MUST-HAVE |
| Process Explorer | Quick token/integrity level checks | HIGH |
| SilkETW | ETW-based behavioral analysis | HIGH |
| ETW | Detection engineering, behavioral telemetry | HIGH |
| LiveKD | Quick kernel analysis without full debug setup | MEDIUM |
| Mex Extension | WinDbg productivity | HIGH |
| DbgKit | Kernel object visualization in WinDbg | HIGH |
| SwishDbgExt | Additional WinDbg commands | MEDIUM |

## Initial Lab Setup Checklist

- [ ] Install WinDbg Preview (Microsoft Store)
- [ ] Configure Microsoft Symbol Server in WinDbg
- [ ] Set up two-VM kernel debugging (KDNET on target VM)
- [ ] Install System Informer on research VMs
- [ ] Install Sysinternals Suite (ProcMon, Process Explorer, AccessChk, Autoruns)
- [ ] Download Mex extension and configure WinDbg to load it
- [ ] Clone SilkETW for ETW research

> See NOTES.md for WinDbg command cheatsheet and debugging workflow notes.
> See RESOURCES.md for full entry details.
