# 07 — Services, Installers & Updaters

Attack surface, internals, and LPE techniques for Windows background services,
the Windows Installer subsystem, update mechanisms, and scheduled tasks.

## Files

| File | Contents |
|------|---------|
| `RESOURCES.md` | Full reference — internals, techniques, tools, CVEs |
| `NOTES.md` | Enumeration methodology, exploitation workflows, key internals facts |
| `README.md` | This file |

## Sections in RESOURCES.md

1. Windows Services Internals — SCM, service types, account privileges
2. Service Configuration Weaknesses — unquoted paths, binary ACLs, registry ACLs, DLL hijacking
3. Windows Installer (MSI) — architecture, InstallerFileTakeOver, AlwaysInstallElevated, custom actions
4. Task Scheduler — SandboxEscaper CVEs, general attack surface
5. Windows Update & Background Services — BITS, Delivery Optimization, DiagTrack, WER
6. Print Spooler — PrintNightmare, PrintSpoofer
7. WMI Subscriptions — persistence technique

## Quick Attack Decision Tree

```
Executing as service account?
├── SeImpersonatePrivilege? → PrintSpoofer / GodPotato → SYSTEM
├── SeAssignPrimaryTokenPrivilege? → CreateProcessAsUser → SYSTEM
└── Neither?
    ├── Writable service binary path? → Replace binary → SYSTEM on restart
    ├── Unquoted service path + writable dir? → Plant binary → SYSTEM on restart
    ├── Writable DLL in service search path? → DLL hijack → SYSTEM on restart
    └── AlwaysInstallElevated? → Malicious MSI → SYSTEM
```

## Cross-References

- CVE details: `../13_cve_case_studies/RESOURCES.md`
- Token impersonation: `../03_token_impersonation/` (if exists)
- File operation primitives: `../01_file_operations/` (if exists)
- Tools: `../11_tools_and_frameworks/`
