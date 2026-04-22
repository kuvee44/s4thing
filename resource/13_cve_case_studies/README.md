# 13 — CVE Case Studies

High-value Windows LPE CVE case studies organized by vulnerability class.

## Files

| File | Contents |
|------|---------|
| `RESOURCES.md` | Full CVE profiles — root cause, primitive, exploitation chain, what it teaches |
| `NOTES.md` | Analysis patterns, recurring bug classes, conversion techniques, research workflow |
| `README.md` | This file |

## Bug Classes Covered

1. **Arbitrary File Write / Move / Delete** — TOCTOU, junction abuse, service file ops
2. **Token Impersonation** — Named pipe, SeImpersonatePrivilege, Potato family
3. **Installer / Updater Abuse** — MSI repair, InstallerFileTakeOver
4. **Win32k Kernel UAF** — Pool grooming, kernel R/W, token overwrite
5. **PrintNightmare** — RPC → arbitrary DLL load as SYSTEM
6. **Object Namespace Symlinks** — Object directory DACL, symlink planting
7. **DLL Search Order Hijacking** — Service DLL load, PATH manipulation

## Top 5 to Study First

1. **PrintSpoofer (CVE-2020-1048)** — Named pipe impersonation, widely applicable
2. **InstallerFileTakeOver** — Arbitrary file move primitive, MSI internals
3. **CVE-2021-1732** — Kernel UAF exploitation, win32k internals
4. **CVE-2020-0787 (BITS)** — Arbitrary file write via background service
5. **CVE-2021-1675/34527 (PrintNightmare)** — RPC attack surface, spooler internals

## Cross-References

- Researcher profiles: `../14_blogs_and_researchers/RESOURCES.md`
- Exploitation techniques: `../01_file_operations/`, `../03_token_impersonation/`
- Tools: `../11_tools_and_frameworks/`
