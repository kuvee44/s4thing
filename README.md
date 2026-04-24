# Windows Security Research Vault

**Purpose:** Elite private research archive for serious Windows vulnerability research  
**Owner:** Private  
**Created:** 2026-04-22  
**Focus:** LPE, Installer abuse, filesystem exploitation, token impersonation, RPC/COM/ALPC, object manager, kernel/Win32k, variant hunting

---

## Quick Navigation

| Start Here | I want to... |
|-----------|-------------|
| [00_index.md](resource/00_index.md) | Navigate everything |
| [ch17-labs-and-exercises.md](resource/ch17-labs-and-exercises.md) | Practice hands-on |
| [ch14-researchers-and-blogs.md](resource/ch14-researchers-and-blogs.md) | Find elite researchers |
| [ch15-github-and-tools.md](resource/ch15-github-and-tools.md) | Get research code |
| [ch12-variant-hunting.md](resource/ch12-variant-hunting.md) | Hunt for variants |
| [ch13-cve-case-studies.md](resource/ch13-cve-case-studies.md) | Study real CVEs |

---

## Vault Structure

```
resource/
├── 00_index.md                    ← Master navigation & chapter summaries
├── ch01-foundations.md            ← NT executive, processes, memory, pool, IRP, SRM
├── ch02-debugging-and-observability.md  ← WinDbg, TTD, ProcMon, ETW, System Informer
├── ch03-windows-security-model.md ← Tokens, ACLs, integrity levels, UAC, AppContainer
├── ch04-object-manager.md         ← Object namespace, symbolic links, handle tables, TOCTOU
├── ch05-rpc-com-alpc.md           ← RPC, COM, ALPC, named pipes, auth coercion
├── ch06-filesystem.md             ← NTFS, oplocks, reparse points, hard links, filter drivers
├── ch07-services-installers.md    ← Services, MSI, updaters, Task Scheduler, WER
├── ch08-bug-classes.md            ← Arb file write, Potato family, DLL hijack, weak ACLs
├── ch09-exploit-primitives.md     ← File move/rename/delete primitives, I/O Ring, token steal
├── ch10-kernel-win32k.md          ← Segment heap, pool exploitation, Win32k, KASLR, HEVD
├── ch11-patch-diff.md             ← BinDiff, Diaphora, patch analysis workflow, root cause
├── ch12-variant-hunting.md        ← CodeQL, Jackalope, WTF, feature interaction methodology
├── ch13-cve-case-studies.md       ← 8 deep CVE analyses: itm4n, Naceri, PrintSpoofer, Win32k
├── ch14-researchers-and-blogs.md  ← Forshaw, itm4n, decoder, j00ru, Shafir — arcs and method
├── ch15-github-and-tools.md       ← NtObjectManager, symboliclink-tools, HEVD, RpcView, etc.
├── ch16-talks-and-papers.md       ← Bochspwn, DEF CON 25, I/O Ring, Pool is Dead — methodology
├── ch17-labs-and-exercises.md     ← 25+ structured hands-on labs, Tiers 1–6
└── ch18-reporting-and-bounty.md   ← MSRC, ZDI, CVSS scoring, disclosure, reputation building
```

---

## Priority Reading (First Week)

1. **Windows Internals Part 1** (Russinovich) — Chapters 1-3, 8, 11
2. **Windows Security Internals** (Forshaw) — Start from Chapter 1
3. **tiraniddo.dev** — Read all posts on token impersonation and object manager
4. **itm4n.github.io** — PrintSpoofer post and PrintNightmare series
5. **Set up WinDbg + TTD** — Follow `resource/ch02-debugging-and-observability.md`

---

## Key Researchers

- **James Forshaw** (tyranid) — tiraniddo.dev — Object manager, RPC, COM, tokens, sandbox
- **j00ru** — j00ru.vexillium.org — Win32k, kernel, fuzzing, syscalls
- **itm4n** — itm4n.github.io — LPE, services, named pipes, PrintSpoofer
- **Decoder** — decoder.cloud — Potato family, token impersonation
- **Yarden Shafir** — windows-internals.com — Kernel, I/O Ring, KASLR

---

## Vault Maintenance

This vault is a living document. When adding new resources:
1. Add entry to the relevant chapter file
2. Update `resource/00_index.md`
3. Avoid adding resources that don't pass the methodology test in `00_index.md`

Label system: `[FOUNDATIONAL]` `[MUST-READ]` `[HISTORICAL]` `[LAB-WORTHY]` `[VARIANT-HUNTING]` `[PATCH-DIFF]`
