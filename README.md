# Windows Security Research Vault

**Purpose:** Elite private research archive for serious Windows vulnerability research  
**Owner:** Private  
**Created:** 2026-04-22  
**Focus:** LPE, Installer abuse, filesystem exploitation, token impersonation, RPC/COM/ALPC, object manager, kernel/Win32k, variant hunting

---

## Quick Navigation

| Start Here | I want to... |
|-----------|-------------|
| [MASTER_INDEX.md](resource/00_index/MASTER_INDEX.md) | Navigate everything |
| [LEARNING_PATH.md](resource/00_index/LEARNING_PATH.md) | Follow a structured study path |
| [TOP_100_MUST_READS.md](resource/00_index/TOP_100_MUST_READS.md) | Read the best first |
| [RESEARCHERS_TO_FOLLOW.md](resource/00_index/RESEARCHERS_TO_FOLLOW.md) | Find elite researchers |
| [LABS_QUEUE.md](resource/00_index/LABS_QUEUE.md) | Practice hands-on |
| [GITHUB_TOP_REPOS.md](resource/00_index/GITHUB_TOP_REPOS.md) | Get research code |

---

## Vault Structure

```
resource/
├── 00_index/              ← Master navigation
├── 01_foundations/        ← Windows internals core
├── 02_debugging/          ← WinDbg, TTD, ProcMon, ETW
├── 03_security_model/     ← Tokens, ACLs, integrity, UAC
├── 04_object_manager/     ← Object namespace, symlinks, device maps
├── 05_rpc_com_alpc/       ← RPC, COM, ALPC, named pipes
├── 06_filesystem/         ← File ops, NTFS, oplocks, reparse points
├── 07_services_installers/← Services, MSI, updaters, repair flows
├── 08_bug_classes/        ← All major Windows LPE bug classes
├── 09_exploit_primitives/ ← Building blocks: file write, oplock, token
├── 10_kernel_win32k/      ← Kernel exploitation, Win32k, pool
├── 11_patch_diff/         ← BinDiff, Diaphora, root cause analysis
├── 12_variant_hunting/    ← Finding variants, CodeQL, systematic search
├── 13_cve_case_studies/   ← Educational CVE deep dives
├── 14_blogs_researchers/  ← Researcher profiles and blogs
├── 15_github_code/        ← Repos, tools, PoCs
├── 16_talks_papers/       ← Conference talks, papers, slide decks
├── 17_labs_exercises/     ← Hands-on practice queue
├── 18_reporting_bounty/   ← MSRC, ZDI, report writing
└── 99_meta/               ← Vault maintenance metadata
```

---

## Priority Reading (First Week)

1. **Windows Internals Part 1** (Russinovich) — Chapters 1-3, 8, 11
2. **Windows Security Internals** (Forshaw) — Start from Chapter 1
3. **tiraniddo.dev** — Read all posts on token impersonation and object manager
4. **itm4n.github.io** — PrintSpoofer post and PrintNightmare series
5. **Set up WinDbg + TTD** — Follow `02_debugging_and_observability/README.md`

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
1. Add entry to the relevant `RESOURCES.md`
2. Update `00_index/MASTER_INDEX.md`
3. Update `99_meta/SEARCH_LOG.md`
4. Check `99_meta/DUPLICATES_MERGED.md` for overlap

Label system: `[FOUNDATIONAL]` `[MUST-READ]` `[HISTORICAL]` `[LAB-WORTHY]` `[VARIANT-HUNTING]` `[PATCH-DIFF]`
