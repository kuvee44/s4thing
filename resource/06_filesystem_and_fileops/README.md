# 06 · Filesystem and File Operations — README

## What This Section Covers

This section documents the Windows filesystem security research landscape — from NTFS internals and the NT I/O subsystem, through reparse points and symlinks, to filter drivers and security operations. The filesystem layer is the substrate on which a disproportionate number of Windows LPE bug classes are built.

## Why This Section Exists

Windows filesystem security is frequently misunderstood because it operates at multiple abstraction layers simultaneously:

1. **NTFS format layer** (MFT records, attribute types, reparse data buffers)
2. **NT kernel I/O layer** (IRP dispatch, FILE_OBJECT, security checks)  
3. **Win32 API layer** (CreateFile flags, path semantics, junction creation)
4. **NT Object Manager layer** (namespace resolution, symbolic link objects)

A vulnerability that appears in layer 3 (Win32) may be exploitable only because of behavior at layer 1 (NTFS) or layer 4 (Object Manager). This section provides resources for all four layers.

## Section Structure

| Sub-section | Layer Focus | Key Resources |
|-------------|-------------|---------------|
| Windows Internals — Storage/FS | Kernel I/O, NTFS driver architecture | Windows Internals Part 2 |
| NTFS Internals | NTFS format, MFT structure | libyal docs, MSDN, Sleuth Kit |
| Reparse Points, Symlinks, Junctions | NTFS reparse mechanism, Win32 APIs | MSDN + Forshaw blog |
| OpLocks and TOCTOU | Race prevention, BaitAndSwitch | Forshaw blog + symlink-testing-tools |
| Filesystem Security Operations | ACL, NtCreateFile flags, handle security | MSDN + Forshaw analysis |
| Filter Drivers and Security | EDR/AV interception, minifilter model | WDK docs + research |

## Key Security Flags Reference

When auditing privileged code for filesystem vulnerability, check for:

| Flag | API | Security Meaning |
|------|-----|-----------------|
| `OBJ_DONT_REPARSE` | NtCreateFile (OBJECT_ATTRIBUTES) | Do not traverse reparse points — prevents junction/symlink attacks |
| `FILE_FLAG_OPEN_REPARSE_POINT` | CreateFile (Win32) | Open the link itself, not its target |
| `LOAD_LIBRARY_SEARCH_SYSTEM32` | LoadLibraryEx | Only search System32 for DLL — prevents search order hijacking |
| `FILE_FLAG_BACKUP_SEMANTICS` | CreateFile | Required for opening directories — check security implications |
| `FILE_SHARE_DELETE` | CreateFile | Allows concurrent delete — enables file-replace attacks |

## Cross-Section Dependencies

```
06_filesystem_and_fileops
    ├── feeds into: 08_bug_classes (all filesystem-based attack classes)
    ├── feeds into: 09_exploit_primitives (oplocks, file rename primitives)
    ├── depends on: Windows Internals (I/O, Memory Management chapters)
    └── tools: Process Monitor, WinDbg (!fileobj, !irp), fsutil, WinObj
```

## Learning Path

```
Beginner:
  → Windows Internals I/O overview (Entry 1.1 — skim)
  → Reparse Points MSDN (Entry 3.1 — read fully)
  → Arbitrary File Write blog post (Entry 5.1 — practical anchor)

Intermediate:
  → NTFS internals (Entry 2.1 — build mental model)
  → NtCreateFile flags (Entry 5.2 — essential for code auditing)
  → Handle inheritance (Entry 5.3 — ACL foundations)

Advanced:
  → OpLock + BaitAndSwitch (Entry 4.1 — key exploit primitive)
  → Filter driver model (Entry 6.1 — understand EDR architecture)
  → Pool + NTFS (Entry 6.3 — kernel vulnerability research)
```
