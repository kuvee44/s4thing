# 06 · Filesystem and File Operations — NOTES

## Windows I/O Architecture for Security Researchers

### The IRP Flow (Security Perspective)

```
User calls: CreateFile("C:\path\file.txt", GENERIC_READ, ...)
              ↓
Win32 → NtCreateFile(ObjectAttributes, DesiredAccess, ...)
              ↓
I/O Manager:
  1. Parse ObjectAttributes.ObjectName ("C:\path\file.txt")
  2. Object Manager namespace lookup → \??\C:\path\file.txt
  3. \??\C: → \Device\HarddiskVolume3 (via DOS device symlink)
  4. Create IRP_MJ_CREATE → send to NTFS driver stack
              ↓
Filter Manager (FltMgr):
  5. Pre-operation callbacks (minifilters at each altitude)
  6. Security check: SeAccessCheck() against file's DACL
              ↓
NTFS.sys:
  7. Look up file in MFT (B-tree traversal of directory)
  8. Process reparse points if present (re-issue IRP if reparse)
  9. Open FCB (File Control Block), create CCB, create FILE_OBJECT
              ↓
Filter Manager:
  10. Post-operation callbacks (minifilters)
              ↓
I/O Manager:
  11. Complete IRP → return HANDLE to user
```

**Security check timing matters:** Step 6 (access check) happens BEFORE step 8 (reparse point processing). This means the security check is performed against the *link itself* (the junction directory), not the *target*. If the junction target is world-accessible but the junction directory is restricted, the access check may wrongly pass or fail depending on implementation.

---

## NTFS MFT Structure Quick Reference

```
MFT Record ($FILE_RECORD_SEGMENT):
  ├── STANDARD_INFORMATION ($10): timestamps, file flags (hidden, system, etc.)
  ├── FILE_NAME ($30): name + parent directory reference (1 per hard link)
  ├── DATA ($80): file content (inline for small files, runs for large)
  ├── INDEX_ROOT ($90): directory B-tree root (for directories)
  ├── INDEX_ALLOCATION ($A0): directory B-tree nodes on disk
  ├── BITMAP ($B0): allocation bitmap for index
  ├── REPARSE_POINT ($C0): reparse data (for symlinks, junctions, etc.)
  ├── SECURITY_DESCRIPTOR ($50): file's security descriptor
  └── ATTRIBUTE_LIST ($20): pointer to additional MFT records (large files)
```

### Hard Link Security Implication

Multiple `FILE_NAME` attributes → multiple directory entries → multiple paths to the same MFT record. Security descriptor is per-MFT-record, not per-path. If path A allows access but path B would not, an attacker with access to path A can read/write through either path.

```
MFT Record #1234:
  FILE_NAME: C:\Users\Alice\secret.txt   ← restricted access
  FILE_NAME: C:\Temp\public.txt          ← world-readable
  SECURITY_DESCRIPTOR: Owner=Alice, DACL=[Alice:FullControl]
  
Result: Both paths read the same data; DACL on path B directory
        controls CREATE but not READ if handle already opened via path A
```

### Reparse Point Tag Registry

| Tag Value | Type | Security Notes |
|-----------|------|---------------|
| `0xA000000C` | `IO_REPARSE_TAG_SYMLINK` | Requires SeCreateSymbolicLinkPrivilege OR Developer Mode |
| `0xA0000003` | `IO_REPARSE_TAG_MOUNT_POINT` | Junction — no special privilege required |
| `0x80000017` | `IO_REPARSE_TAG_CLOUD` | OneDrive stub — can sometimes be used for redirect |
| `0x80000016` | `IO_REPARSE_TAG_CLOUD_1` through `_F` | Various cloud provider stubs |
| `0xC0000004` | `IO_REPARSE_TAG_HSM` | Hierarchical Storage Management |

**Attack note:** Third-party reparse tags (cloud storage stubs) may have their own traversal logic implemented in minifilter drivers, which may have weaker security checks than the native NTFS reparse traversal.

---

## Symlink / Junction / Mount Point Comparison

| Feature | NTFS Junction | NTFS File Symlink | Object Mgr Symlink | Hard Link |
|---------|---------------|-------------------|-------------------|-----------|
| Target type | Directory | File or Directory | Object (any) | File only |
| Cross-volume | ❌ No | ✅ Yes | ✅ Yes | ❌ No |
| Privilege needed | None (write dir) | SeCreateSymbolicLink or Dev Mode | None (in \??\) | Write to dir |
| Win32 visible | ✅ Yes | ✅ Yes | ✅ Via \??\\ | ✅ Yes |
| NTFS stored | ✅ Reparse attr | ✅ Reparse attr | ❌ In Object Manager | ✅ FILE_NAME attr |
| Kernel bypass possible | ✅ With OBJ_DONT_REPARSE | ✅ With OBJ_DONT_REPARSE | ❌ Object Mgr always resolves | N/A |
| Audit trail | Minimal | Minimal | Minimal | Changes MFT records |

**Key exploit design consideration:** Object Manager symlinks (in `\??\`) do not require `SeCreateSymbolicLinkPrivilege` and work even when NTFS symlink creation is restricted. They operate before the NTFS layer, making them the most powerful link type for exploitation.

---

## OpLock Types and Security Use Cases

```
┌─────────────────────────────────────────────────────────────────┐
│  OPLOCK TYPE        │  BREAKS WHEN          │  SECURITY USE     │
├─────────────────────┼───────────────────────┼───────────────────┤
│  Level 1 (exclusive)│  Any other open       │  Poor (breaks on  │
│                     │                       │  first victim open)│
├─────────────────────┼───────────────────────┼───────────────────┤
│  Batch              │  Any open by other    │  Better — batches │
│                     │  process              │  breaks per-open   │
├─────────────────────┼───────────────────────┼───────────────────┤
│  Filter             │  Open for read/write  │  BEST — fires     │
│                     │  by other process     │  before data xfer  │
├─────────────────────┼───────────────────────┼───────────────────┤
│  Read               │  Open for write       │  For cache mgmt   │
├─────────────────────┼───────────────────────┼───────────────────┤
│  FSCTL_REQUEST_     │  Configurable via     │  BEST FOR EXPLOIT │
│  OPLOCK (atomic)    │  RequestedOplockLevel │  Full control over │
│  (Win7+)            │                       │  break conditions  │
└─────────────────────┴───────────────────────┴───────────────────┘
```

### BaitAndSwitch Timing Diagram

```
T=0: Attacker creates bait directory: C:\Temp\BaitDir\
     Attacker creates bait file: C:\Temp\BaitDir\target.dll
     Attacker sets FILTER oplock on C:\Temp\BaitDir\target.dll

T=1: Privileged process accesses C:\Temp\BaitDir\target.dll
     ↓ OPLOCK BREAK NOTIFICATION fires immediately
     ↓ Privileged process is BLOCKED pending oplock acknowledgment

T=2: Attacker receives break notification
     Attacker replaces C:\Temp\BaitDir\ with junction to C:\Windows\System32\
     (attacker deletes directory, creates junction with same name)

T=3: Attacker releases oplock (acknowledges break)
     Privileged process CONTINUES with its OPEN call
     ↓ C:\Temp\BaitDir\target.dll now resolves to C:\Windows\System32\target.dll
     
T=4: Privileged process writes to C:\Windows\System32\target.dll
     → Attacker achieves write to System32 as privileged process
```

---

## NtCreateFile Security Flag Cheat Sheet

For code auditors — look for these patterns in privileged code:

### Dangerous patterns (vulnerable to junction attacks)

```c
// DANGEROUS: No OBJ_DONT_REPARSE, path from user input
OBJECT_ATTRIBUTES oa;
InitializeObjectAttributes(&oa, &userPath, OBJ_CASE_INSENSITIVE, NULL, NULL);
NtCreateFile(&handle, FILE_WRITE_DATA, &oa, ...);
```

### Safer patterns

```c
// SAFER: OBJ_DONT_REPARSE prevents junction traversal
OBJECT_ATTRIBUTES oa;
InitializeObjectAttributes(&oa, &userPath, 
    OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE,  // ← key flag
    NULL, NULL);
NtCreateFile(&handle, FILE_WRITE_DATA, &oa, ...);
```

```c
// SAFER: Open with FILE_FLAG_OPEN_REPARSE_POINT (Win32 equivalent)
HANDLE h = CreateFile(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
    FILE_FLAG_OPEN_REPARSE_POINT,  // ← key flag
    NULL);
```

### Win32 CreateFile flag equivalents

| Win32 Flag | NT Equivalent | Purpose |
|------------|---------------|---------|
| `FILE_FLAG_OPEN_REPARSE_POINT` | `OBJ_DONT_REPARSE` | Don't traverse reparse points |
| `FILE_FLAG_BACKUP_SEMANTICS` | No direct equivalent | Open directories, bypass some checks |
| `SECURITY_SQOS_PRESENT \| SECURITY_IDENTIFICATION` | ImpersonationLevel | Limit token passed to server |

---

## Filter Driver Security Notes

### Altitude Ranges and Security Products

```
Altitude range  Product category
420000–429999   FSFilter Anti-Virus (highest priority)
400000–409999   FSFilter Replication
360000–369999   FSFilter Continuous Backup
340000–349999   FSFilter Content Screener
320000–329999   FSFilter Quota Management
300000–309999   FSFilter System Recovery
280000–289999   FSFilter Cluster File System
260000–269999   FSFilter HSM (Hierarchical Storage)
240000–249999   FSFilter Imaging (Ex: TxF)
220000–229999   FSFilter Compression
200000–209999   FSFilter Encryption
180000–189999   FSFilter Virtualization
160000–169999   FSFilter Physical Quota Management
140000–149999   FSFilter Open File
120000–129999   FSFilter Security Enhancer  ← most EDR DLP filters here
100000–109999   FSFilter Copy Protection
80000–89999     FSFilter Bottom
```

**Bypass implication:** Operations performed at the kernel level *below* the filter's altitude bypass the filter. Operations using `ZwCreateFile` with `KernelMode` from a kernel driver at altitude 0 bypass all minifilters.

### Filter bypass detection matrix

| Technique | Bypass type | Detectable by |
|-----------|------------|---------------|
| Kernel-mode I/O below filter altitude | Altitude | Kernel ETW / ELAM |
| `ZwCreateFile` with `KernelMode` | PreviousMode | Kernel ETW |
| Alternate volume path (`\\?\Volume{guid}\file`) | Path normalization | Filter by GUID path |
| Alternate data stream access | Stream enumeration | Check all stream names |
| NTFS device object access | Device bypass | System call auditing |

---

*Last updated: 2026-04-22*
