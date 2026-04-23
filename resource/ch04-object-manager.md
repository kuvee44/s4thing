# Chapter 04 — Windows Object Manager Namespace: Internals, Security Model, and Attack Patterns

> **Scope:** This chapter covers the Windows Object Manager from a security research perspective.
> Topics include namespace architecture, object header internals, handle tables, symbolic link taxonomy,
> directory object security, name resolution mechanics, device map attacks, and oplock-based TOCTOU
> exploitation chains. WinDbg commands are embedded throughout.

---

## 1. Mental Model: Three Layers of the Windows Namespace

Windows does not expose a single flat address space for kernel resources. Every named kernel object
lives in a hierarchical **Object Manager namespace** rooted at `\`. To reason about attack surface,
you must understand three distinct but overlapping layers:

### Layer 1 — The Object Namespace Tree

The kernel maintains a tree of `_OBJECT_DIRECTORY` nodes rooted at `\`. Each node is a directory
object with its own security descriptor (DACL) controlling who can enumerate it, create objects
inside it, or look up names inside it. Key directories:

```
\                               ← _OBJECT_DIRECTORY (root)
├── Device\                     ← Device objects live here
│   ├── HarddiskVolume3         ← _DEVICE_OBJECT (NTFS volume)
│   ├── NamedPipe               ← _DEVICE_OBJECT (named pipe device)
│   └── Mup                     ← _DEVICE_OBJECT (multiple UNC provider)
├── BaseNamedObjects\           ← User-mode named objects (events, mutexes)
│   ├── SomeEvent               ← _KEVENT (created by user-mode code)
│   └── SomeMutex               ← _KMUTANT
├── Sessions\                   ← Per-session directory
│   └── 1\
│       ├── BaseNamedObjects\   ← Session-isolated named objects
│       └── AppContainerNamedObjects\
│           └── <PackageSid>\   ← AppContainer-isolated named objects
├── KernelObjects\              ← Low-memory notifications, etc.
├── REGISTRY\                   ← Registry namespace root
│   ├── MACHINE\                ← HKLM
│   └── USER\                   ← Per-user hives (HKCU)
├── Windows\                    ← Win32k / windowing objects
└── \??  (virtual per-process)  ← Not a real directory; backed by Device Map
    ├── C: → \Device\HarddiskVolume3
    └── UNC → \Device\Mup
```

**Critical insight:** `\DosDevices` is a symbolic link pointing to `\??`. The `\??` directory is
NOT a real `_OBJECT_DIRECTORY` object in the namespace tree. It is a **virtual** directory resolved
dynamically from the calling process's **Device Map** (`_EPROCESS.DeviceMap`). This distinction
matters profoundly for attacks.

### Layer 2 — The Per-Session Namespace Overlay

Windows isolates user-mode named objects by session. A process in session 1 creates mutexes in
`\Sessions\1\BaseNamedObjects\`, not in `\BaseNamedObjects\`. The kernel silently redirects the
Win32 path `\BaseNamedObjects\Foo` to the session-scoped equivalent when the caller is a user-mode
process. The global `\BaseNamedObjects\` exists but is primarily used by services in session 0.

AppContainer processes get a further isolated namespace:
`\Sessions\<N>\AppContainerNamedObjects\<PackageSid>\`.

An AppContainer process cannot create objects in the session-level `BaseNamedObjects` or the global
`BaseNamedObjects` — this is one of the AppContainer sandbox's namespace isolation boundaries.

### Layer 3 — The Per-Process Device Map

The `_EPROCESS.DeviceMap` field points to a `_DEVICE_MAP` structure. This structure maps short
device names (drive letters like `C`, `D`, `Z`, and device aliases like `UNC`) to their actual
object namespace paths. When the kernel resolves `\??\C:\foo\bar`, it looks up `C` in the
calling process's Device Map and finds `\Device\HarddiskVolume3`, producing the real path
`\Device\HarddiskVolume3\foo\bar`.

Under thread impersonation, the kernel by default uses the **impersonated thread's** Device Map,
not the process's Device Map. This is the root of the device map substitution attack class.

---

## 2. Object Header Anatomy

Every kernel object is preceded in memory by an `_OBJECT_HEADER` structure. Understanding this
structure is prerequisite for both kernel debugging and kernel exploitation.

### 2.1 _OBJECT_HEADER Layout (Windows 10/11 x64)

```c
typedef struct _OBJECT_HEADER {
    LONGLONG   PointerCount;      // +0x000  Kernel reference count (non-handle refs)
    union {
        LONGLONG HandleCount;     // +0x008  Open handle count (when alive)
        PVOID    NextToFree;      // +0x008  Next in free list (when freed)
    };
    EX_PUSH_LOCK Lock;            // +0x010  Push lock protecting header modifications
    UCHAR  TypeIndex;             // +0x018  XOR-encoded index into ObpObjectTypes[]
    union {
        UCHAR TraceFlags;         // +0x019
        struct {
            UCHAR DbgRefTrace       : 1;
            UCHAR DbgTracePermanent : 1;
        };
    };
    UCHAR  InfoMask;              // +0x01A  Bitmask indicating which optional headers exist
    union {
        UCHAR Flags;              // +0x01B
        struct {
            UCHAR NewObject          : 1;  // Object is being initialized
            UCHAR KernelObject       : 1;  // Accessible only from kernel mode
            UCHAR KernelOnlyAccess   : 1;  // Access check enforced for kernel callers too
            UCHAR ExclusiveObject    : 1;  // Only one open handle allowed
            UCHAR PermanentObject    : 1;  // Persists after last handle closes
            UCHAR DefaultSecurityQuota : 1;
            UCHAR SingleHandleEntry  : 1;
            UCHAR DeletedInline      : 1;
        };
    };
    ULONG  Spare;                 // +0x01C  Alignment padding
    union {
        OBJECT_CREATE_INFORMATION *ObjectCreateInfo; // +0x020  Create info or quota
        PVOID QuotaBlockCharged;
    };
    PVOID  SecurityDescriptor;    // +0x028  Pointer into ObpSecurityDescriptorCache
    QUAD   Body;                  // +0x030  Object body starts here
} OBJECT_HEADER;                  // Total header size: 0x30 bytes
```

**Key formula:** To locate the header from a body pointer:
```
header = (PCHAR)body - 0x30
```

The `SecurityDescriptor` field does not point directly to a `SECURITY_DESCRIPTOR` structure.
It points into the **security descriptor cache** (`ObpSecurityDescriptorCache`), a kernel cache
that deduplicates identical security descriptors across objects to save pool memory. The low bits
of the pointer encode cache metadata. Never dereference this field directly without the cache
lookup.

### 2.2 TypeIndex Encoding (Windows 8+)

Starting with Windows 8, the `TypeIndex` field is **XOR-encoded** to prevent trivial type
confusion exploitation:

```
decoded_index = TypeIndex
                XOR ((ULONG_PTR)ObjectHeader >> 8) & 0xFF
                XOR (ObHeaderCookie & 0xFF)
```

`ObHeaderCookie` is a random byte chosen at boot time. Without knowing this cookie, an attacker
cannot reliably compute the TypeIndex value needed to confuse the type dispatch table.

In WinDbg, decode it:
```windbg
; Get ObHeaderCookie
? nt!ObHeaderCookie

; Decode TypeIndex for an object at address <addr>
; header is at <addr> - 0x30
; TypeIndex byte is at <addr> - 0x30 + 0x18
? (poi(nt!ObHeaderCookie) & 0xff) ^
  ((<addr> - 0x30 >> 8) & 0xff) ^
  (by(<addr> - 0x30 + 0x18) & 0xff)
```

**Exploit relevance:** Corrupting `TypeIndex` redirects all type-dispatch operations (close,
duplicate, query, delete) through a fake `_OBJECT_TYPE` structure controlled by the attacker.
A kernel pool overflow adjacent to an `_OBJECT_HEADER` can corrupt `TypeIndex`, triggering
kernel code execution when the handle is closed. Post-Windows 8 XOR encoding requires knowing
`ObHeaderCookie` to fabricate a valid `TypeIndex`, raising the bar for blind exploitation.

### 2.3 Optional Headers (InfoMask)

The `InfoMask` field is a bitmask indicating which optional sub-headers precede the
`_OBJECT_HEADER` in memory (at negative offsets):

| InfoMask Bit | Structure | Content |
|---|---|---|
| 0x01 | `OBJECT_HEADER_CREATOR_INFO` | Creator process + type list link |
| 0x02 | `OBJECT_HEADER_NAME_INFO` | Object name string + directory backlink |
| 0x04 | `OBJECT_HEADER_HANDLE_INFO` | Single-entry handle data |
| 0x08 | `OBJECT_HEADER_QUOTA_INFO` | Pool charge information |
| 0x10 | `OBJECT_HEADER_PROCESS_INFO` | Exclusive owner process (if ExclusiveObject) |
| 0x20 | `OBJECT_HEADER_AUDIT_INFO` | Audit information |
| 0x40 | `OBJECT_HEADER_EXTENDED_INFO` | Extended info pointer |
| 0x80 | `OBJECT_HEADER_PADDING_INFO` | Alignment padding |

The name info sub-header is what makes an object **named** — it contains a `UNICODE_STRING` for
the object's name and a back-pointer to the `_OBJECT_DIRECTORY` that owns it.

---

## 3. Handle Tables

### 3.1 Structure and Organization

Handles are integers representing open references to kernel objects within a process context. The
kernel maintains two primary handle table domains:

**Per-process handle table:** `_EPROCESS.ObjectTable → _HANDLE_TABLE`. Each process has its own
table. User-mode code obtains handles from this table via `NtOpenXxx` or `NtCreateXxx` APIs.

**Kernel handle table:** A global `PspCidTable` maps process/thread IDs to their `_EPROCESS` /
`_ETHREAD` pointers. Additionally, handles with the `OBJ_KERNEL_HANDLE` attribute are stored in a
special kernel handle table and are only accessible from kernel mode.

### 3.2 HANDLE_TABLE_ENTRY

The handle table is a multi-level array (up to three levels). Each entry is a `HANDLE_TABLE_ENTRY`:

```c
typedef struct _HANDLE_TABLE_ENTRY {
    union {
        LONGLONG VolatileLowValue;  // +0x000  Object pointer (low bits encode flags)
        LONGLONG LowValue;
        struct {
            LONGLONG Unlocked     : 1;  // bit 0: table lock bit
            LONGLONG RefCnt       : 16; // bits 1-16: outstanding lock count
            LONGLONG Attributes   : 3;  // bits 17-19: handle attributes
            LONGLONG ObjectPointer: 44; // bits 20-63: pointer to _OBJECT_HEADER (>> 4)
        };
    };
    union {
        ULONG GrantedAccessBits;  // +0x008  Granted access mask (what the handle can do)
        ULONG ObAttributes;       // +0x008  Handle attributes (alternate interpretation)
        struct {
            ULONG Attributes;
            ULONG GrantedAccess;
        } HandleAttributes;
    };
} HANDLE_TABLE_ENTRY;
```

**Granted access bits** are set at handle creation time from the intersection of:
1. The requested `DesiredAccess` by the caller
2. The access granted by the security descriptor's DACL
3. Any maximum allowed access for the object type

Once a handle is open, the granted access is immutable — no re-check is performed on subsequent
operations (read, write, etc.). This means handle duplication can propagate excessive access.

### 3.3 Key WinDbg Handle Commands

```windbg
; Dump handle table for a process
!handle 0 7 <pid>         ; all handles with type and name

; Dump a specific handle
!handle <handle_value> 7

; Inspect handle table entry directly
dt nt!_HANDLE_TABLE_ENTRY <address>

; Find all handles referencing a specific object
!object <object_address>  ; shows handle count

; Enumerate all open handles to a file by name
!handle 0 7 0 File        ; all File handles in all processes
```

---

## 4. Symbolic Link Taxonomy

Windows has six meaningfully distinct link types, each operating at a different layer of the
name resolution stack. Understanding the differences is essential for designing attacks.

| Type | Privilege Required | Redirection Level | Creation API | Cross-Volume? |
|---|---|---|---|---|
| **NTFS Junction (Mount Point)** | None (write to parent dir) | Directory-level, NTFS layer | `fsutil reparsepoint set` / `CreateJunction` | ❌ No |
| **NTFS File Symlink** | `SeCreateSymbolicLinkPrivilege` or Developer Mode | File or directory, NTFS layer | `CreateSymbolicLink` | ✅ Yes |
| **Object Manager Symlink** | None (create access in target dir, e.g. `\??`) | Object namespace, before NTFS | `NtCreateSymbolicLinkObject` | ✅ Yes |
| **DosDevice Override** | None (for current user session) | Drive letter / device name | `DefineDosDevice` | ✅ Yes |
| **Registry Symlink** | Write access to source key | Registry key namespace | `NtSetValueKey` with `REG_LINK` type | N/A |
| **Hard Link** | Write access to directory; same volume | File identity (MFT-level) | `CreateHardLink` | ❌ No |

### Attack Design Rules

1. **NTFS junctions** are the most commonly exploitable link type because they require no
   privilege and are transparently followed by most privileged services. A junction at
   `C:\Users\Public\AttackerDir\` → `C:\Windows\System32\` means any file created through
   that junction lands in System32.

2. **Object Manager symlinks** in `\??` (the DosDevices virtual directory) can be created by
   standard users and operate *before* the NTFS layer. This means `OBJ_DONT_REPARSE` (which
   suppresses NTFS reparse traversal) does NOT protect against Object Manager symlinks.

3. **DosDevice overrides** via `DefineDosDevice` only affect the calling user's session device
   map. If a privileged service running in the same session resolves `\??\MySoftwareDevice`, a
   user-created DosDevice can redirect it.

4. **Registry symlinks** (`REG_LINK` value type) are a little-known but powerful redirect. They
   allow a user-writable `HKCU` key to transparently redirect writes to an `HKLM` key, enabling
   an "arbitrary registry write" primitive from a limited write.

5. **Hard links** do not redirect names — they create an additional directory entry pointing to
   the same MFT record. The security descriptor is on the MFT record, not the path. If a
   privileged process deletes "its" file by name, an attacker's hard link still references the
   same inode. If the privileged process then creates a new file at the same path, a rename trick
   can redirect the create.

---

## 5. Directory Objects and DACL Weaknesses

### 5.1 How Directory DACLs Create Attack Surface

Every `_OBJECT_DIRECTORY` has a security descriptor. The critical access rights for attackers are:

- **`DIRECTORY_CREATE_OBJECT`**: Allows creating a new named object inside the directory. If a
  lower-privilege process has this right on a directory that a higher-privilege process uses for
  name lookups, it can **pre-plant** a malicious object at the expected name.
- **`DIRECTORY_QUERY`**: Allows enumerating directory contents.
- **`DIRECTORY_TRAVERSE`**: Allows lookup of names in the directory.

### 5.2 Default DACLs on Key Directories

On a default Windows installation:

- `\BaseNamedObjects\`: **Authenticated Users** have `DIRECTORY_CREATE_OBJECT`. This is
  intentional (services and applications need to create named synchronization objects) but means
  any authenticated user can pre-plant objects in this namespace.
- `\Sessions\<N>\BaseNamedObjects\`: Session-scoped; created users within session N have
  create access. This provides weak isolation between users in the same session.
- `\Device\`: Only kernel/SYSTEM can create objects here. Named pipes are created here by the
  kernel when user-mode calls `CreateNamedPipe`.
- `\KnownDlls\`: Contains section objects for well-known DLLs. Writable only by SYSTEM.
  A writable `\KnownDlls\` would enable DLL hijacking of every process that loads those DLLs.

### 5.3 Object Directory Squatting Attack Pattern

```
Precondition:
  - Lower-privilege attacker can create objects in \BaseNamedObjects\ (default permission)
  - Privileged service creates \BaseNamedObjects\ServiceInitMutex at startup to prevent
    re-initialization

Attack:
  1. Attacker creates \BaseNamedObjects\ServiceInitMutex before service starts
  2. Service calls NtOpenMutant(\BaseNamedObjects\ServiceInitMutex) — succeeds (attacker's object)
  3. Service checks "mutex already exists" → skips initialization path
  4. Service enters production state without proper initialization
  5. Behavior depends on service logic — may expose unauthenticated RPC, skip privilege drop, etc.

PowerShell PoC:
  $mut = New-NtMutant -Path \BaseNamedObjects\ServiceInitMutex -Win32Path $false
  # Start the service; observe whether it skips initialization
```

Audit for this pattern with:
```powershell
# Find directories where current user has CreateObject rights
Get-AccessibleObject -NtType Directory -Path \ -Recurse -AccessRights CreateObject |
  Format-Table Name, GrantedAccess
```

---

## 6. ObpLookupObjectName: Name Resolution Internals

### 6.1 The Resolution Algorithm

`ObpLookupObjectName` is the kernel function responsible for resolving a Unicode string path
through the object namespace tree. Understanding its behavior reveals where symlink substitution
occurs and where mitigations intervene.

High-level algorithm:

```
INPUT: UNICODE_STRING path (e.g., "\??\C:\Windows\notepad.exe")
       OBJECT_ATTRIBUTES flags (OBJ_DONT_REPARSE, OBJ_IGNORE_IMPERSONATED_DEVICEMAP, etc.)
       RootDirectory handle (optional — relative path lookup)

STEP 1: If path starts with \, start at root directory (\)
        Otherwise, start at RootDirectory

STEP 2: Tokenize path by \

STEP 3: For each component:
  a. Look up component name in current _OBJECT_DIRECTORY's hash table
  b. If found and it's a _OBJECT_SYMBOLIC_LINK:
       - If OBJ_DONT_REPARSE is set → return STATUS_REPARSE_POINT_NOT_RESOLVED (fail)
       - If OBJ_OPENLINK is set → return the symlink object itself
       - Otherwise: substitute the symlink's target string + remaining path
         and restart from step 1 (or from relative base if target is relative)
  c. If found and it's a _OBJECT_DIRECTORY: descend into it
  d. If not found: return STATUS_OBJECT_NAME_NOT_FOUND

STEP 4: The remaining path components after the last namespace object
        are passed to the object's parse routine
        (e.g., for \Device\HarddiskVolume3\Windows\notepad.exe,
         the NTFS parse routine receives "\Windows\notepad.exe")
```

**Symlink substitution point:** The substitution happens at step 3b, *inside* the namespace
traversal loop. The substituted path is re-resolved from the beginning. This means object manager
symlinks redirect the *entire remaining lookup*, not just the current component.

### 6.2 The \?? Virtual Directory

`\??` is resolved through a special code path. When `ObpLookupObjectName` encounters `??` as
the second path component (after the root `\`), it does NOT look in the object namespace for
an `_OBJECT_DIRECTORY` named `??`. Instead, it queries:

1. If the calling **thread** is impersonating: use the impersonated thread's device map
   (unless `OBJ_IGNORE_IMPERSONATED_DEVICEMAP` is set)
2. Otherwise: use the calling **process**'s device map (`_EPROCESS.DeviceMap`)

The device map lookup maps the next component (`C`, `D`, etc.) to its registered target path.

This means that two processes in different logon sessions, or the same process before and after
impersonation, may resolve identical `\??\C:\...` paths to **different devices**.

---

## 7. Device Map and Drive Letter Redirection Attacks

### 7.1 Architecture

The Device Map (`_DEVICE_MAP`) structure maintains:
- A directory of symbolic links for drive letters (`C:`, `D:`, etc.)
- A reference to the session's `_OBJECT_DIRECTORY` for per-session device names

Each logon session gets its own device map. When a process is created, it inherits the device map
of its logon session. When a thread impersonates a different user (via `NtSetInformationThread` or
`ImpersonateLoggedOnUser`), the thread's `_KTHREAD.ImpersonationInfo` points to the impersonated
user's token, which carries the impersonated session's device map.

```windbg
; Inspect current process device map
dt nt!_EPROCESS <addr> DeviceMap

; Inspect device map structure
dt nt!_DEVICE_MAP <addr>

; See drive letter mappings for a session
!object \??\C:
```

### 7.2 The Impersonated Device Map Attack

**Vulnerable pattern:** A SYSTEM service impersonates a user (e.g., for access checking) and
then opens a file using a drive-letter path:

```c
// Service impersonates user for access check
ImpersonateLoggedOnUser(userToken);

// BUG: path resolved using impersonated user's device map
OBJECT_ATTRIBUTES attrs;
InitializeObjectAttributes(&attrs, &fileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
NtCreateFile(&handle, GENERIC_READ, &attrs, &iosb, ...);

// Service stops impersonating
RevertToSelf();
```

**Attack:**
1. Attacker controls a logon session (their own).
2. Attacker modifies their session's device map: `DefineDosDevice("C", "\Device\NamedPipe\AttackerPipe")`.
3. The privileged service impersonates the attacker's token.
4. Service resolves `\??\C:\SensitiveFile` → `\Device\NamedPipe\AttackerPipe` → connects to attacker pipe.
5. Attacker calls `ImpersonateNamedPipeClient()` → receives SYSTEM token.

**Fix:** Use `OBJ_IGNORE_IMPERSONATED_DEVICEMAP` in the `OBJECT_ATTRIBUTES.Attributes` field:

```c
// CORRECT: always use process's device map, ignoring impersonation
OBJECT_ATTRIBUTES attrs;
InitializeObjectAttributes(&attrs, &fileName,
    OBJ_CASE_INSENSITIVE | OBJ_IGNORE_IMPERSONATED_DEVICEMAP,
    NULL, NULL);
NtCreateFile(&handle, GENERIC_READ, &attrs, &iosb, ...);
```

The absence of `OBJ_IGNORE_IMPERSONATED_DEVICEMAP` in privileged path operations is an auditable
vulnerability indicator. Search for `NtCreateFile`/`ZwCreateFile` calls in service binaries that
perform impersonation without this flag.

---

## 8. Oplock + Junction TOCTOU Pattern for LPE

### 8.1 Background: What Makes TOCTOU Hard Without Oplocks

Classic TOCTOU (Time-of-Check to Time-of-Use) races in file operations are notoriously unreliable
because the race window is measured in nanoseconds. A privileged service's check-then-use sequence:

```
T1: Service validates C:\Logs\ directory exists → OK
T2: Service creates C:\Logs\output.tmp (write)
T3: Service renames C:\Logs\output.tmp → C:\Logs\output.txt
```

Without synchronization, an attacker must win the race between T1 and T3 — nearly impossible
against modern multicore CPUs running preemptive kernels.

### 8.2 Opportunistic Locks as a Synchronization Primitive

An **opportunistic lock** (oplock) is an IPC mechanism where a process can request that the
kernel notify it *synchronously* before another process's file operation completes. From an
attacker's perspective, an oplock on a file used in a privileged operation converts the
nanosecond race window into an indefinitely-large, attacker-controlled window.

Oplock types relevant to exploitation:

| Type | Break Trigger | Exploit Utility |
|---|---|---|
| Level 1 (exclusive) | Any other open | Too broad — breaks too early |
| Batch | Any open by other process | Better — fires at open time |
| Filter | Open for read/write by other process | Best — fires before data transfer |
| `FSCTL_REQUEST_OPLOCK` (atomic, Win7+) | Configurable | Best — full control via flags |

The **Filter oplock** fires when another process attempts to open the oplocked file with any
access that would conflict with the filter's cache rights — specifically, before any data is
transferred to the other process. This is the ideal synchronization point.

### 8.3 BaitAndSwitch Step-by-Step

This is the canonical technique for exploiting arbitrary file write or file rename primitives
in privileged services.

```
SETUP (attacker):
  1. Create directory:  C:\Temp\BaitDir\
  2. Create file:       C:\Temp\BaitDir\target.dll  (the "bait")
  3. Request Filter oplock on C:\Temp\BaitDir\target.dll

EXECUTION TIMELINE:
  T0: Privileged service (SYSTEM) begins operation.
      It opens or accesses C:\Temp\BaitDir\target.dll.
      ↓
  T1: Kernel fires oplock break notification to attacker.
      The service's open call is BLOCKED — it does not proceed until
      the attacker acknowledges the break.

  T2: Attacker receives break notification.
      Attacker removes directory C:\Temp\BaitDir\
      Attacker creates NTFS junction C:\Temp\BaitDir → C:\Windows\System32\
      (BaitDir is now a junction point, not a real directory)

  T3: Attacker releases the oplock (acknowledges the break).

  T4: The blocked service operation resumes.
      C:\Temp\BaitDir\target.dll now resolves to:
        junction (C:\Temp\BaitDir) → C:\Windows\System32\
        + target.dll
        = C:\Windows\System32\target.dll
      SYSTEM writes to C:\Windows\System32\target.dll

  T5: Attacker plants a payload DLL at the redirected path.
      Next privileged process to load target.dll executes attacker code.
```

**The key insight:** The service does not re-validate the path after the oplock break. It holds
an in-flight IRP that completes with the *new* resolution of the path, which now points to
System32.

### 8.4 From Arbitrary File Write to Full LPE

The canonical chain derived from Forshaw's research:

```
INGREDIENT: A privileged service writes to a path that contains attacker-controlled
            components (e.g., a service that creates/renames files in a temp directory
            whose full path passes through user-writable parent directories)

CHAIN:
  1. Identify the privileged write:  Service SYSTEM writes to C:\ProgramData\Vendor\update.dll
  2. Identify the race point:         Service validates the path, then writes
  3. Plant bait:                      Oplock on C:\ProgramData\Vendor\update.dll
  4. Wait for oplock break:           Service validates path → triggers oplock
  5. Swap directory:                  Remove C:\ProgramData\Vendor\ (if we created it)
                                      Create junction C:\ProgramData\Vendor\ → C:\Windows\System32\
  6. Release oplock:                  Service continues → writes to System32\update.dll
  7. DLL hijack:                      Update.dll is loaded by a SYSTEM process → LPE

WINDOWS INSTALLER VARIANT:
  If arbitrary write exists but no oplock race is needed:
  1. Write a DLL to C:\Windows\System32\<dll>.dll
  2. Trigger msiexec /fau <MSI GUID> (Windows Installer repair)
  3. MSI repair loads DLLs in SYSTEM context → code execution
```

### 8.5 Oplock APIs

```c
// Request a filter oplock on a file (Win7+ atomic oplock)
// File must be opened with FILE_FLAG_OVERLAPPED and appropriate sharing

REQUEST_OPLOCK_INPUT_BUFFER input = {
    .StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION,
    .StructureLength  = sizeof(input),
    .RequestedOplockLevel = OPLOCK_LEVEL_CACHE_READ |
                            OPLOCK_LEVEL_CACHE_HANDLE,
    .Flags = REQUEST_OPLOCK_INPUT_FLAG_REQUEST
};
REQUEST_OPLOCK_OUTPUT_BUFFER output = { ... };

DeviceIoControl(hFile,
    FSCTL_REQUEST_OPLOCK,
    &input, sizeof(input),
    &output, sizeof(output),
    &bytesReturned,
    &overlapped);  // Async — completes when oplock breaks
```

The `symboliclink-testing-tools` repository (Project Zero) provides `SetOpLock.exe` — a
command-line tool that automates the oplock request and signals when the break fires, making
the BaitAndSwitch timing manual and reliable during PoC development.

---

## 9. Key WinDbg Commands for Object Manager Research

```windbg
; ─── NAMESPACE NAVIGATION ───────────────────────────────────────────
!object \                       ; root directory and contents
!object \Device                 ; device directory
!object \Device\NamedPipe       ; named pipe device
!object \BaseNamedObjects       ; user named objects
!object \Sessions\1\BaseNamedObjects  ; per-session named objects

; ─── STRUCTURE INSPECTION ────────────────────────────────────────────
dt nt!_OBJECT_HEADER <addr>     ; object header
dt nt!_OBJECT_DIRECTORY <addr>  ; directory object (hash buckets)
dt nt!_OBJECT_SYMBOLIC_LINK <addr>  ; symlink (LinkTarget UNICODE_STRING)
dt nt!_DEVICE_MAP <addr>        ; device map structure

; ─── HANDLE OPERATIONS ───────────────────────────────────────────────
!handle 0 7 <pid>               ; all handles in process with type/name
!handle 0 7 0 File              ; all File handles in all processes
!handle <value> f               ; full detail for one handle

; ─── OBJECT TYPE TABLE ───────────────────────────────────────────────
dt nt!ObpObjectTypes            ; array of _OBJECT_TYPE pointers
dt nt!_OBJECT_TYPE <addr>       ; object type structure (TypeInfo, callbacks)

; ─── EPROCESS DEVICE MAP ─────────────────────────────────────────────
dt nt!_EPROCESS <addr> DeviceMap
!process 0 0 <name.exe>         ; find EPROCESS address by name

; ─── DECODE TYPEINDEX ────────────────────────────────────────────────
; header_addr = object_addr - 0x30
; TypeIndex byte at header_addr + 0x18
; ObHeaderCookie:
? nt!ObHeaderCookie
; Decode:
? (poi(nt!ObHeaderCookie) & 0xff) ^ ((<hdr_addr> >> 8) & 0xff) ^ (by(<hdr_addr>+0x18) & 0xff)
```

---

## 10. Research Methodology: Auditing the Object Namespace

**Step 1: Enumerate writeable directories**
```powershell
# Find namespace directories where current user can create objects
Get-AccessibleObject -NtType Directory -Path \ -Recurse -AccessRights CreateObject |
  Format-Table Name, GrantedAccess
```

**Step 2: Identify privileged name lookups**
- Use Process Monitor (filter: Operation=RegOpenKey OR Operation=CreateFile, User=SYSTEM)
- Focus on names that pass through directories where you have CreateObject rights

**Step 3: Check for OBJ_DONT_REPARSE**
- Open the privileged binary in IDA/Ghidra
- Find all `NtCreateFile`/`ZwCreateFile` call sites
- Check the `Attributes` field passed in `OBJECT_ATTRIBUTES` for presence of `0x1000` (OBJ_DONT_REPARSE)
- Absence when operating on user-influenced paths = vulnerability indicator

**Step 4: Check for OBJ_IGNORE_IMPERSONATED_DEVICEMAP (0x2000)**
- Find all code paths that call `NtCreateFile` after an impersonation call
- Absence of `0x2000` in `Attributes` when operating on drive-letter paths under impersonation = vulnerability

**Step 5: Build the exploit chain**
- If the vulnerable operation is a file rename: BaitAndSwitch with junction swap
- If it is a registry write: registry symlink redirect
- If it is a named object lookup: object squatting

---

## References

[R-1] *Windows Internals, Part 1, Chapter 8: System Mechanisms — Object Manager* — Mark Russinovich, David Solomon, Alex Ionescu, Pavel Yosifovich — https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals

[R-2] *Windows Security Internals* — James Forshaw (No Starch Press, 2023) — https://nostarch.com/windows-security-internals

[R-3] *Windows Exploitation Tricks: Exploiting Arbitrary File Writes for Local Elevation of Privilege* — James Forshaw / Google Project Zero — https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html

[R-4] *symboliclink-testing-tools* — James Forshaw / Google Project Zero — https://github.com/googleprojectzero/symboliclink-testing-tools

[R-5] *sandbox-attacksurface-analysis-tools (NtObjectManager)* — James Forshaw / Google Project Zero — https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools

[R-6] *Windows Object Manager — Deep Technical Analysis* — Geoff Chappell — https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ob/

[R-7] *tiraniddo.dev — Symbolic Link, Object Manager, and Device Map Research Series* — James Forshaw — https://www.tiraniddo.dev/

[R-8] *WinObj* — Sysinternals / Microsoft — https://learn.microsoft.com/en-us/sysinternals/downloads/winobj
