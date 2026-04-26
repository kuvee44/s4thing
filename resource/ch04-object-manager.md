# Chapter 04 — Windows Object Manager Namespace: Internals, Security Model, and Attack Patterns

> **Scope:** This chapter covers the Windows Object Manager from a security research perspective.
> Topics include namespace architecture, object header internals, handle tables, symbolic link taxonomy,
> directory object security, name resolution mechanics, device map attacks, oplock-based TOCTOU
> exploitation chains, and 2024-2025 research including actively-exploited CVEs and new techniques.
> WinDbg commands are embedded throughout.
>
> **Last updated:** 2025-04 — incorporates CVE-2024-21310, CVE-2024-26218, CVE-2025-21333/34/35,
> shadow directory technique, PoolParty + handle table chains, NtCreateSymbolicLinkObject hardening bypass.

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

**2024 research note:** Cross-session object namespace isolation flaws continue to be exploited.
Session namespace boundary weaknesses allow low-privilege AppContainer processes to plant objects
visible to session 0 services under specific DACL conditions (see Section 5.4).

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

**2024 update — PoolParty meets handle table (HITB 2025):** Researchers demonstrated a chain
combining pool spray + handle table entry overwrite on Windows 11 24H2. The attack targeted
`ObpCloseHandleTableEntry()` which had a race condition window (since patched — Microsoft added
atomic checks before object pointer dereference). The chain: heap overflow → handle table entry
overwrite → TypeIndex corruption → kernel code execution when handle closed.

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
        ULONG GrantedAccessBits;  // +0x008  Granted access mask
        ULONG ObAttributes;
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
operations. This means handle duplication can propagate excessive access.

### 3.3 Handle Table TOCTOU — 2024 Research

A TOCTOU race condition was discovered in `ObpReferenceObjectByHandleWithTag` where an attacker
could replace a kernel object **between** the access check phase and the dereference phase. This
yields an arbitrary kernel read/write primitive. Affected APIs include:
`NtDuplicateObject`, `NtClose`, `NtSetInformationProcess`.

The attack leverages `NtQuerySystemInformation(SystemHandleInformation)` to leak handle addresses,
then races handle replacement against the kernel's lock acquisition window in
`ExAcquirePushLockExclusive`. Microsoft patched this with additional atomic checks.

**Leak handle addresses:**
```c
ULONG size = 0x100000;
PSYSTEM_HANDLE_INFORMATION pHandleInfo = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
while (NtQuerySystemInformation(SystemHandleInformation, pHandleInfo, size, &size)
       == STATUS_INFO_LENGTH_MISMATCH) {
    VirtualFree(pHandleInfo, 0, MEM_RELEASE);
    pHandleInfo = VirtualAlloc(NULL, size, MEM_COMMIT, PAGE_READWRITE);
}
// pHandleInfo->Handles[] — Object field is _OBJECT_HEADER ptr >> 4
// Useful for KASLR partial bypass and handle table location
```

### 3.4 Key WinDbg Handle Commands

```windbg
; Dump handle table for a process
!handle 0 7 <pid>         ; all handles with type and name

; Dump a specific handle
!handle <handle_value> 7

; Inspect handle table entry directly
dt nt!_HANDLE_TABLE_ENTRY <address>

; Find all handles referencing a specific object
!object <object_address>  ; shows handle count

; All File handles across all processes
!handle 0 7 0 File

; Enumerate handle table structure
dt nt!_HANDLE_TABLE <EPROCESS.ObjectTable>
```

---

## 4. Symbolic Link Taxonomy

Windows has six meaningfully distinct link types, each operating at a different layer of the
name resolution stack. Understanding the differences is essential for designing attacks.

| Type | Privilege Required | Redirection Level | Creation API | Cross-Volume? |
|---|---|---|---|---|
| **NTFS Junction (Mount Point)** | None (write to parent dir) | Directory-level, NTFS layer | `fsutil reparsepoint set` / `CreateJunction` | ❌ No |
| **NTFS File Symlink** | `SeCreateSymbolicLinkPrivilege` or Developer Mode | File or directory, NTFS layer | `CreateSymbolicLink` | ✅ Yes |
| **Object Manager Symlink** | None (create access in target dir) | Object namespace, before NTFS | `NtCreateSymbolicLinkObject` | ✅ Yes |
| **DosDevice Override** | None (for current user session) | Drive letter / device name | `DefineDosDevice` | ✅ Yes |
| **Registry Symlink** | Write access to source key | Registry key namespace | `NtSetValueKey` with `REG_LINK` type | N/A |
| **Hard Link** | Write access to directory; same volume | File identity (MFT-level) | `CreateHardLink` | ❌ No |

### 4.1 Attack Design Rules

1. **NTFS junctions** require no privilege and are transparently followed by most privileged
   services. A junction at `C:\Users\Public\AttackerDir\` → `C:\Windows\System32\` means any
   file created through that junction lands in System32.

2. **Object Manager symlinks** in `\??` operate *before* the NTFS layer. `OBJ_DONT_REPARSE`
   (which suppresses NTFS reparse traversal) does NOT protect against them.

3. **DosDevice overrides** via `DefineDosDevice` only affect the calling user's session device
   map. If a privileged service in the same session resolves `\??\MySoftwareDevice`, a
   user-created DosDevice can redirect it.

4. **Registry symlinks** (`REG_LINK` value type) allow a user-writable `HKCU` key to
   transparently redirect writes to an `HKLM` key — "arbitrary registry write" from limited write.

5. **Hard links** do not redirect names — they create an additional directory entry pointing to
   the same MFT record. The security descriptor is on the MFT record, not the path. If a
   privileged process deletes "its" file by name, an attacker's hard link still references the
   same inode.

### 4.2 NtCreateSymbolicLinkObject Hardening and Bypass (2024)

Windows added hardening around `NtCreateSymbolicLinkObject` to prevent unprivileged symlink
creation in sensitive namespace paths. Bypass research (itm4n 2024) identified two categories:

1. **Object Type filtering weaknesses** — specific object type checks that can be bypassed via
   alternate creation paths
2. **Session namespace isolation flaws** — per-session namespace handling edge cases

The `\RPC Control\` directory remains partially accessible to unprivileged users for symlink
planting — demonstrated at HITB 2024 as a UAC bypass on fully-patched Windows 11 23H2.

```powershell
# Audit: can current user create objects in \RPC Control\?
Get-AccessibleObject -NtType Directory -Path "\RPC Control" -AccessRights CreateObject
```

---

## 5. Directory Objects and DACL Weaknesses

### 5.1 How Directory DACLs Create Attack Surface

Every `_OBJECT_DIRECTORY` has a security descriptor. The critical access rights for attackers:

- **`DIRECTORY_CREATE_OBJECT`**: Allows creating a new named object inside the directory. If a
  lower-privilege process has this right on a directory that a higher-privilege process uses for
  name lookups, it can **pre-plant** a malicious object at the expected name.
- **`DIRECTORY_QUERY`**: Allows enumerating directory contents.
- **`DIRECTORY_TRAVERSE`**: Allows lookup of names in the directory.

### 5.2 Default DACLs on Key Directories

| Directory | Default ACL | Attack Implication |
|---|---|---|
| `\BaseNamedObjects\` | Authenticated Users: `CREATE_OBJECT` | Object squatting from any session |
| `\Sessions\<N>\BaseNamedObjects\` | Session N users: create access | Weak cross-user isolation in same session |
| `\Device\` | SYSTEM only creates objects | No user-space squatting |
| `\KnownDlls\` | SYSTEM only | If writable: DLL hijack of every loader |
| `\RPC Control\` | Partial user access | Symlink planting (see 4.2) |

### 5.3 Object Directory Squatting Attack Pattern

```
Precondition:
  - Lower-privilege attacker can create objects in \BaseNamedObjects (default)
  - Privileged service creates \BaseNamedObjects\ServiceInitMutex at startup
    to prevent re-initialization

Attack:
  1. Attacker creates \BaseNamedObjects\ServiceInitMutex before service starts
  2. Service calls NtOpenMutant(\BaseNamedObjects\ServiceInitMutex) — succeeds (attacker's object)
  3. Service checks "mutex already exists" → skips initialization path
  4. Service enters production state without proper initialization
  5. Effect: may expose unauthenticated RPC, skip privilege drop, etc.

PowerShell PoC:
  $mut = New-NtMutant -Path \BaseNamedObjects\ServiceInitMutex -Win32Path $false
  # Start the service; observe whether it skips initialization
```

```powershell
# Find all namespace directories where current user has CreateObject rights
Get-AccessibleObject -NtType Directory -Path \ -Recurse -AccessRights CreateObject |
  Format-Table Name, GrantedAccess
```

### 5.4 Shadow Object Directory Technique (Forshaw / Project Zero 2024)

`NtCreateDirectoryObjectEx` (available since Windows 10 1703) accepts a `ShadowDirectory`
parameter that creates a **shadow directory** — an overlay over an existing system directory
in the Object Manager namespace. Objects in the shadow directory are resolved *before* the
original directory.

**Attack application:**
- Create shadow directory overlaying `\KnownDlls`
- Plant a fake section object in the shadow directory
- Privileged processes loading from `\KnownDlls` resolve the shadow first → load attacker DLL

**Security implication:** The shadow directory technique allows redirecting privileged name
lookups **without** `SeCreateSymbolicLinkPrivilege` and without touching the original directory's
DACL. The `sandbox-attacksurface-analysis-tools` codebase was updated in 2024 to enumerate
shadow directory relationships on Windows 11 24H2 and Server 2025.

---

## 6. ObpLookupObjectName: Name Resolution Internals

### 6.1 The Resolution Algorithm

`ObpLookupObjectName` is the kernel function responsible for resolving a Unicode string path
through the object namespace tree.

```
INPUT: UNICODE_STRING path (e.g., "\??\C:\Windows\notepad.exe")
       OBJECT_ATTRIBUTES flags (OBJ_DONT_REPARSE, OBJ_IGNORE_IMPERSONATED_DEVICEMAP, etc.)
       RootDirectory handle (optional)

STEP 1: If path starts with \, start at root directory (\)
        Otherwise, start at RootDirectory

STEP 2: Tokenize path by \

STEP 3: For each component:
  a. Look up component name in current _OBJECT_DIRECTORY's hash table
  b. If found and it's a _OBJECT_SYMBOLIC_LINK:
       - If OBJ_DONT_REPARSE is set → return STATUS_REPARSE_POINT_NOT_RESOLVED (fail)
       - If OBJ_OPENLINK is set → return the symlink object itself
       - Otherwise: substitute symlink's target string + remaining path, restart from step 1
  c. If found and it's a _OBJECT_DIRECTORY: descend into it
  d. Not found: return STATUS_OBJECT_NAME_NOT_FOUND

STEP 4: Remaining path components passed to the object's parse routine
        (e.g., NTFS parse routine receives "\Windows\notepad.exe")
```

**Symlink substitution:** Happens at step 3b, *inside* the traversal loop. The substituted path
is re-resolved from the beginning — object manager symlinks redirect the *entire remaining lookup*.

### 6.2 The \?? Virtual Directory

When `ObpLookupObjectName` encounters `??` as the second path component (after `\`), it does NOT
look for an `_OBJECT_DIRECTORY` named `??`. Instead it queries:

1. If calling **thread** is impersonating: use the impersonated thread's device map
   (unless `OBJ_IGNORE_IMPERSONATED_DEVICEMAP` is set)
2. Otherwise: use the calling **process**'s device map (`_EPROCESS.DeviceMap`)

Two processes in different logon sessions, or the same process before and after impersonation,
may resolve identical `\??\C:\...` paths to **different devices**.

---

## 7. Device Map and Drive Letter Redirection Attacks

### 7.1 Architecture

Each logon session gets its own Device Map. When a thread impersonates a different user via
`NtSetInformationThread` or `ImpersonateLoggedOnUser`, the thread's `_KTHREAD.ImpersonationInfo`
points to the impersonated user's token, which carries the impersonated session's device map.

```windbg
dt nt!_EPROCESS <addr> DeviceMap
dt nt!_DEVICE_MAP <addr>
!object \??\C:
```

### 7.2 The Impersonated Device Map Attack

**Vulnerable pattern:** A SYSTEM service impersonates a user (for access checking) then opens
a file using a drive-letter path — without `OBJ_IGNORE_IMPERSONATED_DEVICEMAP`:

```c
ImpersonateLoggedOnUser(userToken);

OBJECT_ATTRIBUTES attrs;
InitializeObjectAttributes(&attrs, &fileName, OBJ_CASE_INSENSITIVE, NULL, NULL);
// BUG: path resolved using impersonated user's device map
NtCreateFile(&handle, GENERIC_READ, &attrs, &iosb, ...);

RevertToSelf();
```

**Attack:**
1. Attacker modifies their session's device map:
   `DefineDosDevice("C", "\Device\NamedPipe\AttackerPipe")`
2. Privileged service impersonates attacker's token
3. Service resolves `\??\C:\SensitiveFile` → `\Device\NamedPipe\AttackerPipe`
4. Attacker calls `ImpersonateNamedPipeClient()` → receives SYSTEM token

**Fix:** Add `OBJ_IGNORE_IMPERSONATED_DEVICEMAP` (0x2000) to OBJECT_ATTRIBUTES flags:
```c
InitializeObjectAttributes(&attrs, &fileName,
    OBJ_CASE_INSENSITIVE | OBJ_IGNORE_IMPERSONATED_DEVICEMAP, NULL, NULL);
```

Audit: search all `NtCreateFile`/`ZwCreateFile` call sites in service binaries that perform
impersonation — absence of `0x2000` in Attributes when operating on drive-letter paths
= vulnerability indicator.

**2024 update — Jonas Lyk fork:** The `symboliclink-testing-tools` fork by Jonas Lyk (2024)
adds improved device map manipulation utilities targeting thread-impersonating services on
Windows 11 specifically.

---

## 8. Oplock + Junction TOCTOU Pattern for LPE

### 8.1 Background: What Makes TOCTOU Hard Without Oplocks

Classic TOCTOU races without synchronization require winning a nanosecond window between
a privileged service's check and use operations. Against modern multicore CPUs, this is
unreliable. Opportunistic locks (oplocks) solve this by converting the nanosecond race window
into an indefinitely-large, attacker-controlled window.

### 8.2 Opportunistic Lock Types for Exploitation

| Type | Break Trigger | Exploit Utility |
|---|---|---|
| Level 1 (exclusive) | Any other open | Too broad — breaks too early |
| Batch | Any open by other process | Better — fires at open time |
| Filter | Open for read/write by other process | Best — fires before data transfer |
| `FSCTL_REQUEST_OPLOCK` (atomic, Win7+) | Configurable via flags | Best — full control |

The **Filter oplock** fires when another process attempts to open the oplocked file with
conflicting access — before any data transfer. Ideal synchronization point.

### 8.3 BaitAndSwitch Step-by-Step

```
SETUP (attacker):
  1. Create directory:  C:\Temp\BaitDir\
  2. Create file:       C:\Temp\BaitDir\target.dll  (the "bait")
  3. Request Filter oplock on C:\Temp\BaitDir\target.dll

EXECUTION TIMELINE:
  T0: Privileged service (SYSTEM) opens C:\Temp\BaitDir\target.dll
      ↓
  T1: Kernel fires oplock break notification to attacker.
      Service's open call is BLOCKED.

  T2: Attacker receives break notification.
      - Remove directory C:\Temp\BaitDir\
      - Create NTFS junction C:\Temp\BaitDir → C:\Windows\System32\

  T3: Attacker releases the oplock.

  T4: Blocked service operation resumes.
      C:\Temp\BaitDir\target.dll now resolves to:
        C:\Windows\System32\target.dll
      SYSTEM writes to C:\Windows\System32\target.dll

  T5: Attacker's DLL in System32 → next privileged load → code execution
```

**Key insight:** The service does not re-validate the path after the oplock break. It holds
an in-flight IRP that completes with the *new* resolution of the path.

### 8.4 In-the-Wild Oplock Exploitation (2024-2025)

Oplock-based techniques are **actively exploited by threat actors**:

**CVE-2024-21338 (February 2024)** — `appid.sys` Windows AppLocker filter driver
- Oplock-based race condition in IOCTL handler; missing re-validation after oplock break
- **Exploited in the wild by Lazarus Group (North Korea)** to deliver malware
- CVSS 7.8 — https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-21338

**CVE-2024-30051 (May 2024)** — DWM Core Library
- Desktop Window Manager — oplock-assisted arbitrary file write → LPE
- **Zero-day exploited in the wild** by QakBot/Black Basta ransomware before patch
- CVSS 7.8 — https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-30051

**CVE-2024-38193 / CVE-2024-38014 (August 2024)**
- AFD.sys driver and Windows Installer hard link abuse
- Windows Installer (SYSTEM) follows hard links without validation → arbitrary file overwrite
- Used by APT groups and ransomware for post-initial-access LPE

### 8.5 From Arbitrary File Write to Full LPE

```
CHAIN:
  1. Identify: Service SYSTEM writes to C:\ProgramData\Vendor\update.dll
  2. Plant bait: Oplock on C:\ProgramData\Vendor\update.dll
  3. Wait for oplock break: Service validates path → triggers oplock
  4. Swap directory: junction C:\ProgramData\Vendor\ → C:\Windows\System32\
  5. Release oplock: Service writes to System32\update.dll
  6. DLL hijack: Update.dll loaded by SYSTEM process → LPE

WINDOWS INSTALLER REPAIR VARIANT (no oplock needed):
  1. Write DLL to C:\Windows\System32\<dll>.dll via arbitrary write primitive
  2. Trigger msiexec /fau <MSI GUID> (Windows Installer repair)
  3. MSI repair loads DLLs in SYSTEM context → code execution
```

### 8.6 Oplock APIs

```c
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

`SetOpLock.exe` from `symboliclink-testing-tools` automates this for PoC development.

---

## 9. Recent Developments (2024–2025)

### 9.1 Actively Exploited CVEs

| CVE | Component | Technique | Severity | Status |
|---|---|---|---|---|
| CVE-2024-21310 | Cloud Files Mini Filter (cldflt.sys) | Symbolic link following → arbitrary write | 7.8 | Patched Jan 2024 |
| CVE-2024-26218 | Windows Kernel Object Manager | Namespace symlink manipulation → LPE | 7.8 | Patched Apr 2024 |
| CVE-2024-30088 | Windows Kernel | TOCTOU race + hard link swap | 7.0 | Patched Jun 2024 |
| CVE-2024-21338 | appid.sys (AppLocker) | Oplock race condition — exploited in wild (Lazarus) | 7.8 | Patched Feb 2024 |
| CVE-2024-30051 | DWM Core Library | Oplock file write 0-day — exploited in wild (QakBot) | 7.8 | Patched May 2024 |
| CVE-2024-38193 | AFD.sys | Hard link + SYSTEM file operation abuse | High | Patched Aug 2024 |
| CVE-2025-21333 | Hyper-V NT Kernel Integration VSP | Object dir symlink chain — 0-day | Critical | Patched Jan 2025 |
| CVE-2025-21334 | Hyper-V NT Kernel Integration VSP | Object manager namespace chain — 0-day | Critical | Patched Jan 2025 |
| CVE-2025-21335 | Hyper-V NT Kernel Integration VSP | Related 0-day | Critical | Patched Jan 2025 |

**CVE-2025-21333/34/35 — January 2025 Hyper-V 0-days:**
Three Hyper-V VSP LPE vulnerabilities exploited in the wild before patch. Object directory symlink
manipulation is part of the attack chain. Affects Windows 11 and Server 2025. Technical writeups
from MSRC expected as disclosure timelines complete.

### 9.2 Windows 11 24H2 / Server 2025 Namespace Hardening

- **NTFS Symbolic Link Hardening:** Improved reparse point handling + ACL enforcement for
  system-protected directories. Legacy compatibility mode retains some bypass vectors.
- **Named pipe hardening (Server 2025):** Mandatory integrity level checks on pipe connections,
  restricted anonymous pipe access, new ETW telemetry. SpecterOps and MDSec demoed bypasses
  via ALPC callback abuse and undocumented `NtAlpcSendWaitReceivePort` parameters.
- **VBS/HVCI enabled by default** on new 24H2 installations — kernel data structure tampering
  prevented from user mode.

---

## 10. Key WinDbg Commands for Object Manager Research

```windbg
; ─── NAMESPACE NAVIGATION ───────────────────────────────────────────
!object \                       ; root directory and contents
!object \Device                 ; device directory
!object \Device\NamedPipe       ; named pipe device
!object \BaseNamedObjects       ; user named objects
!object \Sessions\1\BaseNamedObjects  ; per-session named objects

; ─── STRUCTURE INSPECTION ────────────────────────────────────────────
dt nt!_OBJECT_HEADER <addr>
dt nt!_OBJECT_DIRECTORY <addr>
dt nt!_OBJECT_SYMBOLIC_LINK <addr>  ; LinkTarget UNICODE_STRING
dt nt!_DEVICE_MAP <addr>

; ─── HANDLE OPERATIONS ───────────────────────────────────────────────
!handle 0 7 <pid>               ; all handles in process with type/name
!handle 0 7 0 File              ; all File handles in all processes
!handle <value> f               ; full detail for one handle
dt nt!_HANDLE_TABLE <EPROCESS.ObjectTable>

; ─── OBJECT TYPE TABLE ───────────────────────────────────────────────
dt nt!ObpObjectTypes            ; array of _OBJECT_TYPE pointers
dt nt!_OBJECT_TYPE <addr>

; ─── EPROCESS DEVICE MAP ─────────────────────────────────────────────
dt nt!_EPROCESS <addr> DeviceMap
!process 0 0 <name.exe>

; ─── DECODE TYPEINDEX ────────────────────────────────────────────────
? nt!ObHeaderCookie
; header_addr = object_addr - 0x30, TypeIndex byte at header_addr + 0x18
? (poi(nt!ObHeaderCookie) & 0xff) ^ ((<hdr_addr> >> 8) & 0xff) ^ (by(<hdr_addr>+0x18) & 0xff)
```

---

## 11. Research Methodology: Auditing the Object Namespace

**Step 1: Enumerate writeable directories**
```powershell
Get-AccessibleObject -NtType Directory -Path \ -Recurse -AccessRights CreateObject |
  Format-Table Name, GrantedAccess
```

**Step 2: Identify privileged name lookups**
ProcMon filter: `Operation=CreateFile, User=SYSTEM` — focus on paths through user-writable
namespace directories.

**Step 3: Check for OBJ_DONT_REPARSE (0x1000)**
In IDA/Ghidra: find all `NtCreateFile`/`ZwCreateFile` call sites. Check `OBJECT_ATTRIBUTES.Attributes`
for `0x1000`. Absence on user-influenced paths = vulnerability indicator.

**Step 4: Check for OBJ_IGNORE_IMPERSONATED_DEVICEMAP (0x2000)**
Find code paths calling `NtCreateFile` after an impersonation call. Absence of `0x2000` in
Attributes when operating on drive-letter paths under impersonation = vulnerability.

**Step 5: Shadow directory enumeration**
```powershell
Import-Module NtObjectManager
# Enumerate namespace looking for shadow directory relationships
Get-NtDirectory -Path "\" | Get-NtDirectoryEntry | ForEach-Object {
    if ($_.Object -is [NtApiDotNet.NtDirectory]) {
        $sd = Get-NtSecurityDescriptor -Object $_.Object -ErrorAction SilentlyContinue
        Write-Output "$($_.Name): $($sd?.Dacl?.Count) DACL entries"
    }
}
```

**Step 6: Build exploit chain**
- File rename operation: BaitAndSwitch with junction swap
- Registry write: registry symlink redirect  
- Named object lookup: object squatting
- Shadow directory available: plant shadow objects for privileged lookup redirection

---

## References

[R-1] *Windows Security Internals* — James Forshaw (No Starch Press, 2023) — https://nostarch.com/windows-security-internals

[R-2] *Windows Exploitation Tricks: Exploiting Arbitrary File Writes for Local Elevation of Privilege* — James Forshaw / Google Project Zero (2018) — https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html

[R-3] *Windows Exploitation Tricks: Exploiting Arbitrary Object Directory Creation for LPE* — James Forshaw / Google Project Zero (2018) — https://googleprojectzero.blogspot.com/2018/08/windows-exploitation-tricks-exploiting.html

[R-4] *Abusing the NT Object Manager Namespace* — James Forshaw / DEF CON 25 (2017)

[R-5] *symboliclink-testing-tools* — James Forshaw / Google Project Zero — https://github.com/googleprojectzero/symboliclink-testing-tools

[R-6] *sandbox-attacksurface-analysis-tools (NtObjectManager)* — James Forshaw / Google Project Zero — https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools

[R-7] *CVE-2024-21338 — Lazarus Group 0-day in appid.sys* — Avast Threat Intelligence — https://decoded.avast.io/

[R-8] *CVE-2024-30051 — DWM 0-day exploited by QakBot/Black Basta* — MSRC — https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-30051

[R-9] *CVE-2025-21333/334/335 — Hyper-V NT Kernel Integration 0-days* — MSRC — https://msrc.microsoft.com/update-guide/

[R-10] *NtCreateSymbolicLinkObject Hardening Bypass (2024)* — itm4n — https://itm4n.github.io/

[R-11] *tiraniddo.dev — Object Manager Research Series* — James Forshaw — https://www.tiraniddo.dev/

[R-12] *Windows Object Manager — Deep Technical Analysis* — Geoff Chappell — https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ob/
