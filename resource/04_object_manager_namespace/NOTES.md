# Object Manager Namespace — Research Notes

> Notes on attack techniques, structures, code patterns, and open research threads
> related to the Windows Object Manager namespace.

---

## Core Mental Model: Three Layers of the Namespace

```
Layer 1: The Object Namespace Tree
────────────────────────────────────
\  ← _OBJECT_DIRECTORY (root)
├── Device\     ← _OBJECT_DIRECTORY
│   ├── Harddisk0\DR0  ← _DEVICE_OBJECT
│   ├── NamedPipe      ← _DEVICE_OBJECT
│   └── HarddiskVolume3 ← _DEVICE_OBJECT
├── BaseNamedObjects\  ← _OBJECT_DIRECTORY
│   ├── SomeEvent      ← _EVENT  (created by user-mode code)
│   └── SomeMutex      ← _MUTANT
└── REGISTRY\
    └── MACHINE\       ← Registry CM objects

Layer 2: The Per-Session Overlay
────────────────────────────────────
\Sessions\1\BaseNamedObjects\ ← session-scoped user objects
\Sessions\1\AppContainerNamedObjects\<SID>\ ← AppContainer scoped

Layer 3: The Per-Process Device Map (\\?\ resolution)
────────────────────────────────────
_EPROCESS.DeviceMap → _DEVICE_MAP
    Maps: "C:" → "\Device\HarddiskVolume3"
          "UNC" → "\Device\Mup"
          etc.
The \?? directory is backed by this device map, NOT by a real object directory.
```

---

## Object Header Anatomy (Windows 10/11 x64)

```c
// _OBJECT_HEADER layout (approximate, verify with dt in WinDbg)
typedef struct _OBJECT_HEADER {
    LONGLONG   PointerCount;    // +0x000 Reference count
    union {
        LONGLONG HandleCount;   // +0x008 Handle count (when not in free list)
        PVOID NextToFree;       // +0x008 (when in free list)
    };
    EX_PUSH_LOCK Lock;          // +0x010 Push lock for header modifications
    UCHAR TypeIndex;            // +0x018 Index into ObpObjectTypes[] (XOR'd with cookie)
    union {
        UCHAR TraceFlags;       // +0x019
        struct {
            UCHAR DbgRefTrace : 1;
            UCHAR DbgTracePermanent : 1;
        };
    };
    UCHAR InfoMask;             // +0x01A Optional header presence bitmask
    union {
        UCHAR Flags;            // +0x01B
        struct {
            UCHAR NewObject : 1;
            UCHAR KernelObject : 1;
            UCHAR KernelOnlyAccess : 1;
            UCHAR ExclusiveObject : 1;
            UCHAR PermanentObject : 1;
            UCHAR DefaultSecurityQuota : 1;
            UCHAR SingleHandleEntry : 1;
            UCHAR DeletedInline : 1;
        };
    };
    ULONG Spare;                // +0x01C
    union {
        OBJECT_CREATE_INFORMATION *ObjectCreateInfo; // +0x020
        PVOID QuotaBlockCharged;
    };
    PVOID SecurityDescriptor;   // +0x028 Optional; pointer into security cache
    QUAD Body;                  // +0x030 Object body starts here
} OBJECT_HEADER;

// BODY = OBJECT_HEADER.Body (offset 0x30 from header start)
// To get header from body: subtract 0x30
// Common exploit pattern: CONTAINING_RECORD(body_ptr, OBJECT_HEADER, Body)
```

### TypeIndex XOR Encoding (Windows 8+)

```c
// TypeIndex in _OBJECT_HEADER is NOT a direct index.
// It is XOR'd with a cookie based on the object header address.
//
// To decode TypeIndex:
// real_index = TypeIndex XOR ObHeaderCookie XOR ((ULONG_PTR)&ObjectHeader >> 8) & 0xFF
//
// In WinDbg:
// ? (poi(nt!ObHeaderCookie) & 0xff) ^ (((<ObjectHeaderAddr>) >> 8) & 0xff) ^ poi(<ObjectHeaderAddr>+0x18) & 0xff

// Why this matters for exploits:
// If you corrupt TypeIndex, you redirect dispatch operations to a fake OBJECT_TYPE.
// With an arbitrary kernel write primitive:
//   1. Find an object header you can reach
//   2. Corrupt TypeIndex to point to a fake type object you've crafted
//   3. Trigger type-dispatch operation (close handle, etc.)
//   → Kernel executes your fake dispatch routine
```

---

## Symbolic Link Attack Patterns

### Pattern 1: Race-Free Object Directory Squatting

**Precondition:** Privileged code does `NtCreateMutant(\BaseNamedObjects\PrivMutex, ...)` at startup.
**Attack:** Create `\BaseNamedObjects\PrivMutex` before the service starts.
**Effect:** Service opens attacker's mutant → service may behave incorrectly (e.g., skip initialization).

```powershell
# Create a named object before the service
$mut = New-NtMutant -Path \BaseNamedObjects\PrivMutex -Win32Path $false
# Now start the service and observe behavior
```

### Pattern 2: NTFS Junction + Oplock TOCTOU

**Precondition:** Privileged code does:
1. `CreateFile(C:\Logs\output.txt, CREATE_ALWAYS)` — creates a file
2. `DeleteFile(C:\Logs\output.txt)` — deletes it
3. `MoveFile(C:\Logs\output.txt.tmp, C:\Logs\output.txt)` — moves temp → final

**Attack window:** Between step 1 (verify: path exists) and step 3 (use: move file):
1. Hold oplock on `C:\Logs\output.txt.tmp`
2. Wait for privileged code to reach the MoveFile call
3. Release oplock, race: replace `C:\Logs\` with junction → `C:\Windows\System32\`
4. MoveFile now writes to `C:\Windows\System32\output.txt` as SYSTEM

```
Timeline:
T0: Attacker creates oplock on C:\Logs\output.txt.tmp
T1: Service validates C:\Logs\ exists → OK
T2: Service opens C:\Logs\output.txt.tmp → oplock fires → service pauses
T3: Attacker removes C:\Logs\ directory
T4: Attacker creates junction C:\Logs → C:\Windows\System32\
T5: Attacker releases oplock
T6: Service resumes, executes MoveFile(C:\Logs\..., C:\Windows\System32\output.txt)
    → SYSTEM writes an attacker-controlled file to System32
T7: Attacker uses this to plant DLL → hijack privileged process
```

### Pattern 3: Registry Symlink + Arbitrary Write

**Precondition:** Attacker has arbitrary write to any HKCU registry key.
**Target:** A SYSTEM service reads from HKLM\SOFTWARE\SomeApp\Config.

```
Attack:
1. Check if the target registry path goes through any user-modifiable key
2. Create HKCU\Software\Classes\SomeApp as a REG_LINK symlink
   pointing to HKLM\SOFTWARE\SomeApp
3. Any write to HKCU\Software\Classes\SomeApp\Config
   → redirected to HKLM\SOFTWARE\SomeApp\Config
```

```powershell
# Create registry symlink (requires native API)
# Using NtObjectManager:
$key = New-NtKey -Path \REGISTRY\USER\<SID>\Software\Classes\TestKey `
  -Win32Path $false -Disposition CreateNew
# Then set REG_LINK value pointing to target
# (requires low-level NtSetValueKey call with type REG_LINK = 6)
```

### Pattern 4: DosDevice Squatting (User Session)

**Precondition:** Privileged code (running as user, not SYSTEM) accesses `\\.\MySoftwareDevice`.
**Attack:** `DefineDosDevice("MySoftwareDevice", "\Device\NamedPipe\AttackerPipe")` in same session.
**Effect:** Privileged code opens attacker's named pipe instead of real device.

```powershell
# Create DosDevice mapping
[System.IO.Directory]::Exists("\\.\FakeDev")
# Using Win32 API:
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public class WinAPI {
    [DllImport("kernel32.dll")]
    public static extern bool DefineDosDevice(uint flags, string devname, string target);
}
"@
[WinAPI]::DefineDosDevice(0, "FakeDev", "\Device\NamedPipe\AttackerPipe")
```

---

## Device Map Deep Dive

```
Normal resolution:
  Process accesses "C:\Windows\notepad.exe"
    → NtCreateFile with path "\??\C:\Windows\notepad.exe"
    → ObpLookupObjectName sees "\??"
    → Looks up _EPROCESS.DeviceMap
    → Device map maps "C" → "\Device\HarddiskVolume3"
    → Full resolved path: "\Device\HarddiskVolume3\Windows\notepad.exe"

Under impersonation (without OBJ_IGNORE_IMPERSONATED_DEVICEMAP):
  Service running as SYSTEM impersonates User A
  Service accesses "C:\Users\UserA\config"
    → NtCreateFile with path "\??\C:\Users\UserA\config"
    → ObpLookupObjectName sees "\??"
    → Looks up IMPERSONATED THREAD's device map (User A's device map)
    → If User A's device map maps "C" differently → different path resolution!

Bug pattern:
  1. Attacker controls User A's logon session
  2. Attacker modifies User A's device map (e.g., "C" → "\Device\NamedPipe\AttackerPipe")
  3. Service impersonates User A and accesses "C:\..." → redirected to attacker's device
```

**The fix:** Use `OBJ_IGNORE_IMPERSONATED_DEVICEMAP` flag in `OBJECT_ATTRIBUTES.Attributes` when the privileged code should always use the service's own device map, not the impersonated user's.

```c
// Correct (secure) code pattern:
OBJECT_ATTRIBUTES attrs;
InitializeObjectAttributes(&attrs, &fileName, OBJ_IGNORE_IMPERSONATED_DEVICEMAP, NULL, NULL);
NtCreateFile(&handle, GENERIC_READ, &attrs, ...);
```

---

## Key NT Native API for Object Manager Research

```c
// Object directory operations
NTSTATUS NtCreateDirectoryObject(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
NTSTATUS NtOpenDirectoryObject(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
NTSTATUS NtQueryDirectoryObject(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG);

// Symbolic link operations
NTSTATUS NtCreateSymbolicLinkObject(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PUNICODE_STRING);
NTSTATUS NtOpenSymbolicLinkObject(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES);
NTSTATUS NtQuerySymbolicLinkObject(HANDLE, PUNICODE_STRING, PULONG);

// Object lookup (internal, not exported)
// Use via NtObjectManager's NtApiDotNet wrapper

// Device map
NTSTATUS NtSetSystemInformation(
    SystemSessionProcessInformation, ...); // indirect device map manipulation

// Registry key operations with symlink support
NTSTATUS NtCreateKey(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, ULONG, PUNICODE_STRING, ULONG, PULONG);
// REG_LINK value created via NtSetValueKey with Type = REG_LINK (6)

// Oplock operations
NTSTATUS NtFsControlFile(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID,
    PIO_STATUS_BLOCK, ULONG FsControlCode, ...);
// FSCTL_REQUEST_OPLOCK_LEVEL_1 = 0x00090010
// FSCTL_OPLOCK_BREAK_NOTIFY   = 0x00090018
```

---

## Exploit Primitive Chains

### Chain A: Any File Write → EoP (Forshaw's Generic Methodology)

```
INGREDIENT: Arbitrary file write as SYSTEM to attacker-controlled filename

CHAIN:
1. Create NTFS junction: C:\Windows\Temp\<guid>\ → C:\Windows\System32\
2. Create hard link: C:\Windows\Temp\<guid>\target.dll → C:\Windows\System32\target.dll
   (hard link so deletion via junction redirects correctly)
3. Use oplock on an intermediate file to create race window
4. Trigger arbitrary write → file lands in System32
5. DLL hijack: place payload.dll as System32\target.dll
6. Wait for privileged process to load it

OR (registry variant):
1. Create registry symlink in HKCU pointing to HKLM sensitive key
2. Trigger arbitrary registry write → value written to HKLM
3. Hijack service configuration
```

### Chain B: Object Directory Write → Mutex/Event Squatting

```
INGREDIENT: Write access to \BaseNamedObjects (standard Windows configuration)

CHAIN:
1. Monitor a privileged service with Process Monitor (filter: category=Process)
2. Find: service creates \BaseNamedObjects\ServiceMutex on startup
3. Pre-create \BaseNamedObjects\ServiceMutex (attacker-owned)
4. Service opens existing mutex (attacker's) → service skips initialization
5. Race: attacker releases mutex at the right time
6. Service runs with incorrect state → exploit-dependent behavior
```

### Chain C: Named Pipe + Impersonation (combined with object namespace)

```
INGREDIENT: \Device\NamedPipe\<KnownPipeName> squatting

CHAIN:
1. Identify: privileged process connects to named pipe \Device\NamedPipe\Target
2. Create pipe server at that path first (from a low-priv session)
3. Privileged process connects to attacker's pipe
4. Call ImpersonateNamedPipeClient()
5. With impersonated SYSTEM token + SeImpersonatePrivilege → escalate
```

---

## Open Research Questions

- [ ] In Windows 11, what is the exact DACL on `\BaseNamedObjects` and `\Sessions\<N>\BaseNamedObjects`? Has it been tightened compared to Windows 10?
- [ ] Can an AppContainer process create objects in `\Sessions\<N>\BaseNamedObjects` (non-AppContainer namespace)? What prevents this?
- [ ] Does the `OBJ_IGNORE_IMPERSONATED_DEVICEMAP` flag appear consistently across all file system operations in NTFS.sys, or are there codepaths that miss it?
- [ ] What is the security descriptor on `\Device\NamedPipe` itself? Can a standard user create named pipe objects there?
- [ ] How does `NtLoadKey` validate the target path in the registry namespace? Can a user-controlled hive file be loaded into a path that overlaps with HKLM?
- [ ] Does Windows 11 22H2+ have any new hardening on object directory lookup that prevents squatting in `\BaseNamedObjects`?

---

## Useful References (Quick Links)

| Topic | Link |
|-------|------|
| NT Native API reference | https://ntdoc.m417z.com/ |
| Geoff Chappell object manager | https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ob/ |
| Forshaw arbitrary write blog | https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html |
| symboliclink-testing-tools | https://github.com/googleprojectzero/symboliclink-testing-tools |
| sandbox-attacksurface-analysis-tools | https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools |
| WinObj | https://learn.microsoft.com/en-us/sysinternals/downloads/winobj |
| NtApiDotNet | https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools/tree/main/NtApiDotNet |

---

*Section: 04_object_manager_namespace/NOTES.md | Last updated: 2026-04-22*
