# 05 · RPC / COM / ALPC / Named Pipes — NOTES

## IPC Security Architecture Overview

### The Four Layers

```
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 4: APPLICATION / COM OBJECT MODEL                         │
│  CoCreateInstance, IDispatch, DCOM activation, Elevation Moniker │
│  Security: LaunchPermission, AccessPermission, RunAs             │
└───────────────────────────┬─────────────────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 3: RPC RUNTIME                                            │
│  Interface UUID, endpoint binding, authentication level          │
│  Security: AuthenticationLevel (None/Connect/Call/Pkt/Privacy)   │
│            ImpersonationLevel (Identify/Impersonate/Delegate)    │
└───────────────────────────┬─────────────────────────────────────┘
                            ↓ (transport)
┌──────────────────┬──────────────────┬───────────────────────────┐
│  ncalrpc         │  ncacn_np        │  ncacn_ip_tcp             │
│  (ALPC kernel)   │  (Named Pipe)    │  (TCP socket)             │
└──────────────────┴──────────────────┴───────────────────────────┘
                            ↓
┌─────────────────────────────────────────────────────────────────┐
│  LAYER 1: NT KERNEL                                              │
│  ALPC port objects, Named Pipe file objects, Winsock             │
│  Security: Object security descriptors, mandatory integrity      │
└─────────────────────────────────────────────────────────────────┘
```

---

## RPC Security Model

### Authentication Levels (from weakest to strongest)

| Level | Value | Meaning |
|-------|-------|---------|
| `RPC_C_AUTHN_LEVEL_NONE` | 1 | No authentication — anonymous calls |
| `RPC_C_AUTHN_LEVEL_CONNECT` | 2 | Authenticate connection establishment only |
| `RPC_C_AUTHN_LEVEL_CALL` | 3 | Authenticate each call (header only) |
| `RPC_C_AUTHN_LEVEL_PKT` | 4 | Authenticate all packets |
| `RPC_C_AUTHN_LEVEL_PKT_INTEGRITY` | 5 | Authenticate + sign all packets |
| `RPC_C_AUTHN_LEVEL_PKT_PRIVACY` | 6 | Authenticate + sign + encrypt all packets |

**Security implication:** Interfaces with `RPC_C_AUTHN_LEVEL_NONE` or `RPC_C_AUTHN_LEVEL_CONNECT` can be called without a valid credential. PrintNightmare's coercion method used `RPC_C_AUTHN_LEVEL_NONE` initially.

### Impersonation Levels

| Level | Meaning | Attack use |
|-------|---------|------------|
| `RPC_C_IMP_LEVEL_ANONYMOUS` | Server cannot identify client | Minimal |
| `RPC_C_IMP_LEVEL_IDENTIFY` | Server can identify but not impersonate | Token inspection only |
| `RPC_C_IMP_LEVEL_IMPERSONATE` | Server can impersonate client locally | Full local token impersonation |
| `RPC_C_IMP_LEVEL_DELEGATE` | Server can impersonate client on other machines | Kerberos delegation attacks |

**Security implication:** If a server receives `IMPERSONATE`-level tokens and calls `RpcImpersonateClient()`, it can act as the client. This is by design — but if the server has SYSTEM privileges and the client has less, this is a downgrade (the server gains a less-privileged token, not an upgrade). The attack direction is reversed: the attacker is the *server*, not the client.

---

## COM Security Model

### COM Server Security Descriptors (Registry)

```
HKCR\CLSID\{guid}\
  └── InprocServer32 or LocalServer32 (defines the server binary)
  └── LaunchPermission (SD: who can create a new instance)
  └── AccessPermission (SD: who can call methods on existing instance)
  └── AppID → HKCR\AppID\{guid}\
      └── RunAs (defines the token under which the server runs)
      └── LaunchPermission (app-level override)
      └── AccessPermission (app-level override)
```

**Key attack surface:** COM servers with `RunAs = Interactive User` or `RunAs = System` that have permissive `LaunchPermission` or `AccessPermission` can be activated/called by lower-privilege processes, potentially gaining access to SYSTEM-level operations.

### COM Elevation Moniker

```
CoCreateInstance with moniker: "Elevation:Administrator!new:{CLSID}"
```

This triggers a UAC elevation prompt for COM activation. If the CLSID is registered for **auto-elevation** (a small set of approved Microsoft CLSIDs), no prompt is required. Auto-elevated COM objects have been a rich source of UAC bypass bugs.

**Enumerate auto-elevated CLSIDs:**
```powershell
Get-ItemProperty "HKLM:\SOFTWARE\Classes\CLSID\*" | 
  Where-Object { $_.AutoElevate -eq 1 }
```

---

## ALPC Architecture Notes

### Port Object Hierarchy

```
Server creates: NtAlpcCreatePort("\\RPC Control\\MyServer", ...)
  └── ALPC_PORT (server) — security descriptor controls who can connect

Client connects: NtAlpcConnectPort("\\RPC Control\\MyServer", ...)
  └── ALPC_PORT (connection) — created per client, holds client token

Connected: NtAlpcSendWaitReceivePort(...)
  └── ALPC_MESSAGE — variable-length, includes port attributes section
      └── TokenAttribute: client security context
      └── ViewAttribute: shared memory section for large data
      └── HandleAttribute: handle passing between processes
```

### ALPC Security Implications

1. **Port security descriptor**: If `Everyone` has CONNECT access, any process can connect regardless of integrity level
2. **Token flow**: The server can call `NtAlpcImpersonateClientOfPort()` to impersonate the connecting client
3. **Handle passing**: ALPC can pass kernel handles between processes — `HandleAttribute` in messages
4. **View sections**: Shared memory via ALPC views bypasses read/write checks — memory content should be validated

---

## Named Pipe Security Model

### Pipe Namespace

```
Win32 path:     \\.\pipe\PipeName
NT path:        \Device\NamedPipe\PipeName
Object Manager: \RPC Control\PipeName (for RPC-created pipes)
```

### Pipe DACL Components

- **READ_DATA**: Who can read from the pipe (server reads client data)
- **WRITE_DATA**: Who can write to the pipe (client writes to server)
- **SYNCHRONIZE**: Required for blocking reads/writes
- **FILE_CREATE_PIPE_INSTANCE**: Who can create additional instances (for squatting defense)

### Squatting Attack

```
1. Attacker calls CreateNamedPipe("\\.\pipe\TARGET", ...) before privileged service
2. Service calls CreateNamedPipe("\\.\pipe\TARGET") → fails (pipe already exists)
   - OR: Service calls ConnectNamedPipe on attacker's pipe (if instance count allows)
3. Service connects as SYSTEM
4. Attacker calls ImpersonateNamedPipeClient()
5. Attacker has SYSTEM token
```

**Defense:** Create pipe with `nMaxInstances = 1` and verify the server created the first instance via security descriptor inheritance check.

---

## Authentication Coercion Pattern

All coercion bugs share the same pattern:

```
  attacker calls: SomeRpcMethod(server, "\\attacker\share\trigger")
                                         ↑
                                   UNC path controlled by attacker
  server side: OpenFile("\\attacker\share\trigger")
                 → NTLM/Kerberos authentication to attacker
  attacker receives authentication
                 → relay to LDAP/SMB/AD CS for privilege escalation
```

### Coercible Interfaces (as of 2024)

| Interface | Protocol | Auth Required | Typical Method |
|-----------|----------|---------------|----------------|
| MS-RPRN | Print Spooler | Domain user | RpcRemoteFindFirstPrinterChangeNotification |
| MS-EFSR | EFS | Domain user (post-patch) | EfsRpcOpenFileRaw |
| MS-DFSNM | DFS | Domain user | NetrDfsRemoveStdRoot |
| MS-FSRVP | Shadow Copy | Domain admin (usually) | IsPathSupported |
| MS-PAR | Print Async | Domain user | Various |
| DCOM | Various CLSIDs | Domain user | Activation coercion (Forshaw 2024) |

### Relay Target Comparison

| Target | Protocol | Result |
|--------|----------|--------|
| SMB + signing disabled | SMB | Code execution on target |
| LDAP (no signing/channel binding) | LDAP | Domain object modification |
| AD CS HTTP endpoint | HTTP (WebEnroll) | Certificate → Pass-the-Certificate → DA |
| LDAPS | LDAPS | Limited without LDAP channel binding bypass |

---

## Tooling Summary

| Tool | Purpose | Author |
|------|---------|--------|
| NtObjectManager (PowerShell) | RPC/COM/ALPC enumeration, access check | Forshaw/Google |
| OleViewDotNet | COM object analysis GUI | Forshaw |
| RpcView | RPC endpoint visualization + IDL decompilation | silverf0x |
| RPC Firewall | RPC call filtering and monitoring | Zero Networks |
| impacket | Python protocol implementation | Fortra/community |
| Coercer | Automated coercion testing | p0dalirius |
| pipelist | Named pipe enumeration | Sysinternals |
| WinObj | Object Manager namespace browser | Sysinternals |

---

*Last updated: 2026-04-22*
