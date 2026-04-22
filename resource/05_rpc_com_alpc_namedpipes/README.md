# 05 · RPC / COM / ALPC / Named Pipes — README

## What This Section Covers

This section documents Windows Inter-Process Communication (IPC) mechanisms as security research subjects. RPC, COM, ALPC, and Named Pipes are the primary channels through which Windows services communicate — and the primary attack surfaces for privilege escalation, authentication coercion, sandbox escape, and lateral movement.

## Why This Section Exists

Windows IPC security is complex for several reasons:
1. **Layering**: Named pipes → ALPC (kernel) → RPC (middleware) → COM (object model) — each layer adds security concepts
2. **Documentation gaps**: Many interfaces are undocumented or partially documented
3. **Research tooling barrier**: Until Forshaw's NtObjectManager, systematic IPC research required expensive tools
4. **Dual-use complexity**: The same interface features that enable COM elevation and credential delegation can be abused for privilege escalation

This section provides resources to understand all four layers and their security implications.

## Section Structure

| Sub-section | Layer | Key Attacks |
|-------------|-------|-------------|
| RPC | Middleware | Endpoint enumeration, privileged interface abuse, coercion |
| ALPC | Kernel | Port security, message abuse, sandbox escape |
| COM | Object Model | Elevation moniker, IRundown injection, DCOM coercion |
| Named Pipes | Transport | Squatting, impersonation, PrintSpoofer class |
| Authentication Coercion | Network | PrintNightmare, PetitPotam, Coercer |
| Tooling | Lab | RpcView, NtObjectManager, impacket |

## Protocol Stack

```
Application (Win32)
      ↓
COM (CoCreateInstance, IDispatch, etc.)
      ↓
RPC Runtime (ncacn_np, ncacn_ip_tcp, ncalrpc transports)
      ↓
ALPC (for ncalrpc) / Named Pipe (for ncacn_np) / TCP (for ncacn_ip_tcp)
      ↓
NT Kernel (Object Manager, I/O Manager)
```

Understanding attacks at each layer requires understanding all layers below it.

## Cross-Section Dependencies

```
05_rpc_com_alpc_namedpipes
    ├── depends on: 06_filesystem_and_fileops (named pipe creation, file-based transports)
    ├── depends on: Windows Internals (ALPC, Object Manager chapters)
    ├── feeds into: 08_bug_classes (impersonation, COM elevation bug classes)
    ├── feeds into: 09_exploit_primitives (ALPC as IPC primitive)
    └── tools: NtObjectManager, RpcView, impacket, RPC Firewall
```

## Learning Path

```
Beginner:
  → Windows Internals COM chapter (Entry 1.3)
  → Named Pipe Security overview (Entry 4.1)
  → PrintNightmare case study (Entry 5.1)

Intermediate:
  → Forshaw RPC blog series (Entry 1.1)
  → NtObjectManager lab installation (Entry 1.4)
  → PetitPotam + Coercer (Entries 5.2–5.3)

Advanced:
  → ALPC internals (Entry 1.2)
  → COM IRundown injection (Entry 3.2)
  → Kerberos DCOM relay (Entry 3.1)
```
