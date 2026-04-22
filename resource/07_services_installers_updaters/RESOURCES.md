# Windows Services, Installers & Updaters — Security Research

> Resources covering the attack surface of Windows background services,
> the Windows Installer (MSI) subsystem, update mechanisms, scheduled tasks,
> and service configuration weaknesses.
> These components run with elevated or SYSTEM privileges by design —
> making them prime targets for local privilege escalation.

---

## Tags

| Tag | Meaning |
|-----|---------|
| `[MUST-READ]` | Essential for understanding this attack surface |
| `[FOUNDATIONAL]` | Background knowledge — read before techniques |
| `[CLASSIC]` | Well-known technique, widely documented |
| `[HISTORICAL]` | Patched or older, still architecturally instructive |
| `[ACTIVE]` | Still relevant on current Windows versions |
| `[TOOL]` | Primarily a tool or framework reference |

---

## Section 1: Windows Services Internals

---

### Windows Services Architecture — Foundational Reference

- **Source:** *Windows Internals* (Russinovich, Ionescu, Yosifovich) — Part 1, Chapter 9
- **URL:** https://docs.microsoft.com/en-us/windows/win32/services/services
- **MS Docs:** https://learn.microsoft.com/en-us/windows/win32/services/service-control-manager
- **Coverage:**
  - Service Control Manager (SCM) — `services.exe` internals
  - Service types: Win32OwnProcess, Win32ShareProcess, KernelDriver, FileSystemDriver
  - Service account types: LocalSystem, LocalService, NetworkService, virtual accounts, managed service accounts
  - Service state machine (START_PENDING, RUNNING, STOP_PENDING, etc.)
  - Service binary ACL requirements
  - SCM RPC interface (`svcctl` — used by `sc.exe`, PowerShell `*-Service`)
- **Why essential:**
  Understanding service architecture is a prerequisite for exploiting any service-based
  LPE path. The SCM manages service lifecycle, credentials, and binary paths —
  all potential attack surfaces.
- **Tags:** `[FOUNDATIONAL]` `[MUST-READ]`

---

### Service Control Manager (SCM) Attack Surface

- **Source:** James Forshaw research + itm4n blog
- **URL:** https://itm4n.github.io/ (search "service")
- **Key attack surfaces:**
  - `OpenSCManager` / `OpenService` with weak ACLs → service config modification
  - `ChangeServiceConfig` accessible to low-priv users (misconfigured DACL)
  - SCM RPC endpoint as attack surface for local privilege escalation
  - Service binary path manipulation if writable
- **Tags:** `[FOUNDATIONAL]`

---

## Section 2: Service Configuration Weaknesses (Classic Techniques)

---

### Unquoted Service Paths

- **Technique:** Service binary path contains spaces and is not quoted, e.g.,
  `C:\Program Files\Vendor App\service.exe`. Windows attempts to load
  `C:\Program.exe`, then `C:\Program Files\Vendor.exe`, etc. If any of those
  directories are writable, a planted binary is executed as SYSTEM.
- **Detection:** `sc qc <service>` / PrivescCheck / PowerUp
- **Prevalence:** Extremely common in third-party software installations
- **Exploitation:** Plant binary at first unquoted path segment writable by attacker
- **References:**
  - PrivescCheck automation: https://github.com/itm4n/PrivescCheck
  - PowerSploit PowerUp: `Get-ServiceUnquoted`
  - MITRE ATT&CK T1574.009
- **Tags:** `[CLASSIC]` `[ACTIVE]`

---

### Service Binary Weak Permissions

- **Technique:** Service binary or its parent directory has ACL granting write
  access to low-privileged users. Attacker replaces binary → SYSTEM on next start.
- **Detection:** `icacls <binary_path>` / PrivescCheck / PowerUp `Get-ModifiableServiceFile`
- **Exploitation steps:**
  1. Identify service binary with write permission for current user
  2. Back up original binary
  3. Replace with malicious binary (same name)
  4. Restart service (if allowed) or wait for restart
- **References:**
  - PrivescCheck: https://github.com/itm4n/PrivescCheck
  - MITRE ATT&CK T1574.010
- **Tags:** `[CLASSIC]` `[ACTIVE]`

---

### Service Registry Key Weak Permissions

- **Technique:** `HKLM\SYSTEM\CurrentControlSet\Services\<name>` has write access
  for low-priv users. Modifying `ImagePath` or `ObjectName` redirects service execution.
- **Detection:** `Get-Acl` on registry keys / PrivescCheck
- **Notable research:** itm4n's RpcEptMapper registry key permissions vulnerability
  (CVE-2019-0943 adjacent) — https://itm4n.github.io/windows-server-netman-dll-hijacking/
- **Tags:** `[CLASSIC]` `[ACTIVE]`

---

### DLL Search Order Hijacking in Services

- **Technique:** A service loads DLLs from locations in the DLL search order.
  If an earlier-searched directory is writable, attacker plants malicious DLL.
- **Key contexts:**
  - DLLs missing from system32 but expected (missing DLL hijack)
  - `%PATH%` directories with weak permissions
  - Application directory DLL load when app dir is writable
  - Side-by-side (SxS) manifest manipulation
- **Detection:** Process Monitor filter → `PATH NOT FOUND` for DLL loads in privileged processes
- **References:**
  - itm4n DLL hijacking posts: https://itm4n.github.io/
  - MITRE ATT&CK T1574.001
- **Tags:** `[CLASSIC]` `[ACTIVE]` `[MUST-READ]`

---

## Section 3: Windows Installer (MSI) Internals & Attack Surface

---

### Windows Installer (MSI) Architecture

- **Source:** MS Docs + *Windows Internals* + research blog posts
- **URL:** https://docs.microsoft.com/en-us/windows/win32/msi/windows-installer-portal
- **Key architecture points:**
  - MSI service runs as LocalSystem for system-scope installations
  - Three execution phases: immediate, deferred (elevated context), rollback
  - Advertised installs: product registered for repair without full installation
  - Cached MSI packages: `C:\Windows\Installer\{GUID}.msi` — SYSTEM-owned, readable by users
  - Custom Actions: code executed during install — can run in System context (Type 1) or user context (Type 2)
  - Repair functionality: re-runs deferred actions as SYSTEM to restore advertised product
- **Tags:** `[FOUNDATIONAL]` `[MUST-READ]`

---

### InstallerFileTakeOver — Arbitrary File Move via MSI Repair

- **Researcher:** Abdelhamid Naceri (klinix5 / halov)
- **URL:** https://github.com/klinix5/InstallerFileTakeOver
- **Technique:**
  The MSI repair mechanism moves files from a temp staging area to their installed
  locations as SYSTEM. By manipulating directory junctions at the staging path,
  the privileged file move is redirected to an attacker-chosen destination.
  This provides an **arbitrary file move primitive** (any source → any destination, as SYSTEM).
- **Exploitation chain:**
  1. Identify an advertised MSI product (cached in `C:\Windows\Installer\`)
  2. Trigger repair via `msiexec /fav <product_code>`
  3. During repair, MSI moves staged files as SYSTEM
  4. Junction at staging path → redirect file to attacker-chosen high-privilege path
  5. Use displaced file to achieve code execution (DLL plant, binary overwrite, ACL trick)
- **Requirements:** Any local user (no special privileges needed)
- **Tags:** `[MUST-READ]` `[ACTIVE]`

---

### CVE-2021-41379 — Windows Installer EoP

- **Researcher:** Abdelhamid Naceri
- **URL:** https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2021-41379
- **Technique:**
  Incorrect ACL applied by elevated MSI process to temp files allowed low-privilege
  users to modify them, influencing installation outcome.
  Naceri published a bypass (InstallerFileTakeOver) after finding the patch insufficient.
- **Tags:** `[ACTIVE]`

---

### AlwaysInstallElevated — Classic MSI Misconfiguration

- **Technique:**
  If both `HKCU\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated = 1`
  and `HKLM\Software\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated = 1`
  are set, any MSI package runs with SYSTEM privileges — even if initiated by a
  low-privileged user. Attacker crafts a malicious MSI with a custom action to achieve SYSTEM.
- **Detection:** Registry query or PrivescCheck
- **References:**
  - Metasploit module `exploit/windows/local/always_install_elevated`
  - MITRE ATT&CK T1218.007
  - itm4n PrivescCheck covers this
- **Tags:** `[CLASSIC]` `[ACTIVE]`

---

### MSI Custom Actions — Dangerous by Design

- **Reference:** https://docs.microsoft.com/en-us/windows/win32/msi/custom-actions
- **Security concern:**
  Type 1 custom actions (DLL, EXE, script) can run in deferred execution context (SYSTEM).
  Maliciously crafted or vulnerable custom action code in a legitimate MSI can
  be exploited for LPE if the MSI is re-runnable with elevated privileges.
- **Research angle:**
  - Find MSIs in `C:\Windows\Installer\` with Type 1 custom actions that load writable DLLs
  - DLL hijack within the custom action context
- **Tags:** `[ACTIVE]`

---

## Section 4: Task Scheduler

---

### Task Scheduler LPE Research — SandboxEscaper CVEs

- **Researcher:** SandboxEscaper (2018–2019)
- **Relevant CVEs:** CVE-2018-8440, CVE-2019-0613, CVE-2019-1069
- **Component:** Task Scheduler service, `SchRpcSetSecurity`, `SchRpcRegisterTask`
- **Key techniques:**
  - ALPC port message abuse (CVE-2018-8440): Task Scheduler ALPC interface allowed
    unprivileged users to set arbitrary DACLs on files by abusing the `.job` file handling
  - Race condition in popen() for job logging (CVE-2019-1069): SYSTEM write redirectable
    via junction during TOCTOU window
- **What these teach:**
  - ALPC interface as attack surface
  - Task Scheduler runs jobs in SYSTEM context — all operations are high-value
  - File operation races in privileged services
- **References:**
  - SandboxEscaper GitHub (archived): https://github.com/SandboxEscaper
  - MSRC advisories for each CVE
- **Tags:** `[HISTORICAL]` `[MUST-READ]`

---

### Task Scheduler as Persistence and LPE Vector

- **Technique class:** Beyond the SandboxEscaper CVEs, the Task Scheduler represents
  ongoing attack surface:
  - Scheduled tasks run binaries from writable paths (DLL hijack opportunity)
  - Tasks imported from XML with permissive DACL settings
  - `schtasks` manipulation if registry key ACLs are weak
  - `ITaskScheduler` COM interface for task creation/modification
- **Tags:** `[ACTIVE]`

---

## Section 5: Windows Update & Background Services

---

### BITS (Background Intelligent Transfer Service) — CVE-2020-0787

- **Component:** `qmgr.dll` — BITS service (LocalSystem)
- **Technique:** Create BITS job pointing to local path, swap destination via junction
  during transfer → arbitrary SYSTEM file write
- **See also:** `13_cve_case_studies/RESOURCES.md` for full CVE analysis
- **PoC:** https://github.com/itm4n/CVE-2020-0787
- **Tags:** `[MUST-READ]` `[ACTIVE]`

---

### Windows Update Delivery Optimization

- **Component:** `dosvc.dll` — Delivery Optimization service
- **Attack surface:**
  - Runs as NetworkService with specific privileges
  - Handles file downloads with SYSTEM cooperation
  - Cache directory permissions (`C:\Windows\SoftwareDistribution\`)
- **Research note:** Less-documented attack surface compared to BITS; file operation
  races and junction abuse applicable to any file-writing service
- **Tags:** `[ACTIVE]`

---

### DiagTrack / Connected User Experiences and Telemetry

- **Component:** `utcsvc.dll` — DiagTrack service (LocalSystem)
- **Attack surface:**
  - Writes diagnostic files to `C:\ProgramData\Microsoft\Diagnosis\`
  - File path handling from user-controlled sources (event IDs, crash dump paths)
  - High-frequency file operations as SYSTEM → junction abuse target
- **Tags:** `[ACTIVE]`

---

### Windows Error Reporting (WER)

- **Component:** `wer.dll`, `WerFault.exe`, `WerSvc`
- **Attack surface:**
  - WER processes crash dumps in elevated context
  - Writes dump files to `C:\ProgramData\Microsoft\Windows\WER\`
  - `ReportArchive` and `ReportQueue` paths potentially manipulable via junctions
  - WerFault.exe elevation for interactive user reports
- **References:**
  - Research notes in Forshaw's symbolic link work
- **Tags:** `[ACTIVE]`

---

## Section 6: Print Spooler (Printer Services)

---

### PrintNightmare — CVE-2021-1675 / CVE-2021-34527

- **Component:** `spoolsv.exe` — Print Spooler (LocalSystem)
- **Technique (LPE):** `AddPrinterDriverEx` RPC → load attacker-controlled DLL as SYSTEM
- **Technique (RCE):** Remote authenticated call to same endpoint → RCE on exposed spoolers
- **See also:** Full analysis in `13_cve_case_studies/RESOURCES.md`
- **PoC (educational):** https://github.com/cube0x0/CVE-2021-1675
- **Tags:** `[MUST-READ]` `[HISTORICAL]`

---

### PrintSpoofer — Named Pipe Impersonation (CVE-2020-1048)

- **Researcher:** Clément Labro (itm4n)
- **Technique:** Induce Spooler to connect to attacker-controlled pipe → impersonate SYSTEM
- **Prerequisite:** `SeImpersonatePrivilege` (any IIS, MSSQL, SQL Agent service account)
- **PoC:** https://github.com/itm4n/PrintSpoofer
- **Tags:** `[MUST-READ]` `[ACTIVE]`

---

## Section 7: WMI Subscriptions (Persistence / Service-Adjacent)

---

### WMI Event Subscriptions as Persistence

- **Technique:**
  WMI permanent event subscriptions survive reboots and run consumer code (VBS, PowerShell,
  arbitrary EXE) in SYSTEM context when triggered by system events. Used extensively
  by APT groups for persistent, fileless execution.
- **Components:**
  - `__EventFilter` — trigger condition
  - `__EventConsumer` — action to take (CommandLineEventConsumer, ActiveScriptEventConsumer)
  - `__FilterToConsumerBinding` — links filter to consumer
- **Detection:** `Get-WMIObject` on `__EventFilter`, `__EventConsumer`, `__FilterToConsumerBinding`
  or the Sysinternals Autoruns tool
- **References:**
  - FireEye/Mandiant WMI persistence research
  - MITRE ATT&CK T1546.003
  - PowerSploit `Invoke-WMIMethod`
- **Tags:** `[ACTIVE]` `[CLASSIC]`

---

## Attack Surface Quick Reference

| Component | Runs As | Key Techniques | Primary Reference |
|-----------|---------|---------------|------------------|
| Task Scheduler | SYSTEM | ALPC abuse, job file race, binary hijack | SandboxEscaper CVEs |
| Windows Installer | LocalSystem | AlwaysInstallElevated, repair junction, custom action | InstallerFileTakeOver |
| BITS | LocalSystem | Junction + arbitrary file write | CVE-2020-0787 |
| Print Spooler | LocalSystem | AddPrinterDriverEx DLL load, named pipe impersonation | PrintNightmare, PrintSpoofer |
| DiagTrack | LocalSystem | File write race via junction | Research ongoing |
| WER | LocalSystem | Crash dump path manipulation | Forshaw research |
| SCM (Service Control) | LocalSystem | Weak service ACL, binary replace, reg key | PrivescCheck |
| Delivery Optimization | NetworkService | File operation junction abuse | Research ongoing |
| WMI Subscriptions | SYSTEM | Consumer registration for persistence | MITRE T1546.003 |
