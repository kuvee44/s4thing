# CVE Case Studies — Windows Privilege Escalation

> High-value CVE case studies for learning Windows LPE techniques.
> Organized by bug class. Each entry explains the root cause, exploitation primitive,
> and what it teaches about Windows internals.

---

## Reading Tags

| Tag | Meaning |
|-----|---------|
| `[MUST-READ]` | Essential case study — teaches a core technique class |
| `[FOUNDATIONAL]` | Background; many later techniques build on this |
| `[HISTORICAL]` | Patched, older — still architecturally instructive |
| `[WILD]` | Exploited in the wild before patch |
| `[EDUCATIONAL]` | Reproduction for learning only |

---

## Bug Class 1: Arbitrary File Write / Arbitrary File Move / Arbitrary File Delete

These CVEs share a common exploitation pattern: leverage a privileged Windows
service to write/move/delete a file to an attacker-controlled path, then convert
that primitive into code execution (usually via DLL planting or ACL manipulation).

---

### CVE-2019-1069 — Task Scheduler Arbitrary File Write (SYSTEM)

- **Researcher:** SandboxEscaper (anonymous, 2019)
- **Component:** Task Scheduler service (`schedsvc.dll`, `SchRpcSetSecurity`)
- **Windows versions:** Windows 10, Windows Server 2016/2019 (pre-patch)
- **Bug class:** Race condition / TOCTOU → NTFS hard link → arbitrary file write
- **CVSS:** 7.8 (Local)
- **Root cause:**
  The Task Scheduler service's `popen()` call for job logging runs in a SYSTEM
  context. By carefully timing a junction/hard link swap between the TOCTOU window
  (check vs. use of file path), an attacker could redirect the SYSTEM write to an
  arbitrary file location, including trusted locations like `C:\Windows\System32\`.
- **Exploitation primitive:** Arbitrary SYSTEM file write → DLL plant → SYSTEM code execution
- **What it teaches:**
  - TOCTOU (time-of-check-time-of-use) races in privileged services
  - NTFS junction / hard link / object manager symlink abuse as amplifiers
  - How file operation races convert to arbitrary write primitives
- **PoC / References:**
  - Original disclosure: SandboxEscaper GitHub (archived)
  - MSRC advisory: https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2019-1069
- **Patch strategy:** Removed the vulnerable code path; fixed TOCTOU window
- **Tags:** `[MUST-READ]` `[HISTORICAL]`

---

### CVE-2019-1129 — Windows CreateSymbolicLink Privilege Escalation

- **Researcher:** Multiple (public after patch)
- **Component:** Object Manager symbolic link creation, junction handling
- **Bug class:** Symlink / junction planting → privileged file operation redirect
- **Root cause:**
  Windows allowed low-privileged processes to create object namespace symbolic
  links in certain directories. A privileged service following these links
  would then operate on attacker-controlled targets.
- **Exploitation primitive:** Object namespace symlink → arbitrary privileged file operation
- **What it teaches:**
  - Windows Object Manager namespace structure (BaseNamedObjects, Sessions)
  - How object directory DACLs control symlink creation
  - Forshaw's symlink planting framework (from SAAT toolkit)
- **References:**
  - James Forshaw's symbolic link research: https://www.tiraniddo.dev/
  - NtObjectManager toolkit for symlink analysis
- **Tags:** `[FOUNDATIONAL]` `[HISTORICAL]`

---

### CVE-2020-0787 — BITS (Background Intelligent Transfer Service) Arbitrary File Write

- **Researcher:** Eduardo Braun Prado / ZDI
- **Component:** Background Intelligent Transfer Service (`qmgr.dll`)
- **Windows versions:** Windows 7 through Windows 10 1903 (pre-patch)
- **Bug class:** Arbitrary file write via BITS job + symbolic link abuse
- **CVSS:** 7.8 (Local)
- **Root cause:**
  BITS runs as LocalSystem and handles file transfer jobs. An attacker could
  create a BITS job pointing to a local file path and then swap the destination
  using a junction or symlink during the transfer operation, causing BITS to write
  attacker-supplied data to an arbitrary file as SYSTEM.
- **Exploitation primitive:** BITS local job → directory junction → arbitrary SYSTEM file write → DLL hijack or ACL overwrite
- **What it teaches:**
  - How background service file operations create LPE attack surface
  - BITS as a post-exploitation primitive (used by malware for persistence + LPE)
  - Directory junction + file race as a conversion technique
- **PoC:** https://github.com/itm4n/CVE-2020-0787
- **MSRC:** https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2020-0787
- **Tags:** `[MUST-READ]`

---

### CVE-2021-24092 — Microsoft Defender Arbitrary File Delete

- **Researcher:** SentinelOne research team (Kasif Dekel)
- **Component:** Microsoft Defender Antivirus engine (`MpEngine.dll`, quarantine)
- **Bug class:** Arbitrary file delete via quarantine + symbolic link abuse
- **Root cause:**
  Defender's quarantine mechanism runs as SYSTEM and performs file deletion as part
  of cleaning up malware. By planting a symbolic link or junction at the quarantine
  restore path, an attacker could cause Defender to delete arbitrary files on the
  system — including files owned by SYSTEM or used for security enforcement.
- **Exploitation primitive:** Arbitrary file delete (as SYSTEM) → convert to LPE via:
  - Delete a protected binary and replace with attacker-controlled one
  - Delete a DLL in a trusted directory path → plant malicious DLL
- **What it teaches:**
  - Security software as an attack surface (AV/EDR LPE bug class)
  - Arbitrary delete → LPE conversion techniques
  - Symlink abuse in quarantine/remediation flows
- **References:**
  - SentinelOne blog: https://www.sentinelone.com/labs/
  - MSRC: https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2021-24092
- **Tags:** `[MUST-READ]`

---

### CVE-2022-21838 — Windows Disk Cleanup Arbitrary File Delete

- **Component:** `cleanmgr.exe`, Disk Cleanup utility (runs elevated)
- **Bug class:** Arbitrary file delete via junction abuse in cleanup path
- **Root cause:**
  Disk Cleanup processes paths from a registry-configured list when run elevated.
  By manipulating registry entries and planting junctions, an attacker could cause
  the elevated cleanup process to delete files outside the intended scope.
- **What it teaches:**
  - UAC elevation as an attack surface for LPE
  - Registry manipulation → elevated process behavior change
  - Cleanup/maintenance utilities as high-risk privileged code paths
- **Tags:** `[HISTORICAL]`

---

## Bug Class 2: Token Impersonation

These CVEs exploit the Windows token model — specifically the ability of service
accounts holding `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege` to
elevate to SYSTEM through impersonation.

---

### CVE-2016-3225 — Secondary Logon Service Impersonation (Rotten Potato Precursor)

- **Researcher:** foxglovesecurity team (Hot Potato / Rotten Potato)
- **Component:** Secondary Logon service (`seclogon.dll`)
- **Bug class:** Service token impersonation, NTLM relay to localhost
- **Root cause:**
  The Secondary Logon service, when handling `CreateProcessWithLogonW`, would
  open the pipe created by the calling process and impersonate it. By controlling
  the pipe and inducing the SYSTEM-level service to connect to it, an attacker
  with `SeImpersonatePrivilege` could capture a SYSTEM token.
- **What it teaches:**
  - Token impersonation mechanics (`ImpersonateNamedPipeClient`)
  - SYSTEM service pipe connection patterns as impersonation targets
  - Precursor to the entire Potato exploit family
- **References:**
  - Hot Potato original: https://foxglove.github.io/blog/hot-potato-windows-privilege-escalation
  - RottenPotato: https://github.com/foxglovesec/RottenPotato
- **Tags:** `[FOUNDATIONAL]` `[HISTORICAL]`

---

### PrintSpoofer (CVE-2020-1048 / pipe impersonation) — Named Pipe Impersonation

- **Researcher:** Clément Labro (itm4n)
- **Component:** Print Spooler service, named pipe impersonation
- **Bug class:** Named pipe impersonation → SYSTEM token capture
- **Root cause:**
  The Windows Print Spooler can be induced to connect back to an attacker-controlled
  named pipe by calling `RpcOpenPrinter` with a UNC path pointing to a local pipe
  (e.g., `\\.\pipe\foo\..\..\PRINTIPC\...`). The Spooler connects as SYSTEM and
  can be impersonated with `ImpersonateNamedPipeClient`, yielding a SYSTEM token
  from any account holding `SeImpersonatePrivilege`.
- **Exploitation primitive:** SeImpersonatePrivilege + named pipe → SYSTEM token → `CreateProcessAsUser`
- **What it teaches:**
  - Named pipe impersonation mechanics at the API and kernel level
  - How UNC path parsing can trick services into connecting to attacker-controlled endpoints
  - Token impersonation privilege escalation from service accounts (IIS, MSSQL, etc.)
  - The role of `SeImpersonatePrivilege` in LPE — why it's so dangerous
- **PoC:** https://github.com/itm4n/PrintSpoofer
- **Must-read blog post:** https://itm4n.github.io/printspoofer-abusing-impersonation-privileges/
- **Tags:** `[MUST-READ]` `[FOUNDATIONAL]`

---

## Bug Class 3: Installer / Updater Privilege Abuse

---

### InstallerFileTakeOver — Windows Installer Arbitrary File Move

- **Researcher:** Abdelhamid Naceri (klinix5 / halov)
- **CVE:** No CVE assigned at initial disclosure (bypass of CVE-2021-41379 patch)
- **Component:** Windows Installer service (`msiexec.exe`, `msihnd.dll`)
- **Bug class:** Arbitrary file move (SYSTEM → attacker path) via installer repair
- **Root cause:**
  The Windows Installer's **repair** functionality runs as SYSTEM to restore
  advertised products. During repair, MSI reads a cached package and moves files
  from a temp staging area to their installed locations. By manipulating directory
  junctions at the staging path, an attacker can redirect the privileged file move
  operation to an arbitrary destination — effectively moving any file to any location
  as SYSTEM.
- **Exploitation primitive:** Arbitrary SYSTEM file move → overwrite a privileged binary / plant DLL → code execution as SYSTEM
- **What it teaches:**
  - MSI repair mechanism internals (advertised installs, cached packages)
  - How to convert an "arbitrary file move" into full code execution
  - Why patching file operation bugs is notoriously difficult (many equivalent paths)
- **PoC:** https://github.com/klinix5/InstallerFileTakeOver [MUST-READ]
- **References:**
  - Naceri's original disclosure (Twitter, November 2021)
  - itm4n analysis: https://itm4n.github.io/
- **Tags:** `[MUST-READ]`

---

### CVE-2021-41379 — Windows Installer EoP

- **Researcher:** Abdelhamid Naceri
- **Component:** Windows Installer
- **Bug class:** Incorrect ACL set by elevated MSI process → arbitrary write primitive
- **Root cause:**
  Windows Installer, when running elevated, incorrectly set ACLs on certain
  temporary files during installation, allowing a low-privileged user to
  modify them and influence the installation outcome.
- **Note:** Naceri subsequently published a bypass (InstallerFileTakeOver above)
  after reviewing Microsoft's patch and finding it insufficient.
- **MSRC:** https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2021-41379
- **Tags:** `[MUST-READ]`

---

## Bug Class 4: Win32k Kernel Vulnerabilities

---

### CVE-2021-1732 — Win32k Exploited in the Wild

- **Researcher:** DBAPPSecurity Threat Intelligence Center
- **Component:** `win32k.sys` (Window manager kernel component)
- **Bug class:** Use-after-free (UAF) in win32k window management
- **Exploited:** Yes — in targeted attacks in the wild (APT)
- **Root cause:**
  A use-after-free condition in win32k's window object handling allowed an attacker
  to obtain a dangling pointer to a freed window object. By carefully controlling
  the heap layout (pool grooming/spraying), the freed region could be reclaimed
  with attacker-controlled data, leading to arbitrary kernel read/write.
- **Exploitation primitive:** Kernel arbitrary read/write → overwrite token privileges → SYSTEM
- **What it teaches:**
  - Win32k UAF exploitation methodology
  - Kernel pool grooming techniques on Windows 10
  - Token privilege manipulation for kernel LPE
  - Why Win32k remains a critical attack surface despite lockdown efforts
- **PoC:** Multiple published PoC implementations on GitHub (search CVE-2021-1732)
- **References:**
  - MSRC: https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2021-1732
  - Valentina Palmiotti analysis (Twitter threads)
- **Tags:** `[MUST-READ]` `[WILD]`

---

### CVE-2020-17382 — MSI Ambient Link Driver Kernel Vulnerability

- **Researcher:** Matteo Malvica
- **Component:** MSI Ambient Link kernel driver (`ntiolib.sys` / MSI hardware monitor)
- **Bug class:** Vulnerable third-party kernel driver → kernel read/write from user mode
- **Root cause:**
  The MSI Ambient Link driver exposed an IOCTL interface that allowed user-mode
  callers to perform arbitrary kernel memory read/write operations without privilege
  checks. Any local user could use this to corrupt kernel structures.
- **Exploitation primitive:** IOCTL → arbitrary kernel R/W → token corruption → SYSTEM
- **What it teaches:**
  - Third-party kernel drivers as a major attack surface
  - IOCTL attack surface analysis methodology
  - Kernel arbitrary R/W → LPE conversion techniques
  - Why driver signing / HVCI matters for defense
- **References:**
  - Matteo Malvica blog: https://matteomalvica.com/
  - PoC: GitHub (search CVE-2020-17382)
- **Tags:** `[MUST-READ]`

---

## Bug Class 5: PrintNightmare

---

### CVE-2021-1675 / CVE-2021-34527 — PrintNightmare

- **Researchers:** Zhiniang Peng, Xuefeng Li, Zhipeng Huo, Piotr Madej (Yunah Security), multiple researchers independently
- **Component:** Windows Print Spooler (`spoolsv.exe`)
- **Bug class:** Privileged DLL load via `AddPrinterDriverEx` RPC call + ACL weakness in driver directory
- **Root cause (LPE vector):**
  The Spooler service's `AddPrinterDriverEx` function loads driver DLLs from
  user-specified paths as SYSTEM. A local user can supply a path to a malicious
  DLL. The service performs insufficient validation of the driver path and loads
  the DLL with SYSTEM privileges.
- **Root cause (RCE vector):**
  The same RPC endpoint was reachable remotely (by authenticated users by default),
  enabling remote code execution if Print Spooler was exposed on Domain Controllers.
- **Exploitation primitive (LPE):** Arbitrary DLL load as SYSTEM
- **What it teaches:**
  - How RPC service methods with elevated execution context create LPE surface
  - Driver directory ACL weakness in Windows print infrastructure
  - The distinction between LPE (CVE-2021-1675) and RCE (CVE-2021-34527) variants
  - Patch evasion: the complexity of fully remediating a large RPC attack surface
- **PoC (educational):** https://github.com/cube0x0/CVE-2021-1675
- **References:**
  - itm4n analysis: https://itm4n.github.io/
  - MSRC: https://msrc.microsoft.com/update-guide/en-US/advisory/CVE-2021-34527
- **Trust:** `[EDUCATIONAL]` — reproduction for learning only; do not use against systems without authorization
- **Tags:** `[MUST-READ]` `[EDUCATIONAL]`

---

## Bug Class 6: Object Manager Namespace

---

### CVE-2015-2555 — SYSTEM Object Directory DACL Weakness

- **Researcher:** James Forshaw (Project Zero)
- **Component:** Windows Object Manager — `\BaseNamedObjects` and per-session directories
- **Bug class:** Weak DACL on system object namespace directory → low-priv symlink creation → privileged operation redirect
- **Root cause:**
  Certain object namespace directories had overly permissive DACLs, allowing
  low-privileged users to create symbolic links within them. A privileged service
  following these links would operate on attacker-controlled objects.
- **What it teaches:**
  - Windows Object Manager namespace architecture (`\`, `\BaseNamedObjects`, `\Sessions\0\BaseNamedObjects`)
  - How object namespace DACLs control who can create symlinks
  - Forshaw's symlink planting methodology — the foundation for many subsequent bugs
  - NtObjectManager toolkit for namespace exploration
- **References:**
  - Project Zero issue: https://bugs.chromium.org/p/project-zero/
  - James Forshaw blog posts on symbolic links
- **Tags:** `[FOUNDATIONAL]` `[HISTORICAL]`

---

## Bug Class 7: Services and DLL Search Order Hijacking

---

### DLL Search Order Hijacking — Endemic Bug Class

- **Researchers:** Multiple — CERT, Acros Security (originally), itm4n (practical analysis)
- **Component:** Windows DLL loader, service host processes
- **Bug class:** Predictable DLL search order + weak directory permissions → hijack
- **Root cause:**
  When a Windows process or service loads a DLL without a fully-qualified path,
  the loader searches a deterministic list of directories. If any earlier-searched
  directory is writable by a low-privileged user (e.g., `C:\`, `C:\Windows\Temp`,
  application directory), the attacker can plant a DLL that gets loaded in the
  privileged process's context.
- **Common contexts for exploitation:**
  - Services running from `C:\Program Files\Vendor\` where vendor directory is writable
  - `PATH` directories with weak ACLs
  - Windows services loading DLLs from non-system locations (`C:\ProgramData\...`)
  - AppPaths registry entries pointing to directories with weak permissions
- **Exploitation primitive:** Writable directory in DLL search path of privileged service → DLL plant → code execution in service context
- **What it teaches:**
  - Windows DLL loader search order (KnownDLLs → same dir → system32 → Windows → PATH)
  - How `SafeDllSearchMode` and `DllCharacteristics` affect search behavior
  - ACL enumeration methodology for identifying writable paths in privileged contexts
  - `PrivescCheck` automation for finding these misconfigs
- **References:**
  - itm4n's PrivescCheck: https://github.com/itm4n/PrivescCheck
  - MSRC guidance: https://docs.microsoft.com/en-us/windows/win32/dlls/dynamic-link-library-search-order
- **Tags:** `[FOUNDATIONAL]`

---

## CVE Quick Reference Table

| CVE | Component | Bug Class | Severity | Tags |
|-----|-----------|-----------|----------|------|
| CVE-2019-1069 | Task Scheduler | Arbitrary file write (race) | 7.8 | HISTORICAL, MUST-READ |
| CVE-2019-1129 | Object Manager | Symlink planting | 7.8 | HISTORICAL |
| CVE-2020-0787 | BITS | Arbitrary file write + junction | 7.8 | MUST-READ |
| CVE-2021-24092 | MS Defender | Arbitrary file delete | 7.8 | MUST-READ |
| CVE-2022-21838 | Disk Cleanup | Arbitrary file delete | High | — |
| CVE-2016-3225 | SecLogon | Token impersonation | 7.8 | HISTORICAL, FOUNDATIONAL |
| CVE-2020-1048 (PrintSpoofer) | Print Spooler | Named pipe impersonation | 7.8 | MUST-READ |
| InstallerFileTakeOver | Windows Installer | Arbitrary file move | Critical | MUST-READ |
| CVE-2021-41379 | Windows Installer | Incorrect ACL | 7.8 | MUST-READ |
| CVE-2021-1732 | win32k.sys | Use-after-free (kernel) | 7.8 | WILD, MUST-READ |
| CVE-2020-17382 | MSI driver | Vulnerable IOCTL | 8.8 | MUST-READ |
| CVE-2021-1675/34527 | Print Spooler | Arbitrary DLL load (RPC) | Critical | EDUCATIONAL |
| CVE-2015-2555 | Object Manager | Weak DACL → symlink | 7.2 | HISTORICAL, FOUNDATIONAL |
