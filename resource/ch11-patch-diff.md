# Chapter 11: Patch Diffing & Root Cause Analysis

> **Scope**: This chapter covers the full methodology for Windows patch diffing —
> from obtaining pre/post-patch binaries through BinDiff/Diaphora usage, MSRC advisory
> interpretation, root cause analysis frameworks, symbol-aided analysis, and systematic
> variant hypothesis generation. The goal is actionable skill: reproduce this workflow
> on every Patch Tuesday.

---

## 11.1 Why Patch Diffing Matters

Patch diffing is the practice of comparing a binary before and after a security patch
to identify exactly what code changed — and from that, infer the vulnerability that was
fixed. It is fundamental to three research activities:

**1. 1-day research**: After Patch Tuesday, a security fix is public but a detailed
writeup may not exist for weeks or months. Patch diff finds the vulnerability before
any public PoC. The researcher who diffs the patch on Tuesday can have a working PoC
by Wednesday — before any CVE writeup is published.

**2. Variant discovery**: Analyzing the fix reveals the root cause. Knowing the root
cause enables searching for other code paths that share the same pattern but were not
fixed. Incomplete patches — where Microsoft fixed the PoC path but not the root cause
— are common in Windows. A complete patch diff workflow always includes a "is this fix
complete?" analysis step.

**3. Understanding defensive posture**: Defenders need to understand what was actually
fixed in each update, not just what the CVSS score says. Patch diffing provides the
technical ground truth.

### 11.1.1 The "Distrusting the Patch" Mindset

A patch should be trusted only after verifying that it:

1. **Addresses the root cause** — not just the specific PoC trigger
2. **Covers all call sites** — all code paths sharing the same root cause are patched
3. **Fixes the right layer** — the fix is in the vulnerable function, not just its callers
4. **Does not introduce new bugs** — the fix itself is correct and complete
5. **Handles edge cases** — not just the happy-path trigger

When a patch fails any of these criteria, a variant or bypass is likely possible.
This mindset is not paranoia — it is validated by history. Major Windows vulnerability
classes (Windows Installer, Print Spooler, Win32k type confusion, registry confused
deputy) have each required multiple patch iterations because initial fixes were
symptomatic rather than root-cause.

---

## 11.2 Patch Tuesday Workflow

### 11.2.1 Step 1 — Read the MSRC Advisory

The Microsoft Security Response Center (MSRC) Security Update Guide at
`https://msrc.microsoft.com/update-guide/` is updated on the second Tuesday of
every month (Patch Tuesday).

**Priority targets for patch diff research**:

| Filter | Rationale |
|---|---|
| Exploitation More Likely | MSRC's own assessment that a practical exploit is feasible |
| Critical or Important severity | High-impact bugs worth investment |
| Elevation of Privilege | LPE — directly translates to practical attack |
| Security Feature Bypass | UAC/integrity bypass — often interesting root causes |
| Windows component (not Office/Exchange) | Windows LPE is the primary target |
| Known attack surface (Win32k, Installer, RPC, LSASS) | Areas with historical returns |

**What to extract from each advisory**:
- Affected component and DLL/EXE name (the MSRC advisory usually names it)
- KB article number (needed to download the update package)
- CVSS attack vector (Local vs Network), privileges required, complexity
- Whether MSRC calls out "authentication required" — no auth = higher urgency
- Whether a PoC is referenced (external researcher report) — researcher may have pre-public details

### 11.2.2 Step 2 — Identify the Patched Binary

Not every MSRC advisory names the specific DLL. Methods to find it:

**Method A — MSRC advisory search**:
Some advisories explicitly name the affected file (e.g., "win32k.sys", "windows.storage.dll").

**Method B — KB update catalog extraction**:
```cmd
; Download the .msu update package from Windows Update Catalog
; https://www.catalog.update.microsoft.com/

; Extract .msu contents
expand -F:* KB5027231.msu C:\extracted\

; Extract the .cab inside
expand -F:* Windows10-KB5027231-x64.cab C:\extracted\cabs\

; The payload files are in the .cab — look for the patched binary
dir C:\extracted\cabs\*.dll /s
```

**Method C — WinBindex comparison**:
`https://winbindex.m417z.com/` indexes Windows binaries by filename, build number,
and PE hash. Search for the suspected file and compare build timestamps between
pre-patch and post-patch build numbers. Files with matching names but different
hashes between the two build numbers are candidates.

**Method D — Process Monitor during update application**:
Run ProcMon during update installation, filter for `WriteFile` operations in
`C:\Windows\System32\` and `C:\Windows\SysWOW64\`. Every file written is a candidate.

### 11.2.3 Step 3 — Obtain Pre-Patch and Post-Patch Binaries

**Pre-patch binary sources** (in order of reliability):

| Method | Notes |
|---|---|
| Winbindex (`winbindex.m417z.com`) | Best for system DLLs; search by filename + build |
| VM snapshot before patching | Always snapshot your research VMs before Patch Tuesday |
| Windows Update Catalog historical downloads | Download the previous month's cumulative update |
| Cabinet file from old cumulative update | Each cumulative update contains the full patched set |

**Post-patch binary**:
- Extract directly from the new update `.cab` as described above
- Or copy from an already-patched research VM at `C:\Windows\System32\`

**Verification**: Always verify PE timestamps and file hashes to confirm you have
the exact pre-patch and post-patch versions. A one-day difference in timestamp
between "pre-patch" and "post-patch" files is expected.

### 11.2.4 Step 4 — Load in IDA Pro or Ghidra with Symbols

Configure the Microsoft Symbol Server before diffing. Symbols dramatically accelerate
analysis by providing function names.

**WinDbg symbols**:
```windbg
.sympath srv*C:\Symbols*https://msdl.microsoft.com/download/symbols
.reload /f
```

**IDA Pro symbols**:
- Options → Debugger → Debugger options → Set symbol paths
- `srv*C:\Symbols*https://msdl.microsoft.com/download/symbols`
- File → Load file → PDB file → enter module name to pull from symbol server

**Ghidra symbols**:
- Edit → Symbol Server → Add Microsoft Symbol Server
- URL: `https://msdl.microsoft.com/download/symbols`
- Analyze → One Shot → PDB Analyzer

With symbols loaded, function names like `CmpComputeSecurityDescriptor`,
`NtQueryInformationProcess`, `SpoolerHandleOpenPrinter` appear in the disassembly
instead of `sub_140012345`. This is essential for rapid patch triage.

---

## 11.3 BinDiff Usage

### 11.3.1 Setup

BinDiff (https://www.zynamics.com/bindiff.html) is the industry standard binary
diffing tool. It is free (Google ownership), and integrates with both IDA Pro and
Ghidra via plugins.

**Installation**:
1. Download BinDiff from zynamics.com
2. Install the IDA/Ghidra plugin via the installer
3. In IDA: export a `.BinExport` database for each version via Edit → Plugins → BinDiff
4. Open BinDiff GUI → choose both `.BinExport` files → run diff

### 11.3.2 Understanding Similarity Scores

BinDiff produces a similarity score per function pair:

| Score Range | Interpretation | Research Priority |
|---|---|---|
| 1.0 | Identical — no change | Skip |
| 0.95–0.99 | Very similar, minor change | **HIGH PRIORITY** — likely patch site |
| 0.80–0.95 | Moderate change | Review — may be security-relevant refactor |
| 0.50–0.80 | Significant rewrite | Investigate — may be new mitigation logic |
| 0.0 (unmatched) | New or removed function | Check — added mitigation function, or removed vulnerable function |

The functions with scores in **0.95–0.99** are the primary patch diff targets. They
share the same structure (same CFG, same basic blocks) but have one or a few changed
basic blocks — precisely what a targeted security fix looks like.

### 11.3.3 What to Look For in Changed Basic Blocks

After navigating to a high-similarity changed function, examine the diff view to
identify the specific added/removed/changed instructions. Common security fix patterns:

| Pattern | Code Change | What It Implies |
|---|---|---|
| Added bounds check | New `cmp [size], 0x1000` + conditional `jb/je` + error return | Buffer overflow fix |
| Added NULL check | New `test rax, rax` + `jz` to error handler | Null pointer dereference fix |
| Added privilege check | New `call RtlImpersonationNeeded` or token access check | Impersonation/privilege bypass fix |
| Changed type: DWORD → SIZE_T | Wider register usage in size arithmetic | Integer overflow → pool undersizing fix |
| Added atomization | Replaced load/modify/store with `lock cmpxchg` | TOCTOU race condition fix |
| Changed permission | Modified DACL constant or ACL creation call | ACL weakness fix |
| Added path validation | New call to `RtlDosPathNameToRelativeNtPathName_U` + check | Path traversal fix |
| Removed code path | Basic block deleted | Dangerous feature removed |

### 11.3.4 BinDiff Workflow — Step by Step

```
1. Export pre-patch DLL from IDA → File → Produce file → Create BinExport
   (ensure symbols are loaded before exporting)

2. Export post-patch DLL from IDA → same procedure

3. Open BinDiff GUI → choose both .BinExport files → Diff

4. Primary view: "Matched Functions" sorted by Similarity ascending
   → Focus on functions with 0.95–0.99 similarity

5. Double-click a matched function → opens Flow Graph Diff view
   → Orange = changed blocks, Green = added blocks, Red = removed blocks

6. Examine changed basic blocks
   → What instruction was added? What was removed?
   → What code path leads here? What does the function do?

7. Navigate to callers (cross-references) of the changed function
   → Who calls this? What's the broader context?

8. Form root cause hypothesis
   → What bug did the added check prevent?
```

---

## 11.4 Diaphora vs BinDiff

### 11.4.1 Diaphora Overview

Diaphora (https://github.com/joxeankoret/diaphora) is the leading open-source
alternative to BinDiff. It is a Python IDA plugin with different similarity algorithms.

**Algorithm differences**:
- BinDiff uses structural comparison (CFG isomorphism, basic block hashing)
- Diaphora uses multiple metrics: bytecode hashing, pseudo-code similarity, minhash,
  call graph comparison, graph edit distance
- Diaphora's pseudo-code comparison (via Hex-Rays decompiler) can match functions
  that BinDiff misses when the CFG changed significantly but the logic is the same

### 11.4.2 When Each Tool Excels

| Scenario | Better Tool |
|---|---|
| Minor patch (few added instructions) | BinDiff — faster, cleaner flow graph view |
| Major refactor or inline expansion | Diaphora — pseudo-code similarity handles structural changes |
| Large binary (ntoskrnl.exe) | BinDiff — better performance at scale |
| Open-source customization needed | Diaphora — full Python source, easily extended |
| Finding functions BinDiff missed | Diaphora — run as second pass to catch remaining differences |
| Understanding algorithm confidence | Diaphora — shows breakdown of which metrics matched |

**Best practice**: Run both. BinDiff first for speed; Diaphora as a second pass to
catch any functions that BinDiff's algorithm missed. The union of both results is
more complete than either alone.

### 11.4.3 Diaphora Setup

```python
# Install: copy diaphora.py to IDA's plugins directory
# IDA → Edit → Plugins → Diaphora

# Export database: run Diaphora on both old and new binaries
# → produces .sqlite files

# Diff: File → Open diff → select both .sqlite files → run
```

---

## 11.5 WinDiff / Winbindex for Version Comparison

### 11.5.1 Winbindex

Winbindex (`https://winbindex.m417z.com/`) is a community-maintained index of Windows
system files. For every indexed file it provides:
- Download links for every build version
- PE timestamps, file sizes, hashes
- Windows version coverage

**Research uses**:
- Download pre-patch binaries for any Windows build without having a snapshot
- Compare file hashes across builds to identify which update changed a specific binary
- Get the exact previous cumulative update build number before a given patch

### 11.5.2 j00ru's NtDiff / Syscall Tables

j00ru's Windows NT syscall table database (`https://j00ru.vexillium.org/syscalls/nt/64/`)
tracks system call numbers, names, and availability across every major Windows version.

**As a patch research signal**:
- A syscall **added** in a specific build → new attack surface for that build
- A syscall **removed** in a build → defensive hardening of that interface
- A syscall that **changed argument count** between builds → behavior change, potential ABI
  break indicating a significant internal refactor

When you see a new syscall appear in the NtDiff table after a Patch Tuesday, investigate
its implementation immediately — new syscalls frequently have the vulnerabilities of
newly written code.

---

## 11.6 Reading a MSRC Advisory to Formulate Hypotheses

### 11.6.1 Decoding the Advisory Language

MSRC advisories use standard language. Learning to decode it converts a 200-word advisory
into a precise research hypothesis:

| Advisory Field | Typical Value | Research Implication |
|---|---|---|
| Vulnerability Type | Elevation of Privilege | LPE — look for privilege check, impersonation, or file operation bypass |
| Vulnerability Type | Security Feature Bypass | Mitigation bypass — identify which security feature (KASLR, UAC, CFG) |
| Attack Vector | Local | Caller must be logged in locally; useful for LPE research |
| Attack Vector | Network | Can trigger from network; may affect RPC interfaces |
| Privileges Required | Low | Low-priv user can trigger — LPE from standard user |
| User Interaction | None | No social engineering needed; fully programmatic trigger |
| CVSS Score | ≥7.8 | Typically Important; ≥9.0 = Critical |
| Exploitation | More Likely | MSRC's internal team found a practical exploit path |
| Acknowledgement | External researcher | The reporter likely has a private PoC; writeup may follow in 30-90 days |

**Combining fields for prioritization**:
- `EoP` + `Local` + `Low Privileges` + `No User Interaction` + `Exploitation More Likely`
  = high-priority LPE, likely straightforward exploitation path
- `EoP` + `Local` + `Low Privileges` + `User Interaction Required` = LPE needing social engineering; lower priority

### 11.6.2 Formulating Hypotheses Before Diffing

Before opening BinDiff, write down your hypothesis:
```
CVE-2024-XXXXX
Component: Windows Installer (msiexec.exe)
Vulnerability type: EoP — Local
Hypothesis: Windows Installer performs a file operation (create/move/write) in a
SYSTEM context using a path that is directly or indirectly derived from user-controllable
input, without verifying the resulting path does not cross security boundaries via
junction or symlink.
Predicted change: An added check in a file operation path — either a path
canonicalization call, a symlink check, or an impersonation call before the file operation.
Predicted location: The MSI repair code path in msi.dll, specifically functions
handling file installation or rollback operations.
```

Having a pre-formed hypothesis makes the BinDiff review faster: you know what to
look for rather than reading all changed functions from scratch.

---

## 11.7 Root Cause Analysis Workflow

### 11.7.1 The Five Questions

For every patched function, answer:

1. **What changed?** — Identify the specific instruction or code block added/removed
2. **Why?** — What bug does the change prevent?
3. **Is it complete?** — Does it address root cause or just the reported PoC vector?
4. **Where else?** — Are there other functions with the same pattern but not patched?
5. **What does it enable?** — Can a variant exploit the same root cause via a different path?

### 11.7.2 Root Cause Classification Table

| Root Cause Type | Code Pattern | Fix Pattern |
|---|---|---|
| Missing validation | No bounds check on user-controlled size | Add `if (size > MAX) return error` at all call sites |
| Wrong layer fix | Check added in caller, not in vulnerable function | Move check into the vulnerable function itself |
| Partial call site | Only the reported code path fixed | Fix all functions sharing the same root cause |
| Type confusion | Object treated as wrong type | Add type check before cast or use typed containers |
| TOCTOU race | Check then use with timing window | Make check-use atomic; use transactional file/registry operations |
| Integer overflow | Size arithmetic wraps to small value | Use `RtlSIZETAdd`, `SafeInt`, or validate before arithmetic |
| Missing impersonation | No `RpcImpersonateClient` / `ImpersonateNamedPipeClient` before privileged op | Add impersonation call at correct position |
| Wrong impersonation level | Impersonation level not checked (≥ Impersonation required) | Check `GetImpersonationLevel() >= SecurityImpersonation` |
| Symlink not checked | No `CreateFile` with `FILE_FLAG_OPEN_REPARSE_POINT` check | Add symlink validation before file operations |

### 11.7.3 Fix Quality Assessment Checklist

```
Date:
CVE:
Affected Component:
Affected File:
Build Pre-patch:
Build Post-patch:

Changed Functions:
  1. FunctionName (BinDiff similarity: 0.97)
     - Change: Added `if (pszPath == NULL || !RtlPathIsUncOrDevice(pszPath)) return E_FAIL`
       before CreateFileW call
     - Root cause hypothesis: Path not validated before file operation as SYSTEM;
       caller can supply a junction/symlink path

Root Cause Assessment:
  - Root cause: Missing path validation allowing symlink redirect in SYSTEM file operation
  - Fix type: [root-cause / symptomatic / partial] → PARTIAL — added check only in
    one code path; the repair code path in MsiRepairProduct was not patched
  - Fix completeness: [complete / incomplete] → INCOMPLETE
  - Reason: The check was added in the install path but the rollback/repair path
    calls the same underlying CopyFile function via a different caller

Variant Hypotheses:
  1. MSI repair path: does MsiRepairProduct trigger the same unvalidated file write?
  2. MSI rollback path: does rollback on failed install perform the same file operation?
  3. Are there other MSI operations (custom actions, self-registration) with same pattern?

Follow-up:
  - [x] Check MsiRepairProduct code path in msi.dll
  - [ ] Check MsiInstallMissingComponent
  - [ ] Check self-registration DLL load path
  - [ ] Test variant hypothesis 1 with PoC
```

### 11.7.4 From Crash/PoC to Root Cause

When starting from a crash or a public PoC rather than a patch:

1. **Reproduce the crash**: set up the environment, run the PoC, confirm the crash
2. **Identify the crash site**: in WinDbg, `k` backtrace at the crash; identify the
   function that crashed and the call chain
3. **Understand the crash type**: access violation (read/write to bad address),
   stack overflow, assertion failure, pool corruption
4. **Walk up the call stack**: find where attacker-controlled input entered the
   kernel/privileged path
5. **Identify the missing check**: what validation would have prevented the crash?
6. **Verify the root cause**: write a minimal PoC that demonstrates the root cause
   in isolation — not just the original PoC trigger
7. **Map call sites**: find all other places in the binary that call the same
   underlying vulnerable function or perform the same dangerous operation

---

## 11.8 Symbol-Aided Analysis

### 11.8.1 What Public Symbols Provide

Microsoft's public PDB files contain:
- Function names for all exported and many internal functions
- Basic type information (structure names, field names, sizes)
- Global variable names
- No source code, no local variable names, no parameter names (those are in private PDBs)

This is sufficient for 80% of patch analysis work. Function names like
`CmpComputeSecurityDescriptor`, `MiValidateVirtualAddressForSectionMapView`, or
`NtTokenImpersonateLevel` tell you exactly where you are in the codebase without
reading a single instruction.

### 11.8.2 Recognizing Security-Relevant Function Names

Develop a vocabulary for security-relevant function name patterns in Windows:

| Pattern | Example | Implication |
|---|---|---|
| `Check*` | `CheckImpersonationLevel` | Missing check here → bypass |
| `Validate*` | `ValidateBufferAccess` | Added in patch → previous missing validation |
| `Impersonate*` | `ImpersonateClient` | Present/absent determines impersonation correctness |
| `Probe*` | `ProbeForRead`, `ProbeForWrite` | Kernel safety check for user-mode pointers |
| `RtlSecure*` | `RtlSecureZeroMemory` | Security-hardened primitive |
| `SeAccess*` | `SeAccessCheck` | Access check — absence enables bypass |
| `ObReference*` | `ObReferenceObjectByHandle` | Object handle validation |
| `Cm*` | `CmpCheckRegistry`, `CmOpenKey` | Configuration Manager (registry) |
| `Mm*` | `MmProbeAndLockPages` | Memory manager — probe/lock for user memory access |

When BinDiff shows a new call to a `Check*` or `Validate*` function was added in
the patch, the original code had a missing check — that is the root cause.

### 11.8.3 Workflow: Symbols + BinDiff Together

```
1. Load both pre-patch and post-patch binaries in IDA with symbols
2. Run BinDiff
3. In the matched functions list, immediately visible: function names
4. Sort by similarity 0.90-0.99 — you see names like:
   "NtCreateFile" (score 0.98), "CmpCheckKey" (score 0.96), "MsiInstallFile" (score 0.97)
5. The NAME tells you the component; the score tells you something changed
6. Navigate to the changed function — symbols help you instantly understand context
7. Look at callers (cross-references) by name — quickly assess fix scope
```

---

## 11.9 NtDiff Syscall Table Changes as Signal

The j00ru syscall table (`https://j00ru.vexillium.org/syscalls/nt/64/`) is a build-by-build
record of all NT syscalls. When analyzing a Windows update:

**New syscall added**: Investigate immediately. New syscalls are often:
- New features with their own attack surface
- Replacements for previously vulnerable syscalls (the old one may still exist as
  deprecated, creating a double-implementation situation)
- Split of an existing syscall into multiple variants (check the parent syscall for
  the original vulnerability)

**Syscall removed**: May indicate:
- Hardening (removing a dangerous interface)
- The old interface was the vulnerable one; patched by replacement

**Syscall argument count changed**: The kernel interface was modified. IDA/Ghidra
will show the handler function changed significantly. Worth diffing even without
a specific CVE for it.

---

## 11.10 Real Example Workflow: CVE Advisory → Root Cause → Variant

### 11.10.1 Advisory Analysis

**Hypothetical walkthrough matching the PrintNightmare class**:

MSRC Advisory reads:
```
CVE-2021-1675: Windows Print Spooler Remote Code Execution Vulnerability
Severity: Critical
Exploitation: More Likely
Attack Vector: Network
Privileges Required: Low
Affected: Windows Print Spooler (spoolsv.exe, spoolss.dll)
```

**Hypothesis formed**:
- Network vector + Low Privileges + Print Spooler = likely an RPC method accepting
  a path that triggers a file or DLL load operation
- Print Spooler historically loads printer driver DLLs from UNC paths — likely a
  validation bypass on the driver DLL path

### 11.10.2 Binary Identification

1. Check MSRC advisory: "spoolss.dll" named as affected
2. Download pre-patch spoolss.dll from Winbindex (previous cumulative update build)
3. Download post-patch spoolss.dll from extracted KB

### 11.10.3 BinDiff Analysis

Run BinDiff on both versions. Sort by similarity 0.90-0.99.

Hypothetical findings:
- `AddPrinterDriverEx` — similarity 0.97 — **HIGH PRIORITY**
- `ValidateDriverInfo` — similarity 0.93 — review
- `GetPrinterDriverDirectory` — similarity 0.99 — minor change

Navigate to `AddPrinterDriverEx` diff → added basic block containing:
```c
// Post-patch code added:
if (!IsPrivilegedCallerContext()) {
    if (!IsLocalPath(pConfigInfo->pDriverPath)) {
        return ERROR_ACCESS_DENIED;
    }
}
```

**Root cause identified**: `AddPrinterDriverEx` accepted a UNC path (`\\server\share\driver.dll`)
for the printer driver without checking whether the caller had sufficient privilege to
load remote DLLs. The fix added a check requiring either a privileged caller or a
local (non-UNC) path.

### 11.10.4 Fix Completeness Analysis

**Questions**:
1. Does `AddPrinterDriverW` (non-Ex version) have the same check? → Check with BinDiff
2. Does `InstallPrinterDriver` also need the same validation? → Cross-reference
3. Can the check be bypassed? If the caller can impersonate an admin before calling,
   `IsPrivilegedCallerContext()` returns true → the UNC path restriction is bypassed

**Result**: The fix was incomplete. `AddPrinterDriverEx` was fixed but the underlying
driver installation path was callable via other RPC methods. PrintNightmare's exploitability
persisted through multiple patch iterations as Microsoft addressed individual call sites
rather than the root cause: the design assumption that any caller could specify arbitrary
DLL paths for printer drivers.

### 11.10.5 Variant Hypotheses Generated

1. Are there other `AddPrinter*` RPC methods that call the same DLL loading code?
2. Does the `EnumPrinterDrivers` → `GetPrinterDriverDirectory` combination expose
   a path disclosure that helps target the UNC share?
3. Does the `Point and Print` policy configuration bypass the new check?
4. Are there 32-bit vs 64-bit path differences in the driver loading?

Each hypothesis is a potential CVE. This is variant hunting emerging directly from
patch diff analysis.

---

## 11.11 Practical Setup Checklist

```
[ ] WinDbg configured with Microsoft Symbol Server path
[ ] IDA Pro or Ghidra configured with Microsoft Symbol Server
[ ] BinDiff plugin installed in IDA/Ghidra
[ ] Diaphora installed in IDA (for second-pass diff)
[ ] Research VMs snapshotted BEFORE each Patch Tuesday
[ ] Winbindex bookmarked for pre-patch binary downloads
[ ] MSRC Security Update Guide bookmarked, checked every 2nd Tuesday
[ ] NtDiff syscall table bookmarked for build comparisons
[ ] Patch diff exercise log maintained (one entry per CVE analyzed)
[ ] Hypothesis template applied to each new CVE before diffing
```

---

## References

[R-1] BinDiff — Google / Zynamics
  — https://www.zynamics.com/bindiff.html

[R-2] Diaphora — joxeankoret
  — https://github.com/joxeankoret/diaphora

[R-3] MSRC Security Update Guide — Microsoft Security Response Center
  — https://msrc.microsoft.com/update-guide/

[R-4] Winbindex — Windows Binary Index
  — https://winbindex.m417z.com/

[R-5] Windows NT x64 Syscall Tables (NtDiff)
  — j00ru (Mateusz Jurczyk) — https://j00ru.vexillium.org/syscalls/nt/64/

[R-6] Project Zero Root Cause Methodology
  — Google Project Zero — https://googleprojectzero.blogspot.com/
