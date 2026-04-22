# Patch Diff & Root Cause — Methodology Notes

## The "Distrusting the Patch" Framework

A patch should be trusted only after verifying that it:

1. **Addresses the root cause** — not just the specific PoC trigger
2. **Covers all call sites** — all code paths that share the same root cause
3. **Fixes the right layer** — not just the immediate symptom at a higher layer
4. **Does not introduce new bugs** — the fix itself is correct and complete
5. **Handles edge cases** — not just the happy-path trigger

When a patch fails any of these criteria, a variant or bypass is likely possible.

---

## Root Cause Classification

| Root Cause Type | Example | Fix Pattern |
|---|---|---|
| Missing validation | No bounds check on user-controlled size | Add validation at all call sites |
| Wrong layer fix | Fix in caller, not the vulnerable function | Move fix to the vulnerable function |
| Partial call site coverage | Fix only the reported code path | Fix all code paths with same pattern |
| Type confusion | Treating obj as wrong type | Add type check or redesign typing |
| TOCTOU | Check then use with race window | Atomize the check-use |
| Integer overflow | Size calculation wraps | Use safe math or restrict range |
| Privilege check missing | No impersonation level check | Add check at correct location |

---

## Obtaining Pre-Patch Binaries

### Method 1: Winbindex
- URL: https://winbindex.m417z.com/
- Search by filename (e.g., `ntdll.dll`)
- Filter by Windows version and build number
- Download PE directly

### Method 2: VM Snapshot Archive
- Take snapshots of VMs before applying patches
- Keep a library of known-good pre-patch snapshots
- Extract target DLLs from snapshot before patching

### Method 3: Cabinet File Extraction
- Download the KB update package (.msu)
- Extract with: `expand -F:* <file.msu> <output_dir>`
- Find the .cab within, extract again to get payload files

### Method 4: Windows Update Catalog
- https://www.catalog.update.microsoft.com/
- Download specific KB packages directly

---

## BinDiff Workflow Notes

### Scoring Interpretation
- **1.0** = Identical (not interesting)
- **0.95-0.99** = Very similar with minor changes → HIGH PRIORITY for review
- **0.80-0.95** = Moderate changes → REVIEW
- **0.50-0.80** = Significant changes → may be a rewrite or added functions
- **0.0** = New or removed function

### Common Fix Patterns in Windows
1. **Added bounds check**: New comparison instruction before buffer operation
2. **Added privilege check**: New call to RtlImpersonationNeeded or token check
3. **Changed type**: DWORD changed to SIZE_T for size arithmetic
4. **Added NULL check**: New comparison against 0 before pointer dereference
5. **Atomization**: Replaced non-atomic operation with locked variant
6. **Permission tightening**: Changed DACL/ACL on an object

---

## Symbol Server Configuration

### WinDbg
```
.sympath srv*C:\Symbols*https://msdl.microsoft.com/download/symbols
.reload /f
```

### IDA Pro
- Options → Debugger → Debugger options → Set symbol paths
- `srv*C:\Symbols*https://msdl.microsoft.com/download/symbols`

### Ghidra
- Edit → Symbol Server → Add Microsoft Symbol Server
- URL: `https://msdl.microsoft.com/download/symbols`

---

## MSRC Security Update Guide — Research Filters

Priority targets for patch diff:
1. **Exploitation More Likely** + **Critical** or **Important** severity
2. **Windows** component (not just Office/Exchange)
3. **Elevation of Privilege** or **Security Feature Bypass** vulnerability type
4. Components with known research attention (Win32k, Windows Installer, RPC, LSASS)

---

## Patch Diff Exercise Log Template

```
Date: 
CVE: 
Affected Component: 
Affected File: 
Build Pre-patch: 
Build Post-patch: 

Changed Functions:
  1. FunctionName (similarity: X.XX)
     - Change description:
     - Root cause hypothesis:

Root Cause Assessment:
  - Root cause:
  - Fix type: [root-cause / symptomatic / partial]
  - Fix completeness: [complete / incomplete — reason]

Variant Hypotheses:
  1. [hypothesis]
  2. [hypothesis]

Follow-up:
  - [ ] Check related functions
  - [ ] Search for similar patterns in related components
  - [ ] Verify fix completeness
```
