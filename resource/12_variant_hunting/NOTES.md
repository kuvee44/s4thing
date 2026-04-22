# Variant Hunting — Methodology Notes

## Core Methodology: From One Bug to a Class

### Step 1: Root Cause Abstraction
Move from the specific to the general:
- **Specific**: "NtCreateFile does not check impersonation level before creating a file as SYSTEM"
- **Abstract**: "Windows components that create files as SYSTEM do not validate the calling thread's impersonation level"

The abstract version defines the search space.

### Step 2: Search Space Definition
Define what you are looking for:
- What operation is involved? (file create, registry write, token access...)
- What privilege context is involved? (running as SYSTEM, with a particular privilege...)
- What validation is missing? (impersonation check, bounds check, type check...)
- What is the effect? (arbitrary write, KASLR defeat, privilege escalation...)

### Step 3: Enumeration Strategy
Choose the approach based on what you have:
- **Source available** → CodeQL or Semgrep for automated scan
- **Binary only** → IDA/Ghidra pattern search, BinDiff across versions
- **Black-box** → Behavioral testing, API fuzzing, targeted input mutation
- **System-level** → Emulation-based taint tracking (Bochspwn approach)

### Step 4: Hypothesis Generation
For each candidate found in the scan:
- Does this code share the root cause?
- Is the vulnerable condition reachable?
- Can it be triggered from an exploitable context?
- Document even negative results — they define the boundary of the class

### Step 5: Fix Quality Assessment
After finding all instances:
- Which were patched in the same update?
- Which were patched in subsequent updates?
- Which are still unpatched?
- Document the fix completeness across the class

---

## Incomplete Fix Patterns in Windows History

### Pattern 1: Single Call Site Fixed, Others Missed
**Example**: Windows Installer rollback abuse — Naceri found multiple variants as Microsoft fixed individual call sites rather than the root cause.
**Detection**: Enumerate all call sites of the vulnerable function. Patches that only add a check in one caller while leaving others unchecked.

### Pattern 2: Surface-Level Fix Without Root Cause
**Example**: Administrator Protection bypasses — fixing the specific bypass demonstrated in the PoC while the underlying design assumption remains.
**Detection**: Reproduce the original PoC with a slightly different input or code path. If the fix only prevents the exact PoC, variants usually work.

### Pattern 3: Wrong Layer Fix
**Example**: Adding a check in a high-level API while the vulnerability exists in a lower-level function called by many APIs.
**Detection**: Identify all callers of the vulnerable function. If the fix is only in one caller, other callers remain vulnerable.

### Pattern 4: Regression (Previously Fixed Bug Reintroduced)
**Example**: A security fix in one Windows version is not forward-ported, or a refactor removes a security check.
**Detection**: Track the vulnerable function across Windows versions using BinDiff or j00ru's syscall tables. Look for cases where a security check that existed in version N is missing in version N+1.

---

## CodeQL Variant Hunting — Workflow

### Getting Started
1. Install CodeQL CLI: https://github.com/github/codeql-cli-binaries
2. Download CodeQL packs: `codeql pack download codeql/cpp-queries`
3. Create a database from target source: `codeql database create mydb --language=cpp`
4. Run a query: `codeql query run <query.ql> --database=mydb`

### Writing a Variant Hunting Query (C++ example template)
```ql
import cpp
import semmle.code.cpp.dataflow.TaintTracking

// Find all calls to DangerousFunction where the size argument
// is derived from user-controlled data without validation

from FunctionCall call, Expr sizeArg
where
  call.getTarget().getName() = "DangerousFunction" and
  sizeArg = call.getArgument(1) and
  // Add taint source condition here
  not exists(/* validation check */)
select call, "Potential variant: unvalidated size argument"
```

### GitHub Security Lab Query Examples
- https://github.com/github/codeql (search "windows" in queries)
- Look for queries in `cpp/ql/src/Security/` directory

---

## Bochspwn-Style Methodology — Applying to New Classes

The Bochspwn approach can be generalized to any class with a detectable invariant:

**Original**: "Uninitialized kernel memory should never be copied to userspace"
**Mechanism**: Taint bytes on allocation, detect when tainted bytes reach copy-to-user operations

**Generalize**:
1. Identify a security invariant: "X should never happen when Y"
2. Instrument the system to detect violations: taint tracking, shadow memory, hooks
3. Run the target workload: exercise the system extensively
4. Collect and triage violations

**Other invariants that could be checked with similar methodology**:
- "No kernel pointer should be written to userspace without encoding" (KASLR)
- "No kernel operation should be performed at the token's impersonation level without checking it is >= Impersonation" 
- "No user-controlled data should reach a kernel allocation size without bounds checking"

---

## Case Study Template: Variant Hunting Exercise

```
Target Component: 
Initial Bug/CVE: 
Root Cause (Abstract): 

Search Strategy:
  Tool used:
  Search pattern:
  Scope:

Candidates Found: N

Confirmed Variants:
  1. Location:
     Root cause match: [exact / similar / related]
     Exploitability: 
     CVE (if any): 

  2. Location: ...

Ruled Out:
  1. Location:
     Reason not a variant:

Fix Quality Assessment:
  Original patch: [complete / incomplete]
  Reason: 
  Subsequent patches: CVE-XXXX-XXXX (if any)

Lessons Learned:
```
