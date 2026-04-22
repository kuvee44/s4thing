# Windows Security Research — Learning Path

> This path builds a Windows hunter, not a Windows reader. Every stage demands output artifacts, not just familiarity. You advance when you meet the criteria, not when the calendar says so.

---

## Stage 1 — Structural Foundations

**Purpose:** Install the accurate kernel-level mental model of how Windows works. Without this, every subsequent observation is surface pattern-matching.

**Entry condition:** Comfortable reading x64 disassembly, can reason about pointer arithmetic and memory layout in C/C++, can navigate decompiled output in IDA or Ghidra without losing context.

---

### Canon Readings

1. *Windows Internals Part 1* (7th Ed.) — Yosifovich, Ionescu, Russinovich, Solomon — **S-TIER**
   - Ch. 1–3 (architecture, processes, threads), Ch. 5 (memory), Ch. 7 (security), Ch. 8 (I/O system)
   - Read with WinDbg open. Every concept has a `dt`, `!process`, or `!token` command that verifies it.
2. *Windows Security Internals* — James Forshaw — Ch. 1–4 **S-TIER**
   - These chapters establish the access check algorithm, token structure, and object security model. Without them, Stage 3 is memorization, not understanding.

---

### Labs

- **LAB: Access check algorithm in WinDbg** — Walk every branch of `SeAccessCheck` / `SepAccessCheck` under the kernel debugger. Teaches where security decisions actually happen and what inputs they consume.
- **LAB: Object namespace enumeration** — Enumerate the NT object namespace with WinObj and `NtObjectManager`. Teaches the substrate that all IPC, named pipe, section, and file operations are layered on top of.
- **LAB: Token anatomy across process classes** — Read `!token` output for 10 processes (service, GUI app, SYSTEM service, restricted, impersonating). Write an explanation of every field before closing the session.

---

### Investigation Skills to Develop

- Use `dt nt!_TOKEN`, `dt nt!_OBJECT_HEADER`, `dt nt!_SECURITY_DESCRIPTOR` actively — not just to confirm book descriptions but to find undocumented fields
- Trace every Win32 API you use to its NT syscall counterpart
- Maintain a personal glossary of every kernel data structure you touch

---

### Output Artifacts

Before advancing, produce without reference:

1. Written explanation of the NT access check algorithm: inputs, decision points, output
2. Token impersonation level table: what each level (Anonymous, Identification, Impersonation, Delegation) grants and denies
3. Call chain diagram: `CreateFile()` → Win32 subsystem → NT kernel → IRP dispatch to filesystem driver

---

### Failure Modes

- Reading *Windows Internals* without WinDbg open — the book without the debugger produces theory, not intuition
- Moving to Stage 2 before producing the output artifacts — familiarity is not the same as internalization
- Treating the security chapter as a checklist rather than a model to debug against

---

### Advancement Criteria

- Can explain every field in `!token` output cold, without reference
- Can trace a `CreateFile()` call from Win32 to IRP dispatch and set a breakpoint at the filesystem driver entry point
- Can write a working C program that opens a process token, enumerates its privileges, and prints their attributes
- Can use `Get-NtGrantedAccess` in NtObjectManager to verify what a specific token can access on a named object

---

## Stage 2 — Debugger Fluency

**Purpose:** Make the debugger a natural extension of thought. If you have to think about WinDbg syntax, you cannot think about the security question.

**Entry condition:** Stage 1 complete. Basic WinDbg orientation assumed. Knows what a kernel pool is.

---

### Canon Readings

1. Time Travel Debugging (TTD) documentation — Microsoft Learn — **S-TIER**
2. WinDbg Preview documentation — **A-TIER**
3. Process Monitor documentation + field reference — Sysinternals — **A-TIER**

---

### Labs

- **LAB: KDNET kernel debugging setup** — Configure KDNET, attach WinDbg to a live VM kernel, break on `NtCreateFile`, read the stack, read the arguments. Teaches kernel-level observation as a repeatable workflow, not a one-time setup.
- **LAB: TTD crash replay** — Record a process crash with TTD, replay to the faulting instruction, trace back to the cause. Teaches temporal investigation — understanding an event by rewinding to its cause.
- **LAB: ProcMon installer repair trace** — Capture a ProcMon trace of `msiexec /fa` on any installed MSI. Filter for SYSTEM-context file operations. Teaches the privileged file operation patterns that are the foundation of installer exploitation.
- **LAB: NtImpersonateThread breakpoint** — Break on `NtImpersonateThread` in the kernel debugger, trace the token duplication flow. Teaches where impersonation transitions actually occur in the kernel, not just the Win32 API layer.
- **LAB: Hardware breakpoint on arbitrary memory** — Set a hardware write watchpoint on a field in `_TOKEN` during an impersonation operation. Read the accessor. Teaches hardware breakpoint mechanics needed for data-flow tracing.

---

### Investigation Skills to Develop

- ProcMon filter construction is instantaneous — you should be able to build any filter from memory
- TTD `dx` queries for navigating object timelines (not just crash dumps)
- WinDbg scripting for repetitive observation (`.foreach`, conditional breakpoints)
- Know the difference between software breakpoints (INT3) and hardware breakpoints, and when each is necessary

---

### Output Artifacts

- A ProcMon saved filter set for: installer repair tracing, named pipe creation monitoring, privilege escalation indicators
- One TTD session analysis note: what happened, what caused it, what the timeline looked like

---

### Failure Modes

- Using WinDbg only when something crashes, not as an active investigation tool
- ProcMon as a passive observer — if you don't know what you're filtering for, the tool produces noise
- Never scripting a breakpoint — manual is fine for learning, but automation reveals patterns you'd miss manually

---

### Advancement Criteria

- Can configure KDNET from scratch in under 15 minutes
- Can set any NT syscall breakpoint and read its arguments before returning
- Can replay any TTD recording, find a specific function call, and read register/memory state at that point
- Can build a ProcMon filter for privileged file writes and identify suspicious operations in under 30 seconds on a live trace

---

## Stage 3 — Security Model Mastery

**Purpose:** Understand the Windows security model with sufficient precision to recognize when it is being violated — including when the violation is subtle.

**Entry condition:** Stages 1–2 complete. Can trace NT syscalls in WinDbg.

---

### Canon Readings

1. *Windows Security Internals* — James Forshaw — complete — **S-TIER**
2. tiraniddo.dev — COM security series — **A-TIER**
3. `NtObjectManager` PowerShell module — used as primary investigation tool throughout this stage — **S-TIER**

---

### Labs

- **LAB: Named pipe impersonation at the API level** — Write a C program: create a named pipe server, call `ImpersonateNamedPipeClient`, verify the impersonated token's level and privileges. Teaches the core impersonation primitive: what the API does, what the kernel enforces, and what the resulting token looks like.
- **LAB: COM server security descriptor enumeration** — Use `OleViewDotNet` to enumerate COM servers where `LaunchPermission` is absent or grants broad access. Teaches COM attack surface: what "no launch permission" means in practice and who can activate a COM server.
- **LAB: Named pipe DACL survey** — Use `NtObjectManager` to enumerate every named pipe on a test system and read each DACL. Identify pipes with overly permissive DACLs or no security descriptor. Teaches named pipe security surface as an enumerable, analyzable dataset.
- **LAB: UAC elevation trace in TTD** — Record a UAC elevation from consent dialog to elevated token creation. Trace `AiLaunchConsentUI`, `RpcSsImpersonateClient`, token creation in TTD. Teaches what UAC actually enforces (process isolation, not privilege barrier) and where the trust transition occurs.
- **LAB: Integrity level access control** — Use `NtObjectManager` to find objects with mandatory integrity labels. Verify that a Medium integrity process cannot write to a High integrity object. Explain why this is enforced separately from DACL checks.

---

### Investigation Skills to Develop

- Read any security descriptor with `NtObjectManager` and state immediately what it grants and to whom
- Enumerate COM servers, their activation contexts, and their security descriptors as a workflow, not a one-off
- Understand exactly what changes at each impersonation level — not just that Delegation is "highest" but what operations each level unlocks

---

### Output Artifacts

- Written analysis of a COM server's security descriptor: what permissions it grants, to which principals, what an attacker with `SeImpersonatePrivilege` could do with the activation context
- Impersonation level reference card: for each level (Anonymous, Identification, Impersonation, Delegation), what you can do with the resulting token

---

### Failure Modes

- Understanding token structure without understanding impersonation levels with precision — knowing `Impersonation` exists but not being able to state what it allows vs. `Identification`
- Treating UAC as a security boundary — the *Windows Security Internals* book is explicit on this; if you still believe UAC prevents privilege escalation, you have not finished this stage
- Enumerating COM servers without understanding why some have no launch permissions and others do

---

### Advancement Criteria

- Given any process token, can state exactly what it can and cannot access, at what integrity level, and why
- Can enumerate COM server security descriptors with `NtObjectManager` and identify misconfigured ones in under 5 minutes on a live system
- Can explain exactly why `SeImpersonatePrivilege` allows SYSTEM escalation — tracing the precise path from "privilege held" to "SYSTEM token obtained"
- Can articulate the security model difference between Identification, Impersonation, and Delegation with concrete examples of what each permits and prohibits

---

## Stage 4 — Bug Class Taxonomy

**Purpose:** Build a complete mental model of Windows LPE attack surface organized by primitive, not by CVE number. A CVE is an instance; a primitive is the class.

**Entry condition:** Stages 1–3 complete. Can enumerate and analyze security descriptors independently.

---

### Canon Readings

1. Windows Exploitation Tricks series — James Forshaw (Project Zero) — **S-TIER**
2. itm4n blog — `itm4n.github.io` — **A-TIER**
3. decoder.cloud — Andrea Pierini — **A-TIER**
4. `symboliclink-testing-tools` — James Forshaw — **S-TIER as tool**

---

### Labs

- **LAB: PrintSpoofer API trace** — Reproduce PrintSpoofer step by step. For every API call, open the documentation and the implementation. Teaches the named pipe impersonation primitive: `CreateNamedPipe` + trigger SYSTEM connection + `ImpersonateNamedPipeClient` → SYSTEM token.
- **LAB: BaitAndSwitch junction + oplock construction** — Build a junction + opportunistic lock attack targeting a test directory. Races a SYSTEM write operation through a junction redirection. Teaches the TOCTOU primitive: how a race window between security check and use creates a redirection opportunity.
- **LAB: COM impersonation surface enumeration** — Use `NtObjectManager` to scan for COM servers that impersonate their callers during file operations. Teaches COM as an attack surface: activation → impersonation → file operation → redirection.
- **LAB: Windows Installer repair ProcMon + TTD** — Trace a full `msiexec /fa` repair in ProcMon, identify every SYSTEM file write, then replay in TTD. Teaches Windows Installer attack surface: MSI repair as a SYSTEM file operation trigger with controllable file paths.
- **LAB: Object namespace squatting** — Use `symboliclink-testing-tools` to place a symbolic link in the object namespace before a SYSTEM process creates its named pipe or section. Teaches object namespace as a security-relevant substrate: first-create-wins and what privileges that requires.

---

### Investigation Skills to Develop

- Classify any exploit primitive in one sentence: "X provides Y via Z"
- Enumerate, using tools, the live attack surface for any primitive: named pipes, COM servers, installer repair triggers, object namespace
- Identify which vulnerability reports are variants of the same primitive vs. genuinely distinct bug classes

---

### Output Artifacts

Pattern card for each bug class below — one paragraph per card: root cause, primitive provided, example CVE, variant hunting angle:

- Arbitrary file write / move / delete
- Junction / symlink / oplock (TOCTOU)
- Token impersonation (Potato family)
- Windows Installer / repair trigger
- Named pipe squatting
- Object namespace (symlinks, device maps)

---

### Failure Modes

- Reading about exploits without identifying the primitive — knowing that PrintSpoofer uses named pipes but not being able to find the *next* service that does the same thing
- Treating the Potato family (Hot, Rotten, Rogue, Sweet, Local) as distinct exploits rather than variations on one primitive with different trigger mechanisms
- Completing labs without producing the pattern cards

---

### Advancement Criteria

- Given a CVE description, can identify the exploit primitive in one sentence
- Can write the root cause of PrintSpoofer, InstallerFileTakeOver, and Rotten Potato in one sentence each, without reference
- Can enumerate named pipe surfaces, COM activation surfaces, and Windows Installer repair triggers on a live test system using tools — not manual browsing

---

## Stage 5 — Exploit Primitives

**Purpose:** Know how to transform a vulnerability's primitive into a working escalation chain. The primitive is the raw capability; the chain is the path to SYSTEM.

**Entry condition:** Stage 4 complete. Has produced all pattern cards.

---

### Canon Readings

1. Windows Exploitation Tricks series — James Forshaw — **S-TIER** (reread with exploitation focus)
2. HEVD (HackSys Extreme Vulnerable Driver) — **A-TIER**
3. Yarden Shafir — I/O Ring research — **A-TIER**
4. *Windows Kernel Programming* — Pavel Yosifovich — **A-TIER** (for kernel object model context)

---

### Labs

- **LAB: HEVD Stack Overflow → SYSTEM token steal (Win10)** — Stack overflow, shellcode or ROP to overwrite token pointer in EPROCESS, swap to SYSTEM token. Teaches kernel exploit skeleton: how userspace reaches kernel memory, how token stealing works at the kernel structure level.
- **LAB: HEVD Pool Overflow with segment heap grooming (Win10 20H1+)** — Pool corruption on the segment heap with controlled grooming. Teaches modern kernel pool exploitation: why naive pool sprays fail post-20H1 and what the segment heap requires.
- **LAB: MoveFileEx MOVEFILE_DELAY_UNTIL_REBOOT → DLL plant** — Weaponize a file move primitive into a reboot-persistent DLL plant. Build the full chain from "can move a file as SYSTEM" to "code executes on next boot." Teaches how a constrained file operation primitive becomes an exploitation chain.
- **LAB: NtSetInformationFile rename from unprivileged context** — Attempt NtSetInformationFile rename on a file in a protected directory. Document what fails and why. Teaches the exact NT-level constraints on file rename primitives and what privilege or handle access bypasses them.
- **LAB: Arbitrary file write → token privilege escalation chain** — Given a test harness that provides one arbitrary SYSTEM file write, build the full chain to code execution. Document every step and what breaks if any step is removed.

---

### Investigation Skills to Develop

- Draw a primitive chain diagram from any starting primitive to SYSTEM
- Know what additional primitives are required when a direct chain does not exist (e.g., "I have file write but not file move — what do I need next?")
- Read HEVD source and identify which vulnerability class each module represents before exploiting it

---

### Output Artifacts

Primitive chain diagram for each starting primitive → SYSTEM (method and required conditions):

- Arbitrary file write
- Arbitrary file move
- Arbitrary file delete
- Token impersonation (SeImpersonate held)
- Kernel write-what-where

---

### Failure Modes

- Treating exploit primitives as recipes rather than composable components — following a tutorial without understanding why each step requires the previous one
- Completing HEVD labs without being able to explain what would fail if the pool grooming step were skipped
- Not producing the primitive chain diagrams

---

### Advancement Criteria

- Given a primitive, can describe the escalation chain to SYSTEM without reference
- Can identify which HEVD vulnerability class any given kernel bug most resembles
- Can explain why segment heap grooming is necessary on Win10 20H1+ that was not necessary on earlier Windows versions

---

## Stage 6 — Lab Reproduction Intensive

**Purpose:** Build real exploitation intuition through hands-on reproduction. Reading about an exploit and building it are entirely different cognitive operations.

**Entry condition:** Stages 1–5 complete.

---

### Canon Readings

All tooling and PoC repositories from S/A-tier list. No new reading — this stage is execution.

---

### Labs (ordered by decreasing foundational importance)

- **LAB: InstallerFileTakeOver full reproduction** — Build the MSI repair trigger, construct the junction chain, verify that the SYSTEM file write is redirected to an attacker-controlled path. Teaches Windows Installer exploitation from first principles: MSI trigger → SYSTEM operation → junction redirection → arbitrary file write.
- **LAB: RoguePotato end-to-end** — Reproduce RoguePotato, with explicit focus on the OXID resolver step. Understand what the OXID resolver is, why it's contacted, and why redirecting it enables SYSTEM token capture. Teaches the DCOM/RPC component of the Potato primitive family.
- **LAB: Junction chain → DLL plant** — Build a junction chain that turns a SYSTEM cleanup operation (file deletion) into a DLL plant in a privileged directory. Teaches directory junction + symlink chaining: how to redirect a delete to a create.
- **LAB: LocalPotato NTLM reflection trace** — Reproduce LocalPotato. Trace the NTLM reflection at the SSPI layer in WinDbg. Understand what `AcquireCredentialsHandle` / `AcceptSecurityContext` / `InitializeSecurityContext` are doing in the loopback scenario. Teaches local NTLM reflection as a primitive distinct from the OXID-based Potato family.
- **LAB: PrintSpoofer variant** — After reproducing PrintSpoofer, find one additional Windows service that: (a) connects to a named pipe as SYSTEM, (b) you control the pipe name. Document whether it is exploitable. Teaches variant recognition: the exploit is a template, not a one-off.

---

### Investigation Skills to Develop

- For any reproduced exploit, be able to state in one sentence why each step is necessary
- Identify at which layer (Win32, NT, kernel, hardware) each exploit step operates
- Recognize when an exploit you're reproducing is a variant of a pattern you've already seen

---

### Output Artifacts

For every reproduced exploit: a one-paragraph explanation of why each step is necessary and what would fail if it were removed.

---

### Failure Modes

- "Reproduced" meaning "ran the PoC and got SYSTEM" — that is not reproduction, that is execution
- Not tracing the key steps in WinDbg — reading the code is not the same as observing the behavior
- Skipping the PrintSpoofer variant-finding task

---

### Advancement Criteria

- Can explain why each step of InstallerFileTakeOver, RoguePotato, and LocalPotato is necessary, cold
- Can identify the exact point in WinDbg traces where the privilege transition occurs for at least two reproduced exploits

---

## Stage 7 — Patch Diffing & Root Cause Analysis

**Purpose:** Read Microsoft's patches as research material. A patch tells you what invariant was missing; a missing invariant tells you where to look for variants.

**Entry condition:** Stage 4 complete. Can be run in parallel with Stage 6.

---

### Canon Readings

1. BinDiff — Zynamics/Google — **A-TIER** (as tool)
2. Diaphora — **A-TIER** (as tool, especially for large diffs)
3. MSRC Security Update Guide — **A-TIER**
4. Project Zero bug reports — style reference for root cause writing — **A-TIER**

---

### Labs

- **LAB: CVE-2021-41379 patch diff** — Diff `msi.dll` pre/post November 2021 patch. Find the added check. Write what condition the check enforces and whether it fully closes the primitive or only the specific trigger path. Teaches what MSRC considers a sufficient fix vs. what a researcher considers sufficient.
- **LAB: Naceri bypass analysis** — Read the Naceri bypass disclosure for the InstallerFileTakeOver patch bypass. Verify in the diffed binary that the bypass would not be caught by the patch. Teaches incomplete fix recognition: understanding the gap between what a patch checks and what the actual invariant should be.
- **LAB: Arbitrary Patch Tuesday diff** — Pick any Win32k or kernel fix from the last 6 months. Obtain pre-patch binary from a snapshot or MSRC portal. Run BinDiff or Diaphora. Identify the patched function. Write root cause in one sentence.
- **LAB: Project Zero report calibration** — Read three Project Zero reports for Windows vulnerabilities. For each, locate the "root cause" section. Write your own root cause for each before reading their version. Compare. Calibrate your precision.

---

### Investigation Skills to Develop

- Obtain pre-patch binaries from Windows Update catalogs or snapshot archives
- Run BinDiff on an unfamiliar binary pair without documentation assistance
- Distinguish between a patch that fixes a bug and a patch that adds a heuristic — they have different implications for variant hunting

---

### Output Artifacts

Root cause analysis in Project Zero format for 3 patched CVEs. Each must contain:
- Exact function name where the bug exists
- Exact condition that was absent
- What the patch added
- Whether the fix is sufficient (justify your answer)
- One variant hunting angle that the patch does not address

---

### Failure Modes

- Treating patch diffing as "find changed code" — the goal is to understand what invariant the patch enforces, not to locate the diff
- Writing root causes that describe behavior rather than conditions: "the function moves a file without checking permissions" is a behavior description, not a root cause
- Not assessing whether fixes are sufficient — incomplete fix recognition is a primary source of new findings

---

### Advancement Criteria

- Can obtain a pre-patch binary, run BinDiff, identify changed functions, and read the patch in under 2 hours on an unfamiliar CVE
- Can write a root cause analysis at Project Zero quality: precise condition, precise function, precise patch assessment

---

## Stage 8 — Variant Hunting

**Purpose:** Transition from consuming research to producing new findings. Everything before this was preparation.

**Entry condition:** Stages 4–7 complete.

---

### Canon Readings

1. `From_Strong_Reader_To_Variant_Hunter.md` — this vault — **S-TIER**
2. Bochspwn methodology — Mateusz Jurczyk — **S-TIER**
3. `NtObjectManager` — James Forshaw — **S-TIER as tool**
4. CodeQL Windows variant hunting queries — GitHub Security Lab — **A-TIER**

---

### Labs

- **LAB: Post-InstallerFileTakeOver MSI surface enumeration** — Enumerate all MSI packages installed on a test system. For each package, identify whether it runs SYSTEM file operations during repair. For SYSTEM-write candidates, determine whether the write path is user-influenceable. Document the full candidate list with reasoning.
- **LAB: Post-PrintSpoofer named pipe surface enumeration** — Enumerate all Windows services with named pipe endpoints. Filter for services that connect as SYSTEM with `SeImpersonatePrivilege` context. Identify candidates that have not been documented in prior research.
- **LAB: CodeQL / Semgrep pattern for privileged file write** — Write a static analysis pattern for "privileged file write without reparse point flag validation." Run against ReactOS source as a proxy for Windows internals. Document hits, assess each for exploitability.
- **LAB: Patch Tuesday monitoring cycle** — Monitor one complete Patch Tuesday cycle: read advisories, identify bug class, diff the patch, write root cause, identify variant hunting angle. Produce this output as a structured report.
- **LAB: New variant investigation** — Take the most interesting candidate from the MSI or named pipe enumeration labs. Investigate it to the point of confirming or ruling out exploitability. Document your methodology, not just your conclusion.

---

### Investigation Skills to Develop

- Build tool-based enumeration workflows that scale — manual review of 500 COM servers is not a methodology
- Distinguish "not yet found" from "not exploitable" — they require different documentation
- Maintain a running candidate list: every "interesting but unconfirmed" finding belongs there, not in the discard pile

---

### Output Artifacts

A variant hunting report for one bug class:

- Abstract pattern (3 sentences max)
- Tool-based enumeration of attack surface (document the enumeration methodology, not just the results)
- Candidate list with per-candidate analysis
- At minimum one "interesting" finding — unconfirmed and possibly unpatched, or an already-patched variant you found independently

---

### Failure Modes

- Waiting to do this stage until you feel ready — you will not feel ready, and you advance by doing, not by preparing
- Treating "no exploitable finding" as a failed stage — the methodology and enumeration are the product, not the CVE
- Producing candidates without methodology documentation — a list of suspicious services without an enumeration process is not variant hunting

---

### Advancement Criteria

**You have found something novel.** Even if already patched, not exploitable in current Windows version, or requiring additional primitives — you identified it yourself, using your own enumeration and analysis, not because someone told you where to look. This is the criterion. Everything else is preparatory.

---

## Stage 9 — Reporting & Bounty Workflow

**Purpose:** Write reports that MSRC accepts and pays on. Engagement with MSRC is a skill with known failure modes.

**Entry condition:** Stages 1–8 ongoing. Submit findings as they mature.

---

### Canon Readings

1. MSRC Security Update Guide — **A-TIER**
2. Windows Security Servicing Criteria — **A-TIER** (defines what MSRC considers a security boundary)
3. Prior MSRC disclosure communications — any public researcher's disclosure thread — **A-TIER**

---

### Labs

- **LAB: MSRC Servicing Criteria calibration** — Read the Windows Security Servicing Criteria document. For each of your bug class pattern cards from Stage 4, assess whether a finding in that class would qualify for a security bulletin under MSRC's criteria. Document the boundary cases.
- **LAB: Report structure draft** — Write a draft MSRC report for any reproduced CVE as if you had found it yourself. Include: vulnerability summary, root cause, reproduction steps, impact assessment, suggested fix. Have someone else read it and identify the first point of ambiguity.

---

### Output Artifacts

- Report template calibrated to MSRC's format requirements
- Servicing Criteria assessment for each bug class in your taxonomy

---

### Failure Modes

- Submitting before you understand MSRC's servicing criteria — a valid vulnerability in a non-security boundary wastes time on both sides
- Reproduction steps that require the reviewer to infer context — if they cannot reproduce in under 30 minutes from your report, rewrite it
- Treating the report as a formality after finding the bug — clarity of communication directly affects severity rating and payout

---

### Advancement Criteria

- MSRC acknowledges the report as a valid security vulnerability
- Report required no follow-up clarification to reproduce

---

## Time and Advancement

Done when you can meet the success criteria, not when the calendar says so.

The stages are ordered by dependency, not by time. Stage 7 (patch diffing) can run parallel to Stage 6. Stage 9 runs continuously once you have findings. The path is not a checklist — it is a model of what must be true before the next level of work is possible.
