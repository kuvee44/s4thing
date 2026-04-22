# From Strong Reader to Variant Hunter
## The Transition That Actually Matters

Most people who study Windows security for long enough eventually reach a point where they can read a Forshaw post and understand it. They can explain what happened. They can reproduce the technique. They can describe the primitive. They feel like they know the field.

And then they sit down to find a new bug and find nothing.

This document is about that gap — what it is, why it exists, and specifically how to cross it.

---

## The Gap

The gap is not about knowledge. This is the most common misdiagnosis. Researchers who can't find bugs assume they need to know more. They read more papers, study more CVEs, build more internals knowledge. None of this closes the gap, because the gap is not caused by a knowledge deficit.

The gap is caused by a mode deficit.

There are two fundamentally different ways to engage with Windows security material: consumption mode and production mode. Consumption mode asks: "what does this code do?" Production mode asks: "what does this code assume, and can I falsify that assumption?"

These are different questions. They require different habits of mind. And crucially, you can spend years in consumption mode — becoming highly knowledgeable — without ever developing the production-mode reflex. Most researchers do exactly this.

The transition from strong reader to variant hunter is the transition from "I understand this bug class" to "I am asking productive questions about new code." Knowledge is necessary but not sufficient for that transition. The transition itself requires a deliberate change in how you read and how you think while reading.

---

## What Changes When You Start Hunting

In consumption mode, the question you're implicitly asking while reading is: "do I recognize this?" You're pattern-matching against known bug classes. When you see a TOCTOU, you recognize it. When you see a junction abuse, you recognize it. This is useful — it's how security expertise feels. Recognition.

In production mode, the question is different: "what does this code assume the caller cannot do?"

This is a question about invariants, not recognition. Every piece of code that makes a security-relevant decision has implicit invariants — things that must be true for the decision to be correct. Those invariants are often unstated. They're obvious to the original author, so they never got written down. And they're often violable — not always, but often enough that the question is worth asking systematically.

Some examples of what invariant-based questioning looks like in practice:

- "This service opens a file based on a path from the registry. What does it assume about who controls that registry key?"
- "This code checks the file ACL and then performs an operation on the file. What does it assume about the relationship between the checked path and the operated path?"
- "This COM server accepts an IDispatch interface pointer from the caller. What does it assume about what the implementation behind that pointer will do?"
- "This function impersonates the calling thread's token when writing to the log file. What does it assume about where the log file path resolves to?"

In each case, the invariant is implicit — the code doesn't say it. Your job is to make it explicit and then ask whether it can be falsified.

This is not a technique you learn once and apply mechanically. It's a reflex you develop by deliberately practicing it on code you understand well, until it becomes automatic on code you're seeing for the first time.

---

## The Five Reading Modes

Reading for study and reading for hunting are different activities. Most researchers only practice the first two modes. Variants come from the last two.

### Mode 1: Comprehension Mode

*Question: What happened?*

You're following the narrative. You understand the attack chain. You can retell it. This is necessary and relatively fast to achieve. Almost everyone who studies a writeup reaches this level.

It does not enable you to find variants. It enables you to recognize the bug if you see it again in a PoC.

### Mode 2: Root Cause Mode

*Question: Why did this happen? What architectural reason explains it?*

You're going deeper. Not just the chain of events, but the specific design decision or assumption that made the chain possible. This requires Windows Internals knowledge to achieve — you need to know enough about the system to understand the "why" at the right level of abstraction.

Root cause mode is where most active researchers plateau. They can explain why a bug worked, in terms of the specific code involved. But they haven't yet abstracted that explanation to the level where it becomes a search query.

### Mode 3: Primitive Mode

*Question: What capability does this grant, independently of any specific exploit path?*

You're asking about the exploitation primitive, not the exploitation technique. "This provides an arbitrary file write into any directory SYSTEM has write access to" is a primitive. "This provides a SYSTEM token if the victim machine has the spooler running and the attacker has SeImpersonatePrivilege" is a primitive. The specific path to achieving the primitive may change; the primitive itself characterizes the bug's value.

Primitive mode is useful for two things: comparing bugs to determine relative value, and recognizing when different bugs provide the same primitive through different mechanisms (allowing you to chain techniques).

### Mode 4: Pattern Mode

*Question: Where else in Windows does this architectural pattern exist?*

This is where variant hunting begins. You've understood the root cause. You've identified the primitive. Now you abstract: what is the general description of the code pattern, design decision, or trust relationship that enabled this?

The abstraction must be at the right level. Too specific: "services that use the Windows print spooler RPC endpoint." Too abstract: "privileged services." Right level: "services running as SYSTEM that accept a path from the caller and perform a file operation with their own token, using impersonation only for the initial security check."

That abstract pattern is a search query. You can look for it in other services, other components, other Windows builds.

### Mode 5: Hunting Mode

*Question: Is this instance actually vulnerable?*

You've identified candidates from Mode 4. Now you're doing the actual work of verifying whether any of them are vulnerable. This involves:

- Confirming the preconditions exist (the pattern is actually present)
- Confirming the primitive is achievable (you can actually trigger the relevant code path from your privilege level)
- Confirming the protection mechanism is absent (there's no check you missed that prevents the attack)
- Attempting reproduction (building a PoC or a test case that demonstrates the issue)

Hunting mode is where you find bugs or confirm dead ends. Both outcomes are useful. The dead ends build understanding of why certain apparent patterns are actually protected.

Most researchers have never spent significant time in Mode 4 or 5. They're not because they lack knowledge — they're stuck because they've never deliberately practiced the transition.

---

## The Variant Hunting Workflow

After deeply studying any Windows vulnerability, this is the required sequence:

### Step 1: Write the Root Cause in One Sentence

Non-negotiable. If you cannot write the root cause in one sentence, you do not understand it at the level required for variant hunting. The sentence must name:
- The specific code or component
- The invariant that was assumed to hold
- The specific mechanism by which that invariant can be violated

*Bad*: "The service doesn't properly check the path before using it."

*Good*: "The service evaluates whether the path is in an allowed directory using `GetFullPathName`, then performs the file operation in a separate function that re-evaluates the path — between these two evaluations, the caller can replace the path's intermediate directory with a junction to redirect the final operation to an arbitrary target."

The good version generates a search query immediately: "code that evaluates path properties in one call and performs path-based operations in a separate call, where the path can be modified between the two."

### Step 2: Write the Abstract Pattern

Not the specific bug — the abstract description. Strip the component-specific details. What remains should be expressible as a search query that could match multiple Windows components.

*Specific*: "Task Scheduler LPE via junction attack on .job file path"

*Abstract*: "Privileged SYSTEM file operation on a path derived from a user-controlled registry value, without reparse point protection during the operation"

The abstract pattern is your search template. The specific instance is the proof of concept.

### Step 3: Enumerate Where the Pattern Recurs

Systematically. Don't guess — search.

**Same component, different code path**: Does the same function that contains the bug have other callers? Does the same component have other operations that use the same pattern? Patches frequently address the exact reported instance but leave adjacent code paths untouched.

**Different component, same pattern**: What other Windows services or components use this architectural pattern? "Services that call `CreateFile` with SYSTEM token on a path derived from user-controlled input without holding a handle open" is a pattern you can search for using Process Monitor traces and static analysis.

**Same pattern on different Windows versions**: Does the pattern exist on ARM64 builds? On Windows Server 2022? On older builds that may still be in enterprise production? The exploit preconditions or the specific API behavior may differ.

**Variant through a different primitive**: Can you achieve the same abstract root cause through a different mechanism? If the pattern is "check then use with user-modifiable state between them," are there other ways to modify the relevant state that the patch doesn't address?

### Step 4: Verify Candidates

For each candidate identified in Step 3:

1. **Confirm preconditions**: Is the service actually running? Is the code path reachable from your privilege level? Does the relevant registry key or file path exist?
2. **Confirm the primitive**: Can you actually trigger the relevant code path with controlled input? Use Process Monitor to trace file/registry operations during the trigger.
3. **Confirm protection absence**: Are there checks in the code path that prevent the attack? Use IDA/Ghidra or WinDbg to trace the execution. Don't assume the pattern is unprotected just because it looks similar.
4. **Attempt reproduction**: Build a test case. Document what happens, including failures. Failed reproduction attempts contain information about where the protection is, if there is one.

---

## The Patch Analysis Loop

Every patch is a free variant hunting report. MSRC tells you where the bug was, and the patch tells you what invariant they're now enforcing. From that, you can infer what invariant was previously assumed but not enforced, and you can look for other places where the same assumption holds.

**What does the patch add?**

A new check. A new flag. A restricted set of allowed paths. A different ordering of operations. A held handle replacing a path lookup. Each of these describes what was absent before.

**What does the check protect?**

Specifically: what invariant is the new check enforcing? "The path must not contain a reparse point" enforces the invariant that path traversal is stable. "The operation must be performed under impersonation" enforces the invariant that the actor's privileges apply to the operation. Making the invariant explicit tells you what the original code assumed and what the patch now requires.

**Is the check sufficient?**

This is the most important question, and the one most researchers skip. Does the new check:
- Apply to all callers of the vulnerable function? (Or only to the specific call site that was reported?)
- Apply to all input variants? (Or only to the specific input format that was demonstrated in the PoC?)
- Apply correctly across all Windows versions and configurations? (Or only under the specific conditions that the reporter tested?)
- Enforce the right invariant? (Or does it enforce a related but subtly weaker invariant that can still be circumvented?)

Naceri's same-day bypass of CVE-2021-41379 is the canonical example of this workflow executed correctly. The patch added a check at the specific code path that was reported. Naceri read the diff, identified that the check was not applied to a sibling code path in the same component, and demonstrated that the sibling path also had the vulnerability. The patch enforced the invariant in one place; the component had two places where the invariant needed to hold. This is not rare — it is the common case for complex Windows components.

**What assumption did the original code make that was wrong?**

State it explicitly: "The original code assumed [X] but this assumption fails when [Y]." Then ask: "Does this same assumption appear in adjacent code?" Adjacent means: the same file, the same component, or the same type of service.

**Does the same assumption appear in adjacent code?**

If yes, you have a variant. If no, document why not — the protection mechanism may be interesting in its own right.

---

## The Tooling Stack for Variant Hunting

Tools are not a substitute for understanding, but the right tools make understanding actionable.

**NtObjectManager (Forshaw, PowerShell module)**

This is the reconnaissance tool for pattern-based hunting. It lets you enumerate:
- COM server registrations and their process/activation contexts
- Named pipe instances and their permissions
- RPC endpoints and their interfaces
- Object directory contents
- Token and privilege information for running processes

When you have an abstract pattern like "SYSTEM service that exposes a named pipe with insufficient ACLs," NtObjectManager gives you the enumeration capability to find candidates without manually inspecting every service. Use it to build candidate lists, then triage manually.

**Process Monitor**

The ground truth tool for "what does this privileged process touch and can I influence it?" Configure it to trace a specific process (filter by PID) while performing a relevant operation. Watch for:
- File operations on paths that include user-controlled components (registry values, environment variables, user-writable directories)
- Registry reads during security-relevant decisions
- Named pipe connections from privileged services

Process Monitor makes implicit behavior explicit. A service that reads from `HKCU` before performing a privileged operation is doing something the security model may not have intended. Process Monitor shows you this is happening before you need to read the code to confirm it.

**BinDiff / Diaphora**

When you've found a pattern in a specific function, BinDiff (or the free Diaphora) finds structurally similar functions in the same or different binaries. If the vulnerable function is `Foo` in `Xyz.dll`, use BinDiff to find functions in other DLLs with similar call graphs. This is a force multiplier for variant finding when the pattern is identifiable at the function level.

**CodeQL**

Write the pattern as a query. Run it against the source. For Windows specifically, this requires either the Windows source (you don't have it), the ReactOS source (imperfect proxy for kernel patterns, more useful for user-mode components), or Wine (better for Win32 API patterns). The limitation is real — you can only query what you have source for. But CodeQL is worth learning because the discipline of writing a pattern query forces you to make the abstract pattern precise in a way that informal description doesn't.

**WinDbg with Breakpoints**

For verifying that a candidate code path is reachable and behaves as expected under controlled conditions. Once you have a candidate from enumeration or Process Monitor traces, use WinDbg to:
- Set a breakpoint at the location of the assumed-vulnerable check
- Confirm the breakpoint is hit when you trigger the candidate
- Inspect the arguments and register state at the breakpoint
- Step through the surrounding logic to confirm your mental model

Don't skip this step. Code that looks vulnerable statically is often protected by something that only appears at runtime.

**Time Travel Debugging (TTD)**

Record a trace of the trigger, then replay it to trace exact execution flow. TTD is valuable when the bug involves timing or when the code path is complex enough that single-step debugging is unwieldy. Record once; trace indefinitely. TTD is the fastest path from "this behaves unexpectedly" to "I understand exactly why it behaves unexpectedly."

---

## The Mindset Difference

The variant hunter carries a set of permanent questions that they apply to every new code pattern they encounter. These are not a checklist — they're reflexes, the kind of thing that happens automatically while reading code rather than requiring deliberate effort. You build the reflexes by asking the questions deliberately until they become automatic.

**"What does this code assume the caller cannot do?"**

The most important question. Every piece of code that makes a security decision has implicit assumptions about the caller's capabilities. Find the assumptions. Are they enforceable?

**"What would happen if this path were a junction?"**

Junction attacks are one of the most persistent bug classes in Windows file system security because so much code makes the implicit assumption that path traversal is stable. Ask this reflexively whenever you see privileged file operations. If the code would behave differently when a directory in the path is a junction, and the caller can create junctions, you have a candidate.

**"What privilege level does this service run as, and what can it be asked to do?"**

These two questions together define the attack surface. If the service runs as SYSTEM and can be asked to perform file operations on caller-specified paths, the attack surface is significant. If the service runs as a constrained virtual account with no privileges and can only perform operations on fixed paths, the surface is much smaller.

**"Where does the security check run, and where does the operation run? Is there a window between them?"**

The TOCTOU pattern is the most common shape of Windows file system vulnerabilities. The check and the operation are often in different functions, different threads, or different processes. The window is often much larger than the original author intended. Ask this whenever you see a security check followed by an operation, at any level of abstraction.

**"If this fix checks for X, what about Y?"**

The patch analysis question. MSRC fixes what they can reproduce and what they understand. They often fix the specific instance without fixing the general case. When you read a patch, ask what the general case is and whether the patch covers it.

---

## The Exercise

Take any CVE from the past two years in the Windows Installer or file system space. Pick something you haven't studied in depth. Then do the following:

**Step 1 (30 minutes)**: Read the MSRC bulletin, the patch diff if available, and the primary writeup. Write the root cause in one sentence — architectural level, invariant-based, specific. If you can't write the sentence after 30 minutes, keep reading and using WinDbg/Process Monitor until you can.

**Step 2 (30 minutes)**: Write the abstract pattern. Strip all component-specific details. What remains should be a description that could match other Windows components. If the pattern is too specific to this component, you haven't abstracted far enough.

**Step 3 (1 hour)**: Use NtObjectManager and Process Monitor to search for other Windows components that match the abstract pattern. Don't read code yet — enumerate candidates from behavior (what do privileged processes touch that user can influence?) and from structure (what services register the architectural properties your pattern requires?).

**Step 4 (varies)**: Document what you found. If you found candidates, note them. If you found no candidates, note why the pattern apparently doesn't recur — the protective mechanism that stops it is worth understanding.

Do this exercise. Document the output. The value is not in finding a bug — though that would be excellent. The value is in completing the mode transitions: comprehension → root cause → primitive → pattern → hunting. The transitions are what you're practicing. Do this exercise ten times, with different CVEs, and the mode transitions will become reflexive.

That's when you start finding things.
