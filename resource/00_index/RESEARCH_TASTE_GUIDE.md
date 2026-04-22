# Research Taste Guide
## How to Tell Elite Windows Security Research from Noise

This is not a reading list. It's a calibration instrument. The goal is to develop the judgment to look at a blog post and know within two minutes whether it belongs in your canon or should be filed under "someone's CVE bounty story." That judgment is learnable. It's also what separates a researcher who consistently finds new bugs from one who consistently understands old ones.

---

## Part 1: What Elite Research Looks Like

The highest-tier Windows security research shares a set of structural properties. Not stylistic properties — structural ones. These are properties of what the author understood, not how they wrote.

### Root Cause Primacy

Elite research traces the vulnerability to the specific trust boundary that failed. Not "there's a race condition" but:

> "The security check evaluates the object path at the time of the IOCTL, but the actual file operation occurs later using a stored handle. The window exists because the object directory lookup in the kernel is not atomic with respect to the junction traversal — the path can be remounted between check and use because the directory object reference is not held across the gap."

That's a root cause. "The attacker tricks the service into writing to an arbitrary path" is not. One of these tells you where to look for siblings. The other tells you nothing except that the author has a PoC that works.

The diagnostic question: **can you trace the root cause to a specific invariant that was assumed to hold but doesn't?** If the author can, they're writing real research. If they explain that the software "doesn't properly validate user input," they've described the symptom, not the disease.

### Primitive Identification

An exploit chain is a path through a maze. A primitive is the capability the maze gives you, independent of any specific path.

Elite research names the primitive explicitly and independently of the exploit chain:

> "This gives an arbitrary file move primitive — we can move any file we own to any path the service's token can write to, including directories where only SYSTEM has write access."

This is the most intellectually durable part of the research. The specific exploit chain might break when a patch changes one API behavior. The primitive persists. A researcher who understands the primitive can find a new chain. A researcher who only understands the chain is stuck when one link breaks.

Notice that Forshaw almost always names the primitive before explaining how to use it. This is not a stylistic habit — it's evidence that he thought about the problem correctly. The primitive is the finding; the exploit is the demonstration.

### Variant Awareness

The best research explicitly asks: where else does this pattern exist?

Not every post reaches this. But the S-tier ones do, or they lay the architectural foundation that makes the question obvious to a careful reader. Look for:

- Explicit statements: "this same design pattern appears in X, Y, and Z"
- Implicit variants: the author explains an architectural reason why the bug exists (e.g., "every service that calls `CreateFile` to check permissions and then passes the path to another function") — any attentive reader can then generate the search query
- Fix analysis that points at partial coverage: "the patch addresses this specific caller, but the same helper function is called from three other locations"

When a post doesn't include any variant angle, ask yourself why. Either the author found only one instance (possible), the author didn't look (common), or the bug class has no natural siblings (rare).

### Architectural Reasoning

There's a difference between explaining how an exploit works and explaining why the design made the bug possible. The best research does both.

The "why" answer is usually one of a small number of Windows architectural patterns:

- Security checks in user mode; operations in kernel mode; user can modify state between the two
- Security check on name; operation on handle; name can be remapped
- Impersonation only applied to token lookup; file operation reverts to process token
- Capability granted by OS to a component; that component re-exposes it to less trusted callers without restricting it
- COM server with elevated token processes untrusted input that can escape to the file system

A researcher who understands these patterns doesn't need to memorize CVEs. They can audit new components by asking whether any of these patterns are present.

### Fix Analysis

This is a separator between researchers who understand bugs and researchers who understand Windows. Analyzing the fix requires understanding not just what was broken but what the correct design should have been.

Elite posts examine:
- **Completeness**: Does the patch cover all callers, all code paths, all input variants?
- **Correctness**: Does the fix enforce the right invariant, or does it enforce a related but weaker one?
- **Sufficiency**: Is this bug class now closed, or has the patch merely addressed the most obvious instance?

The Naceri-finds-bypass-day-of-patch workflow is the gold standard here. When CVE-2021-41379 was patched, the patch added a check — but it added it only in one place. The same pattern existed in a sibling code path. Reading the patch diff told Naceri exactly what the patch assumed and therefore exactly where the assumption still didn't hold.

This workflow is repeatable. It's also learnable. But you have to look at patches.

### The Forshaw Standard

Forshaw's writing is the canonical reference point not because of its reach or reputation but because of its specific qualities:

**Structural clarity**: Every post has an implicit structure — here is the system, here is the trust model, here is the place where the trust model has a gap, here is how to demonstrate the gap. You always know where you are.

**Explicit primitive labeling**: He names the capability before explaining how to achieve it. "This provides an arbitrary process token impersonation primitive" appears before the code, not after.

**Boundary analysis by name**: He identifies specific Windows security boundaries by their proper names — the user/kernel boundary, the integrity level boundary, the token impersonation boundary, the sandbox escape surface — and explains which one failed and why.

**Code-level grounding**: The explanation doesn't stop at the API level. It traces into the kernel. When he says "the object manager does X," he means it literally — you can follow the call in a debugger and watch it happen. This is not imprecision dressed up with italics; it's accurate description of actual execution.

**Selective completeness**: He doesn't explain everything. He explains exactly what's necessary to establish the root cause and the primitive, and no more. The prose is dense because it's not padded.

When you read something else, ask: does it have these properties? If not, it can still be useful. But calibrate accordingly.

---

## Part 2: What Mediocre Research Looks Like

Mediocre research is easy to produce. It requires finding a bug, producing a PoC, and writing up what you did in the order you did it. This is sufficient for a CVE bounty. It is not sufficient for building a research canon.

### The CVE Story Format

The shape of most low-quality writeups:

1. I was looking at X
2. I noticed Y
3. I wrote a PoC
4. It works on Windows 10/11
5. MSRC patched it
6. Here is the PoC

What's missing: why Y is exploitable. What trust boundary it violates. What the invariant was. What it means architecturally. What else has the same pattern. Whether the patch is correct.

A writeup in this format tells you one thing: that the bug existed. It does not tell you what you should know to find the next one.

### Crutch Phrases as Diagnostic Signals

When a technical author uses phrases like "basically," "kind of like," or "essentially does," they are signaling that they understand the phenomenon well enough to describe it but not well enough to explain it precisely. In casual speech, this is fine. In security research, it's a flag.

- "The service basically impersonates the client" — does it call `ImpersonateNamedPipeClient`? Or `SetThreadToken`? Or does it use COM server impersonation? These have different security properties. "Basically" hides the distinction.
- "It's kind of like a TOCTOU" — is it a TOCTOU? Does it have the specific properties (check-use gap, shared mutable state, window for race) that make TOCTOU meaningful? Or is it something else that superficially resembles one?

Elite research uses precise vocabulary because the author thought precisely. Crutch phrases are evidence that they didn't.

### The Exploit Chain as the Story

When the exploit chain is the narrative spine, the research is organized around what the author did rather than what Windows does. This produces writeups that are interesting to follow but useless for variant hunting.

"I pivoted to NTLM relay after the initial foothold" tells you about the attack path. "The service performs NTLM authentication over loopback, which allows any process that can force authentication to relay the token" tells you about the vulnerability.

One of these generates follow-on research. The other generates a copy-paste template.

### No Security Boundary Named

If you read the entire writeup and cannot identify which specific security boundary was violated, the writeup failed. Not "a privilege escalation occurred" — which boundary? Which invariant? User to kernel? Low integrity to medium? User to SYSTEM? Constrained to unconstrained token? AppContainer to full process?

This matters because Windows security is organized around boundaries. A researcher who thinks in terms of boundaries can audit any new component by asking "what boundaries does this component cross and how does it protect them?" A researcher who thinks in terms of specific CVEs can only recognize previously labeled bugs.

### Passive Voice as Epistemic Evasion

"The attacker can leverage this to elevate privileges." Who is the attacker? What privilege level do they start from? What access do they need to trigger the vulnerable code? What does "leverage" mean, precisely?

Elite research specifies the actor, their starting position, and the exact action:

> "A local user running as medium integrity with no special privileges can trigger this via [specific API call] to achieve [specific outcome]."

Every word here is load-bearing. "Local user" rules out remote exploitation. "Medium integrity" rules out low-integrity sandbox escape. "No special privileges" means no SeBackupPrivilege, no membership in specific groups. "Via [specific API call]" means the trigger is exact, reproducible, and diagnosable.

When a writeup uses passive voice throughout, it's usually because the author hasn't thought carefully about the preconditions and the scope of the vulnerability.

### Treating `NtCreateFile` as the End of the Story

A large fraction of Windows LPE bugs involve file system operations. Many writeups describe the attack using Win32 API calls: `CreateFile`, `MoveFileEx`, `SetFileAttributes`. This is sufficient for a PoC. It is not sufficient for understanding.

Below the Win32 layer is the NT API layer. Below that is the object manager, the I/O manager, the security reference monitor. At each layer, there are access checks, object lookups, handle operations, and security decisions being made. A researcher who knows what happens after `NtCreateFile` returns — what the object manager does with the path, how junctions are evaluated, where impersonation is applied and where it isn't — can reason about the bug class. A researcher who doesn't is limited to noticing that `CreateFile` with a certain path produces an unexpected result.

This is not about memorizing internals. It's about having a mental model at the right level of granularity to ask the right questions. When you don't know what happens after a call, you can't know where the window is, why the window exists, or whether it exists elsewhere.

---

## Part 3: How to Develop a Researcher's Eye

Taste is not innate. It's the product of systematic comparison with calibrated feedback.

### Exercise 1: The Parallel Read

Take a Forshaw Project Zero post from bugs.chromium.org and a randomly selected CVE blog post from the same year. Read them on the same day.

Then do a structural comparison:
- Can you state the root cause of each bug in one sentence?
- Can you name the security boundary violated in each case?
- Can you identify the exploit primitive in each case?
- Does either author ask where else this pattern exists?
- Does either author analyze the fix?

The answers should be consistently yes for the Forshaw post and inconsistently yes-or-no for the other. That difference is what you're training yourself to notice. After doing this ten times with ten different post pairs, you'll have internalized the structural template.

### Exercise 2: The One-Sentence Test

For any resource you read, immediately after finishing: write down three things.

1. **The exploit primitive in one sentence**: "This provides [capability] from [starting privilege level] to [achieved privilege level] via [mechanism]."
2. **The root cause in one sentence**: "The bug exists because [specific code] assumes [invariant] which can be violated by [specific action]."
3. **The variant question in one sentence**: "Where else does [abstract pattern] appear in Windows?"

If you cannot write sentence 1, either the resource failed to identify the primitive or you didn't understand the resource well enough. Figure out which.

If you cannot write sentence 2, either the resource gave you the exploit chain without the root cause (common) or the root cause requires more internals background (also common — this is the reason to read Windows Internals). Identify what you don't know.

If you cannot write sentence 3, you're not yet in variant-hunting mode. You can write it when you understand the abstract pattern well enough to search for it.

### Exercise 3: Read the Patch First

Before reading a writeup, find the patch. For recent Windows bugs, this is the MSRC security update page plus the diff (when source is available via reactos/wine comparison or via binary diff). For older bugs, this is often just the version delta in an affected DLL.

Ask: what does the patch add? A new check? A new flag? A new constraint on an operation? What does that tell you about what was missing?

Then read the writeup. Does it match your analysis? If the writeup's explanation of the root cause is inconsistent with what the patch does, at least one of them is wrong. Work out which.

This exercise builds patch-reading skill directly. It also means you arrive at the writeup with a hypothesis already formed, which makes the read much more productive.

### Exercise 4: The Five-Bugs-a-Year Test

After reading anything, ask: "What does a researcher who finds five bugs per year know from this post that someone who finds zero bugs per year doesn't know?"

The answer is usually not a specific technique — it's a way of looking. A specific question to ask when auditing code. A pattern to look for. A set of API properties to keep in mind.

If you can't articulate that difference, read again. The difference is there. The best research plants it deliberately.

---

## Part 4: The Hierarchy of Understanding

There are five levels of understanding Windows security material. Most researchers plateau at Level 2 and call it done. Only Level 4-5 understanding justifies moving to the next topic.

### Level 1: Can Describe

You can explain what happened in approximately accurate terms, using the vocabulary from the writeup you read.

*Example*: "PrintSpoofer abuses named pipe impersonation to get a SYSTEM token by tricking the spooler service into connecting to an attacker-controlled pipe."

This is necessary but not sufficient. You can pass a verbal quiz. You cannot debug a reproduction failure. You cannot find a sibling.

### Level 2: Can Reproduce

You can run the exploit in a lab on the right Windows build and patch level. You understand the environmental dependencies. You can tell when your reproduction failed because of an environment issue versus a misunderstanding.

Most people who study a bug reach this level and stop. This is a mistake. Level 2 understanding decays almost immediately — if the patch changes something or the environment changes, you're helpless. It also transfers to no other bug.

### Level 3: Can Explain

You can explain each step of the exploit at the API level, and at least the kernel-level explanation of the critical steps. Not "the service impersonates the client" but "the service calls `ImpersonateNamedPipeClient`, which internally calls `PsImpersonateClient`, which copies the client's token into the calling thread's impersonation token slot, which means subsequent object accesses from that thread use the client's access token rather than the service's process token."

At this level, you can reason about why mitigations would or wouldn't work. You can debug reproductions. You can answer questions. But you still can't reliably generate new bugs.

### Level 4: Can Generalize

You can enumerate at least three other places in Windows where the same architectural pattern exists. Not by guessing — by applying a search methodology. For the PrintSpoofer case: "privileged service listens on a named pipe with a predictable name; uses `ImpersonateNamedPipeClient` after a client connects; client's token propagates into a security-relevant operation." You can then search for other services in this category.

At this level, you're producing output that goes beyond what you read. You can do a variant search. You might find something.

### Level 5: Can Produce

You can find new instances of the bug class without being told where to look. You have a methodology for looking, a set of tools for searching, and a understanding deep enough to evaluate candidates quickly.

Level 5 does not require exceptional intelligence. It requires Level 3 understanding plus the discipline to actually go looking (Level 4) enough times that you develop intuitions about where the interesting patterns are.

The gap between Level 4 and Level 5 is iteration. The gap between Level 2 and Level 4 is understanding.

---

## Part 5: Reading Strategy for Elite Material

Reading a Forshaw post the way you read a blog post is a waste of a Forshaw post.

### Pass 1: Structure Read

Read once, quickly, for the architecture of the argument. Answer these questions:
- What is the exploit primitive? (Usually named in the first third.)
- What is the security boundary being crossed?
- What is the root cause at one level of abstraction above "the code"?
- What is the fix, and where does it apply the check?

You should be able to answer all four in writing after Pass 1. If you can't, the post is more complex than you expected and you need more background before Pass 2 is productive.

### Pass 2: Mechanism Read

Read again, slowly, tracing each API call. For every API name you encounter:
- Do you know what it does at the NT layer?
- Do you know what access checks it performs?
- Do you know under what conditions it uses the thread token vs. the process token?

Where you can't answer these questions, that's the gap to fill via Windows Internals, ReactOS source, or WinDbg. Don't skip it. The mechanism is where the bug lives.

### Pass 3: Variant Read

Read a third time asking one question for every design decision described: "Does this pattern exist elsewhere in Windows?"

This is not a rhetorical exercise. It produces a list of candidates. Write them down. You won't research all of them, but the act of generating the list builds the pattern-recognition capability that makes you faster on the next post.

### Pass 4: Lab Pass

Reproduce, or adapt, the key technique. Not necessarily the full exploit — the key primitive. If the bug requires an oplock to create a timing window, practice creating an oplock. If it requires a junction at a specific path, practice creating the junction with the required timing. If it requires connecting to a pipe that a privileged service will then open with specific access, practice building that listener.

The lab pass builds hands-on understanding that reading cannot give you. It also immediately reveals the places where your Pass 2 understanding was shallower than you thought.

### Pass 5: Write-Up Pass

Write one paragraph — not for publication, for yourself — summarizing:
1. Root cause (one sentence, architectural level)
2. Exploit primitive (one sentence, capability level)
3. Variant angle (one question: "where else does [abstract pattern] exist?")

Keep this. These paragraphs accumulate into a search index. When you're auditing new code six months later and encounter a pattern that half-matches something you've studied, you'll search your write-up paragraphs and find the ancestor.

---

*This guide is calibrated against the Project Zero body of work and specifically against the 2018-2025 Forshaw blog posts. If your research taste conflicts with these calibration points, update your taste.*
