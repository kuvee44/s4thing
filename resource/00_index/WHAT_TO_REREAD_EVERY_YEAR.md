# What to Reread Every Year

Eight items. That's the list. Not because the field has only eight important works — it has many more — but because the discipline of rereading demands selectivity. These are the materials where a stronger researcher will notice genuinely different things on reread than they noticed before. That's the criterion for inclusion.

Read the whole list once a year. In order if you can. Take notes each time. Compare your notes year-over-year. The delta in what you notice is a direct measurement of your growth as a researcher.

---

## Windows Security Internals (Forshaw, No Starch Press)

- **Author:** James Forshaw
- **URL:** https://nostarch.com/windows-security-internals (book)
- **Why reread:** This is the only book that explains Windows security as a system of interacting trust models rather than as a list of features. Every CVE you study changes what you see when you reread specific chapters. The book does not age — the mechanisms it describes are the ones that matter.
- **What a stronger reader notices on second read that a weaker reader misses:** On first read, most people read for the models — how tokens work, how ACLs work, how integrity levels work. On second read, a researcher who has seen 10-20 CVEs starts noticing the precise wording of conditional statements. "When X performs Y, the check is applied IF Z" — the "if Z" becomes the interesting part. Forshaw is precise in a way that, on first read, looks like careful writing. On second read, the precision reveals which conditions are and aren't protected.
- **What to look for on Year 1 reread:** Build the basic models correctly. Tokens, privileges, ACLs, DACLs, SACLs, integrity levels, the security reference monitor. Understand how `AccessCheck` works at the level of what it actually checks. Understand what impersonation means mechanically (not conceptually). Understand what "impersonation level" means and why `SecurityIdentification` is different from `SecurityImpersonation`. These are the primitives for everything else.
- **What to look for on Year 2 reread:** Look for sentences that describe when checks are NOT performed. "This check is only performed if..." Read those completions slowly. They describe the attack surface. Also: read Chapter 8 (on sandboxing) after having studied at least two sandbox escape CVEs. The design decisions that enabled those escapes will now be visible in the text. Also: start asking "where does Forshaw hint at interesting behavior without labeling it as a bug?" He does this. He knows he's pointing at things. He can't write a bug bounty report in a book, but he can write a sentence that a careful reader will parse as "this is worth auditing."
- **What to look for on Year 3+ reread:** Use specific chapters as auditing checklists. When you're reviewing a new Windows component that crosses privilege boundaries, reread the chapter on tokens before you start. When you're looking at a COM server, reread the chapter on COM security. The book becomes a pre-audit preparation tool. Also: annotate where Windows behavior has changed since the book was written. The book describes a snapshot; Windows changes. The gap between the book's description and current behavior is itself an attack surface.

---

## Windows Exploitation Tricks Series (Forshaw, Project Zero Blog)

- **Author:** James Forshaw
- **URL:** https://googleprojectzero.blogspot.com/search/label/exploitation (filter for "Windows Exploitation Tricks" in title)
- **Why reread:** These posts are a systematic catalog of exploitation primitives, not CVE-specific write-ups. They describe capabilities: "here is a way to achieve an arbitrary file write from low integrity." The primitives persist longer than the specific bugs that motivate them, and each reread against a more knowledgeable background reveals which techniques remain viable and which have been retired.
- **What a stronger reader notices on second read that a weaker reader misses:** On first read, the techniques appear as a list of tricks. On second read, after studying more Windows internals, you see the architectural logic connecting them — why these tricks work is explained by the same underlying models. A stronger reader also notices which techniques Forshaw describes but doesn't fully exploit — places where he presents the primitive and a limited use case but the full use case requires assembly work that the post doesn't cover. Those are research leads.
- **What to look for on Year 1 reread:** Understand the primitive in each post at the level of "what does this give an attacker, and from what starting position?" Build a mental map: arb-file-write, arb-file-read, SYSTEM file op with user-controlled path, low-to-medium integrity escalation, etc.
- **What to look for on Year 2 reread:** For each primitive, ask: is this still unmitigated? Has a Windows update addressed the root pattern, or only specific instances? This requires looking at changelogs and security update metadata, which is tedious but productive. Also identify which primitives Forshaw hints at but doesn't develop — these are invitations to do the follow-on work he left on the table.
- **What to look for on Year 3+ reread:** Use each primitive as a mental search query when auditing new code. "Does this component perform a privileged file operation on a user-influenced path?" is a question that maps directly to the write-up on oplock-based file race primitives. The posts become a vocabulary for thinking about attack surface, not a list of historical techniques.

---

## PrintSpoofer: Abusing Impersonation Privileges on Windows 10 and Server 2019 (itm4n)

- **Author:** itm4n
- **URL:** https://itm4n.github.io/printspoofer-abusing-impersonation-privileges/
- **Why reread:** This post demonstrates not just a technique but a methodology for finding that technique. Itm4n didn't discover this by accident — he was systematically looking for privileged services with named pipe interactions. The methodology is more durable than the specific bug, and it's present in the post if you read for it.
- **What a stronger reader notices on second read that a weaker reader misses:** On first read, most readers focus on the exploit: the pipe name, the impersonation flow, the privilege escalation. On second read, a stronger reader notices how itm4n found the pipe name pattern — what he was looking for, how he searched for it, what properties made the spooler service a candidate. The search methodology is embedded in the post but easy to miss when you're focused on the technique.
- **What to look for on Year 1 reread:** Understand the exploit chain mechanically. What does `ImpersonateNamedPipeClient` do? Why does a SYSTEM service connecting to an attacker-controlled pipe result in token theft? What is the minimum impersonation level needed for this to work?
- **What to look for on Year 2 reread:** Reverse-engineer the search methodology. What properties must a service have to be vulnerable to this class of attack? Make a list: service runs as SYSTEM, service connects to named pipes based on a predictable naming scheme, service calls `ImpersonateNamedPipeClient` after connecting, impersonation level is sufficient for the attacker's goal. That list is a search template for new instances.
- **What to look for on Year 3+ reread:** Apply the template to current Windows builds. Does the specific named pipe name pattern still work? Are there new services that match the template properties? Have new mitigations been applied to `ImpersonateNamedPipeClient` or to the spooler specifically? The post is also worth rereading after each major Windows version to ask: where does this pattern still apply?

---

## Bochspwn Reloaded: Detecting Kernel Memory Disclosure with x86 Emulation (j00ru)

- **Author:** Mateusz "j00ru" Jurczyk
- **URL:** https://j00ru.vexillium.org/slides/2017/bochspwn_reloaded.pdf (Black Hat 2017)
- **Why reread:** The technique — full-system x86 emulation with taint tracking to find kernel information leaks — is secondary. The primary value is the architectural insight into why kernel code touches user memory without proper protection. That insight is platform-wide and enduring. The methodology for building systematic detection tooling for a whole bug class is also worth studying independently.
- **What a stronger reader notices on second read that a weaker reader misses:** On first read, the technique is fascinating and the scale of the findings is impressive. On second read, after reading more kernel internals, the reader understands the architectural reason why these bugs exist — not "kernel code forgot to check," but the specific design patterns in the Windows I/O stack that create the conditions. The structural reason is in the research if you know enough to see it.
- **What to look for on Year 1 reread:** Understand what taint tracking is, how Bochs emulation is instrumented, and what category of bugs this finds. Understand what a kernel information leak is, why it matters for exploit reliability (KASLR bypass, stack layout disclosure), and why these bugs are systematically underreported before tooling like this exists.
- **What to look for on Year 2 reread:** Ask: why does kernel code touch user memory in the first place? The answer involves the Windows I/O model, buffer passing conventions, and the architecture of user-kernel transitions. Understanding this explains why the bug class is common, not just that it is common. Also ask: what other bug classes would this methodology find if the taint tracking invariant were changed?
- **What to look for on Year 3+ reread:** Generalize the methodology. Bochspwn is a specific instantiation of "instrument full-system emulation to detect invariant violations." What other invariants can you instrument for? What other kernel subsystems have structurally similar design patterns where the bug class might be common? The kernel/user memory disclosure angle has been largely addressed. What's the analog for today?

---

## Windows Internals Part 1 (7th Edition), Chapters 3 and 7

- **Author:** Yosifovich, Ionescu, Russinovich, Solomon
- **URL:** (book) https://learn.microsoft.com/en-us/sysinternals/resources/windows-internals
- **Why reread:** Chapter 7 (Security) and Chapter 3 (Processes, Threads, and Jobs) are the two chapters most directly relevant to privilege escalation research. Every sentence in Chapter 7 becomes richer after you've studied ten real CVEs. The design decisions become visible as choices that had to be made and could have been made differently.
- **What a stronger reader notices on second read that a weaker reader misses:** On first read, the chapter on security reads like a reference. On second read, after studying real vulnerabilities, the same text reads like a map of attack surface. "The security reference monitor performs the access check" — where exactly? What state does it read? Can that state be manipulated? These questions don't occur to a first-time reader. They're obvious to someone who has studied how access check manipulation leads to privilege escalation.
- **What to look for on Year 1 reread:** Build the complete model of Windows process security. Token structure, privilege set, mandatory integrity level, session, desktop. How access checks work: DACL evaluation order, deny ACEs, integrity level comparisons. What impersonation is: the thread token override and when it applies. The difference between a token and a logon session.
- **What to look for on Year 2 reread:** Reread Chapter 7 after having studied 10+ CVEs with privilege escalation as the impact. Every sentence now should trigger a question: "which CVE class exploited this mechanism?" "What would break this check?" "Is there a way to influence the inputs to this comparison?" The chapter's descriptions become a checklist of things to probe when auditing a new component.
- **What to look for on Year 3+ reread:** Read as an auditor. Pick a Windows component you haven't studied. Read Chapter 7. Then enumerate: which of these mechanisms does this component use? What are the security-relevant decision points? Which inputs to those decisions come from untrusted sources? You're now auditing rather than studying.

---

## Working Your Way Around an ACL (Forshaw, tiraniddo.dev, 2024)

- **Author:** James Forshaw
- **URL:** https://www.tiraniddo.dev/2024/01/working-your-way-around-acl.html (approximate — verify current URL)
- **Why reread:** This post documents an ACL bypass involving the `WIN://SYSAPPID` security attribute and the WindowsApps folder permissions. It's a recent example of how Windows security mechanisms that appear comprehensive have edge cases in their attribute handling. It rewards rereading as Windows app security evolves.
- **What a stronger reader notices on second read that a weaker reader misses:** On first read, the exploit path is the focus. On second read, the reader notices the specific conditional logic in how Windows evaluates security attributes in ACL checks — the "when does the attribute override the standard check?" question. This conditional logic is the generalizable finding.
- **What to look for on Year 1 reread:** Understand the WindowsApps folder permission model, what `WIN://SYSAPPID` is and how it interacts with ACL evaluation, and what the attack achieves. This also requires background on UWP app security and how packaged apps are isolated.
- **What to look for on Year 2 reread:** Ask: where else does Windows use security attributes in access checks? What other attributes exist that could have similar conditional logic? This post documents one attribute bypass; is the attribute evaluation mechanism broadly correct, or is this a systemic issue?
- **What to look for on Year 3+ reread:** Track what Microsoft changed. Did they fix the specific attribute behavior? Did they fix the general evaluation logic? Are there new packaged app security mechanisms introduced in the Windows versions since this post that reopen or close this surface?

---

## Alex Ionescu's ALPC Research Posts and Presentations

- **Author:** Alex Ionescu
- **URL:** http://www.alex-ionescu.com/?p=336 and associated Black Hat/SyScan presentations (search "Ionescu ALPC")
- **Why reread:** ALPC is the interprocess communication mechanism underlying COM, RPC, and significant security-relevant kernel operations. It is structurally underexplored as an attack surface relative to its importance. Each time you know more about COM or RPC, you see ALPC differently.
- **What a stronger reader notices on second read that a weaker reader misses:** On first read, ALPC appears as plumbing — the mechanism underneath things. On second read, after studying COM security and RPC endpoint security, ALPC's own security model (connection attributes, message attributes, port handles, process handles embedded in connection context) becomes legible as an attack surface. The connection between ALPC security decisions and higher-level COM/RPC security properties only becomes clear when you know both layers.
- **What to look for on Year 1 reread:** Understand ALPC primitives: what a port is, how connection is established, what message types exist, how handles are passed, what the kernel-side objects look like. This is necessary background for everything else.
- **What to look for on Year 2 reread:** Map ALPC onto the COM and RPC layers above it. When a COM server accepts an activation request, what ALPC operations happen? When RPC validates a client, where in the ALPC flow does that happen? The security properties of COM and RPC are implemented at the ALPC layer, and bugs in that implementation have wide impact.
- **What to look for on Year 3+ reread:** ALPC attack surface is largely uncharted relative to the number of researchers who work on COM and named pipe issues. Where does ALPC handle untrusted data? What is the attack surface for ALPC port connections? What kernel operations does ALPC trigger that might have security-relevant side effects? This is an open research direction.

---

## Rotten Potato: Privilege Escalation from Service Accounts to SYSTEM (foxglovesecurity)

- **Author:** Stephen Breen / foxglovesecurity
- **URL:** https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/
- **Why reread:** This post is a historical record of a technique that was eventually closed — but more importantly, it documents the three specific Windows architectural decisions whose intersection enabled the attack: DCOM local activation, NTLM loopback authentication, and the impersonation semantics of `SeImpersonatePrivilege`. Each of these individually is a design decision. Together, in the right conditions, they enabled a reliable LPE from any service account. Understanding exactly which decisions enabled this, and how they were addressed, is a template for finding the next intersection.
- **What a stronger reader notices on second read that a weaker reader misses:** On first read, the technique appears as a clever chaining of behaviors. On second read, the reader sees the three specific architectural properties being exploited, and asks: "If those three properties are X, Y, and Z, what analogous sets of properties might intersect in similarly dangerous ways in current Windows?"
- **What to look for on Year 1 reread:** Understand the technique mechanically. Why does DCOM activate as SYSTEM? Why does the NTLM loopback restriction not apply here? What does `SeImpersonatePrivilege` actually allow? What happens at the token level when `ImpersonateNamedPipeClient` is called?
- **What to look for on Year 2 reread:** Understand which specific Windows changes addressed this: the introduction of DCOM activation restrictions, the loopback authentication changes, the `SeImpersonatePrivilege` hardening. Notice which changes addressed root causes and which addressed symptoms. Notice that the Juicy/Sweet/RottenPotato family persisted for years because the changes were incremental symptom treatment rather than architectural fix.
- **What to look for on Year 3+ reread:** Use this as a template for "what services trigger SYSTEM authentication flows that I can intercept?" This is a generalization of the core technique. The specific DCOM vector changed, but the abstract pattern — find a privileged service that authenticates somewhere you can intercept, relay that authentication to gain an impersonation token — recurs. Where does it recur in current Windows builds?

---

## On the Discipline of Rereading

The weakness of most researchers is breadth without depth. A vault of 200 items read once is a bibliography. An 8-item canon read 3 times each is a research methodology.

Each reread of a strong technical work is a different read — not because the text changes, but because the reader does. The Forshaw chapter you read at six months of Windows research is not the same document you read at three years of Windows research. The mechanisms are identical. What you can see in them is not.

The act of rereading with deliberate questions — what do I notice now that I didn't notice before? — forces the comparison that measures growth. Without that comparison, it's easy to mistake familiarity for understanding. You can feel like you know something because you've seen the words before. Rereading with fresh questions immediately reveals the gap between familiarity and actual understanding.

Schedule it. Once a year, work through this list. Write two or three sentences on what each item means to you now vs. what it meant last year. The sentences will be different. That difference is the measure of the year.
