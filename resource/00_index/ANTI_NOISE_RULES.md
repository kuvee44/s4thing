# Anti-Noise Rules
## What Never Enters the Canon

These rules exist because noise is expensive. Every mediocre resource you read costs time you could spend on an elite one. Bad resources don't just waste time — they install shallow mental models that have to be uninstalled later. A researcher who learns privilege escalation from WinPEAS output will spend years re-learning the security model that WinPEAS was hiding.

---

## The Core Test

Ask this before adding any resource:

> "Does this help me think more clearly about Windows trust boundaries, attack surfaces, and primitive chains — or does it just tell me what to do?"

If the answer is "just tells me what to do," it belongs in the archive at best, and in the trash at worst.

A second test, for tools specifically:

> "When I use this tool, do I understand more about Windows security afterward — or do I just have a list of findings I still have to interpret?"

If the tool produces output you then have to understand using the primary reading material, it is a B-tier tool. It is not primary material. It is not a substitute for reading what it summarizes.

---

## Excluded Categories (with reasoning)

### 1. Enumeration Without Understanding

Tools and posts that produce privilege escalation checklists without explaining the security model behind each item. WinPEAS is the canonical example: it runs fast, finds things, and teaches nothing. A researcher who runs WinPEAS and gets a hit on "AlwaysInstallElevated" has not learned anything about the Windows Installer service trust model, the registry key hierarchy, the privilege the policy grants, or why it matters. They have learned that a tool found something. This is not the same thing.

The rule: if a resource produces a checklist without explaining the security model behind each item, it is B/C-tier at best and never enters the primary reading flow. Enumeration tools belong in the toolbox, not the library. Using them is not reading material.

A harder edge case: a blog post that explains the security model and then produces a checklist may still be A-tier. The test is whether the checklist is the goal or an artifact. If the security model explanation is the goal, the checklist is acceptable. If the checklist is the goal, the security model explanation is decoration.

### 2. CVE Tourism

A post that covers CVE-XXXX-YYYY by presenting the PoC, describing the patch, and noting the affected versions, without identifying the primitive class, the root cause, or the variant surface. The test: after reading this post, can you find the next bug in the same class? If not, the post is CVE tourism. It tells you about one bug but does not teach you how to find the next one.

CVE tourism is not false — it is incomplete in a way that masquerades as research. A post that says "here is a use-after-free in win32k" without asking "what allocation pattern enabled this, what class of objects shares this pattern, and has Microsoft audited all of them?" is a report, not research.

Specific failure modes: posts that start with "a researcher discovered CVE-XXXX," walk through the PoC, and end with "Microsoft patched this in MS-XXXX." No root cause. No primitive. No variant thinking. These are news, not analysis.

Inclusion threshold: a post that identifies the primitive, explains the root cause, and raises at least one variant question earns A-tier consideration. A post that does all of that and builds a class-level analysis earns S-tier consideration.

### 3. Derivative Summaries

Posts that re-explain another researcher's work without adding new insight. The test: does the author say anything that the original source doesn't? If the post is a paraphrase of Forshaw's exploitation tricks with different variable names and a friendly introduction, it is noise. It is not wrong — it may be an accurate summary — but it occupies mental space that the original source would occupy more efficiently. Reading the derivative costs the same time as the original but delivers less.

Specific failure mode: "I read this paper and here's what it means" posts. If the paper is in the canon, read the paper. If the paper is not in the canon, the summary is not a substitute for determining whether the paper should be. Summaries compress; compression loses signal.

The narrow exception: a post that translates a primary source into a working implementation, showing something the original did not, may earn A-tier. The question is whether new information was produced. Translation of existing information is not production.

### 4. Popularity Without Depth

High-star GitHub repositories that are compiled exploit binaries with minimal or no analysis. The test: can you reproduce this from first principles using this repository as your only reference? If not, and if the repository does not link to analysis that enables reproduction, it is a B/C-tier reference. A repository with 3,000 stars and a README that says "run this to get SYSTEM" is not a research resource.

This applies to: most "awesome-windows-privesc" aggregator repositories, most CTF tool collections that bundle exploit binaries, and any PoC that links to its parent research post but does not contain the analysis itself.

The narrow exception: repositories where the source code IS the analysis (symboliclink-testing-tools, NtObjectManager) are S-tier or A-tier tools because the implementation reveals the mechanics. The test is whether the code teaches. If you can read the source and understand the primitive more deeply than you did before, the repository earns inclusion.

### 5. Beginner-Anchored Framing

Resources that frame their content for someone who does not know what privilege escalation is, what a token is, or what SYSTEM is. These are not wrong — they serve a different audience. But they impose overhead: the reader must read through the foundational explanation to reach the substantive content, and the foundational explanation is worse than the primary sources for the same material.

The signal is in the opening sentences. "In this post, we will learn about Windows privilege escalation" is not a research post. "In this post, we will examine the NtSetInformationFile FileRenameInformation primitive and its interaction with the Windows Installer staged file mechanism" is. If the opening requires no context, the post probably adds no context.

This is not elitism — it is allocation. A researcher's reading time is finite. Reading beginner-anchored material means not reading S-tier material. The cost is real.

### 6. Red Team Tradecraft Without Internals

Posts on AV evasion, C2 infrastructure, OPSEC, beacon deployment, and living-off-the-land techniques. These are operational skills, not research skills. They teach how to avoid detection and maintain access; they do not teach how Windows enforces trust boundaries or how those boundaries are violated.

The narrow exception: a tradecraft post that teaches something meaningful about Windows internals — for example, a post on AMSI bypass that explains the AMSI architecture and where the hooking is done — may earn B-tier inclusion. The test is whether the Windows internals content is incidental (the post explains evasion and happens to mention AMSI) or central (the post explains AMSI and uses evasion as a demonstration).

Explicitly excluded: all OPSEC guides, all C2 infrastructure posts, all "Red Team tips" listicles, all posts whose goal is operational deniability rather than technical understanding.

### 7. OSCP / CEH / OSEP Certification Prep Material

Certification prep material optimizes for pass rate, not research depth. The mental models installed by certification prep are specifically designed to produce correct multiple-choice answers and checklist-based lab completions. These mental models are actively harmful for original research because they train the researcher to identify situations that match a known template rather than to analyze situations with no template.

The OSCP model for privilege escalation is: run the enumeration script, find the misconfiguration, apply the matching technique. This is pattern-matching, not research. Pattern-matching works for the known; original research requires operating in the unknown.

Specifically excluded: all TryHackMe rooms tagged "Windows Privilege Escalation," all HackTheBox writeups that present technique without root cause, all prep books for any certification, all "OSCP-like" machine writeups that follow the enumeration → exploitation → post-exploitation narrative without security model analysis.

The narrow exception: a machine writeup that contains genuine root cause analysis and variant reasoning at the same quality as an A-tier blog post may earn B-tier inclusion. These are rare.

### 8. Vendor Threat Intelligence Marketing

Quarterly threat reports from security vendors. These documents are produced to demonstrate vendor visibility, not to advance the reader's understanding of Windows security. They contain accurate data about observed attacker behavior, which is occasionally useful for C-tier reference (understanding which techniques attackers are currently deploying). They do not contain security model analysis, root cause work, or variant thinking.

The specific failure mode: a report says "Threat Actor X used technique Y to escalate from user to SYSTEM." A research-grade resource would explain why technique Y works, what primitive it relies on, and whether there are variants. The threat report does not. It is a log, not an analysis.

Inclusion rule: threat reports are never primary reading material. They may be archived at C-tier for current-state reference. They do not belong in the Canon Index.

### 9. Abandoned / Untested PoCs Without Analysis

GitHub repositories that contain exploit code with no analysis, no documentation of when it was tested, and no indication of current Windows version compatibility. These are especially dangerous because they may have worked on Windows 7 or 8 but are silently incorrect on current systems — teaching the reader a primitive that no longer behaves as described.

The rule: a PoC without analysis is B-tier at best, and only if it is historically important enough to warrant retention. The test: is there something about this code that teaches the primitive in a way the analysis posts do not? If not, and if the primary research posts cover the same primitive, the standalone PoC is redundant.

Specifically excluded: repositories tagged "for educational purposes" with no supporting analysis, repositories that are forks of known-working tools with no additional documentation, and any repository whose last commit was before Windows 10 with no version-specific notes.

Historical exception: PoCs for primitives that no longer work but document important techniques are archived at C-tier [HISTORICAL]. The historical label means "this teaches something about the primitive's history"; it does not mean "this technique currently works."

### 10. "Top 10 Windows LPE Techniques" Listicles

The list format is a signal. If someone can summarize a bug class in a bullet point, they have not understood it. Privilege escalation techniques are not items on a checklist — they are applications of underlying primitives. A bullet point that says "• SeImpersonatePrivilege → SYSTEM via token impersonation" does not teach the impersonation model, the coercion mechanism, the token duplication path, or the conditions under which this fails. It teaches a mapping: if A, then B. This is pattern-matching, not security research.

Listicles are also commonly stale: the list of "top LPE techniques" from 2019 includes techniques that were patched, techniques that require specific conditions, and techniques that have been superseded. The list format does not accommodate nuance, so the nuance is dropped. The reader learns confident-sounding false information.

Exclusion rule: any resource whose primary organizational structure is a numbered or bulleted list of techniques, without security model analysis for each item, is excluded from the canon.

---

## The Grandfathering Problem

Be especially critical of resources that are "in the vault for historical reasons." Historical importance is not a permanent free pass. A resource earns continued inclusion only if it still teaches something that cannot be learned more efficiently from current sources.

The question to ask annually about historical resources: "If I removed this from the vault and told a researcher to learn what it teaches, would they find a better current source?" If yes, remove it or downgrade it to the archive. The [HISTORICAL] label is a flag that the resource needs re-evaluation, not a justification for permanent retention.

Specific failure mode: keeping Rotten Potato because it is "where it all started." Rotten Potato earns A-tier [HISTORICAL] not because it started the impersonation chain, but because reading it shows the original observation and reasoning in a way that the PrintSpoofer post does not reproduce. If the PrintSpoofer post reproduced it entirely, Rotten Potato would be archive-only.

The test: can a researcher skip the historical resource and lose something they cannot recover from current sources? If no, archive it.

---

## A Note on Tools

Tools earn inclusion differently from reading material. A tool's tier reflects its research value, not its exploitation utility. A tool can be extremely effective at producing exploits and still be a C-tier resource because it teaches nothing.

- **A-tier tool**: Used as a research instrument. When you use it, you learn something about the Windows security model. Examples: NtObjectManager (access check engine), ProcMon (filesystem/registry access tracer), TTD (deterministic replay debugger), RpcView (RPC surface enumerator). Using these tools produces understanding.
- **B-tier tool**: Produces output you then have to analyze using primary resources. Examples: PrivescCheck, WinPEAS, PowerSploit's PowerUp. Using these tools produces findings. The understanding must come from elsewhere.
- **C-tier tool**: Produces exploitation outcomes with no research value. Examples: GodPotato, SweetPotato, standalone Potato-family binaries. These tools are deployable; they are not instructive.

Being a good tool does not make something primary reading material. A C-tier tool can be legitimately useful in an engagement. Its usefulness there does not change its research tier. Do not conflate "useful" with "educational." A lookup table is useful; it is not a textbook.

---

## Decisions Already Made

These resources were explicitly evaluated for the canon and excluded. This table is a permanent record; do not re-litigate these decisions without new information.

| Resource | Tier Assigned | Reason for Exclusion from Canon |
|---|---|---|
| WinPEAS / PEAS-ng | C-tier tool | Enumeration without understanding; produces checklist output that requires primary sources to interpret; teaches nothing about Windows security model |
| PrivescCheck (itm4n) | B-tier tool | More analytical than WinPEAS but still enumeration-first; the companion blog (itm4n.github.io) is A-tier reading; the tool is B-tier output producer |
| "Awesome Windows Privilege Escalation" (various GitHub aggregators) | Archive / C-tier | Link collections with no analysis; accurately identify that resources exist without providing them or contextualizing them |
| PayloadsAllTheThings — Windows Privesc section | B/C-tier reference | Useful quick-reference during operations; teaches nothing; no security model analysis; accuracy degrades faster than primary sources |
| TryHackMe Windows Privesc paths | C-tier / excluded | Certification-adjacent framing; pattern-matching; does not develop security model intuition |
| HackTheBox writeups (generic) | C-tier / excluded | Narrative exploitation without root cause; the rare writeup with genuine analysis may be A-tier; the default is C-tier |
| SweetPotato / BadPotato / SharpEfsPotato | C-tier tools | Impersonation chain tools with no novel analysis; derivatives of primitives better documented in itm4n and decoder.cloud posts |
| Metasploit local_exploit_suggester | C-tier tool | Enumeration tool; lists potential techniques without security model; same failure mode as WinPEAS |
| Any vendor quarterly threat report | C-tier reference | Behavioral data without analysis; never primary reading |
| PowerSploit / PowerUp | B-tier tool [HISTORICAL] | Was the state of the art in 2015; now superseded by better tools and better analysis; retains historical value only for studying evolution of the field |
| SecWiki / windows-kernel-exploits compilations | Archive only | Aggregations of exploit code; no analysis; some historically important but all superseded by primary sources |
| OSCP Prep Guide / PWK Material | Excluded entirely | Certification-optimized framing actively harmful to research mindset; does not meet the core test under any reading |
| "Red Team Notes" aggregator sites | C-tier reference | Operations-focused; useful for tradecraft, not for security model understanding; occasionally cite A-tier sources but are not those sources |
| Any YouTube "Windows Privilege Escalation" tutorial | Excluded entirely | Format cannot carry the technical density required; the best videos reference primary sources rather than replacing them; reading the primary source is always faster |
