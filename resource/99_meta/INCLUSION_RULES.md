# Inclusion Rules
## Windows Security Research Knowledge Base

---

## Core Criteria for Inclusion

For a resource to be included in this knowledge base, it must satisfy **at least two** of the following criteria:

### 1. Technical Depth
The resource explains **why** something works, not just **how** to use it. A resource that says "run this command to get a shell" without explaining the underlying mechanism does not qualify. A resource that explains the kernel data structure being corrupted, the security check being bypassed, or the race condition being exploited does qualify.

### 2. Research Value
The resource contributes to the practice of **finding** bugs, not just exploiting already-known ones. Tools for enumeration, methodology for variant hunting, analysis of bug classes, and techniques for patch diffing all have research value.

### 3. Originality / Primary Source
The resource contains **original analysis** — the author discovered the technique, developed the tool, or performed the root cause analysis independently. Aggregator posts that summarize other people's work without adding analysis are excluded.

### 4. Verifiable Accuracy
The technical claims in the resource can be **independently verified** — either through public source code, published CVEs, reproducible PoC code, or independent confirmation from other trusted researchers.

### 5. Temporal Relevance
The resource is either:
- **Currently applicable** (technique works on a supported Windows version), OR
- **Historically important** for understanding the evolution of techniques (marked `HISTORICAL`)

---

## Tier System

### Tier 1 — Foundational Must-Reads
**Definition:** Resources that define the field. Every Windows security researcher should read these before anything else.

**Criteria for Tier 1:**
- Widely cited by other high-quality researchers
- Covers fundamental concepts that all subsequent work builds on
- Either a primary source for a technique OR the definitive explanation of a concept
- Author is a recognized authority in the field

**Examples:** Windows Security Internals (Forshaw), Windows Internals (Russinovich et al.), Forshaw's COM security tour, Bochspwn papers

**Tag:** `FOUNDATIONAL` `MUST-READ`

---

### Tier 2 — Important Research
**Definition:** High-quality research that meaningfully advances the field or provides excellent coverage of a specific topic.

**Criteria for Tier 2:**
- Original research with solid technical depth
- Author has a track record of quality work
- Adds significant value beyond what Tier 1 covers
- Reproducible or verifiable claims

**Examples:** Bug class writeups by itm4n, decoder's RoguePotato analysis, Yarden Shafir's pool exploitation research

**Tag:** `MUST-READ` (for highest tier 2), no special tag for standard tier 2

---

### Tier 3 — Reference
**Definition:** Useful reference material that is accurate and reliable but not required reading for everyone.

**Criteria for Tier 3:**
- Technically accurate
- Useful for specific lookup needs
- May be official documentation, tool documentation, or supplementary analysis

**Examples:** MSDN API documentation, Sysinternals tool docs, CVSS scoring guide

**Tag:** `REFERENCE`

---

## Exclusion Criteria

The following types of resources are **automatically excluded**, regardless of topic:

### 1. SEO Blogspam
Posts that exist primarily to rank for keywords. Identifiers:
- Title is "Top 10 Windows hacking tools" or similar listicles
- Body has no original analysis
- Author has no track record in the security community
- Content is paraphrased from other sources without attribution

### 2. Shallow Tutorials
Step-by-step "how to get a shell" guides with no explanation of mechanisms. Identifiers:
- No mention of why the technique works
- No reference to underlying Windows internals
- Could be read by someone with no security background and executed without understanding

### 3. Unverifiable Claims
Posts that make technical claims that cannot be independently verified. If a blog claims "CVE-XXXX works by exploiting the kernel stack" but doesn't show proof-of-concept, code analysis, or reproducible steps, it's excluded.

### 4. Outdated-Without-Historical-Note
Techniques that have been patched without acknowledging they are patched, presented as if they still work. Resources about patched techniques are acceptable only if they clearly mark the affected Windows versions and note the fix.

### 5. Duplicate Coverage Without Added Value
If three blog posts cover the same technique, only the highest-quality one (typically the primary source) is included unless others add meaningful perspective. Duplicates with no value-add are excluded.

### 6. Malicious-Only Resources
Resources that describe techniques with no defensive value and no research methodology — pure "attack cookbook" content without any analytical depth. (Note: Potato exploit writeups are included because they have analytical depth even if they're offensive tools.)

### 7. Paywalled Resources
Resources behind a paywall are noted but not linked to, since inclusion requires the resource to be accessible for verification.

---

## Trust Level Definitions

Trust levels apply to **GitHub repositories and code resources**.

### HIGH Trust
- Author is a recognized security researcher with a public track record
- Repository has been reviewed by multiple credible researchers
- Source code is available and has been reviewed
- The technique or tool is widely used in the security research community
- There is no evidence of malicious modification

**What HIGH means in practice:** You can clone and compile from source, review the code, and run in an isolated lab VM.

### MEDIUM Trust
- Author may be pseudonymous but has consistent and quality output
- Repository has reasonable star count from security community
- Source code is available but may not have been externally audited
- Technique is based on known and verifiable mechanisms

**What MEDIUM means in practice:** Review the code before running. Run only in isolated VMs. Don't use compiled binaries from unknown sources.

### CAUTION
- Author is unknown or pseudonymous with no track record
- Repository may contain live exploits that could damage lab environments
- Technique may be outdated or inaccurate
- Binary-only releases with no source code

**What CAUTION means in practice:** Read source code carefully before compiling. Never run pre-compiled binaries. Prefer to reimplement from scratch using the technique description.

---

## Label Definitions

Labels applied to resources in the index for quick navigation:

| Label | Definition |
|-------|-----------|
| `FOUNDATIONAL` | Core knowledge that all security researchers need. Read before anything else in this area. |
| `MUST-READ` | Highest-value resource in its specific topic area. Prioritize before other resources on the same topic. |
| `HISTORICAL` | Technique or research is patched or superseded, but important for understanding the evolution of the field. Study for methodology, not for current exploitation. |
| `LAB-WORTHY` | Resource has reproducible exercises, PoC code, or a clear lab exercise that reinforces learning by doing. |
| `VARIANT-HUNTING` | Directly applicable to the methodology of finding variants of known bugs. Tools, techniques, or methodologies in this category. |
| `PATCH-DIFF` | Directly useful for patch analysis workflow — binary diffing tools, methodology posts, or case studies. |
| `EXPLOIT-PRIMITIVE` | Documents a technique used to convert a vulnerability into a useful exploit primitive (arbitrary read, arbitrary write, code execution). |
| `ATTACK-SURFACE` | Enumerates or characterizes attack surface — where to look for bugs, not how to exploit them. |
| `REFERENCE` | Reference document, consulted for specific facts rather than read cover-to-cover. |
| `TOOL` | A software tool or script. |
| `OPEN-SOURCE` | Source code is publicly available. |
| `BOOK` | Long-form book resource. |
| `BLOG` | Blog post or article. |
| `TALK` | Conference talk or presentation (video/slides). |
| `PAPER` | Academic or technical paper. |
| `OFFICIAL` | Official vendor or standards body documentation. |
| `CVE` | Associated with a specific CVE. |
| `OFFENSIVE` | Primarily offensive technique (does not mean excluded — offense is part of research). |
| `DETECTION` | Defensive or detection perspective. |
| `TRAINING` | Designed for learning and skill building rather than as primary reference. |

---

## Quality Review Process

### When Adding a New Resource

1. **Read or watch the full resource** — do not add based on title/summary alone
2. **Verify technical claims** — check at least one key technical claim against a known-good source
3. **Assign tier** — Tier 1, 2, or 3 based on the criteria above
4. **Assign trust level** — for code resources only
5. **Assign tags** — select all applicable tags from the label definitions
6. **Write a summary** — the "Why it's included" note should explain the research value in one sentence

### When Removing a Resource

A resource is removed if:
- The linked URL becomes dead and no archive exists
- A higher-quality primary source is found that makes it redundant
- The technical claims are found to be incorrect
- The author has been found to have published deliberately misleading information

Removals are logged in the SEARCH_LOG.md file with date and reason.

---

## Versioning

This inclusion rules document is versioned with the collection date in SEARCH_LOG.md. Any changes to inclusion criteria are noted there with a rationale.
