# Variant Hunting — Windows Security Research

> Category: Variant analysis, patch analysis, systematic bug discovery, CodeQL
> Tags: [FOUNDATIONAL] [MUST-READ] [VARIANT-HUNTING]

---

## Foundational Methodology

---

- **Title:** Project Zero Variant Hunting Methodology
- **Author / Organization:** Google Project Zero (Forshaw, Ormandy, j00ru, and others)
- **URL:** https://googleprojectzero.blogspot.com/ (search "variant" and "in-the-wild")
- **Resource type:** Research blog posts (methodology embedded in individual analyses)
- **Topic tags:** Variant hunting, vulnerability class analysis, systematic research, root cause generalization, incomplete fix detection, security research methodology
- **Difficulty:** Advanced
- **Historical or current:** Current (ongoing research philosophy)
- **Trust level:** HIGH — Project Zero is the gold standard for vulnerability research methodology
- **Why it matters:** Project Zero operationalized variant hunting as a formal research discipline. Their key insight: when you find one bug, you have found a research direction, not just a single CVE. A good researcher uses the root cause of one bug to generate a search strategy for all bugs with the same root cause. They have proven this repeatedly — every time a 0-day is found in the wild, Project Zero searches for related bugs, and they reliably find more. This methodology is what distinguishes systematic security research from ad-hoc bug finding.
- **What it teaches:** How to generalize a single bug into a search strategy; the difference between a symptom and a root cause; how to enumerate all code paths that share a root cause; what to look for after a patch (fix completeness, other call sites, related APIs); how to write up variant findings; why every in-the-wild 0-day should trigger a full class analysis.
- **Best use:** Read Project Zero blog posts that explicitly discuss variant analysis. Then pick any published Windows CVE, identify its root cause, and systematically search for other manifestations yourself before reading whether Project Zero found variants. This active practice builds the variant hunting mindset.
- **Related bug classes / primitives:** All — variant hunting is a meta-methodology applicable to every vulnerability class
- **Suggested next resource:** "Exploiting the Same Bug Twice" analysis pattern; CodeQL for code-based variant scanning
- **Notes:** The most important research philosophy in modern vulnerability research. Internalize this before any other methodology. [FOUNDATIONAL] [MUST-READ]

---

- **Title:** "Exploiting the Same Bug Twice" — Analysis of Incomplete Patches (Forshaw-Style)
- **Author / Organization:** James Forshaw / Google Project Zero (primary practitioner); multiple others
- **URL:** https://googleprojectzero.blogspot.com/ (multiple posts; search "bypass" and "incomplete fix")
- **Resource type:** Research blog posts + CVE analysis
- **Topic tags:** Incomplete fix, patch bypass, variant, same root cause, multiple exploitation paths, fix analysis
- **Difficulty:** Advanced
- **Historical or current:** Current (recurring pattern)
- **Trust level:** HIGH
- **Why it matters:** A substantial fraction of Windows security vulnerabilities are patched incompletely on the first attempt. The fix addresses the specific proof-of-concept but not the general root cause, allowing a variant to exploit the same underlying issue. Forshaw has demonstrated this pattern repeatedly — sandbox escapes, token impersonation, symbolic link bugs — where understanding why a fix is incomplete leads directly to a bypass. This teaches both offensive research depth and defensive fix quality analysis.
- **What it teaches:** What makes a fix "incomplete" vs. "complete" at the root cause level; how to analyze a patch to determine if it addresses all exploitation paths; how to craft a variant PoC that bypasses the specific fix; how to communicate fix incompleteness to vendors; patterns of incomplete fixes in Windows (e.g., fixing one call site while missing others, fixing the wrong layer, adding a check that can be bypassed).
- **Best use:** For each Forshaw-authored bug report or blog post, explicitly identify whether he mentions an incomplete fix or bypass. Analyze the original fix to understand why it was incomplete. Then look at the bypass fix to understand what complete remediation looked like.
- **Related bug classes / primitives:** All — the incomplete fix pattern appears across every vulnerability class
- **Suggested next resource:** Project Zero variant hunting methodology; Administrator Protection bypass variants (2024-2025 case study)
- **Notes:** Forshaw has published dozens of examples of this pattern. His sandbox escape research is particularly rich with incomplete fix examples. Track his Project Zero bug reports chronologically to see the pattern repeat.

---

## Code Analysis Tools

---

- **Title:** CodeQL for Variant Analysis
- **Author / Organization:** GitHub Security Lab / GitHub (now owned by Microsoft)
- **URL:** https://codeql.github.com/
- **Resource type:** Code analysis platform + query language
- **Topic tags:** CodeQL, variant analysis, static analysis, semantic code search, taint tracking, SAST, code pattern matching, GitHub Security Lab
- **Difficulty:** Intermediate → Advanced (query writing requires learning QL)
- **Historical or current:** Current (actively developed)
- **Trust level:** HIGH — GitHub Security Lab publishes high-quality QL queries for Windows vulnerabilities
- **Why it matters:** CodeQL enables semantic code search — writing queries that find patterns across a codebase that match the structure of a known vulnerability. GitHub Security Lab has used CodeQL to find variants of major vulnerabilities (including Windows-adjacent bugs) by writing a query that captures the root cause pattern and running it across large codebases. For open-source targets or when Microsoft provides a code snapshot, CodeQL can systematically find all instances of a bug class in minutes.
- **What it teaches:** QL query language for code analysis; how to model a vulnerability pattern as a CodeQL query; taint tracking in CodeQL (tracking dangerous data flows from source to sink); how to write queries that find variants of a known bug; integrating CodeQL into research workflows; using GitHub Code Scanning results for variant hunting.
- **Best use:** Start with CodeQL's official tutorials. Then find a published GitHub Security Lab advisory that used CodeQL for variant analysis — read the advisory and the associated QL query together. Write a query for a simple vulnerability pattern you understand well. Scale up from there.
- **Related bug classes / primitives:** Any bug class with identifiable code patterns — buffer overflows, integer overflows, missing validation, dangerous API usage, type confusion in source
- **Suggested next resource:** GitHub Security Lab blog (https://securitylab.github.com/) for real-world QL variant hunting case studies; Semgrep for faster but less semantic pattern matching
- **Notes:** CodeQL is most effective on open-source targets. For closed-source Windows binaries, Semgrep (on available source) and binary analysis tools are better suited. GitHub Security Lab's QL query repository contains expert-written queries worth studying directly. [LAB-WORTHY]

---

- **Title:** Semgrep
- **Author / Organization:** Semgrep Inc. (r2c)
- **URL:** https://semgrep.dev/
- **Resource type:** Static analysis / pattern matching tool
- **Topic tags:** Pattern matching, code search, SAST, variant analysis, fast scanning, rule-based detection, code patterns
- **Difficulty:** Beginner → Intermediate (simple rules) / Advanced (complex taint rules)
- **Historical or current:** Current (very actively maintained)
- **Trust level:** HIGH — widely used, well-documented
- **Why it matters:** Semgrep trades CodeQL's deep semantic analysis for speed and simplicity. Writing a Semgrep rule takes minutes vs hours for a CodeQL query, and for many variant hunting scenarios (finding all calls to a dangerous API, finding patterns that match a known vulnerable code structure), it is sufficient. The Semgrep Registry contains hundreds of security rules. For researchers with access to Windows component source code or third-party software, Semgrep is the fastest first-pass variant scanner.
- **What it teaches:** Rule-based code pattern matching; how to express vulnerability patterns as syntactic rules; cross-language analysis; how to quickly scan a codebase for dangerous patterns; the trade-off between semantic precision (CodeQL) and speed (Semgrep).
- **Best use:** When you identify a vulnerability pattern in a codebase with available source, write a Semgrep rule that captures it. Run it across the codebase. Use Semgrep as a first pass to identify candidates, then manually verify and potentially elevate to a CodeQL query for deeper analysis.
- **Related bug classes / primitives:** All — pattern matching applies universally at the source level
- **Suggested next resource:** CodeQL for deeper semantic analysis; Semgrep Registry for expert-written rules to study
- **Notes:** Best suited for source code analysis. Less useful for Windows closed-source research, but valuable when source is available (Microsoft open-source components, third-party Windows software). Very accessible entry point for systematic code analysis.

---

## Automated Variant Discovery

---

- **Title:** Bochspwn Reloaded — Automated Kernel Leak Discovery
- **Author / Organization:** j00ru (Mateusz Jurczyk) / Google Project Zero
- **URL:** https://j00ru.vexillium.org/talks/blackhat17-bochspwn-reloaded/
- **Resource type:** Research paper + conference talk + tool
- **Topic tags:** Automated variant discovery, taint tracking, kernel memory disclosure, emulation-based analysis, systematic scanning, KASLR bypass
- **Difficulty:** Advanced
- **Historical or current:** Historical (2017) — methodology is a timeless model
- **Trust level:** HIGH
- **Why it matters:** Bochspwn Reloaded is the canonical example of automated variant hunting through systematic analysis. By running the kernel under instrumented emulation and tracking taint (uninitialized bytes) as they flow from kernel allocations to user-space memcpy operations, j00ru discovered 30+ independently reportable kernel memory disclosure vulnerabilities. The power of the approach is that once the methodology is built, the tool finds variants automatically. This is variant hunting at scale.
- **What it teaches:** Emulation-based taint tracking as a systematic bug finding methodology; how a single vulnerability class (uninitialized memory disclosure) can be automated into a scanning system; the engineering required to instrument a kernel emulator for taint tracking; how to process and triage automated results; why this approach found bugs that manual review missed; how to publish systematic vulnerability class discoveries.
- **Best use:** Study the paper + talk in depth. Understand the taint tracking algorithm precisely. Then ask: what other kernel-level invariants could be checked the same way? What other data flows from kernel to user mode that shouldn't contain sensitive data? This generalization exercise builds variant hunting intuition.
- **Related bug classes / primitives:** Uninitialized memory, kernel memory disclosure, KASLR bypass, systematic automated variant discovery
- **Suggested next resource:** Original Bochspwn paper (2013); kernel taint tracking research; Triforce (QEMU-based kernel fuzzing) for related automated analysis approaches
- **Notes:** One of the most influential Windows security research papers for methodology. Essential reading for understanding systematic variant hunting. [MUST-READ] [VARIANT-HUNTING]

---

## Case Studies

---

- **Title:** Hunting for Patterns in the Windows Codebase — Methodology for Similar Bugs
- **Author / Organization:** Multiple researchers — Project Zero, Forshaw, Naceri, and others implicitly
- **URL:** Distributed across Project Zero blog, conference talks, individual CVE analyses
- **Resource type:** Methodological framework (distributed)
- **Topic tags:** Code pattern hunting, similar bugs, architectural weakness identification, codebase-wide analysis, attack surface mapping
- **Difficulty:** Advanced
- **Historical or current:** Current
- **Trust level:** HIGH
- **Why it matters:** The Windows codebase has recurring patterns of similar code — multiple implementations of the same logic, copy-pasted vulnerable code, architectural assumptions that are consistently violated. Researchers who have internalized the Windows codebase (through years of reverse engineering and study) develop pattern recognition that lets them predict where similar bugs exist. This resource captures the methodology for developing that pattern recognition systematically rather than waiting for intuition to emerge.
- **What it teaches:** How to enumerate similar code patterns in binaries; how to use function cross-references to find related code; how to identify copy-paste code reuse in Windows; how to approach a new Windows component by mapping it to known vulnerable patterns from other components; how to use symbol information and IDA/Ghidra to navigate large binaries systematically.
- **Best use:** After deeply analyzing one Windows vulnerability, explicitly generate a list of other components that might have similar code. Research each hypothesis. Document what you found (even negative results) to build your component knowledge database.
- **Related bug classes / primitives:** All — pattern hunting applies universally
- **Suggested next resource:** CodeQL for automating the pattern search; specific case studies (Windows Installer variants, Administrator Protection variants)
- **Notes:** This methodology lives primarily in researchers' heads rather than in published resources. The way to learn it is through practice: find one bug, enumerate similar code, discover variants. Repeat.

---

- **Title:** Windows Exploitation Tricks Variants — Forshaw's Technique of Studying Incomplete Fixes
- **Author / Organization:** James Forshaw / Google Project Zero
- **URL:** https://googleprojectzero.blogspot.com/search/label/exploitation%20techniques (search "exploitation tricks")
- **Resource type:** Blog post series
- **Topic tags:** Exploitation techniques, symlink, junction, OPLOCK, named pipe, TOCTOU, variant, incomplete fix, bypass
- **Difficulty:** Advanced
- **Historical or current:** Current (technique evolution continues)
- **Trust level:** HIGH
- **Why it matters:** Forshaw's "Windows Exploitation Tricks" series is a masterclass in both technique development and variant discovery. Each post introduces or refines an exploitation primitive, and many of them emerged from studying incomplete patches — the patch fixed one technique, so Forshaw found another. The series demonstrates how deep understanding of Windows primitives leads to a continuously expanding toolkit of exploitation techniques.
- **What it teaches:** Advanced exploitation primitives (symlink/junction combinations, OPLOCK races, named pipe tricks, directory creation races); how to reason about the full possibility space for a given Windows mechanism; how fixing one exploitation path opens research into alternative paths; the cumulative nature of Windows exploitation knowledge.
- **Best use:** Read the series in publication order to follow the evolution. For each technique, understand: what primitive does it provide, what Windows mechanism enables it, what mitigations affect it, and what related techniques exist. This builds a complete mental model of the Windows exploitation primitive space.
- **Related bug classes / primitives:** Symlink abuse, TOCTOU, named pipe impersonation, OPLOCK, junction abuse, directory race conditions
- **Suggested next resource:** sandbox-attacksurface-analysis-tools (Forshaw's toolkit); symboliclink-testing-tools (for hands-on technique practice)
- **Notes:** The single best series for understanding Windows exploitation technique development. Forshaw writes clearly and provides sufficient technical detail to reproduce each technique. [MUST-READ]

---

- **Title:** Administrator Protection Bypass — Multiple Variants (2024-2025 Case Study)
- **Author / Organization:** Google Project Zero / multiple researchers
- **URL:** https://projectzero.google/ ; https://googleprojectzero.blogspot.com/
- **Resource type:** Active CVE research series
- **Topic tags:** Administrator Protection, UAC replacement, Windows 11 24H2, variant hunting, incomplete fix, privilege elevation, new feature attack surface
- **Difficulty:** Advanced
- **Historical or current:** Current (active research series as of 2024-2025)
- **Trust level:** HIGH
- **Why it matters:** Administrator Protection is Microsoft's replacement for UAC in Windows 11 24H2. Project Zero's discovery of 9 variants of bypass techniques in a new security feature demonstrates: (1) how new features introduce new attack surface, (2) how variant hunting against a single new feature can yield many CVEs, (3) the pattern of incomplete fixes in a new, immature security mechanism. This is a real-time case study in variant hunting methodology applied to the most current Windows security feature.
- **What it teaches:** How to approach a new Windows security feature as a research target; how to systematically enumerate bypass opportunities for a new privilege boundary; how incomplete fixes in a new feature can lead to rapid variant discovery; the specific attack surface of Administrator Protection and how it differs from UAC; how 9 different bypass techniques can share a common root cause.
- **Best use:** Follow Project Zero's disclosure timeline for this series. For each bypass, understand: what architectural assumption was violated, what was fixed, and why the fix didn't prevent the next variant. This case study is an accelerated master class in variant hunting methodology.
- **Related bug classes / primitives:** UAC/Administrator Protection bypass, privilege elevation, security feature bypass, new feature attack surface
- **Suggested next resource:** UAC bypass research (historical context); Project Zero's variant hunting methodology posts
- **Notes:** This is the most current and comprehensive real-time variant hunting case study available. Follow it as it develops. [VARIANT-HUNTING] [MUST-READ]

---

- **Title:** Variant Hunting Through Patch Analysis — Multiple Researchers
- **Author / Organization:** Forshaw, Naceri, Yarden Shafir, itm4n, and others
- **URL:** Distributed across individual blogs and conference talks
- **Resource type:** Methodological documentation (distributed)
- **Topic tags:** Patch analysis, variant discovery, one patch leads to another, systematic research, vulnerability class
- **Difficulty:** Advanced
- **Historical or current:** Current
- **Trust level:** HIGH
- **Why it matters:** The most productive variant hunting begins with patch analysis. Studying how Microsoft fixed a vulnerability reveals: whether the fix is root-cause-level or symptomatic; whether other code paths exist that share the root cause; whether related APIs/components have similar patterns. Multiple Windows researchers have documented how studying one patch led directly to another CVE — this pattern is reliable enough to be a core research technique.
- **What it teaches:** How to read a patch diff with variant hunting in mind; what questions to ask about a patch to assess completeness; how to enumerate related code paths after identifying one vulnerability; how to document the chain from patch analysis to variant discovery; case studies where a single patch led to multiple follow-on vulnerabilities.
- **Best use:** For every patch diff exercise, apply the variant hunting lens explicitly: Is the fix complete? Are there other call sites? Are there related APIs? Produce a structured analysis document for each. Over time, build a database of "open hypotheses" — potential variants that need further investigation.
- **Related bug classes / primitives:** All — variant hunting through patch analysis is universal
- **Suggested next resource:** "Distrusting the Patch" methodology; Project Zero disclosure pattern studies
- **Notes:** The key discipline is being systematic rather than intuitive. Write down your variant hunting hypotheses even when you don't have time to pursue them immediately.

---

- **Title:** Symbol-Based Triage — Using Public Symbols to Understand Fix Scope
- **Author / Organization:** Multiple researchers (methodology implicit in Forshaw, j00ru, Yarden Shafir work)
- **URL:** https://msdl.microsoft.com/download/symbols (Microsoft Symbol Server)
- **Resource type:** Methodology + tool reference
- **Topic tags:** PDB symbols, public symbols, Windows symbol server, function names, type information, fix scope analysis, reverse engineering aid
- **Difficulty:** Intermediate → Advanced
- **Historical or current:** Current
- **Trust level:** HIGH
- **Why it matters:** Microsoft publishes public PDB symbol files for Windows binaries, which contain function names and basic type information. This dramatically accelerates patch analysis: instead of reverse-engineering unnamed functions, you can identify patched functions by name and understand their role in the component immediately. Symbol-based triage means using function names visible in the PDB to quickly assess what a patch changed and how significant the fix is. It is the first step of an efficient patch diff workflow.
- **What it teaches:** How to use the Microsoft Symbol Server from WinDbg or IDA/Ghidra; how PDB files enhance disassembly analysis; how to use symbol names to navigate to relevant code quickly after a diff; which information is available in public symbols vs full private symbols; how to combine symbol information with BinDiff results to prioritize analysis.
- **Best use:** Configure IDA or Ghidra to use the Microsoft Symbol Server automatically. When performing a patch diff, use the symbol names to contextualize changed functions immediately. Look for functions with names suggesting security-relevant operations (Check*, Validate*, Impersonate*, etc.) among the changed functions.
- **Related bug classes / primitives:** All — symbols accelerate analysis of any vulnerability class
- **Suggested next resource:** WinDbg symbol documentation; BinDiff workflow with symbols; PDB format documentation for understanding what symbols contain
- **Notes:** Free, always available, dramatically improves analysis efficiency. Never patch-diff without symbols loaded. Learn the WinDbg and IDA/Ghidra symbol configuration early in your research setup.

---

## Methodology Checklist

---

> See NOTES.md for the complete variant hunting methodology checklist.

---
