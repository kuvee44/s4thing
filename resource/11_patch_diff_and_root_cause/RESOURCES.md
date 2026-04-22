# Patch Diffing & Root Cause Analysis — Windows Security Research

> Category: Binary diffing, patch analysis, vulnerability root cause methodology
> Tags: [FOUNDATIONAL] [MUST-READ] [LAB-WORTHY]

---

## Tools

---

- **Title:** BinDiff
- **Author / Organization:** Google (acquired from Zynamics)
- **URL:** https://www.zynamics.com/bindiff.html
- **Resource type:** Binary diffing tool (GUI + IDA/Ghidra plugin)
- **Topic tags:** Patch diffing, binary diff, function matching, control flow comparison, vulnerability analysis, CVE analysis
- **Difficulty:** Intermediate
- **Historical or current:** Current (maintained by Google)
- **Trust level:** HIGH — industry standard, maintained by Google
- **Why it matters:** BinDiff is the industry standard tool for comparing two binaries and identifying what changed between them. For patch diffing, this means comparing a pre-patch and post-patch DLL/EXE to identify exactly which functions were modified and how. This is the primary method for locating the vulnerable code after a Microsoft Patch Tuesday update, before a public CVE writeup exists. BinDiff + IDA/Ghidra is the standard workflow for every serious Windows vulnerability researcher.
- **What it teaches:** Binary similarity algorithms (function hashing, call graph comparison, CFG comparison); how to identify patched functions in a large binary; how to navigate from the patched function to the specific change that fixes the vulnerability; workflow for rapid post-Patch-Tuesday analysis; how to use structural function matching to handle compiler differences.
- **Best use:** Download two versions of a Windows DLL (e.g., ntdll.dll from October vs November Patch Tuesday). Load both in IDA Pro or Ghidra. Run BinDiff to generate the diff. Sort by similarity score — functions with high but not perfect scores are candidates for patched vulnerabilities. Navigate to changed blocks to understand what was fixed.
- **Related bug classes / primitives:** All — BinDiff is the universal patch diffing tool regardless of vulnerability class
- **Suggested next resource:** MSRC Security Update Guide (to find which files changed in a given update); Diaphora (open-source alternative with different algorithms)
- **Notes:** BinDiff is free since Google took ownership. Requires IDA Pro or Ghidra. The primary differentiator from Diaphora is commercial polish and algorithm maturity. [FOUNDATIONAL] [MUST-READ]

---

- **Title:** Diaphora
- **Author / Organization:** joxeankoret
- **URL:** https://github.com/joxeankoret/diaphora
- **Resource type:** Open-source IDA/Ghidra patch diffing plugin (Python)
- **Topic tags:** Patch diffing, binary diff, function matching, IDA plugin, open source, CVE analysis
- **Difficulty:** Intermediate
- **Historical or current:** Current (actively maintained)
- **Trust level:** HIGH — widely used, open source, well-maintained
- **Why it matters:** Diaphora is the leading open-source alternative to BinDiff, and in some cases finds differences that BinDiff misses due to different matching algorithms. Being open source means you can understand exactly how the diffing works, customize it for specific targets, and contribute improvements. Essential for researchers who don't have a BinDiff license or want to combine both tools.
- **What it teaches:** Function similarity algorithms (minhash, bytecode hashing, CFG comparison); how open-source diffing tools handle large binaries; Python-based IDA scripting for automated analysis; how to interpret diff results and filter noise; combining multiple similarity metrics to reduce false positives.
- **Best use:** Use alongside BinDiff — run both on the same patch diff and compare results. Diaphora often finds additional changed functions. Read the source code to understand the similarity algorithm. Customize the scoring weights for specific target types.
- **Related bug classes / primitives:** All — universal patch diffing tool
- **Suggested next resource:** BinDiff documentation for algorithm comparison; joxeankoret's blog posts about specific vulnerability discoveries made with Diaphora
- **Notes:** Actively maintained. More flexible than BinDiff for custom workflows. The open-source nature means you can inspect and trust the implementation. [LAB-WORTHY]

---

## Methodology and Resources

---

- **Title:** Patch Diffing Windows Updates — Methodology and Workflow
- **Author / Organization:** Multiple researchers (documented across blog posts by Forshaw, itm4n, Naceri, Yarden Shafir, and others)
- **URL:** https://googleprojectzero.blogspot.com/ ; https://itm4n.github.io/ ; https://msrc.microsoft.com/update-guide/
- **Resource type:** Blog posts + methodology documentation (distributed)
- **Topic tags:** Patch Tuesday, patch diffing workflow, CVE timeline, 1-day research, root cause analysis, variant hunting starter
- **Difficulty:** Intermediate → Advanced
- **Historical or current:** Current (Patch Tuesday is monthly; methodology is permanent)
- **Why it matters:** The ability to diff a patch and identify a vulnerability before a public writeup is a fundamental skill for security researchers. It enables 1-day vulnerability analysis, variant hunting, and understanding the defensive fix quality. The workflow — download patched binary, locate via MSRC which files changed, diff, identify change, root cause, reason about exploitability — is a repeatable methodology that can be applied to every Patch Tuesday.
- **What it teaches:** How to use MSRC Security Update Guide to identify affected files; how to obtain both pre-patch and post-patch binaries; choosing between BinDiff and Diaphora for the diff; identifying the minimal change; reasoning from the fix backward to the vulnerability root cause; assessing fix completeness (leading to variant hunting).
- **Best use:** Practice every Patch Tuesday. Pick one CRITICAL or IMPORTANT CVE in a Windows component you understand. Download both binary versions. Perform the full diff workflow. Write up your analysis. Over time, develop intuition for common fix patterns and incomplete patches.
- **Related bug classes / primitives:** All — methodology applies universally
- **Suggested next resource:** MSRC blog for Microsoft's perspective on fixes; Project Zero methodology posts for root cause analysis framework
- **Notes:** Practice is the only path to proficiency. The first few diffs are slow — it gets dramatically faster with experience. Keep notes on each diff exercise to build institutional knowledge.

---

- **Title:** MSRC Security Update Guide
- **Author / Organization:** Microsoft Security Response Center
- **URL:** https://msrc.microsoft.com/update-guide/
- **Resource type:** Official vulnerability disclosure database
- **Topic tags:** CVE, Patch Tuesday, CVSS scores, affected products, KB articles, Microsoft security advisories
- **Difficulty:** Beginner → Advanced (using it is easy; interpreting it deeply requires experience)
- **Historical or current:** Current (updated monthly on Patch Tuesday)
- **Trust level:** HIGH — official Microsoft source
- **Why it matters:** The MSRC Security Update Guide is the authoritative source for Microsoft security vulnerability disclosures. It tells you: what CVEs were patched this month, which Windows versions are affected, what files were updated, the CVE CVSS score and exploitation likelihood. It is the starting point for every patch diff exercise and for understanding the vulnerability landscape.
- **What it teaches:** How Microsoft categorizes and discloses vulnerabilities; what "Exploitation More Likely" vs "Exploitation Less Likely" means; how KB articles map to binary updates; how to identify which DLL/EXE to diff for a specific CVE; CVSS scoring interpretation for Windows vulnerabilities; how to identify high-value patch diff targets.
- **Best use:** Check every Patch Tuesday. Filter by "Exploitation More Likely" first — these are highest-priority research targets. For any CVE of interest, identify the affected component and KB article, download both versions of the binary, and begin the diff workflow.
- **Related bug classes / primitives:** All — universal starting point
- **Suggested next resource:** BinDiff/Diaphora for the actual diff; MSRC blog for detailed technical posts on specific CVEs
- **Notes:** The guide has improved significantly in recent years — Microsoft now provides more detail about attack vectors and exploitation complexity. The "Exploitation Likelihood" assessment is useful but not always accurate. [FOUNDATIONAL]

---

- **Title:** Microsoft Security Response Center (MSRC) Blog
- **Author / Organization:** Microsoft Security Response Center
- **URL:** https://msrc.microsoft.com/blog/
- **Resource type:** Official security blog
- **Topic tags:** CVE analysis, Microsoft security, vulnerability disclosure, defender perspective, mitigations, vulnerability classes
- **Difficulty:** Intermediate → Advanced
- **Historical or current:** Current (active blog)
- **Trust level:** HIGH — official Microsoft source
- **Why it matters:** MSRC's own blog occasionally publishes detailed technical analysis of fixed vulnerabilities, especially significant or complex ones. These posts provide the official Microsoft perspective on root cause and fix — invaluable for calibrating your own patch diff analysis. They also announce new security mitigations and the rationale behind them.
- **What it teaches:** Microsoft's internal process for handling vulnerability reports; how specific CVE classes are fixed; new security features and their design rationale; how Microsoft classifies vulnerability severity; occasionally, detailed technical analysis of patched issues.
- **Best use:** Subscribe to MSRC blog RSS. When Microsoft publishes analysis of a specific CVE, compare it against your own patch diff analysis to validate your methodology. Read architectural posts to understand new mitigations before they affect your research targets.
- **Related bug classes / primitives:** All — broad coverage of Microsoft security topics
- **Suggested next resource:** Project Zero's vulnerability disclosures for a researcher's perspective on the same bugs
- **Notes:** Posts vary in technical depth. Some are highly detailed; others are communications-focused. Filter for posts with "Technical Analysis" or specific CVE numbers for the highest value content.

---

- **Title:** "Distrusting the Patch" — Root Cause Analysis Methodology
- **Author / Organization:** Matteo Malvica; various researchers who have written about patch analysis
- **URL:** https://www.matteomalvica.com/blog/ ; references throughout Windows security community
- **Resource type:** Blog posts + methodological framework
- **Topic tags:** Root cause analysis, patch analysis, incomplete fixes, variant hunting, fix quality assessment, trust but verify
- **Difficulty:** Advanced
- **Historical or current:** Current (methodology is permanent)
- **Trust level:** HIGH
- **Why it matters:** The "distrusting the patch" mindset is fundamental to serious vulnerability research. It means: don't assume a patch is complete just because it was issued. Analyze the fix to understand whether it addresses the root cause, addresses only one exploitation path, or introduces new bugs. This approach has led to the discovery of numerous variants and bypass techniques after supposedly-complete patches.
- **What it teaches:** How to analyze a patch fix for completeness; criteria for assessing whether a fix is root-cause vs. surface-level; how to identify whether a fix can be bypassed; the relationship between patch quality and variant discovery; how to document fix analysis formally; historical examples of incomplete patches (Windows Installer, Print Spooler, etc.).
- **Best use:** After performing a patch diff and identifying the fix, write up an explicit analysis: what was the root cause? Does the fix address the root cause or just a specific manifestation? Are there other code paths that could trigger the same root cause? This structured analysis naturally leads into variant hunting.
- **Related bug classes / primitives:** Variant hunting, incomplete fix analysis, bypass technique identification
- **Suggested next resource:** Project Zero's root cause analysis posts; "Exploiting the Same Bug Twice" methodology (variant hunting)
- **Notes:** The mindset shift from "the patch fixed it" to "let me verify the patch is complete" is one of the most valuable things a security researcher can develop. Every significant bug class has examples of incomplete patches.

---

- **Title:** Project Zero — Root Cause Analysis Methodology
- **Author / Organization:** Google Project Zero
- **URL:** https://googleprojectzero.blogspot.com/
- **Resource type:** Research blog (methodology embedded in individual posts)
- **Topic tags:** Root cause analysis, vulnerability disclosure, exploit analysis, in-the-wild analysis, patch quality, security research methodology
- **Difficulty:** Advanced
- **Historical or current:** Current (active blog)
- **Trust level:** HIGH — highest-trust external security research organization for Windows research
- **Why it matters:** Project Zero's bug reports and blog posts are models for how to perform and document root cause analysis. Their 90-day disclosure policy has shaped the industry standard. The depth of analysis in their posts — from initial reproduction through root cause, exploit development, and fix verification — is unmatched. Their in-the-wild exploit analysis posts are particularly valuable for understanding how attackers approach the same problems.
- **What it teaches:** How to structure and document a vulnerability root cause analysis; the difference between triggering a bug and understanding its root cause; how to reason about exploitability from root cause; how to assess fix quality and discover variants; how to communicate vulnerabilities responsibly and effectively.
- **Best use:** Read Project Zero posts for Windows vulnerabilities systematically. For each post: (1) understand the vulnerable code before reading the explanation, (2) reproduce the bug if possible, (3) study their root cause reasoning, (4) compare the analysis to what you would have written. This comparative exercise builds analytical skill rapidly.
- **Related bug classes / primitives:** All — Project Zero covers the full spectrum of Windows vulnerabilities
- **Suggested next resource:** All primary sources linked in Project Zero posts; their GitHub for associated tools
- **Notes:** The blog archive is enormous and high-value. Search for Windows-specific posts. The in-the-wild exploit analysis series is particularly valuable for understanding real-world exploitation methodology. [FOUNDATIONAL] [MUST-READ]

---

- **Title:** WinDiff — Windows Version Comparison Tool
- **Author / Organization:** j00ru (Mateusz Jurczyk) / Google Project Zero
- **URL:** https://winbindex.m417z.com/ (Winbindex — related binary index); j00ru's original WinDiff references
- **Resource type:** Web tool / research methodology aid
- **Topic tags:** Windows version diffing, binary history, system call tables, API changes, Windows API evolution
- **Difficulty:** Intermediate
- **Historical or current:** Current
- **Trust level:** HIGH
- **Why it matters:** Understanding how Windows APIs, system call tables, and binary implementations change across versions is essential for both exploitation and patch analysis. WinDiff-style tools (and the related Winbindex for finding specific binary versions) enable researchers to compare API behavior across Windows versions, find when specific functions were added or modified, and obtain specific binary versions for diff work.
- **What it teaches:** How Windows system call numbering changes across versions; how to find which Windows version introduced a specific API or changed its behavior; how to obtain older Windows binaries for comparative analysis; cross-version exploitation considerations.
- **Best use:** Use Winbindex (https://winbindex.m417z.com/) to download specific versions of Windows system DLLs for diff exercises. Use the syscall table databases (maintained by j00ru at https://j00ru.vexillium.org/syscalls/nt/64/) to understand system call evolution.
- **Related bug classes / primitives:** Cross-version exploitation, patch regression analysis, API change detection
- **Suggested next resource:** j00ru's system call tables; Winbindex for obtaining specific binary versions
- **Notes:** j00ru's system call table database is the definitive reference for Windows NT syscall evolution. Essential for kernel research.

---

- **Title:** ASLR/KASLR Bypass Research via Patch Diff — Variant Hunting Methodology
- **Author / Organization:** Multiple researchers — Bochspwn team, Project Zero, various CVE researchers
- **URL:** https://googleprojectzero.blogspot.com/ ; https://j00ru.vexillium.org/
- **Resource type:** Research methodology + blog posts
- **Topic tags:** KASLR bypass, information disclosure, patch diff, variant, systematic scanning, Bochspwn class
- **Difficulty:** Advanced
- **Historical or current:** Current (KASLR bypass remains an active research area)
- **Trust level:** HIGH
- **Why it matters:** The Bochspwn class of uninitialized kernel memory disclosures represents one of the most successful applications of variant hunting via systematic analysis — dozens of KASLR-defeating bugs were found by the same taint-tracking methodology. Understanding how a single root cause analysis (uninitialized memory copied to userspace) led to a systematic scan that found 30+ vulnerabilities is a masterclass in variant hunting methodology applied to patch diff.
- **What it teaches:** How to think about a vulnerability class systematically rather than as individual CVEs; how taint-tracking analysis generalizes a single root cause into a scan methodology; how to use patch diff to verify that all instances of a class were fixed; how KASLR-defeating information disclosures are systematically found and patched.
- **Best use:** Study the original Bochspwn paper, then Bochspwn Reloaded, then trace which specific CVEs were generated. Understand how the same root cause manifested in many different code paths. Then apply the same reasoning to a different class of bug in Windows.
- **Related bug classes / primitives:** Uninitialized memory, information disclosure, KASLR bypass, systematic variant discovery
- **Suggested next resource:** Bochspwn Reloaded paper; Project Zero's variant hunting methodology posts in the variant hunting category (resource 12)
- **Notes:** One of the clearest real-world examples of how a single insight (taint tracking + copy-to-userspace) can yield a systematic vulnerability class. [MUST-READ for methodology]

---

- **Title:** NtDiff — System Call Table Differences Between Windows Versions
- **Author / Organization:** j00ru (Mateusz Jurczyk) / Google Project Zero (related resource)
- **URL:** https://j00ru.vexillium.org/syscalls/nt/64/
- **Resource type:** Online reference database
- **Topic tags:** System call tables, NT syscalls, Windows version differences, kernel API evolution, syscall numbers
- **Difficulty:** Intermediate → Advanced
- **Historical or current:** Current (updated for new Windows releases)
- **Trust level:** HIGH — j00ru's authoritative reference
- **Why it matters:** The Windows NT kernel system call table changes with every major Windows version — syscall numbers shift, new calls are added, old ones are removed or renamed. For kernel security research, having a precise record of these changes is essential for: writing cross-version shellcode, identifying when a specific syscall was introduced (correlating with feature introduction), understanding what new attack surface appears in each version, and tracking the evolution of the kernel API surface.
- **What it teaches:** Windows version-to-version API evolution at the syscall level; how to locate specific NT syscalls across versions; when specific kernel functionality was introduced; how syscall numbering affects shellcode portability; how to identify new syscalls as potential research targets.
- **Best use:** Bookmark and reference constantly during kernel research. When investigating a new Windows feature, check when its syscalls were introduced. When writing cross-version shellcode, verify syscall numbers. When hunting for new attack surface, look for syscalls added in recent versions.
- **Related bug classes / primitives:** Cross-version kernel exploitation, new attack surface identification, shellcode portability
- **Suggested next resource:** Windows Internals for understanding what each syscall does at the implementation level; WinDbg for live investigation of specific syscalls
- **Notes:** One of the most practically useful reference resources for Windows kernel research. j00ru maintains this meticulously. [FOUNDATIONAL]

---
