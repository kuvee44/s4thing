# Exclusion Log

## Purpose
Track resources considered but excluded, with justification. Prevents re-evaluation of already-rejected sources.

---

## Excluded Categories

### SEO Blogspam / Shallow Content
- Generic "how to hack Windows" tutorial blogs with no original research
- Medium posts that re-summarize other researchers without attribution or depth
- YouTube walkthroughs that cover only surface-level enumeration with no internals explanation
- **Reason:** No research value. Beginner content only. Not useful for a serious researcher.

### OSCP/CEH Study Guides
- Most OSCP prep material (HackTheBox, THM tutorials) on Windows privesc
- **Exception:** Some HackTheBox content that happens to be technically deep is kept
- **Reason:** Focused on exam pass mechanics, not root cause understanding or variant hunting

### Weaponized Exploit Repositories (No Educational Value)
- Repositories that just collect pre-compiled `.exe` exploit binaries with no source/explanation
- Metasploit modules without associated explanation or research writeup
- **Reason:** No learning value. Low trust.

### Outdated Without Historical Value
- Resources about Windows XP/Vista/7 kernel exploitation that have no modern relevance or conceptual carryover
- **Exception:** Resources marked [HISTORICAL] that establish foundational concepts still relevant today
- **Reason:** Time-limited research value for a researcher focused on current targets

### Vendor Marketing Content
- "10 Ways to Protect Windows" enterprise blog posts from security vendors
- SIEM/EDR vendor "threat research" blogs that are primarily marketing
- **Reason:** Not internals-focused, not useful for offense research

### Duplicate Coverage
See DUPLICATES_MERGED.md for resources merged or consolidated.

---

## Specific Excluded Resources

| Resource | Reason for Exclusion | Date |
|----------|---------------------|------|
| Random Medium post "Windows Privilege Escalation for Beginners" | Shallow, no original research | 2026-04-22 |
| HackTricks (as primary source) | Useful as quick reference but not deep enough as primary, kept as secondary note | 2026-04-22 |
| Most exploit-db entries without writeups | Binary dumps with no explanation | 2026-04-22 |
| OSCP Prep Windows PrivEsc guides | Enumeration-only, no root cause | 2026-04-22 |
| Metasploit Wiki | Too high-level, not internals-focused | 2026-04-22 |

---

## Borderline Cases (Kept With Caution Flag)

| Resource | Why Borderline | Decision |
|----------|---------------|---------|
| HackTricks Windows section | Quick reference value, not depth | Kept as supplementary reference only |
| Old PoC exploits (pre-2018) | Historical value vs. outdated techniques | Kept if marked [HISTORICAL] |
| Some corporate threat research blogs | Occasional deep analysis | Keep individual posts, not the blog as a whole |

---

## Re-evaluation Queue
Resources that were excluded but may be re-evaluated if they publish high-quality content:
- (None currently)

---

*Updated: 2026-04-22*
