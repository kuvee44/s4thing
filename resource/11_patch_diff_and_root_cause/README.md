# Patch Diff & Root Cause — Quick Reference

> Section 11: Binary diffing, patch analysis, root cause methodology

## Summary

This section covers tools and methodology for patch diffing Windows updates, identifying vulnerability root causes, and developing the "distrusting the patch" mindset that leads to variant discovery.

## Entry Count

| Category | Count |
|---|---|
| Diffing Tools | 2 |
| Methodology Resources | 7 |
| Reference Databases | 1 |
| **Total** | **10** |

## Standard Patch Diff Workflow

```
1. Check MSRC Security Update Guide (Patch Tuesday)
   → msrc.microsoft.com/update-guide/
   → Filter by "Exploitation More Likely"

2. Identify target CVE and affected binary
   → Note the KB article number
   → Identify which DLL/EXE was updated

3. Obtain both binary versions
   → Pre-patch: Winbindex (winbindex.m417z.com) or old VM snapshot
   → Post-patch: extract from KB update package or updated system

4. Load both in IDA Pro / Ghidra
   → Configure Microsoft Symbol Server in both
   → Let symbols download before diffing

5. Run BinDiff
   → Sort results by similarity (NOT 1.0 or 0.0 — focus on 0.7-0.99)
   → Functions with high but imperfect similarity → changed functions

6. Identify the change
   → Navigate to changed basic blocks
   → Understand what code was added/modified/removed

7. Root cause analysis
   → What was the bug? (missing check, wrong type, off-by-one, etc.)
   → What does the fix do?
   → Is the fix complete?

8. Variant hunting
   → Are there other call sites with the same pattern?
   → Are there related APIs with similar code?
   → Does the fix address root cause or just the PoC path?
```

## Key Questions for Every Patch

1. **What changed?** — Identify the specific code change
2. **Why?** — What bug does the change fix?
3. **Is it complete?** — Does it address root cause or just the PoC vector?
4. **Where else?** — Are there other code paths with the same bug?
5. **What does it enable?** — Can a variant exploit the same root cause via a different path?

> See NOTES.md for extended methodology notes and patch diff checklists.
> See RESOURCES.md for full entry details on all resources.
