# Variant Hunting — Quick Reference

> Section 12: Systematic variant discovery, CodeQL, incomplete fix analysis

## Summary

This section covers methodologies, tools, and case studies for systematic variant discovery — finding multiple bugs with the same root cause, analyzing incomplete fixes, and scaling individual vulnerability insights into vulnerability class research.

## Entry Count

| Category | Count |
|---|---|
| Foundational Methodology | 2 |
| Code Analysis Tools | 2 |
| Automated Variant Discovery | 1 |
| Case Studies | 5 |
| **Total** | **10** |

## The Variant Hunting Mindset

> "Every bug is a research direction, not just a CVE."

The core insight: when you find a vulnerability, you have found a **class** of vulnerability. The research question changes from "how do I exploit this?" to "where else does this pattern exist?"

## Variant Hunting Checklist

### After Finding a Bug

- [ ] **Root cause identification**: What is the fundamental flaw (not the symptom)?
- [ ] **Call site enumeration**: How many other code paths share this root cause?
- [ ] **Fix quality assessment**: Does the fix address root cause or just the PoC path?
- [ ] **Related API scan**: What other APIs in the same component do similar operations?
- [ ] **Cross-component scan**: Do other Windows components have similar patterns?
- [ ] **Historical variants**: Has this class appeared before? What were the previous fixes?

### After Analyzing a Patch

- [ ] **Fix completeness**: Does the fix cover all call sites?
- [ ] **Root cause fix**: Is the fix at the root cause level or symptomatic?
- [ ] **Bypass potential**: Can the fix be bypassed (different input, different code path)?
- [ ] **Sibling check**: Are there sibling functions with the same bug unfixed?
- [ ] **Version regression**: Was this bug present before? Was a previous fix reverted?

### Systematic Scan

- [ ] **CodeQL query**: Can the root cause pattern be expressed as a CodeQL query?
- [ ] **Semgrep rule**: Can it be expressed as a fast pattern-matching rule?
- [ ] **Manual pattern search**: What IDA/Ghidra search would find similar code?
- [ ] **Symbol-guided search**: What function names suggest similar operations?

---

## Variant Hunting Tools at a Glance

| Tool | Best For | Speed | Depth |
|---|---|---|---|
| CodeQL | Semantic variant scanning in source | Slow (query writing) | Deep (data flow) |
| Semgrep | Fast pattern matching in source | Fast | Shallow (syntactic) |
| BinDiff | Finding changed functions in patches | Fast | Medium |
| Binary pattern search (IDA/Ghidra) | Finding similar code in binaries | Medium | Medium |
| Bochspwn-style taint tracking | Systematic class-level automated discovery | Very slow (infrastructure) | Deep (runtime) |

---

## High-Value Variant Hunting Targets (Windows)

Components historically rich in repeated vulnerability patterns:

| Component | Recurring Bug Class | Key Researchers |
|---|---|---|
| Windows Installer / MSI | Arbitrary file write, rollback abuse | Naceri (klinix5), Forshaw |
| Win32k | Type confusion, NULL ptr, UAF | j00ru, Forshaw, Project Zero |
| Print Spooler | Impersonation, RPC coerce | Various (multiple CVEs) |
| Task Scheduler | TOCTOU, DACL write, LPE | Multiple researchers |
| RPC/ALPC | Authentication, type marshaling | Forshaw, Project Zero |
| LSASS plugins | Driver-level vulnerabilities | Various |
| Administrator Protection | New feature, many bypasses | Project Zero (2024-2025) |

> See NOTES.md for the complete variant hunting methodology checklist and case study templates.
> See RESOURCES.md for full entry details.
