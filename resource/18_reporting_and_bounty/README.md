# Reporting and Bounty
## Windows Security Research — Vulnerability Disclosure Overview

---

## What This Section Contains

This section covers the full pipeline from finding a vulnerability to receiving acknowledgment and bounty payment. It includes:

- **Submission portals:** MSRC, ZDI, HackerOne — how and when to use each
- **Writing reports:** Templates, tips, and examples for excellent vulnerability reports
- **Scoring:** CVSS v3.1 scoring for common Windows vulnerability types
- **Disclosure policy:** Coordinated disclosure best practices, 90-day rule
- **Windows Servicing Criteria:** What MSRC considers a bug vs expected behavior
- **MSRC severity ratings:** How Microsoft categorizes vulnerability severity

---

## Quick Reference

| Task | Resource |
|------|---------|
| Submit a bug to Microsoft | https://msrc.microsoft.com/report/vulnerability |
| Check if bug is in scope | https://learn.microsoft.com/en-us/windows/security/security-servicing-criteria |
| Check bounty amounts | https://www.microsoft.com/en-us/msrc/bounty |
| Submit to ZDI | https://www.zerodayinitiative.com |
| Calculate CVSS score | https://www.first.org/cvss/calculator/3.1 |
| Check who got credited | https://msrc.microsoft.com/update-guide/acknowledgement |

---

## Files in This Section

| File | Contents |
|------|---------|
| `RESOURCES.md` | Comprehensive guide to all reporting and bounty resources |

---

## Golden Rule

**Before submitting:** Test your reproduction steps on a clean VM snapshot. A report that the vendor cannot reproduce is a report that does not get patched.

**Before disclosing publicly:** Give MSRC at least 90 days. Responsible disclosure builds trust and ensures bugs get fixed.

**After disclosure:** Write a public post-mortem analysis of the bug. This builds your research reputation, helps the community learn, and is how the best researchers share knowledge.
