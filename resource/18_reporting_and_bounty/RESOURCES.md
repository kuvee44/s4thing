# Reporting and Bounty Resources
## Windows Security Research — Vulnerability Disclosure and Bug Bounty

---

## 1. MSRC (Microsoft Security Response Center) Submission

### Portal
**URL:** https://msrc.microsoft.com/report/vulnerability

**What MSRC handles:**
- All Microsoft products and services including Windows OS, Windows components, Office, Azure, Edge, Xbox
- Vulnerabilities in first-party Microsoft code
- Supply chain issues affecting Microsoft products

### Submission Checklist
Before submitting to MSRC, ensure you have:

- [ ] **Title:** Concise description including affected component (e.g., "Windows Print Spooler arbitrary file write via junction leads to LPE")
- [ ] **Affected products:** Specific Windows versions (e.g., "Windows 10 21H2 build 19044.1466 and earlier")
- [ ] **Reproduction steps:** Numbered, exact steps to reproduce the vulnerability
- [ ] **Proof of concept:** Working PoC code (commented, minimal)
- [ ] **Impact:** What an attacker with the minimal required access level can achieve
- [ ] **Root cause:** Technical explanation of why the bug exists
- [ ] **CVSS score:** Your assessment (MSRC will revise this)
- [ ] **Has this been shared with third parties?** Be honest

### MSRC Response Timeline
- **Initial acknowledgment:** 24–72 hours
- **Vulnerability assessment:** 1–2 weeks
- **Case assigned to engineer:** 2–4 weeks
- **Patch development + testing:** Variable (1–6 months)
- **Patch Tuesday release:** Monthly (second Tuesday of each month)
- **Public disclosure:** 90 days after patch, or coordinated with researcher

### MSRC Bug Bounty Payouts (as of 2024 — verify current rates)
| Category | Max Payout |
|----------|-----------|
| Windows LPE (critical) | Up to $50,000 |
| Windows LPE (important) | Up to $20,000 |
| Remote code execution | Up to $100,000+ |
| Hyper-V escape | Up to $250,000 |
| Security feature bypass | Up to $30,000 |

**Full bounty table:** https://www.microsoft.com/en-us/msrc/bounty

---

## 2. Windows Security Servicing Criteria

**URL:** https://learn.microsoft.com/en-us/windows/security/security-servicing-criteria

**This is the single most important reference for determining if a bug is in scope.** MSRC uses this document to decide what constitutes a vulnerability vs expected behavior.

### Key Concepts from Servicing Criteria

**Security Boundaries Windows Defends:**
1. User/Admin boundary — code running as a normal user should not be able to gain admin without explicit consent
2. Admin/Kernel boundary — admin code should not be able to exploit the kernel (note: this boundary is NOT defended; admin → kernel is not a vulnerability)
3. Process isolation — a process should not be able to access another process's memory without permission
4. Network boundary — unauthenticated network access should not grant local privilege
5. Sandbox boundary — processes in AppContainer/Low IL should not be able to escape

**What is NOT a security boundary (i.e., bugs that won't get a CVE):**
- Admin to kernel: "If an administrator can already execute arbitrary code as administrator, we do not consider this a vulnerability"
- Bypasses requiring physical access
- Social engineering (user must click to get compromised in many scenarios)

**Vulnerability vs Defense-in-Depth:**
- Some fixes are "defense-in-depth" — they make exploitation harder but don't cross a defined security boundary
- These may get a CVE but typically lower severity and may not qualify for bounty

---

## 3. Zero Day Initiative (ZDI) Submission

**URL:** https://www.zerodayinitiative.com/advisories/disclosure_policy/

**What ZDI does:**
- Purchase vulnerabilities from researchers
- Pay bounties and then coordinate disclosure with the vendor
- Publish advisories (often with technical details) after the patch is released

### ZDI vs Direct MSRC Submission

| Factor | ZDI | MSRC Direct |
|--------|-----|-------------|
| Payment timing | Faster (ZDI pays you after accepting) | Slower (after patch + bounty review) |
| Payment amount | May be lower (ZDI takes a margin) | Potentially higher for critical bugs |
| Coordination | ZDI handles vendor coordination | You coordinate directly |
| Advisories | ZDI publishes advisories with your name | MSRC publishes acknowledgments |
| For unknown researchers | ZDI may be more approachable | MSRC handles all submissions |

### ZDI Submission Requirements
1. Register an account at zerodayinitiative.com
2. Submit through the portal with:
   - Full technical description
   - Proof-of-concept code
   - Affected versions
   - Impact assessment
3. ZDI reviews (1–4 weeks)
4. If accepted: sign agreement, receive payment
5. ZDI coordinates 120-day disclosure timeline with vendor

---

## 4. HackerOne — Microsoft Program

**URL:** https://hackerone.com/microsoft

**HackerOne Policy:**
- Microsoft maintains an active HackerOne program in addition to MSRC direct submission
- Some Microsoft products are in scope through HackerOne specifically
- Disclosure timelines and bounty ranges are listed on the program page

**When to use HackerOne:**
- Bugs in Microsoft online services (Azure, M365, Bing, etc.)
- When you want program-style tracking and public disclosure
- For bugs that may not rise to full MSRC severity

**Note:** Core Windows OS vulnerabilities are generally better submitted to MSRC directly rather than HackerOne.

---

## 5. Google Bug Hunter University

**URL:** https://bughunters.google.com/learn

**Why relevant for Windows researchers:**
- Google Project Zero has set the standard for vulnerability research methodology
- Bug Hunter University teaches systematic approach to vulnerability research
- Chrome/Chromium sandbox escape research overlaps heavily with Windows sandbox research
- Google pays bounties for bugs in Windows when they affect Chrome/Chromium (via Chrome's sandbox)

### Relevant Resources
- Project Zero's bug disclosure policy: https://googleprojectzero.blogspot.com/p/vulnerability-disclosure-policy.html
- How Project Zero writes writeups: read any Project Zero blog post as a template
- Google's VRP reward amounts: https://bughunters.google.com/about/rules/google-friends/6625844

---

## 6. Writing Great Vulnerability Reports

### Structure of an Excellent Report

```
Title: [Component] — [Bug Type] — [Impact]
Example: "Windows Print Spooler — Arbitrary File Write via Junction — Local Privilege Escalation"

1. SUMMARY (3–5 sentences)
   - What is the bug?
   - What component is affected?
   - What can an attacker do with it?
   - What privileges/conditions are required?

2. AFFECTED VERSIONS
   - List specific build numbers tested
   - Note earliest confirmed affected version (if known)
   - Note if patched version is known

3. REPRODUCTION STEPS
   1. [Exact step]
   2. [Exact step]
   3. [Exact step]
   Note: Steps must be numbered, exact, and reproducible by someone 
         who has never seen the bug.

4. PROOF OF CONCEPT
   - Attach or include working PoC code
   - Code should be commented to explain each step
   - Should produce a clear "you are SYSTEM" indicator
   - Should be minimal (not a full framework, just the bug)

5. ROOT CAUSE ANALYSIS
   - What is the specific missing check / incorrect assumption?
   - What code path leads to the bug?
   - Why does this violate the security boundary?
   - Reference: function names, module names, relevant structures

6. IMPACT
   - What can an attacker with minimal required access (e.g., local user, 
     network access, low-IL process) achieve?
   - What data can they access?
   - Can they achieve code execution / persistence?
   - Is this a reliability issue or a security issue?

7. CVSS SCORE
   - Include your CVSS v3.1 score with vector string
   - Example: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H = 7.8

8. SUGGESTED FIX (Optional)
   - What check should be added or corrected?
   - Not required, but appreciated and may speed patch development
```

### Tips for Writing Good Reports

**Do:**
- Test your reproduction steps on a clean VM before submitting
- Include screenshots or recordings if the bug is visual or timing-dependent
- Explicitly state the Windows build number (`winver` output)
- Explain the root cause in plain language even if you also include technical detail
- Be responsive to follow-up questions from the vendor's security engineer

**Don't:**
- Submit a "theoretical" bug without a working PoC — vendors need to reproduce it
- Over-inflate severity — vendors will recalculate CVSS and credibility matters
- Include unnecessary attack framework code in the PoC
- Disclose publicly before the 90-day window unless the vendor is non-responsive
- Submit the same bug to multiple vendors/platforms simultaneously without disclosure

---

## 7. CVSS v3.1 Scoring for Windows LPE Bugs

**Calculator:** https://www.first.org/cvss/calculator/3.1
**Full specification:** https://www.first.org/cvss/specification-document

### Common Windows LPE Scoring Patterns

**Local Privilege Escalation (standard):**
```
Attack Vector: Local (AV:L)
Attack Complexity: Low (AC:L)
Privileges Required: Low (PR:L)      ← requires local user account
User Interaction: None (UI:N)
Scope: Unchanged (S:U)
Confidentiality: High (C:H)
Integrity: High (I:H)
Availability: High (A:H)
Score: 7.8 HIGH
```

**LPE with high complexity (race condition / specific timing):**
```
Attack Complexity: High (AC:H)
All others: same as above
Score: 7.0 HIGH
```

**LPE from AppContainer sandbox (scope change):**
```
Scope: Changed (S:C)          ← escaping from Low IL to medium/high
Score: typically 8.8+ CRITICAL
```

**RCE from network:**
```
Attack Vector: Network (AV:N)
Score: 9.0+ CRITICAL
```

---

## 8. Coordinated Disclosure Best Practices

### The 90-Day Rule (Project Zero Standard)
The security community generally follows a 90-day disclosure policy:
1. Report bug to vendor
2. Vendor has 90 days to patch
3. After 90 days, the bug is disclosed publicly regardless of patch status
4. If patch is issued before 90 days: disclose after patch (or wait up to 7 more days for users to patch)

**Why 90 days:** Long enough for most vendors to issue a patch; short enough to incentivize rapid response.

### MSRC's Formal Acknowledgment
- Once MSRC assigns a CVE, they send an acknowledgment email
- You can track the case at msrc.microsoft.com
- MSRC may request: additional reproduction details, specific Windows versions affected, impact clarification

### Handling Non-Responsive Vendors
If MSRC doesn't respond meaningfully within 90 days:
1. Send a formal "30-day final notice" email
2. Notify that you plan to disclose on a specific date
3. Disclose on that date — include full technical details, PoC
4. Inform ZDI or other third parties who may facilitate disclosure

### What to Do If Exploited In the Wild
If you have reason to believe a bug you've reported is being actively exploited:
1. Immediately notify MSRC and request emergency response
2. If critical infrastructure is at risk, consider notifying CISA (cisa.gov)
3. MSRC can issue out-of-band patches for in-the-wild exploits

---

## 9. Understanding MSRC Severity Ratings

**MSRC Severity Blog:** https://msrc.microsoft.com/blog/2022/05/microsoft-vulnerability-severity-classification/

### Severity Levels

**Critical:** Vulnerabilities whose exploitation could allow code propagation without user action — typically RCE or wormable bugs.
- Examples: Unauthenticated RCE over network, wormable kernel bugs

**Important:** Vulnerabilities that could result in compromise of data confidentiality, integrity, or availability, or a bypass of authentication.
- Examples: Local privilege escalation to SYSTEM, sensitive data disclosure, sandbox escape

**Moderate:** Vulnerabilities mitigated by significant factors — e.g., requires significant user interaction, limited impact, or non-default configuration.
- Examples: UAC bypass (admin required), information disclosure with limited impact

**Low:** Vulnerabilities that are difficult to exploit or have minimal impact.
- Examples: Non-sensitive information disclosure, denial of service with limited scope

### For Windows LPE Research
Most Windows LPE bugs fall into **Important** severity. To be rated **Critical**, a Windows LPE would need to:
- Be wormable (reachable from the network without authentication), OR
- Allow escaping from a sandbox in a way that affects many users at scale

---

## 10. Building a Research Reputation

### MSRC Acknowledgments
- Every CVE you report that MSRC considers valid gets you an acknowledgment
- Track these for your portfolio: https://msrc.microsoft.com/update-guide/acknowledgement
- Researchers are listed by name, CVE number, and month

### Responsible Research Principles
1. **Minimize harm:** Don't exploit bugs against systems you don't own
2. **Disclose responsibly:** Give vendors time to patch before publishing
3. **Be accurate:** Don't claim impact you can't demonstrate
4. **Help vendors:** Assist with reproduction if asked; suggest fixes when you can

### Building a Public Track Record
- Publish blog posts analyzing patched CVEs (after disclosure)
- Speak at conferences (DEF CON, Black Hat, BlueHat)
- Release open-source research tools
- Contribute to the community by reviewing others' research publicly

---

## See Also
- `00_index/LEARNING_PATH.md` — Stage 9: Reporting and Bounty Workflow
- `13_cve_case_studies/` — Case studies of real CVEs and their disclosures
- `00_index/RESEARCHERS_TO_FOLLOW.md` — Researchers who have published disclosure analyses
