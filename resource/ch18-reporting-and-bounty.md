# Chapter 18 — Vulnerability Reporting & Bug Bounty

> This chapter covers the full disclosure lifecycle: from writing a clear vulnerability report through MSRC and ZDI submission mechanics to CVSS scoring, coordinated disclosure timelines, and building a public research reputation. Understanding this process is not optional — a well-documented bug gets patched correctly and earns appropriate credit; a poorly documented one gets rejected or misclassified.

---

## 1. What Counts as a Vulnerability (MSRC Security Boundaries)

**The single most important document for scoping Windows security research:**
https://learn.microsoft.com/en-us/windows/security/security-servicing-criteria

MSRC uses this document to determine if a reported issue qualifies as a security vulnerability. Researchers who misread this waste months on non-qualifying bugs.

### Security Boundaries Windows Actively Defends

| Boundary | Meaning | Example Bug That Qualifies |
|----------|---------|---------------------------|
| User → Admin | Normal user should not gain admin without explicit consent | LPE: medium IL → SYSTEM without UAC prompt |
| Process isolation | A process should not access another process's memory without permission | One medium-IL process reads SYSTEM process memory |
| Network → Local | Unauthenticated network access should not grant local privilege | RCE from LAN without credentials |
| Sandbox → Host | AppContainer / Low IL should not escape | Chrome renderer (Low IL) → medium IL or higher |
| Hyper-V → Host | Guest VM should not access host or other VMs | Hyper-V guest escape |

### What Is NOT a Security Boundary

| Scenario | Why Not Defended |
|----------|-----------------|
| Admin → Kernel | If you have admin, you can already load drivers, modify kernel memory. This is *by design*. Admin → kernel is not a vulnerability. |
| Physical access | Assumed to be out of scope for software defenses |
| Social engineering (user must act) | Some scenarios require user to click a link, run a file — degree of interaction matters |

### Defense-in-Depth vs. Security Boundary Violation

Some bugs get a CVE but don't cross a defined security boundary. These are "defense-in-depth" hardening fixes:
- They make exploitation harder
- May get a lower-severity CVE
- Often don't qualify for bounty

**Practical test:** Can a low-privilege user (Medium IL, no special privileges) run your PoC and reliably obtain SYSTEM/admin without consent prompts? That's a qualifying Windows LPE.

---

## 2. MSRC Submission

**Portal:** https://msrc.microsoft.com/report/vulnerability

**Submission checklist:**

- [ ] Clear title: `[Component] — [Bug Type] — [Impact]`
  - Example: `Windows Print Spooler — Arbitrary File Write via Junction — Local Privilege Escalation`
- [ ] Affected products with exact build numbers (`winver` output)
- [ ] Numbered reproduction steps (reproducible by someone who has never seen the bug)
- [ ] Working proof-of-concept code (commented, minimal — not a full framework)
- [ ] Root cause analysis (what check is missing, what code path is wrong)
- [ ] Impact statement (what can an attacker with minimal required access achieve?)
- [ ] CVSS v3.1 score with vector string

**Response timeline:**

| Stage | Typical Duration |
|-------|----------------|
| Initial acknowledgment | 24–72 hours |
| Vulnerability assessment | 1–2 weeks |
| Case assigned to security engineer | 2–4 weeks |
| Patch development + testing | 1–6 months |
| Patch Tuesday release | Monthly (second Tuesday) |
| Public disclosure | 90 days after patch (or coordinated) |

**MSRC Bug Bounty Payouts (verify at https://www.microsoft.com/en-us/msrc/bounty):**

| Category | Approximate Max Payout |
|----------|----------------------|
| Windows LPE (critical) | Up to $50,000 |
| Windows LPE (important) | Up to $20,000 |
| Remote code execution | Up to $100,000+ |
| Hyper-V escape | Up to $250,000 |
| Security feature bypass | Up to $30,000 |

---

## 3. Zero Day Initiative (ZDI) as an Alternative

**URL:** https://www.zerodayinitiative.com/

ZDI purchases vulnerabilities from researchers and coordinates disclosure with the vendor. They accept Windows bugs.

| Factor | ZDI Path | MSRC Direct Path |
|--------|---------|-----------------|
| Payment timing | Faster (ZDI pays after acceptance, before vendor patch) | After patch + bounty review (slower) |
| Payment amount | Potentially lower (ZDI margin) | Potentially higher for critical bugs |
| Coordination burden | ZDI handles it | You coordinate directly |
| Advisory credit | ZDI publishes with your name | MSRC acknowledgment page |
| New researcher | ZDI may be more approachable | MSRC handles all submissions |

**ZDI timeline:** 120-day disclosure window (vs. Project Zero's 90-day standard).

---

## 4. Writing a Great Vulnerability Report

### Structure

```
Title: Windows [Component] — [Bug Type] — [Impact]

1. SUMMARY (3–5 sentences)
   - What is the bug?
   - What component is affected?
   - What can an attacker achieve with it?
   - What privileges/conditions are required?

2. AFFECTED VERSIONS
   - Specific Windows versions and build numbers tested
   - Earliest confirmed affected version (if known)
   - Whether a patched version is known

3. REPRODUCTION STEPS
   1. [Exact numbered step]
   2. [Exact numbered step]
   ...
   Note: Steps must be exact and reproducible on a clean VM.

4. PROOF OF CONCEPT
   - Attach working PoC code
   - Code should be commented to explain each step
   - Should produce clear "you are SYSTEM" confirmation
   - Keep it minimal — not a full post-exploitation framework

5. ROOT CAUSE ANALYSIS
   - The specific missing check or incorrect assumption
   - The code path that leads to the bug
   - Why this violates the security boundary
   - Function names, module names, relevant structures

6. IMPACT
   - What can an attacker with minimal required access achieve?
   - Data access, code execution, persistence?
   - Required preconditions (local user? specific privilege? specific service running?)

7. CVSS v3.1 SCORE
   - Vector string: CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
   - Score: 7.8 HIGH

8. SUGGESTED FIX (optional)
   - What check should be added or corrected?
   - Accelerates patch development if included
```

### Dos and Don'ts

**Do:**
- Test reproduction steps on a clean VM before submitting
- Include screenshots or recordings if timing-dependent
- State the exact Windows build (`winver` output — e.g., "19044.1466")
- Explain root cause in plain language even if you include technical detail
- Respond promptly to follow-up questions from MSRC engineers

**Don't:**
- Submit a theoretical bug without a working PoC — vendors need to reproduce it
- Over-inflate severity — MSRC recalculates CVSS, and credibility matters for future submissions
- Include unnecessary attack framework code in the PoC
- Disclose publicly before the disclosure deadline unless vendor is non-responsive
- Submit the same bug to multiple vendors/platforms simultaneously

---

## 5. CVSS v3.1 Scoring for Windows LPE Bugs

**Calculator:** https://www.first.org/cvss/calculator/3.1

### Common Windows LPE Patterns

**Standard local privilege escalation (medium → SYSTEM, no interaction):**
```
AV:L  / AC:L / PR:L / UI:N / S:U / C:H / I:H / A:H
Score: 7.8 HIGH
```
- `AV:L` — Local (requires local access, not network)
- `AC:L` — Low complexity (reliable, no race conditions)
- `PR:L` — Low privilege required (standard user)
- `UI:N` — No user interaction
- `S:U` — Scope unchanged (same security boundary)
- `C/I/A:H` — Full confidentiality/integrity/availability impact at SYSTEM

**LPE with race condition (timing-dependent):**
```
AV:L / AC:H / PR:L / UI:N / S:U / C:H / I:H / A:H
Score: 7.0 HIGH
```
- `AC:H` — High complexity (race window, not 100% reliable)

**Sandbox escape (AppContainer/Low IL → Medium IL or higher):**
```
AV:L / AC:L / PR:L / UI:N / S:C / C:H / I:H / A:H
Score: 8.8 HIGH (can reach Critical with S:C)
```
- `S:C` — Scope changed (crossing from Low IL to outside sandbox)

**Remote code execution (network, no auth):**
```
AV:N / AC:L / PR:N / UI:N / S:U / C:H / I:H / A:H
Score: 9.8 CRITICAL
```

---

## 6. Coordinated Disclosure Best Practices

### The 90-Day Standard (Project Zero)

1. Report bug to vendor
2. Vendor has 90 days to patch
3. After 90 days: disclose publicly regardless of patch status
4. If patch issued before 90 days: disclose after patch (wait up to 7 more days for user adoption)

**Grace period:** If a patch is issued on day 89, wait an additional 7 days before public disclosure (so users have time to patch).

**Why 90 days works:** Long enough for most vendors to issue a Patch Tuesday fix; short enough to maintain researcher incentive and user protection.

### MSRC Formal Timeline

After submission:
1. MSRC acknowledges within 24–72 hours
2. Case assigned to engineer (you get a MSRC case ID)
3. MSRC may request additional details — respond promptly
4. Once patched: CVE assigned, acknowledgment published at `msrc.microsoft.com/update-guide/acknowledgement`
5. Patch usually ships on the next Patch Tuesday after the fix is ready

### Handling Non-Responsive Vendors

If MSRC doesn't respond meaningfully within 90 days:
1. Send a formal "30-day final notice" email citing the 90-day policy
2. State the specific date you will disclose
3. Disclose on that date with full technical details and PoC
4. Notify ZDI or vulnerability disclosure facilitators if needed

### In-the-Wild Exploited Bugs

If you have evidence a bug you've reported is actively exploited:
1. Immediately notify MSRC and request emergency response
2. If critical infrastructure is at risk, notify CISA (cisa.gov)
3. MSRC can issue out-of-band patches for actively exploited vulnerabilities (does not wait for Patch Tuesday)

---

## 7. MSRC Severity Ratings

**Full reference:** https://msrc.microsoft.com/blog/2022/05/microsoft-vulnerability-severity-classification/

| Severity | Definition | LPE Examples |
|----------|-----------|-------------|
| **Critical** | Exploitation allows code propagation without user action | Wormable LPE, unauthenticated network LPE |
| **Important** | Compromise of confidentiality/integrity/availability or auth bypass | Standard local → SYSTEM LPE (most LPEs fall here) |
| **Moderate** | Significant mitigating factors — high interaction, limited impact, non-default config | UAC bypass requiring admin already, info disclosure with low impact |
| **Low** | Difficult to exploit, minimal impact | DoS with limited scope, non-sensitive info disclosure |

**For LPE research:** Most qualifying Windows LPE bugs land at **Important** (7.0–7.8 CVSS). To reach **Critical**, a LPE would need to be wormable (reachable from network without auth) or affect a very large-scale sandboxed context.

---

## 8. Building a Research Reputation

### MSRC Acknowledgments

- Every qualifying CVE earns an MSRC acknowledgment
- Listed at: https://msrc.microsoft.com/update-guide/acknowledgement
- Visible per-month and per-researcher; industry-standard credential

### Public Track Record Activities

| Activity | Platform | Visibility |
|----------|---------|-----------|
| Blog post on patched CVE | Personal blog / Medium | High — referenced by community |
| Conference talk | DEF CON, Black Hat, BlueHat | Very high — recorded and archived |
| Open-source tool release | GitHub | High — ongoing citation |
| CVE acknowledgments | MSRC page | Searchable, permanent record |
| Community engagement | Twitter/X, Mastodon, conferences | Relationship-building |

### The 3 Rules of Public Research

1. **Only publish after the patch is live** — or after your declared disclosure deadline has passed and vendor has had adequate notice
2. **Minimize harm** — don't release weaponized exploit code that attackers can use against unpatched systems without considering the impact
3. **Be accurate** — don't claim impact you can't demonstrate; community reputation is built on accuracy

### Role Models for Research Publication Quality

- itm4n (itm4n.github.io) — clear, reproducible, explains root cause and technique
- James Forshaw (tiraniddo.dev, Project Zero blog) — defines the standard for depth and rigor
- Yarden Shafir (windows-internals.com) — detailed kernel exploitation posts with full context

---

## References

- [R-1] MSRC Submission Portal — Microsoft — https://msrc.microsoft.com/report/vulnerability
- [R-2] Windows Security Servicing Criteria — Microsoft — https://learn.microsoft.com/en-us/windows/security/security-servicing-criteria
- [R-3] MSRC Bug Bounty Programs — Microsoft — https://www.microsoft.com/en-us/msrc/bounty
- [R-4] ZDI Submission — Trend Micro ZDI — https://www.zerodayinitiative.com/
- [R-5] CVSS v3.1 Calculator — FIRST — https://www.first.org/cvss/calculator/3.1
- [R-6] Project Zero Disclosure Policy — Google — https://googleprojectzero.blogspot.com/p/vulnerability-disclosure-policy.html
- [R-7] MSRC Acknowledgments — Microsoft — https://msrc.microsoft.com/update-guide/acknowledgement
