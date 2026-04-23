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

### Annotated Example Report — Windows Service Tracing LPE

The following is a fully annotated example modeled after CVE-2020-0668 (Windows Service Tracing arbitrary file move) to illustrate what each section of a report should look like in practice.

---

**Title:**
`Windows Service Tracing — Arbitrary File Write via Weak Registry ACL and Junction — Local Privilege Escalation`

*Why this title works: Component (Windows Service Tracing) → bug mechanism (Arbitrary File Write via Junction) → impact (LPE). Reviewers know immediately what to route this to and what the expected impact is.*

---

**1. SUMMARY**

Windows Service Tracing allows low-privilege users to write to registry keys under `HKLM\SOFTWARE\Microsoft\Tracing\` due to an overly permissive DACL that grants `KEY_SET_VALUE` to `BUILTIN\Users`. A low-privilege attacker can set the `EnableFileTracing` value and control the `FileDirectory` registry value to point to an arbitrary directory. When the RPCSS service (running as LocalSystem) initializes tracing, it creates a log file at the attacker-specified path. By placing a directory junction at the target path before service initialization, the attacker redirects the file creation to any directory on the system — including `C:\Windows\System32`. A specially named file placed there by this primitive can achieve code execution as SYSTEM, constituting a Local Privilege Escalation from any standard user (Medium integrity) to SYSTEM (System integrity) without UAC interaction.

*What this summary covers: what (weak registry ACL + junction), where (HKLM\SOFTWARE\Microsoft\Tracing + RPCSS), impact (LPE to SYSTEM), preconditions (standard user, no admin, no special privilege).*

---

**2. AFFECTED VERSIONS**

```
Windows 10 Version 1903  — Build 18362.592  (confirmed vulnerable, tested)
Windows 10 Version 1909  — Build 18363.592  (confirmed vulnerable, tested)
Windows 10 Version 1809  — Build 17763.1039 (confirmed vulnerable, tested)
Windows Server 2019      — Build 17763.1039 (confirmed vulnerable, tested)
Windows 7 SP1            — Build 7601.24545 (expected vulnerable, not tested)
```

Earliest affected: Believed to affect all Windows versions since Windows Vista introduced Service Tracing.
Patched version: Not known at time of submission.

*Note: Exact build numbers from `winver` dialog. "Tested" means you ran the PoC yourself on a clean VM at that build. "Expected" means you analyzed code or documentation but did not test directly — be honest about this distinction.*

---

**3. REPRODUCTION STEPS**

```
Environment:
  - Clean Windows 10 Version 1909 VM (Build 18363.592)
  - Standard user account (no admin, no special groups)
  - No AV (disable Windows Defender for testing)

1. Open a command prompt as the standard user (verify: whoami shows non-admin, `whoami /priv` shows no SeImpersonatePrivilege)

2. Verify the weak DACL on the tracing registry key:
   accesschk.exe -kw "BUILTIN\Users" HKLM\SOFTWARE\Microsoft\Tracing\RPCSS_MEDIASERVER
   Expected output: "BUILTIN\Users" KEY_SET_VALUE

3. Create a staging directory for junction manipulation:
   mkdir C:\Temp\junction_stage

4. Compile and run the provided PoC (Exploit.exe):
   Exploit.exe
   The PoC performs:
     a. Sets EnableFileTracing=1 and FileDirectory=C:\Temp\junction_stage under HKLM\...\Tracing\RPCSS_MEDIASERVER
     b. Acquires an oplock on C:\Temp\junction_stage
     c. Triggers RPCSS service to re-initialize tracing (via registry modification)
     d. When RPCSS opens C:\Temp\junction_stage to create the log file, the oplock fires
     e. PoC removes C:\Temp\junction_stage, creates a junction from C:\Temp\junction_stage → C:\Windows\System32
     f. Releases oplock
     g. RPCSS creates log file at C:\Windows\System32\RPCSS_MEDIASERVER.log (owned by SYSTEM)

5. Verify the file was created:
   dir C:\Windows\System32\RPCSS_MEDIASERVER.log
   Expected: file exists, owned by SYSTEM

6. Use the arbitrary file creation primitive to plant a malicious DLL at a hijackable path (see PoC comments) and trigger a SYSTEM process to load it.

7. Observe SYSTEM shell or note "NT AUTHORITY\SYSTEM" in spawned process token.
```

*What makes reproduction steps good: exact environment specification, verification commands at each step, explanation of what the PoC is doing internally (not just "run it"), clear expected output.*

---

**4. ROOT CAUSE ANALYSIS**

The root cause is a missing access control check on the `HKLM\SOFTWARE\Microsoft\Tracing\` registry key tree.

**Which check is missing:** The registry key DACL grants `KEY_SET_VALUE` to `BUILTIN\Users`. For a registry key that controls the behavior of a LocalSystem service, this permission should be restricted to `Administrators` or `NT SERVICE\RPCSS` only.

**Code path:**
1. `RPCSS.dll!InitializeTracing()` reads `HKLM\SOFTWARE\Microsoft\Tracing\RPCSS_MEDIASERVER\FileDirectory` to determine the log directory
2. The function calls `CreateFile()` on `[FileDirectory]\[ServiceName].log` with `GENERIC_WRITE | CREATE_ALWAYS`
3. No check is performed to verify that the calling process (RPCSS) wrote this registry value, or that the path is a system-owned directory
4. Because a standard user can write `FileDirectory`, the attacker controls the path argument to `CreateFile()`
5. Combined with the oplock/junction primitive, the single `CreateFile` call can be redirected to any path

**Why this violates the security boundary:** A standard user (Medium IL) can direct a SYSTEM-integrity process (`RPCSS`, running as `LocalSystem`) to create an attacker-controlled file at any path on the filesystem. This constitutes a write primitive crossing the User → Admin security boundary. Writing to `C:\Windows\System32` is restricted to Administrators, but through this bug, a standard user can plant files in that directory via the RPCSS service.

**Relevant modules:** `rpcss.dll` (tracing init), `ntdll.dll!NtSetValueKey` (registry write), `ntdll.dll!NtCreateFile` (file creation at attacker-controlled path).

---

**5. CVSS v3.1 VECTOR — FULLY ANNOTATED**

```
CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H
Score: 7.8 HIGH
```

| Metric | Value | Reasoning |
|--------|-------|-----------|
| **AV (Attack Vector)** | **L** (Local) | Attacker must have a local user session on the machine. Not exploitable over the network. |
| **AC (Attack Complexity)** | **L** (Low) | The oplock/junction technique is reliable and deterministic. No race window in the probabilistic sense — oplock fires exactly once, junction placement is synchronous. Exploit works consistently. |
| **PR (Privileges Required)** | **L** (Low) | Requires only a standard user account. No special groups, no SeImpersonatePrivilege, no existing local admin. |
| **UI (User Interaction)** | **N** (None) | The attacker does not require another user to take any action. The exploit targets a service that is always running. |
| **S (Scope)** | **U** (Unchanged) | The exploited component (RPCSS) and the component gaining elevated impact (local filesystem) are within the same security authority — the local machine. Not a sandbox escape. |
| **C (Confidentiality)** | **H** (High) | Once SYSTEM shell is obtained, attacker has complete access to all files, credentials, and secrets on the machine. |
| **I (Integrity)** | **H** (High) | Attacker can write to any location on the filesystem, including system binaries and configuration. |
| **A (Availability)** | **H** (High) | Attacker can terminate any process, corrupt system files, or install a bootkit. |

*Note on AC: If your exploit requires a probabilistic race (e.g., double-fetch without oplock), use AC:H (score drops to 7.0). Oplock-gated exploits are AC:L because timing is attacker-controlled.*

---

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

## 8. Common Report Rejection Reasons

Understanding why MSRC rejects or downgrades reports saves significant time. These are the most common failure patterns.

### Pattern 1 — "Admin → Kernel" Submissions

**What happens:** Researcher finds a way to read or write kernel memory, patch SSDT, or load an unsigned driver — but the PoC requires local administrator privileges to start.

**MSRC response:** "This issue does not cross a defined security boundary. Admin-level access is sufficient to load a kernel driver and perform these operations by design."

**Why it fails:** Windows explicitly considers Admin → Kernel to be a non-boundary. If you are already admin, you can `sc create` a driver service, use `bcdedit /set testsigning on`, or use `NtLoadDriver` directly. The Windows Security Servicing Criteria states this explicitly.

**What to do instead:** Verify your PoC starts from Medium integrity (standard user, no UAC elevation, no admin token). Run it from a restricted account. If it fails from Medium IL, the bug does not cross the security boundary.

### Pattern 2 — Missing PoC

**What happens:** Researcher submits a report describing a bug theoretically ("the code appears to be missing a check on the ACL") without a working exploit.

**MSRC response:** Request for proof-of-concept. If not provided, case may be closed or deprioritized.

**Why it matters:** MSRC engineers triage hundreds of submissions. A theoretical description without a PoC cannot be independently verified. "Appears to be vulnerable" is not enough — demonstrate it.

**Rule:** Do not submit until you have a working PoC that reliably reproduces the impact on a clean VM.

### Pattern 3 — PoC Starts from Wrong Privilege Level

**What happens:** PoC achieves SYSTEM, but the setup requires enabling a specific privilege, adding the user to a group, or running one step as admin.

**MSRC response:** "Your PoC requires [SeImpersonatePrivilege / membership in Performance Log Users / admin rights to install service] — this privilege level is not representative of the standard user scenario."

**What to do:** Run the entire PoC as a freshly created standard user. Check `whoami /all` before and after — no elevated privileges, no special groups except the defaults (Users, Authenticated Users, Everyone). If any step requires more, you have a different bug class (or no bug).

### Pattern 4 — Severity Inflation

**What happens:** Researcher submits with CVSS 9.8 Critical. MSRC recalculates and assigns Important (7.8).

**Common causes:**
- Researcher sets `AV:N` (network) when the attack requires local access (`AV:L`)
- Researcher sets `AC:L` when the exploit requires a probabilistic race (`AC:H`)
- Researcher sets `PR:N` (no privilege) when a standard user account is required (`PR:L`)

**Why credibility matters:** MSRC tracks researcher accuracy over time. Consistently over-rating bugs damages your relationship and may result in slower responses. Submit the vector string you genuinely believe is correct, and explain your reasoning — MSRC will discuss it if they disagree.

### Pattern 5 — Affected Version Not Specified

**What happens:** Report says "Windows 10" without a build number. MSRC cannot triage without knowing if the issue is present in the current shipping version.

**What to include:** Run `winver` on the test machine and copy the full output. Example: "Windows 10 Version 21H2 (OS Build 19044.1466)". If you tested multiple builds, list all of them with results.

### Pattern 6 — Submitting a Known Duplicate

**Before submitting, search for existing CVEs:**

1. **NVD (nvd.nist.gov):** Search by component name + CWE type. Example: `"Windows Installer" privilege escalation`
2. **MSRC Update Guide:** https://msrc.microsoft.com/update-guide/ — search by keyword in the title
3. **MSRC Acknowledgments:** Search by technique or component in past Patch Tuesday advisories
4. **GitHub:** Search for PoCs related to your bug class — if there's a public PoC with a CVE number, it's patched

**If you find a CVE for the same component:** Read the advisory carefully. The fix may address only a specific code path — your variant may still be novel. Document the differences explicitly in your report.

---

## 9. Working with MSRC Engineers

### What to Expect After Submission

After your case is acknowledged and assigned:

- The MSRC engineer assigned to your case will review the PoC and attempt to reproduce it
- They may send technical follow-up questions within 1–2 weeks of assignment — these are usually specific: "Does this reproduce on Windows 11 23H2?", "What is the exact service state required?", "Does this work without the additional junction step?"
- **Answer promptly and completely.** Delays in your responses extend the timeline and may result in the case being deprioritized. Aim to respond within 48 hours.

### How to Handle Disagreements on Severity

MSRC may assess your bug as lower severity than you believe. Do not simply accept their initial assessment if you disagree:

1. **Present the full exploitation chain, not just the primitive.** A "Moderate" file write becomes "Important" when you show the complete chain from file write → DLL plant → SYSTEM shell. If MSRC only sees the primitive, they may miss the downstream impact.
2. **Show the attacker perspective.** Enumerate: starting conditions (standard user, no special privileges), steps to SYSTEM, reliability, and prerequisites. Make it impossible to argue the impact is limited.
3. **Reference similar CVEs.** If a similar bug class received Important or Critical, cite the CVE and explain why your bug is equivalent.
4. **Accept reasonable disagreements.** If MSRC's CVSS calculation differs by one metric and their reasoning is sound, conceding is appropriate. Fighting over every metric damages the working relationship.

### "Won't Fix" vs. "Not a Security Boundary" vs. "Defense-in-Depth"

These three outcomes have different implications for public disclosure:

| Outcome | Meaning | Disclosure Implication |
|---------|---------|----------------------|
| **Won't Fix** | MSRC acknowledges the bug is real and violates a security boundary, but determines the fix risk outweighs the benefit (often low exploitability + high fix risk) | You can disclose after notifying MSRC of your intent. Bug remains exploitable. |
| **Not a Security Boundary** | MSRC determines the behavior does not cross any defined security boundary (e.g., Admin → Kernel) | The bug is by design. If you disagree, argue via the Security Research Criteria. Public disclosure of a "not a vulnerability" finding is your right but typically has less impact. |
| **Defense-in-Depth** | MSRC acknowledges the hardening value but issues no CVE or bounty | The fix ships silently. No acknowledgment. |

### Tracking Your Submission

After initial acknowledgment you receive a **MSRC case ID** (format: `VULN-XXXXXXXX` or a numeric ID). Keep this ID — it is your reference for all follow-up.

**If you have heard nothing for 2 weeks after the case was assigned to an engineer:**
1. Reply to the last communication thread referencing your case ID
2. Ask for a status update on the vulnerability assessment
3. State your expected disclosure date (90 days from submission)

**If you have heard nothing for 30 days total:**
1. Send a formal follow-up noting the 30-day mark
2. Reference the MSRC coordinated disclosure policy
3. State the date you intend to disclose if no response

MSRC is generally responsive, but case loads vary. Polite, professional follow-ups are appropriate and expected.

---

## 10. ADCS and Kerberos Research Reporting Specifics

ADCS and Kerberos vulnerabilities have some nuances in how they are scoped and routed within MSRC.

### ADCS Vulnerabilities (ESC Bugs)

**Which team handles them:** ADCS vulnerabilities (the ESC1–ESC13 class discovered by SpecterOps) are handled by the Active Directory/Identity team at MSRC, not the general Windows team. In your submission title, explicitly name "Active Directory Certificate Services" and the specific ESC class.

**What makes an ADCS bug qualify:**
- A misconfiguration that allows a standard domain user to obtain a certificate for a privileged user's UPN without authorization
- The exploit must work in a *default or common configuration* — bugs that only work in highly unusual non-default CA setups receive lower priority
- MSRC generally treats the most severe ESC bugs (ESC1, ESC6, ESC8) as warranting patches; template-level misconfigurations by administrators are treated as configuration issues rather than vulnerabilities

**What does NOT qualify:**
- An AD administrator deliberately misconfigures a certificate template — this is an admin action, not a vulnerability
- Attacks that require Domain Admin already to execute

### Kerberos Protocol vs. Windows Implementation Bugs

These are fundamentally different in scope:

| Bug Type | Scope | MSRC Handling |
|----------|-------|---------------|
| **Kerberos protocol-level flaw** | Affects all Kerberos implementations (MIT Kerberos, Heimdal, Windows) | Windows-specific report goes to MSRC; protocol flaw may need broader disclosure via CERT/CC |
| **Windows Kerberos implementation bug** | Only Windows KDC or Windows Kerberos client | Pure MSRC submission; treated as standard Windows vulnerability |
| **Active Directory-specific Kerberos feature abuse** | RBCD, delegation misconfiguration, S4U abuse | AD team at MSRC; often treated as design choice unless clearly unintended behavior |

When submitting, be explicit: "This is a Windows Kerberos client implementation issue affecting `kerberos.dll` version X" vs. "This is an Active Directory feature that can be abused due to default ACL configuration."

### Domain Controller vs. Workstation Vulnerabilities

**Impact assessment differs significantly:**

A vulnerability that only works against a domain controller carries lower impact in MSRC's view *if it requires domain admin to trigger*, because domain admins are already trusted at that level.

A vulnerability that allows a standard workstation user to compromise a domain controller without admin privileges is extremely high severity — this crosses multiple security boundaries simultaneously (User → Admin, potentially Network → DC).

**What to document for DC vulnerabilities:**
- Clarify the required starting privilege level precisely
- State whether the attack works from a domain-joined workstation with standard credentials
- State whether it requires a DC-local session or is network-reachable
- Document the impact on the entire domain (DC compromise = full domain compromise)

---

## 11. Building a Research Reputation

### MSRC Acknowledgments

- Every qualifying CVE earns an MSRC acknowledgment
- Listed at: https://msrc.microsoft.com/update-guide/acknowledgement
- Visible per-month and per-researcher; industry-standard credential
- **CVE count vs. quality:** The acknowledgment page is searchable by researcher name. One Critical severity CVE (e.g., Hyper-V escape, RCE in widely-deployed service) carries more weight than ten Low-severity information disclosures. Prioritize finding impactful bugs over volume.

### Conference Presentations

Presenting your research at conferences dramatically multiplies its reach and establishes your name in the community:

| Conference | Prestige Level | Notes |
|------------|----------------|-------|
| **BlueHat** (Microsoft) | Very high — directly in front of MSRC/product teams | Microsoft pays travel and accommodation for speakers; invite-only / selected CFP; disclosed bugs only |
| **OffensiveCon** (Berlin) | High — technical offense-focused; peer respect | Prestige in the offensive research community; strong technical bar |
| **Black Hat USA** | Very high — wide industry and press coverage | Reviewed CFP; must submit 3 months ahead; career-defining for major research |
| **DEF CON** | Very high — widest reach, most public visibility | Open CFP; recordings archived permanently on YouTube |
| **Hardwear.io** | Medium-high — hardware + software intersection | Good for kernel/driver/hardware-adjacent research |

**Timing:** You can present before or after patch release:
- **Before patch (coordinated):** Requires MSRC coordination. Present the bug class and technique without a working PoC. "Research in progress" talks are acceptable if the mechanism is novel.
- **After patch:** Present full technical details including PoC. Most common format. Allows attendees to learn and researchers to reproduce.

### Writing Post-Patch Content

**Post-patch analysis post** (most common format):
- Start with a one-paragraph summary of the vulnerability for non-technical readers
- Technical sections: root cause analysis, affected code path (with pseudocode or decompiled snippets), exploitation technique, CVSS justification
- Include ProcMon screenshots, WinDbg output, and PoC walkthrough
- **What to withhold even post-patch:** Specific bypasses of any compensating controls that a defender might be relying on; exact NTFS tricks that work on unpatched versions that haven't been superseded by newer techniques

**Disclosure post vs. analysis post:**
- A *disclosure post* announces the CVE and patches — short, factual, published same day as Patch Tuesday
- An *analysis post* explains the internals, exploitation path, and lessons — published 1–2 weeks after Patch Tuesday when community has had time to patch

### GitHub Repo Strategy

The standard package that circulates widely:
```
your-cve-repo/
├── README.md          -- Overview, CVE number, affected versions, patch date
├── writeup/
│   └── analysis.md   -- Full technical writeup
├── poc/
│   ├── Exploit.c     -- Minimal PoC, well-commented
│   └── Makefile
└── references/       -- ProcMon captures, WinDbg output, screenshots
```

**Timing:** Publish PoC code *after* the patch is live. Publishing before the patch is irresponsible unless disclosure has expired with no vendor action.

**What to comment in PoC code:** Every non-obvious step should have a comment explaining the *why* — not just what the code does, but what Windows behavior it is triggering and why that behavior leads to the primitive you're building.

### Engaging with the Community

- **Twitter/X security community:** Post when your patch ships ("CVE-2024-XXXXX patched today — writeup coming next week"). Tag @msftsecurity and use `#PatchTuesday`. This creates a public record and attracts attention.
- **Responding to researchers who reproduce your work:** When someone posts "reproduced CVE-XXXXX by [you]," acknowledge it. These interactions build relationships that lead to collaboration, co-publications, and peer review of future research.
- **Cross-linking:** If your technique builds on prior work (e.g., uses the oplock/junction pattern from Forshaw's research), cite it. The community remembers researchers who give credit generously.
- **Engage on technical disagreements:** If another researcher claims your bug doesn't work or is misclassified, engage technically and publicly. Being able to defend your analysis improves credibility more than avoiding controversy.

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
- Will Schroeder / harmj0y (blog.harmj0y.net) — AD and Kerberos research with thorough protocol-level explanation

---

## References

- [R-1] MSRC Submission Portal — Microsoft — https://msrc.microsoft.com/report/vulnerability
- [R-2] Windows Security Servicing Criteria — Microsoft — https://learn.microsoft.com/en-us/windows/security/security-servicing-criteria
- [R-3] MSRC Bug Bounty Programs — Microsoft — https://www.microsoft.com/en-us/msrc/bounty
- [R-4] ZDI Submission — Trend Micro ZDI — https://www.zerodayinitiative.com/
- [R-5] CVSS v3.1 Calculator — FIRST — https://www.first.org/cvss/calculator/3.1
- [R-6] Project Zero Disclosure Policy — Google — https://googleprojectzero.blogspot.com/p/vulnerability-disclosure-policy.html
- [R-7] MSRC Acknowledgments — Microsoft — https://msrc.microsoft.com/update-guide/acknowledgement
- [R-8] MSRC Severity Classification — Microsoft — https://msrc.microsoft.com/blog/2022/05/microsoft-vulnerability-severity-classification/
- [R-9] NVD CVE Search — NIST — https://nvd.nist.gov/vuln/search
- [R-10] SpecterOps ADCS Research (ESC1-ESC8) — Will Schroeder / Andy Robbins — https://posts.specterops.io/certified-pre-owned-d95910965cd2
