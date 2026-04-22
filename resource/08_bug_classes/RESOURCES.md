# 08 · Bug Classes — RESOURCES.md

> **Section purpose:** Catalog the canonical bug classes that drive Windows Local Privilege Escalation (LPE) and lateral-movement research. Every entry below is a primary source, reference implementation, or seminal case study. Read in the order given within each sub-section to build compounding context.

---

## Table of Contents

1. [Arbitrary File Write / Move / Delete](#1-arbitrary-file-write--move--delete)
2. [Junction / Symlink / Mount Point / Hard Link Abuse](#2-junction--symlink--mount-point--hard-link-abuse)
3. [Token Impersonation / SeImpersonate Abuse](#3-token-impersonation--seimpersonate-abuse)
4. [Named Pipe / RPC / COM Abuse](#4-named-pipe--rpc--com-abuse)
5. [Windows Installer / Updater / Repair Flows](#5-windows-installer--updater--repair-flows)
6. [Object Manager Namespace Abuse](#6-object-manager-namespace-abuse)

---

## 1. Arbitrary File Write / Move / Delete

---

### Entry 1.1

- **Title:** Windows Exploitation Tricks: Exploiting Arbitrary File Writes for Local Elevation of Privilege
- **Author / Organization:** James Forshaw / Google Project Zero
- **URL:** https://googleprojectzero.blogspot.com/2018/04/windows-exploitation-tricks-exploiting.html
- **Resource type:** Blog post / technical deep-dive
- **Topic tags:** `arbitrary-file-write` `LPE` `NTFS` `symbolic-links` `junction` `token-impersonation` `Windows-exploitation-tricks`
- **Difficulty:** Intermediate–Advanced
- **Historical or current:** Current (techniques still applicable as of Windows 11 / Server 2022)
- **Trust level:** ⭐⭐⭐⭐⭐ — Google Project Zero primary source; peer-reviewed by publication standards
- **Why it matters:** This post established the *canonical exploitation chain* for arbitrary file write primitives on Windows. Before this, researchers knew that writing to arbitrary paths was "bad," but this post showed exactly how to turn a write-anywhere into SYSTEM via DLL planting into a privileged service repair/update path.
- **What it teaches:**
  - How to convert an arbitrary file write into a DLL hijack that runs as SYSTEM
  - Using `NtSetInformationFile` rename (FileRenameInformation) as a file-move primitive
  - Oplock (opportunistic lock) + junction trick to win TOCTOU races
  - The concept of "planting" into `%SystemRoot%\System32` or per-user installer paths
  - Why `SeImpersonatePrivilege` is a secondary escalation path
- **Best use:** Read first before any LPE CVE writeup involving "arbitrary write." This defines the vocabulary every later researcher borrows.
- **Related bug classes / primitives:** Arbitrary File Move, DLL Hijacking, Junction Abuse, Oplock + TOCTOU, Windows Installer repair
- **Suggested next resource:** Entry 1.2 (directory creation to file read), then Entry 2.1 (symboliclink-testing-tools)
- **Notes:** The `BaitAndSwitch` technique (oplock + junction) described here became the reference primitive for dozens of CVEs. Lab it with Entry 2.1.

---

### Entry 1.2

- **Title:** Windows Exploitation Tricks: Arbitrary Directory Creation to Arbitrary File Read
- **Author / Organization:** James Forshaw / Google Project Zero
- **URL:** https://googleprojectzero.blogspot.com/2017/08/windows-exploitation-tricks-arbitrary.html
- **Resource type:** Blog post / technical deep-dive
- **Topic tags:** `arbitrary-directory-creation` `arbitrary-file-read` `NTFS` `junctions` `LPE` `Windows-exploitation-tricks`
- **Difficulty:** Intermediate
- **Historical or current:** Current
- **Trust level:** ⭐⭐⭐⭐⭐ — Project Zero primary source
- **Why it matters:** Shows that the ability to create a directory at an arbitrary path — often considered low-severity — can be upgraded to an arbitrary file read, leading to credential theft or further escalation. Establishes the pattern of chaining low-severity primitives.
- **What it teaches:**
  - How to use a directory creation bug to set up a mount point that redirects later file opens
  - NTFS junction semantics under the kernel vs. Win32 layer
  - The distinction between object-directory junctions (`\RPC Control`) and filesystem junctions
  - How an arbitrary read can leak SAM, SYSTEM hive, or sensitive config files
- **Best use:** Read after Entry 1.1. The two posts form a matched pair covering the write/read sides of the arbitrary filesystem operation family.
- **Related bug classes / primitives:** Mount point abuse, Arbitrary File Read, SAM dump, NTFS reparse points
- **Suggested next resource:** Entry 2.1 (symbolic link testing tools) to replicate these attacks in a lab
- **Notes:** Many "arbitrary folder creation" bugs were re-rated as High/Critical after this post. A must-read for anyone doing triage.

---

### Entry 1.3

- **Title:** Dropbox Arbitrary File Move LPE (CVE writeup)
- **Author / Organization:** itm4n (Clément Labro)
- **URL:** https://itm4n.github.io/dropbox-lpe/
- **Resource type:** Blog post / CVE walkthrough
- **Topic tags:** `arbitrary-file-move` `LPE` `third-party-software` `Windows-service` `DLL-hijacking` `real-world-CVE`
- **Difficulty:** Intermediate
- **Historical or current:** Historical (specific to Dropbox version at time of research, but technique is evergreen)
- **Trust level:** ⭐⭐⭐⭐⭐ — itm4n is a top-tier Windows LPE researcher; CVD-verified
- **Why it matters:** Demonstrates the complete end-to-end exploitation of an arbitrary file move in a real, widely-deployed application. Bridges the gap between theoretical primitives (Entry 1.1) and practical exploitation of third-party installers/services.
- **What it teaches:**
  - How to identify file move operations in privileged service code
  - Using Process Monitor to locate vulnerable move operations
  - Constructing junction/symlink chains to redirect the privileged move
  - Post-exploitation path from DLL side-load to SYSTEM shell
- **Best use:** Read after Entries 1.1–1.2. Use as a template for auditing other third-party applications with privileged update/cleanup services.
- **Related bug classes / primitives:** Arbitrary File Move, DLL Hijacking, Junction Abuse, Windows Service Security
- **Suggested next resource:** Entry 1.4 for a delete variant; then Entry 3.13 (PrintSpoofer) for an independent escalation path
- **Notes:** itm4n's blog (https://itm4n.github.io/) is generally essential reading — check all posts.

---

### Entry 1.4

- **Title:** CVE-2022-21838 — Windows Cleanup Manager Arbitrary File Delete
- **Author / Organization:** Various (publicly disclosed via MSRC / researcher writeups)
- **URL:** https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-21838 *(primary)* — search "CVE-2022-21838 writeup" for researcher analysis
- **Resource type:** CVE advisory + community writeups
- **Topic tags:** `arbitrary-file-delete` `LPE` `Windows-Cleanup-Manager` `Disk-Cleanup` `CVE-2022-21838`
- **Difficulty:** Intermediate
- **Historical or current:** Historical (patched); technique class remains active
- **Trust level:** ⭐⭐⭐⭐ — MSRC-confirmed; researcher writeups vary in depth
- **Why it matters:** Illustrates the "arbitrary file delete → LPE" chain, the third member of the arbitrary filesystem primitive family (write/move/delete). Disk Cleanup runs as SYSTEM and processes attacker-influenced paths. Deleting a DLL from a trusted path can trigger DLL load from a user-controlled fallback.
- **What it teaches:**
  - How privilege escalation can occur through deletion, not just write or move
  - The `DiagTrack` / Disk Cleanup privileged cleanup service attack surface
  - DLL search order hijacking via deletion of a higher-priority DLL
  - How to find similar patterns: look for privileged cleanup services that traverse user-writable paths
- **Best use:** Use alongside Entry 1.1 to build a complete mental model of the three filesystem primitive classes. Also compare to the "diagHub" DLL planting class.
- **Related bug classes / primitives:** Arbitrary File Delete, DLL Search Order Hijacking, Arbitrary File Write (complementary)
- **Suggested next resource:** Entry 2.1 (symboliclink-testing-tools) for lab reproduction; Entry 5.1 for installer-class bugs
- **Notes:** The Disk Cleanup / cleanmgr attack surface has produced multiple CVEs; search for "cleanmgr LPE" for the full history.

---

## 2. Junction / Symlink / Mount Point / Hard Link Abuse

---

### Entry 2.1

- **Title:** Symbolic Link Testing Tools (symboliclink-testing-tools)
- **Author / Organization:** James Forshaw / Google Project Zero
- **URL:** https://github.com/googleprojectzero/symboliclink-testing-tools
- **Resource type:** Open-source tool suite / lab framework
- **Topic tags:** `symbolic-links` `junctions` `mount-points` `hard-links` `NTFS` `object-manager` `oplock` `TOCTOU` `lab-tools`
- **Difficulty:** Intermediate (to use); Advanced (to read source)
- **Historical or current:** Current (actively maintained, used in modern research)
- **Trust level:** ⭐⭐⭐⭐⭐ — Google Project Zero; the de facto standard lab toolkit for this class
- **Why it matters:** This repository IS the lab environment for symbolic link, junction, mount point, and hard link exploitation on Windows. Every serious LPE researcher has this cloned. Contains `CreateSymlink`, `NtApiDotNet` usage examples, `BaitAndSwitch`, `SetOpLock`, and more. Understanding the tools = understanding the attacks.
- **What it teaches:**
  - How to create kernel-level symbolic links (object manager namespace) vs. Win32 symlinks
  - The difference between NTFS junctions, directory symlinks, file symlinks, and hard links
  - How to set an oplock on a file and trigger a junction swap before the privileged process continues
  - The `\RPC Control` object directory trick for named pipe squatting
  - How to redirect `NtCreateFile` calls through the object manager
- **Best use:** Clone this repository and run every tool with `Process Monitor` capturing. Read the source of each tool alongside the corresponding Project Zero blog post.
- **Related bug classes / primitives:** Arbitrary File Write/Move/Delete, TOCTOU, Object Manager Namespace, Named Pipe Squatting
- **Suggested next resource:** Entry 2.2 (Forshaw's blog for theoretical grounding); Entry 6.1 (BaitAndSwitch description)
- **Notes:** The `CreateMountPoint`, `CreateDosDeviceSymlink`, `NtCreateSymbolicLinkObject` utilities in this repo expose primitives that are intentionally hard to use from Win32. Required reading for the source.

---

### Entry 2.2

- **Title:** Abusing Windows Symbolic Links — Tyranid's Lair (James Forshaw's blog)
- **Author / Organization:** James Forshaw (tyranid) / Google Project Zero
- **URL:** https://www.tiraniddo.dev/
- **Resource type:** Blog (multiple posts; search "symbolic link" and "mount point")
- **Topic tags:** `symbolic-links` `mount-points` `junctions` `object-manager` `Windows-internals` `LPE`
- **Difficulty:** Advanced
- **Historical or current:** Current (posts span 2015–2024)
- **Trust level:** ⭐⭐⭐⭐⭐ — Forshaw is the primary researcher in this space; posts are authoritative
- **Why it matters:** Forshaw's blog is the primary literature for Windows symbolic link abuse. Individual posts include: "Symlink Testing Tools," "Windows Exploitation Tricks" series, COM security, ALPC, and more. No other single source covers this ground as thoroughly.
- **What it teaches:**
  - Full taxonomy of Windows link types: NTFS symlinks, junctions, object manager symlinks, hardlinks, bind mounts
  - Security boundary differences between each link type
  - How NT object manager resolves names through the namespace hierarchy
  - Practical techniques used in real CVEs (with PoC references)
- **Best use:** Bookmark and search by tag. Read the "Windows Symlinks Revisited" and "Exploiting Symbolic Links" posts first. Return to specific posts as you encounter related CVEs.
- **Related bug classes / primitives:** All junction/symlink/mount primitives; Object Manager Namespace; File System Redirector
- **Suggested next resource:** Entry 2.1 (lab tools), Entry 6.1 (BaitAndSwitch in detail)
- **Notes:** Blog posts may require cross-referencing with NtApiDotNet source for full understanding. Forshaw regularly presents at OffensiveCon, CanSecWest, and Black Hat — slide decks complement the blog.

---

### Entry 2.3

- **Title:** Mount Point Abuse and Junction Exploits — CVE Case Studies
- **Author / Organization:** Various researchers (itm4n, tyranid, SandboxEscaper, NSFOCUS, etc.)
- **URL:** Search: site:itm4n.github.io junction OR mount-point; site:googleprojectzero.blogspot.com mount
- **Resource type:** Collection of CVE writeups / blog posts
- **Topic tags:** `mount-point` `junction` `LPE` `CVE-collection` `real-world-bugs`
- **Difficulty:** Intermediate–Advanced
- **Historical or current:** Mix (specific CVEs are historical; technique is current)
- **Trust level:** ⭐⭐⭐⭐ — varies by author; cross-reference MSRC advisories
- **Why it matters:** Theory without cases is incomplete. This category of resource shows mount point / junction bugs in real Windows components: Task Scheduler, Windows Update, Windows Installer, Defender, etc. Builds pattern-matching ability for finding new bugs.
- **What it teaches:**
  - How to spot junction-vulnerable code patterns in source or binaries
  - The role of impersonation (or lack thereof) in privileged file operations
  - How SYSTEM-level services fail to validate that paths haven't been redirected
  - Common mitigations: `FILE_FLAG_OPEN_REPARSE_POINT`, `FILE_FLAG_NO_RECALL`, security descriptor checks
- **Best use:** After reading Entries 2.1–2.2, enumerate CVEs in this space (NVD: search "Windows junction symbolic" + severity High/Critical). Read 3–5 detailed writeups.
- **Related bug classes / primitives:** Arbitrary File Write/Move/Delete, TOCTOU, Windows Service Security
- **Suggested next resource:** Entry 1.1 for the exploitation chain; Entry 5.1 for installer-specific cases
- **Notes:** SandboxEscaper (2018–2019) published several junction-based LPEs that were dropped as 0-days — read these for adversarial pattern recognition despite their controversial disclosure context.

---

### Entry 2.4

- **Title:** Windows Hard Links — NTFS Hard Link Security Implications
- **Author / Organization:** James Forshaw / NtfsCreate research / multiple sources
- **URL:** https://www.tiraniddo.dev/ (search "hard link") + https://github.com/googleprojectzero/symboliclink-testing-tools (CreateHardLink utility)
- **Resource type:** Blog posts + tool source
- **Topic tags:** `hard-links` `NTFS` `LPE` `file-security` `Windows-internals`
- **Difficulty:** Intermediate
- **Historical or current:** Current
- **Trust level:** ⭐⭐⭐⭐⭐
- **Why it matters:** Hard links are the least-understood member of the Windows link family. Unlike junctions/symlinks, hard links bypass certain security checks because they point directly to the MFT record. This creates bugs where a low-privilege user can cause a privileged process to operate on an unintended file.
- **What it teaches:**
  - NTFS MFT structure and how hard links share inode entries
  - The `CreateHardLink` Win32 API vs. `NtSetInformationFile(FileHardLinkInformation)` difference
  - Why hard links can cross security boundary in specific scenarios (e.g., world-writable directories with wrong ACL inheritance)
  - `NtfsCreate` (kernel) hard link creation path and security checks
  - CVE examples: Windows CNG hard link bugs, DLL hijacking via hard link to writable DLL
- **Best use:** Read in parallel with junction/symlink material. Use CreateHardLink from symboliclink-testing-tools to experiment.
- **Related bug classes / primitives:** NTFS Junctions, Arbitrary File Write, DLL Hijacking
- **Suggested next resource:** Entry 6.2 (NTFS internals deep dive)
- **Notes:** Hard links cannot cross volumes; this constrains their use but they remain exploitable within the same volume. The `FILE_FLAG_OPEN_REPARSE_POINT` defense does NOT protect against hard links.

---

## 3. Token Impersonation / SeImpersonate Abuse

---

### Entry 3.1

- **Title:** Rotten Potato — Privilege Escalation from Service Accounts to SYSTEM
- **Author / Organization:** foxglovesecurity (Stephen Breen, Chris Mallz)
- **URL:** https://foxglovesecurity.com/2016/09/26/rotten-potato-privilege-escalation-from-service-accounts-to-system/
- **Resource type:** Blog post / original research
- **Topic tags:** `token-impersonation` `SeImpersonatePrivilege` `DCOM` `NTLM-relay` `LPE` `service-accounts` `historical`
- **Difficulty:** Intermediate
- **Historical or current:** Historical (technique patched/evolved; foundational concept remains)
- **Trust level:** ⭐⭐⭐⭐⭐ — Original disclosure; widely cited and validated
- **Why it matters:** Rotten Potato was the first publicly documented technique for reliably escalating from a service account with `SeImpersonatePrivilege` (IIS, SQL Server, etc.) to SYSTEM. It triggered an entire lineage of research (Juicy, Sweet, Rogue, God, Local Potato) and changed how defenders think about service account privileges.
- **What it teaches:**
  - What `SeImpersonatePrivilege` allows and why it is granted to service accounts
  - The DCOM activation mechanism and how to trigger SYSTEM DCOM calls
  - NTLM relay via loopback to capture and impersonate the SYSTEM token
  - The `ImpersonateNamedPipeClient` API and how it grants token access
  - Why `Network Service` and `Local Service` are not equivalent to limited accounts from an exploitation standpoint
- **Best use:** Read as the origin story before studying the modern variants. Understand *why* each subsequent "Potato" variant was created — usually to bypass a specific mitigation.
- **Related bug classes / primitives:** Token Impersonation, NTLM Relay, DCOM, Named Pipes, SeImpersonatePrivilege
- **Suggested next resource:** Entry 3.2 (Juicy Potato for extended CLSID list), then Entry 3.5 (PrintSpoofer for the pipe-based evolution)
- **Notes:** The term "Potato exploit" became generic slang for any SeImpersonate-to-SYSTEM chain. The DCOM component (port 135) was later restricted in some configurations, motivating the evolution.

---

### Entry 3.2

- **Title:** Juicy Potato — Extended CLSID-based Token Impersonation
- **Author / Organization:** ohpe.it (Andrea Pierini, Giuseppe Trotta)
- **URL:** https://ohpe.it/juicy-potato/
- **Resource type:** Research post + tool release
- **Topic tags:** `token-impersonation` `SeImpersonatePrivilege` `DCOM` `CLSID` `LPE` `historical`
- **Difficulty:** Intermediate
- **Historical or current:** Historical (non-functional on Windows 10 1809+ / Server 2019+ without modifications)
- **Trust level:** ⭐⭐⭐⭐⭐ — Widely used, reproduced, and documented
- **Why it matters:** Juicy Potato extended Rotten Potato by providing a comprehensive list of exploitable DCOM CLSIDs and a standalone tool. Made SeImpersonate exploitation trivially automated on Windows Server 2016 and earlier. The extensive CLSID database became a research resource in its own right.
- **What it teaches:**
  - How to enumerate exploitable DCOM CLSIDs programmatically
  - The relationship between COM activation ports and token capture
  - Why not all DCOM activations are equal — only those that activate as SYSTEM are useful
  - Tool architecture: the custom COM server, pipe listener, and token impersonation sequence
- **Best use:** Run in a lab on a Windows Server 2016 or earlier VM to understand the complete flow. Study the CLSID list — it teaches you what COM classes run as elevated principals.
- **Related bug classes / primitives:** Token Impersonation, DCOM, NTLM Relay, COM Security
- **Suggested next resource:** Entry 3.3 (Sweet Potato) for the evolution, or Entry 3.5 (PrintSpoofer) for the alternative named-pipe branch
- **Notes:** Broken on Windows 10 1809+ due to DCOM hardening. This is intentional — understanding *why* it broke teaches you the mitigations that motivated subsequent research.

---

### Entry 3.3

- **Title:** SweetPotato — Combined Privilege Escalation Techniques
- **Author / Organization:** ElevenPaths / CCob (Charlie Clark)
- **URL:** https://github.com/CCob/SweetPotato
- **Resource type:** Open-source tool + documentation
- **Topic tags:** `token-impersonation` `SeImpersonatePrivilege` `DCOM` `named-pipes` `WebClient` `LPE`
- **Difficulty:** Intermediate
- **Historical or current:** Current
- **Trust level:** ⭐⭐⭐⭐ — Active repository; documented but less formal writeup than some others
- **Why it matters:** SweetPotato consolidates multiple impersonation techniques (EfsRpc, WebClient, PrintSpoofer-style named pipe) into one tool. It represents the state of the art for SeImpersonate exploitation on Windows 10/Server 2019 after Juicy Potato's mitigations.
- **What it teaches:**
  - How to use `EfsRpcOpenFileRaw` (EFSRPC) to trigger an authentication from SYSTEM to an attacker-controlled named pipe
  - The WebClient (WebDAV) trick: convincing SYSTEM to authenticate over HTTP to a local listener
  - Combining multiple coercion methods to handle diverse Windows configurations
  - Token duplication after impersonation for a stable SYSTEM token
- **Best use:** Read the source and README after understanding Rotten/Juicy Potato. The code structure shows how each technique branches — educational for understanding the design space.
- **Related bug classes / primitives:** Token Impersonation, Named Pipe Impersonation, EFSRPC Coercion, WebClient Abuse
- **Suggested next resource:** Entry 3.4 (RoguePotato for the OXID resolver trick), Entry 3.5 (PrintSpoofer)
- **Notes:** Best used with `SeImpersonatePrivilege` confirmed on target. Check `whoami /priv` first. Some EDRs now flag SweetPotato binary signatures — relevant for red team use.

---

### Entry 3.4

- **Title:** RoguePotato — No More JuicyPotato
- **Author / Organization:** Decoder.cloud (Antonio Cocomazzi / splinter_code)
- **URL:** https://decoder.cloud/2020/05/11/no-more-juicypotato-old-story-welcome-roguepotato/
- **Resource type:** Blog post / tool release
- **Topic tags:** `token-impersonation` `SeImpersonatePrivilege` `DCOM` `OXID-resolver` `named-pipes` `LPE` `Windows-10`
- **Difficulty:** Intermediate–Advanced
- **Historical or current:** Current (works on Windows 10 / Server 2019)
- **Trust level:** ⭐⭐⭐⭐⭐ — Decoder.cloud is a high-quality research blog; technique independently verified
- **Why it matters:** After Juicy Potato stopped working, RoguePotato was the first demonstrated replacement. It replaced the DCOM port trick with a custom OXID resolver on a remote machine, bypassing the loopback DCOM restriction. Bridged the gap to Windows 10 / Server 2019 targets.
- **What it teaches:**
  - The DCOM OXID resolver and how a remote OXID resolver can redirect activation requests
  - Why the loopback restriction in Windows 10 1809+ blocked Juicy Potato
  - The role of a helper machine (or redirector) in the RoguePotato chain
  - Named pipe impersonation as the final step after token coercion
- **Best use:** Study after fully understanding Juicy Potato. Map the architectural differences — this teaches the mitigation/bypass cycle clearly.
- **Related bug classes / primitives:** Token Impersonation, DCOM OXID Resolver, Named Pipes, NTLM Relay
- **Suggested next resource:** Entry 3.5 (PrintSpoofer — alternative that avoids DCOM entirely)
- **Notes:** Requires a separate machine or redirector for the OXID resolver in some configurations. PrintSpoofer (Entry 3.5) became more popular for single-machine scenarios.

---

### Entry 3.5

- **Title:** PrintSpoofer — Abusing Impersonation Privileges on Windows 10 and Server 2019
- **Author / Organization:** itm4n (Clément Labro)
- **URL:** https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/
- **Resource type:** Blog post / tool release
- **Topic tags:** `token-impersonation` `SeImpersonatePrivilege` `named-pipes` `Print-Spooler` `LPE` `Windows-10` `MUST-READ`
- **Difficulty:** Intermediate
- **Historical or current:** Current
- **Trust level:** ⭐⭐⭐⭐⭐ — itm4n primary research; independently reproduced extensively
- **Why it matters:** PrintSpoofer cracked the problem of SeImpersonate-to-SYSTEM on Windows 10/Server 2019 without needing a second machine. It uses the Print Spooler service's pipe connection mechanism — available from any process with SeImpersonate — to receive a SYSTEM token. Became the dominant technique in its class.
- **What it teaches:**
  - How the Print Spooler creates named pipe connections back to callers via `OpenPrinter`
  - The `\pipe\spoolss` pipe and how to create a fake server that intercepts the spooler's connection
  - The exact sequence: create pipe → call `OpenPrinter` → spooler connects → `ImpersonateNamedPipeClient` → duplicate token
  - Why this bypasses the DCOM loopback restrictions that broke Juicy Potato
  - How to identify similar "privileged service connects to attacker-controlled pipe" patterns
- **Best use:** Read the blog carefully, then run the tool in a lab. Read the source code to understand the pipe creation and impersonation sequence at the API level.
- **Related bug classes / primitives:** Named Pipe Impersonation, Token Duplication, SeImpersonatePrivilege, Print Spooler Attack Surface
- **Suggested next resource:** Entry 3.6 (GodPotato for the latest evolution), Entry 4.1 (named pipe internals)
- **Notes:** The Print Spooler service has been the source of multiple critical bugs (PrintNightmare CVE-2021-1675/34527). The `Stop-Service Spooler` mitigation breaks this technique but causes other issues. Monitor for this.

---

### Entry 3.6

- **Title:** GodPotato — Universal Potato via ImpersonateNamedPipeClient
- **Author / Organization:** BeichenDream
- **URL:** https://github.com/BeichenDream/GodPotato
- **Resource type:** Open-source tool + README
- **Topic tags:** `token-impersonation` `SeImpersonatePrivilege` `named-pipes` `ITaskSchedulerService` `LPE` `Windows-2012-2022`
- **Difficulty:** Intermediate
- **Historical or current:** Current (supports Windows Server 2012 – 2022)
- **Trust level:** ⭐⭐⭐⭐ — Widely deployed and tested; less formal write-up than itm4n/decoder work
- **Why it matters:** GodPotato extends the Potato lineage to cover Windows Server 2012–2022 via the Task Scheduler RPC interface (`ITaskSchedulerService`), which reliably triggers a SYSTEM authentication to an attacker-controlled named pipe. Practical breadth across versions makes it the most versatile potato variant currently.
- **What it teaches:**
  - How `ITaskSchedulerService` can be abused as a SYSTEM authentication coercion source
  - The pattern of searching RPC interfaces for methods that trigger SYSTEM-level authentication
  - Cross-version compatibility considerations for impersonation exploits
- **Best use:** Use as a reference for the current "best of breed" SeImpersonate tool. Study how the RPC interface coercion differs from PrintSpoofer's pipe-based approach.
- **Related bug classes / primitives:** Token Impersonation, RPC Coercion, Task Scheduler Security, Named Pipes
- **Suggested next resource:** Entry 3.7 (LocalPotato for a distinct local NTLM relay variant)
- **Notes:** Detection: named pipe creation from low-privilege processes followed by token impersonation is a strong indicator. See Elastic, Splunk detection rules for "potato exploit."

---

### Entry 3.7

- **Title:** LocalPotato — Local NTLM Reflection Privilege Escalation
- **Author / Organization:** Decoder.cloud (Antonio Cocomazzi)
- **URL:** https://www.decoder.cloud/2023/02/15/local-potato/
- **Resource type:** Blog post / tool release
- **Topic tags:** `NTLM-reflection` `local-NTLM-relay` `token-impersonation` `LPE` `SeImpersonatePrivilege` `Windows-NTLM`
- **Difficulty:** Advanced
- **Historical or current:** Current (2023)
- **Trust level:** ⭐⭐⭐⭐⭐ — Decoder.cloud primary research; CVE-2023-21746 confirmed
- **Why it matters:** LocalPotato exploits local NTLM reflection (a variant of NTLM relay) entirely on the local machine without network access or a helper system. This bypasses mitigations that target remote NTLM relay (EPA, SMB signing) and represents a distinct research lineage from the printer/pipe-based potatos.
- **What it teaches:**
  - How NTLM authentication works at the SSPI/NTLM SSP level
  - Why local NTLM relay/reflection was thought to be mitigated and why it was not
  - The `AcceptSecurityContext` / `InitializeSecurityContext` exchange at the API level
  - How to construct a local NTLM relay chain to impersonate the SYSTEM security context
  - CVE-2023-21746 root cause analysis
- **Best use:** Read after fully understanding basic token impersonation (Entries 3.1–3.6). This requires NTLM protocol knowledge — have Windows Internals and the NTLM spec handy.
- **Related bug classes / primitives:** NTLM Relay, Token Impersonation, SSPI, Local Authentication
- **Suggested next resource:** NTLM relay documentation (impacket NTLM relay source); Entry 5.2 (ALPC — RPC section for protocol-level follow-up)
- **Notes:** Patched in January 2023 Patch Tuesday. The blog post is detailed enough to reconstruct the PoC. Study the patch diff to understand the mitigation.

---

## 4. Named Pipe / RPC / COM Abuse

---

### Entry 4.1

- **Title:** Windows Installer Privilege Escalation via Named Pipe Impersonation
- **Author / Organization:** Multiple researchers (itm4n, james forshaw, various CVE disclosures)
- **URL:** https://itm4n.github.io/ (search "named pipe") + https://www.tiraniddo.dev/ (search "named pipe")
- **Resource type:** Blog posts / CVE collection
- **Topic tags:** `named-pipes` `token-impersonation` `Windows-Installer` `LPE` `IPC`
- **Difficulty:** Intermediate
- **Historical or current:** Current
- **Trust level:** ⭐⭐⭐⭐⭐
- **Why it matters:** Named pipe impersonation is the underlying mechanism of most Potato exploits and many standalone LPEs. Understanding it at the API level (CreateNamedPipe, ConnectNamedPipe, ImpersonateNamedPipeClient) is foundational for auditing any privileged service that uses named pipes for IPC.
- **What it teaches:**
  - Named pipe security descriptor semantics — who can connect
  - `ImpersonateNamedPipeClient` API and when it succeeds
  - Squatting attacks: creating a pipe before a privileged service creates its own
  - The `\RPC Control\` object directory trick for redirecting pipe connections
  - Windows Installer's use of named pipes and historical squatting CVEs
- **Best use:** After reading PrintSpoofer (Entry 3.5), return to first principles with this resource. Enumerate named pipes on a live system with `pipelist.exe` or `Get-ChildItem \\.\pipe\`.
- **Related bug classes / primitives:** Token Impersonation, Potato Family, COM Security, RPC Transport
- **Suggested next resource:** Entry 4.3 (COM Elevation Moniker for COM-specific privilege abuse)
- **Notes:** `pipelist` from Sysinternals and `NtObjectManager` (PowerShell module from Forshaw) are essential tools for pipe enumeration and analysis.

---

### Entry 4.2

- **Title:** Win32k NULL Page Dereference and Kernel Bug Classes (Historical Reference)
- **Author / Organization:** Multiple researchers (VUPEN, MWR Labs, Exodus, Project Zero)
- **URL:** https://googleprojectzero.blogspot.com/ (search "win32k") + https://conference.hitb.org/hitbsecconf2014kul/materials/
- **Resource type:** Research papers / blog posts collection
- **Topic tags:** `Win32k` `kernel-LPE` `NULL-dereference` `pool-corruption` `GDI-objects` `historical`
- **Difficulty:** Advanced
- **Historical or current:** Historical (Win32k isolation / HVCI mitigations reduced impact significantly)
- **Trust level:** ⭐⭐⭐⭐ — Academic and practitioner papers; some dated
- **Why it matters:** Win32k was the most prolific source of Windows kernel LPE bugs for a decade (2010–2020). Understanding this history illuminates why Microsoft introduced Win32k lockdown in AppContainer (IE), GDI object handle table changes, and HVCI. The techniques (type confusion, pool overflow, UAF in GDI objects) recur in other subsystems.
- **What it teaches:**
  - GDI object handle table layout and how bitmaps/palettes were used as R/W primitives
  - The "HMValidateHandle" kernel-to-userland pointer leak pattern
  - Pool spray techniques for Win32k pool objects
  - Why the `NtUserSetWindowLongPtr` / `tagWND` chain became a canonical kernel R/W primitive
  - The evolution of Win32k mitigations and their impact
- **Best use:** Historical reference. Read for conceptual grounding before studying modern kernel attack surfaces. Useful for understanding why current mitigations exist.
- **Related bug classes / primitives:** Kernel Pool Corruption, UAF, Type Confusion, GDI Object Abuse
- **Suggested next resource:** Modern Win32k research (Project Zero 2020+), HVCI documentation
- **Notes:** Win32k syscall filtering (available since Windows 8 for sandboxed processes) is the primary mitigation. Kernel pool isolation (Windows 10 20H1+) also significantly raised the bar.

---

### Entry 4.3

- **Title:** COM Elevation Moniker — Bypassing UAC via COM
- **Author / Organization:** James Forshaw / Google Project Zero
- **URL:** https://www.tiraniddo.dev/ (search "COM elevation") + https://docs.microsoft.com/en-us/windows/win32/com/the-com-elevation-moniker
- **Resource type:** Blog posts + MSDN documentation
- **Topic tags:** `COM` `UAC-bypass` `elevation-moniker` `COM-security` `LPE` `DCOM`
- **Difficulty:** Advanced
- **Historical or current:** Current
- **Trust level:** ⭐⭐⭐⭐⭐
- **Why it matters:** The COM Elevation Moniker is a designed feature that allows COM servers to elevate via UAC prompts on behalf of a client. Forshaw identified that this mechanism can be abused to elevate privilege without a prompt when combined with COM activation security misconfigurations. Foundational for understanding COM-based UAC bypass and elevation chains.
- **What it teaches:**
  - How COM Elevation Monikers work: `Elevation:Administrator!new:{CLSID}`
  - COM security descriptors: `LaunchPermission`, `AccessPermission`, `RunAs` registry keys
  - How to identify COM classes registered for auto-elevation
  - The role of the DLL Surrogate (`dllhost.exe`) in out-of-process COM activation
  - Privilege checks during `CoCreateInstance` for elevated CLSIDs
- **Best use:** Pair with the `OleViewDotNet` tool (also by Forshaw — see sandbox-attacksurface-analysis-tools) to enumerate COM classes by security configuration.
- **Related bug classes / primitives:** UAC Bypass, DCOM, Token Impersonation, COM Security
- **Suggested next resource:** RPC section (05_rpc_com_alpc_namedpipes) for COM/RPC interaction; Entry 4.1 for named pipe interaction with COM activation
- **Notes:** `OleViewDotNet` (https://github.com/tyranid/oleviewdotnet) is the essential COM analysis tool. Cross-reference with sandbox-attacksurface-analysis-tools for access check analysis.

---

## 5. Windows Installer / Updater / Repair Flows

---

### Entry 5.1

- **Title:** Windows Installer Repair Technique — MSI Repair Privilege Escalation
- **Author / Organization:** Multiple researchers (Florian Bogner "bogner.sh", itm4n, Wietze Beukema "hijacklibs.net")
- **URL:** https://bogner.sh/2014/01/windows-installer-elevatedinstallmode/ + https://itm4n.github.io/ (search "msi repair") + https://hijacklibs.net/
- **Resource type:** Blog posts / CVE collection
- **Topic tags:** `Windows-Installer` `MSI` `repair` `DLL-hijacking` `LPE` `AlwaysInstallElevated` `msiexec`
- **Difficulty:** Intermediate
- **Historical or current:** Current (MSI repair bugs continue to appear)
- **Trust level:** ⭐⭐⭐⭐ — Multiple independent confirmations
- **Why it matters:** Windows Installer's repair functionality (`msiexec /fa`) runs with SYSTEM privileges and can be triggered from a low-privilege context. When a repair reinstalls files or DLLs into locations where an attacker can pre-plant a file, this constitutes a privilege escalation. Dozens of third-party MSI packages contain these vulnerabilities.
- **What it teaches:**
  - How `msiexec /fa` (reinstall, re-cache) works at the process level
  - The DLL search order during MSI repair installation (often missing path validation)
  - The `AlwaysInstallElevated` policy and its security implications
  - How to identify MSI repair vulnerabilities: look for SYSTEM-level reinstalls touching user-writable directories
  - Tools: `Orca` (MSI editor), `msiexec /log`, Process Monitor during repair
- **Best use:** After Entry 1.1 (file write primitives). Use Process Monitor to observe file operations during `msiexec /fa` on common applications (Zoom, VS Code, etc.). Combine with junction attacks.
- **Related bug classes / primitives:** Arbitrary File Write, DLL Hijacking, Windows Installer, Junction Abuse
- **Suggested next resource:** Entry 1.1 for the write-to-escalation chain; hijacklibs.net for DLL hijack candidates
- **Notes:** `hijacklibs.net` maintains a database of known DLL hijack candidates — invaluable for MSI repair research. CVE density in this class is high for enterprise software.

---

### Entry 5.2

- **Title:** Windows Update and Patching Service Attack Surface
- **Author / Organization:** Various (Project Zero, Eclypsium, SEC Consult)
- **URL:** https://googleprojectzero.blogspot.com/ (search "Windows Update") + https://eclypsium.com/research/
- **Resource type:** Research papers / blog posts
- **Topic tags:** `Windows-Update` `WaasMedic` `TrustedInstaller` `LPE` `update-service-security`
- **Difficulty:** Advanced
- **Historical or current:** Current
- **Trust level:** ⭐⭐⭐⭐
- **Why it matters:** The Windows Update stack (WU client, WaasMedic, TrustedInstaller, CBS) runs with TrustedInstaller or SYSTEM privileges and handles cryptographically unsigned temporary files in some flows. Understanding this attack surface is critical for both offensive research and supply-chain security.
- **What it teaches:**
  - The Windows Update architecture: WU client → WaasMedic → CBS → TrustedInstaller
  - Temporary file handling during update staging (often user-influenced directories)
  - How `WaaSMedicSvc` (Windows Update Medic Service) protects the update stack and how it can be an escalation target
  - CBS (Component Based Servicing) log injection and path manipulation bugs
- **Best use:** Advanced topic — study after thoroughly understanding Entries 1.x and 5.1. Requires familiarity with Windows service security model.
- **Related bug classes / primitives:** Arbitrary File Write, TrustedInstaller, CBS Log Injection, Service Security
- **Suggested next resource:** Windows Internals coverage of CBS and servicing stack
- **Notes:** This attack surface is heavily monitored by Microsoft and high-severity bugs are rare. However, third-party update mechanisms using similar patterns are often less hardened.

---

## 6. Object Manager Namespace Abuse

---

### Entry 6.1

- **Title:** BaitAndSwitch — OpLock + Junction TOCTOU Race (symboliclink-testing-tools)
- **Author / Organization:** James Forshaw / Google Project Zero
- **URL:** https://github.com/googleprojectzero/symboliclink-testing-tools (BaitAndSwitch utility + source)
- **Resource type:** Open-source tool + implicit documentation via source code
- **Topic tags:** `oplock` `TOCTOU` `junction` `race-condition` `BaitAndSwitch` `LPE` `object-manager` `LAB-WORTHY`
- **Difficulty:** Advanced
- **Historical or current:** Current (primitive still used in modern exploits)
- **Trust level:** ⭐⭐⭐⭐⭐ — Project Zero; directly used in CVE PoCs
- **Why it matters:** BaitAndSwitch is the canonical implementation of the oplock + junction race technique. It allows an attacker to atomically swap a path's destination between two operations by a privileged process (e.g., security check then file open). This converts many TOCTOU vulnerabilities in privileged code into reliable arbitrary file operations.
- **What it teaches:**
  - How opportunistic locks (oplocks) work: range locks that pause a file operation until the locker releases
  - The `FSCTL_REQUEST_OPLOCK` filter oplock: fires when a privileged process accesses a specific file, allowing the attacker to swap the junction before the access completes
  - The race window created between security-check and file-operation in Windows services
  - How to set up the oplock, receive the notification, swap the junction, and release — all before the privileged process continues
  - Practical implementation using the `SetOpLock` and `CreateMountPoint` utilities
- **Best use:** Clone symboliclink-testing-tools, read BaitAndSwitch source carefully, then reproduce the attack with a known CVE PoC (e.g., CVE-2018-8440 — Task Scheduler LPE). Use Process Monitor and WinDbg to observe the race.
- **Related bug classes / primitives:** OpLock, TOCTOU, Junction Abuse, Arbitrary File Write, Mount Point Abuse
- **Suggested next resource:** Entry 1.1 (Forshaw's blog post explaining the technique in prose); Entry 6.2 for object namespace context
- **Notes:** The filter oplock approach (as opposed to exclusive oplock) is less disruptive and more reliable for this use case. Study `FSCTL_REQUEST_OPLOCK` documentation thoroughly.

---

### Entry 6.2

- **Title:** Windows Object Manager Namespace — \RPC Control, \Sessions, \Global Directory
- **Author / Organization:** James Forshaw (NtApiDotNet / NtObjectManager) + Windows Internals (Russinovich et al.)
- **URL:** https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools + Windows Internals Part 1 (Chapter 3 — System Mechanisms)
- **Resource type:** Tool documentation + book
- **Topic tags:** `object-manager` `NT-namespace` `RPC-Control` `symbolic-links` `named-pipes` `Windows-internals`
- **Difficulty:** Advanced
- **Historical or current:** Current
- **Trust level:** ⭐⭐⭐⭐⭐
- **Why it matters:** The NT Object Manager namespace is the substrate beneath all Windows IPC and file system operations. Understanding `\RPC Control`, `\GLOBAL??`, `\Sessions\N\BaseNamedObjects`, and `\Device` directories is necessary to understand *how* symlink and junction attacks redirect operations — and why they work at the kernel level rather than just the Win32 level.
- **What it teaches:**
  - NT namespace structure: `\`, `\Device`, `\??\`, `\GLOBAL??`, `\RPC Control`, `\Sessions`
  - How `\??\` (per-user DOS device namespace) enables user-controlled symlink creation
  - The `\RPC Control` directory and its role in named pipe squatting
  - Session isolation: why `\Sessions\1\BaseNamedObjects` differs from `\BaseNamedObjects`
  - `NtCreateSymbolicLinkObject` vs. Win32 `CreateSymbolicLink` — privilege requirements and scope
  - Using NtObjectManager PowerShell module to browse the namespace live
- **Best use:** Use `WinObj` (Sysinternals) and NtObjectManager together to explore the namespace while reading Windows Internals Chapter 3. Build a mental map of the namespace hierarchy.
- **Related bug classes / primitives:** Named Pipe Squatting, Junction Abuse, Symbolic Link Attacks, Session Isolation
- **Suggested next resource:** Entry 2.1 (symboliclink-testing-tools); RPC/COM section (05_rpc_com_alpc_namedpipes)
- **Notes:** `WinObj` from Sysinternals is the GUI browser; `NtObjectManager` (`Get-NtObject`, `Get-NtDirectory`) is the scriptable version. Both are essential lab tools.

---

*Last updated: 2026-04-22 · Maintained as part of the windows-research-vault*
