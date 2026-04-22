# Labs and Exercises
## Windows Security Research — Hands-On Practice

---

## Overview

This section contains structured, hands-on lab exercises for Windows security researchers. Each lab is designed to reinforce theoretical knowledge with practical experience. Labs are organized by difficulty and topic, and reference real tools, techniques, and vulnerabilities used in professional security research.

The exercises here are not CTF challenges — they are research skills labs. The goal is not to "solve" a puzzle but to develop muscle memory and intuition for the real research workflow: setting up environments, tracing system behavior, building PoCs, and documenting findings.

---

## Lab Environment Requirements

### Virtual Machine Setup

**Required VMs (create and snapshot all before starting):**

| VM Name | OS Version | Purpose | Network |
|---------|-----------|---------|---------|
| `win10-research` | Windows 10 22H2 (latest) | Tool exploration, enumeration labs | Host-only |
| `win10-vuln` | Windows 10 1903 (unpatched) | Historical CVE reproduction | Isolated (no internet) |
| `win11-research` | Windows 11 22H2 | Modern kernel labs | Host-only |
| `winserver-lab` | Windows Server 2019 | Service/RPC/COM labs | Host-only |
| `win10-debuggee` | Windows 10 22H2 | Kernel debug target (KDNET) | Internal switch only |
| `win10-debugger` | Windows 10 22H2 | WinDbg host for kernel debugging | Internal switch only |

**Hardware recommendations:**
- Minimum 16GB RAM for running 2 VMs simultaneously
- 32GB+ recommended for kernel debugging pair + research VM
- SSD storage — kernel debugging is latency-sensitive
- Snapshots: take a "clean" snapshot of every VM before any lab exercise

### Hypervisor Setup
- **Hyper-V** (recommended on Windows host): Good network isolation, nested virtualization for KDNET
- **VMware Workstation/Fusion**: Better compatibility with some tools, easier NAT configuration
- **VirtualBox**: Free option, more limited for kernel debugging

### Required Tools (Install on Research VM)
```
# Sysinternals
- Process Monitor (procmon.exe)
- WinObj
- AccessChk
- Autoruns
- PsExec

# Debugging
- WinDbg Preview (winget install Microsoft.WinDbg)
- x64dbg (https://x64dbg.com/)
- dnSpyEx (for .NET debugging)

# Security Research
- System Informer (https://github.com/winsiderss/systeminformer)
- API Monitor (http://www.rohitab.com/apimonitor)

# PowerShell Modules
Install-Module NtObjectManager  # Forshaw's NT object toolkit
Install-Module PowerSploit      # (research use only)

# Reversing
- Ghidra (https://ghidra-sre.org/)
- IDA Free (https://hex-rays.com/ida-free/)
- BinDiff (https://github.com/google/bindiff)

# Code
- Visual Studio Community (C/C++, C#)
- Python 3.x (for exploit scripts)
- Git

# Enumeration
- PrivescCheck: git clone https://github.com/itm4n/PrivescCheck
- SharpUp: git clone https://github.com/GhostPack/SharpUp (build with VS)

# Research PoCs (for lab reproduction)
- HEVD: git clone https://github.com/hacksysteam/HackSysExtremeVulnerableDriver
- symboliclink-testing-tools: git clone https://github.com/googleprojectzero/symboliclink-testing-tools
- sandbox-attacksurface-analysis-tools: git clone https://github.com/googleprojectzero/sandbox-attacksurface-analysis-tools
```

---

## Safety Considerations

### The Three Rules of Exploit Labs

1. **Isolation first:** Every lab involving real exploit code must run in a VM with no network connection to production systems or the internet. Use Hyper-V internal switches or VMware host-only networks.

2. **Snapshot before every exercise:** Take a VM snapshot immediately before starting a lab. If something goes wrong (system crash, accidental BSOD, corrupted state), revert and start fresh.

3. **Never run compiled binaries from unknown sources:** Always compile from source after reviewing the code. For PoC code from GitHub, read the full source before building.

### For Kernel Labs Specifically
- Kernel bugs can crash (BSOD) the VM instantly — always have a snapshot ready
- KDNET debugging: the debuggee VM is connected to the debugger, so breaking in with WinDbg pauses the entire debuggee VM — plan your investigation steps
- When experimenting with HEVD or kernel exploits: disable automatic restart on BSOD (`sysdm.cpl` → Advanced → Startup and Recovery → uncheck "Automatically restart") so you can read STOP codes

---

## Lab Progression

### Recommended Sequence

The labs are numbered and sequenced, but researchers with existing skills can jump to the relevant tier:

```
Tier 1 (Fundamentals)        → Labs 1–5 in LABS_QUEUE.md
    ↓
Tier 2 (Security Model)      → Labs 6–8 in LABS_QUEUE.md
    ↓
Tier 3 (Bug Class Repro)     → Labs 9–15 in LABS_QUEUE.md
    ↓
Tier 4 (Kernel Exploitation) → Labs 16–20 in LABS_QUEUE.md
    ↓
Tier 5 (Patch Diffing)       → Labs 21–23 in LABS_QUEUE.md
    ↓
Tier 6 (Variant Hunting)     → Labs 24–27 in LABS_QUEUE.md
    ↓
Tier 7 (Reporting)           → Labs 28–30 in LABS_QUEUE.md
```

### Entry Points by Background

| Background | Starting Lab |
|-----------|-------------|
| Complete beginner | Lab 1 (WinDbg setup) |
| Know debugging but not Windows security | Lab 5 (Token analysis) |
| Know Windows security model | Lab 9 (PrintSpoofer reproduction) |
| Know LPE concepts, want kernel | Lab 16 (HEVD stack overflow) |
| Know kernel exploitation | Lab 21 (Patch diffing) |

---

## Lab Documentation Template

When completing a lab, document your work using this template (save in a personal notes directory):

```markdown
## Lab: [Name]
**Date completed:** YYYY-MM-DD
**VM used:** win10-research / win10-vuln / etc.
**Time taken:** X hours

### What I Did
[Step-by-step notes of what you actually did, including dead ends]

### Key Observations
- [Observation 1]
- [Observation 2]

### What I Learned
[In your own words, what new concept or technique you understand now]

### Questions Raised
[What questions does this lab raise that you want to investigate further?]

### Variants/Extensions
[Ideas for extending the lab or finding related bugs]
```

---

## See Also

- `00_index/LABS_QUEUE.md` — Full list of 30+ labs with detailed instructions
- `00_index/LEARNING_PATH.md` — How labs fit into the full learning path
- `01_foundations/` — Theoretical background for foundational labs
- `08_bug_classes/` — Background reading for bug class reproduction labs
- `09_exploit_primitives/` — Background for kernel exploitation labs
- `10_kernel_win32k/` — Kernel reference material for kernel labs
- `11_patch_diff_and_root_cause/` — Tools and methodology for patch diffing labs
