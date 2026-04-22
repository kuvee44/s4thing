# GitHub & Code — Quick Reference

> Section 15: GitHub repositories and code resources for Windows security research

## Summary

This section covers the most important GitHub repositories for Windows security research, organized into four categories: Research Tooling, LPE Exploit Collections, Kernel/Driver Research, and Analysis/RE Tools.

## Entry Count

| Category | Count |
|---|---|
| Research Tooling (High Trust) | 6 |
| LPE Exploit Collections | 6 |
| Kernel / Driver Research | 5 |
| Analysis and RE Tools | 2 |
| **Total** | **19** |

## Top Priority Repositories

| Priority | Repository | Why |
|---|---|---|
| 1 | sandbox-attacksurface-analysis-tools | Most important Windows security research toolkit |
| 2 | HEVD | Only complete kernel exploitation training environment |
| 3 | Sysinternals Suite | Foundational toolset, required always |
| 4 | impacket | Network protocol research standard |
| 5 | PrivescCheck | Best LPE enumeration + educational source |
| 6 | symboliclink-testing-tools | Foundational symlink/junction/OPLOCK research |
| 7 | System Informer | Deepest process/token/handle visibility |
| 8 | pe-sieve | PE analysis and injection detection |

## Trust Level Summary

| Trust Level | Repositories |
|---|---|
| HIGH | sandbox-attacksurface-analysis-tools, symboliclink-testing-tools, PrivescCheck, PrintSpoofer, RpcView, Sysinternals, SharpUp, Seatbelt, HEVD, windows-local-privilege-escalation-cookbook, impacket, System Informer, pe-sieve |
| MEDIUM-HIGH | InstallerFileTakeOver |
| MEDIUM | GodPotato, SweetPotato, PowerUp (archived), awesome_windows_logical_bugs, WinPwn |
| CAUTION | Windows-Kernel-Exploits (SecWiki) |

## Quick Setup Checklist

- [ ] Clone sandbox-attacksurface-analysis-tools and install NtObjectManager from PSGallery
- [ ] Install Sysinternals Suite to a permanent location (add to PATH)
- [ ] Install System Informer (replaces Process Hacker)
- [ ] Set up HEVD on a kernel debugging VM
- [ ] Install Python + impacket for network protocol research
- [ ] Clone PrivescCheck for reference and study

> See REPOS.md for a one-line-per-repo reference table.
> See RESOURCES.md for full entry details on each repository.
