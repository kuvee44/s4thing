# Duplicates Merged Log

## Purpose
Track cases where multiple resources covering the same topic were merged into a single entry, or where one resource superseded another.

---

## Merge Decisions

### Windows Internals Coverage
- **Merged:** Multiple blog posts explaining basic Windows process/thread model
- **Into:** Single authoritative reference to Windows Internals book (F-001)
- **Reason:** The book covers these topics definitively; shallow blog posts add nothing

### Potato Exploit Family
- **Kept separate:** Rotten Potato, Juicy Potato, Sweet Potato, RoguePotato, PrintSpoofer, GodPotato, LocalPotato
- **Reason:** Each represents a distinct technical evolution in the token impersonation landscape and teaches different techniques. The evolutionary progression is itself educational.
- **NOT merged** — the progression narrative is valuable

### WinDbg Tutorials
- **Merged:** Multiple "WinDbg tutorial" blog posts
- **Into:** Official Microsoft documentation + NOTES.md WinDbg cheatsheet
- **Reason:** Most tutorials are shallow; direct doc + our own notes are more useful

### Sysinternals Tools
- **Merged:** Multiple blog posts about individual Sysinternals tools
- **Into:** Single entry for the Sysinternals suite (official Microsoft resource)
- **Reason:** Official docs are authoritative; individual blog reviews add little

### PrintNightmare Coverage
- **Multiple sources found:** cube0x0 repo, CERT/CC advisory, various blog posts
- **Decision:** Kept primary research repo (cube0x0) + itm4n analysis post
- **Merged out:** Generic news articles, vendor advisories that just describe the bug

### NTLM Relay Coverage
- **Multiple sources:** Various blog posts on NTLM relay
- **Primary kept:** impacket toolkit (authoritative implementation) + Dirk-jan Mollema's blog
- **Merged out:** Tutorial posts that just repeat the same attack steps

---

## Supersession Log

| Old Resource | Superseded By | Reason |
|-------------|---------------|--------|
| Process Hacker (original) | System Informer (fork) | Project continuation with active maintenance |
| symboliclink-testing-tools (functional) | NtObjectManager PowerShell module | More comprehensive and maintained |
| Various old potato exploits | GodPotato / PrintSpoofer | More modern, works on current Windows versions |
| Windows Internals 6th edition | Windows Internals 7th edition | Updated for modern Windows |

---

## Near-Duplicates (Kept Both)

| Resource A | Resource B | Why Both Kept |
|-----------|-----------|--------------|
| tiraniddo.dev blog | Windows Security Internals book | Blog has more cutting-edge research; book is more systematic |
| Windows Internals book | OSR NT Insider | Book for structure; NT Insider for deep driver/kernel dev details |
| ProcMon | ETW directly | Different abstraction levels, both useful |

---

*Updated: 2026-04-22*
