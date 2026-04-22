# Academic Papers & Technical Reports

> Companion to RESOURCES.md (conference talks).
> This file covers formal papers, technical reports, theses, and long-form research.

---

## Foundational Papers

### "An Analysis of Address Space Layout Randomization on Windows Vista"
- **Authors:** Symantec Research Labs
- **Relevance:** Windows ASLR design analysis; basis for understanding KASLR bypass work

### "Exploiting the Windows Kernel" — phrack.org series
- **Source:** Phrack magazine (various issues)
- **URL:** http://phrack.org/
- **Relevance:** Classic kernel exploitation technique papers; historical foundation

### "Windows 8 Kernel Memory Protections Bypass"
- **Relevance:** Pool header changes, safe unlinking bypass techniques

### "SafeStack, CFI, and Windows CET"
- **Source:** Microsoft Research / academic papers
- **Relevance:** Understanding what modern control flow integrity protects and doesn't protect

---

## Project Zero Technical Reports

Project Zero publishes detailed technical issue reports that function as mini-papers:

- **Windows issues tracker:** https://bugs.chromium.org/p/project-zero/issues/list?q=windows
- **Notable authors:** James Forshaw, Jann Horn, Tavis Ormandy
- **Format:** Issue description + root cause + PoC code + Microsoft response timeline

---

## MSRC Security Research Defense Papers

- **URL:** https://www.microsoft.com/security/blog/
- **BlueHat submissions:** https://www.microsoft.com/en-us/msrc/bluehat-conference
- Notable: CFG internals, HVCI architecture, VBS design, CET implementation

---

## Recommended Reading Order (Papers)

1. Forshaw — Symbolic Links (DEF CON 23 slides → blog posts)
2. j00ru — Bochspwn Reloaded (Black Hat 2017 whitepaper)
3. Yarden Shafir — I/O Ring primitive (windows-internals.com)
4. Tarjei Mandt — Windows kernel pool series
5. harmj0y — Kerberos attack papers and slides
