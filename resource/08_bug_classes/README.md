# 08 · Bug Classes — README

## What This Section Covers

This section catalogs the **primary Windows LPE bug classes**: the recurring vulnerability patterns that researchers exploit to escalate privilege on Windows systems. Each sub-section corresponds to a distinct attack family, with curated resources covering theory, reference implementations, and real CVE walkthroughs.

## Why This Section Exists

Windows LPE research is a domain where vocabulary matters enormously. Phrases like "arbitrary file write," "token impersonation," or "junction abuse" each refer to precise, well-defined exploitation families with specific mechanics, mitigations, and tooling. Without a shared taxonomy, researchers reinvent wheels and miss connections between related bug classes.

This section provides:
- **Primary sources** for each bug class (foundational papers, original disclosures)
- **Lab tools** for hands-on reproduction
- **Real CVE references** to ground theory in practice
- **Cross-references** between related classes (e.g., arbitrary file write → DLL hijacking → installer repair)

## Section Structure

| Sub-section | Key Themes |
|-------------|------------|
| Arbitrary File Write/Move/Delete | Primitive construction, DLL planting chains |
| Junction / Symlink / Mount Point / Hard Link | Link type taxonomy, kernel/Win32 layer differences |
| Token Impersonation / SeImpersonate | Potato family evolution, named pipe impersonation |
| Named Pipe / RPC / COM Abuse | IPC security, squatting, COM elevation |
| Windows Installer / Updater / Repair | MSI repair triggers, update service attack surface |
| Object Manager Namespace | NT namespace, BaitAndSwitch, oplock primitives |

## How to Use This Section

**For beginners:** Start with Entry 1.1 (Forshaw arbitrary file write) and Entry 3.5 (PrintSpoofer). These two posts cover the most impactful and well-documented techniques and establish the vocabulary for the rest of the section.

**For intermediate researchers:** Work through the Token Impersonation sub-section in chronological order (Rotten → Juicy → RoguePotato → SweetPotato → PrintSpoofer → GodPotato → LocalPotato) to understand the mitigation/bypass arms race that defines this class.

**For advanced researchers:** The Object Manager Namespace sub-section (BaitAndSwitch, NT namespace) is the deepest material — read alongside the symboliclink-testing-tools source code.

## Cross-Section Dependencies

```
08_bug_classes
    ├── depends on: 06_filesystem_and_fileops (NTFS, reparse points)
    ├── depends on: 05_rpc_com_alpc_namedpipes (COM, RPC, named pipes)
    ├── feeds into: 09_exploit_primitives (primitives used in exploitation chains)
    └── tools in: symboliclink-testing-tools, NtObjectManager, impacket
```

## Difficulty Progression

```
Beginner → PrintSpoofer blog (3.5) → Arbitrary File Write (1.1) → Junction Tools (2.1)
Intermediate → Token Impersonation series (3.1–3.7) → COM Elevation (4.3) → MSI Repair (5.1)
Advanced → LocalPotato (3.7) → BaitAndSwitch (6.1) → Object Namespace (6.2)
```
