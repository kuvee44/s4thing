# Debugging & Observability — Windows Security Research

> Category: Debugging tools, kernel analysis, ETW, observability
> Tags: [FOUNDATIONAL] [MUST-READ] [LAB-WORTHY]

---

## Primary Debugging Tools

---

- **Title:** WinDbg
- **Author / Organization:** Microsoft
- **URL:** https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/
- **Resource type:** Kernel and user-mode debugger (official Microsoft tool)
- **Topic tags:** Kernel debugging, user-mode debugging, crash dump analysis, BSOD analysis, live kernel, symbols, extensions, KD, KDNET
- **Difficulty:** Intermediate → Advanced
- **Historical or current:** Current (actively developed)
- **Trust level:** HIGH — official Microsoft tool
- **Why it matters:** WinDbg is the primary tool for Windows kernel debugging. There is no substitute. Every kernel security researcher must become proficient with WinDbg to: inspect kernel structures during exploit development, analyze crash dumps from kernel bugs, perform live kernel debugging of a target VM, understand what happens during a BSOD, and use kernel extensions (Mex, DbgKit, SwishDbgExt) for advanced analysis. Without WinDbg, kernel security research is impossible.
- **What it teaches:** Kernel debugging commands (!process, !thread, !token, dt, dps, k, ub, u, bp, ba); crash dump analysis workflow; kernel structure inspection; how to navigate from a crash to the responsible code; symbol usage and configuration; extension loading and usage; the WinDbg command language; kernel live debugging via KDNET.
- **Best use:** Set up a two-VM debugging environment immediately (host debugger + guest target via KDNET). Work through the WinDbg documentation systematically. Use HEVD exploits to practice kernel debugging in a meaningful context. Keep a personal WinDbg command cheatsheet (see NOTES.md).
- **Related bug classes / primitives:** All kernel bugs — WinDbg is required for all kernel research
- **Suggested next resource:** Time Travel Debugging (TTD) for deterministic replay; Mex extension for productivity; HEVD for a meaningful debugging target
- **Notes:** Two interfaces exist: classic WinDbg (windbg.exe) and WinDbg Preview (new UX, includes TTD). Learn both. The command set is identical but TTD integration makes Preview the preferred choice for new workflows. [FOUNDATIONAL]

---

- **Title:** Time Travel Debugging (TTD)
- **Author / Organization:** Microsoft
- **URL:** https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/time-travel-debugging-overview
- **Resource type:** Debugger feature / recording engine
- **Topic tags:** Time travel debugging, deterministic replay, record and replay, race condition analysis, kernel TTD, user-mode TTD, bug reproduction
- **Difficulty:** Intermediate → Advanced
- **Historical or current:** Current (actively developed; kernel TTD is newer)
- **Trust level:** HIGH — official Microsoft technology
- **Why it matters:** TTD changes how debugging works fundamentally. Instead of reproducing a bug live and hoping to catch it at the right moment, you record execution and then step forward and backward in time through the recording. For race conditions, heap corruption, use-after-free bugs, and any bug that is hard to reproduce: TTD lets you record the crash, then step backward from the crash to find the exact moment of corruption. This is a paradigm shift in debugging productivity. Project Zero researchers have publicly called it a game-changer for vulnerability research.
- **What it teaches:** TTD recording and playback; time-travel-specific WinDbg commands (t- for step back, g- for run back, .positions); how to navigate from a crash backward to the root cause; TTD queries for memory access tracking (dx @$cursession.TTD.Memory()); how to record a kernel crash with kernel TTD; performance considerations for TTD recording.
- **Best use:** Use TTD for every HEVD exploit development exercise. Record the exploit execution, then use backward stepping to understand exactly when corruption occurred. Practice TTD queries to find when a specific memory address was last written. Use kernel TTD for kernel debugging when available (Windows Insider or Azure VMs).
- **Related bug classes / primitives:** All — TTD is universally valuable but particularly transformative for race conditions, UAF, and heap corruption
- **Suggested next resource:** WinDbg Preview (includes TTD integration); TTD-specific MSDN documentation and the dx query language
- **Notes:** User-mode TTD is available in WinDbg Preview. Kernel TTD requires specific configurations (AMD hardware or Azure VMs with the feature). Even user-mode TTD is transformative for user-space security research. [MUST-READ] [LAB-WORTHY]

---

- **Title:** Process Monitor (ProcMon)
- **Author / Organization:** Sysinternals / Microsoft
- **URL:** https://learn.microsoft.com/en-us/sysinternals/downloads/procmon
- **Resource type:** System monitoring tool (GUI)
- **Topic tags:** File system monitoring, registry monitoring, process creation, network monitoring, dynamic analysis, API call tracing, filter rules
- **Difficulty:** Beginner → Intermediate
- **Historical or current:** Current (actively maintained)
- **Trust level:** HIGH — official Microsoft tool
- **Why it matters:** ProcMon is the fastest way to understand what a program is doing at the API level without a debugger. For security research, it is essential for: understanding what files/registry keys an installer creates or modifies (TOCTOU research), tracing how a service binary searches for DLLs (DLL hijacking research), monitoring what happens during MSI repair operations (Windows Installer research), and identifying unexpected file/registry operations that suggest a vulnerability. Every LPE researcher uses ProcMon constantly.
- **What it teaches:** How to create effective filters to reduce noise; how to read stack traces for traced events; how to correlate file operations with process context; how to use ProcMon boot logging to trace early startup; how file/registry/process/network events appear in the trace; how to identify "NAME NOT FOUND" registry/file lookups (DLL hijacking indicators).
- **Best use:** Use with targeted filters — unfiltered ProcMon output is overwhelming. Standard research workflow: enable capture, trigger the operation of interest, disable capture, filter by process or path. For DLL hijacking research, filter by "NAME NOT FOUND" result with extension ".dll". For installer research, filter by the installer process and write operations.
- **Related bug classes / primitives:** DLL hijacking, TOCTOU, arbitrary file write, registry key hijacking, named pipe squatting discovery
- **Suggested next resource:** Sysmon for persistent logging; ETW for programmatic event collection; AccessChk for validating discovered paths
- **Notes:** Mandatory tool. Master ProcMon filtering early — it is the skill multiplier for dynamic analysis. Boot logging feature is particularly valuable for analyzing startup-time vulnerabilities. [FOUNDATIONAL]

---

- **Title:** Process Explorer
- **Author / Organization:** Sysinternals / Microsoft
- **URL:** https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer
- **Resource type:** Process viewer / analysis tool (GUI)
- **Topic tags:** Process analysis, token inspection, handle inspection, DLL view, thread view, security context, process tree
- **Difficulty:** Beginner → Intermediate
- **Historical or current:** Current
- **Trust level:** HIGH — official Microsoft tool
- **Why it matters:** Process Explorer provides more detail than Task Manager about the security context of processes. During security research, you need to quickly answer: what integrity level is this process running at? What token privileges does it have? What handles does it hold? What DLLs are loaded? Process Explorer answers all of these without requiring WinDbg or PowerShell scripting. It is a rapid assessment tool used constantly during dynamic analysis.
- **What it teaches:** Process token and integrity level inspection; handle viewing (files, registry keys, mutexes, events, pipes); DLL loading analysis; process tree relationships; service identification; how to use the "Verify" feature to check binary signing status.
- **Best use:** Keep running during all lab work alongside System Informer. Use for quick token checks and integrity level verification. Use the handle view to identify what resources a process has open. Use the DLL view to identify unexpected library loading.
- **Related bug classes / primitives:** Token analysis, handle inspection, DLL hijacking detection, process security context
- **Suggested next resource:** System Informer for deeper token and handle analysis; AccessChk for ACL-level analysis of discovered handles
- **Notes:** Good first-look tool. System Informer (Process Hacker 3) provides deeper analysis of the same data but Process Explorer's Microsoft integration and signing make it convenient in managed environments.

---

- **Title:** System Informer (Process Hacker 3)
- **Author / Organization:** wj32, community maintainers (now Winsider Seminars & Solutions)
- **URL:** https://github.com/winsiderss/systeminformer
- **Resource type:** System analysis tool (GUI + source)
- **Topic tags:** Process analysis, token viewer, handle viewer, kernel structures, driver enumeration, ETW, memory analysis, impersonation levels
- **Difficulty:** Intermediate → Advanced
- **Historical or current:** Current (replaces Process Hacker 2)
- **Trust level:** HIGH
- **Why it matters:** System Informer provides a window into Windows kernel data structures at a depth that no other GUI tool matches. Its token view shows impersonation level, privileges (enabled vs disabled), groups, and capability SIDs. Its handle view shows kernel object types with addresses. Its memory view shows region protection, commit state, and mapped file names. For kernel security research, this level of visibility is essential for understanding what an exploit actually accomplished.
- **What it teaches:** Real-time token structure analysis; handle table inspection; thread impersonation level verification; kernel pool object visualization; driver and service enumeration; ETW session monitoring; memory region analysis during exploit development.
- **Best use:** Use alongside WinDbg during exploit development — System Informer's GUI shows you the overall security state while WinDbg provides kernel-level detail. Particularly valuable for verifying that token manipulation in a kernel exploit actually succeeded. Study the source code to understand how it queries undocumented kernel structures.
- **Related bug classes / primitives:** Token manipulation verification, handle leak detection, impersonation analysis, kernel exploit result verification
- **Suggested next resource:** WinDbg for the next level of kernel detail; the source code itself as a learning resource for native API usage
- **Notes:** The source code is a masterclass in Windows native API usage. High trust. Replaces the unmaintained Process Hacker 2. [LAB-WORTHY]

---

- **Title:** WinDbg Preview
- **Author / Organization:** Microsoft
- **URL:** https://apps.microsoft.com/store/detail/windbg/9PGJGD53TN86
- **Resource type:** Modern WinDbg GUI with TTD integration
- **Topic tags:** WinDbg, TTD, modern debugger UX, time travel, scripting, JavaScript extensions, data model
- **Difficulty:** Intermediate → Advanced
- **Historical or current:** Current (primary development focus for WinDbg)
- **Trust level:** HIGH — official Microsoft tool
- **Why it matters:** WinDbg Preview is the modern evolution of WinDbg with a significantly improved UI, integrated TTD support, and a powerful data model (dx command) that enables scripting with JavaScript and NatVis. It is the preferred WinDbg interface for new research workflows. The data model's dx queries are particularly powerful for kernel structure traversal and TTD memory access queries.
- **What it teaches:** All WinDbg fundamentals; TTD-specific workflow; dx command and data model queries; JavaScript debugger extensions; improved symbol handling and source level debugging; how to use the WinDbg scripting API for automated analysis.
- **Best use:** Use WinDbg Preview as your primary debugger. Install classic WinDbg as a backup for scenarios where Preview has compatibility issues. Learn the dx query language — it dramatically improves productivity for structure traversal and TTD queries.
- **Related bug classes / primitives:** All — WinDbg Preview is the universal kernel debugging environment
- **Suggested next resource:** TTD documentation; dx data model documentation; WinDbg extension development guides
- **Notes:** Available free from the Microsoft Store. Regularly updated. The dx command and data model are worth dedicating specific learning time to — they change how you interact with kernel structures.

---

## Kernel Debugging Infrastructure

---

- **Title:** Kernel Debugging Setup — Local and Remote via KDNET
- **Author / Organization:** Microsoft documentation
- **URL:** https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/setting-up-network-debugging-of-a-virtual-machine-host
- **Resource type:** Setup documentation / configuration guide
- **Topic tags:** KDNET, kernel debugging, network debugging, VM debugging, bcdedit, debug configuration, two-machine setup
- **Difficulty:** Intermediate
- **Historical or current:** Current
- **Trust level:** HIGH — official Microsoft documentation
- **Why it matters:** Setting up kernel debugging is the first practical step in kernel security research. Without a working kernel debugging environment, you cannot practice HEVD exploits, analyze kernel crashes, or inspect kernel structures. KDNET (network kernel debugging) is the modern approach and works well with VMs. Getting this setup right is a prerequisite for all kernel work.
- **What it teaches:** bcdedit commands for enabling kernel debugging; KDNET configuration; WinDbg debugger connection; firewall configuration for kernel debugging; serial debugging as a fallback; local kernel debugging limitations; saving/restoring VM snapshots for exploit development.
- **Best use:** Set up this environment first, before any other kernel research. Use a hypervisor (Hyper-V or VMware) as the target VM. Configure KDNET with a known port and key. Connect WinDbg Preview from the host. Verify the connection by breaking into the kernel (!version command). This setup is used for all HEVD and subsequent kernel research.
- **Related bug classes / primitives:** Foundational infrastructure — required for all kernel research
- **Suggested next resource:** HEVD for the first meaningful use of this setup
- **Notes:** Invest the time to get a reliable, snapshot-able kernel debugging environment early. It pays dividends for all subsequent research. Local kernel debugging (using `bcdedit /debug on` on your primary machine) is possible but risky — a kernel crash takes your debugging environment with it. Two-machine setup (or VM + host) is strongly preferred.

---

## WinDbg Extensions

---

- **Title:** DbgKit — WinDbg Extension for Kernel Object Visualization
- **Author / Organization:** Yarden Shafir (Windows Internals)
- **URL:** https://www.youtube.com/c/WindowsInternals (associated with Windows Internals channel)
- **Resource type:** WinDbg extension
- **Topic tags:** WinDbg extension, kernel object visualization, process objects, token viewer, EPROCESS, KTHREAD, kernel structures
- **Difficulty:** Intermediate → Advanced
- **Historical or current:** Current
- **Trust level:** HIGH
- **Why it matters:** DbgKit extends WinDbg with commands that provide structured, navigable views of kernel objects — process trees, token details, handle tables — in a more human-readable form than raw dt commands. For kernel security research, this speeds up the analysis of process security context during exploit development.
- **What it teaches:** How WinDbg extensions work; how to navigate kernel object hierarchies efficiently; visualizing EPROCESS, KTHREAD, TOKEN structures; using extensions to accelerate kernel analysis.
- **Best use:** Install alongside Mex extension. Use for kernel structure visualization during HEVD exploit development and general kernel research.
- **Related bug classes / primitives:** Kernel object structure, token analysis, process security context
- **Suggested next resource:** Mex extension; SwishDbgExt for additional analysis capabilities
- **Notes:** Part of the Windows Internals research ecosystem. Yarden Shafir's research is highly trusted.

---

- **Title:** Mex WinDbg Extension
- **Author / Organization:** Microsoft (internal tool, made public)
- **URL:** https://www.microsoft.com/en-us/download/details.aspx?id=53304
- **Resource type:** WinDbg extension
- **Topic tags:** WinDbg productivity, extension, crash analysis, stack analysis, kernel debugging aid
- **Difficulty:** Intermediate
- **Historical or current:** Current
- **Trust level:** HIGH — Microsoft-origin extension
- **Why it matters:** Mex is a productivity extension for WinDbg that provides dozens of additional commands for crash analysis, stack analysis, and general debugging productivity. It is widely used by Microsoft engineers and Windows security researchers. The `!mex.help` command reveals a substantial set of commands that are not available in stock WinDbg.
- **What it teaches:** Extended WinDbg command set; crash analysis automation; stack analysis commands; productivity patterns for common debugging tasks.
- **Best use:** Install immediately after setting up WinDbg. Run !mex.help to survey available commands. Use !mex.crash for quick initial crash analysis. Gradually incorporate Mex commands into your regular debugging workflow.
- **Related bug classes / primitives:** Universal — productivity tool for all kernel debugging
- **Suggested next resource:** SwishDbgExt for additional commands; DbgKit for object visualization
- **Notes:** Required extension for any serious kernel debugging work. Learn the available commands systematically.

---

- **Title:** SwishDbgExt — WinDbg Extension by Matthieu Suiche
- **Author / Organization:** Matthieu Suiche
- **URL:** https://github.com/comaeio/SwishDbgExt
- **Resource type:** WinDbg extension (open source)
- **Topic tags:** WinDbg extension, live kernel analysis, memory forensics, kernel object inspection, DLL analysis
- **Difficulty:** Intermediate → Advanced
- **Historical or current:** Historical (last active updates ~2018) — commands remain useful
- **Trust level:** HIGH — Matthieu Suiche is a respected Windows internals researcher
- **Why it matters:** Provides additional kernel analysis commands not available in stock WinDbg or Mex, particularly around memory forensics operations. Useful for cross-referencing analysis with other extensions.
- **What it teaches:** Extended kernel object analysis; memory forensics commands from a debugging context; WinDbg extension development patterns (source is readable).
- **Best use:** Install alongside Mex and DbgKit. Check whether specific commands you need are available here when other extensions don't cover them. The source code is readable and instructive.
- **Related bug classes / primitives:** Universal — additional debugging commands
- **Suggested next resource:** Mex and DbgKit for primary extension coverage
- **Notes:** Older but commands still work. Less actively maintained than Mex. Useful as a third extension layer.

---

- **Title:** LiveKD — Sysinternals Live Kernel Dump
- **Author / Organization:** Mark Russinovich / Sysinternals / Microsoft
- **URL:** https://learn.microsoft.com/en-us/sysinternals/downloads/livekd
- **Resource type:** Kernel dump tool / WinDbg launcher
- **Topic tags:** Live kernel dump, kernel analysis without kernel debugging mode, local kernel debugging, kernel snapshot
- **Difficulty:** Intermediate
- **Historical or current:** Current
- **Trust level:** HIGH — official Microsoft tool
- **Why it matters:** LiveKD allows kernel debugging and memory analysis on a live system without enabling full kernel debugging mode (which requires a reboot). It takes a snapshot of the live kernel and opens it in WinDbg. Useful for investigating kernel state on systems where enabling KDNET is impractical, for quick checks, and for forensic analysis.
- **What it teaches:** Local kernel analysis without full debugging setup; how to use WinDbg commands against a live kernel snapshot; kernel state observation on production-like systems; how live kernel debugging differs from full interactive debugging.
- **Best use:** Use when you need to quickly inspect kernel state on a non-dedicated research machine or when a full KDNET setup is not available. Not suitable for interactive breakpoint-based debugging — for that, use KDNET.
- **Related bug classes / primitives:** Kernel structure inspection, forensic analysis, quick kernel state assessment
- **Suggested next resource:** KDNET setup for interactive kernel debugging with breakpoints
- **Notes:** Read-only analysis — you cannot set breakpoints or change kernel state with LiveKD. Useful complement to the full debugging setup.

---

## System Monitoring and Telemetry

---

- **Title:** ETW — Event Tracing for Windows
- **Author / Organization:** Microsoft
- **URL:** https://learn.microsoft.com/en-us/windows/win32/etw/event-tracing-portal
- **Resource type:** Kernel telemetry mechanism + API
- **Topic tags:** ETW, event tracing, kernel telemetry, security events, process creation, network events, file events, provider manifests, consumer development
- **Difficulty:** Intermediate → Advanced
- **Historical or current:** Current (fundamental Windows mechanism, continuously expanded)
- **Trust level:** HIGH — official Microsoft mechanism
- **Why it matters:** ETW is the primary Windows telemetry infrastructure. Nearly every security-relevant event — process creation, thread creation, file operations, network connections, registry access, RPC calls — has an ETW provider. Security tools (Windows Defender, Microsoft Sentinel, EDR products) rely on ETW for detection. For security researchers, ETW provides: behavioral analysis of malware or exploits, detection engineering context, understanding what telemetry attackers might be visible in, and programmatic event collection for research analysis.
- **What it teaches:** ETW architecture (providers, sessions, consumers); how to enumerate ETW providers on a system; how to write an ETW consumer in C# or C++; what security-relevant providers exist (Microsoft-Windows-Security-Auditing, Microsoft-Windows-Kernel-Process, etc.); how attackers try to disable or evade ETW; how EDR tools use ETW for detection; the relationship between ETW and Windows Event Log.
- **Best use:** Use logman or xperf to start ETW collection sessions. Use SilkETW for research-focused consumption. Experiment with different providers to understand what events each generates. Study the Microsoft-Windows-Threat-Intelligence provider (requires special access but documents how EDR tools access deeper telemetry).
- **Related bug classes / primitives:** Detection evasion, behavioral analysis, EDR research, telemetry bypass
- **Suggested next resource:** SilkETW for research-focused ETW consumption; Matt Graeber's ETW security research; Windows Event Log infrastructure documentation
- **Notes:** ETW is also an attack surface — ETW patching and provider disabling are techniques used to blind security tools. Understanding ETW deeply illuminates both attack and defense. [LAB-WORTHY]

---

- **Title:** SilkETW
- **Author / Organization:** FireEye / Mandiant
- **URL:** https://github.com/mandiant/SilkETW
- **Resource type:** ETW consumer / research framework (C#)
- **Topic tags:** ETW consumer, security research, event filtering, YARA integration, JSON output, ETW telemetry collection, threat intelligence
- **Difficulty:** Intermediate
- **Historical or current:** Current (maintained by Mandiant)
- **Trust level:** HIGH — Mandiant is a trusted security research organization
- **Why it matters:** SilkETW makes ETW consumption accessible for security researchers. It handles the boilerplate of ETW consumer setup and provides flexible event filtering, JSON output, and YARA signature integration. For research purposes, it enables rapid collection and analysis of ETW events during exploit or malware execution without writing a custom consumer from scratch.
- **What it teaches:** Practical ETW consumption workflow; how to select specific ETW providers for targeted monitoring; how to filter events to reduce noise; how ETW data can be used for behavioral analysis; how to integrate threat intelligence (YARA) with real-time event streams; SilkETW's companion tool SilkService for persistent collection.
- **Best use:** Use during malware analysis or exploit testing to capture ETW events. Configure a specific ETW provider relevant to your research (e.g., Microsoft-Windows-Kernel-Process for process creation events). Combine with ProcMon and System Informer for comprehensive behavioral analysis.
- **Related bug classes / primitives:** Behavioral analysis, detection engineering, ETW-based monitoring, evasion research
- **Suggested next resource:** ETW documentation for understanding the underlying mechanism; Matt Graeber's ETW security research for deeper understanding of the security implications
- **Notes:** Makes ETW research accessible. Good starting point for behavioral analysis workflows. Mandiant's quality control means the implementation is reliable. [LAB-WORTHY]

---

- **Title:** ProcMon Boot Logging
- **Author / Organization:** Sysinternals / Microsoft
- **URL:** https://learn.microsoft.com/en-us/sysinternals/downloads/procmon
- **Resource type:** Feature of Process Monitor
- **Topic tags:** Boot logging, early startup, driver loading, service initialization, startup vulnerabilities, SYSTEM-level operations
- **Difficulty:** Intermediate
- **Historical or current:** Current
- **Trust level:** HIGH — official Microsoft tool
- **Why it matters:** Many Windows security vulnerabilities are triggered during boot or early system initialization when services start as SYSTEM with minimal monitoring. ProcMon's boot logging feature enables capturing file/registry/process events from the very start of the boot process before the GUI loads. This is essential for analyzing vulnerabilities in services that initialize during boot, driver loading issues, and race conditions in startup sequences.
- **What it teaches:** How to enable and capture ProcMon boot logs; filtering boot log data to find relevant events; identifying security-relevant operations during service initialization; how SYSTEM-level services behave during startup vs. normal operation; analysis of startup race conditions.
- **Best use:** Enable boot logging before triggering a vulnerability that manifests during service startup. After reboot, filter the enormous log to the relevant process and timeframe. Combine with AccessChk to validate permissions of files/registry keys accessed during boot.
- **Related bug classes / primitives:** Startup race conditions, service initialization vulnerabilities, early-boot TOCTOU, DLL hijacking during service start
- **Suggested next resource:** Full ProcMon documentation; Sysmon for persistent boot-time logging
- **Notes:** Boot logs are large — learn the filtering workflow before using this feature. Essential for a specific class of vulnerabilities that only manifest during system startup.

---
