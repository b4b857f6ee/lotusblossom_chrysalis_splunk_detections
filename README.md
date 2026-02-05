
🔍 39 Splunk Detection Searches — Lotus Blossom / Chrysalis Backdoor

Covering the recent Notepad++ supply chain compromise by Chinese APT group Lotus Blossom (Feb 2026), based on Rapid7's research and Neo23x0/signature-base YARA rules.

📁 Part A — Filename IOCs (Search 1-15) Detection of malicious file drops in USOShared, AppData\Roaming\ProShow, Adobe\Scripts, and fake Bluetooth directories. Covers Sysmon file creation, process execution, DLL side-loading, registry persistence, scheduled tasks, and Windows Defender correlation.

🧬 Part B — YARA-Derived Detections (Search 16-24) SHA256 hash matching for 5 known malware samples (Chrysalis DLL Loader, Shellcode Loader, Backdoor, Cobalt Strike Beacon Loader, Microsoft Warbird Shellcode Loader). Includes CobaltStrike named pipe detection, process injection patterns, Notepad++ supply chain behavioral indicators, and DLL side-loading from suspicious paths.

🌐 Part C — Network IOCs (Search 25-39) 9 C2 IPs (Vultr, Alibaba, Tencent Cloud) and 7 C2 domains (including WireGuard typosquat). Covers Sysmon, firewalls (OPNsense), ZenArmor NGFW (all 5 sourcetypes), DNS resolution, proxy logs, TLS/SNI inspection, IDS alerts, suspicious User-Agent strings, and GUP.exe (Notepad++ updater) abuse detection.

✅ All searches available in both raw SPL and CIM Data Model (tstats) versions for maximum compatibility.
