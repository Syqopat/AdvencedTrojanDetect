# 🛡️ TrojanSentinel (AdvencedTrojanDetect)

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-0078D6.svg)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security Audit](https://img.shields.io/badge/audit-PowerShell%20Kernel%20%26%20WMI-red.svg)](#features)

**TrojanSentinel** is an enterprise-grade terminal-based malware scanner and persistence forensic auditor designed for Windows environments. It bypasses superficial antivirus checks by directly auditing low-level system endpoints using PowerShell, Windows Management Instrumentation (WMI), Registry Run keys, and Authenticode Digital Signature verification.

---

## 🚀 Features

- **Task Scheduler Persistence Audit:** Filters out native `\Microsoft\` tasks to isolate third-party or malicious scheduled tasks, inspects executable actions, triggers, and suspicious short repetition intervals.
- **Auto-Run Registry & Winlogon Inspector:** Audits `HKCU` and `HKLM` `Run`, `RunOnce`, `WOW6432Node` keys, `Winlogon` `Shell` & `Userinit` hijacks, `AppInit_DLLs`, and `WMI Event Consumers` (`root\subscription`).
- **Active Processes & Code Signature Verification:** Validates Authenticode signatures (`Get-AuthenticodeSignature`), isolates unsigned processes running from temporary user directories (`%APPDATA%`, `%TEMP%`, `%PROGRAMDATA%`), and flags DLL side-loading anomalies.
- **Hidden Executable & Folder Inspection:** Audits `C:\ProgramData` for disguised directory paths, hidden binaries, and recent executable creations (`.exe`, `.dll`, `.vbs`, `.ps1`, `.bat`) within the last 30-60 days.
- **Network Port & Backdoor Hijack Scan:** Maps active listening and established sockets to process PIDs, identifies non-standard outbound data transfers, inspects local DNS `hosts` file integrity, and checks WinINet Proxy/DNS hijack parameters.
- **Windows Defender Integration:** Inspects Defender threat logs (`Get-MpThreatDetection`) and allows one-click invocation and verification of Windows Defender QuickScan.
- **One-Click Administrative Cleanup Script Generator:** Automatically generates a standalone `.bat` script on your Desktop configured to terminate malicious processes, unregister rogue tasks, clean registry persistence keys, and quarantine bad payloads.
- **Exportable Forensic Reports:** Saves structured threat intelligence reports in JSON and Markdown formats.

---

## 🛠️ Architecture

```
AdvencedTrojanDetect/
│
├── main.py                  # CLI Terminal Entry Point
├── requirements.txt         # Terminal UI & System Dependencies
├── README.md                # System Documentation & Usage Guide
│
├── core/                    # Security Audit Engines
│   ├── __init__.py
│   ├── ps_runner.py          # PowerShell Execution Bridge
│   ├── task_scheduler.py     # Task Scheduler Forensic Engine
│   ├── persistence.py        # Registry, Winlogon & WMI Audit
│   ├── process_analyzer.py   # Process & Authenticode Verifier
│   ├── directory_inspector.py# ProgramData & Temp Directory Engine
│   ├── network_checker.py    # Socket, Hosts & Proxy Auditor
│   ├── defender_history.py   # Defender Threat Log Engine
│   ├── cleanup_generator.py  # One-Click .bat Script Generator
│   └── report_generator.py   # JSON & Markdown Exporter
│
└── ui/                      # Terminal User Interface
    ├── __init__.py
    └── terminal.py           # Rich UI Banners, Tables & Progress Bars
```

---

## 📦 Installation & Setup

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/your-username/AdvencedTrojanDetect.git
   cd AdvencedTrojanDetect
   ```

2. **Install Python Dependencies:**
   ```bash
   py -m pip install -r requirements.txt
   ```

3. **Run TrojanSentinel:**
   ```bash
   py main.py
   ```

---

## 💻 Interactive Terminal Menu

| Option | Audit Engine | Target Scope |
| :---: | :--- | :--- |
| **1** | **Full System Security Scan** | Executes all 6 forensic modules simultaneously |
| **2** | **Task Scheduler Audit** | Scans scheduled tasks outside `\Microsoft\` |
| **3** | **Startup & Registry Keys Audit** | Audits `Run`, `RunOnce`, `Winlogon`, `WMI` |
| **4** | **Active Processes & Signatures** | Verifies Authenticode digital signatures |
| **5** | **Critical Directories Scan** | Scans `ProgramData` and `%TEMP%` executables |
| **6** | **Network Ports & Backdoors** | Checks sockets, PIDs, `hosts` file & Proxy |
| **7** | **Defender History & QuickScan** | Retrieves threat log & triggers Defender |
| **8** | **Generate Cleanup Script** | Builds one-click administrative `.bat` script |
| **9** | **Export Audit Reports** | Generates JSON & Markdown reports |
| **0** | **Exit** | Closes TrojanSentinel |

---

## 🛡️ License

This project is licensed under the MIT License.
