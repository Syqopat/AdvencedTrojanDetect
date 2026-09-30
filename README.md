# 🛡️ TrojanSentinel (AdvencedTrojanDetect) v3.0

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%2F11-0078D6.svg)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security Audit](https://img.shields.io/badge/audit-Discord%20%7C%20UAC%20%7C%20Backdoors-red.svg)](#features)

**TrojanSentinel** is an advanced Windows threat intelligence, persistence auditor, and malware detection suite. It audits low-level kernel endpoints, Discord client JS token stealer injections, UAC bypass registry hijacks, C2 backdoor sockets, WMI persistence, and Authenticode Digital Signatures.

---

## 🚀 Key Features

- **Discord & Discord Canary Injection Audit:** Inspects `discord_desktop_core` modules across Discord, Discord Canary, Discord PTB, and Discord Development clients for malicious token stealer JavaScript injections, obfuscated `eval()` blocks, and exfiltration webhooks.
- **UAC Bypass Hijack Detector:** Identifies user-mode UAC elevation bypass hijacks including `ms-settings` (FODHelper/ComputerDefaults), `mscfile` (EventVwr), `CLSID` COM hijacks, and `UserInitMprLogonScript` overrides.
- **Backdoor & Reverse Shell Scanner:** Detects unauthorized listening C2 ports (e.g. 4444, 5555, 1337, 31337), RAT signatures (AsyncRAT, NjRAT, Quasar, Remcos, Warzone, Venom, XWorm), and reverse shell process trees.
- **Task Scheduler Persistence Audit:** Filters out native `\Microsoft\` tasks to isolate third-party or rogue scheduled tasks, executable triggers, and periodic repetition mechanics.
- **Auto-Run Registry & Winlogon Inspector:** Audits `HKCU` and `HKLM` `Run`, `RunOnce`, `WOW6432Node`, `Winlogon` `Shell` & `Userinit` hijacks, `AppInit_DLLs`, and `WMI Event Consumers` (`root\subscription`).
- **Active Processes & Code Signature Verification:** Validates Authenticode digital signatures (`Get-AuthenticodeSignature`), isolates unsigned processes running from user directories (`%APPDATA%`, `%TEMP%`, `%PROGRAMDATA%`), and detects DLL side-loading.
- **Hidden Executable & Folder Inspection:** Audits `C:\ProgramData` for disguised directory paths, hidden binaries, and recent executable creations (`.exe`, `.dll`, `.vbs`, `.ps1`, `.bat`).
- **Network Port & Proxy Hijack Scan:** Maps active listening and established sockets to process PIDs, inspects local DNS `hosts` file integrity, and checks WinINet Proxy/DNS parameters.
- **Windows Defender Integration:** Inspects Defender threat logs (`Get-MpThreatDetection`) and allows one-click invocation and verification of Defender QuickScan.
- **One-Click Administrative Cleanup Script Generator:** Generates a standalone `.bat` script on your Desktop configured to terminate malicious processes, repair injected Discord JS files, delete UAC bypass hijacks, unregister rogue tasks, and quarantine payloads.
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
│   ├── discord_injector.py   # Discord & Canary JS Injection Engine
│   ├── uac_checker.py        # UAC Bypass Registry Hijack Auditor
│   ├── backdoor_detector.py  # C2 Backdoor & RAT Scanner
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

## 📦 Installation & Quick Start

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/Syqopat/AdvencedTrojanDetect.git
   cd AdvencedTrojanDetect
   ```

2. **Install Dependencies:**
   ```bash
   py -m pip install -r requirements.txt
   ```

3. **Run TrojanSentinel:**
   ```bash
   py main.py
   ```

---

## 💻 Interactive Terminal Options

| Option | Audit Engine | Target Scope |
| :---: | :--- | :--- |
| **1** | **Full System Forensic Scan** | Executes all 9 audit engines simultaneously |
| **2** | **Discord & Canary Injection Audit** | Inspects `desktop_core` `index.js` files |
| **3** | **UAC Bypass Hijack Audit** | Audits `ms-settings`, `mscfile`, `UserInit` |
| **4** | **Backdoor & Reverse Shell Scan** | Scans C2 listening ports and RAT signatures |
| **5** | **Task Scheduler Audit** | Scans scheduled tasks outside `\Microsoft\` |
| **6** | **Startup & Registry Keys Audit** | Audits `Run`, `RunOnce`, `Winlogon`, `WMI` |
| **7** | **Active Processes & Signatures** | Verifies Authenticode digital signatures |
| **8** | **Critical Directories Scan** | Scans `ProgramData` and `%TEMP%` executables |
| **9** | **Network Ports & Proxy Hijacks** | Checks sockets, PIDs, `hosts` file & Proxy |
| **10** | **Defender History & QuickScan** | Retrieves threat logs & triggers Defender |
| **11** | **Generate Cleanup Script** | Builds one-click administrative `.bat` script |
| **12** | **Export Audit Reports** | Generates JSON & Markdown reports |
| **0** | **Exit** | Closes TrojanSentinel |

---

## 🛡️ License

Licensed under the MIT License.
