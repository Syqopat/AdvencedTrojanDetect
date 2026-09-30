import os

def generate_cleanup_script(findings, output_path=None):
    if output_path is None:
        desktop = os.path.expanduser("~/Desktop")
        output_path = os.path.join(desktop, "Cleanup_Malware.bat")
    
    lines = [
        "@echo off",
        "setlocal enabledelayedexpansion",
        "",
        "net session >nul 2>&1",
        "if %errorlevel% neq 0 (",
        "    echo [!] Administrator privileges required. Relaunching as Admin...",
        "    powershell -Command \"Start-Process '%~f0' -Verb RunAs\"",
        "    exit /b",
        ")",
        "",
        "title ADVANCED TROJAN & MALWARE CLEANUP SCRIPT",
        "echo ========================================================",
        "echo   TROJAN SENTINEL - AUTOMATED CLEANUP SCRIPT",
        "echo ========================================================",
        "echo."
    ]

    for item in findings.get("suspicious_processes", []):
        pid = item.get("Id")
        pname = item.get("ProcessName")
        lines.append(f"echo [*] Terminating suspicious process {pname} (PID: {pid})...")
        lines.append(f"taskkill /F /PID {pid} 2>nul")

    for item in findings.get("suspicious_registry", []):
        rpath = item.get("RegistryPath", "").replace("HKCU:", "HKCU").replace("HKLM:", "HKLM")
        vname = item.get("ValueName", "")
        lines.append(f"echo [*] Removing Registry Persistence Key: {vname}...")
        lines.append(f'reg delete "{rpath}" /v "{vname}" /f 2>nul')

    for item in findings.get("suspicious_tasks", []):
        tname = item.get("TaskName", "")
        lines.append(f"echo [*] Unregistering Suspicious Scheduled Task: {tname}...")
        lines.append(f'schtasks /delete /tn "{tname}" /f 2>nul')

    for item in findings.get("suspicious_files", []):
        fpath = item.get("FullPath", "")
        lines.append(f"echo [*] Quarantining File: {fpath}...")
        lines.append(f'if exist "{fpath}" (')
        lines.append(f'    attrib -h -s -r "{fpath}"')
        lines.append(f'    ren "{fpath}" "*.quarantine" 2>nul')
        lines.append(f'    echo [+] Quarantined: {fpath}')
        lines.append(")")

    lines.extend([
        "echo.",
        "echo ========================================================",
        "echo   CLEANUP OPERATIONS SUCCESSFULLY COMPLETED!",
        "echo ========================================================",
        "echo.",
        "pause"
    ])

    content = "\n".join(lines)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(content)
    return output_path
