import json
import datetime
import os

def export_json_report(audit_data, filepath="trojan_sentinel_report.json"):
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(audit_data, f, indent=4)
    return filepath

def export_markdown_report(audit_data, filepath="trojan_sentinel_report.md"):
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    md = []
    md.append("# TrojanSentinel - Deep Security Audit Report")
    md.append(f"**Generated On:** {now}\n")

    md.append("## Executive Summary")
    threat_count = audit_data.get("summary", {}).get("total_threats", 0)
    if threat_count > 0:
        md.append(f"> **WARNING:** Found {threat_count} high-priority security concerns or persistence mechanisms.")
    else:
        md.append("> **OK:** No critical threats or malware persistence mechanisms identified.")
    md.append("\n---\n")

    md.append("## 1. Task Scheduler Audit")
    tasks = audit_data.get("tasks", [])
    if tasks:
        md.append("| Task Name | Path | State | Actions | Suspicious |")
        md.append("| --- | --- | --- | --- | --- |")
        for t in tasks:
            is_sus = "YES" if t.get("IsSuspicious") else "NO"
            md.append(f"| {t.get('TaskName')} | {t.get('TaskPath')} | {t.get('State')} | {t.get('Actions')} | {is_sus} |")
    else:
        md.append("No third-party scheduled tasks found.")
    md.append("\n---\n")

    md.append("## 2. Startup & Registry Persistence")
    reg = audit_data.get("persistence", {}).get("RegistryStartup", [])
    if reg:
        md.append("### Registry Auto-Run Keys")
        md.append("| Registry Path | Value Name | Value Data | Suspicious |")
        md.append("| --- | --- | --- | --- |")
        for r in reg:
            is_sus = "YES" if r.get("IsSuspicious") else "NO"
            md.append(f"| {r.get('RegistryPath')} | {r.get('ValueName')} | `{r.get('ValueData')}` | **{is_sus}** |")
    
    winlogon = audit_data.get("persistence", {}).get("Winlogon", {})
    md.append(f"\n- **Winlogon Shell:** `{winlogon.get('Shell')}`")
    md.append(f"- **Winlogon Userinit:** `{winlogon.get('Userinit')}`\n")
    md.append("\n---\n")

    md.append("## 3. Active Processes & Code Signatures")
    procs = audit_data.get("processes", [])
    sus_procs = [p for p in procs if p.get("IsSuspicious")]
    if sus_procs:
        md.append("| PID | Process Name | Path | Status | Signer |")
        md.append("| --- | --- | --- | --- | --- |")
        for p in sus_procs:
            md.append(f"| {p.get('Id')} | {p.get('ProcessName')} | `{p.get('Path')}` | {p.get('Status')} | {p.get('Signer')} |")
    else:
        md.append("All active processes are signed or running from standard directories.")
    md.append("\n---\n")

    md.append("## 4. Directory Inspection (ProgramData & Temp)")
    prog_files = audit_data.get("directories", {}).get("ProgramDataFiles", [])
    if prog_files:
        md.append("### ProgramData Executables/Scripts")
        for f in prog_files:
            md.append(f"- `{f.get('FullPath')}` ({f.get('Length')} bytes)")
    else:
        md.append("No loose executable files found in ProgramData root.")
    md.append("\n---\n")

    md.append("## 5. Network Connections & Proxy Hijack")
    conns = audit_data.get("network", {}).get("Connections", [])
    sus_conns = [c for c in conns if c.get("IsSuspicious")]
    if sus_conns:
        md.append("| Local Address | Remote Address | State | PID | Process Name |")
        md.append("| --- | --- | --- | --- | --- |")
        for c in sus_conns:
            md.append(f"| {c.get('LocalAddress')}:{c.get('LocalPort')} | {c.get('RemoteAddress')}:{c.get('RemotePort')} | {c.get('State')} | {c.get('PID')} | {c.get('ProcessName')} |")
    else:
        md.append("No suspicious active external connections detected.")
    
    proxy = audit_data.get("network", {}).get("ProxySettings", {})
    md.append(f"\n- **Proxy Enabled:** {proxy.get('ProxyEnable')}")
    md.append(f"- **Proxy Server:** `{proxy.get('ProxyServer')}`")

    content = "\n".join(md)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    return filepath
