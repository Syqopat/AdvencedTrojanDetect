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
    md.append("# TrojanSentinel - Advanced Forensic Audit Report")
    md.append(f"**Generated On:** {now}\n")

    md.append("## Executive Summary")
    threat_count = audit_data.get("summary", {}).get("total_threats", 0)
    if threat_count > 0:
        md.append(f"> **WARNING:** Found {threat_count} high-priority security concerns or persistence mechanisms.")
    else:
        md.append("> **OK:** System passed primary threat verification controls.")
    md.append("\n---\n")

    md.append("## 1. Discord & Discord Canary Injection Audit")
    disc = audit_data.get("discord_injections", [])
    if disc:
        md.append("| Variant | File Path | Injected | Details |")
        md.append("| --- | --- | --- | --- |")
        for d in disc:
            inj = "YES" if d.get("IsInjected") else "NO"
            md.append(f"| {d.get('Variant')} | `{d.get('FilePath')}` | **{inj}** | {d.get('Reasons')} |")
    else:
        md.append("No installed Discord desktop clients found.")
    md.append("\n---\n")

    md.append("## 2. UAC Bypass Hijack Audit")
    uac = audit_data.get("uac_bypasses", [])
    if uac:
        md.append("| Technique | Registry Path | Hijack Value | Bypassed |")
        md.append("| --- | --- | --- | --- |")
        for u in uac:
            byp = "YES" if u.get("IsBypassed") else "NO"
            md.append(f"| {u.get('BypassTechnique')} | `{u.get('RegistryPath')}` | `{u.get('HijackValue')}` | **{byp}** |")
    else:
        md.append("No active UAC bypass registry hijacks detected.")
    md.append("\n---\n")

    md.append("## 3. Backdoor & RAT Connection Audit")
    back = audit_data.get("backdoors", [])
    if back:
        md.append("| Type | PID | Process Name | Path | Endpoints | State |")
        md.append("| --- | --- | --- | --- | --- | --- |")
        for b in back:
            md.append(f"| {b.get('Type')} | {b.get('PID')} | {b.get('ProcessName')} | `{b.get('Path')}` | `{b.get('LocalEndpoint')} -> {b.get('RemoteEndpoint')}` | {b.get('State')} |")
    else:
        md.append("No active backdoor ports or RAT signature processes detected.")
    md.append("\n---\n")

    md.append("## 4. Task Scheduler Audit")
    tasks = audit_data.get("tasks", [])
    if tasks:
        md.append("| Task Name | Path | State | Actions | Suspicious |")
        md.append("| --- | --- | --- | --- | --- |")
        for t in tasks:
            is_sus = "YES" if t.get("IsSuspicious") else "NO"
            md.append(f"| {t.get('TaskName')} | {t.get('TaskPath')} | {t.get('State')} | {t.get('Actions')} | {is_sus} |")
    md.append("\n---\n")

    md.append("## 5. Startup & Registry Persistence")
    reg = audit_data.get("persistence", {}).get("RegistryStartup", [])
    if reg:
        md.append("| Registry Path | Value Name | Value Data | Suspicious |")
        md.append("| --- | --- | --- | --- |")
        for r in reg:
            is_sus = "YES" if r.get("IsSuspicious") else "NO"
            md.append(f"| {r.get('RegistryPath')} | {r.get('ValueName')} | `{r.get('ValueData')}` | **{is_sus}** |")
    
    content = "\n".join(md)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    return filepath
