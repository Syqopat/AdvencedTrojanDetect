import sys
import os
from rich.console import Console
from rich.prompt import Prompt
from rich.panel import Panel

from ui.terminal import (
    show_banner,
    show_menu,
    simulate_progress,
    print_result_panel,
    print_findings_table
)

from core.task_scheduler import audit_task_scheduler
from core.persistence import audit_persistence
from core.process_analyzer import audit_processes
from core.directory_inspector import audit_directories
from core.network_checker import audit_network
from core.defender_history import audit_defender, trigger_quick_scan
from core.cleanup_generator import generate_cleanup_script
from core.report_generator import export_json_report, export_markdown_report

console = Console()

class TrojanSentinelApp:
    def __init__(self):
        self.audit_data = {}

    def run_full_scan(self):
        show_banner()
        console.print("[bold cyan][*] INITIATING FULL DEEP SYSTEM SECURITY AUDIT...[/bold cyan]\n")
        
        simulate_progress("1/6 Auditing Task Scheduler Tasks...", 0.6)
        tasks = audit_task_scheduler()
        self.audit_data["tasks"] = tasks

        simulate_progress("2/6 Auditing Registry & Startup Persistence...", 0.6)
        persistence = audit_persistence()
        self.audit_data["persistence"] = persistence

        simulate_progress("3/6 Analyzing Active Processes & Code Signatures...", 0.8)
        processes = audit_processes()
        self.audit_data["processes"] = processes

        simulate_progress("4/6 Inspecting ProgramData & Temp Directories...", 0.6)
        directories = audit_directories()
        self.audit_data["directories"] = directories

        simulate_progress("5/6 Checking Network Connections & Proxy Hijacks...", 0.6)
        network = audit_network()
        self.audit_data["network"] = network

        simulate_progress("6/6 Retrieving Windows Defender Threat Log...", 0.6)
        defender = audit_defender()
        self.audit_data["defender"] = defender

        self.display_summary()

    def display_summary(self):
        console.print("\n[bold green]========================================================[/bold green]")
        console.print("[bold green]          AUDIT RESULTS SUMMARY & THREAT FINDINGS        [/bold green]")
        console.print("[bold green]========================================================[/bold green]\n")

        sus_reg = []
        reg_items = self.audit_data.get("persistence", {}).get("RegistryStartup", [])
        for r in reg_items:
            val_name = str(r.get("ValueName", ""))
            val_data = str(r.get("ValueData", ""))
            if "AppData" in val_data or "Temp" in val_data or r.get("IsSuspicious"):
                sus_reg.append(r)

        if sus_reg:
            console.print("[bold red][!] HIGH PRIORITY THREAT DETECTED IN REGISTRY RUN KEYS![/bold red]")
            print_findings_table(
                "Suspicious Persistence Registry Entries",
                sus_reg,
                ["Registry Key", "Value Name", "Target Binary Path"],
                ["RegistryPath", "ValueName", "ValueData"]
            )
        else:
            console.print("[bold green][+] Registry Auto-Run keys: Clean[/bold green]")

        sus_procs = [p for p in self.audit_data.get("processes", []) if p.get("IsSuspicious")]
        if sus_procs:
            console.print(f"\n[bold yellow][!] Found {len(sus_procs)} processes running from non-standard locations or unsigned.[/bold yellow]")
            print_findings_table(
                "Suspicious / Unsigned Active Processes",
                sus_procs[:10],
                ["PID", "Process", "Executable Path", "Signature Status"],
                ["Id", "ProcessName", "Path", "Status"]
            )
        else:
            console.print("[bold green][+] Active Processes & Code Signatures: Clean[/bold green]")

        sus_tasks = [t for t in self.audit_data.get("tasks", []) if t.get("IsSuspicious")]
        if sus_tasks:
            console.print(f"\n[bold yellow][!] Found {len(sus_tasks)} suspicious scheduled tasks.[/bold yellow]")
            print_findings_table(
                "Suspicious Scheduled Tasks",
                sus_tasks,
                ["Task Name", "State", "Actions"],
                ["TaskName", "State", "Actions"]
            )
        else:
            console.print("[bold green][+] Task Scheduler: Clean[/bold green]")

        threat_findings = {
            "suspicious_processes": sus_procs,
            "suspicious_registry": sus_reg,
            "suspicious_tasks": sus_tasks,
            "suspicious_files": []
        }
        
        desktop_script = generate_cleanup_script(threat_findings)
        console.print(f"\n[bold green][+] Administrative Cleanup Batch Script Created:[/bold green] [bold yellow]{desktop_script}[/bold yellow]")

    def run_individual_module(self, choice):
        show_banner()
        if choice == "2":
            console.print("[bold cyan][*] Running Task Scheduler Audit...[/bold cyan]")
            tasks = audit_task_scheduler()
            print_findings_table("Scheduled Tasks Outside \\Microsoft\\", tasks, ["Name", "Path", "State", "Actions"], ["TaskName", "TaskPath", "State", "Actions"])
        elif choice == "3":
            console.print("[bold cyan][*] Running Registry & Persistence Audit...[/bold cyan]")
            p = audit_persistence()
            reg = p.get("RegistryStartup", [])
            print_findings_table("Registry Startup Keys", reg, ["Path", "Name", "Data"], ["RegistryPath", "ValueName", "ValueData"])
            win = p.get("Winlogon", {})
            console.print(f"\n[bold white]Winlogon Shell:[bold white] {win.get('Shell')}")
            console.print(f"[bold white]Winlogon Userinit:[bold white] {win.get('Userinit')}")
        elif choice == "4":
            console.print("[bold cyan][*] Running Process & Signature Audit...[/bold cyan]")
            procs = audit_processes()
            sus = [p for p in procs if p.get("IsSuspiciousPath") or p.get("Status") != "Valid (System)"]
            print_findings_table("Active Process Digital Signatures", sus[:15], ["PID", "Name", "Path", "Status"], ["Id", "ProcessName", "Path", "Status"])
        elif choice == "5":
            console.print("[bold cyan][*] Inspecting ProgramData & Temp Directories...[/bold cyan]")
            dirs = audit_directories()
            files = dirs.get("ProgramDataFiles", [])
            print_findings_table("ProgramData Executables", files, ["File Path", "Size", "Created"], ["FullPath", "Length", "CreationTime"])
        elif choice == "6":
            console.print("[bold cyan][*] Checking Active Network Ports & Backdoors...[/bold cyan]")
            net = audit_network()
            conns = net.get("Connections", [])
            print_findings_table("Active Network Connections", conns[:15], ["Local", "Remote", "State", "PID", "Process"], ["LocalAddress", "RemoteAddress", "State", "PID", "ProcessName"])
        elif choice == "7":
            console.print("[bold cyan][*] Retrieving Windows Defender Threat Log...[/bold cyan]")
            def_data = audit_defender()
            if isinstance(def_data, list) and len(def_data) > 0:
                print_findings_table("Defender Threat History", def_data, ["Threat ID", "Name", "Resource", "Process"], ["ThreatID", "ThreatName", "Resources", "ProcessName"])
            else:
                console.print("[bold green][+] No threat history recorded in Windows Defender.[/bold green]")
            
            trigger = Prompt.ask("\n[bold yellow]Do you want to initiate a Windows Defender Quick Scan now? (y/n)[/bold yellow]", default="n")
            if trigger.lower() == 'y':
                console.print("[bold cyan][*] Triggering Windows Defender QuickScan...[/bold cyan]")
                res = trigger_quick_scan()
                console.print(f"[bold green][+] QuickScan Status:[/bold green] {res}")

        elif choice == "8":
            console.print("[bold cyan][*] Generating One-Click Desktop Cleanup Script...[/bold cyan]")
            if not self.audit_data:
                self.run_full_scan()
            sus_reg = []
            reg_items = self.audit_data.get("persistence", {}).get("RegistryStartup", [])
            for r in reg_items:
                if "AppData" in str(r.get("ValueData", "")) or r.get("IsSuspicious"):
                    sus_reg.append(r)
            sus_procs = [p for p in self.audit_data.get("processes", []) if p.get("IsSuspicious")]
            sus_tasks = [t for t in self.audit_data.get("tasks", []) if t.get("IsSuspicious")]
            
            script_path = generate_cleanup_script({
                "suspicious_processes": sus_procs,
                "suspicious_registry": sus_reg,
                "suspicious_tasks": sus_tasks,
                "suspicious_files": []
            })
            console.print(f"[bold green][+] Administrative Cleanup script ready at:[bold green] [bold yellow]{script_path}[/bold yellow]")

        elif choice == "9":
            console.print("[bold cyan][*] Exporting Audit Reports...[/bold cyan]")
            if not self.audit_data:
                self.run_full_scan()
            j_path = export_json_report(self.audit_data)
            m_path = export_markdown_report(self.audit_data)
            console.print(f"[bold green][+] JSON Report Exported:[bold green] {j_path}")
            console.print(f"[bold green][+] Markdown Report Exported:[bold green] {m_path}")

        Prompt.ask("\n[bold cyan]Press Enter to return to main menu...[/bold cyan]")

    def main_loop(self):
        while True:
            show_banner()
            show_menu()
            choice = Prompt.ask("[bold yellow]Select audit option (0-9)[/bold yellow]", choices=["0","1","2","3","4","5","6","7","8","9"], default="1")
            
            if choice == "0":
                console.print("\n[bold magenta]Exiting TrojanSentinel. Stay Safe![/bold magenta]\n")
                sys.exit(0)
            elif choice == "1":
                self.run_full_scan()
                Prompt.ask("\n[bold cyan]Press Enter to return to main menu...[/bold cyan]")
            else:
                self.run_individual_module(choice)

def main():
    app = TrojanSentinelApp()
    app.main_loop()

if __name__ == "__main__":
    main()
