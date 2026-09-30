import sys
import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.text import Text
from rich.align import Align
from rich.prompt import Prompt

console = Console()

BANNER = """
 [bold cyan]
  ████████╗██████╗  ██████╗  ██████╗  █████╗ ███╗   ██╗███████╗███████╗███╗   ██╗████████╗██╗███╗   ██╗███████╗██╗     
  ╚══██╔══╝██╔══██╗██╔═══██╗██╔════╝ ██╔══██╗████╗  ██║██╔════╝██╔════╝████╗  ██║╚══██╔══╝██║████╗  ██║██╔════╝██║     
     ██║   ██████╔╝██║   ██║██║  ███╗███████║██╔██╗ ██║███████╗█████╗  ██╔██╗ ██║   ██║   ██║██╔██╗ ██║█████╗  ██║     
     ██║   ██╔══██╗██║   ██║██║   ██║██╔══██║██║╚██╗██║╚════██║██╔══╝  ██║╚██╗██║   ██║   ██║██║╚██╗██║██╔══╝  ██║     
     ██║   ██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║ ╚████║███████║███████╗██║ ╚████║   ██║   ██║██║ ╚████║███████╗███████╗
     ╚═╝   ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝
 [/bold cyan]
 [bold yellow]         >>> ADVANCED TROJAN & PERSISTENCE FORENSIC SYSTEM v1.0.0 <<<[/bold yellow]
 [bold magenta]                 [ Cyber Threat Intelligence & Deep Malware Auditor ] [/bold magenta]
"""

def show_banner():
    console.clear()
    console.print(Align.center(Text.from_markup(BANNER)))
    console.print(Align.center("[bold white on blue] DISCORD INJECTION | UAC BYPASS | CLIPPER | WALLET & BROWSER SECURITY [/bold white on blue]\n"))

def show_menu():
    table = Table(title="[bold cyan]SYSTEM AUDIT & ADVANCED THREAT CONTROLS[/bold cyan]", show_header=True, header_style="bold underline magenta", expand=True)
    table.add_column("Option", style="bold yellow", justify="center", width=8)
    table.add_column("Audit Module Description", style="bold white")
    table.add_column("Scope / Target", style="cyan")

    table.add_row("1", "Full Deep Security Scan (All 12 Modules)", "Complete System & Stealer Audit")
    table.add_row("2", "Discord & Canary JS Injection Audit", "Inspect desktop_core index.js")
    table.add_row("3", "UAC Bypass Hijack Audit", "ms-settings, mscfile, UserInit")
    table.add_row("4", "Crypto Clipper & Address Swap Scan", "Clipboard Hooks & Processes")
    table.add_row("5", "Browser Extensions & WebRequest Audit", "Chrome, Edge, Brave, Opera")
    table.add_row("6", "Crypto Wallet Integrity Audit", "Exodus, Atomic, MetaMask, Phantom")
    table.add_row("7", "Backdoor & Reverse Shell Scan", "Listening Ports, RAT Signatures")
    table.add_row("8", "Task Scheduler Persistence Audit", "Get-ScheduledTask / Triggers")
    table.add_row("9", "Startup & Registry Keys Audit", "Run, RunOnce, Winlogon, WMI")
    table.add_row("10", "Active Processes & Code Signatures", "Authenticode, AppData / Temp")
    table.add_row("11", "Critical Directories & Temp Scan", "ProgramData / Temp Executables")
    table.add_row("12", "Network Ports & Proxy Hijack Scan", "TCP Connections, Hosts, Proxy")
    table.add_row("13", "Defender Threat Log & QuickScan", "Get-MpThreatDetection / Scan")
    table.add_row("14", "Generate Desktop One-Click Cleanup Script", "Build Administrative .bat")
    table.add_row("15", "Export Audit Report (JSON & Markdown)", "Save Local Artifacts")
    table.add_row("0", "Exit System", "Terminate TrojanSentinel")

    console.print(table)
    console.print()

def simulate_progress(task_name: str, duration: float = 0.6):
    with Progress(
        SpinnerColumn("dots", style="bold cyan"),
        TextColumn("[bold green]{task.description}"),
        BarColumn(bar_width=40, style="blue", complete_style="green"),
        TaskProgressColumn(),
        console=console
    ) as progress:
        task = progress.add_task(task_name, total=100)
        for _ in range(20):
            time.sleep(duration / 20)
            progress.update(task, advance=5)

def print_result_panel(title: str, content: str, style: str = "bold green"):
    p = Panel(content, title=f"[{style}]{title}[/{style}]", border_style=style, expand=True)
    console.print(p)

def print_findings_table(title: str, items: list, headers: list, keys: list):
    table = Table(title=f"[bold yellow]{title}[/bold yellow]", show_header=True, header_style="bold cyan")
    for h in headers:
        table.add_column(h)
    
    for item in items:
        row = []
        is_sus = item.get("IsSuspicious", False) or item.get("IsSuspiciousPath", False) or item.get("IsInjected", False) or item.get("IsBypassed", False) or item.get("IsTampered", False)
        style = "bold red" if is_sus else "white"
        for k in keys:
            val = str(item.get(k, "N/A"))
            row.append(f"[{style}]{val}[/{style}]")
        table.add_row(*row)
    
    console.print(table)
