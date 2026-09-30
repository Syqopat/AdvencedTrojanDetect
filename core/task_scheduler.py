from core.ps_runner import run_ps_json

def audit_task_scheduler():
    script = """
    $tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike '\\Microsoft*' }
    $result = @()
    foreach ($t in $tasks) {
        $execs = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join " ; "
        $trigs = ($t.Triggers | ForEach-Object { $_.ToString() }) -join " ; "
        $isSuspicious = ($execs -match "powershell|-enc|cmd\.exe|cscript|wscript|temp|appdata|AppData|vbs|bat|scr")
        $result += [PSCustomObject]@{
            TaskName = $t.TaskName
            TaskPath = $t.TaskPath
            State = $t.State.ToString()
            Actions = $execs
            Triggers = $trigs
            IsSuspicious = [bool]$isSuspicious
        }
    }
    $result | ConvertTo-Json -Depth 4
    """
    items = run_ps_json(script)
    if isinstance(items, dict):
        items = [items]
    return items
