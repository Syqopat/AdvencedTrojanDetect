from core.ps_runner import run_ps_json

def audit_clipper_mechanisms():
    script = """
    $clipperFindings = @()
    
    $procs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path }
    $clipperKeywords = "clipper|clipboard|address_swap|btc_swap|eth_swap|crypto_swap"

    foreach ($p in $procs) {
        $isSusPath = ($p.Path -match "AppData|Temp|ProgramData")
        $isMatch = ($p.ProcessName -match $clipperKeywords) -or ($p.Path -match $clipperKeywords)
        
        if ($isMatch -or ($isSusPath -and $p.ProcessName -match "clip")) {
            $clipperFindings += [PSCustomObject]@{
                Type = "Active Crypto Clipper Process Indicator"
                PID = $p.Id
                ProcessName = $p.ProcessName
                Path = $p.Path
                Details = "Process name or execution path indicates clipboard address swap malware"
                IsSuspicious = $true
            }
        }
    }

    $clipperFindings | ConvertTo-Json -Depth 3
    """
    items = run_ps_json(script)
    if isinstance(items, dict):
        items = [items]
    return items
