from core.ps_runner import run_ps_json
from core.white_list import is_whitelisted_process

def audit_backdoors():
    script = """
    $backdoorFindings = @()

    $netConns = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Listen' -or $_.State -eq 'Established' }
    $c2Ports = @(4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 4443, 8443)

    foreach ($c in $netConns) {
        $lAddr = $c.LocalAddress
        $rAddr = $c.RemoteAddress
        $lPort = $c.LocalPort
        $rPort = $c.RemotePort
        $p = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
        $pName = if ($p) { $p.ProcessName } else { "Unknown" }
        $pPath = if ($p) { $p.Path } else { "N/A" }

        $isLoopback = ($lAddr -eq "127.0.0.1" -or $rAddr -eq "127.0.0.1" -or $lAddr -eq "::1" -or $rAddr -eq "::1")
        $isStandardPort = ($rPort -eq 443 -or $rPort -eq 80 -or $rPort -eq 53 -or $rPort -eq 4070 -or $lPort -eq 11434)
        $isC2Port = ($c2Ports -contains $lPort) -or ($c2Ports -contains $rPort)

        if ($isLoopback -or ($isStandardPort -and -not $isC2Port)) {
            continue
        }

        if ($isC2Port) {
            $backdoorFindings += [PSCustomObject]@{
                Type = "Suspicious C2 Backdoor Port Identified"
                PID = $c.OwningProcess
                ProcessName = $pName
                Path = $pPath
                LocalEndpoint = "$lAddr:$lPort"
                RemoteEndpoint = "$rAddr:$rPort"
                State = $c.State.ToString()
                Details = "Port associated with known Trojan C2 communication"
                IsSuspicious = $true
            }
        }
    }

    $ratNames = "async|njrat|quasar|remcos|warzone|venom|xworm|meterpreter|cobalt|netcat|ncat|chisel|ngrok"
    $procs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path }
    foreach ($p in $procs) {
        if ($p.ProcessName -match $ratNames -or $p.Path -match $ratNames) {
            $backdoorFindings += [PSCustomObject]@{
                Type = "Known RAT / Reverse Shell Signature"
                PID = $p.Id
                ProcessName = $p.ProcessName
                Path = $p.Path
                LocalEndpoint = "N/A"
                RemoteEndpoint = "N/A"
                State = "Running"
                Details = "Binary signature matches Trojan RAT family"
                IsSuspicious = $true
            }
        }
    }

    $backdoorFindings | ConvertTo-Json -Depth 4
    """
    items = run_ps_json(script)
    if isinstance(items, dict):
        items = [items]

    filtered_items = []
    for item in items:
        p_name = item.get("ProcessName", "")
        p_path = item.get("Path", "")
        if is_whitelisted_process(p_name, p_path) and "Signature" not in item.get("Type", ""):
            continue
        filtered_items.append(item)

    return filtered_items
