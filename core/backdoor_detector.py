from core.ps_runner import run_ps_json

def audit_backdoors():
    script = """
    $backdoorFindings = @()

    $netConns = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Listen' -or $_.State -eq 'Established' }
    $suspiciousPorts = @(4444, 5555, 6666, 7777, 8888, 9999, 1337, 31337, 4443, 8443)

    foreach ($c in $netConns) {
        $lPort = $c.LocalPort
        $rPort = $c.RemotePort
        $p = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
        $pName = if ($p) { $p.ProcessName } else { "Unknown" }
        $pPath = if ($p) { $p.Path } else { "N/A" }

        $isSusPort = ($suspiciousPorts -contains $lPort) -or ($suspiciousPorts -contains $rPort)
        $isSusPath = ($pPath -match "AppData|Temp|ProgramData")

        if ($isSusPort -or ($isSusPath -and $c.State -eq "Established")) {
            $backdoorFindings += [PSCustomObject]@{
                Type = "Suspicious Network Connection / Backdoor Port"
                PID = $c.OwningProcess
                ProcessName = $pName
                Path = $pPath
                LocalEndpoint = "$($c.LocalAddress):$lPort"
                RemoteEndpoint = "$($c.RemoteAddress):$rPort"
                State = $c.State.ToString()
                Details = "Port or Path associated with C2/RAT communication"
                IsSuspicious = $true
            }
        }
    }

    $ratNames = "async|njrat|quasar|remcos|warzone|venom|xworm|meterpreter|cobalt|netcat|ncat|chisel|ngrok"
    $procs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path }
    foreach ($p in $procs) {
        if ($p.ProcessName -match $ratNames -or $p.Path -match $ratNames) {
            $backdoorFindings += [PSCustomObject]@{
                Type = "Known RAT / Reverse Shell Process Signature"
                PID = $p.Id
                ProcessName = $p.ProcessName
                Path = $p.Path
                LocalEndpoint = "N/A"
                RemoteEndpoint = "N/A"
                State = "Running"
                Details = "Binary name matches known Trojan RAT malware family"
                IsSuspicious = $true
            }
        }
    }

    $backdoorFindings | ConvertTo-Json -Depth 4
    """
    items = run_ps_json(script)
    if isinstance(items, dict):
        items = [items]
    return items
