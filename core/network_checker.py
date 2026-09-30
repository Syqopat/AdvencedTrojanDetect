from core.ps_runner import run_ps_json

def audit_network():
    script = """
    $res = [ordered]@{}
    
    $netConns = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Listen' -or $_.State -eq 'Established' } | Select-Object -First 50 | ForEach-Object {
        $c = $_
        $p = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
        $pName = if ($p) { $p.ProcessName } else { "Unknown" }
        $pPath = if ($p) { $p.Path } else { "N/A" }
        $isSus = ($c.RemotePort -notmatches "^(80|443|53|8080)$") -and ($c.State -eq "Established") -and ($pPath -match "AppData|Temp")
        
        [PSCustomObject]@{
            LocalAddress = $c.LocalAddress
            LocalPort = $c.LocalPort
            RemoteAddress = $c.RemoteAddress
            RemotePort = $c.RemotePort
            State = $c.State.ToString()
            PID = $c.OwningProcess
            ProcessName = $pName
            ProcessPath = $pPath
            IsSuspicious = [bool]$isSus
        }
    }
    $res["Connections"] = $netConns

    $hostsPath = "C:\\Windows\\System32\\drivers\\etc\\hosts"
    $hostsContent = if (Test-Path $hostsPath) { Get-Content $hostsPath | Where-Object { $_ -notmatch "^\\s*#" -and $_ -match "\\S" } } else { @() }
    $res["HostsEntries"] = $hostsContent

    $proxy = Get-ItemProperty -Path "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" -ErrorAction SilentlyContinue
    $proxyEnabled = if ($proxy) { $proxy.ProxyEnable } else { 0 }
    $proxyServer = if ($proxy) { $proxy.ProxyServer } else { "" }
    $res["ProxySettings"] = [PSCustomObject]@{
        ProxyEnable = $proxyEnabled
        ProxyServer = $proxyServer
        IsSuspicious = [bool]($proxyEnabled -eq 1)
    }

    $res | ConvertTo-Json -Depth 4
    """
    data = run_ps_json(script)
    if isinstance(data, list) and len(data) > 0:
        return data[0]
    return data if isinstance(data, dict) else {}
