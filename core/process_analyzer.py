from core.ps_runner import run_ps_json
from core.white_list import is_whitelisted_process

def audit_processes():
    script = """
    $procs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path } | ForEach-Object {
        $p = $_
        $isSystemPath = ($p.Path -match "^C:\\\\Windows\\\\System32" -or $p.Path -match "^C:\\\\Windows\\\\SysWOW64")
        $statusStr = "Valid (System)"
        $signerStr = "Microsoft Windows"
        if (-not $isSystemPath) {
            $sig = Get-AuthenticodeSignature -FilePath $p.Path -ErrorAction SilentlyContinue
            if ($sig -and $sig.Status) { $statusStr = $sig.Status.ToString() } else { $statusStr = "Unknown" }
            if ($sig -and $sig.SignerCertificate) { $signerStr = $sig.SignerCertificate.Subject } else { $signerStr = "Unsigned" }
        }
        $isSusPath = ($p.Path -match "AppData|Temp|ProgramData")
        $isUnsigned = ($statusStr -ne "Valid" -and $statusStr -ne "Valid (System)")
        $isSus = $isSusPath -or ($isUnsigned -and -not $isSystemPath)
        
        [PSCustomObject]@{
            Id = $p.Id
            ProcessName = $p.ProcessName
            Path = $p.Path
            Status = $statusStr
            Signer = $signerStr
            IsSuspiciousPath = [bool]$isSusPath
            IsUnsigned = [bool]$isUnsigned
            IsSuspicious = [bool]$isSus
        }
    }
    $procs | ConvertTo-Json -Depth 3
    """
    items = run_ps_json(script)
    if isinstance(items, dict):
        items = [items]

    filtered_items = []
    for item in items:
        p_name = item.get("ProcessName", "")
        p_path = item.get("Path", "")
        if is_whitelisted_process(p_name, p_path):
            item["IsSuspicious"] = False
            item["IsSuspiciousPath"] = False
        filtered_items.append(item)

    return filtered_items
