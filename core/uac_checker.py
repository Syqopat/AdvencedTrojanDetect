from core.ps_runner import run_ps_json

def audit_uac_bypasses():
    script = """
    $uacResults = @()

    $checkPaths = @(
        @{ Path = "HKCU:\\Software\\Classes\\ms-settings\\Shell\\Open\\command"; Name = "Fodhelper / ComputerDefaults UAC Bypass" },
        @{ Path = "HKCU:\\Software\\Classes\\mscfile\\shell\\open\\command"; Name = "EventVwr UAC Bypass Hijack" },
        @{ Path = "HKCU:\\Environment"; ValueName = "UserInitMprLogonScript"; Name = "UserInit Logon Script UAC Bypass" },
        @{ Path = "HKCU:\\Software\\Classes\\exefile\\shell\\open\\command"; Name = "ExeFile File Association Hijack" },
        @{ Path = "HKCU:\\Software\\Classes\\launcher.ExecutionEngine\\Shell\\open\\command"; Name = "Launcher Execution Engine Hijack" }
    )

    foreach ($item in $checkPaths) {
        $p = $item.Path
        if (Test-Path $p) {
            $prop = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
            $val = if ($item.ValueName) { $prop.($item.ValueName) } else { $prop.'(default)' }
            if ($val) {
                $uacResults += [PSCustomObject]@{
                    BypassTechnique = $item.Name
                    RegistryPath = $p
                    HijackValue = $val.ToString()
                    IsBypassed = $true
                }
            }
        }
    }

    $uacPolicy = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" -ErrorAction SilentlyContinue
    $enableLUA = if ($uacPolicy) { $uacPolicy.EnableLUA } else { 1 }
    $consentAdmin = if ($uacPolicy) { $uacPolicy.ConsentPromptBehaviorAdmin } else { 5 }
    $policyDisabled = ($enableLUA -eq 0) -or ($consentAdmin -eq 0)

    $uacResults += [PSCustomObject]@{
        BypassTechnique = "System UAC Global Policy Audit"
        RegistryPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System"
        HijackValue = "EnableLUA=$enableLUA, ConsentPromptBehaviorAdmin=$consentAdmin"
        IsBypassed = [bool]$policyDisabled
    }

    $uacResults | ConvertTo-Json -Depth 3
    """
    items = run_ps_json(script)
    if isinstance(items, dict):
        items = [items]
    return items
