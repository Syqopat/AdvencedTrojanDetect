from core.ps_runner import run_ps_json

def audit_persistence():
    script = """
    $res = [ordered]@{}
    
    $regPaths = @(
        "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
        "HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
        "HKLM:\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce"
    )
    $startupReg = @()
    foreach ($p in $regPaths) {
        if (Test-Path $p) {
            $props = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
            if ($props) {
                foreach ($prop in $props.PSObject.Properties) {
                    if ($prop.Name -notmatch "^PS|^Class") {
                        $isSus = ($prop.Value -match "temp|appdata|AppData|powershell|-enc|cscript|wscript|vbs|bat|scr")
                        $startupReg += [PSCustomObject]@{
                            RegistryPath = $p
                            ValueName = $prop.Name
                            ValueData = $prop.Value
                            IsSuspicious = [bool]$isSus
                        }
                    }
                }
            }
        }
    }
    $res["RegistryStartup"] = $startupReg

    $winlogon = Get-ItemProperty -Path "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" -ErrorAction SilentlyContinue
    $shell = if ($winlogon) { $winlogon.Shell } else { "explorer.exe" }
    $userinit = if ($winlogon) { $winlogon.Userinit } else { "C:\\Windows\\system32\\userinit.exe," }
    $winlogonSus = ($shell -ne "explorer.exe") -or ($userinit -notmatch "userinit\.exe")
    $res["Winlogon"] = [PSCustomObject]@{
        Shell = $shell
        Userinit = $userinit
        IsSuspicious = [bool]$winlogonSus
    }

    $startupDirs = @(
        "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
    )
    $startupFiles = @()
    foreach ($dir in $startupDirs) {
        if (Test-Path $dir) {
            Get-ChildItem -Path $dir -ErrorAction SilentlyContinue | ForEach-Object {
                $isSus = ($_.Extension -match "\.(lnk|bat|vbs|ps1|exe|cmd|scr)$")
                $startupFiles += [PSCustomObject]@{
                    Directory = $dir
                    FileName = $_.Name
                    FullPath = $_.FullName
                    IsSuspicious = [bool]$isSus
                }
            }
        }
    }
    $res["StartupFiles"] = $startupFiles

    $appInit1 = (Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows" -ErrorAction SilentlyContinue).AppInit_DLLs
    $appInit2 = (Get-ItemProperty "HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows NT\\CurrentVersion\\Windows" -ErrorAction SilentlyContinue).AppInit_DLLs
    $appInitSus = [bool]($appInit1 -or $appInit2)
    $res["AppInitDLLs"] = [PSCustomObject]@{
        HKLM = if ($appInit1) { $appInit1 } else { "" }
        WOW6432Node = if ($appInit2) { $appInit2 } else { "" }
        IsSuspicious = $appInitSus
    }

    $wmiConsumers = Get-CimInstance -Namespace root\\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }
    $wmiFilters = Get-CimInstance -Namespace root\\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }
    $wmiSus = [bool]($wmiConsumers.Count -gt 0 -or $wmiFilters.Count -gt 0)
    $res["WMIPersistence"] = [PSCustomObject]@{
        Consumers = $wmiConsumers
        Filters = $wmiFilters
        IsSuspicious = $wmiSus
    }

    $res | ConvertTo-Json -Depth 4
    """
    data = run_ps_json(script)
    if isinstance(data, list) and len(data) > 0:
        return data[0]
    return data if isinstance(data, dict) else {}
