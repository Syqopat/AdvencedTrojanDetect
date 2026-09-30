$report = [ordered]@{}

$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskPath -notlike '\Microsoft*' } | Select-Object -First 30 | ForEach-Object {
    $t = $_
    $actions = ($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join " ; "
    $triggers = ($t.Triggers | ForEach-Object { $_.ToString() }) -join " ; "
    [PSCustomObject]@{
        TaskName = $t.TaskName
        TaskPath = $t.TaskPath
        State = if ($t.State) { $t.State.ToString() } else { "Unknown" }
        Actions = $actions
        Triggers = $triggers
    }
}
$report["ScheduledTasks"] = $tasks

$regPaths = @(
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce"
)
$startupReg = @()
foreach ($p in $regPaths) {
    if (Test-Path $p) {
        $props = Get-ItemProperty -Path $p -ErrorAction SilentlyContinue
        if ($props) {
            foreach ($prop in $props.PSObject.Properties) {
                if ($prop.Name -notmatch "^PS|^Class") {
                    $startupReg += [PSCustomObject]@{
                        RegistryPath = $p
                        ValueName = $prop.Name
                        ValueData = $prop.Value
                    }
                }
            }
        }
    }
}
$report["RegistryStartup"] = $startupReg

$winlogon = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -ErrorAction SilentlyContinue
$report["Winlogon"] = [PSCustomObject]@{
    Shell = if ($winlogon) { $winlogon.Shell } else { "N/A" }
    Userinit = if ($winlogon) { $winlogon.Userinit } else { "N/A" }
}

$startupDirs = @(
    "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
    "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
)
$startupFiles = @()
foreach ($dir in $startupDirs) {
    if (Test-Path $dir) {
        Get-ChildItem -Path $dir -ErrorAction SilentlyContinue | ForEach-Object {
            $startupFiles += [PSCustomObject]@{
                Directory = $dir
                FileName = $_.Name
                FullPath = $_.FullName
                Length = $_.Length
                LastWriteTime = $_.LastWriteTime
            }
        }
    }
}
$report["StartupFiles"] = $startupFiles

$appInit1 = (Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" -ErrorAction SilentlyContinue).AppInit_DLLs
$appInit2 = (Get-ItemProperty "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows" -ErrorAction SilentlyContinue).AppInit_DLLs
$report["AppInitDLLs"] = [PSCustomObject]@{
    HKLM = if ($appInit1) { $appInit1 } else { "" }
    WOW6432Node = if ($appInit2) { $appInit2 } else { "" }
}

$wmiConsumers = Get-CimInstance -Namespace root\subscription -ClassName __EventConsumer -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }
$wmiFilters = Get-CimInstance -Namespace root\subscription -ClassName __EventFilter -ErrorAction SilentlyContinue | ForEach-Object { $_.Name }
$report["WMIPersistence"] = [PSCustomObject]@{
    Consumers = $wmiConsumers
    Filters = $wmiFilters
}

$procs = Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.Path } | ForEach-Object {
    $p = $_
    $isSystemPath = ($p.Path -match "^C:\\Windows\\System32" -or $p.Path -match "^C:\\Windows\\SysWOW64")
    $statusStr = "Valid (System)"
    $signerStr = "Microsoft Windows"
    if (-not $isSystemPath) {
        $sig = Get-AuthenticodeSignature -FilePath $p.Path -ErrorAction SilentlyContinue
        if ($sig -and $sig.Status) { $statusStr = $sig.Status.ToString() } else { $statusStr = "Unknown" }
        if ($sig -and $sig.SignerCertificate) { $signerStr = $sig.SignerCertificate.Subject } else { $signerStr = "Unsigned/Unknown" }
    }
    [PSCustomObject]@{
        Id = $p.Id
        ProcessName = $p.ProcessName
        Path = $p.Path
        Status = $statusStr
        Signer = $signerStr
        IsSuspiciousPath = ($p.Path -match "AppData|Temp|ProgramData")
    }
}
$report["Processes"] = $procs

$progDataDirs = Get-ChildItem -Path "C:\ProgramData" -Directory -ErrorAction SilentlyContinue | Select-Object Name, FullName, CreationTime
$susProgDataFiles = Get-ChildItem -Path "C:\ProgramData" -File -Include *.exe,*.dll,*.bat,*.vbs,*.ps1 -ErrorAction SilentlyContinue | Select-Object FullName, Length, CreationTime
$report["ProgramDataDirs"] = $progDataDirs
$report["ProgramDataSusFiles"] = $susProgDataFiles

$cutoff = (Get-Date).AddDays(-60)
$tempExecs = Get-ChildItem -Path $env:TEMP -File -Include *.exe,*.dll,*.bat,*.vbs,*.ps1,*.scr,*.cmd -ErrorAction SilentlyContinue | Where-Object { $_.CreationTime -gt $cutoff } | Select-Object FullName, Length, CreationTime
$report["TempRecentExecutables"] = $tempExecs

$netConns = Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Listen' -or $_.State -eq 'Established' } | Select-Object -First 50 | ForEach-Object {
    $c = $_
    $p = Get-Process -Id $c.OwningProcess -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        LocalAddress = $c.LocalAddress
        LocalPort = $c.LocalPort
        RemoteAddress = $c.RemoteAddress
        RemotePort = $c.RemotePort
        State = if ($c.State) { $c.State.ToString() } else { "Unknown" }
        PID = $c.OwningProcess
        ProcessName = if ($p) { $p.ProcessName } else { "N/A" }
        ProcessPath = if ($p) { $p.Path } else { "N/A" }
    }
}
$report["NetworkConnections"] = $netConns

$hostsPath = "C:\Windows\System32\drivers\etc\hosts"
$hostsContent = if (Test-Path $hostsPath) { Get-Content $hostsPath | Where-Object { $_ -notmatch "^\s*#" -and $_ -match "\S" } } else { @() }
$report["HostsEntries"] = $hostsContent

$proxy = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
$report["ProxySettings"] = [PSCustomObject]@{
    ProxyEnable = if ($proxy) { $proxy.ProxyEnable } else { 0 }
    ProxyServer = if ($proxy) { $proxy.ProxyServer } else { "" }
    AutoConfigURL = if ($proxy) { $proxy.AutoConfigUrl } else { "" }
}

$defenderThreats = Get-MpThreatDetection -ErrorAction SilentlyContinue | Select-Object ThreatID, InitialDetectionTime, ThreatName, Resources, ProcessName
$report["DefenderThreats"] = $defenderThreats

$report | ConvertTo-Json -Depth 5 | Out-File -FilePath "audit_results.json" -Encoding utf8
