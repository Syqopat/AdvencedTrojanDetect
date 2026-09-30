from core.ps_runner import run_ps_json

def audit_directories():
    script = """
    $res = [ordered]@{}
    
    $progDataDirs = Get-ChildItem -Path "C:\\ProgramData" -Directory -ErrorAction SilentlyContinue | ForEach-Object {
        $name = $_.Name
        $isSus = ($name -match "app_config|update|cache|config|temp|system|microsoft_sys")
        [PSCustomObject]@{
            Name = $name
            FullPath = $_.FullName
            CreationTime = $_.CreationTime.ToString()
            IsSuspicious = [bool]$isSus
        }
    }
    $res["ProgramDataDirs"] = $progDataDirs

    $progDataFiles = Get-ChildItem -Path "C:\\ProgramData" -File -Include *.exe,*.dll,*.bat,*.vbs,*.ps1,*.zip,*.rar -ErrorAction SilentlyContinue | ForEach-Object {
        [PSCustomObject]@{
            FullPath = $_.FullName
            Length = $_.Length
            CreationTime = $_.CreationTime.ToString()
            IsHidden = [bool]($_.Attributes -match "Hidden")
        }
    }
    $res["ProgramDataFiles"] = $progDataFiles

    $cutoff = (Get-Date).AddDays(-60)
    $tempExecs = Get-ChildItem -Path $env:TEMP, $env:LOCALAPPDATA -File -Include *.exe,*.dll,*.bat,*.vbs,*.ps1,*.scr,*.cmd -ErrorAction SilentlyContinue | Where-Object { $_.CreationTime -gt $cutoff } | ForEach-Object {
        [PSCustomObject]@{
            FullPath = $_.FullName
            Length = $_.Length
            CreationTime = $_.CreationTime.ToString()
        }
    }
    $res["TempRecentExecutables"] = $tempExecs

    $res | ConvertTo-Json -Depth 4
    """
    data = run_ps_json(script)
    if isinstance(data, list) and len(data) > 0:
        return data[0]
    return data if isinstance(data, dict) else {}
