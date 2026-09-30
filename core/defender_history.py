from core.ps_runner import run_ps_json, run_ps_script

def audit_defender():
    script = """
    $threats = Get-MpThreatDetection -ErrorAction SilentlyContinue | ForEach-Object {
        [PSCustomObject]@{
            ThreatID = $_.ThreatID
            InitialDetectionTime = $_.InitialDetectionTime.ToString()
            ThreatName = $_.ThreatName
            Resources = ($_.Resources -join " ; ")
            ProcessName = $_.ProcessName
        }
    }
    $threats | ConvertTo-Json -Depth 3
    """
    threats = run_ps_json(script)
    if isinstance(threats, dict):
        threats = [threats]
    return threats

def trigger_quick_scan():
    script = """
    Start-MpScan -ScanType QuickScan -ErrorAction SilentlyContinue
    $status = Get-MpComputerStatus -ErrorAction SilentlyContinue
    [PSCustomObject]@{
        QuickScanAge = $status.QuickScanAge
        AntivirusEnabled = $status.AntivirusEnabled
        RealTimeProtectionEnabled = $status.RealTimeProtectionEnabled
    } | ConvertTo-Json
    """
    res = run_ps_json(script)
    if isinstance(res, list) and len(res) > 0:
        return res[0]
    return res if isinstance(res, dict) else {}
