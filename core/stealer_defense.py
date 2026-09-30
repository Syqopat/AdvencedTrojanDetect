import os
import glob
from core.ps_runner import run_ps_json

def audit_stealer_threats():
    appdata = os.environ.get("APPDATA", "")
    localappdata = os.environ.get("LOCALAPPDATA", "")

    stealer_findings = []

    leveldb_paths = [
        os.path.join(appdata, "discord", "Local Storage", "leveldb"),
        os.path.join(appdata, "discordcanary", "Local Storage", "leveldb"),
        os.path.join(appdata, "discordptb", "Local Storage", "leveldb"),
        os.path.join(localappdata, "Google", "Chrome", "User Data", "Default", "Local Storage", "leveldb"),
        os.path.join(localappdata, "Microsoft", "Edge", "User Data", "Default", "Local Storage", "leveldb")
    ]

    for l_path in leveldb_paths:
        if os.path.exists(l_path):
            ldb_files = glob.glob(os.path.join(l_path, "*.ldb")) + glob.glob(os.path.join(l_path, "*.log"))
            for f in ldb_files:
                try:
                    with open(f, "r", encoding="utf-8", errors="ignore") as file:
                        c = file.read()
                    if "dQw4w9WgXcQ" in c or "mfa." in c:
                        stealer_findings.append({
                            "Type": "Discord / Browser Encrypted Token Artifact",
                            "Path": f,
                            "Details": "Encrypted token pattern present in storage DB",
                            "IsSuspicious": False
                        })
                except Exception:
                    pass

    return stealer_findings
