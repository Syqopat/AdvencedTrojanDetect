import os
import glob
import re

def audit_discord_injections():
    appdata = os.environ.get("APPDATA", "")
    
    discord_paths = [
        os.path.join(appdata, "discord"),
        os.path.join(appdata, "discordcanary"),
        os.path.join(appdata, "discordptb"),
        os.path.join(appdata, "discorddevelopment")
    ]
    
    results = []

    for d_path in discord_paths:
        if not os.path.exists(d_path):
            continue
        
        variant_name = os.path.basename(d_path)
        pattern = os.path.join(d_path, "*", "modules", "discord_desktop_core*", "index.js")
        index_files = glob.glob(pattern)
        
        pattern_app = os.path.join(d_path, "*", "modules", "discord_desktop_core*", "discord_desktop_core", "index.js")
        index_files.extend(glob.glob(pattern_app))

        if not index_files:
            pattern_recursive = os.path.join(d_path, "**", "index.js")
            index_files.extend(glob.glob(pattern_recursive, recursive=True))

        for idx_file in index_files:
            if "discord_desktop_core" not in idx_file:
                continue
            try:
                with open(idx_file, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                is_injected = False
                reasons = []

                if len(content.strip()) > 300:
                    is_injected = True
                    reasons.append("File size abnormally large")

                suspicious_patterns = [
                    (r"api/webhooks", "Discord Webhook URL detected"),
                    (r"https://[^/]+/api/v\d+/webhooks", "Webhook Exfiltration Endpoint"),
                    (r"discord\.com/api/v\d+/users/@me", "Token Theft API Call"),
                    (r"eval\(", "Obfuscated Eval Execution"),
                    (r"Buffer\.from\(", "Encoded Payload Decoding"),
                    (r"mainWindow\.webContents\.executeJavaScript", "JS Injection into WebContents")
                ]

                for pat, desc in suspicious_patterns:
                    if re.search(pat, content, re.IGNORECASE):
                        if "module.exports = require('./core.asar');" not in content:
                            is_injected = True
                            reasons.append(desc)

                results.append({
                    "Variant": variant_name,
                    "FilePath": idx_file,
                    "IsInjected": is_injected,
                    "Reasons": " ; ".join(reasons) if reasons else "Clean",
                    "ContentLength": len(content)
                })
            except Exception as e:
                results.append({
                    "Variant": variant_name,
                    "FilePath": idx_file,
                    "IsInjected": False,
                    "Reasons": f"Error: {str(e)}",
                    "ContentLength": 0
                })

    return results
