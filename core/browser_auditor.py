import os
import glob
import json

def audit_browser_security():
    localappdata = os.environ.get("LOCALAPPDATA", "")
    appdata = os.environ.get("APPDATA", "")

    browser_dirs = [
        ("Google Chrome", os.path.join(localappdata, "Google", "Chrome", "User Data")),
        ("Microsoft Edge", os.path.join(localappdata, "Microsoft", "Edge", "User Data")),
        ("Brave", os.path.join(localappdata, "BraveSoftware", "Brave-Browser", "User Data")),
        ("Opera", os.path.join(appdata, "Opera Software", "Opera Stable")),
        ("Vivaldi", os.path.join(localappdata, "Vivaldi", "User Data"))
    ]

    results = []

    for name, path in browser_dirs:
        if not os.path.exists(path):
            continue

        ext_pattern = os.path.join(path, "*", "Extensions", "*", "*", "manifest.json")
        manifests = glob.glob(ext_pattern)

        for m_path in manifests:
            try:
                with open(m_path, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)
                
                ext_name = data.get("name", "Unknown Extension")
                permissions = data.get("permissions", [])
                
                has_web_request = any("webRequest" in p for p in permissions if isinstance(p, str))
                has_all_urls = any("<all_urls>" in p or "*://*/*" in p for p in permissions if isinstance(p, str))

                if has_web_request and has_all_urls:
                    results.append({
                        "Browser": name,
                        "ExtensionName": ext_name,
                        "ManifestPath": m_path,
                        "IsSuspicious": True,
                        "Details": "Extension possesses global network interception & webRequest permissions"
                    })
            except Exception:
                pass

    return results
