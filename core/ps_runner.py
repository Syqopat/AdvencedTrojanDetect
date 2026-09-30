import subprocess
import json

def run_ps_script(ps_script: str):
    cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_script]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=60, encoding='utf-8', errors='replace')
        return res.stdout.strip()
    except Exception as e:
        return f"Error: {str(e)}"

def run_ps_json(ps_script: str):
    raw = run_ps_script(ps_script)
    if not raw:
        return []
    try:
        data = json.loads(raw)
        if isinstance(data, dict):
            return [data]
        return data
    except Exception:
        return []
