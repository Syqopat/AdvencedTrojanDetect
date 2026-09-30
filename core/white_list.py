import os

KNOWN_LEGIT_PROCESSES = {
    "robloxplayerbeta.exe", "robloxlauncher.exe", "steam.exe", "steamwebhelper.exe",
    "riotclientservices.exe", "vgtray.exe", "valorant-win64-shipping.exe", "leagueclient.exe",
    "javaw.exe", "minecraftlauncher.exe", "epicgameslauncher.exe", "bluestacksservices.exe",
    "bluestackshelper.exe", "sldworks.exe", "discord.exe", "discordcanary.exe", "discordptb.exe",
    "spotify.exe", "ollama.exe", "tailscale.exe", "chrome.exe", "msedge.exe", "firefox.exe",
    "brave.exe", "opera.exe", "vivaldi.exe", "antigravity.exe", "antigravity ide.exe", "python.exe",
    "code.exe", "git.exe", "bash.exe", "rtkauduserveice64.exe", "lghub_system_tray.exe",
    "claude.exe", "curseforge.exe", "curse.agent.host.exe", "language_server.exe",
    "opencode-cli.exe", "zcode.exe", "node.exe", "electron.exe"
}

KNOWN_LEGIT_PATHS = [
    r"c:\program files",
    r"c:\program files (x86)",
    r"c:\windows\system32",
    r"c:\windows\syswow64",
    r"c:\windows\winsxs"
]

def is_whitelisted_process(p_name: str, p_path: str) -> bool:
    if not p_name:
        return False
    
    name_lower = p_name.strip().lower()
    if not name_lower.endswith(".exe"):
        name_lower += ".exe"
        
    if name_lower in KNOWN_LEGIT_PROCESSES:
        return True

    if p_path:
        path_lower = p_path.strip().lower()
        for legit_dir in KNOWN_LEGIT_PATHS:
            if path_lower.startswith(legit_dir):
                return True
        if "appdata\\local\\programs" in path_lower or "appdata\\local\\discord" in path_lower or "appdata\\local\\roblox" in path_lower or "appdata\\local\\openclaw" in path_lower:
            return True

    return False
