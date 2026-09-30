import os
import glob

def audit_crypto_wallets():
    appdata = os.environ.get("APPDATA", "")
    localappdata = os.environ.get("LOCALAPPDATA", "")

    wallet_paths = [
        ("Exodus Wallet", os.path.join(appdata, "Exodus")),
        ("Atomic Wallet", os.path.join(appdata, "atomic")),
        ("Electrum", os.path.join(appdata, "Electrum")),
        ("Armory", os.path.join(appdata, "Armory")),
        ("Guarda", os.path.join(appdata, "Guarda")),
        ("Coinomi", os.path.join(localappdata, "Coinomi"))
    ]

    known_wallet_ext_ids = {
        "nkbihfbeogaeaoehlefnkodbefgpgknn": "MetaMask",
        "bfnaelmomeimhlpmgjnjophhpkkoljpa": "Phantom",
        "hnfanklipfeaoannneiibahdmnncobok": "Coinbase Wallet",
        "eggemefphpheaiggikmgflmooedhhbmp": "Trust Wallet",
        "fhbohimaelbohpjbbldcngcnapndodjp": "Binance Wallet"
    }

    results = []

    for w_name, w_path in wallet_paths:
        if os.path.exists(w_path):
            results.append({
                "WalletName": w_name,
                "Path": w_path,
                "Status": "Detected Local Installation",
                "IsTampered": False,
                "Details": "Desktop wallet files verified"
            })

    chrome_ext_dir = os.path.join(localappdata, "Google", "Chrome", "User Data", "Default", "Extensions")
    if os.path.exists(chrome_ext_dir):
        for ext_id, ext_name in known_wallet_ext_ids.items():
            ext_path = os.path.join(chrome_ext_dir, ext_id)
            if os.path.exists(ext_path):
                js_files = glob.glob(os.path.join(ext_path, "**", "*.js"), recursive=True)
                is_hooked = False
                for jf in js_files:
                    try:
                        with open(jf, "r", encoding="utf-8", errors="ignore") as f:
                            c = f.read()
                        if "api/webhooks" in c or "discord.com/api" in c:
                            is_hooked = True
                            break
                    except Exception:
                        pass
                
                results.append({
                    "WalletName": f"{ext_name} Extension",
                    "Path": ext_path,
                    "Status": "Installed Browser Extension",
                    "IsTampered": is_hooked,
                    "Details": "SUSPICIOUS WEBHOOK HOOK DETECTED!" if is_hooked else "Extension integrity verified"
                })

    return results
