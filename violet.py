#!/usr/bin/env python3
# VIOLET v5.0 — command-driven multi-target diagnostics
# Traffic operations are intentionally restricted to 127.0.0.1 / ::1.

import os, sys, json, time, hmac, hashlib, secrets, socket, threading, shlex, select
import urllib.request
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

BASE = os.path.join(os.path.expanduser("~"), ".violet")
DB = os.path.join(BASE, "violet.json")
RESET = "\033[0m"; PURPLE = "\033[38;5;141m"; VIOLET = "\033[38;5;99m"
LILAC = "\033[38;5;183m"; WHITE = "\033[97m"; GREY = "\033[38;5;245m"
GREEN = "\033[38;5;120m"; YELLOW = "\033[38;5;221m"; RED = "\033[38;5;203m"
ROLES = {"viewer": 0, "operator": 1, "admin": 2}
DEFAULTS = {"method": "GET", "max_concurrency": 4, "duration": 10}

def paint(s, color=PURPLE): return color + str(s) + RESET
def prompt(s="violet"): 
    try: return input(paint(f"\n{ s } > ", LILAC)).strip()
    except (EOFError, KeyboardInterrupt): return ":quit"
def password(s):
    import getpass
    try: return getpass.getpass(paint(s, LILAC))
    except Exception: return input(s)

def load():
    os.makedirs(BASE, exist_ok=True)
    try:
        with open(DB, encoding="utf-8") as f: data = json.load(f)
        if isinstance(data, dict):
            data.setdefault("users", {}); data.setdefault("history", [])
            data.setdefault("settings", DEFAULTS.copy()); data.setdefault("quotas", {})
            for k, v in DEFAULTS.items(): data["settings"].setdefault(k, v)
            return data
    except Exception: pass
    return {"users": {}, "history": [], "settings": DEFAULTS.copy(), "quotas": {}}

DATA = load()
def save():
    os.makedirs(BASE, exist_ok=True)
    tmp = DB + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f: json.dump(DATA, f, indent=2)
    os.replace(tmp, DB)

def stamp(): return datetime.now().astimezone().isoformat(timespec="seconds")
def record(event, **fields):
    DATA["history"].append({"time": stamp(), "event": event, **fields})
    DATA["history"] = DATA["history"][-250:]
    save()

def hash_password(pw, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 240000).hex()
    return salt, digest

def verify(pw, user):
    return hmac.compare_digest(hash_password(pw, user["salt"])[1], user["hash"])

def banner():
    os.system("clear" if os.name == "posix" else "cls")
    print(paint(r"""
██╗   ██╗██╗ ██████╗ ██╗     ███████╗████████╗
██║   ██║██║██╔═══██╗██║     ██╔════╝╚══██╔══╝
██║   ██║██║║   ██║██║     █████╗     ██║
╚██╗ ██╔╝██║║   ██║██║     ██╔══╝     ██║
 ╚████╔╝ ██║╚█████╔╝███████╗███████╗   ██║
  ╚═══╝  ╚═╝ ╚════╝ ╚══════╝╚══════╝   ╚═╝"""))
    print(paint(" V I O L E T   //   COMMAND CONSOLE   v5.0", LILAC))
    print(paint(" LOCAL LAB ONLY  •  ROLE CONTROL  •  SESSION TELEMETRY", GREY))
    print(paint("─" * 68, VIOLET))

def first_run():
    if DATA["users"]: return
    banner()
    print(paint("First launch: create the owner account.", YELLOW))
    while True:
        name = input("Owner username: ").strip()
        pw = password("Owner password (12+ characters): ")
        if name and len(pw) >= 12:
            salt, digest = hash_password(pw)
            DATA["users"][name] = {"salt": salt, "hash": digest, "role": "admin", "enabled": True}
            save()
            print(paint("Owner account created. New accounts start as VIEWER.", GREEN))
            return
        print(paint("Enter a username and a password of at least 12 characters.", RED))

def login():
    banner()
    for _ in range(3):
        name = input("Username: ").strip()
        pw = password("Password: ")
        u = DATA["users"].get(name)
        if u and u.get("enabled", True) and verify(pw, u):
            record("login", user=name, role=u["role"])
            return name, u["role"]
        print(paint("Login failed.", RED))
    return None, None

def allowed(role, needed):
    if ROLES.get(role, -1) >= ROLES[needed]: return True
    print(paint(f"Permission denied: {needed} role required.", RED))
    return False

def help_text():
    print(paint("""
COMMANDS
  :help                         Show this command reference
  :settings                     View and adjust methods, concurrency, duration,
                                account keys and role permissions
  :history [count]              Show recent session usage and target statistics
  :users                        List local accounts (admin)
  :user add <name>              Create a viewer account (admin)
  :user role <name> <role>      Set viewer/operator/admin (admin)
  :user enable <name>           Enable an account (admin)
  :user disable <name>          Disable an account (admin)
  :logout                       Log out
  :quit                         Exit VIOLET

LAB COMMANDS — LOOPBACK ONLY
  !l7 [127.0.0.1] [port] [concurrency]
       Bounded HTTP request test against a local web service
  !tcp 127.0.0.1 <port> [concurrency]
       Bounded TCP connection check against a local service

EXAMPLES
  !l7 127.0.0.1 8000 3
  !tcp 127.0.0.1 8080 2

Run options are controlled in :settings. Maximum 25 targets per batch; one check per target.
The concurrency value is capped by the administrator's local settings.
""", LILAC))

def settings(role, current_user):
    while True:
        s = DATA["settings"]
        print(paint("\nSETTINGS", PURPLE))
        print(f"  Default HTTP method : {s['method']}")
        print(f"  Max concurrency     : {s['max_concurrency']}")
        print(f"  Max duration        : {s['duration']} seconds")
        print("  Account keys        : local account passwords are PBKDF2-hashed")
        print("  Permissions         : viewer / operator / admin")
        print(paint("  1 method  2 concurrency  3 duration  4 keys  5 permissions  0 back", GREY))
        q = prompt("violet/settings")
        if q == "0": return
        if q == "1":
            if not allowed(role, "admin"): continue
            val = input("Default method [GET/HEAD]: ").strip().upper()
            if val in ("GET", "HEAD"):
                s["method"] = val; save(); record("setting_changed", setting="method", value=val)
            else: print(paint("Choose GET or HEAD.", RED))
        elif q == "2":
            if not allowed(role, "admin"): continue
            try: val = int(input("Maximum concurrency [1-4]: "))
            except ValueError: val = 0
            if 1 <= val <= 4:
                s["max_concurrency"] = val; save(); record("setting_changed", setting="max_concurrency", value=val)
            else: print(paint("Allowed range is 1-4.", RED))
        elif q == "3":
            if not allowed(role, "admin"): continue
            try: val = int(input("Maximum duration [1-30 seconds]: "))
            except ValueError: val = 0
            if 1 <= val <= 30:
                s["duration"] = val; save(); record("setting_changed", setting="duration", value=val)
            else: print(paint("Allowed range is 1-30.", RED))
        elif q == "4":
            print(paint("KEYS / CREDENTIALS", LILAC))
            print("  Passwords are stored as salted PBKDF2-HMAC-SHA256 hashes.")
            print("  1 change my password   2 list account access (admin)   0 back")
            action = input("Select: ").strip()
            if action == "1":
                old_pw = password("Current password: ")
                user_record = DATA["users"].get(current_user, {})
                if not user_record or not verify(old_pw, user_record):
                    print(paint("Current password is incorrect.", RED)); continue
                new_pw = password("New password (12+ characters): ")
                if len(new_pw) < 12:
                    print(paint("Password must be at least 12 characters.", RED)); continue
                salt, digest = hash_password(new_pw)
                user_record["salt"], user_record["hash"] = salt, digest
                save(); record("password_changed", user=current_user)
                print(paint("Password updated.", GREEN))
            elif action == "2" and allowed(role, "admin"):
                for n, u in DATA["users"].items():
                    print(f"   {n:<20} {u['role']:<10} {'enabled' if u.get('enabled') else 'disabled'}")
        elif q == "5":
            print(paint("ROLE PERMISSIONS", LILAC))
            print("  viewer   : help, settings view, account-independent commands")
            print("  operator : viewer + localhost lab commands + session history")
            print("  admin    : operator + account and configuration management")
            print("  New accounts are viewer by default. Only an admin can grant roles.")
        else: print(paint("Unknown setting.", RED))


def valid_target(host):
    # Accept IP addresses and DNS names for ordinary one-shot diagnostics.
    import ipaddress, re
    host = host.strip()
    if not host or len(host) > 253 or any(c in host for c in "/?#@"):
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(re.fullmatch(r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*", host))

def run_lab(kind, args, role, username):
    if not allowed(role, "operator"): return
    if kind == "l7":
        if not args:
            print(paint("Usage: !l7 host[,host...] [port] [concurrency]", YELLOW)); return
        targets_arg = args[0]
        try: port = int(args[1]) if len(args) >= 2 else 80
        except ValueError: print(paint("Port must be a number.", RED)); return
        try: requested_workers = int(args[2]) if len(args) >= 3 else 2
        except ValueError: print(paint("Concurrency must be a number.", RED)); return
    else:
        if len(args) < 2:
            print(paint("Usage: !tcp host[,host...] <port> [concurrency]", YELLOW)); return
        targets_arg = args[0]
        try: port = int(args[1])
        except ValueError: print(paint("Port must be a number.", RED)); return
        try: requested_workers = int(args[2]) if len(args) >= 3 else 2
        except ValueError: print(paint("Concurrency must be a number.", RED)); return

    targets = list(dict.fromkeys(x.strip() for x in targets_arg.split(",") if x.strip()))
    if not targets:
        print(paint("Enter at least one target.", RED)); return
    if len(targets) > 25:
        print(paint("Maximum 25 targets per diagnostic batch.", RED)); return
    invalid = [t for t in targets if not valid_target(t)]
    if invalid:
        print(paint("Invalid target(s): " + ", ".join(invalid), RED)); return
    if not 1 <= port <= 65535:
        print(paint("Port must be between 1 and 65535.", RED)); return

    settings_data = DATA["settings"]
    workers = max(1, min(requested_workers, int(settings_data["max_concurrency"]), len(targets)))
    method = settings_data["method"]
    duration = int(settings_data["duration"])
    print(paint("\nMULTI-TARGET DIAGNOSTIC", PURPLE))
    print(f"Targets: {len(targets)}  |  Port: {port}  |  Concurrency: {workers}")
    print(f"Mode: {kind.upper()}  |  Method: {method if kind == 'l7' else 'TCP_CONNECT'}")
    print(paint("One bounded check per target; no repeated request loop or packet flood.", GREY))
    print(paint("Only test systems you own or are explicitly authorized to assess.", YELLOW))
    if input("Type RUN to confirm this authorized diagnostic batch: ").strip() != "RUN":
        print(paint("Cancelled.", YELLOW)); return

    lock = threading.Lock()
    stop = threading.Event()
    results = []
    started = time.monotonic()

    def check(host):
        t0 = time.monotonic()
        row = {"target": f"{host}:{port}", "status": "ERROR", "latency_ms": 0.0, "detail": ""}
        try:
            if kind == "tcp":
                addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
                last_error = None
                connected = False
                for family, socktype, proto, _, sockaddr in addresses:
                    if stop.is_set(): break
                    sock = socket.socket(family, socktype, proto)
                    sock.settimeout(min(3.0, max(1, duration)))
                    try:
                        sock.connect(sockaddr)
                        connected = True
                        sock.close()
                        break
                    except OSError as e:
                        last_error = e
                        sock.close()
                if connected:
                    row["status"] = "OPEN"
                    row["detail"] = "TCP connection established"
                else:
                    row["detail"] = str(last_error or "Connection failed")
            else:
                scheme = "https" if port == 443 else "http"
                url = f"{scheme}://{host}:{port}/"
                req = urllib.request.Request(url, method=method,
                    headers={"User-Agent": "VIOLET-Diagnostic/5.0"})
                with urllib.request.urlopen(req, timeout=min(4.0, max(1, duration))) as response:
                    row["status"] = f"HTTP {response.status}"
                    row["detail"] = response.reason or "Response received"
                    if method == "GET":
                        response.read(1024)
        except Exception as e:
            row["detail"] = str(e)[:140]
        row["latency_ms"] = round((time.monotonic() - t0) * 1000, 2)
        with lock:
            results.append(row)
            print(paint(f"\n[{row['status']}] {row['target']}  {row['latency_ms']:.1f}ms  {row['detail']}", GREEN if row["status"] in ("OPEN", "HTTP 200") else YELLOW))

    print(paint("Running checks... press ENTER or type stop + ENTER to cancel queued checks.", GREY))
    pool = ThreadPoolExecutor(max_workers=workers)
    futures = [pool.submit(check, host) for host in targets]
    try:
        while any(not f.done() for f in futures):
            ready, _, _ = select.select([sys.stdin], [], [], 0.15)
            if ready:
                line = sys.stdin.readline()
                if line == "" or line.strip().lower() in ("", "stop", "q", "quit"):
                    stop.set()
                    break
    except KeyboardInterrupt:
        stop.set()
    finally:
        if stop.is_set():
            for f in futures: f.cancel()
        pool.shutdown(wait=True, cancel_futures=True)

    elapsed = round(time.monotonic() - started, 2)
    results.sort(key=lambda x: x["target"])
    success = sum(1 for r in results if r["status"] == "OPEN" or r["status"].startswith("HTTP "))
    errors = len(results) - success
    report = {
        "user": username, "kind": kind, "targets": [r["target"] for r in results],
        "target_count": len(targets), "port": port,
        "method": method if kind == "l7" else "TCP_CONNECT",
        "concurrency": workers, "duration_s": elapsed,
        "sent": len(results), "ok": success, "errors": errors,
        "bytes": 0, "avg_latency_ms": round(sum(r["latency_ms"] for r in results) / len(results), 2) if results else 0,
        "min_latency_ms": min((r["latency_ms"] for r in results), default=0),
        "max_latency_ms": max((r["latency_ms"] for r in results), default=0),
        "results": results, "stopped_early": stop.is_set()
    }
    DATA["history"].append({"time": stamp(), "event": "lab_run", **report})
    DATA["history"] = DATA["history"][-250:]
    save()
    print(paint("\n" + "─" * 68, VIOLET))
    print(paint(" BATCH SESSION REPORT", PURPLE))
    print(f"  Targets checked : {len(results)}/{len(targets)}")
    print(f"  Successful      : {success}")
    print(f"  Errors          : {errors}")
    print(f"  Method          : {report['method']}")
    print(f"  Concurrency     : {workers}")
    print(f"  Elapsed         : {elapsed}s")
    print(f"  Average latency : {report['avg_latency_ms']} ms")
    print(f"  Stopped early   : {'yes' if stop.is_set() else 'no'}")
    print(paint("Saved to :history.", GREEN))

def show_history(role, args):
    if not allowed(role, "operator"): return
    try: count = max(1, min(50, int(args[0]))) if args else 15
    except ValueError: count = 15
    print(paint("\nSESSION HISTORY / USAGE TELEMETRY", PURPLE))
    entries = [x for x in DATA["history"] if x.get("event") == "lab_run"][-count:]
    if not entries: print(paint("No lab sessions recorded yet.", GREY)); return
    for x in entries:
        print(paint(f"\n{x['time']}  {x['kind'].upper()}  {x['target']}", LILAC))
        print(f"  method={x['method']}  concurrency={x['concurrency']}  duration={x['duration_s']}s")
        print(f"  sent={x['sent']}  ok={x['ok']}  errors={x['errors']}  bytes={x['bytes']}")
        print(f"  latency avg/min/max={x['avg_latency_ms']}/{x['min_latency_ms']}/{x['max_latency_ms']} ms")
        for item in x.get("results", []):
            print(f"    {item['target']:<28} {item['status']:<12} {item['latency_ms']}ms")

def user_command(role, args, current):
    if not allowed(role, "admin"): return
    if len(args) < 2: print("Usage: :user add <name> | :user role <name> <role> | :user enable/disable <name>"); return
    action, name = args[0].lower(), args[1]
    if action == "add":
        if name in DATA["users"]: print(paint("User already exists.", RED)); return
        pw = password("Temporary password (12+ chars): ")
        if len(pw) < 12: print(paint("Password too short.", RED)); return
        salt, digest = hash_password(pw)
        DATA["users"][name] = {"salt": salt, "hash": digest, "role": "viewer", "enabled": True}
        save(); record("user_created", user=name, role="viewer")
        print(paint("Created as viewer.", GREEN))
    elif action == "role" and len(args) >= 3:
        new_role = args[2].lower()
        if name == current or name not in DATA["users"] or new_role not in ROLES:
            print(paint("Invalid user/role or self-role change blocked.", RED)); return
        if new_role == "admin" and input("Type PROMOTE to confirm: ") != "PROMOTE": return
        DATA["users"][name]["role"] = new_role; save(); record("role_changed", user=name, role=new_role)
        print(paint("Role updated.", GREEN))
    elif action in ("enable", "disable"):
        if name == current or name not in DATA["users"]: print(paint("Unknown user or self-change blocked.", RED)); return
        DATA["users"][name]["enabled"] = action == "enable"; save(); record("user_status", user=name, enabled=action == "enable")
        print(paint("Account status updated.", GREEN))
    else: print("Unknown user command.")

def main():
    first_run()
    username, role = login()
    if not username: print(paint("Authentication failed.", RED)); return
    print(paint(f"\nAuthenticated: {username}  |  role={role.upper()}", GREEN))
    print(paint("Type :help for commands. No menu is displayed.", GREY))
    while True:
        raw = prompt(f"{username}@violet")
        if not raw: continue
        try: parts = shlex.split(raw)
        except ValueError: print(paint("Invalid command syntax.", RED)); continue
        cmd, args = parts[0].lower(), parts[1:]
        if cmd in (":quit", ":logout"):
            record("logout", user=username)
            if cmd == ":quit": break
            username, role = login()
            if not username: break
        elif cmd == ":help": help_text()
        elif cmd == ":settings": settings(role, username)
        elif cmd == ":history": show_history(role, args)
        elif cmd == ":users":
            if allowed(role, "admin"):
                for n, u in DATA["users"].items(): print(f"{n:<20} {u['role']:<10} {'enabled' if u.get('enabled') else 'disabled'}")
        elif cmd == ":user": user_command(role, args, username)
        elif cmd == "!l7": run_lab("l7", args, role, username)
        elif cmd == "!tcp": run_lab("tcp", args, role, username)
        else: print(paint("Unknown command. Type :help.", RED))

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt:
        save()
        print(paint("\nVIOLET closed. Session data saved.", GREY))
