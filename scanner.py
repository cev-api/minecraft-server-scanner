# === Minecraft Scanner by Cev-API ===

import shodan
import socket
import struct
import json
import re
import os
import time
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import init, Fore, Style
import nbtlib
from nbtlib import Compound, String, Byte

# Hide console window
if os.name == "nt": __import__("ctypes").windll.user32.ShowWindow(__import__("ctypes").windll.kernel32.GetConsoleWindow(), 0)

# Tkinter + threading
import tkinter as tk  
from tkinter import ttk, filedialog, messagebox, simpledialog  
import threading  

import base64  
import io      
try:
    from PIL import Image, ImageTk  
    _PIL_AVAILABLE = True
except Exception:
    _PIL_AVAILABLE = False
import hashlib
import uuid

init(autoreset=True)

SHODAN_KEY_PATH = os.path.join(os.getcwd(), "shodan_key.txt")
GLOBAL_IP_LOG = "ips.txt"
TIMEOUT = 3
PROTOCOL_VERSION = 772
MAX_WORKERS = 100
SERVERS_DAT_PATH = os.path.expandvars(r"%APPDATA%\.minecraft\servers.dat")
BACKUP_PATH = SERVERS_DAT_PATH + ".bak"

IGNORE_FILE = "ignore.txt"
SAVED_FILE = "saved.txt"
DEFAULT_JSONL_FILE = "minecraft_servers.json"
USER_LOG_FILE = "user_log.json"
SERVER_MONITOR_FILE = "server_monitor_log.json"
DEFAULT_MONITOR_INTERVAL = 60

ICON_ENABLED = True           
ICON_SIZE = 24                
ICON_COL_EXTRA_PAD = 24       
ICON_FETCH_TIMEOUT = 2        
ICON_THREADS = 10             
ICON_PLACEHOLDER = "#ffffff"  


# ========================================

def _load_key_from_cwd():
    if os.path.exists(SHODAN_KEY_PATH):
        with open(SHODAN_KEY_PATH, "r", encoding="utf-8") as f:
            k = f.readline().strip()
            return k or None
    return None

def _save_key_to_cwd(k: str):
    with open(SHODAN_KEY_PATH, "w", encoding="utf-8") as f:
        f.write(k.strip() + "\n")

def ensure_shodan_key_ui(parent) -> str | None:
    """
    Main-thread only. If no key file exists, prompt the user and save it.
    Returns the key or None if the user cancels.
    """
    key = _load_key_from_cwd()
    if key:
        return key
    key = simpledialog.askstring(
        "Shodan API Key",
        "Enter your Shodan API key:",
        parent=parent,
        show="*"  # hides the text while typing
    )
    if key:
        _save_key_to_cwd(key)
        return key.strip()
    return None

# ========================================

def _extract_ip_port_from_text(s):
    m = re.search(r'([0-9a-zA-Z\.\-]+):([0-9]{1,5})', s.strip())
    if not m:
        return None
    return f"{m.group(1)}:{int(m.group(2))}"

def load_ignore_set():
    s = set()
    if os.path.exists(IGNORE_FILE):
        with open(IGNORE_FILE, "r", encoding="utf-8") as f:
            for line in f:
                ip_port = _extract_ip_port_from_text(line)
                if ip_port:
                    s.add(ip_port)
    return s

IGNORE_SET = load_ignore_set()

def is_ignored(ip_port):
    return ip_port in IGNORE_SET

def refresh_ignore_set(ip_port_added=None):  #
    global IGNORE_SET
    if ip_port_added:
        IGNORE_SET.add(ip_port_added)
    else:
        IGNORE_SET = load_ignore_set()

# ========================================

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def ask_yes_no(prompt):
    return input(f"{prompt} (y/n): ").strip().lower().startswith('y')

def sanitize_query_for_filename(query):
    return re.sub(r'[^a-zA-Z0-9]+', '_', query.strip().lower()).strip('_')

def is_valid_ip_port(entry):
    return re.match(r"^\d{1,3}(\.\d{1,3}){3}:\d{1,5}$", entry)

def get_ip_only(line_or_ip):  #
    if " |" in line_or_ip:
        line_or_ip = line_or_ip.split(" |")[0]
    return _extract_ip_port_from_text(line_or_ip) or line_or_ip

# Common formatter so all tabs show exactly the same line format
def format_result_line(ip_port, motd, players_online, players_max, version):  #
    return f"{ip_port} | MOTD: {sanitize_motd(motd)} | Players: {players_online}/{players_max} | Version: {version}"

# Sorting helpers for Treeviews
def _players_key(val):  # "6/73" -> 6
    try:
        return int(str(val).split("/", 1)[0])
    except:
        return -1

def _ip_key(val):  # "a.b.c.d:port" -> (a,b,c,d,port)
    s = str(val)
    try:
        host, port = s.split(":")
        port = int(port)
    except:
        host, port = s, 0
    parts = host.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        try:
            return tuple(int(p) for p in parts) + (port,)
        except:
            return (0, 0, 0, 0, port)
    return (999, 999, 999, 999, str(host), port)

def _version_key(val):  # "1.21.1" -> (1,21,1)
    t = []
    for token in str(val).strip().split("."):
        if token.isdigit():
            t.append(int(token))
        else:
            nums = re.findall(r'\d+', token)
            t.extend(int(n) for n in nums) if nums else t.append(0)
    return tuple(t) if t else (0,)

def make_tree_sortable(tree, column_key_funcs):  #
    sort_state = {}  # col -> bool

    def sort_by(col):
        reverse = sort_state.get(col, False)
        rows = [(column_key_funcs.get(col, str)(tree.set(iid, col)), iid) for iid in tree.get_children("")]
        rows.sort(reverse=reverse)
        for idx, (_, iid) in enumerate(rows):
            tree.move(iid, "", idx)
        sort_state[col] = not reverse

    for col in tree["columns"]:
        tree.heading(col, command=lambda c=col: sort_by(c))

# Robust parser for "IP | MOTD: ... | Players: x/y | Version: ..."
def parse_formatted_line(line):  #
    ip = get_ip_only(line)
    motd = ""
    players = ""
    version = ""
    try:
        m_motd = re.search(r"\bMOTD:\s*(.*?)\s*\|\s*Players:", line)
        if m_motd:
            motd = m_motd.group(1).strip()
        m_pl = re.search(r"\bPlayers:\s*([^|]+)", line)
        if m_pl:
            players = m_pl.group(1).strip()
        m_ver = re.search(r"\bVersion:\s*(.*)$", line)
        if m_ver:
            version = m_ver.group(1).strip()
    except:
        pass
    return ip, motd, players, version
    
def sanitize_motd(m):
    m = "" if m is None else str(m)
    m = re.sub(r"§[0-9A-FK-ORa-fk-or]", "", m)  # strip legacy MC color/style codes
    return re.sub(r"\s+", " ", m.replace("\r", " ").replace("\n", " ")).strip()


# ==================== SHODAN ====================

def get_user_query():
    user_input = input('\nEnter Shodan Search Query (excluding "minecraft"): ').strip()
    if user_input.lower().startswith("minecraft"):
        user_input = user_input[len("minecraft"):].strip()
    full_query = f"minecraft {user_input}"
    return full_query

def search_shodan(query, api_key):
    api = shodan.Shodan(api_key)
    try:
        results = api.search(query)
        return results.get('matches', [])
    except shodan.APIError as e:
        # Let caller decide how to handle (invalid key, rate limit, etc.)
        raise


def parse_description_from_raw(data_string):
    desc_match = re.search(r"Description:\s*(.*?)\s*Online Players:", data_string, re.DOTALL)
    return sanitize_motd(desc_match.group(1).strip() if desc_match else "N/A")

def parse_players(data_string):
    match = re.search(r"Online Players:\s*(\d+)\s*Maximum Players:\s*(\d+)", data_string)
    if match:
        return f"{match.group(1)}/{match.group(2)}"
    return "N/A"

def parse_version(data_string):
    match = re.search(r"Version:\s*(.*?)\s*\(", data_string)
    return match.group(1).strip() if match else "N/A"

def save_shodan_results(servers, filepath):
    ip_set = set()
    skipped_ignored = 0
    with open(filepath, "w", encoding="utf-8") as f:
        for server in servers:
            ip = server.get("ip_str")
            port = server.get("port", 25565)
            data = server.get("data", "")

            motd = parse_description_from_raw(data)
            players = parse_players(data)
            version = parse_version(data)
            ip_port = f"{ip}:{port}"

            if is_ignored(ip_port):
                skipped_ignored += 1
                continue
            ip_set.add(ip_port)
            line = f"{ip_port} | MOTD: {motd} | Players: {players} | Version: {version}"
            f.write(line + "\n")

    update_global_ip_log(ip_set)
    if skipped_ignored:
        print(Fore.YELLOW + f"Skipped {skipped_ignored} ignored entrie(s).")

def update_global_ip_log(new_entries):
    updated_lines = {}
    if os.path.exists(GLOBAL_IP_LOG):
        with open(GLOBAL_IP_LOG, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    ip = line.strip().split(' |')[0]
                    updated_lines[ip] = line.strip()

    for entry in new_entries:
        if entry not in updated_lines and not is_ignored(entry):
            updated_lines[entry] = f"{entry} | MOTD: N/A | Players: N/A | Version: N/A"

    with open(GLOBAL_IP_LOG, 'w', encoding='utf-8') as f:
        for line in sorted(updated_lines.values()):
            f.write(line + "\n")

def read_servers(file):
    with open(file, 'r', encoding='utf-8') as f:
        return [line.strip().split(" |")[0] for line in f if line.strip()]

def split_host_port(entry):
    match = re.match(r'^([0-9a-zA-Z\.\-]+):([0-9]+)', entry.strip())
    if match:
        return match.group(1), int(match.group(2))
    raise ValueError(f"Invalid entry format: {entry}")

# ==================== PING ====================

def varint_encode(number):
    out = bytearray()
    while True:
        temp = number & 0b01111111
        number >>= 7
        if number != 0:
            temp |= 0b10000000
        out.append(temp)
        if number == 0:
            break
    return bytes(out)

def write_string(s):
    encoded = s.encode('utf-8')
    return varint_encode(len(encoded)) + encoded

def varint_decode(sock):
    number = 0
    for i in range(5):
        byte = sock.recv(1)
        if not byte:
            raise IOError("Socket closed")
        byte = byte[0] 
        number |= (byte & 0x7F) << (7 * i)
        if not (byte & 0x80):
            break
    return number

def parse_description(desc):
    if isinstance(desc, str):
        return sanitize_motd(desc)
    elif isinstance(desc, dict):
        if 'text' in desc:
            return sanitize_motd(desc['text'])
        elif 'extra' in desc:
            return sanitize_motd(''.join([x.get('text', '') for x in desc['extra']]))
    return ''

def ping_server(entry):
    try:
        host, port = split_host_port(entry)
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            sock.settimeout(TIMEOUT)

            handshake = (
                varint_encode(0x00) +
                varint_encode(PROTOCOL_VERSION) +
                write_string(host) +
                struct.pack('>H', port) +
                varint_encode(1)
            )
            sock.send(varint_encode(len(handshake)) + handshake)
            sock.send(varint_encode(1) + b'\x00')

            _ = varint_decode(sock)
            _ = varint_decode(sock)
            json_length = varint_decode(sock)
            data = sock.recv(json_length).decode('utf-8')
            response = json.loads(data)

            motd = parse_description(response.get('description', ''))
            players = response.get('players', {}).get('online', 0)
            max_players = response.get('players', {}).get('max', 0)
            # sample is a list of dicts like {"id": "uuid", "name": "playername"}
            sample = response.get('players', {}).get('sample', []) or []

            # Normalize sample to list of tuples (id, name)
            players_sample = []
            for p in sample:
                try:
                    pid = str(p.get('id') or "")
                    pname = str(p.get('name') or "")
                    players_sample.append((pid, pname))
                except Exception:
                    continue

            # cracked detection: if any reported player id matches the offline-mode UUID for that name
            def _offline_uuid_for_name(name: str) -> str:
                # Replicate Java's UUID.nameUUIDFromBytes("OfflinePlayer:" + name)
                h = hashlib.md5()
                h.update(b"OfflinePlayer:")
                h.update(name.encode('utf-8'))
                d = bytearray(h.digest())
                # set variant and version bits like Java's nameUUIDFromBytes (version 3)
                d[6] = (d[6] & 0x0f) | 0x30
                d[8] = (d[8] & 0x3f) | 0x80
                return str(uuid.UUID(bytes=bytes(d)))

            cracked = False
            for pid, pname in players_sample:
                if not pname:
                    continue
                try:
                    off_uuid = _offline_uuid_for_name(pname).replace('-', '').lower()
                    reported = pid.replace('-', '').lower()
                    if reported == off_uuid:
                        cracked = True
                        break
                except Exception:
                    continue

            return {
                'ip': f"{host}:{port}",
                'players': players,
                'max_players': max_players,
                'motd': motd,
                'version': response.get('version', {}).get('name', 'N/A'),
                'players_sample': players_sample,
                'cracked': cracked
            }
    except:
        return None

def format_player_list(sample):
    """
    Returns a comma-separated string of player names from the sample, or "-" if none.
    """
    names = []
    for item in sample or []:
        name = None
        if isinstance(item, (list, tuple)) and len(item) >= 2:
            name = item[1]
        elif isinstance(item, dict):
            name = item.get("name")
        if isinstance(name, str) and name.strip():
            names.append(name.strip())
    return ", ".join(names) if names else "-"


class UserLogManager:
    """
    Thread-safe store that tracks the last seen server for each player name.
    """
    def __init__(self):
        self._entries = {}  # player -> {"ip": ..., "motd": ..., "last_seen": ts}
        self._lock = threading.Lock()
        self._tab = None
        self._load_from_disk()

    def attach_tab(self, tab: "UserLogTab"):
        self._tab = tab
        tab.bind_manager(self)
        tab.request_refresh(initial=True)

    def snapshot(self):
        with self._lock:
            return [
                {
                    "player": player,
                    "ip": data["ip"],
                    "motd": data["motd"],
                    "last_seen": data["last_seen"]
                }
                for player, data in self._entries.items()
            ]

    def update_from_result(self, result: dict):
        sample = result.get("players_sample") or []
        if not sample:
            return
        ip = result.get("ip", "")
        motd = result.get("motd", "")
        now = time.time()
        changed = False
        with self._lock:
            for _pid, pname in sample:
                player = (pname or "").strip()
                if not player:
                    continue
                entry = self._entries.get(player)
                if not entry or entry["ip"] != ip or entry["motd"] != motd:
                    self._entries[player] = {"ip": ip, "motd": motd, "last_seen": now}
                else:
                    self._entries[player]["last_seen"] = now
                changed = True
        if changed:
            self._save_to_disk()
            self._notify_tab()

    def _notify_tab(self):
        if self._tab:
            self._tab.request_refresh()

    def _load_from_disk(self):
        if not os.path.exists(USER_LOG_FILE):
            return
        try:
            with open(USER_LOG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return
        if not isinstance(data, list):
            return
        entries = {}
        for row in data:
            try:
                player = (row.get("player") or "").strip()
                if not player:
                    continue
                ip = row.get("ip") or ""
                motd = row.get("motd") or ""
                ts = float(row.get("last_seen") or 0)
                entries[player] = {"ip": ip, "motd": motd, "last_seen": ts}
            except Exception:
                continue
        with self._lock:
            self._entries = entries

    def _save_to_disk(self):
        snapshot = self.snapshot()
        try:
            with open(USER_LOG_FILE, "w", encoding="utf-8") as f:
                json.dump(snapshot, f, indent=2)
        except Exception:
            pass


USER_LOG_MANAGER = UserLogManager()

def fetch_server_favicon_bytes(entry):  # returns raw PNG bytes or None
    try:
        host, port = split_host_port(entry)
        with socket.create_connection((host, port), timeout=ICON_FETCH_TIMEOUT) as sock:
            sock.settimeout(ICON_FETCH_TIMEOUT)
            handshake = (
                varint_encode(0x00) +
                varint_encode(PROTOCOL_VERSION) +
                write_string(host) +
                struct.pack('>H', port) +
                varint_encode(1)
            )
            sock.send(varint_encode(len(handshake)) + handshake)
            sock.send(varint_encode(1) + b'\x00')
            _ = varint_decode(sock)
            _ = varint_decode(sock)
            json_length = varint_decode(sock)
            data = sock.recv(json_length).decode('utf-8')
            response = json.loads(data)
            fav = response.get('favicon')
            if isinstance(fav, str) and fav.startswith('data:image'):
                b64 = fav.split(',', 1)[1]
                return base64.b64decode(b64)
    except Exception:
        pass
    return None

# GUI-friendly scan with streaming callbacks
def scan_servers_gui(servers, on_start=None, on_result=None, on_progress=None):
    filtered = [s for s in servers if not is_ignored(s)]
    results, online_lines, updated_ips = [], [], {}
    total, done = len(filtered), 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        def task(ip):
            if on_start:
                try: on_start(ip)
                except Exception: pass
            return ping_server(ip)

        futures = {executor.submit(task, s): s for s in filtered}

        for fut in as_completed(futures):
            r = fut.result()
            done += 1

            if r:
                results.append(r)
                ip_key = r['ip']
                line = f"{ip_key} | MOTD: {r['motd']} | Players: {r['players']}/{r['max_players']} | Version: {r['version']}"
                updated_ips[ip_key] = line
                if r['players'] > 0:
                    online_lines.append(line)
                USER_LOG_MANAGER.update_from_result(r)
                if on_result:
                    try: on_result(r, line)
                    except Exception: pass

            if on_progress:
                try: on_progress(done, total)
                except Exception: pass

    existing = {}
    if os.path.exists(GLOBAL_IP_LOG):
        with open(GLOBAL_IP_LOG, 'r', encoding='utf-8') as f:
            for line in f:
                if line.strip():
                    ip = line.strip().split(' |')[0]
                    existing[ip] = line.strip()
    existing.update({k: v for k, v in updated_ips.items() if not is_ignored(k)})

    with open(GLOBAL_IP_LOG, 'w', encoding='utf-8') as f:
        for line in sorted(existing.values()):
            f.write(line + "\n")

    return results, online_lines

# ==================== Server Monitor State ====================

def load_server_monitor_state():
    if not os.path.exists(SERVER_MONITOR_FILE):
        return {"servers": {}}
    try:
        with open(SERVER_MONITOR_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {"servers": {}}
    if not isinstance(data, dict):
        return {"servers": {}}
    data.setdefault("servers", {})
    return data

def save_server_monitor_state(state):
    try:
        with open(SERVER_MONITOR_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
    except Exception:
        pass

def _ensure_monitor_server_entry(state, ip):
    if "servers" not in state:
        state["servers"] = {}
    entries = state["servers"]
    if ip not in entries:
        entries[ip] = {
            "ip": ip,
            "motd": "",
            "last_status": "unknown",
            "last_ping": 0,
            "players_online": 0,
            "max_players": 0,
            "version": "N/A",
            "cracked": False,
            "player_log": {}
        }
    return entries[ip]

def update_server_monitor_entry(state, ip, result, timestamp):
    entry = _ensure_monitor_server_entry(state, ip)
    entry["motd"] = result.get("motd", "")
    entry["version"] = result.get("version", "N/A")
    entry["players_online"] = result.get("players", 0)
    entry["max_players"] = result.get("max_players", 0)
    entry["last_status"] = "online"
    entry["last_ping"] = timestamp
    entry["cracked"] = bool(result.get("cracked"))
    sample = result.get("players_sample") or []
    log = entry.setdefault("player_log", {})
    for player_id, player_name in sample:
        uid = (player_id or "").strip()
        name = (player_name or "").strip()
        if not uid or not name:
            continue
        log[uid] = {"name": name, "last_seen": timestamp}

def mark_server_offline_in_state(state, ip, timestamp):
    entry = _ensure_monitor_server_entry(state, ip)
    entry["last_status"] = "offline"
    entry["last_ping"] = timestamp

def format_timestamp(ts):
    if not ts:
        return "n/a"
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    except Exception:
        return str(ts)

SERVER_MONITOR_TAB_INSTANCE = None

def register_monitor_tab(tab):
    global SERVER_MONITOR_TAB_INSTANCE
    SERVER_MONITOR_TAB_INSTANCE = tab

def add_ips_to_monitor_list(ips):
    if not ips:
        return 0, 0, 0
    state = load_server_monitor_state()
    added = 0
    invalid = 0
    duplicates = 0
    for raw in ips:
        ip = get_ip_only(raw)
        if not ip or not is_valid_ip_port(ip):
            invalid += 1
            continue
        if ip in state.get("servers", {}):
            duplicates += 1
            continue
        _ensure_monitor_server_entry(state, ip)
        added += 1
    if added:
        save_server_monitor_state(state)
        if SERVER_MONITOR_TAB_INSTANCE:
            try:
                SERVER_MONITOR_TAB_INSTANCE.reload_state()
            except Exception:
                pass
    return added, invalid, duplicates

def format_monitor_feedback(added, invalid, duplicates):
    if added:
        parts = [f"Added {added} server(s) to monitor list."]
        if duplicates:
            parts.append(f"{duplicates} already monitored.")
        if invalid:
            parts.append(f"{invalid} invalid entrie(s) skipped.")
        return " ".join(parts)
    parts = []
    if duplicates:
        parts.append(f"{duplicates} already monitored.")
    if invalid:
        parts.append(f"{invalid} invalid entrie(s) skipped.")
    if parts:
        return " ".join(parts)
    return "No new servers were added to the monitor list."

# ==================== NBT Export ====================

def list_txt_files():
    return [f for f in os.listdir() if f.endswith(".txt")]

def choose_input_file():
    txt_files = list_txt_files()
    if not txt_files:
        print("No .txt files found in the current folder.")
        exit(1)
    print("Available .txt files:")
    for idx, fname in enumerate(txt_files, 1):
        print(f"  {idx}) {fname}")
    choice = input("Select a file by number: ").strip()
    try:
        index = int(choice) - 1
        return txt_files[index]
    except (IndexError, ValueError):
        print("Invalid selection.")
        exit(1)

def backup_or_restore():
    if os.path.exists(BACKUP_PATH):
        if ask_yes_no("Backup already exists. Restore it before continuing?"):
            shutil.copyfile(BACKUP_PATH, SERVERS_DAT_PATH)
            print("Backup restored.")
        else:
            print("Proceeding with current servers.dat.")
    else:
        if ask_yes_no("No backup found. Create a backup of servers.dat before modifying?"):
            shutil.copyfile(SERVERS_DAT_PATH, BACKUP_PATH)
            print(f"Backup saved to: {BACKUP_PATH}")

def load_servers():
    if not os.path.exists(SERVERS_DAT_PATH):
        print("servers.dat not found. Creating new one.")
        return nbtlib.File({"servers": nbtlib.List[Compound]()})
    try:
        nbt_file = nbtlib.load(SERVERS_DAT_PATH)
        if "servers" not in nbt_file:
            nbt_file["servers"] = nbtlib.List[Compound]()
        return nbt_file
    except Exception as e:
        print(f"Error loading servers.dat: {e}")
        print("❌ Aborting to prevent overwrite.")
        exit(1)

def already_exists(server_list, ip):
    return any(entry['ip'] == ip for entry in server_list)

def import_to_minecraft_servers_dat():  # kept original cli flow - whatever?
    print("\n=== Minecraft Server List Importer ===")
    backup_or_restore()
    input_file = choose_input_file()
    print(f"Importing from: {input_file}")
    nbt_data = load_servers()
    if "servers" not in nbt_data:
        nbt_data["servers"] = nbtlib.List[Compound]()
    servers = nbt_data["servers"]
    existing_ips = {entry['ip'] for entry in servers}
    added_count = 0
    skipped_ignored = 0
    with open(input_file, "r", encoding="utf-8") as f:
        for line in f:
            ip = line.strip()
            if " |" in ip:
                ip = ip.split(" |")[0]
            ip_extracted = _extract_ip_port_from_text(ip)
            if ip_extracted:
                ip = ip_extracted
            if not is_valid_ip_port(ip):
                continue
            if is_ignored(ip):
                skipped_ignored += 1
                continue
            if ip in existing_ips:
                continue
            new_entry = Compound({
                "name": String(f"Imported {ip}"),
                "ip": String(ip),
                "hidden": Byte(0),
                "acceptTextures": Byte(1)
            })
            servers.append(new_entry)
            existing_ips.add(ip)
            added_count += 1
            print(f"Added {ip}")
    nbt_data.save(SERVERS_DAT_PATH)
    print(f"\n✅ Added {added_count} new servers.")
    if skipped_ignored:
        print(f"⚠️ Skipped {skipped_ignored} entrie(s) from ignore list.")
    print(f"📦 Total entries in servers.dat: {len(servers)}")

# GUI-friendly import
def import_file_to_servers_dat(path, do_backup=True):
    if do_backup and not os.path.exists(BACKUP_PATH):
        try:
            if os.path.exists(SERVERS_DAT_PATH):
                shutil.copyfile(SERVERS_DAT_PATH, BACKUP_PATH)
        except Exception as e:
            return False, f"Backup failed: {e}"

    try:
        nbt_data = load_servers()
        if "servers" not in nbt_data:
            nbt_data["servers"] = nbtlib.List[Compound]()
        servers = nbt_data["servers"]
        existing_ips = {entry['ip'] for entry in servers}
        added = 0
        skipped_ignored = 0
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                ip = get_ip_only(line.strip())
                if not is_valid_ip_port(ip):
                    continue
                if is_ignored(ip):
                    skipped_ignored += 1
                    continue
                if ip in existing_ips:
                    continue
                servers.append(Compound({
                    "name": String(f"Imported {ip}"),
                    "ip": String(ip),
                    "hidden": Byte(0),
                    "acceptTextures": Byte(1)
                }))
                existing_ips.add(ip)
                added += 1
        nbt_data.save(SERVERS_DAT_PATH)
        msg = f"Added {added} entries."
        if skipped_ignored:
            msg += f" Skipped {skipped_ignored} ignored."
        return True, msg
    except Exception as e:
        return False, f"Import failed: {e}"

# ==================== JSON search helpers ====================

from typing import List

def extract_ip_port_JSON(entry):
    return f"{entry.get('ip_str')}:{entry.get('port')}"

# Produce a fully formatted line directly from JSON entry
def extract_formatted_JSON(entry):  #
    ip_port = extract_ip_port_JSON(entry)
    data = entry.get("data", "")
    motd = parse_description_from_raw(data)
    players = parse_players(data)
    if "/" in players:
        online, maximum = players.split("/", 1)
    else:
        online, maximum = "N", "A"
    version = parse_version(data)
    return format_result_line(ip_port, motd, online, maximum, version)

def matches_JSON(entry, term):
    term_lower = term.lower()
    return (
        term_lower in str(entry.get("ip_str", "")).lower() or
        term_lower in str(entry.get("port", "")).lower() or
        term_lower in str(entry.get("data", "")).lower() or
        term_lower in str(entry.get("minecraft", "")).lower() or
        term_lower in str(entry.get("location", "")).lower() or
        term_lower in str(entry.get("version", "")).lower() or
        term_lower in str(entry.get("hostnames", "")).lower()
    )

def parse_boolean_expression_JSON(expression: str, entry) -> bool:
    tokens = re.findall(r'\(|\)|\w+(?:\.\w+)*|AND|OR|NOT', expression, flags=re.IGNORECASE)

    def eval_tokens(tokens_in):
        stack = []
        def resolve():
            result = stack.pop()
            while stack:
                op = stack.pop()
                if op == "AND":
                    result = result and stack.pop()
                elif op == "OR":
                    result = result or stack.pop()
            return result

        it = iter(tokens_in)
        for token in it:
            token_upper = token.upper()
            if token == "(":
                sub = []
                depth = 1
                for t in it:
                    if t == "(":
                        depth += 1
                    elif t == ")":
                        depth -= 1
                        if depth == 0:
                            break
                    sub.append(t)
                stack.append(eval_tokens(sub))
            elif token_upper in ("AND", "OR"):
                stack.append(token_upper)
            elif token_upper == "NOT":
                next_token = next(it)
                stack.append(not matches_JSON(entry, next_token))
            else:
                stack.append(matches_JSON(entry, token))
        return resolve()

    return eval_tokens(tokens)

def filter_entries_JSON(data: List[dict], query: str) -> List[str]:  
    out = []
    for entry in data:
        if parse_boolean_expression_JSON(query, entry):
            out.append(extract_formatted_JSON(entry))
    return out

def load_json_entries(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File '{file_path}' not found.")
    entries = []
    with open(file_path, "r", encoding="utf-8") as f:
        for idx, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON on line {idx}: {e}") from e
    return entries

def json_entries_to_rows(entries: List[dict]):
    rows = []
    seen = set()
    for entry in entries:
        formatted = extract_formatted_JSON(entry)
        ip, motd, players, version = parse_formatted_line(formatted)
        ip = get_ip_only(ip)
        if not is_valid_ip_port(ip):
            continue
        if is_ignored(ip):
            continue
        if ip in seen:
            continue
        rows.append((ip, motd, players, version))
        seen.add(ip)
    return rows

def json_search_load(file_path, query):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File '{file_path}' not found.")
    with open(file_path, "r", encoding="utf-8") as f:
        data = [json.loads(line) for line in f if line.strip()]
    return filter_entries_JSON(data, query)

# ======================================

def append_with_reason(file_path, ip_port, reason, prefix):
    line = f"{ip_port} | {prefix}: {reason if reason else 'No reason'}".strip() 
    with open(file_path, "a", encoding="utf-8") as f:
        f.write(line + "\n")

def add_to_ignore(ip_port, reason):
    append_with_reason(IGNORE_FILE, ip_port, reason or "No reason", "Reason")
    refresh_ignore_set(ip_port)

def add_to_saved(ip_port, reason):
    append_with_reason(SAVED_FILE, ip_port, reason or "No reason", "Reason")
    
def parse_reason_line(line):
    ip = get_ip_only(line)
    reason = ""
    m = re.search(r"\|\s*Reason:\s*(.*)$", line)
    if m:
        reason = m.group(1).strip()
    return ip, reason

def load_reason_file(file_path):
    rows = []
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            for ln in f:
                ln = ln.strip()
                if not ln:
                    continue
                ip, reason = parse_reason_line(ln)
                if is_valid_ip_port(ip):
                    rows.append((ip, reason))
    return rows

def save_reason_file(file_path, rows):
    with open(file_path, "w", encoding="utf-8") as f:
        for ip, reason in rows:
            f.write(f"{ip} | Reason: {reason or 'No reason'}\n")

def load_ips_rows(file_path=GLOBAL_IP_LOG):
    rows = []
    if os.path.exists(file_path):
        with open(file_path, "r", encoding="utf-8") as f:
            for ln in f:
                if not ln.strip():
                    continue
                ip, motd, players, version = parse_formatted_line(ln.strip())
                ip = get_ip_only(ip)
                if is_valid_ip_port(ip):
                    rows.append((ip, motd, players, version))
    return rows

def save_ips_rows(rows, file_path=GLOBAL_IP_LOG):
    with open(file_path, "w", encoding="utf-8") as f:
        for (ip, motd, players, version) in rows:
            players = players or "N/A"
            f.write(f"{ip} | MOTD: {sanitize_motd(motd)} | Players: {players} | Version: {version}\n")

def ask_reason_with_whitelist(parent, title="Reason", prompt="Why ignore? (optional)"):

    dlg = tk.Toplevel(parent)
    dlg.transient(parent)
    dlg.grab_set()
    dlg.title(title)

    # Make small, non-resizable and center over parent (best-effort)
    try:
        dlg.resizable(False, False)
    except Exception:
        pass

    frm = ttk.Frame(dlg, padding=(12, 10))
    frm.pack(fill="both", expand=True)

    ttk.Label(frm, text=prompt).pack(anchor="w", pady=(0,6))

    var = tk.StringVar()
    entry = ttk.Entry(frm, textvariable=var, width=60)
    entry.pack(fill="x", expand=True)
    entry.focus_set()

    btns = ttk.Frame(frm)
    btns.pack(fill="x", pady=(10,0))

    def _close_with(val):
        dlg.result = None if val is None else str(val)
        try:
            dlg.grab_release()
        except Exception:
            pass
        dlg.destroy()

    def _on_ok():
        _close_with(var.get().strip() if var.get().strip() else "")

    def _on_whitelist():
        # immediate accept with "White List"
        _close_with("White List")

    def _on_cancel():
        _close_with(None)

    # Buttons: OK, White List, Cancel
    ttk.Button(btns, text="OK", command=_on_ok).pack(side="left", padx=(0,6))
    ttk.Button(btns, text="White List", command=_on_whitelist).pack(side="left", padx=(0,6))
    ttk.Button(btns, text="Cancel", command=_on_cancel).pack(side="left")

    # Bind Enter / Escape keys
    dlg.bind("<Return>", lambda e: _on_ok())
    dlg.bind("<Escape>", lambda e: _on_cancel())

    # center over parent (best-effort)
    try:
        parent.update_idletasks()
        px = parent.winfo_rootx()
        py = parent.winfo_rooty()
        pw = parent.winfo_width()
        ph = parent.winfo_height()
        dlg.update_idletasks()
        w = dlg.winfo_reqwidth()
        h = dlg.winfo_reqheight()
        x = px + max(0, (pw - w) // 2)
        y = py + max(0, (ph - h) // 2)
        dlg.geometry(f"+{x}+{y}")
    except Exception:
        pass

    parent.wait_window(dlg)
    return getattr(dlg, "result", None)

# ========================================  

class _IconManager:
    def __init__(self):
        self._cache_bytes = {}        # ip -> png bytes or None
        self._cache_images = {}       # ip -> PhotoImage (or placeholder)
        self._executor = ThreadPoolExecutor(max_workers=max(1, ICON_THREADS))
        self._attached = set()
        self._placeholder_image = None

    def _ensure_tree_ready(self, tree: ttk.Treeview):
        # turn on the tree column to host images, center it, set width
        try:
            tree["show"] = "tree headings"
        except Exception:
            pass
        tree.heading("#0", text="ICON")
        tree.column("#0", width=ICON_SIZE + ICON_COL_EXTRA_PAD, stretch=False, anchor="center")

        # increase row height just for this tree
        sty = ttk.Style(tree)
        style_name = f"IconTreeview{str(id(tree))}"
        try:
            sty.configure(style_name, rowheight=max(ICON_SIZE + 8, 24))
            tree.configure(style=style_name)
        except Exception:
            pass

        # storage for PhotoImage refs so they don't get GC'd
        if not hasattr(tree, "_icon_images"):
            tree._icon_images = {}

    def attach_to_tree(self, tree: ttk.Treeview):
        if not ICON_ENABLED:
            return
        if tree in self._attached:
            return
        self._ensure_tree_ready(tree)

        # monkeypatch insert to auto-register rows
        if not hasattr(tree, "_orig_insert"):
            tree._orig_insert = tree.insert

            def _insert_wrapper(parent, index, iid=None, **kw):
                values = kw.get("values")
                new_iid = tree._orig_insert(parent, index, iid=iid, **kw)
                if values and len(values) > 0:
                    ip = values[0]
                    if is_valid_ip_port(ip):
                        self._fetch_and_set_icon(tree, new_iid, ip)
                return new_iid

            tree.insert = _insert_wrapper  # type: ignore

        self._attached.add(tree)

    def _fetch_and_set_icon(self, tree: ttk.Treeview, iid: str, ip: str):
        # if already cached, set immediately on UI thread
        if ip in self._cache_bytes:
            data = self._cache_bytes[ip]
            self._apply_icon_to_item(tree, iid, ip, data)
            return

        # fetch in background
        def work():
            data = fetch_server_favicon_bytes(ip)
            # cache whether None or bytes to avoid repeat lookups
            self._cache_bytes[ip] = data
            try:
                tree.after(0, lambda: self._apply_icon_to_item(tree, iid, ip, data))
            except Exception:
                pass

        self._executor.submit(work)

    def _apply_icon_to_item(self, tree: ttk.Treeview, iid: str, ip: str, png_bytes: bytes | None):
        try:
            photo = self._photo_for_ip(ip, png_bytes)
            # keep ref
            tree._icon_images[iid] = photo
            tree.item(iid, image=photo, text="")
        except Exception:
            # ignore per-row failures silently
            pass

    def _photo_for_ip(self, ip: str, png_bytes: bytes | None):
        if ip in self._cache_images:
            return self._cache_images[ip]
        photo = self._make_photo(png_bytes)
        if photo is None:
            photo = self._placeholder_photo()
        self._cache_images[ip] = photo
        return photo

    def _make_photo(self, png_bytes):
        if not png_bytes:
            return None
        if _PIL_AVAILABLE:
            try:
                im = Image.open(io.BytesIO(png_bytes)).convert("RGBA")
                im = im.resize((ICON_SIZE, ICON_SIZE), Image.LANCZOS)
                return ImageTk.PhotoImage(im)
            except Exception:
                return None
        # fallback: try raw PhotoImage (cannot upscale; can downscale via subsample)
        try:
            b64 = base64.b64encode(png_bytes)
            img = tk.PhotoImage(data=b64)
            w = img.width()
            if w > 0 and ICON_SIZE < w:
                factor = max(1, round(w / ICON_SIZE))
                img = img.subsample(factor)
            return img
        except Exception:
            return None

    def _placeholder_photo(self):
        if self._placeholder_image is not None:
            return self._placeholder_image
        # simple solid square to reserve space
        img = tk.PhotoImage(width=ICON_SIZE, height=ICON_SIZE)
        img.put(ICON_PLACEHOLDER, to=(0, 0, ICON_SIZE, ICON_SIZE))
        self._placeholder_image = img
        return img


# singleton accessor
_ICON_MANAGER_SINGLETON = None
def _get_icon_manager():
    global _ICON_MANAGER_SINGLETON
    if _ICON_MANAGER_SINGLETON is None:
        _ICON_MANAGER_SINGLETON = _IconManager()
    return _ICON_MANAGER_SINGLETON


# ==================== GUI ====================

class FullAppGUI(tk.Tk):  #
    def __init__(self):
        super().__init__()
        self.title("Minecraft Server Scanner — GUI")
        self.geometry("1100x760")  # slightly taller
        self.create_widgets()

    def create_widgets(self):
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)

        # Tabs
        self.shodan_tab = ShodanTab(nb)
        self.json_tab = JSONTab(nb)
        self.servers_tab = ServersTab(nb)
        self.import_tab = ExportTab(nb)
        self.saved_tab = SavedTab(nb)    
        self.ignore_tab = IgnoreTab(nb)  
        self.iplog_tab = IpLogTab(nb)    
        self.user_log_tab = UserLogTab(nb)
        self.monitor_tab = ServerMonitorTab(nb)

        nb.add(self.shodan_tab, text="Shodan")
        nb.add(self.json_tab, text="JSON Search")
        nb.add(self.servers_tab, text="Servers")
        nb.add(self.import_tab, text="Export To MC")
        nb.add(self.saved_tab, text="Saved List")  
        nb.add(self.ignore_tab, text="Ignore List")
        nb.add(self.iplog_tab, text="IP Log")     
        nb.add(self.user_log_tab, text="User Log")
        nb.add(self.monitor_tab, text="Server Monitor")

        USER_LOG_MANAGER.attach_tab(self.user_log_tab)

# ---- Servers Tab ----
class ServersTab(ttk.Frame):  #
    def __init__(self, master):
        super().__init__(master)
        self.current_source = None
        self.servers = []  # list[str] of IP:PORT
        self.source_rows = []  # list[tuple(ip,motd,players,version)]
        self._in_ignore = False  # re-entrancy guard
        self._build_ui()
        self._current_scan_ip = None 

    def add_ignore(self):  #
        sel = self._selected_ips_any()
        if not sel:
            messagebox.showinfo("Info","Select one or more.")
            return
        # use the new dialog that offers a "White List" shortcut button
        reason = ask_reason_with_whitelist(self, "Reason", "Why ignore? (optional)")
        # If user cancelled (None), do nothing
        if reason is None:
            self.set_status("Ignore cancelled.")
            return
        for ip in sel:
            add_to_ignore(ip, reason or "")
        # remove from self.servers
        self.servers = [s for s in self.servers if s not in sel]
        self.refresh_list()
        self.set_status(f"Added {len(sel)} to ignore.txt")

    def add_saved(self):  #
        sel = self._selected_ips_any()
        if not sel:
            messagebox.showinfo("Info","Select one or more.")
            return
        reason = simpledialog.askstring("Reason","Why save? (optional)")
        for ip in sel:
            add_to_saved(ip, reason or "")
        self.set_status(f"Added {len(sel)} to saved.txt")

    def _build_ui(self):
        # Root grid: content (row 0) + footer (row 1) pinned
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        content = ttk.Frame(self)
        content.grid(row=0, column=0, sticky="nsew")

        # Paned: top (source) / middle (results)
        pane = tk.PanedWindow(content, orient="vertical", sashwidth=8)
        pane.pack(fill="both", expand=True, padx=8, pady=(8,0))
        pane_top = ttk.Frame(pane)
        pane_mid = ttk.Frame(pane)
        pane.add(pane_top, minsize=160)
        pane.add(pane_mid, minsize=220)

        # --- Source area (TOP) ---
        top = ttk.Frame(pane_top)
        top.pack(fill="x", padx=8, pady=8)

        self.src_label = ttk.Label(top, text="Source: (none)")
        self.src_label.pack(side="left")

        middle = ttk.Frame(pane_top)
        middle.pack(fill="both", expand=True, padx=8, pady=(0,8))

        # Source Tree (no icons here)
        cols = ("ip", "motd", "players", "version", "cracked")
        self.source_tree = ttk.Treeview(middle, columns=cols, show="headings", height=12, selectmode="extended")
        for c in cols:
            self.source_tree.heading(c, text=c.upper())
            if c == "motd":
                width = 240
            elif c == "players":
                width = 120
            elif c == "version":
                width = 120
            elif c == "cracked":
                width = 90
            else:
                width = 170
            self.source_tree.column(c, width=width, anchor="w")
        self.source_tree.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(middle, orient="vertical", command=self.source_tree.yview)
        sb.pack(side="left", fill="y")
        self.source_tree.config(yscrollcommand=sb.set)
        make_tree_sortable(self.source_tree, {
            "ip": _ip_key,
            "motd": lambda v: str(v).lower(),
            "players": _players_key,
            "version": _version_key,
            "cracked": lambda v: (0 if str(v).lower() in ("false","no","0") else 1) if v is not None else -1
        })

        right = ttk.Frame(middle)
        right.pack(side="right", fill="y", padx=8)
        ttk.Button(right, text="Import .txt", command=self.load_txt).pack(fill="x", pady=(0,6))
        ttk.Button(right, text="Copy IP", command=self.copy_ip).pack(fill="x", pady=2)
        ttk.Button(right, text="Add to Ignore", command=self.add_ignore).pack(fill="x", pady=2)
        ttk.Button(right, text="Add to Saved", command=self.add_saved).pack(fill="x", pady=2)
        ttk.Button(right, text="Add to Monitor", command=self.add_search_selected_to_monitor).pack(fill="x", pady=2)
        ttk.Separator(right, orient="horizontal").pack(fill="x", pady=6)
        ttk.Button(right, text="Scan Selected", command=self.scan_selected).pack(fill="x", pady=2)
        ttk.Button(right, text="Scan All", command=self.scan_all).pack(fill="x", pady=2)
        self.only_players_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(right, text="Only players > 0", variable=self.only_players_var).pack(anchor="w", pady=(8,0))

        # --- Results area (MIDDLE) ---
        bottom = ttk.Frame(pane_mid)
        bottom.pack(fill="both", expand=True, padx=8, pady=8)
        ttk.Label(bottom, text="Results (select to copy/save/ignore):").pack(anchor="w")

        res_frame = ttk.Frame(bottom)
        res_frame.pack(fill="both", expand=True)

        cols2 = ("ip", "motd", "players", "version", "cracked", "active_players")
        # show icons ONLY in results tree
        self.results_tree = ttk.Treeview(res_frame, columns=cols2, show="headings", height=10, selectmode="extended")
        for c in cols2:
            self.results_tree.heading(c, text=c.upper())
            if c in ("motd", "active_players"):
                width = 240
            elif c == "players":
                width = 130
            elif c == "version":
                width = 130
            elif c == "cracked":
                width = 90
            else:
                width = 170
            self.results_tree.column(c, width=width, anchor="w")
        self.results_tree.pack(side="left", fill="both", expand=True)
        res_sb = ttk.Scrollbar(res_frame, orient="vertical", command=self.results_tree.yview)
        res_sb.pack(side="left", fill="y")
        self.results_tree.config(yscrollcommand=res_sb.set)
        make_tree_sortable(self.results_tree, {
            "ip": _ip_key,
            "motd": lambda v: str(v).lower(),
            "players": _players_key,
            "version": _version_key,
            "cracked": lambda v: (0 if str(v).lower() in ("false","no","0") else 1) if v is not None else -1,
            "active_players": lambda v: str(v).lower()
        })

        # ------- Footer (pinned) -------
        footer = ttk.Frame(self)
        footer.grid(row=1, column=0, sticky="ew", padx=8, pady=(6,8))
        footer.grid_columnconfigure(1, weight=1)

        res_btns = ttk.Frame(footer)
        res_btns.grid(row=0, column=0, sticky="w")
        ttk.Button(res_btns, text="Copy IP(s)", command=self.copy_scan_selected).pack(side="left", padx=4)
        ttk.Button(res_btns, text="Add to Ignore", command=self.ignore_scan_selected).pack(side="left", padx=4)
        ttk.Button(res_btns, text="Add to Saved", command=self.save_scan_selected).pack(side="left", padx=4)
        ttk.Button(res_btns, text="Add to Monitor", command=self.add_scan_selected_to_monitor).pack(side="left", padx=4)
        ttk.Button(res_btns, text="Export Scan…", command=self.export_scan_results).pack(side="left", padx=4)
        self.player_search_var = tk.StringVar()
        search_entry = ttk.Entry(res_btns, textvariable=self.player_search_var, width=18)
        search_entry.pack(side="left", padx=(12,4))
        search_entry.bind("<Return>", lambda _e: self.search_players())
        ttk.Button(res_btns, text="Find Player", command=self.search_players).pack(side="left", padx=4)

        self.status = tk.StringVar(value="Ready.")
        ttk.Label(footer, textvariable=self.status, anchor="w").grid(row=0, column=1, sticky="ew", padx=(12,0))

        # ---------- ICONS attach (Servers: results only) ----------
        _get_icon_manager().attach_to_tree(self.results_tree)

    def set_status(self, msg):
        self.status.set(msg)

    def refresh_list(self, items=None):
        #populate source_tree using parsed rows when available
        for iid in self.source_tree.get_children():
            self.source_tree.delete(iid)
        if items is not None:
            rows = [(ip, "", "", "") for ip in items]  # explicit override
        elif self.source_rows:
            rows = self.source_rows
        else:
            rows = [(ip, "", "", "") for ip in self.servers]
        for row in rows:
            self.source_tree.insert("", "end", values=row)

    def load_txt(self):
        path = filedialog.askopenfilename(title="Open .txt", filetypes=[("Text files","*.txt"),("All files","*.*")])
        if not path:
            return
        try:
            rows = []  # (ip,motd,players,version)
            seen = set()  # prevent duplicates
            with open(path, "r", encoding="utf-8") as f:
                for ln in f:
                    ln = ln.strip()
                    if not ln:
                        continue
                    # Try to parse full formatted line first
                    ip, motd, players, version = parse_formatted_line(ln)  #
                    ip = get_ip_only(ip)
                    if not is_valid_ip_port(ip):
                        continue
                    if is_ignored(ip):
                        continue
                    if ip in seen:
                        continue
                    seen.add(ip)
                    rows.append((ip, motd, players, version))
            # update state
            self.current_source = path
            self.source_rows = rows  #
            self.servers = [ip for (ip, _, _, _) in rows]  # keep scan list intact
            self.src_label.config(text=f"Source: {os.path.basename(path)} ({len(rows)} entries)")
            self.refresh_list()
            self.set_status(f"Loaded {len(rows)} entries.")
        except Exception as e:
            messagebox.showerror("Load error", str(e))

    def _selected_ips_from_tree(self, tree):
        sel = []
        for iid in tree.selection():
            vals = tree.item(iid, "values")
            if vals:
                sel.append(vals[0])
        return sel

    def _selected_ips_any(self):
        ips = []
        ips.extend(self._selected_ips_from_tree(self.source_tree))
        for vals in self._scan_selected_rows():
            if vals:
                ips.append(vals[0])
        seen = []
        for ip in ips:
            if ip not in seen:
                seen.append(ip)
        return seen

    def copy_ip(self):
        sel = self._selected_ips_any()
        if not sel:
            messagebox.showinfo("Info","Select one or more.")
            return
        self.clipboard_clear()
        self.clipboard_append("\n".join(sel))
        self.set_status(f"Copied {len(sel)} IP(s).")

    # Helpers to read selected rows from results tree
    def _scan_selected_rows(self):
        out = []
        for iid in self.results_tree.selection():
            vals = self.results_tree.item(iid, "values")
            if vals:
                out.append(vals)
        return out

    def copy_scan_selected(self):  
        rows = self._scan_selected_rows()
        if not rows:
            messagebox.showinfo("Info", "Select results first.")
            return
        ips = [row[0] for row in rows]
        self.clipboard_clear()
        self.clipboard_append("\n".join(ips))
        self.set_status(f"Copied {len(ips)} IP(s) from results.")

    def ignore_scan_selected(self):  
        rows = self._scan_selected_rows()
        if not rows:
            messagebox.showinfo("Info", "Select results first.")
            return
        reason = ask_reason_with_whitelist(self, "Reason", "Why ignore? (optional)")
        if reason is None:
            self.set_status("Ignore cancelled.")
            return
        for ip, *_ in rows:
            add_to_ignore(ip, reason or "")
        for iid in list(self.results_tree.selection()):
            self.results_tree.delete(iid)
        self.set_status(f"Added {len(rows)} to ignore.txt from results.")

    def save_scan_selected(self):  
        rows = self._scan_selected_rows()
        if not rows:
            messagebox.showinfo("Info", "Select results first.")
            return
        reason = simpledialog.askstring("Reason","Why save? (optional)")
        for ip, *_ in rows:
            add_to_saved(ip, reason or "")
        self.set_status(f"Added {len(rows)} to saved.txt from results.")

    def add_scan_selected_to_monitor(self):
        rows = self._scan_selected_rows()
        if not rows:
            messagebox.showinfo("Info", "Select results first.")
            return
        ips = [row[0] for row in rows]
        added, invalid, duplicates = add_ips_to_monitor_list(ips)
        self.set_status(format_monitor_feedback(added, invalid, duplicates))

    def export_scan_results(self):  
        rows = []
        for iid in self.results_tree.get_children():
            vals = self.results_tree.item(iid, "values")
            if vals:
                rows.append(vals)
        if not rows:
            messagebox.showinfo("Info", "No scan results to export.")
            return
        # default name uses source file name (if any)
        if self.current_source:
            base_name = os.path.splitext(os.path.basename(self.current_source))[0]
            base = sanitize_query_for_filename(base_name + "_scan")
        else:
            base = "servers_scan"
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files","*.txt")],
            title="Export Servers Scan Results",
            initialfile=f"{base}.txt"
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            for row in rows:
                if not row:
                    continue
                ip = row[0]
                motd = row[1] if len(row) > 1 else ""
                players = row[2] if len(row) > 2 else "N/A"
                version = row[3] if len(row) > 3 else "N/A"
                if "/" in str(players):
                    online, maximum = str(players).split("/", 1)
                else:
                    online, maximum = "N", "A"
                f.write(format_result_line(ip, motd, online, maximum, version) + "\n")
        self.set_status(f"Exported {len(rows)} scan rows to {os.path.basename(path)}")

    def search_players(self):
        query_raw = self.player_search_var.get() or ""
        query = query_raw.strip().lower()
        if not query:
            self.set_status("Enter a player name to search.")
            return
        matches = []
        for iid in self.results_tree.get_children():
            vals = self.results_tree.item(iid, "values")
            if not vals:
                continue
            players_text = vals[5] if len(vals) >= 6 else (vals[-1] if vals else "")
            if isinstance(players_text, str) and query in players_text.lower():
                matches.append(iid)
        current_sel = self.results_tree.selection()
        if current_sel:
            self.results_tree.selection_remove(current_sel)
        if matches:
            self.results_tree.selection_set(matches)
            self.results_tree.focus(matches[0])
            self.results_tree.see(matches[0])
            self.set_status(f"Found {len(matches)} match(es) for '{query_raw.strip()}'.")
        else:
            self.set_status(f"No matches for '{query_raw.strip()}'.")

    def _scan(self, items):
        for iid in self.results_tree.get_children():
            self.results_tree.delete(iid)
        self.set_status("Preparing scan...")

        def work():
            try:
                total = len(items)
                def on_start(ip):
                    self._current_scan_ip = ip
                    self.after(0, lambda ip=ip: self.set_status(f"Currently scanning: {ip} [0/{total}]"))

                def on_result(r, line):
                    if not r:
                        return

                    if not self.only_players_var.get() or r.get('players', 0) > 0:
                        active_players = format_player_list(r.get('players_sample'))
                        vals = (
                            r['ip'],
                            r['motd'],
                            f"{r['players']}/{r['max_players']}",
                            r['version'],
                            "Yes" if r.get('cracked') else "No",
                            active_players
                        )
                        self.after(0, lambda v=vals: self.results_tree.insert("", "end", values=v))

                def on_progress(done, total):
                    ip = self._current_scan_ip or "…"
                    self.after(0, lambda d=done, t=total, ip=ip:
                               self.set_status(f"Currently scanning: {ip} [{d}/{t}]"))

                results, online_lines = scan_servers_gui(
                    items, on_start=on_start, on_result=on_result, on_progress=on_progress
                )
                self.after(0, lambda: self.set_status(f"Scan complete. Responded: {len(results)}; With 1+: {len(online_lines)}"))
            except Exception as e:
                self.after(0, lambda: self.set_status(f"Scan failed: {e}"))

        threading.Thread(target=work, daemon=True).start()

    def scan_selected(self):
        sel = self._selected_ips_any()
        if not sel:
            messagebox.showinfo("Info","Select one or more.")
            return
        self._scan(sel)

    def scan_all(self):
        if not self.servers:
            messagebox.showinfo("Info","Load a .txt first.")
            return
        self._scan(self.servers)


def _servers_tab_add_search_selected_to_monitor(self):
    sel = self._selected_ips_any()
    if not sel:
        messagebox.showinfo("Info","Select items first.")
        return
    added, invalid, duplicates = add_ips_to_monitor_list(sel)
    self.set_status(format_monitor_feedback(added, invalid, duplicates))


ServersTab.add_search_selected_to_monitor = _servers_tab_add_search_selected_to_monitor

class ServerMonitorTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.monitor_state = load_server_monitor_state()
        self.interval_var = tk.IntVar(value=DEFAULT_MONITOR_INTERVAL)
        self.status_var = tk.StringVar(value="Monitor idle.")
        self._monitor_thread = None
        self._monitoring = False
        self._monitor_interval = DEFAULT_MONITOR_INTERVAL
        self._stop_event = threading.Event()
        self._last_selected_ip = None
        self._build_ui()
        register_monitor_tab(self)
        self._refresh_server_tree()
        self._refresh_players_tree()

    def _build_ui(self):
        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)

        input_frame = ttk.Frame(self)
        input_frame.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 4))
        input_frame.columnconfigure(0, weight=1)
        ttk.Label(input_frame, text="Add servers (one IP:PORT per line):").grid(row=0, column=0, sticky="w")
        self.server_input = tk.Text(input_frame, height=3, wrap="none")
        self.server_input.grid(row=1, column=0, sticky="ew", padx=(0, 4))
        input_scroll = ttk.Scrollbar(input_frame, orient="vertical", command=self.server_input.yview)
        input_scroll.grid(row=1, column=1, sticky="ns")
        self.server_input.configure(yscrollcommand=input_scroll.set)
        btn_frame = ttk.Frame(input_frame)
        btn_frame.grid(row=2, column=0, columnspan=2, sticky="w", pady=(4, 0))
        ttk.Button(btn_frame, text="Add to Monitor", command=self.add_servers_from_input).pack(side="left")
        ttk.Button(btn_frame, text="Clear Input", command=self.clear_input).pack(side="left", padx=6)
        ttk.Button(btn_frame, text="Remove Selected", command=self.remove_selected_servers).pack(side="left")
        ttk.Button(btn_frame, text="Copy Selected", command=self.copy_monitored_ips).pack(side="left", padx=6)

        control_frame = ttk.Frame(self)
        control_frame.grid(row=1, column=0, sticky="ew", padx=8, pady=4)
        control_frame.columnconfigure(6, weight=1)
        ttk.Label(control_frame, text="Ping interval (secs):").grid(row=0, column=0, sticky="w")
        ttk.Entry(control_frame, width=6, textvariable=self.interval_var).grid(row=0, column=1, sticky="w", padx=(4, 12))
        self.start_btn = ttk.Button(control_frame, text="Start Monitoring", command=self.start_monitoring)
        self.start_btn.grid(row=0, column=2, padx=4)
        self.stop_btn = ttk.Button(control_frame, text="Stop", command=self.stop_monitoring, state="disabled")
        self.stop_btn.grid(row=0, column=3, padx=4)
        ttk.Button(control_frame, text="Export Player Log", command=self.export_players).grid(row=0, column=4, padx=4)

        main_pane = tk.PanedWindow(self, orient="vertical", sashwidth=8)
        main_pane.grid(row=2, column=0, sticky="nsew", padx=8, pady=4)
        main_pane.rowconfigure(0, weight=1)
        main_pane.columnconfigure(0, weight=1)

        server_frame = ttk.Frame(main_pane)
        server_frame.rowconfigure(0, weight=1)
        server_frame.columnconfigure(0, weight=1)
        cols = ("ip", "status", "players", "version", "cracked", "motd", "last_ping")
        self.server_tree = ttk.Treeview(server_frame, columns=cols, show="headings", height=10, selectmode="extended")
        for col in cols:
            self.server_tree.heading(col, text=col.replace("_", " ").title())
            if col == "ip":
                width = 150
            elif col == "status":
                width = 100
            elif col == "players":
                width = 110
            elif col == "version":
                width = 120
            elif col == "cracked":
                width = 90
            elif col == "motd":
                width = 260
            else:
                width = 170
            self.server_tree.column(col, width=width, anchor="w")
        self.server_tree.grid(row=0, column=0, sticky="nsew")
        tree_scroll = ttk.Scrollbar(server_frame, orient="vertical", command=self.server_tree.yview)
        tree_scroll.grid(row=0, column=1, sticky="ns")
        self.server_tree.configure(yscrollcommand=tree_scroll.set)
        self.server_tree.bind("<<TreeviewSelect>>", lambda e: self._on_server_selected())
        self.server_tree.tag_configure("status_offline", background="#ffe6e6")
        make_tree_sortable(self.server_tree, {
            "ip": _ip_key,
            "status": lambda v: str(v).lower(),
            "players": _players_key,
            "version": _version_key,
            "cracked": lambda v: 0 if str(v).lower() in ("false","no","0") else 1,
            "motd": lambda v: str(v).lower(),
            "last_ping": lambda v: v or ""
        })
        main_pane.add(server_frame, minsize=260)

        players_frame = ttk.Frame(main_pane)
        players_frame.rowconfigure(1, weight=1)
        players_frame.columnconfigure(0, weight=1)
        ttk.Label(players_frame, text="Recorded players for selected server:").grid(row=0, column=0, sticky="w", pady=(0,4))
        player_cols = ("uuid", "name", "last_seen")
        self.players_tree = ttk.Treeview(players_frame, columns=player_cols, show="headings", height=6)
        for col in player_cols:
            self.players_tree.heading(col, text=col.replace("_", " ").title())
            if col == "uuid":
                width = 260
            elif col == "name":
                width = 200
            else:
                width = 170
            self.players_tree.column(col, width=width, anchor="w")
        self.players_tree.grid(row=1, column=0, sticky="nsew")
        player_scroll = ttk.Scrollbar(players_frame, orient="vertical", command=self.players_tree.yview)
        player_scroll.grid(row=1, column=1, sticky="ns")
        self.players_tree.configure(yscrollcommand=player_scroll.set)
        btn_frame = ttk.Frame(players_frame)
        btn_frame.grid(row=2, column=0, sticky="w", pady=(4,0))
        ttk.Button(btn_frame, text="Copy Username(s)", command=self.copy_selected_player_names).pack(side="left")
        main_pane.add(players_frame, minsize=160)

        footer = ttk.Frame(self)
        footer.grid(row=3, column=0, sticky="ew", padx=8, pady=(8, 8))
        ttk.Label(footer, textvariable=self.status_var, anchor="w").pack(fill="x")

    def _set_status(self, msg):
        self.status_var.set(msg)

    def add_servers_from_input(self):
        raw = self.server_input.get("1.0", "end").strip()
        if not raw:
            self._set_status("Paste one or more servers first.")
            return
        added = 0
        invalid = 0
        for line in raw.splitlines():
            ip = get_ip_only(line.strip())
            if not ip:
                continue
            if not is_valid_ip_port(ip):
                invalid += 1
                continue
            if ip in self.monitor_state.get("servers", {}):
                continue
            _ensure_monitor_server_entry(self.monitor_state, ip)
            added += 1
        if added:
            save_server_monitor_state(self.monitor_state)
            self._refresh_server_tree()
            self._set_status(f"Added {added} server(s) to monitor list.")
        elif invalid:
            self._set_status("Skipped invalid entries.")
        else:
            self._set_status("No new servers added.")
        self.server_input.delete("1.0", "end")

    def clear_input(self):
        self.server_input.delete("1.0", "end")
        self._set_status("Input cleared.")

    def remove_selected_servers(self):
        selected = self.server_tree.selection()
        if not selected:
            messagebox.showinfo("Info", "Select rows to remove.")
            return
        removed = 0
        for iid in selected:
            vals = self.server_tree.item(iid, "values")
            if not vals:
                continue
            ip = vals[0]
            if ip in self.monitor_state.get("servers", {}):
                self.monitor_state["servers"].pop(ip, None)
                removed += 1
        if removed:
            save_server_monitor_state(self.monitor_state)
            self._last_selected_ip = None
            self._refresh_server_tree()
            self._refresh_players_tree(None)
            self._set_status(f"Removed {removed} server(s) from monitor list.")
        else:
            self._set_status("No servers removed.")

    def copy_monitored_ips(self):
        selected = self.server_tree.selection()
        if not selected:
            messagebox.showinfo("Info", "Select rows first.")
            return
        ips = []
        for iid in selected:
            vals = self.server_tree.item(iid, "values")
            if vals:
                ips.append(vals[0])
        if not ips:
            messagebox.showinfo("Info", "No valid IPs selected.")
            return
        self.clipboard_clear()
        self.clipboard_append("\n".join(ips))
        self._set_status(f"Copied {len(ips)} monitored server(s).")

    def copy_selected_player_names(self):
        selected = self.players_tree.selection()
        if not selected:
            messagebox.showinfo("Info", "Select player rows first.")
            return
        names = []
        for iid in selected:
            vals = self.players_tree.item(iid, "values")
            if vals and len(vals) >= 2:
                name = vals[1]
                if isinstance(name, str) and name.strip():
                    names.append(name.strip())
        if not names:
            messagebox.showinfo("Info", "No player names selected.")
            return
        self.clipboard_clear()
        self.clipboard_append("\n".join(names))
        self._set_status(f"Copied {len(names)} player name(s).")

    def start_monitoring(self):
        if self._monitoring:
            return
        interval = self._read_interval()
        if not interval:
            messagebox.showinfo("Info", "Enter a valid interval (in seconds).")
            return
        ips = self._get_monitored_ips()
        if not ips:
            messagebox.showinfo("Info", "Add at least one server to monitor.")
            return
        self._monitor_interval = interval
        self._stop_event.clear()
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()
        self._monitoring = True
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self._set_status(f"Monitoring {len(ips)} server(s) every {interval}s.")

    def stop_monitoring(self):
        if not self._monitoring:
            return
        self._stop_event.set()
        self._monitoring = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self._set_status("Monitoring paused.")

    def _monitor_loop(self):
        while not self._stop_event.is_set():
            start = time.time()
            try:
                self._run_monitor_pass()
            except Exception as exc:
                self.after(0, lambda: self._set_status(f"Monitor error: {exc}"))
            elapsed = time.time() - start
            wait = max(0, self._monitor_interval - elapsed)
            if self._stop_event.wait(wait):
                break

    def _run_monitor_pass(self):
        ips = self._get_monitored_ips()
        if not ips:
            self.after(0, lambda: self._set_status("No servers configured to monitor."))
            return
        self.after(0, lambda: self._set_status(f"Pinging {len(ips)} server(s)..."))
        cycle_ts = time.time()
        results, _ = scan_servers_gui(ips)
        processed = set()
        for result in results:
            ip = result.get("ip")
            if not ip:
                continue
            update_server_monitor_entry(self.monitor_state, ip, result, cycle_ts)
            processed.add(ip)
        for ip in ips:
            if ip not in processed:
                mark_server_offline_in_state(self.monitor_state, ip, cycle_ts)
        save_server_monitor_state(self.monitor_state)
        self.after(0, self._refresh_server_tree)
        self.after(0, self._refresh_players_tree)
        self.after(0, lambda: self._set_status(f"Monitor cycle complete ({len(ips)} servers)."))

    def export_players(self):
        ip = self._last_selected_ip
        if not ip:
            messagebox.showinfo("Info", "Select a server first.")
            return
        entry = self.monitor_state.get("servers", {}).get(ip)
        if not entry:
            messagebox.showinfo("Info", "Server data unavailable.")
            return
        log = entry.get("player_log", {})
        if not log:
            messagebox.showinfo("Info", "No player data for this server yet.")
            return
        safe_name = ip.replace(":", "_")
        path = filedialog.asksaveasfilename(
            title="Export Player Log",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt")],
            initialfile=f"{safe_name}_players.txt"
        )
        if not path:
            return
        rows = sorted(log.items(), key=lambda kv: kv[1].get("last_seen", 0), reverse=True)
        with open(path, "w", encoding="utf-8") as f:
            for uid, data in rows:
                name = data.get("name", "")
                seen = format_timestamp(data.get("last_seen"))
                f.write(f"{uid} | {name} | Last seen: {seen}\n")
        self._set_status(f"Exported {len(rows)} player entries for {ip}.")

    def _get_monitored_ips(self):
        return list(self.monitor_state.get("servers", {}).keys())

    def _read_interval(self):
        try:
            val = int(self.interval_var.get())
            return max(5, val)
        except Exception:
            return None

    def _refresh_server_tree(self):
        current = self._last_selected_ip
        target_iid = None
        self.server_tree.delete(*self.server_tree.get_children())
        for ip in sorted(self.monitor_state.get("servers", {})):
            entry = self.monitor_state["servers"][ip]
            players = entry.get("players_online", 0)
            max_players = entry.get("max_players", 0)
            status = entry.get("last_status", "unknown")
            last_ping = format_timestamp(entry.get("last_ping"))
            version = entry.get("version", "N/A")
            cracked = "Yes" if entry.get("cracked") else "No"
            motd = sanitize_motd(entry.get("motd", ""))
            iid = self.server_tree.insert(
                "",
                "end",
                values=(ip, status.title(), f"{players}/{max_players}", version, cracked, motd, last_ping),
                tags=("status_offline",) if status.strip().lower() != "online" and status.strip() else ()
            )
            if ip == current:
                target_iid = iid
        if target_iid:
            self.server_tree.selection_set(target_iid)
            self.server_tree.see(target_iid)

    def _refresh_players_tree(self, ip=None):
        if ip is None:
            ip = self._last_selected_ip
        self.players_tree.delete(*self.players_tree.get_children())
        if not ip:
            return
        entry = self.monitor_state.get("servers", {}).get(ip)
        if not entry:
            return
        rows = []
        for uid, pdata in entry.get("player_log", {}).items():
            rows.append((uid, pdata.get("name", ""), pdata.get("last_seen", 0)))
        rows.sort(key=lambda item: item[2], reverse=True)
        for uid, name, last_seen in rows:
            self.players_tree.insert("", "end", values=(uid, name, format_timestamp(last_seen)))

    def _on_server_selected(self):
        selection = self.server_tree.selection()
        if not selection:
            self._last_selected_ip = None
            self._refresh_players_tree(None)
            return
        vals = self.server_tree.item(selection[0], "values")
        if not vals:
            return
        self._last_selected_ip = vals[0]
        self._refresh_players_tree(self._last_selected_ip)
    
    def reload_state(self):
        self.monitor_state = load_server_monitor_state()
        if self._last_selected_ip not in self.monitor_state.get("servers", {}):
            self._last_selected_ip = None
        self._refresh_server_tree()
        self._refresh_players_tree(self._last_selected_ip)

# ---- Shodan Tab ----
class ShodanTab(ttk.Frame):  
    def __init__(self, master):
        super().__init__(master)
        self.results = []  # list[tuple(ip,motd,players,version)]
        self._in_ignore = False
        self._build_ui()
        self._current_scan_ip = None

    def _build_ui(self):
        # Root grid: content (row 0) + footer (row 1) pinned
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        content = ttk.Frame(self)
        content.grid(row=0, column=0, sticky="nsew")

        # Paned window: top (search + table) / bottom (scan output)
        pane = tk.PanedWindow(content, orient="vertical", sashwidth=8)
        pane.pack(fill="both", expand=True, padx=8, pady=(8,0))
        pane_top = ttk.Frame(pane)
        pane_bottom = ttk.Frame(pane)
        pane.add(pane_top, minsize=300)
        pane.add(pane_bottom, minsize=240)

        bar = ttk.Frame(pane_top)
        bar.pack(fill="x", padx=8, pady=8)
        ttk.Label(bar, text="Query (without 'minecraft'): ").pack(side="left")
        self.query_var = tk.StringVar()
        ttk.Entry(bar, textvariable=self.query_var, width=50).pack(side="left", padx=6)
        ttk.Button(bar, text="Search", command=self.do_search).pack(side="left")
        ttk.Button(bar, text="Export Search…", command=self.export_search_results).pack(side="left", padx=6)

        mid = ttk.Frame(pane_top)
        mid.pack(fill="both", expand=True, padx=8, pady=4)

        cols = ("ip","motd","players","version")
        self.tree = ttk.Treeview(mid, columns=cols, show="headings", height=14, selectmode="extended")
        for c in cols:
            self.tree.heading(c, text=c.upper())
            if c == "motd":
                width = 240
            elif c == "players":
                width = 120
            elif c == "version":
                width = 120
            else:
                width = 170
            self.tree.column(c, width=width, anchor="w")
        self.tree.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        sb.pack(side="left", fill="y")
        self.tree.config(yscrollcommand=sb.set)

        make_tree_sortable(self.tree, {
            "ip": _ip_key,
            "motd": lambda v: str(v).lower(),
            "players": _players_key,
            "version": _version_key
        })

        right = ttk.Frame(mid)
        right.pack(side="right", fill="y", padx=8)
        ttk.Button(right, text="Copy IP(s)", command=self.copy_selected).pack(fill="x", pady=2)
        ttk.Button(right, text="Add to Ignore", command=self.ignore_selected).pack(fill="x", pady=2)
        ttk.Button(right, text="Add to Saved", command=self.save_selected).pack(fill="x", pady=2)
        ttk.Button(right, text="Add to Monitor", command=self.add_search_selected_to_monitor).pack(fill="x", pady=2)
        ttk.Separator(right, orient="horizontal").pack(fill="x", pady=6)
        ttk.Button(right, text="Scan Selected", command=self.scan_selected).pack(fill="x", pady=2)
        ttk.Button(right, text="Scan All", command=self.scan_all).pack(fill="x", pady=2)
        self.only_players_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(right, text="Only players > 0", variable=self.only_players_var).pack(anchor="w", pady=(8,0))

        # BOTTOM: Scan output table
        out = ttk.Frame(pane_bottom)
        out.pack(fill="both", expand=True, padx=8, pady=(0,8))
        ttk.Label(out, text="Scan Output (select to copy/save/ignore):").pack(anchor="w")
        of = ttk.Frame(out)
        of.pack(fill="both", expand=True)

        cols_out = ("ip","motd","players","version","cracked","active_players")
        self.scan_tree = ttk.Treeview(of, columns=cols_out, show="headings", height=8, selectmode="extended")
        for c in cols_out:
            self.scan_tree.heading(c, text=c.upper())
            if c in ("motd", "active_players"):
                width = 240
            elif c == "players":
                width = 130
            elif c == "version":
                width = 130
            elif c == "cracked":
                width = 90
            else:
                width = 170
            self.scan_tree.column(c, width=width, anchor="w")
        self.scan_tree.pack(side="left", fill="both", expand=True)
        osb = ttk.Scrollbar(of, orient="vertical", command=self.scan_tree.yview)
        osb.pack(side="left", fill="y")
        self.scan_tree.config(yscrollcommand=osb.set)
        make_tree_sortable(self.scan_tree, {
            "ip": _ip_key,
            "motd": lambda v: str(v).lower(),
            "players": _players_key,
            "version": _version_key,
            "cracked": lambda v: (0 if str(v).lower() in ("false","no","0") else 1) if v is not None else -1,
            "active_players": lambda v: str(v).lower()
        })

        # ------- Footer (pinned) -------
        footer = ttk.Frame(self)
        footer.grid(row=1, column=0, sticky="ew", padx=8, pady=(6,8))
        footer.grid_columnconfigure(1, weight=1)

        obtns = ttk.Frame(footer)
        obtns.grid(row=0, column=0, sticky="w")
        ttk.Button(obtns, text="Copy IP(s)", command=self.copy_scan_selected).pack(side="left", padx=4)
        ttk.Button(obtns, text="Add to Ignore", command=self.ignore_scan_selected_from_output).pack(side="left", padx=4)
        ttk.Button(obtns, text="Add to Saved", command=self.save_scan_selected_from_output).pack(side="left", padx=4)
        ttk.Button(obtns, text="Add to Monitor", command=self.add_scan_output_selected_to_monitor).pack(side="left", padx=4)
        ttk.Button(obtns, text="Export Scan…", command=self.export_scan_output).pack(side="left", padx=4)

        self.status = tk.StringVar(value="Ready.")
        ttk.Label(footer, textvariable=self.status, anchor="w").grid(row=0, column=1, sticky="ew", padx=(12,0))

        # ---------- ICONS: attach (Shodan: search & output) ----------
        _get_icon_manager().attach_to_tree(self.tree)
        _get_icon_manager().attach_to_tree(self.scan_tree)

    def set_status(self, msg):
        self.status.set(msg)

    def do_search(self):
        q = self.query_var.get().strip()
        full_query = f"minecraft {q}" if q else "minecraft"

        # MAIN THREAD: ensure key (may open a dialog)
        key = ensure_shodan_key_ui(self)
        if not key:
            self.set_status("Search canceled: no Shodan API key.")
            return

        self.set_status(f"Searching: {full_query}")
        self.tree.delete(*self.tree.get_children())

        def work(k=key, fq=full_query):
            try:
                matches = search_shodan(fq, k) or []
                rows = []
                for m in matches:
                    ip = f"{m.get('ip_str')}:{m.get('port', 25565)}"
                    if is_ignored(ip):
                        continue
                    data = m.get("data", "")
                    motd = parse_description_from_raw(data)
                    players = parse_players(data)
                    version = parse_version(data)
                    rows.append((ip, motd, players, version))
                self.results = rows

                def insert_all():
                    for row in rows:
                        self.tree.insert("", "end", values=row)
                    self.set_status(f"Found {len(rows)} (ignored filtered).")

                self.after(0, insert_all)

            except shodan.APIError as e:
                msg = str(e)

                def report_error():
                    self.set_status(f"Search failed: {msg}")
                    if "invalid" in msg.lower() or "unauthorized" in msg.lower():
                        try:
                            if os.path.exists(SHODAN_KEY_PATH):
                                os.remove(SHODAN_KEY_PATH)
                        except Exception:
                            pass
                        messagebox.showerror(
                            "Shodan",
                            "The Shodan API key appears to be invalid.\n"
                            "I removed shodan_key.txt. Search again and enter a valid key."
                        )

                self.after(0, report_error)

            except Exception as e:
                self.after(0, lambda: self.set_status(f"Search failed: {e}"))

        threading.Thread(target=work, daemon=True).start()
        return


    def _search_selected_ips(self):
        sel = []
        for iid in self.tree.selection():
            vals = self.tree.item(iid, "values")
            if vals:
                sel.append(vals[0])
        return list(dict.fromkeys(sel))

    def _all_selected_ips(self):
        ips = self._search_selected_ips()
        for vals in self._scan_selected_rows():
            if vals:
                ips.append(vals[0])
        seen = []
        for ip in ips:
            if ip not in seen:
                seen.append(ip)
        return seen

    # ---- Scan Output helpers ----
    def _scan_selected_rows(self):  #
        out = []
        for iid in self.scan_tree.selection():
            vals = self.scan_tree.item(iid, "values")
            if vals:
                out.append(vals)
        return out

    def copy_scan_selected(self):
        rows = self._scan_selected_rows()
        if not rows:
            messagebox.showinfo("Info", "Select scan output rows.")
            return
        ips = [row[0] for row in rows]
        self.clipboard_clear()
        self.clipboard_append("\n".join(ips))
        self.set_status(f"Copied {len(ips)} IP(s) from scan output.")

    def ignore_selected(self):  
        sel = self._all_selected_ips()
        if not sel:
            messagebox.showinfo("Info","Select items first.")
            return
        reason = ask_reason_with_whitelist(self, "Reason", "Why ignore? (optional)")
        if reason is None:
            self.set_status("Ignore cancelled.")
            return
        for ip in sel:
            add_to_ignore(ip, reason or "")
        for iid in list(self.tree.selection()):
            self.tree.delete(iid)
        self.set_status(f"Added {len(sel)} to ignore.txt")

    def save_selected(self):  
        sel = self._all_selected_ips()
        if not sel:
            messagebox.showinfo("Info","Select items first.")
            return
        reason = simpledialog.askstring("Reason","Why save? (optional)")
        for ip in sel:
            add_to_saved(ip, reason or "")
        self.set_status(f"Added {len(sel)} to saved.txt")

    def add_search_selected_to_monitor(self):
        sel = self._all_selected_ips()
        if not sel:
            messagebox.showinfo("Info","Select items first.")
            return
        added, invalid, duplicates = add_ips_to_monitor_list(sel)
        self.set_status(format_monitor_feedback(added, invalid, duplicates))

    def ignore_scan_selected_from_output(self):
        rows = self._scan_selected_rows()
        if not rows:
            messagebox.showinfo("Info", "Select scan output rows.")
            return
        reason = ask_reason_with_whitelist(self, "Reason", "Why ignore? (optional)")
        if reason is None:
            self.set_status("Ignore cancelled.")
            return
        for ip, *_ in rows:
            add_to_ignore(ip, reason or "")
        for iid in list(self.scan_tree.selection()):
            self.scan_tree.delete(iid)
        self.set_status(f"Added {len(rows)} to ignore.txt from scan output.")

    def save_scan_selected_from_output(self):
        rows = self._scan_selected_rows()
        if not rows:
            messagebox.showinfo("Info", "Select scan output rows.")
            return
        reason = simpledialog.askstring("Reason","Why save? (optional)")
        for ip, *_ in rows:
            add_to_saved(ip, reason or "")
        self.set_status(f"Added {len(rows)} to saved.txt from scan output.")

    def add_scan_output_selected_to_monitor(self):
        rows = self._scan_selected_rows()
        if not rows:
            messagebox.showinfo("Info", "Select scan output rows.")
            return
        ips = [row[0] for row in rows]
        added, invalid, duplicates = add_ips_to_monitor_list(ips)
        self.set_status(format_monitor_feedback(added, invalid, duplicates))

    def export_scan_output(self):  
        rows = []
        for iid in self.scan_tree.get_children():
            vals = self.scan_tree.item(iid, "values")
            if vals:
                rows.append(vals)
        if not rows:
            messagebox.showinfo("Info", "No scan output to export.")
            return
        q = self.query_var.get().strip()
        base = sanitize_query_for_filename((q if q else "minecraft") + "_scan")
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files","*.txt")],
            title="Export Shodan Scan Output",
            initialfile=f"{base}.txt"
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            for row in rows:
                if not row:
                    continue
                ip = row[0]
                motd = row[1] if len(row) > 1 else ""
                players = row[2] if len(row) > 2 else "N/A"
                version = row[3] if len(row) > 3 else "N/A"
                if "/" in str(players):
                    online, maximum = str(players).split("/", 1)
                else:
                    online, maximum = "N", "A"
                f.write(format_result_line(ip, motd, online, maximum, version) + "\n")
        self.set_status(f"Exported {len(rows)} scan rows to {os.path.basename(path)}")

    def search_players(self):
        query_raw = self.player_search_var.get() or ""
        query = query_raw.strip().lower()
        if not query:
            self.set_status("Enter a player name to search.")
            return
        matches = []
        for iid in self.scan_tree.get_children():
            vals = self.scan_tree.item(iid, "values")
            if not vals:
                continue
            players_text = vals[5] if len(vals) >= 6 else (vals[-1] if vals else "")
            if isinstance(players_text, str) and query in players_text.lower():
                matches.append(iid)
        current_sel = self.scan_tree.selection()
        if current_sel:
            self.scan_tree.selection_remove(current_sel)
        if matches:
            self.scan_tree.selection_set(matches)
            self.scan_tree.focus(matches[0])
            self.scan_tree.see(matches[0])
            self.set_status(f"Found {len(matches)} match(es) for '{query_raw.strip()}'.")
        else:
            self.set_status(f"No matches for '{query_raw.strip()}'.")

    def _scan_and_show(self, items):
        for iid in self.scan_tree.get_children():
            self.scan_tree.delete(iid)
        self.set_status("Preparing scan...")

        def work():
            try:
                def on_start(ip):
                    self._current_scan_ip = ip
                    self.after(0, lambda ip=ip: self.set_status(f"Currently scanning: {ip} [0/{len(items)}]"))

                def on_result(r, line):
                    if not r:
                        return

                    if not self.only_players_var.get() or r.get('players', 0) > 0:
                        active_players = format_player_list(r.get('players_sample'))
                        vals = (
                            r['ip'],
                            r['motd'],
                            f"{r['players']}/{r['max_players']}",
                            r['version'],
                            "Yes" if r.get('cracked') else "No",
                            active_players
                        )
                        self.after(0, lambda v=vals: self.scan_tree.insert("", "end", values=v))

                def on_progress(done, total):
                    ip = self._current_scan_ip or "…"
                    self.after(0, lambda d=done, t=total, ip=ip:
                               self.set_status(f"Currently scanning: {ip} [{d}/{t}]"))

                results, online_lines = scan_servers_gui(
                    items, on_start=on_start, on_result=on_result, on_progress=on_progress
                )
                self.after(0, lambda: self.set_status(f"Scan complete. Responded: {len(results)}; With 1+: {len(online_lines)}"))
            except Exception as e:
                self.after(0, lambda: self.set_status(f"Scan failed: {e}"))

        threading.Thread(target=work, daemon=True).start()

    def scan_selected(self):  
        sel = self._all_selected_ips()
        if not sel:
            messagebox.showinfo("Info","Select items in the table.")
            return
        self._scan_and_show(sel)

    def scan_all(self): 
        if not self.results:
            messagebox.showinfo("Info","Run a search first.")
            return
        all_ips = [row[0] for row in self.results]
        self._scan_and_show(all_ips)

    def copy_selected(self):
        sel = self._all_selected_ips()
        if not sel:
            messagebox.showinfo("Info","Select items first.")
            return
        self.clipboard_clear()
        self.clipboard_append("\n".join(sel))
        self.set_status(f"Copied {len(sel)} IP(s).")

    def export_search_results(self): 
        if not self.results:
            messagebox.showinfo("Info","No search results to export.")
            return
        q = self.query_var.get().strip()
        base = sanitize_query_for_filename(q if q else "minecraft")
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files","*.txt")],
            title="Export Shodan Search Results",
            initialfile=f"{base}.txt"
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            for (ip, motd, players, version) in self.results:
                if "/" in players:
                    online, maximum = players.split("/", 1)
                else:
                    online, maximum = "N", "A"
                f.write(format_result_line(ip, motd, online, maximum, version) + "\n")
        self.set_status(f"Exported {len(self.results)} rows to {os.path.basename(path)}")

# ---- JSON Search Tab ----
class JSONTab(ttk.Frame):  
    def __init__(self, master):
        super().__init__(master)
        self._in_ignore = False
        self.json_entries = []
        self.all_rows = []
        self._loaded_json_path = None
        self._build_ui()
        self._current_scan_ip = None
        self.search_rows = []  # list[tuple(ip,motd,players,version)]
        default_path = self.file_var.get().strip()
        if default_path and os.path.exists(default_path):
            self.load_json_file(default_path)

    def _build_ui(self):
        # Root grid: content (row 0) + footer (row 1) pinned
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        content = ttk.Frame(self)
        content.grid(row=0, column=0, sticky="nsew")

        bar = ttk.Frame(content)
        bar.pack(fill="x", padx=8, pady=8)

        self.file_var = tk.StringVar(value=DEFAULT_JSONL_FILE)
        ttk.Entry(bar, textvariable=self.file_var, width=48).pack(side="left", padx=4)
        ttk.Button(bar, text="Import .json", command=self.pick_json).pack(side="left", padx=4)

        self.query_var = tk.StringVar()
        ttk.Entry(bar, textvariable=self.query_var, width=48).pack(side="left", padx=4)
        ttk.Button(bar, text="Search", command=self.search).pack(side="left")
        ttk.Button(bar, text="Export Search…", command=self.export_search_results).pack(side="left", padx=6)

        pane = tk.PanedWindow(content, orient="vertical", sashwidth=8)
        pane.pack(fill="both", expand=True, padx=8, pady=4)

        mid = ttk.Frame(pane)
        pane.add(mid, minsize=260)

        # Search results Treeview with same columns
        cols = ("ip","motd","players","version")
        self.search_tree = ttk.Treeview(mid, columns=cols, show="headings", height=12, selectmode="extended")
        for c in cols:
            self.search_tree.heading(c, text=c.upper())
            if c == "motd":
                width = 240
            elif c == "players":
                width = 120
            elif c == "version":
                width = 120
            else:
                width = 170
            self.search_tree.column(c, width=width, anchor="w")
        self.search_tree.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(mid, orient="vertical", command=self.search_tree.yview)
        sb.pack(side="left", fill="y")
        self.search_tree.config(yscrollcommand=sb.set)
        make_tree_sortable(self.search_tree, {
            "ip": _ip_key,
            "motd": lambda v: str(v).lower(),
            "players": _players_key,
            "version": _version_key
        })

        right = ttk.Frame(mid)
        right.pack(side="right", fill="y", padx=8)
        ttk.Button(right, text="Copy IP(s)", command=self.copy_ip).pack(fill="x", pady=2)
        ttk.Button(right, text="Add to Ignore", command=self.add_ignore).pack(fill="x", pady=2)
        ttk.Button(right, text="Add to Saved", command=self.add_saved).pack(fill="x", pady=2)
        ttk.Button(right, text="Add to Monitor", command=self.add_search_selected_to_monitor).pack(fill="x", pady=2)
        ttk.Separator(right, orient="horizontal").pack(fill="x", pady=6)
        ttk.Button(right, text="Scan Selected", command=self.scan_selected).pack(fill="x", pady=2)
        ttk.Button(right, text="Scan All", command=self.scan_all).pack(fill="x", pady=2)
        self.only_players_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(right, text="Only players > 0", variable=self.only_players_var).pack(anchor="w", pady=(8,0))

        # Scan output -> Treeview (still inside content)
        out = ttk.Frame(pane)
        pane.add(out, minsize=220)
        ttk.Label(out, text="Scan Output (select to copy/save/ignore):").pack(anchor="w")
        of = ttk.Frame(out)
        of.pack(fill="both", expand=True)

        cols2 = ("ip","motd","players","version","cracked","active_players")
        self.scan_tree = ttk.Treeview(of, columns=cols2, show="headings", height=8, selectmode="extended")
        for c in cols2:
            self.scan_tree.heading(c, text=c.upper())
            if c in ("motd", "active_players"):
                width = 240
            elif c == "players":
                width = 130
            elif c == "version":
                width = 130
            elif c == "cracked":
                width = 90
            else:
                width = 170
            self.scan_tree.column(c, width=width, anchor="w")
        self.scan_tree.pack(side="left", fill="both", expand=True)
        osb = ttk.Scrollbar(of, orient="vertical", command=self.scan_tree.yview)
        osb.pack(side="left", fill="y")
        self.scan_tree.config(yscrollcommand=osb.set)
        make_tree_sortable(self.scan_tree, {
            "ip": _ip_key,
            "motd": lambda v: str(v).lower(),
            "players": _players_key,
            "version": _version_key,
            "cracked": lambda v: (0 if str(v).lower() in ("false","no","0") else 1) if v is not None else -1,
            "active_players": lambda v: str(v).lower()
        })

        # ------- Footer (pinned) -------
        footer = ttk.Frame(self)
        footer.grid(row=1, column=0, sticky="ew", padx=8, pady=(6,8))
        footer.grid_columnconfigure(1, weight=1)

        obtns = ttk.Frame(footer)
        obtns.grid(row=0, column=0, sticky="w")
        ttk.Button(obtns, text="Copy IP(s)", command=self.copy_scan_selected).pack(side="left", padx=4)
        ttk.Button(obtns, text="Add to Ignore", command=self.ignore_scan_selected).pack(side="left", padx=4)
        ttk.Button(obtns, text="Add to Saved", command=self.save_scan_selected).pack(side="left", padx=4)
        ttk.Button(obtns, text="Add to Monitor", command=self.add_scan_output_selected_to_monitor).pack(side="left", padx=4)
        ttk.Button(obtns, text="Export Scan…", command=self.export_scan_output).pack(side="left", padx=4)
        self.player_search_var = tk.StringVar()
        search_entry = ttk.Entry(obtns, textvariable=self.player_search_var, width=18)
        search_entry.pack(side="left", padx=(12,4))
        search_entry.bind("<Return>", lambda _e: self.search_players())
        ttk.Button(obtns, text="Find Player", command=self.search_players).pack(side="left", padx=4)

        self.status = tk.StringVar(value="Ready.")
        ttk.Label(footer, textvariable=self.status, anchor="w").grid(row=0, column=1, sticky="ew", padx=(12,0))

        # ---------- ICONS: attach (JSON: search & output) ----------
        _get_icon_manager().attach_to_tree(self.search_tree)
        _get_icon_manager().attach_to_tree(self.scan_tree)

    def set_status(self,msg):
        self.status.set(msg)

    def _populate_search_tree(self, rows):
        self.search_tree.delete(*self.search_tree.get_children())
        for ip, motd, players, version in rows:
            self.search_tree.insert("", "end", values=(ip, motd, players, version))

    def _load_json_data(self, path):
        entries = load_json_entries(path)
        rows = json_entries_to_rows(entries)
        return entries, rows

    def load_json_file(self, path):
        if not path:
            return
        self._populate_search_tree([])
        self.set_status("Loading JSON…")
        def work():
            try:
                entries, rows = self._load_json_data(path)
                def update():
                    self.json_entries = entries
                    self.all_rows = rows
                    self.search_rows = list(rows)
                    self._loaded_json_path = path
                    self._populate_search_tree(rows)
                    self.set_status(f"Loaded {len(rows)} entries from {os.path.basename(path)}.")
                self.after(0, update)
            except Exception as e:
                self.after(0, lambda: self.set_status(f"Load failed: {e}"))
        threading.Thread(target=work, daemon=True).start()

    def pick_json(self):
        path = filedialog.askopenfilename(title="Pick JSON Lines", filetypes=[("JSON/JSONL","*.json *.jsonl *.*")])
        if path:
            self.file_var.set(path)
            self.load_json_file(path)

    def search(self):
        file_path = self.file_var.get().strip()
        query = self.query_var.get().strip()
        status_msg = "Searching..." if query else "Loading data..."
        self.set_status(status_msg)
        self._populate_search_tree([])
        def work():
            try:
                if not self.json_entries or self._loaded_json_path != file_path:
                    entries, rows = self._load_json_data(file_path)
                    self.json_entries = entries
                    self.all_rows = rows
                    self._loaded_json_path = file_path
                if not query:
                    rows = json_entries_to_rows(self.json_entries)
                    self.all_rows = rows
                    result_message = f"Showing all {len(rows)} entrie(s)."
                else:
                    filtered = filter_entries_JSON(self.json_entries, query)
                    rows = []
                    seen = set()
                    for line in filtered:
                        ip, motd, players, version = parse_formatted_line(line)
                        ip = get_ip_only(ip)
                        if not is_valid_ip_port(ip) or is_ignored(ip) or ip in seen:
                            continue
                        rows.append((ip, motd, players, version))
                        seen.add(ip)
                    result_message = f"{len(rows)} result(s)."
                def update():
                    self.search_rows = list(rows)
                    if not query:
                        self.all_rows = list(rows)
                    self._populate_search_tree(rows)
                    self.set_status(result_message)
                self.after(0, update)
            except FileNotFoundError:
                self.after(0, lambda: self.set_status(f"File not found: {file_path}"))
            except Exception as e:
                self.after(0, lambda: self.set_status(f"Search failed: {e}"))
        threading.Thread(target=work, daemon=True).start()

    def _search_selected_rows(self):  #
        out = []
        for iid in self.search_tree.selection():
            vals = self.search_tree.item(iid, "values")
            if vals:
                out.append(vals)
        return out

    def _search_selected_ips(self):
        return [row[0] for row in self._search_selected_rows() if row]

    def _all_selected_ips(self):
        ips = self._search_selected_ips()
        for row in self._scan_selected_rows():
            if row:
                ips.append(row[0])
        seen = []
        for ip in ips:
            if ip not in seen:
                seen.append(ip)
        return seen

    def copy_ip(self):
        ips = self._all_selected_ips()
        if not ips:
            messagebox.showinfo("Info","Select items first.")
            return
        self.clipboard_clear()
        self.clipboard_append("\n".join(ips))
        self.set_status(f"Copied {len(ips)} IP(s).")

    def add_ignore(self):
        if self._in_ignore:
            return
        rows = self._search_selected_rows()
        if not rows:
            messagebox.showinfo("Info","Select items first.")
            return
        reason = ask_reason_with_whitelist(self, "Reason", "Why ignore? (optional)")
        if reason is None:
            self.set_status("Ignore cancelled.")
            return
        self._in_ignore = True
        try:
            for (ip, *_rest) in rows:
                add_to_ignore(ip, reason or "")
            # remove from tree
            for iid in list(self.search_tree.selection()):
                self.search_tree.delete(iid)
            self.set_status(f"Added {len(rows)} to ignore.txt")
        finally:
            self._in_ignore = False

    def add_saved(self):
        rows = self._search_selected_rows()
        if not rows:
            messagebox.showinfo("Info","Select items first.")
            return
        reason = simpledialog.askstring("Reason","Why save? (optional)")
        for (ip, *_rest) in rows:
            add_to_saved(ip, reason or "")
        self.set_status(f"Added {len(rows)} to saved.txt")

    def add_search_selected_to_monitor(self):
        ips = self._all_selected_ips()
        if not ips:
            messagebox.showinfo("Info","Select items first.")
            return
        added, invalid, duplicates = add_ips_to_monitor_list(ips)
        self.set_status(format_monitor_feedback(added, invalid, duplicates))

    def add_search_selected_to_monitor(self):
        rows = self._search_selected_rows()
        if not rows:
            messagebox.showinfo("Info","Select items first.")
            return
        ips = [row[0] for row in rows]
        added, invalid, duplicates = add_ips_to_monitor_list(ips)
        self.set_status(format_monitor_feedback(added, invalid, duplicates))

    # ---- JSON scan-output helpers ----
    def _scan_selected_rows(self):
        out = []
        for iid in self.scan_tree.selection():
            vals = self.scan_tree.item(iid, "values")
            if vals:
                out.append(vals)
        return out

    def search_players(self):
        query_raw = self.player_search_var.get() or ""
        query = query_raw.strip().lower()
        if not query:
            self.set_status("Enter a player name to search.")
            return
        matches = []
        for iid in self.scan_tree.get_children():
            vals = self.scan_tree.item(iid, "values")
            if not vals:
                continue
            players_text = vals[5] if len(vals) >= 6 else (vals[-1] if vals else "")
            if isinstance(players_text, str) and query in players_text.lower():
                matches.append(iid)
        current_sel = self.scan_tree.selection()
        if current_sel:
            self.scan_tree.selection_remove(current_sel)
        if matches:
            self.scan_tree.selection_set(matches)
            self.scan_tree.focus(matches[0])
            self.scan_tree.see(matches[0])
            self.set_status(f"Found {len(matches)} match(es) for '{query_raw.strip()}'.")
        else:
            self.set_status(f"No matches for '{query_raw.strip()}'.")

    def _scan_and_show(self, items):
        for iid in self.scan_tree.get_children():
            self.scan_tree.delete(iid)
        self.set_status("Preparing scan...")

        def work():
            try:
                total = len(items)
                def on_start(ip):
                    self._current_scan_ip = ip
                    self.after(0, lambda ip=ip: self.set_status(f"Currently scanning: {ip} [0/{total}]"))

                def on_result(r, line):
                    if not r:
                        return

                    if not self.only_players_var.get() or r.get('players', 0) > 0:
                        active_players = format_player_list(r.get('players_sample'))
                        vals = (
                            r['ip'],
                            r['motd'],
                            f"{r['players']}/{r['max_players']}",
                            r['version'],
                            "Yes" if r.get('cracked') else "No",
                            active_players
                        )
                        self.after(0, lambda v=vals: self.scan_tree.insert("", "end", values=v))

                def on_progress(done, total):
                    ip = self._current_scan_ip or "…"
                    self.after(0, lambda d=done, t=total, ip=ip:
                               self.set_status(f"Currently scanning: {ip} [{d}/{t}]"))

                results, online_lines = scan_servers_gui(
                    items, on_start=on_start, on_result=on_result, on_progress=on_progress
                )
                self.after(0, lambda: self.set_status(f"Scan complete. Responded: {len(results)}; With 1+: {len(online_lines)}"))
            except Exception as e:
                self.after(0, lambda: self.set_status(f"Scan failed: {e}"))

        threading.Thread(target=work, daemon=True).start()

    def scan_selected(self):
        ips = self._all_selected_ips()
        if not ips:
            messagebox.showinfo("Info","Select items first.")
            return
        self._scan_and_show(ips)

    def scan_all(self):
        if not self.search_rows:
            messagebox.showinfo("Info","Run a search first.")
            return
        ips = [row[0] for row in self.search_rows]
        self._scan_and_show(ips)

    def copy_scan_selected(self):
        rows = self._scan_selected_rows()
        if not rows:
            messagebox.showinfo("Info", "Select scan output rows.")
            return
        ips = [row[0] for row in rows]
        self.clipboard_clear()
        self.clipboard_append("\n".join(ips))
        self.set_status(f"Copied {len(ips)} IP(s) from scan output.")

    def ignore_scan_selected(self):
        rows = self._scan_selected_rows()
        if not rows:
            messagebox.showinfo("Info", "Select scan output rows.")
            return
        reason = ask_reason_with_whitelist(self, "Reason", "Why ignore? (optional)")
        if reason is None:
            self.set_status("Ignore cancelled.")
            return
        for (ip, *_rest) in rows:
            add_to_ignore(ip, reason or "")
        for iid in list(self.scan_tree.selection()):
            self.scan_tree.delete(iid)
        self.set_status(f"Added {len(rows)} to ignore.txt from scan output.")

    def save_scan_selected(self):
        rows = self._scan_selected_rows()
        if not rows:
            messagebox.showinfo("Info", "Select scan output rows.")
            return
        reason = simpledialog.askstring("Reason", "Why save? (optional)")
        for (ip, *_rest) in rows:
            add_to_saved(ip, reason or "")
        self.set_status(f"Added {len(rows)} to saved.txt from scan output.")

    def add_scan_output_selected_to_monitor(self):
        rows = self._scan_selected_rows()
        if not rows:
            messagebox.showinfo("Info", "Select scan output rows.")
            return
        ips = [row[0] for row in rows]
        added, invalid, duplicates = add_ips_to_monitor_list(ips)
        self.set_status(format_monitor_feedback(added, invalid, duplicates))

    def export_search_results(self):  #
        if not self.search_rows:
            messagebox.showinfo("Info","No search results to export.")
            return
        q = self.query_var.get().strip()
        base = sanitize_query_for_filename(q if q else "json_search")
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files","*.txt")],
            title="Export JSON Search Results",
            initialfile=f"{base}.txt"
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            for (ip, motd, players, version) in self.search_rows:
                online, maximum = ("N","A")
                if "/" in players:
                    parts = players.split("/",1)
                    online, maximum = parts[0], parts[1]
                f.write(format_result_line(ip, motd, online, maximum, version) + "\n")
        self.set_status(f"Exported {len(self.search_rows)} rows to {os.path.basename(path)}")

    def export_scan_output(self):  
        rows = []
        for iid in self.scan_tree.get_children():
            vals = self.scan_tree.item(iid, "values")
            if vals:
                rows.append(vals)
        if not rows:
            messagebox.showinfo("Info","No scan output to export.")
            return
        q = self.query_var.get().strip()
        base = sanitize_query_for_filename((q if q else "json_search") + "_scan")
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files","*.txt")],
            title="Export JSON Scan Output",
            initialfile=f"{base}.txt"
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            for row in rows:
                if not row:
                    continue
                ip = row[0]
                motd = row[1] if len(row) > 1 else ""
                players = row[2] if len(row) > 2 else "N/A"
                version = row[3] if len(row) > 3 else "N/A"
                if "/" in str(players):
                    online, maximum = str(players).split("/",1)
                else:
                    online, maximum = "N","A"
                f.write(format_result_line(ip, motd, online, maximum, version) + "\n")
        self.set_status(f"Exported {len(rows)} scan rows to {os.path.basename(path)}")

# ---- Export Tab ----
class ExportTab(ttk.Frame):  #
    def __init__(self, master):
        super().__init__(master)
        self._build_ui()

    def _build_ui(self):
        box = ttk.Frame(self)
        box.pack(fill="x", padx=8, pady=8)

        self.file_var = tk.StringVar()
        ttk.Entry(box, textvariable=self.file_var, width=60).pack(side="left", padx=4)
        ttk.Button(box, text="Pick .txt", command=self.pick_txt).pack(side="left", padx=4)

        self.backup_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self, text="Backup servers.dat if no backup exists", variable=self.backup_var).pack(anchor="w", padx=8)

        btns = ttk.Frame(self)
        btns.pack(fill="x", padx=8, pady=8)
        ttk.Button(btns, text="Export to servers.dat", command=self.do_import).pack(side="left", padx=4)
        ttk.Button(btns, text="Restore Backup", command=self.restore_backup).pack(side="left", padx=4)

        self.status = tk.StringVar(value="Ready.")
        ttk.Label(self, textvariable=self.status).pack(fill="x", padx=8, pady=8)

    def set_status(self,msg):
        self.status.set(msg)

    def pick_txt(self):
        path = filedialog.askopenfilename(title="Pick .txt source", filetypes=[("Text files","*.txt")])
        if path:
            self.file_var.set(path)

    def do_import(self):
        path = self.file_var.get().strip()
        if not path:
            messagebox.showinfo("Info","Pick a .txt first.")
            return
        def work():
            ok, msg = import_file_to_servers_dat(path, do_backup=self.backup_var.get())
            self.set_status(msg if ok else f"Failed: {msg}")
        threading.Thread(target=work, daemon=True).start()
        self.set_status("Importing...")

    def restore_backup(self):
        try:
            if not os.path.exists(BACKUP_PATH):
                messagebox.showinfo("Info","No backup found.")
                return
            shutil.copyfile(BACKUP_PATH, SERVERS_DAT_PATH)
            self.set_status("Backup restored.")
        except Exception as e:
            self.set_status(f"Restore failed: {e}")

# ---- Saved / Ignore (Reason file) Tab ----
class _ReasonFileTab(ttk.Frame):
    def __init__(self, master, file_path, tab_name):
        super().__init__(master)
        self.file_path = file_path
        self.tab_name = tab_name
        self.rows = []  # list[(ip, reason)]
        self._build_ui()
        self._load()

    def _build_ui(self):
        bar = ttk.Frame(self); bar.pack(fill="x", padx=8, pady=8)
        ttk.Button(bar, text="Add", command=self._add).pack(side="left", padx=2)
        ttk.Button(bar, text="Edit", command=self._edit).pack(side="left", padx=2)
        ttk.Button(bar, text="Remove", command=self._remove).pack(side="left", padx=2)
        ttk.Button(bar, text="Copy IP(s)", command=self._copy).pack(side="left", padx=8)
        ttk.Button(bar, text="Reload", command=self._load).pack(side="left", padx=8)
        ttk.Button(bar, text="Save", command=self._save).pack(side="left", padx=2)

        mid = ttk.Frame(self); mid.pack(fill="both", expand=True, padx=8, pady=(0,8))
        cols = ("ip", "reason")
        self.tree = ttk.Treeview(mid, columns=cols, show="headings", height=16, selectmode="extended")
        for c in cols:
            self.tree.heading(c, text=c.upper())
            width = 240 if c == "ip" else 600
            self.tree.column(c, width=width, anchor="w")
        self.tree.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        sb.pack(side="left", fill="y")
        self.tree.config(yscrollcommand=sb.set)

        # enable sorting
        make_tree_sortable(self.tree, {
            "ip": _ip_key,
            "reason": lambda v: str(v).lower()
        })


    def _load(self):
        self.rows = load_reason_file(self.file_path)
        self.tree.delete(*self.tree.get_children())
        for ip, reason in self.rows:
            self.tree.insert("", "end", values=(ip, reason))

    def _save(self):
        # collect from UI to rows
        rows = []
        for iid in self.tree.get_children():
            ip, reason = self.tree.item(iid, "values")
            if is_valid_ip_port(ip):
                rows.append((ip, reason))
        save_reason_file(self.file_path, rows)
        # refresh in-memory ignore set if needed
        if self.file_path == IGNORE_FILE:
            refresh_ignore_set()
        messagebox.showinfo(self.tab_name, "Saved.")

    def _selected_iids(self):
        return list(self.tree.selection())

    def _add(self):
        ip = simpledialog.askstring(self.tab_name, "IP:PORT")
        if not ip or not is_valid_ip_port(ip): return
        reason = simpledialog.askstring(self.tab_name, "Reason (optional)") or ""
        self.tree.insert("", "end", values=(get_ip_only(ip), reason))

    def _edit(self):
        iids = self._selected_iids()
        if not iids: return
        ip, reason = self.tree.item(iids[0], "values")
        new_ip = simpledialog.askstring(self.tab_name, "IP:PORT", initialvalue=ip) or ip
        if not is_valid_ip_port(get_ip_only(new_ip)): return
        new_reason = simpledialog.askstring(self.tab_name, "Reason", initialvalue=reason) or ""
        self.tree.item(iids[0], values=(get_ip_only(new_ip), new_reason))

    def _remove(self):
        for iid in self._selected_iids():
            self.tree.delete(iid)

    def _copy(self):
        ips = []
        for iid in self._selected_iids():
            v = self.tree.item(iid, "values")
            if v: ips.append(v[0])
        if not ips: return
        self.clipboard_clear(); self.clipboard_append("\n".join(ips))

class SavedTab(_ReasonFileTab):
    def __init__(self, master):
        super().__init__(master, SAVED_FILE, "Saved")

class IgnoreTab(_ReasonFileTab):
    def __init__(self, master):
        super().__init__(master, IGNORE_FILE, "Ignore")

# ---- IP Log (ips.txt) Tab ----
class IpLogTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.rows = []  # list[(ip,motd,players,version)]
        self._build_ui()
        self._load()

    def _build_ui(self):
        bar = ttk.Frame(self); bar.pack(fill="x", padx=8, pady=8)
        ttk.Button(bar, text="Add", command=self._add).pack(side="left", padx=2)
        ttk.Button(bar, text="Edit", command=self._edit).pack(side="left", padx=2)
        ttk.Button(bar, text="Remove", command=self._remove).pack(side="left", padx=2)
        ttk.Button(bar, text="Copy IP(s)", command=self._copy).pack(side="left", padx=8)
        ttk.Button(bar, text="Reload", command=self._load).pack(side="left", padx=8)
        ttk.Button(bar, text="Save", command=self._save).pack(side="left", padx=2)

        mid = ttk.Frame(self); mid.pack(fill="both", expand=True, padx=8, pady=(0,8))
        cols = ("ip","motd","players","version")
        self.tree = ttk.Treeview(mid, columns=cols, show="headings", height=16, selectmode="extended")
        for c in cols:
            self.tree.heading(c, text=c.upper())
            if c == "motd":
                width = 240
            elif c == "players":
                width = 120
            elif c == "version":
                width = 120
            else:
                width = 170
            self.tree.column(c, width=width, anchor="w")
        self.tree.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        sb.pack(side="left", fill="y")
        self.tree.config(yscrollcommand=sb.set)

        # enable sorting
        make_tree_sortable(self.tree, {
            "ip": _ip_key,
            "motd": lambda v: str(v).lower(),
            "players": _players_key,
            "version": _version_key
        })

    def _load(self):
        self.rows = load_ips_rows(GLOBAL_IP_LOG)
        self.tree.delete(*self.tree.get_children())
        for row in self.rows:
            self.tree.insert("", "end", values=row)

    def _save(self):
        rows = []
        for iid in self.tree.get_children():
            vals = self.tree.item(iid, "values")
            if vals and is_valid_ip_port(vals[0]):
                rows.append(vals)
        save_ips_rows(rows, GLOBAL_IP_LOG)
        messagebox.showinfo("IP Log", "Saved.")

    def _selected_iids(self):
        return list(self.tree.selection())

    def _add(self):
        ip = simpledialog.askstring("IP Log", "IP:PORT")
        if not ip or not is_valid_ip_port(ip): return
        motd = simpledialog.askstring("IP Log", "MOTD (optional)") or ""
        players = simpledialog.askstring("IP Log", "Players (e.g. 0/20 or N/A)", initialvalue="N/A") or "N/A"
        version = simpledialog.askstring("IP Log", "Version (optional)") or "N/A"
        self.tree.insert("", "end", values=(get_ip_only(ip), motd, players, version))

    def _edit(self):
        iids = self._selected_iids()
        if not iids: return
        ip, motd, players, version = self.tree.item(iids[0], "values")
        new_ip = simpledialog.askstring("IP Log", "IP:PORT", initialvalue=ip) or ip
        if not is_valid_ip_port(get_ip_only(new_ip)): return
        motd = simpledialog.askstring("IP Log", "MOTD", initialvalue=motd) or ""
        players = simpledialog.askstring("IP Log", "Players", initialvalue=players) or players
        version = simpledialog.askstring("IP Log", "Version", initialvalue=version) or version
        self.tree.item(iids[0], values=(get_ip_only(new_ip), motd, players, version))

    def _remove(self):
        for iid in self._selected_iids():
            self.tree.delete(iid)

    def _copy(self):
        ips = []
        for iid in self._selected_iids():
            v = self.tree.item(iid, "values")
            if v: ips.append(v[0])
        if not ips: return
        self.clipboard_clear(); self.clipboard_append("\n".join(ips))


class UserLogTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self._manager = None
        self._refresh_pending = False
        self._cached_entries = []
        self._build_ui()

    def _build_ui(self):
        bar = ttk.Frame(self); bar.pack(fill="x", padx=8, pady=8)
        ttk.Button(bar, text="Copy Player(s)", command=self.copy_players).pack(side="left", padx=2)
        ttk.Button(bar, text="Copy IP(s)", command=self.copy_ips).pack(side="left", padx=2)
        ttk.Button(bar, text="Export Log…", command=self.export_log).pack(side="left", padx=8)
        self.user_search_var = tk.StringVar()
        ttk.Entry(bar, textvariable=self.user_search_var, width=20).pack(side="left", padx=(4,4))
        ttk.Button(bar, text="Search Player", command=self.search_player_log).pack(side="left", padx=4)
        ttk.Button(bar, text="Clear Search", command=self.clear_player_log_search).pack(side="left", padx=4)

        mid = ttk.Frame(self); mid.pack(fill="both", expand=True, padx=8, pady=(0,8))
        cols = ("player", "ip", "motd", "last_seen")
        self.tree = ttk.Treeview(mid, columns=cols, show="headings", height=18, selectmode="extended")
        for c in cols:
            self.tree.heading(c, text=c.upper())
            if c == "motd":
                width = 360
            elif c == "ip":
                width = 170
            elif c == "last_seen":
                width = 170
            else:
                width = 200
            self.tree.column(c, width=width, anchor="w")
        self.tree.pack(side="left", fill="both", expand=True)
        sb = ttk.Scrollbar(mid, orient="vertical", command=self.tree.yview)
        sb.pack(side="left", fill="y")
        self.tree.config(yscrollcommand=sb.set)

        make_tree_sortable(self.tree, {
            "player": lambda v: str(v).lower(),
            "ip": _ip_key,
            "motd": lambda v: str(v).lower(),
            "last_seen": lambda v: str(v)
        })

        self.status = tk.StringVar(value="Ready.")
        ttk.Label(self, textvariable=self.status, anchor="w").pack(fill="x", padx=8, pady=(0,8))

    def bind_manager(self, manager: UserLogManager):
        self._manager = manager

    def request_refresh(self, initial=False):
        if not self._manager:
            return
        if self._refresh_pending and not initial:
            return
        self._refresh_pending = True
        try:
            self.after(0, self._refresh_from_manager)
        except Exception:
            self._refresh_pending = False

    def _refresh_from_manager(self):
        if not self._manager:
            self._refresh_pending = False
            return
        entries = self._manager.snapshot()
        entries.sort(key=lambda e: e["last_seen"], reverse=True)
        self._cached_entries = list(entries)
        self._populate_user_tree(entries)
        self.status.set(f"Tracking {len(entries)} player(s).")
        self._refresh_pending = False

    def _populate_user_tree(self, entries):
        self.tree.delete(*self.tree.get_children())
        for entry in entries:
            self.tree.insert(
                "",
                "end",
                values=(
                    entry["player"],
                    entry["ip"],
                    entry["motd"],
                    self._format_last_seen(entry["last_seen"])
                )
            )

    def search_player_log(self):
        query = (self.user_search_var.get() or "").strip().lower()
        if not query:
            self.set_status("Enter a player name to search.")
            return
        matches = [
            entry for entry in self._cached_entries
            if query in (entry.get("player") or "").lower()
        ]
        self._populate_user_tree(matches)
        self.set_status(f"{len(matches)} match(es) for '{self.user_search_var.get().strip()}'.")

    def clear_player_log_search(self):
        self.user_search_var.set("")
        self._populate_user_tree(self._cached_entries)
        self.set_status(f"Tracking {len(self._cached_entries)} player(s).")

    def _format_last_seen(self, ts):
        try:
            return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
        except Exception:
            return "-"

    def _selected_rows(self):
        rows = []
        for iid in self.tree.selection():
            vals = self.tree.item(iid, "values")
            if vals:
                rows.append(vals)
        return rows

    def copy_players(self):
        rows = self._selected_rows()
        if not rows:
            messagebox.showinfo("User Log", "Select one or more rows.")
            return
        players = [row[0] for row in rows]
        self.clipboard_clear()
        self.clipboard_append("\n".join(players))
        self.status.set(f"Copied {len(players)} player(s).")

    def copy_ips(self):
        rows = self._selected_rows()
        if not rows:
            messagebox.showinfo("User Log", "Select one or more rows.")
            return
        ips = [row[1] for row in rows]
        self.clipboard_clear()
        self.clipboard_append("\n".join(ips))
        self.status.set(f"Copied {len(ips)} IP(s).")

    def export_log(self):
        if not self._cached_entries:
            messagebox.showinfo("User Log", "Nothing to export yet.")
            return
        path = filedialog.asksaveasfilename(
            title="Export User Log",
            defaultextension=".txt",
            filetypes=[("Text files","*.txt")]
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                for entry in self._cached_entries:
                    ts = self._format_last_seen(entry["last_seen"])
                    motd = sanitize_motd(entry["motd"])
                    f.write(f"{entry['player']} | {entry['ip']} | Last Seen: {ts} | MOTD: {motd}\n")
            self.status.set(f"Exported {len(self._cached_entries)} player(s) to {os.path.basename(path)}.")
        except Exception as e:
            self.status.set(f"Export failed: {e}")
            messagebox.showerror("User Log", f"Export failed: {e}")



def main():  #gone but not forgotten
    pass

# ==================== GUI Entry ====================

if __name__ == "__main__":  #
    app = FullAppGUI()
    app.mainloop()
