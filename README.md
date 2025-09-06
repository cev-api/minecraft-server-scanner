# Minecraft Server Scanner

A desktop GUI for discovering and testing Minecraft servers. It searches Shodan, imports/exports server lists, pings servers concurrently to fetch live status, and can export results directly into your Minecraft `servers.dat`.

![UI](https://i.imgur.com/t1dlk7Y.png)

---

## What it does

- **Shodan search:** Enter a query (the app prepends `minecraft` for you) and browse results in a sortable table: **ICON**, **IP**, **MOTD**, **Players**, **Version**.
- **Status scan:** Ping selected or all servers in any tab. Scans run concurrently and stream results back into a results table.
- **JSON search:** Load a local Shodan dump (`.json`/`.jsonl`) and run boolean searches (AND/OR/NOT with parentheses). View and scan matches.
- **Import/export lists:**  
  - Load `.txt` lists into the GUI.  
  - Export search/scan results as `.txt` in a consistent, human-readable format.
- **Ignore / Saved lists:** Add servers to `ignore.txt` or `saved.txt` (with optional reasons) from any table; ignored servers are filtered everywhere.
- **Minecraft integration:** Export any `.txt` list into `%APPDATA%\.minecraft\servers.dat` (creates a one-time `.bak` backup if none exists).
- **Player filter:** Only show severs that have currently active players.

---

## Tabs & workflows

### Servers
- Load a `.txt` list into a sortable table.
- Scan **Selected** or **All**; live results appear below in another table.
- Actions on either table: **Copy IP(s)**, **Add to Ignore**, **Add to Saved**, **Export Scan…**.
- Optional filter: “Only players > 0” for scan output.

### Shodan
- Type a query **without** the word `minecraft` (the app prepends it).
- Results table is sortable with actions identical to the Servers tab.
- Scan **Selected/All** from the results; export results or scan output.

### JSON Search
- Point at a local `minecraft_servers.json`/`.jsonl` or any JSON Lines file with Shodan entries.
- Enter a boolean query (see below) and browse sortable matches.
- Scan **Selected/All**; export search results or scan output.

### Export to MC
- Choose a `.txt` and export it directly into `%APPDATA%\.minecraft\servers.dat`.
- On first export (and if no backup exists), a `%APPDATA%\.minecraft\servers.dat.bak` is created.
- Includes a **Restore Backup** button.

### Saved List
- Reads your saved.txt and allows editing and copying

### Ignore List
- Reads your ignore.txt and allows editing and copying

### IP Log
- Reads your ips.txt and allows editing and copying

  
---

## Boolean search (JSON tab)

The JSON search matches across common Shodan fields (`ip_str`, `port`, `data`, `minecraft`, `location`, `version`, `hostnames`).

Supported:
- `AND`, `OR`, `NOT` (case-insensitive)
- Parentheses for grouping

Examples:
```
java AND (version.1.21 OR version.1.20) AND (survival OR anarchy)
```

---

## Files the app reads/writes

All paths are relative to the app’s working directory unless stated otherwise.

- `shodan_key.txt` — your Shodan API key (first line). Managed by the app.
- `ignore.txt` — entries you choose to ignore. Lines look like:
  ```
  1.2.3.4:25565 | Reason: <your note or "No reason">
  ```
- `saved.txt` — entries you’ve saved for later consideration, same format as above.
- `ips.txt` — a global log of known servers. Updated by scans to keep latest MOTD/players/version.
- `%APPDATA%\.minecraft\servers.dat` — target file for **Export**.
- `%APPDATA%\.minecraft\servers.dat.bak` — one-time backup created by the app if none exists.

---

## Scanning behavior

- **Concurrent workers:** `MAX_WORKERS = 100`  
- **Socket timeout:** `TIMEOUT = 3` seconds  
- **Protocol version:** `PROTOCOL_VERSION = 772` (adjust in code if needed)  
- Results stream into the UI as they arrive; an optional “Only players > 0” filter is available on output tables.

---

## Export formats

All export actions produce plain `.txt` where every line is in the canonical format:

```
<IP:PORT> | MOTD: <text> | Players: <online>/<max> | Version: <version>
```

This is the same format the importer accepts, which makes round-tripping easy.

---

## Notes & limits

- Shodan access requires a valid API key and is subject to Shodan’s rate limits and terms.
- Some servers may not respond to status pings, return partial data, or throttle connections.
- The app filters out anything listed in `ignore.txt` across all tabs and workflows.

---

## Purpose

This project streamlines the full loop of **discover → triage → verify → keep/ignore → export** for Minecraft servers. It replaces manual shell scripts and ad-hoc text parsing with a single, fast GUI that stays consistent across Shodan searches, local JSON dumps, and your own text lists—right up to expprting into Minecraft’s `servers.dat`.

I created this to replace my [Web UI version](https://github.com/cev-api/minecraft-server-scanner-web-ui) of the same app, which in turn was a replacement for a CLI version of the same app. I like this one the most! Enjoy!


