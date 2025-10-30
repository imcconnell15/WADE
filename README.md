# WADE
Automation Framework

WADE – Linux Install & Staging (Heuristic)

Build a lightweight, heuristic-driven staging daemon on Linux that classifies and routes forensic artifacts (disk images, memory dumps, network configs) into a shared pipeline with full vs light processing profiles — all while maintaining idempotency, auditability, and zero heavy tooling in staging

This doc captures the current Linux side of WADE: install, the staging daemon (Python), how to use wade.env, the systemd service .conf, how the “full vs light” intake works, and the new work‑order queue in the share for remote pipeline servers.
⸻
1) Components at a glance

- Install script: install_beta.sh (sets up base packages, users, dirs; see your script for specifics).
- Staging daemon: /opt/wade/stage_daemon.py (Python, heuristic classification; no heavy tools required).
- Systemd service: /etc/systemd/system/wade-staging.service (manages the daemon).
- Environment: /etc/wade/wade.env (all tunables live here).
- Shared folders (exported via SMB/NFS as you prefer):
    - Staging intake: /home/<owner>/<Staging>/full and /home/<owner>/<Staging>/light
    - Data deposit: /home/<owner>/<DataSources>
    - Queue (work‑orders): configurable; default is /home/<owner>/<DataSources>/_queue

<owner> defaults to autopsy. <Staging> defaults to Staging. <DataSources> defaults to DataSources. All are configurable via wade.env.
⸻
2) Directory layout (default)

/home/autopsy/
  ├─ Staging/
  │   ├─ full/          # drop images here for FULL pipeline
  │   └─ light/         # drop images here for LIGHT pipeline
  └─ DataSources/
      ├─ Hosts/<hostname>/...           # images moved/renamed here
      ├─ Network/<hostname>/cfg_*.txt   # router/switch configs
      └─ _queue/                        # JSON work-orders for remote workers
/var/wade/
  ├─ logs/stage/*.json   # one JSON per processed file
  └─ state/*.sqlite3     # local idempotency index (metadata signatures)

⸻
3) What the staging daemon does

- Watches two intake folders: Staging/full and Staging/light.
- Waits for file writes to stabilize, then classifies using signatures (no heavy tools):
    - E01 (EWF) by extension / file(1); notes fragmentation siblings .E02+.
    - Disk images (disk_raw) via GPT ("EFI PART" @ LBA1), MBR (0x55AA), or common FS boot markers (e.g., NTFS, FAT32).
    - Memory dumps (mem) via header hints (HIBR, LiME) or filename hints (e.g., .mem, hiberfil.sys), provided it doesn’t also look like a disk.
    - Network configs (network_config) as plain text with vendor fingerprints (Cisco IOS/IOS‑XE, Juniper, VyOS/EdgeOS, Arista EOS, MikroTik). Extracts hostname and version when available.
- Moves + renames into DataSources/Hosts/<hostname>/ or DataSources/Network/<hostname>/.
- Writes a per‑file JSON log to /var/wade/logs/stage/ with start/finish time, duration, classification, profile (full|light), and metadata.
- Creates a work‑order JSON in the shared queue (see §6) for downstream workers.

Idempotency: instead of hashing TB‑sized files, the daemon records a metadata signature (device, inode, size, mtime_ns) in a tiny SQLite DB. No re‑processing unless the file actually changes.
⸻
4) The .env – /etc/wade/wade.env

Add or edit keys like this (no quotes required, though supported):

# Core identities/paths
WADE_OWNER_USER=autopsy
WADE_DATADIR=DataSources
WADE_STAGINGDIR=Staging

# Scanner timing
WADE_STAGE_SCAN_INTERVAL=30       # seconds between sweeps
WADE_STAGE_STABLE_SECONDS=10      # how long size must remain stable

# Heuristic scan sizes
WADE_STAGE_HEAD_SCAN_BYTES=1048576        # read up to 1 MiB of header
WADE_STAGE_KDBG_SCAN_BYTES=0              # off (set >0 for tiny KDBG probe)
WADE_STAGE_TEXT_SNIFF_BYTES=131072        # text check for network configs
WADE_STAGE_TEXT_MIN_PRINTABLE_RATIO=0.92

# Queue location (in the share)
# If absolute (/path/...), use as-is. If relative, it's joined under /home/<owner>/<DataSources>/
WADE_QUEUE_DIR=_queue


Reload after edits: sudo systemctl restart wade-staging.
⸻
5) The systemd service .conf

/etc/systemd/system/wade-staging.service (key bits):

[Service]
User=autopsy
Group=autopsy
EnvironmentFile=-/etc/wade/wade.env
WorkingDirectory=/opt/wade
ExecStart=/usr/bin/python3 /opt/wade/stage_daemon.py
Restart=on-failure


Lifecycle:

sudo systemctl daemon-reload
sudo systemctl enable --now wade-staging.service
sudo systemctl status wade-staging.service
sudo journalctl -u wade-staging -f

⸻
6) Work‑order queue in the share

By default, queue files are written under:

/home/<owner>/<DataSources>/_queue/<classification>/<profile>/<uuid>.json


Why: Remote pipeline servers (Windows/Linux) can just watch this folder over SMB/NFS, pick up JSONs, and run the right tools based on classification and profile.

Work‑order schema (v1)

{
  "schema": "wade.queue.workorder",
  "version": 1,
  "id": "d95e6ed6-4a2b-43db-8a4b-8f2d15f9e4e2",
  "created_utc": "2025-10-24T15:30:12Z",
  "profile": "full",                     // or "light"
  "classification": "mem",               // e01 | mem | disk_raw | network_config
  "original_name": "HERMES.mem",
  "source_host": "zagreus",              // optional; producer host
  "dest_path": "/home/autopsy/DataSources/Hosts/HERMES/HERMES_2025-10-09.mem",
  "size_bytes": 123456789,
  "sig": "st_dev:st_ino:st_size:st_mtime_ns",

  // optional enrichments by type
  "hostname": "HERMES",
  "date_collected": "2025-10-09",
  "vendor": "cisco_ios",
  "os_version": "16.12",
  "fragmentation": { "fragmented": false, "parts": [] }
}


Atomicity: files are written as *.json.tmp then renamed to *.json to avoid half‑reads. Consumers should only read *.json and write their own, separate ack files or move completed JSONs to an archival subfolder (_done/…) to prevent reprocessing.
⸻
7) Full vs Light profiles (what runs later)

- full: run all tools (Linux + Windows) once your worker boxes are wired: Dissect, Hayabusa, YARA, Volatility, Plaso/log2timeline, Autopsy, and Zimmermann (RECmd, MFTECmd, etc.).
- light: skip heavy/GUI or long‑running steps (e.g., Autopsy, Plaso, RECmd), but still do the fast pass for triage.

The choice is encoded in the work‑order (profile), so your downstream workers can enforce it automatically.
⸻
8) Logs & troubleshooting

- Per‑file logs: /var/wade/logs/stage/*.json (searchable by Splunk or jq).
- Service logs: journalctl -u wade-staging -f
- Defragmentation helper (E01 multi‑part notice): DataSources/images_to_be_defragmented.log
⸻
9) Samba/NFS sharing notes (example)

Export Staging and DataSources (and thus _queue) over SMB:

- Share roots: /home/autopsy/Staging, /home/autopsy/DataSources
- Ensure autopsy owns these trees; disable “oplocks” if you see stale handle issues during large writes.
- For NFS, prefer sync and adequate rsize/wsize. Consider a dedicated _queue export for consumers.
⸻
10) Placeholders for upcoming pipeline stages

- Dissect: consume disk_raw and e01 work‑orders; output JSONL to wade_dissect index.
- Hayabusa: consume disk_raw/mounted, or host‑logs; output JSONL to wade_hayabusa.
- Volatility: consume mem; output JSONL to wade_volatility.
- YARA: consume any class; output to wade_yara.
- Plaso: (full only) consume disk_raw/e01; output to wade_plaso.
- Autopsy: (full only) receive images; keep artifacts under case dirs; export JSON for Splunk.

Each consumer should:
1. Watch _queue/<classification>/<profile>/*.json
2. Process the dest_path
3. Write its own results into tool‑specific folders and Splunk‑shippable JSON
4. Move the work‑order to _queue/_done/… (or write an .ack) to prevent re‑runs
⸻
11) Extending detection

- Add more vendors in stage_daemon.py (detect_network_config()): Cisco ASA/NX‑OS, FortiOS, PAN‑OS, etc.
- Tweak heuristics with WADE_STAGE_* env vars (see §4).
- If you need hostname extraction for memory without using Volatility in staging: we can defer hostname to the Volatility worker and update Splunk later; staging falls back to filename stem.
⸻
12) Security & performance tips

- Keep _queue small: consumers should drain and archive promptly.
- Consider read‑only exports for DataSources/Hosts/* to workers; only the _queue needs write for acks/moves.
- Avoid huge head scans: 1 MiB is usually enough to identify disk vs mem.
- The idempotency signature avoids multi‑TB hashing; switch to full hashing only in a downstream verification step if needed.
⸻
13) TL;DR workflow (operator POV)

1. Drop an image in Staging/full (or light).
2. Wait a minute: it’s moved to DataSources/..., a log shows up in /var/wade/logs/stage/, and a work‑order JSON appears under DataSources/_queue/....
3. Remote workers see the JSON, run the right tools, and ship results to Splunk.
4. Work‑order is archived by the worker when done.

Semper staging. 💪
