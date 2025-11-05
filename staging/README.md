# WADE Staging Daemon (Heuristic Edition – VM Aware)

The staging daemon watches two intake folders and classifies incoming evidence, moves it into `DataSources`, writes rich JSON logs, and enqueues work orders for downstream tooling.

## Intake folders

- `~/Staging/full/`
- `~/Staging/light/`

Files are considered *stable* when size hasn't changed for `WADE_STAGE_STABLE_SECONDS` (default 10s).

## Classifications

- `e01` — EnCase EWF images (fragment-awareness for `.E0[2-9]*`).
- `mem` — Memory dumps (HIBR, LiME, or filename hints; Volatility metadata if available).
- `vm_disk` — **Virtualization disk images**: `vmdk`, `vhd`, `vhdx`, `qcow/qcow2`, `vdi`.
- `disk_raw` — Generic raw / bootable disks: GPT/MBR, NTFS, FAT32 identified; OS heuristics via filesystem strings.
- `vm_package` — **Virtualization packages**: `ova` (tar/ustar), `ovf` (XML envelope).
- `network_config` — Router/firewall/switch configs (Cisco IOS/ASA, PAN-OS, FortiGate, JunOS, VyOS/EdgeOS, Arista EOS, Mikrotik).
- `misc` — Best-effort host association from filename.

## Destination layout

- `e01` → `~/DataSources/Hosts/<host>/<host>_<YYYY-MM-DD>.E01`
- `mem` → `~/DataSources/Hosts/<host>/<host>_<YYYY-MM-DD>.mem` (or original ext)
- `disk_raw` → `~/DataSources/Hosts/<host>/<host>_<YYYY-MM-DD>.img` (or original ext)
- `vm_disk` → `~/DataSources/Hosts/<host>/vm/vm_<host>_<YYYY-MM-DD>.<ext>`
- `vm_package` → `~/DataSources/Hosts/<host>/vm/vm_pkg_<host>_<YYYY-MM-DD>.<ext>`
- `network_config` → `~/DataSources/Network/<host>/cfg_<host>_<YYYY-MM-DD>.<ext>`
- `misc` → `~/DataSources/Hosts/<host>/misc/<original_name>`

If a destination exists, `__<n>` suffix is appended.

## Queue

Each staged item writes a work order to `~/DataSources/_queue/<classification>/<profile>/<uuid>.json`.

## Logs

Daily JSON lines at `/var/wade/logs/stage/stage_YYYY-MM-DD.log`.

Events:
- `staged`: includes `classification`, paths, size, timing, and `metadata` (OS/format/fragmentation, etc.)
- `skipped_unknown`, `duplicate_ignored`, `processing_failed`.

## Configuration

Env file: `/etc/wade/wade.env`

Key variables:

```ini
WADE_OWNER_USER=autopsy
WADE_DATADIR=DataSources
WADE_STAGINGDIR=Staging
WADE_QUEUE_DIR=_queue

WADE_STAGE_SCAN_INTERVAL=30
WADE_STAGE_STABLE_SECONDS=10
WADE_STAGE_HEAD_SCAN_BYTES=1048576
WADE_STAGE_TEXT_SNIFF_BYTES=131072
WADE_STAGE_TEXT_MIN_PRINTABLE_RATIO=0.92

# Optional:
# WADE_VOL_PATH=/opt/pipx/venvs/volatility3/bin/vol
