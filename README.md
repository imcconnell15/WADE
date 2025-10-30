# WADE — Wide-Area Data Extraction

*A DFIR automation framework for staging, routing, and processing forensic artifacts at scale—built for austere ops, friendly to Splunk, and allergic to drama.*

---

## TL;DR

* **Idempotent & auditable** — predictable installs, per-file JSON logs, state tracking
* **Modular** — small `wade-*` services (starting with `wade-stage`) you can add over time
* **Online or offline** — works with pinned packages; offline kit is on the roadmap
* **Ops-friendly** — sane defaults, `systemd` units, `logrotate`, single `.env`

Repo: **[https://github.com/imcconnell15/WADE](https://github.com/imcconnell15/WADE)**

---

## What WADE Does (Today)

### `wade-stage` — Staging Daemon

* Watches `Staging/{full,light}` for new files
* Classifies artifacts with fast header/hint checks (E01/EWF, raw disks, memory dumps, network configs)
* Moves/renames into `DataSources/...` using a consistent `<HOST>/<DATE>` scheme
* Writes **per-file JSON logs** to `/var/wade/logs/stage/`
* Drops **work-order JSON** into a `_queue/` share for downstream processors (Dissect, Volatility, Plaso, etc.)

> **Config:** All tunables live in `/etc/wade/wade.env`.
> **Service:** Managed by `systemd` and ships with a `logrotate` policy (uses `SIGUSR1` to reopen logs).

---

## Repo Structure

```
WADE/
├─ scripts/           # helper scripts & service bits (growing over time)
├─ splunkapp/         # Splunk app scaffolding (indexes/props/transforms & more)
├─ stigs/             # STIG-ish hardening bits and checklists
├─ install.sh         # idempotent installer (Linux host bootstrap & config)
└─ loader_patch.py    # helper/loader utility (dev)
```

Browse the tree for the latest content.

---

## Quick Start (Linux Host)

Tested Linux-first; Windows workers (KAPE/Zimmerman/etc.) come later.

```bash
git clone https://github.com/imcconnell15/WADE.git
cd WADE
sudo -E bash ./install.sh
```

The installer bootstraps packages, users/dirs, env files, and the `wade-stage` service.
Splunk UF and app packaging are in the project plan; see [`splunkapp/`](./splunkapp/).

---

## Service Lifecycle

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now wade-stage.service
sudo systemctl status wade-stage.service
journalctl -u wade-stage -f
```

---

## Where to Drop Things

```
/home/autopsy/Staging/
├─ full/   # full pipeline targets (full tooling downstream)
└─ light/  # minimal pipeline / triage
```

### What Shows Up

* Processed data → `/home/autopsy/DataSources/Hosts/<HOST>/...`
* Per-file JSON logs → `/var/wade/logs/stage/`
* Work orders (JSON) → `<share>/_queue/...` for processors to consume

---

## Configuration

**Everything lives in** `/etc/wade/wade.env`. Common keys you’ll see:

| Key                       | Purpose                                                     |
| ------------------------- | ----------------------------------------------------------- |
| `WADE_OWNER_USER`         | Service/account owner (e.g., `autopsy`)                     |
| `WADE_DATADIR`            | Root for processed data (e.g., `/home/autopsy/DataSources`) |
| `WADE_STAGINGDIR`         | Inbound watch root (e.g., `/home/autopsy/Staging`)          |
| `WADE_QUEUE_DIR`          | Work-order drop location (absolute or `~autopsy` relative)  |
| `WADE_SCAN_INTERVAL`      | Poll cadence / stabilization window                         |
| `WADE_SNIFF_HEADER_BYTES` | Header bytes to read for classification                     |
| `WADE_SNIFF_TEXT_BYTES`   | Text bytes to sample when needed                            |

**Example snippet:**

```env
WADE_OWNER_USER=autopsy
WADE_DATADIR=/home/autopsy/DataSources
WADE_STAGINGDIR=/home/autopsy/Staging
WADE_QUEUE_DIR=/home/autopsy/_queue
WADE_SCAN_INTERVAL=5
WADE_SNIFF_HEADER_BYTES=4096
WADE_SNIFF_TEXT_BYTES=16384
```

> **After changes:** `sudo systemctl restart wade-stage.service`

---

## Logging & Rotation

* Per-artifact JSON logs under `/var/wade/logs/stage/`
* Rotated **daily**, keep **14** compressed archives
* Uses `SIGUSR1` (no `copytruncate`) so the daemon cleanly reopens the file

This policy is wired automatically by `install.sh` during service setup.

---

## Splunk

A WADE Splunk app scaffold lives under [`splunkapp/`](./splunkapp/) to centralize:

* **Indexes / sourcetypes** (e.g., `wade_<tool>`)
* **Props/transforms** for JSONL/JSON tool outputs
* **Deployment packaging** for Universal Forwarders (road-mapped)

Use it as your starting point for search, dashboards, and operational views.

---

## Roadmap (Abridged)

* [ ] Windows worker host with KAPE / Zimmerman / RECmd
* [ ] Processor services: Dissect, Volatility3, Plaso, Hayabusa, YARA, Bulk Extractor
* [ ] Offline kit packaging for air-gapped installs (pinned artifacts)
* [ ] Splunk: final indexes, props/transforms, saved searches, dashboards
* [ ] More `wade-*` services + a shared work-order schema

---

## License

MIT — see [`LICENSE`](./LICENSE).

---

## Credits

Built by practitioners who want DFIR automation that’s simple to deploy, easy to audit, and comfortable both online and in austere environments.
Shout-out to **Mr. Speaks**.
