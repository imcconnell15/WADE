WADE — Wide-Area Data Extraction

WADE is a DFIR automation framework for staging, routing, and processing forensic artifacts at scale, with outputs designed for Splunk search and visualization. It aims to be:

Idempotent & auditable: predictable installs, per-file JSON logs, state tracking

Modular: small wade-* services (start with wade-stage) you can add over time

Online or offline: install works with pinned packages and offline kits (road-mapped)

Ops-friendly: sane defaults, systemd units, logrotate, single .env

Core repo layout: scripts/, splunkapp/, stigs/, top-level install.sh and Python helpers. 
GitHub

What WADE does (today)

Staging daemon (wade-stage)

Watches Staging/{full,light} for new files

Classifies artifacts without heavy tooling (headers & hints): E01/EWF, raw disks, memory dumps, network configs

Moves/renames into DataSources/… with a consistent host/date naming scheme

Writes a per-file JSON log to /var/wade/logs/stage/

Drops a work-order JSON in a share _queue/ for downstream workers (Dissect, Volatility, Plaso, etc.) to pick up later

All tunables live in /etc/wade/wade.env. Service is managed by systemd and ships with a logrotate policy (USR1 reopen). These pieces are reflected in the current README and script set. 
GitHub

Repo structure
WADE/
├─ scripts/           # helper scripts & service bits (growing over time)
├─ splunkapp/         # Splunk app scaffolding (indexes/props/transforms & more)
├─ stigs/             # STIG-ish hardening bits and checklists
├─ install.sh         # idempotent installer (Linux host bootstrap & config)
└─ loader_patch.py    # helper/loader utility (dev)


Browse the tree for the latest content. 
GitHub

Quick start (Linux host)

Tested as a Linux-first flow; Windows workers come later (KAPE/Zimmerman/etc.).

Clone & run installer

git clone https://github.com/imcconnell15/WADE.git
cd WADE
sudo -E bash ./install.sh


The installer bootstraps packages, users/dirs, env files, and the wade-stage service.

Splunk UF and app packaging are included in the project plan; see splunkapp/.

Service lifecycle

sudo systemctl daemon-reload
sudo systemctl enable --now wade-stage.service
sudo systemctl status wade-stage.service
journalctl -u wade-stage -f


Where to drop things

/home/autopsy/Staging/
├─ full/   # full pipeline targets (full tooling downstream)
└─ light/  # minimal pipeline / triage


What shows up

Processed data → /home/autopsy/DataSources/Hosts/<HOST>/... (and /Network/... for configs)

Per-file JSON logs → /var/wade/logs/stage/

Work orders (JSON) → <share>/_queue/… for your processors to consume

These behaviors match the current project docs and scripts. 
GitHub

Configuration

All runtime tunables live in /etc/wade/wade.env. Examples you’ll see in the docs:

Identity/paths: WADE_OWNER_USER, WADE_DATADIR, WADE_STAGINGDIR

Scanner cadence & stabilization windows

Header/text sniff sizes for classification

Queue directory (absolute or relative under ~autopsy)

The README in-repo outlines these keys and restart steps. 
GitHub

Logging & rotation

Logs are written per artifact to /var/wade/logs/stage/ as JSON.

A logrotate policy rotates daily, keeps 14 compressed archives, and signals the service with SIGUSR1 so it reopens its log file (no copytruncate).

install.sh wires this automatically during service setup.

This pattern is baked into the repo’s service guidance. 
GitHub

Splunk

A WADE Splunk app scaffold lives under splunkapp/ to centralize:

indexes / sourcetypes

props/transforms for JSONL/JSON tools

deployment packaging for UFs (road-mapped)

Use this as your starting point for index naming like wade_<tool> and the dashboards you build on top. Repo contains the app folder today. 
GitHub

Roadmap (abridged)

Windows worker host with KAPE/Zimmerman/RECmd, etc.

Processors: Dissect, Volatility3, Plaso, Hayabusa, YARA, Bulk Extractor

Offline kit packaging for air-gapped installs (pinned artifacts)

Splunk: final indexes, props/transforms, saved searches, dashboards

More wade-* services for each processor + a shared work-order schema

License

MIT — see LICENSE
. 
GitHub

Credits

Built by practitioners who want DFIR automation that’s simple to deploy, easy to audit, and friendly to both online and austere environments. Shout out to one Mr Speaks
