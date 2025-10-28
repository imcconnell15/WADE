
# WADE Queue Worker (Skeleton)

This worker drains the shared `_queue` populated by the staging daemon and runs a minimal, safe set of tools by classification, respecting the `profile` (`full` vs `light`). It’s designed to be extended as your pipelines mature.

## How it works

1. **Watch** the queue root (from `/etc/wade/wade.env`: `WADE_QUEUE_DIR` under `DataSources`).
2. **Claim** a work-order JSON by atomically moving it to `_inflight/<worker-host>/`.
3. Build a **plan** from `classification` + `profile`:
   - `mem`: Volatility 3 basic triage (`windows.info`, `pslist`).
   - `disk_raw` / `e01`: `bulk_extractor` (both profiles); add `dissect_quick` in `full`.
   - `network_config`: acknowledge (placeholder; add lints/normalization later).
4. **Run tasks** (with timeouts) and write outputs under:
   `/home/<owner>/DataSources/Hosts/<hostname>/wade/<tool>/<work_id>/`
5. Emit a **worker log** to `/var/wade/logs/worker/*.json`.
6. Move the work-order to `_done/<worker-host>/` or `_failed/<worker-host>/`.

> Multiple workers can run against the same share. Atomic rename into `_inflight/<host>/` provides a simple exclusive lock.

## Install

```
sudo install -d -m 0755 /opt/wade
sudo install -m 0755 wade_worker.py /opt/wade/wade_worker.py
sudo install -m 0644 wade-worker.service /etc/systemd/system/wade-worker.service

# Optional env
sudo install -d -m 0755 /etc/wade
sudo cp wade-worker.env.example /etc/wade/wade-worker.env

sudo systemctl daemon-reload
sudo systemctl enable --now wade-worker.service
```

## Configure

- Queue path comes from `/etc/wade/wade.env` (`WADE_OWNER_USER`, `WADE_DATADIR`, `WADE_QUEUE_DIR`).
- Worker-specific toggles from `/etc/wade/wade-worker.env`:
  - `ENABLE_VOL3` (default 1)
  - `ENABLE_BULK_EXTRACTOR` (default 1)
  - `ENABLE_DISSECT` (default 0)
  - `WADE_WORKER_TOOL_TIMEOUT_SEC` (default 1800s)
  - `WADE_WORKER_MAX_PARALLEL` (default 1)

## Extending

- Add more Vol3 plugins or switch to JSON output for Splunk.
- Wire real Dissect modules once your CLI and mounts are defined.
- Add **Hayabusa** once you mount/harvest EVTX from images.
- Add **Plaso/Autopsy** to the `full` plan when ready.
- Forward worker logs and tool outputs to Splunk via your UF app.

Semper modular.
