#!/usr/bin/env python3
import sys, json, argparse
from pathlib import Path

from .utils import load_env, read_ticket

# Worker classes
from .volatility_worker import VolatilityWorker
from .dissect_worker import DissectWorker
from .hayabusa_worker import HayabusaWorker
from .bulkextractor_worker import BulkExtractorWorker
from .autopsy_manifest import AutopsyManifestWorker
from .yara_worker import YaraWorker

# Map staging classifications -> internal plans
CLASS_MAP = {
    "e01":         "ewf-e01",
    "mem":         "memory",
    "disk_raw":    "disk-raw",
    "vm_disk":     "disk-raw",
    "archive":     "archive",
    "windows_etl": "windows-etl",
    "misc":        "misc",
    "unknown":     "unknown",
}

# Plan registry (ordered)
WORKER_REGISTRY = {
    "memory":      [VolatilityWorker, YaraWorker],
    "ewf-e01":     [DissectWorker, YaraWorker, BulkExtractorWorker, AutopsyManifestWorker],
    "disk-raw":    [DissectWorker, YaraWorker, BulkExtractorWorker, AutopsyManifestWorker],
    "archive":     [BulkExtractorWorker],
    "windows-etl": [HayabusaWorker],     # harmless no-op if no EVTX found
    "misc":        [],
    "unknown":     [],
}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ticket", type=Path)
    ap.add_argument("--config", type=Path, default=Path("/etc/wade/wade_workers.yaml"))
    args = ap.parse_args()

    env = load_env()
    tpath = args.ticket
    ticket = read_ticket(tpath) or {}

    # Map staging classification to internal key
    cls = ticket.get("classification","unknown")
    plan_key = CLASS_MAP.get(cls, cls)
    group = WORKER_REGISTRY.get(plan_key, [])

    # Optional per-worker config (YAML)
    config = {}
    if args.config.exists():
        try:
            import yaml
            config = yaml.safe_load(args.config.read_text()) or {}
        except Exception:
            pass

    errors = []
    for W in group:
        try:
            res = W(env, config).run(ticket)
            if getattr(res, "errors", None):
                errors.extend(res.errors)
        except Exception as e:
            errors.append(f"{W.__name__}:{e!r}")

    if errors:
        print(json.dumps({"ticket": str(tpath), "errors": errors}))
        sys.exit(1)
    else:
        print(json.dumps({"ticket": str(tpath), "ok": True}))
        sys.exit(0)

if __name__ == "__main__":
    main()
