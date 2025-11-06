#!/usr/bin/env python3
import sys, json, argparse
from pathlib import Path

from .utils import load_env, read_ticket
from .noop_worker import NoopWorker
from .volatility_worker import VolatilityWorker
from .dissect_worker import DissectWorker
from .yara_worker import YaraWorker
from .bulkextractor_worker import BulkExtractorWorker
from .autopsy_manifest import AutopsyManifestWorker
from .hayabusa_worker import HayabusaWorker

# Classification mapping from staging → internal plan key
CLASS_MAP = {
    "mem":         "memory",
    "e01":         "disk",
    "disk_raw":    "disk",
    "vm_disk":     "disk",
    "windows_etl": "windows-etl",
    "misc":        "noop",
    "unknown":     "noop",
}

# Ordered plan definitions (workers run in list order)
PLAN = {
    "memory":      [VolatilityWorker, YaraWorker],
    "disk":        [DissectWorker, YaraWorker, BulkExtractorWorker, AutopsyManifestWorker],
    "windows-etl": [HayabusaWorker],
    "noop":        [NoopWorker],
}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ticket", type=Path)
    ap.add_argument("--config", type=Path, default=Path("/etc/wade/wade_workers.yaml"))
    args = ap.parse_args()

    env = load_env()
    ticket = read_ticket(args.ticket) or {}
    cls = ticket.get("classification", "unknown")
    plan_key = CLASS_MAP.get(cls, "noop")
    group = PLAN.get(plan_key, [NoopWorker])

    # Optional config file
    config = {}
    if args.config.exists():
        try:
            import yaml
            config = yaml.safe_load(args.config.read_text()) or {}
        except Exception:
            config = {}

    errors = []
    total = 0
    last_path = None
    for W in group:
        try:
            res = W(env, config).run(ticket)
            last_path = res.path or last_path
            total += int(getattr(res, "count", 0))
            if getattr(res, "errors", None):
                errors.extend(res.errors)
        except Exception as e:
            errors.append(f"{W.__name__}:{e!r}")

    if errors:
        print(json.dumps({"ticket": str(args.ticket), "plan": plan_key, "errors": errors, "count": total, "last_path": str(last_path) if last_path else None}))
        sys.exit(1)

    print(json.dumps({"ticket": str(args.ticket), "plan": plan_key, "ok": True, "count": total, "last_path": str(last_path) if last_path else None}))
    sys.exit(0)

if __name__ == "__main__":
    main()
