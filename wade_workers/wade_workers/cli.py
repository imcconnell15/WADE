#!/usr/bin/env python3
import sys, json, argparse
from pathlib import Path
from .utils import load_env, read_ticket
from .noop_worker import NoopWorker

CLASS_MAP = {
    "e01":         "noop",
    "mem":         "noop",
    "disk_raw":    "noop",
    "vm_disk":     "noop",
    "archive":     "noop",
    "windows_etl": "noop",
    "misc":        "noop",
    "unknown":     "noop",
}

PLAN = {
    "noop": [NoopWorker],
}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ticket", type=Path)
    ap.add_argument("--config", type=Path, default=Path("/etc/wade/wade_workers.yaml"))
    args = ap.parse_args()

    env = load_env()
    ticket = read_ticket(args.ticket) or {}
    cls = ticket.get("classification","unknown")
    plan_key = CLASS_MAP.get(cls, "noop")
    group = PLAN.get(plan_key, [NoopWorker])

    errors = []
    for W in group:
        try:
            res = W(env, {}).run(ticket)
            if getattr(res, "errors", None):
                errors.extend(res.errors)
        except Exception as e:
            errors.append(f"{W.__name__}:{e!r}")

    if errors:
        print(json.dumps({"ticket": str(args.ticket), "errors": errors}))
        sys.exit(1)
    print(json.dumps({"ticket": str(args.ticket), "ok": True}))
    sys.exit(0)

if __name__ == "__main__":
    main()
