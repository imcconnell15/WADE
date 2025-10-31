#!/usr/bin/env python3
import argparse, json, sys
from pathlib import Path
from .utils import load_env, read_ticket
from .volatility_worker import VolatilityWorker
from .dissect_worker import DissectWorker
from .hayabusa_worker import HayabusaWorker
from .bulkextractor_worker import BulkExtractorWorker
from .autopsy_manifest import AutopsyManifestWorker
from .yara_worker import YaraWorker

WORKER_REGISTRY = {
    "memory": [VolatilityWorker, YaraWorker],
    "ewf-e01": [DissectWorker, YaraWorker, BulkExtractorWorker, AutopsyManifestWorker],
    "disk-raw": [DissectWorker, YaraWorker, BulkExtractorWorker, AutopsyManifestWorker],
    "archive": [BulkExtractorWorker],
    "unknown": [BulkExtractorWorker],
}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("ticket", help="Path to queue ticket (JSON)")
    ap.add_argument("-c", "--config", help="Config YAML (optional)", default=None)
    args = ap.parse_args()

    env = load_env()
    tpath = Path(args.ticket)
    ticket = read_ticket(tpath)
    if not ticket:
        print(f"[-] invalid ticket: {tpath}", file=sys.stderr)
        sys.exit(1)

    kind = ticket.get("kind","unknown")
    workers = WORKER_REGISTRY.get(kind, WORKER_REGISTRY["unknown"])

    # Minimal config routing (future: load YAML if provided)
    config = {}
    errors = []
    for W in workers:
        try:
            w = W(env, config)
            res = w.run(ticket)
            if res.errors:
                errors.extend(res.errors)
        except Exception as e:
            errors.append(f"{W.__name__}:{e!r}")

    if errors:
        print(json.dumps({"ticket": str(tpath), "errors": errors}))
    return 0

if __name__ == "__main__":
    main()
