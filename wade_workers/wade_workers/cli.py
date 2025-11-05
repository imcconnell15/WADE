from .volatility_worker import VolatilityWorker
from .dissect_worker import DissectWorker
from .hayabusa_worker import HayabusaWorker
from .bulkextractor_worker import BulkExtractorWorker
from .autopsy_manifest import AutopsyManifestWorker
from .yara_worker import YaraWorker

CLASS_MAP = {
    "e01":        "ewf-e01",
    "mem":        "memory",
    "disk_raw":   "disk-raw",
    "vm_disk":    "disk-raw",
    "archive":    "archive",
    "windows_etl":"windows-etl",
    "misc":       "misc",
    "unknown":    "unknown",
}

WORKER_REGISTRY = {
    "memory":      [VolatilityWorker, YaraWorker],
    "ewf-e01":     [DissectWorker, YaraWorker, BulkExtractorWorker, AutopsyManifestWorker],
    "disk-raw":    [DissectWorker, YaraWorker, BulkExtractorWorker, AutopsyManifestWorker],
    "archive":     [BulkExtractorWorker],
    "windows-etl": [HayabusaWorker],
    "misc":        [],
    "unknown":     [],
}

# ...
kind = ticket.get("classification","unknown")
group = WORKER_REGISTRY.get(CLASS_MAP.get(kind, kind), [])

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
print(json.dumps({"ticket": str(tpath), "ok": True}))
sys.exit(0)
