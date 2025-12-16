import importlib
from wade_workers.ticket_schema import WorkerTicket
from staging.tool_routing import ToolRouting  # if runner can import; else duplicate tiny shim
from wade_workers.logging import EventLogger

WORKER_MAP = {
    "volatility": ("wade_workers.volatility_worker", "VolatilityWorker"),
    "dissect": ("wade_workers.dissect_worker", "DissectWorker"),
    "plaso": ("wade_workers.plaso_worker", "PlasoWorker"),
    "hayabusa": ("wade_workers.hayabusa_worker", "HayabusaWorker"),
    "bulk_extractor": ("wade_workers.bulk_extractor_worker", "BulkExtractorWorker"),
    "yara": ("wade_workers.yara_worker", "YaraWorker"),
    # Optional/placeholder workers:
    "autopsy": ("wade_workers.autopsy_manifest", "AutopsyManifestWorker"),
    "netcfg": ("wade_workers.netcfg_worker", "NetworkConfigWorker"),
    "netdoc": ("wade_workers.netdoc_worker", "NetworkDocWorker"),
}

def _load_worker(module_name: str, class_name: str):
    try:
        mod = importlib.import_module(module_name)
        return getattr(mod, class_name)
    except Exception:
        return None

def _resolve_worker(tool: str):
    # alias handling
    if tool == "yara_mem":
        return WORKER_MAP.get("yara"), {"mode": "memory"}
    return WORKER_MAP.get(tool), {}

def dispatch_ticket(ticket_path: Path, env: Optional[dict] = None) -> int:
    logger = EventLogger.get_logger("queue_runner")
    ticket = WorkerTicket.load(ticket_path)

    requested = (ticket.worker_config or {}).get("requested_tools") or []
    if not requested:
        # Fallback: compute on the fly (back-compat)
        router = ToolRouting()
        requested = router.select_tools(
            classification=ticket.metadata.classification,
            profile=(ticket.worker_config or {}).get("profile", "full"),
            details={"os_family": ticket.metadata.os_family, **(ticket.metadata.custom or {})},
            location=(ticket.worker_config or {}).get("location"),
        )

    exit_codes = []
    for tool in requested:
        entry, overrides = _resolve_worker(tool)
        if not entry:
            logger.log_event("queue.worker_skip", status="warning", tool=tool, reason="unknown_worker")
            continue
        mod_name, cls_name = entry
        WorkerClass = _load_worker(mod_name, cls_name)
        if not WorkerClass:
            logger.log_event("queue.worker_skip", status="warning", tool=tool, reason="import_failed", module=mod_name, class_name=cls_name)
            continue

        # Merge per-tool overrides into ticket.worker_config[tool]
        wc = ticket.worker_config or {}
        per_tool = wc.get(tool, {})
        per_tool.update(overrides)
        wc[tool] = per_tool
        ticket.worker_config = wc

        # Run worker
        worker = WorkerClass(env=env)
        result = worker.run(ticket.to_dict())
        logger.log_event("queue.worker_done", status="info", tool=tool, records=result.count, errors=len(result.errors))
        exit_codes.append(0 if not result.errors else 1)

    return 0 if all(code == 0 for code in exit_codes) else 1
