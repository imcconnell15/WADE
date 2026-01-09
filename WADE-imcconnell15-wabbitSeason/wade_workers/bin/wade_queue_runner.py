import importlib
import logging
from pathlib import Path
from typing import Optional, Any, Dict, Tuple, Type

from wade_workers.ticket_schema import WorkerTicket
from wade_workers.logging import EventLogger

try:
    from staging.tool_routing import ToolRouting  # optional
except Exception:
    ToolRouting = None  # type: ignore

_logger = logging.getLogger(__name__)

WORKER_MAP: Dict[str, Tuple[str, str]] = {
    "volatility": ("wade_workers.volatility_worker", "VolatilityWorker"),
    "dissect": ("wade_workers.dissect_worker", "DissectWorker"),
    "plaso": ("wade_workers.plaso_worker", "PlasoWorker"),
    "hayabusa": ("wade_workers.hayabusa_worker", "HayabusaWorker"),
    "bulk_extractor": ("wade_workers.bulkextractor_worker", "BulkExtractorWorker"),
    "yara": ("wade_workers.yara_worker", "YaraWorker"),
    # Optional/placeholder workers:
    "autopsy": ("wade_workers.autopsy_manifest", "AutopsyManifestWorker"),
    "netcfg": ("wade_workers.netcfg_worker", "NetworkConfigWorker"),
    "netdoc": ("wade_workers.netdoc_worker", "NetworkDocWorker"),
}

def _load_worker(module_name: str, class_name: str) -> Optional[Type[Any]]:
    try:
        mod = importlib.import_module(module_name)
        return getattr(mod, class_name)
    except Exception:
        _logger.debug("Failed to load %s.%s", module_name, class_name, exc_info=True)
        return None

def _resolve_worker(tool: str) -> Tuple[str, Optional[Tuple[str, str]], Dict[str, Any]]:
    """
    Returns: (worker_key, (module, class) or None, overrides)
    worker_key is the canonical key used for worker_config.
    """
    if tool == "yara_mem":
        return "yara", WORKER_MAP.get("yara"), {"mode": "memory"}
    return tool, WORKER_MAP.get(tool), {}

def dispatch_ticket(ticket_path: Path, env: Optional[dict] = None) -> int:
    logger = EventLogger.get_logger("queue_runner")
    ticket = WorkerTicket.load(ticket_path)

    wc: Dict[str, Any] = dict(ticket.worker_config or {})

    requested = wc.get("requested_tools") or []
    if not requested:
        if ToolRouting is None:
            logger.log_event(
                "queue.no_requested_tools",
                status="error",
                reason="requested_tools_missing_and_toolrouting_unavailable",
            )
            return 1

        router = ToolRouting()
        requested = router.select_tools(
            classification=ticket.metadata.classification,
            profile=wc.get("profile", "full"),
            details={"os_family": ticket.metadata.os_family, **(ticket.metadata.custom or {})},
            location=wc.get("location"),
        )

    # de-dupe while preserving order
    seen = set()
    requested = [t for t in requested if not (t in seen or seen.add(t))]

    any_ran = False
    exit_codes = []

    for tool in requested:
        worker_key, entry, overrides = _resolve_worker(tool)
        if not entry:
            logger.log_event("queue.worker_skip", status="warning", tool=tool, reason="unknown_worker")
            continue

        mod_name, cls_name = entry
        WorkerClass = _load_worker(mod_name, cls_name)
        if not WorkerClass:
            logger.log_event(
                "queue.worker_skip",
                status="warning",
                tool=tool,
                reason="import_failed",
                module=mod_name,
                class_name=cls_name,
            )
            continue

        # Merge overrides into worker_config under canonical key
        per_tool = dict(wc.get(worker_key, {}))
        per_tool.update(overrides)
        wc[worker_key] = per_tool

        payload = ticket.to_dict()
        payload["worker_config"] = wc

        try:
            any_ran = True
            worker = WorkerClass(env=env)
            result = worker.run(payload)

            rec_count = getattr(result, "count", None)
            err_list = getattr(result, "errors", []) or []
            logger.log_event(
                "queue.worker_done",
                status="info",
                tool=tool,
                records=rec_count,
                errors=len(err_list),
            )
            exit_codes.append(0 if len(err_list) == 0 else 1)

        except Exception:
            logger.log_event("queue.worker_failed", status="error", tool=tool, reason="exception", traceback=True)
            exit_codes.append(1)

    if not any_ran:
        logger.log_event("queue.no_workers_ran", status="error", reason="all_skipped_or_missing")
        return 1

    return 0 if all(code == 0 for code in exit_codes) else 1
