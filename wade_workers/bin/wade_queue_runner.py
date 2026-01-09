import importlib
import logging
import os
import pwd
import signal
import time
from pathlib import Path
from typing import Optional, Any, Dict, Tuple, Type
from datetime import datetime

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

_STOP = False

def _handle_stop(signum, frame):
    global _STOP
    _STOP = True

def _current_user() -> str:
    return pwd.getpwuid(os.getuid()).pw_name

def _queue_paths() -> tuple[Path, Path, Path, Path]:
    """
    Default queue layout:
      /var/wade/queue/<user>/pending
      /var/wade/queue/<user>/processing
      /var/wade/queue/<user>/done
      /var/wade/queue/<user>/failed
    Override base with WADE_QUEUE_ROOT and user with WADE_QUEUE_USER.
    """
    base = Path(os.environ.get("WADE_QUEUE_ROOT", "/var/wade/queue"))
    user = os.environ.get("WADE_QUEUE_USER", _current_user())

    root = base / user
    pending = root / "pending"
    processing = root / "processing"
    done = root / "done"
    failed = root / "failed"

    for d in (pending, processing, done, failed):
        d.mkdir(parents=True, exist_ok=True)

    return pending, processing, done, failed

def _claim_ticket(src: Path, processing_dir: Path) -> Optional[Path]:
    """
    Atomically move a ticket into processing to "claim" it.
    If another runner grabbed it first, rename fails and we return None.
    """
    dst = processing_dir / src.name
    try:
        src.rename(dst)
        return dst
    except (FileNotFoundError, OSError):
        return None

def _stamp(name: str) -> str:
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    return f"{name}.{ts}"

def main() -> int:
    logger = EventLogger.get_logger("queue_runner")

    poll = float(os.environ.get("WADE_QUEUE_POLL_SEC", "2"))
    glob_pat = os.environ.get("WADE_TICKET_GLOB", "*.json")

    pending, processing, done, failed = _queue_paths()

    logger.log_event(
        "queue.runner_start",
        status="info",
        pending=str(pending),
        poll_sec=poll,
        glob=glob_pat,
    )

    env = dict(os.environ)

    while not _STOP:
        tickets = sorted(pending.glob(glob_pat), key=lambda p: p.stat().st_mtime)
        if not tickets:
            time.sleep(poll)
            continue

        for t in tickets:
            if _STOP:
                break

            claimed = _claim_ticket(t, processing)
            if claimed is None:
                continue

            try:
                rc = dispatch_ticket(claimed, env=env)
            except Exception as e:
                logger.log_event(
                    "queue.ticket_exception",
                    status="error",
                    ticket=str(claimed),
                    exception=str(e),
                )
                rc = 1

            try:
                if rc == 0:
                    claimed.rename(done / _stamp(claimed.name))
                    logger.log_event("queue.ticket_done", status="info", ticket=str(t))
                else:
                    claimed.rename(failed / _stamp(claimed.name))
                    logger.log_event("queue.ticket_failed", status="warning", ticket=str(t), rc=rc)
            except Exception as e:
                logger.log_event(
                    "queue.ticket_move_failed",
                    status="error",
                    ticket=str(claimed),
                    exception=str(e),
                )

    logger.log_event("queue.runner_stop", status="info")
    return 0

if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _handle_stop)
    signal.signal(signal.SIGINT, _handle_stop)
    raise SystemExit(main())

