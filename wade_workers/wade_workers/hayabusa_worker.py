from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from .base import BaseWorker, WorkerResult
from .module_config import get_global_config
from .subprocess_utils import run_tool
from .logging import EventLogger
from .ticket_schema import WorkerTicket
from .path_resolver import compute_worker_output_paths


class HayabusaWorker(BaseWorker):
    tool = "hayabusa"
    module = "detections"
    help_text = "Run Hayabusa against Windows event logs (JSONL detections)."

    WIN_EVT_DIR = r"C:\Windows\System32\WinEvt"
    WIN_EVT_LOGS_DIR = r"C:\Windows\System32\WinEvt\Logs"

    def __init__(self, env=None, config=None):
        """
        Initialize the HayabusaWorker, set up its event logger, and load the global configuration.
        
        Parameters:
            env (optional): Environment or runtime context passed to the base worker; used as-is.
            config (optional): Worker-specific configuration overrides; passed to the base worker.
        """
        super().__init__(env, config)
        self.logger = EventLogger.get_logger("hayabusa_worker")
        self.cfg = get_global_config()

    # ----------------------------
    # Small helpers
    # ----------------------------
    def _contains_evtx(self, d: Path) -> bool:
        """
        Determine whether a directory contains any .evtx files, including within its subdirectories.
        
        Parameters:
            d (Path): Directory to inspect.
        
        Returns:
            bool: `True` if the directory or any of its subdirectories contains at least one `.evtx` file, `False` otherwise.
        """
        if not d.exists() or not d.is_dir():
            return False
        # Cheap check first, then recurse if needed
        if any(p.suffix.lower() == ".evtx" for p in d.iterdir() if p.is_file()):
            return True
        return any(p.suffix.lower() == ".evtx" for p in d.rglob("*.evtx"))

    def _read_target_info(self, image: Path) -> dict:
        # Matches your prior bash usage: target-info "$filepath" -j -q
        """
        Retrieve and parse target metadata from an image using the external `target-info` tool.
        
        Parameters:
            image (Path): Path to the target image or file to inspect.
        
        Returns:
            dict: Parsed JSON object returned by `target-info`, containing the target metadata.
        
        Raises:
            RuntimeError: If `target-info` exits with a non-zero return code (stderr/stdout included) or if its output cannot be parsed as JSON.
        """
        res = run_tool("target-info", [str(image), "-j", "-q"], timeout=120, check=False)
        if res.rc != 0:
            raise RuntimeError(f"target-info rc={res.rc}: {res.stderr.strip() or res.stdout.strip()}")
        try:
            return json.loads(res.stdout)
        except Exception as e:
            raise RuntimeError(f"target-info returned non-JSON: {e}")

    def _target_has_winevt_logs(self, image: Path) -> bool:
        """
        Check whether the given disk image exposes a Windows Event Logs ("Logs") directory under the Windows Event path.
        
        Parameters:
            image (Path): Path to the target disk image or container to inspect (passed to `target-fs`).
        
        Returns:
            True if a directory named "Logs" appears in the listing of the Windows Event directory inside the image, False otherwise.
        """
        res = run_tool(
            "target-fs",
            [str(image), "-q", "ls", self.WIN_EVT_DIR],
            timeout=120,
            check=False,
        )
        if res.rc != 0:
            return False
        lines = [ln.strip() for ln in (res.stdout or "").splitlines() if ln.strip()]
        return any(ln == "Logs" for ln in lines)

    def _carve_winevt_logs(self, image: Path, carve_root: Path) -> Path:
        """
        Carves Windows Evtx Logs from a disk image into a working directory.
        
        Parameters:
            image (Path): Path to the disk image to read from.
            carve_root (Path): Directory where carved files will be placed; will be created if missing.
        
        Returns:
            Path: Path to the directory containing the carved .evtx files to be scanned (commonly carve_root/Logs or carve_root).
        
        Raises:
            RuntimeError: If the carve operation fails or no `.evtx` files are found under the carve_root after carving.
        """
        carve_root.mkdir(parents=True, exist_ok=True)

        # Copy Logs directory out of image
        res = run_tool(
            "target-fs",
            [str(image), "-q", "cp", self.WIN_EVT_LOGS_DIR, "-o", str(carve_root)],
            timeout=int(self.cfg.get_tool_config("hayabusa").get("carve_timeout", 900)),
            check=False,
        )
        if res.rc != 0:
            raise RuntimeError(f"target-fs cp failed rc={res.rc}: {res.stderr.strip() or res.stdout.strip()}")

        # target-fs usually creates carve_root/Logs/...
        candidate = carve_root / "Logs"
        if candidate.exists() and candidate.is_dir() and self._contains_evtx(candidate):
            return candidate

        # Otherwise, assume the evtx are somewhere under carve_root
        if self._contains_evtx(carve_root):
            return carve_root

        raise RuntimeError(f"Carve completed but no .evtx found under {carve_root}")

    def _run_hayabusa_jsonl(self, evtx_dir: Path, tmp_out: Path) -> None:
        """
        Run Hayabusa against a directory of EVTX files and produce JSONL output at tmp_out.
        
        Reads Hayabusa settings from the worker's "hayabusa" tool config (notably "subcommand" and "timeout").
        If "subcommand" is "json-timeline", runs Hayabusa in timeline mode; otherwise uses a detect-style invocation
        which honors "min_level" and optional "rules_dir". If Hayabusa produces a non-empty tmp_out file or emits JSON
        to stdout, that output is preserved; otherwise the function raises RuntimeError.
        
        Parameters:
            evtx_dir (Path): Directory containing EVTX files to scan.
            tmp_out (Path): Path where Hayabusa JSONL output will be written or captured.
        """
        hay_cfg = self.cfg.get_tool_config("hayabusa") or {}

        subcommand = str(hay_cfg.get("subcommand", "json-timeline"))
        timeout = int(hay_cfg.get("timeout", 1200))

        # Defaults that match your bash invocation
        args = [subcommand]

        if subcommand == "json-timeline":
            args += ["-L", "--RFC-3339", "-w", "--directory", str(evtx_dir), "--output", str(tmp_out)]
        else:
            # Generic “detect” style fallback (only used if you set subcommand: detect)
            min_level = str(hay_cfg.get("min_level", "low"))
            rules_dir = hay_cfg.get("rules_dir")
            args += ["--input", str(evtx_dir), "--format", "jsonl", "--min-level", min_level, "--output", str(tmp_out)]
            if rules_dir:
                args += ["--rules", str(rules_dir)]

        res = run_tool("hayabusa", args, timeout=timeout, check=False)

        # If Hayabusa failed but still produced output, keep going.
        if tmp_out.exists() and tmp_out.stat().st_size > 0:
            return

        # Some builds might dump to stdout. Capture that if present.
        if res.stdout and res.stdout.strip():
            tmp_out.write_text(res.stdout, encoding="utf-8")
            return

        raise RuntimeError(f"hayabusa failed rc={res.rc}: {res.stderr.strip() or 'no stderr'}")

    # ----------------------------
    # Main worker entrypoint
    # ----------------------------
    def run(self, ticket_dict: dict) -> WorkerResult:
        """
        Process a worker ticket to run Hayabusa against Windows event logs and produce JSONL detection artifacts.
        
        Validates the ticket input, optionally enriches hostname/domain from target metadata, determines the directory of .evtx files (direct directory, parent of an .evtx file, or carved from a disk image), runs Hayabusa to generate raw JSONL, wraps each record with the ticket artifact envelope, writes the final JSONL output, and returns a WorkerResult summarizing the output path and record count. On failure, returns a WorkerResult with error details.
        
        Parameters:
            ticket_dict (dict): Serialized WorkerTicket dictionary containing metadata and destination path.
        
        Returns:
            WorkerResult: On success, contains path to the output directory and the number of records written. On failure, contains None path, a count of 0, and an errors list describing the failure.
        """
        ticket = WorkerTicket.from_dict(ticket_dict)
        target = Path(ticket.metadata.dest_path)

        if not target.exists():
            return WorkerResult(path=None, count=0, errors=[f"Input not found: {target}"])

        # Prefer ticket hostname, but if missing, attempt to derive from target-info (image inputs)
        try:
            if (not ticket.metadata.hostname or ticket.metadata.hostname == "unknown_host") and target.is_file():
                info = self._read_target_info(target)
                if info.get("hostname"):
                    ticket.metadata.hostname = info["hostname"]
                if info.get("domain") and not getattr(ticket.metadata, "domain", None):
                    ticket.metadata.domain = info["domain"]
        except Exception:
            # Don’t hard-fail just for hostname enrichment.
            pass

        host = ticket.metadata.hostname or "unknown_host"
        self.logger.log_worker_start(self.tool, host=host, image_path=str(target))

        outdir, outfile = compute_worker_output_paths(ticket, self.tool, self.module, self.env)

        # Put carved logs *next to* the JSONL output, but unique per run (timestamped stem)
        carve_root = outdir / f"WinEvtLogs_{outfile.stem}"

        total = 0
        tmp_out = outdir / f"_hayabusa_tmp_{outfile.stem}.jsonl"

        try:
            # Decide what directory Hayabusa should scan
            evtx_dir: Optional[Path] = None

            if target.is_dir() and self._contains_evtx(target):
                evtx_dir = target
            elif target.is_file() and target.suffix.lower() == ".evtx":
                evtx_dir = target.parent
            else:
                # Treat as an image/container; validate Windows + logs path then carve
                info = self._read_target_info(target)
                if str(info.get("os_family", "")).lower() != "windows":
                    return WorkerResult(path=None, count=0, errors=[f"Windows not detected (os_family={info.get('os_family')})"])

                if not self._target_has_winevt_logs(target):
                    return WorkerResult(
                        path=None,
                        count=0,
                        errors=[f"Logs not found in {self.WIN_EVT_DIR} (expected 'Logs' directory)"],
                    )

                evtx_dir = self._carve_winevt_logs(target, carve_root)

            # Run hayabusa -> tmp_out (raw JSONL)
            self._run_hayabusa_jsonl(evtx_dir, tmp_out)

            # Wrap each JSONL record with envelope (hostname injection handled here)
            envelope = ticket.get_artifact_envelope(self.tool, self.module)

            with tmp_out.open("r", encoding="utf-8") as src, outfile.open("w", encoding="utf-8") as dst:
                for line in src:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        rec = json.loads(line)
                    except Exception:
                        rec = {"raw": line}
                    obj = {**envelope, **rec}
                    dst.write(json.dumps(obj, ensure_ascii=False) + "\n")
                    total += 1

            tmp_out.unlink(missing_ok=True)

            self.logger.log_worker_complete(
                self.tool,
                host=host,
                module=self.module,
                record_count=total,
                output_path=outfile,
            )
            return WorkerResult(path=outdir, count=total)

        except Exception as e:
            return WorkerResult(path=None, count=0, errors=[f"hayabusa failed: {e}"])