#!/usr/bin/env python3
import os, shutil, subprocess
from pathlib import Path
from typing import Iterable, List
from .base import BaseWorker, WorkerResult
from .utils import wade_paths, now_iso, ensure_dir

class DissectWorker(BaseWorker):
    tool = "dissect"
    help_text = "Dissect disk analysis & harvesting (winevtlog export, basic facts)."
    prefer_jsonl = True

    def __init__(self, env=None, config=None):
        super().__init__(env, config)
        self.mount_bin = shutil.which("target-mount")
        self.info_bin  = shutil.which("target-info")

    def _target_info(self, image: Path) -> dict:
        if not self.info_bin:
            return {"error": "target-info not installed"}
        p = subprocess.run([self.info_bin, str(image)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        return {"stdout": p.stdout, "stderr": p.stderr, "rc": p.returncode}

    def _export_winevt(self, mount: Path, dest: Path) -> int:
        # Common Windows path inside mounted fs
        candidates = [
            mount/"Windows/System32/winevt/Logs",
            mount/"Windows/System32/config/TxR",  # not logs, but sometimes useful
        ]
        ensure_dir(dest)
        cnt = 0
        for c in candidates:
            if c.exists() and c.is_dir():
                for f in c.glob("*.evtx"):
                    shutil.copy2(f, dest/f.name)
                    cnt += 1
        return cnt

    def _mount_image(self, image: Path, mnt: Path) -> bool:
        if not self.mount_bin:
            return False
        ensure_dir(mnt)
        p = subprocess.run([self.mount_bin, str(image), str(mnt)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return p.returncode == 0

    def run(self, ticket: dict) -> WorkerResult:
        kind = ticket.get("kind")
        path = Path(ticket.get("dest_path",""))
        host = ticket.get("host") or self.env.get("WADE_HOSTNAME","host")
        if kind not in ("ewf-e01","disk-raw") or not path.exists():
            return WorkerResult(None, 0, [f"skip kind={kind} path_exists={path.exists()}"])
        if self.should_skip_by_splunk(host, "disk-suite", str(path)):
            return WorkerResult(None, 0, ["dedupe_splunk"])

        # 1) target-info
        info = self._target_info(path)

        # 2) mount and export EVTX → DataSources/Hosts/<host>/winevtlog
        paths = wade_paths(self.env, host)
        winevt_out = paths["host_root"]/"winevtlog"
        cnt_evtx = 0
        tmp_mnt = Path(f"/var/wade/tmp/mnt-{host}-{os.getpid()}")
        try:
            if self._mount_image(path, tmp_mnt):
                cnt_evtx = self._export_winevt(tmp_mnt, winevt_out)
        finally:
            # best-effort unmount (target-mount typically uses fuse; it toggles on term)
            pass

        # 3) Produce a facts blob
        self.module = "disk-facts"
        recs = [{
            "ts": now_iso(),
            "image_path": str(path),
            "exported_evtx": cnt_evtx,
            "target_info": info,
        }]
        return self.run_records(host, recs, str(path))
