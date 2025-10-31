#!/usr/bin/env python3
import os, json, shutil, subprocess, tempfile
from pathlib import Path
from .base import BaseWorker, WorkerResult
from .utils import now_iso

class BulkExtractorWorker(BaseWorker):
    tool = "bulk_extractor"
    help_text = "Bulk Extractor content scanning summary (emails, URLs, CCNs)."
    prefer_jsonl = True

    def __init__(self, env=None, config=None):
        super().__init__(env, config)
        self.be = shutil.which("bulk_extractor")

    def _summarize_outdir(self, outdir: Path) -> list:
        recs = []
        for f in outdir.glob("*.txt"):
            try:
                sz = f.stat().st_size
                head = f.read_text(errors="ignore")[:2000]
                recs.append({"file": f.name, "size": sz, "preview": head})
            except Exception:
                pass
        return recs

    def run(self, ticket: dict) -> WorkerResult:
        kind = ticket.get("kind")
        path = Path(ticket.get("dest_path",""))
        host = ticket.get("host") or self.env.get("WADE_HOSTNAME","host")
        if kind not in ("ewf-e01","disk-raw","archive","memory","unknown") or not path.exists():
            return WorkerResult(None, 0, [f"skip kind={kind} path_exists={path.exists()}"])
        if not self.be:
            return WorkerResult(None,0,["bulk_extractor_not_found"])
        if self.should_skip_by_splunk(host, "bulkextractor", str(path)):
            return WorkerResult(None,0,["dedupe_splunk"])

        tmp = Path(tempfile.mkdtemp(prefix="be-"))
        try:
            p = subprocess.run([self.be, "-o", str(tmp), str(path)],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            recs = [{
                "ts": now_iso(),
                "image_path": str(path),
                "rc": p.returncode,
                "stderr": p.stderr[:4000],
                "summary": self._summarize_outdir(tmp),
            }]
            self.module = "scan"
            return self.run_records(host, recs, str(path))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
