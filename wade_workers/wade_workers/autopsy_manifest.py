#!/usr/bin/env python3
from pathlib import Path
from .base import BaseWorker, WorkerResult
from .utils import wade_paths, now_iso

CASE_TPL = """<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<AutopsyManifest>
    <CaseName>{name}</CaseName>
    <IngestModule>Disk Image Ingest</IngestModule>
    <DataSource>{image}</DataSource>
</AutopsyManifest>
"""

class AutopsyManifestWorker(BaseWorker):
    tool = "autopsy"
    help_text = "Generate Autopsy manifest XML beside image."
    prefer_jsonl = False

    def run(self, ticket: dict) -> WorkerResult:
        path = Path(ticket.get("dest_path",""))
        host = ticket.get("host") or self.env.get("WADE_HOSTNAME","host")
        if not path.exists():
            return WorkerResult(None, 0, ["image_missing"])
        # Write an XML next to the image
        xml = path.with_suffix(path.suffix + ".autopsy.xml")
        xml.write_text(CASE_TPL.format(
            name=f"{host}-{path.stem}",
            created=now_iso(),
            image=str(path)
        ), encoding="utf-8")
        # Also produce a small JSON record for Splunk traceability
        self.module = "manifest"
        return self.run_records(host, [{"ts": now_iso(), "manifest": str(xml), "image_path": str(path)}], str(path))
