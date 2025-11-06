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
    module = "manifest"
    help_text = "Generate Autopsy manifest XML into the wade_autopsy tree."

    def run(self, ticket: dict) -> WorkerResult:
        host = ticket.get("host") or self.env.get("WADE_HOSTNAME","host")
        img = Path(ticket.get("dest_path") or ticket.get("path") or "")
        if not img.exists():
            return WorkerResult(None, 0, [f"missing image: {img}"])

        out_dir, _ = wade_paths(self.env, host, self.tool, self.module)
        case_name = f"{host}_{img.stem}"
        xml_path = out_dir / f"{case_name}.manifest.xml"
        xml_path.write_text(CASE_TPL.format(name=case_name, image=str(img)), encoding="utf-8")

        # Emit a small JSON pointer for Splunk and traceability
        rec = {"ts": now_iso(), "manifest": str(xml_path), "image": str(img)}
        out, cnt = self.run_records(host, [rec], str(img))
        return WorkerResult(out, cnt, [])
