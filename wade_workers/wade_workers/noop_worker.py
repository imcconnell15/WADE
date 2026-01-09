#!/usr/bin/env python3
from .base import BaseWorker, WorkerResult
from .utils import now_iso
from pathlib import Path

class NoopWorker(BaseWorker):
    tool = "noop"
    module = "ticket"
    help_text = "Placeholder worker to validate end-to-end pipeline."

    def run(self, ticket: dict) -> WorkerResult:
        host = ticket.get("host") or self.env.get("WADE_HOSTNAME","host")
        path = ticket.get("dest_path") or ticket.get("path")
        record = {"ts": now_iso(), "ticket_class": ticket.get("classification","unknown"), "dest_path": path}
        return self.run_records(host, [record], str(path) if path else None)
