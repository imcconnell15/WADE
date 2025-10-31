#!/usr/bin/env python3
import os, time, json, urllib.request, urllib.error, urllib.parse
from typing import Dict, Optional

class SplunkDedupe:
    """
    Safe-by-default stub; returns False unless REST config provided.
    Configure in config.yaml:
      splunk:
        rest_url: "https://splunk.example.org:8089"
        token: "Splunk <mgmt_token>"
        search: 'search index=wade_* wade.image_path="{image_path}" earliest=-30d | head 1'
    """
    def __init__(self, env: Dict[str,str], cfg: Dict):
        self.env = env
        self.url = cfg.get("rest_url", "").rstrip("/")
        self.token = cfg.get("token", "")
        self.search_tpl = cfg.get("search",
            'search index=wade_* wade.image_path="{image_path}" earliest=-30d | head 1'
        )
        self.timeout = int(cfg.get("timeout_sec", 4))

    def already_ingested(self, host: str, tool: str, module: str, image_path: Optional[str]) -> bool:
        if not self.url or not self.token or not image_path:
            return False
        try:
            # Splunk management /services/search/jobs/export (oneshot)
            q = self.search_tpl.format(image_path=image_path.replace('"', '\\"'))
            data = urllib.parse.urlencode({"search": q, "output_mode": "json"}).encode("utf-8")
            req = urllib.request.Request(self.url + "/services/search/jobs/export", data=data, method="POST")
            req.add_header("Authorization", self.token)
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                body = r.read(32768)
                return b'"results":' in body and b'}' in body
        except Exception:
            return False
