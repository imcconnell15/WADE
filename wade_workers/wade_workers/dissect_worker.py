#!/usr/bin/env python3
"""
WADE Dissect worker

- Run `target-info -J` to capture OS + target metadata.
- Use OS family (windows/linux/etc.) to select a plugin bundle.
- Run `target-query -q -f <plugin> <image> | rdump -J`.
- Ingest JSONL output into WADE via run_records() for Splunk.

You can override the plugin bundles via:
  - ticket["plugins"]  (list or comma-separated string)
  - env DISSECT_PLUGINS_WINDOWS / DISSECT_PLUGINS_LINUX
"""

import json
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple, Optional

from .base import BaseWorker, WorkerResult
from .utils import wade_paths, now_iso


def _cmd_target_info(env: Dict[str, str]) -> str:
    """Resolve the target-info command (allow override via env)."""
    return env.get("DISSECT_TARGET_INFO_CMD") or shutil.which("target-info") or "target-info"


def _cmd_target_query(env: Dict[str, str]) -> str:
    """Resolve the target-query command (allow override via env)."""
    return env.get("DISSECT_TARGET_QUERY_CMD") or shutil.which("target-query") or "target-query"


def _cmd_rdump(env: Dict[str, str]) -> str:
    """Resolve the rdump command (allow override via env)."""
    return env.get("DISSECT_RDUMP_CMD") or shutil.which("rdump") or "rdump"


# ---------------------------------------------------------------------------
# Default plugin bundles
#
# These are *starting points* — tune them to match the output of
# `target-query -l` in your environment. You can also override them
# via DISSECT_PLUGINS_WINDOWS / DISSECT_PLUGINS_LINUX or ticket["plugins"].
# ---------------------------------------------------------------------------

WINDOWS_DEFAULT_PLUGINS: List[str] = [
    # OS / general telemetry
    "generic.activity",          # last seen activity (filesystem timeline-ish)
    "generic.install_date",      # OS install date

    # Execution / usage
    "amcache.general",
    "amcache.applications",
    "amcache.files",
    "prefetch",
    "regf.userassist",
    "regf.shellbags",
    "regf.shimcache",

    # Persistence / configuration
    "regf.runkeys",
    "services.services",
    "tasks.tasks",
    "startupinfo.startupinfo",

    # User activity & artifacts
    "browser.history",
    "browser.downloads",
    "browser.cookies",
    "lnk.lnk",
    "jumplist.automatic_destination",
    "jumplist.custom_destination",
    "recyclebin.recyclebin",

    # Logging / timeline
    "log.evtx.evtx",
    "log.evt.evt",
    "firewall.logs",
    "sru.application_timeline",
]

LINUX_DEFAULT_PLUGINS: List[str] = [
    # Auth / sessions / system logs
    "log.authlog",
    "log.securelog",
    "log.messages",
    "log.syslog",
    "log.journal",
    "log.lastlog",
    "log.utmp.utmp",
    "log.utmp.wtmp",

    # Packages / updates
    "debian.apt.logs",
    "debian.dpkg.log",
    "debian.dpkg.status",
    "redhat.yum.logs",
    "suse.zypper.logs",
    "packagemanager.logs",

    # Processes / services / sockets
    "linux.processes.processes",
    "linux.services.services",
    "linux.sockets.tcp",
    "linux.sockets.udp",
    "linux.sockets.unix",

    # Shell / schedule / user activity
    "history.bashhistory",
    "cronjobs.cronjobs",
    "recentlyused.recently_used",

    # Network / firewall
    "linux.iptables.iptables",
    "linux.network.interfaces",
    "linux.network.dns",
    "linux.network.gateways",
    "linux.network.ips",
    "linux.network.macs",

    # Containers / webservers
    "container.containers",
    "container.images",
    "container.logs",
    "webserver.access",
    "webserver.error",
    "webserver.logs",
]


class DissectWorker(BaseWorker):
    tool = "dissect"
    module = "target-info"  # primary "module" name for logging
    help_text = (
        "Run Dissect target-info and OS-specific target-query plugins, "
        "outputting JSON records suitable for Splunk."
    )

    # ------------------------------------------------------------------
    # Small helpers
    # ------------------------------------------------------------------

    def _host_and_img(self, ticket: dict) -> Tuple[str, Path]:
        host = ticket.get("host") or self.env.get("WADE_HOSTNAME", "host")
        p = Path(ticket.get("dest_path") or ticket.get("path") or "")
        if not p.exists():
            raise FileNotFoundError(f"target not found: {p}")
        return host, p

    def _append_log(self, host: str, text: str) -> None:
        _, log_dir = wade_paths(self.env, host, self.tool, self.module)
        log_path = log_dir / f"{self.tool}_{self.module}.log"
        prev = ""
        if log_path.exists():
            prev = log_path.read_text(encoding="utf-8", errors="ignore")
        log_path.write_text(prev + text.rstrip() + "\n", encoding="utf-8")

    # ------------------------------------------------------------------
    # target-info: OS + metadata
    # ------------------------------------------------------------------

    def _get_target_info(
        self,
        host: str,
        img: Path,
        errors: List[str],
    ) -> Tuple[Optional[Dict], int]:
        """
        Run `target-info -J` and store a single JSON record via run_records.

        Returns (info_dict or None, record_count).
        """
        cmd = _cmd_target_info(self.env)
        args = [cmd, "-J", str(img)]
        self._append_log(host, f"{now_iso()} running: {' '.join(args)}")

        try:
            cp = subprocess.run(args, capture_output=True, text=True, check=False)
        except Exception as e:
            errors.append(f"target-info spawn: {e!r}")
            return None, 0

        if cp.returncode != 0:
            errors.append(f"target-info rc={cp.returncode} stderr={cp.stderr.strip()[:4000]}")
            return None, 0

        stdout = cp.stdout.strip()
        if not stdout:
            errors.append("target-info produced no output")
            return None, 0

        first_line = stdout.splitlines()[0]
        try:
            info = json.loads(first_line)
        except Exception as e:
            errors.append(f"target-info JSON parse error: {e!r}")
            return None, 0

        rec = {
            "ts": now_iso(),
            "tool": "dissect",
            "module": "target-info",
            "image_path": str(img),
            "info": info,
        }
        _, cnt = self.run_records(host, [rec], str(img))
        return info, cnt

    # ------------------------------------------------------------------
    # Plugin selection
    # ------------------------------------------------------------------

    def _plugins_for_os(self, os_family: str, ticket: dict) -> List[str]:
        """
        Decide which target-query plugins to run.

        Priority:
          1) ticket["plugins"] (list or comma-separated string)
          2) env DISSECT_PLUGINS_WINDOWS / DISSECT_PLUGINS_LINUX
          3) built-in defaults per OS family
        """
        # Explicit override on the ticket
        if "plugins" in ticket:
            val = ticket["plugins"]
            if isinstance(val, str):
                return [p.strip() for p in val.split(",") if p.strip()]
            if isinstance(val, (list, tuple)):
                return [str(p).strip() for p in val if str(p).strip()]

        os_key = (ticket.get("os_family") or ticket.get("os") or os_family or "").lower()

        if "win" in os_key:
            env_val = self.env.get("DISSECT_PLUGINS_WINDOWS")
            if env_val:
                return [p.strip() for p in env_val.split(",") if p.strip()]
            return WINDOWS_DEFAULT_PLUGINS

        if "linux" in os_key or "unix" in os_key:
            env_val = self.env.get("DISSECT_PLUGINS_LINUX")
            if env_val:
                return [p.strip() for p in env_val.split(",") if p.strip()]
            return LINUX_DEFAULT_PLUGINS

        # Unknown OS family – caller can still override via ticket["plugins"]
        return []

    # ------------------------------------------------------------------
    # target-query + rdump for a single plugin
    # ------------------------------------------------------------------

    def _run_plugin(
        self,
        host: str,
        img: Path,
        plugin: str,
        errors: List[str],
        os_family: str,
    ) -> int:
        """
        Run a single target-query plugin and feed JSONL into run_records().

        Returns number of records ingested.
        """
        tq_cmd = _cmd_target_query(self.env)
        rd_cmd = _cmd_rdump(self.env)

        # If commands are missing, record an error and bail.
        if not shutil.which(tq_cmd):
            errors.append(f"target-query command '{tq_cmd}' not found in PATH")
            return 0
        if not shutil.which(rd_cmd):
            errors.append(f"rdump command '{rd_cmd}' not found in PATH")
            return 0

        tq_args = [tq_cmd, "-q", "-f", plugin, str(img)]
        self._append_log(host, f"{now_iso()} running: {' '.join(tq_args)} | {rd_cmd} -J")

        # First stage: target-query
        try:
            cp1 = subprocess.run(
                tq_args,
                capture_output=True,
                text=True,
                check=False,
            )
        except Exception as e:
            errors.append(f"{plugin}: target-query spawn error: {e!r}")
            return 0

        if cp1.returncode != 0:
            stderr = (cp1.stderr or "").strip()
            errors.append(f"{plugin}: target-query rc={cp1.returncode} stderr={stderr[:4000]}")
            return 0

        if not cp1.stdout.strip():
            # No records for this plugin is fine.
            return 0

        # Second stage: rdump -J to convert records to JSONL
        try:
            cp2 = subprocess.run(
                [rd_cmd, "-J"],
                input=cp1.stdout,
                capture_output=True,
                text=True,
                check=False,
            )
        except Exception as e:
            errors.append(f"{plugin}: rdump spawn error: {e!r}")
            return 0

        if cp2.returncode != 0:
            stderr = (cp2.stderr or "").strip()
            errors.append(f"{plugin}: rdump rc={cp2.returncode} stderr={stderr[:4000]}")
            return 0

        lines = [ln.strip() for ln in (cp2.stdout or "").splitlines() if ln.strip()]
        if not lines:
            return 0

        recs: List[dict] = []
        for ln in lines:
            try:
                obj = json.loads(ln)
            except Exception as e:
                errors.append(f"{plugin}: JSON parse error: {e!r}")
                continue

            # Annotate for WADE/Splunk context
            obj["_tool"] = "dissect"
            obj["_module"] = "target-query"
            obj["_plugin"] = plugin
            obj["_image_path"] = str(img)
            if os_family:
                obj["_os_family"] = os_family
            obj["_wade_ts"] = now_iso()
            recs.append(obj)

        if not recs:
            return 0

        _, cnt = self.run_records(host, recs, str(img))
        return cnt

    # ------------------------------------------------------------------
    # Main entrypoint
    # ------------------------------------------------------------------

    def run(self, ticket: dict) -> WorkerResult:
        """
        Full workflow:

          1) Resolve host + image.
          2) Run target-info -J, store metadata record.
          3) Derive os_family from target-info (or ticket).
          4) Determine plugin set.
          5) Run each plugin through target-query | rdump -J and ingest JSONL.
        """
        errors: List[str] = []

        host, img = self._host_and_img(ticket)

        # 1) target-info
        info, meta_cnt = self._get_target_info(host, img, errors)
        os_family = ""
        if isinstance(info, dict):
            # target-info JSON schema may vary; be defensive.
            os_family = str(
                info.get("os_family")
                or info.get("os", {}).get("family")
                or info.get("system", {}).get("os_family")
                or ""
            )

        # Fallback to ticket fields if needed
        if not os_family:
            os_family = str(ticket.get("os_family") or ticket.get("os") or "")

        # 2) plugin bundle
        plugins = self._plugins_for_os(os_family, ticket)
        total_cnt = meta_cnt

        if not plugins:
            errors.append(
                f"no plugin bundle selected for os_family={os_family!r}; "
                "only target-info metadata was collected"
            )
            return WorkerResult(None, total_cnt, errors)

        # 3) run plugins
        for plugin in plugins:
            try:
                total_cnt += self._run_plugin(host, img, plugin, errors, os_family)
            except Exception as e:
                errors.append(f"{plugin}: unexpected exception: {e!r}")

        # We don't rely on WorkerResult.out for anything in WADE right now,
        # so returning None here is fine.
        return WorkerResult(None, total_cnt, errors)
