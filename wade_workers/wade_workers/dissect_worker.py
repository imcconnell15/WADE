"""
WADE Dissect Worker

Runs Dissect target-query plugins against disk images and VM containers.
Supports OS-specific plugin bundles configurable via YAML and environment.

Configuration:
  YAML (wade_config.yaml):
    dissect:
      windows_plugins:
        - amcache.general
        - prefetch
        - regf.shellbags
      linux_plugins:
        - log.authlog
        - history.bashhistory
      disabled_windows_plugins:
        - prefetch
  
  Environment:
    WADE_DISSECT_WINDOWS_PLUGINS="+regf.runkeys,-prefetch"
    WADE_DISSECT_LINUX_PLUGINS="log.authlog,log.syslog,cronjobs.cronjobs"
"""
import json
from pathlib import Path
from typing import Dict, List, Tuple

from .base import BaseWorker, WorkerResult
from .subprocess_utils import run_tool, safe_run, get_default_registry, ToolNotFoundError, CommandExecutionError
from .logging import EventLogger, finalize_worker_records
from .module_config import get_global_config


# Default plugin bundles
DEFAULT_WINDOWS_PLUGINS = [
    # Execution
    "amcache.general",
    "prefetch",
    "regf.userassist",
    "regf.shellbags",
    "regf.shimcache",
    
    # Persistence
    "regf.runkeys",
    "services.services",
    "tasks.tasks",
    
    # User activity
    "lnk.lnk",
    "jumplist.automatic_destination",
    "recyclebin.recyclebin",
    
    # Logs
    "log.evtx.evtx",
    "firewall.logs",
    
    # Browsers
    "browser.history",
    "browser.downloads",
    "browser.cookies",
]

DEFAULT_LINUX_PLUGINS = [
    # Auth/logs
    "log.authlog",
    "log.syslog",
    "log.lastlog",
    
    # Shell history
    "history.bashhistory",
    
    # Scheduled tasks
    "cronjobs.cronjobs",
    
    # Network
    "linux.network.interfaces",
    "linux.iptables.iptables",
    
    # Packages
    "debian.dpkg.status",
    "packagemanager.logs",
]


class DissectWorker(BaseWorker):
    """Worker for running Dissect forensic analysis."""
    
    tool = "dissect"
    module = "target-query"
    help_text = "Run Dissect target-info and OS-specific target-query plugins."

    def __init__(self, env=None, config=None):
        super().__init__(env, config)
        self.logger = EventLogger.get_logger("dissect_worker")
        self.module_config = get_global_config()
        
        # Verify dissect tools are available
        for tool_name in ["target-info", "target-query", "rdump"]:
            try:
                get_default_registry().require_tool(tool_name)
            except ToolNotFoundError:
                self.logger.log_event(
                    f"worker.dissect.tool_missing",
                    status="warning",
                    tool=tool_name,
                    message=f"{tool_name} not found - dissect functionality may be limited"
                )

    def _resolve_host_and_image(self, ticket: dict) -> Tuple[str, Path]:
        """Extract host and image path from ticket."""
        path_str = ticket.get("dest_path") or ticket.get("path") or ticket.get("image_path")
        if not path_str:
            raise ValueError("No image path specified in ticket")
        
        img_path = Path(path_str)
        if not img_path.exists():
            raise FileNotFoundError(f"Target image not found: {img_path}")
        
        # Try to derive host from ticket or path
        host = (
            ticket.get("host")
            or img_path.parent.name
            or self.env.get("WADE_HOSTNAME", "unknown_host")
        )
        
        return host, img_path

    def _get_target_info(self, image_path: Path, host: str) -> Tuple[Dict, str]:
        """Run target-info to get OS and metadata.
        
        Args:
            image_path: Path to target image
            host: Hostname for logging
        
        Returns:
            Tuple of (info_dict, os_family)
            Returns ({}, "") on error
        """
        self.logger.log_event(
            "worker.dissect.target_info_start",
            host=host,
            image_path=str(image_path),
        )
        
        try:
            result = run_tool(
                "target-info",
                ["-J", str(image_path)],
                timeout=60,
                check=False,
            )
        except ToolNotFoundError as e:
            self.logger.log_worker_error("dissect", str(e), module="target-info", host=host)
            return {}, ""
        
        if not result.success:
            self.logger.log_worker_error(
                "dissect",
                f"target-info failed: {result.truncated_stderr()}",
                module="target-info",
                host=host,
                returncode=result.rc,
            )
            return {}, ""
        
        # Parse JSON output
        try:
            # target-info may output multiple lines; take first JSON object
            for line in result.stdout.splitlines():
                line = line.strip()
                if line and line.startswith("{"):
                    info = json.loads(line)
                    break
            else:
                info = {}
        except json.JSONDecodeError:
            self.logger.log_worker_error(
                "dissect",
                "Failed to parse target-info JSON",
                module="target-info",
                host=host,
            )
            return {}, ""
        
        # Extract OS family (schema varies by dissect version)
        os_family = str(
            info.get("os_family")
            or info.get("os", {}).get("family")
            or info.get("system", {}).get("os_family")
            or ""
        ).lower()
        
        self.logger.log_classification(
            image_path,
            classification=f"dissect_{os_family}" if os_family else "dissect_unknown",
            os_family=os_family,
        )
        
        return info, os_family

    def _get_plugins(self, os_family: str, ticket: dict) -> List[str]:
        """Get plugin list based on OS family.
        
        Priority:
          1. ticket["plugins"] (explicit override)
          2. Environment variable
          3. YAML config
          4. Default plugin bundles
        
        Args:
            os_family: OS family from target-info ("windows", "linux", etc.)
            ticket: Worker ticket (may contain plugins override)
        
        Returns:
            List of plugin names
        """
        # Explicit ticket override
        if "plugins" in ticket:
            val = ticket["plugins"]
            if isinstance(val, str):
                return [p.strip() for p in val.split(",") if p.strip()]
            if isinstance(val, (list, tuple)):
                return [str(p) for p in val if str(p).strip()]
        
        # Determine OS-specific key
        if "win" in os_family:
            key = "windows_plugins"
            default = DEFAULT_WINDOWS_PLUGINS
        elif "linux" in os_family or "unix" in os_family:
            key = "linux_plugins"
            default = DEFAULT_LINUX_PLUGINS
        else:
            # Unknown OS - no defaults
            self.logger.log_event(
                "worker.dissect.unknown_os",
                status="warning",
                os_family=os_family,
                message="No default plugins for this OS family"
            )
            return []
        
        # Get from config with env override
        return self.module_config.get_modules(
            tool="dissect",
            key=key,
            default=default,
        )

    def _run_plugin(
        self,
        plugin: str,
        image_path: Path,
        host: str,
        os_family: str,
    ) -> Tuple[List[dict], str]:
        """Run a single target-query plugin.
        
        Args:
            plugin: Plugin name (e.g., "prefetch")
            image_path: Path to target image
            host: Hostname for logging
            os_family: OS family for metadata
        
        Returns:
            Tuple of (parsed_records, error_message)
        """
        self.logger.log_event(
            "worker.dissect.plugin_start",
            plugin=plugin,
            host=host,
            image_path=str(image_path),
        )
        
        # Run target-query | rdump pipeline
        try:
            # Stage 1: target-query
            tq_result = run_tool(
                "target-query",
                ["-q", "-f", plugin, str(image_path)],
                timeout=180,
                check=False,
            )
            
            if not tq_result.success:
                error = f"target-query failed: {tq_result.truncated_stderr()}"
                return [], error
            
            if not tq_result.stdout.strip():
                # No records - not necessarily an error
                return [], ""
            
            # Stage 2: rdump -J to convert to JSONL
            rd_result = safe_run(
                ["rdump", "-J"],
                timeout=60,
                check=False,
                log_output=False,
            )
            # Feed target-query output to rdump stdin
            import subprocess
            proc = subprocess.run(
                ["rdump", "-J"],
                input=tq_result.stdout,
                capture_output=True,
                text=True,
                timeout=60,
            )
            
            if proc.returncode != 0:
                error = f"rdump failed: rc={proc.returncode}"
                return [], error
            
            # Parse JSONL output
            records = []
            for line in proc.stdout.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    # Annotate with metadata
                    obj["_plugin"] = plugin
                    obj["_os_family"] = os_family
                    records.append(obj)
                except json.JSONDecodeError:
                    continue
            
            self.logger.log_event(
                "worker.dissect.plugin_complete",
                status="success",
                plugin=plugin,
                host=host,
                record_count=len(records),
            )
            
            return records, ""
            
        except ToolNotFoundError as e:
            return [], str(e)
        except subprocess.TimeoutExpired:
            return [], f"{plugin}: timeout after 180s"
        except Exception as e:
            return [], f"{plugin}: {e}"

    def run(self, ticket: dict) -> WorkerResult:
        """Execute Dissect worker.
        
        Workflow:
          1. Run target-info to get OS
          2. Select plugin bundle for OS
          3. Run each plugin via target-query | rdump
          4. Write JSONL records
        
        Args:
            ticket: Worker ticket
        
        Returns:
            WorkerResult with execution summary
        """
        errors: List[str] = []
        
        try:
            host, img_path = self._resolve_host_and_image(ticket)
        except (ValueError, FileNotFoundError) as e:
            errors.append(str(e))
            return WorkerResult(path=None, count=0, errors=errors)
        
        self.logger.log_worker_start("dissect", host=host, image_path=str(img_path))
        
        # Get target info and OS
        info, os_family = self._get_target_info(img_path, host)
        
        # Get plugins for OS
        plugins = self._get_plugins(os_family, ticket)
        if not plugins:
            msg = "No plugins configured for OS family: {os_family}"
            errors.append(msg)
            self.logger.log_worker_error("dissect", msg, host=host, os_family=os_family)
            return WorkerResult(path=None, count=0, errors=errors)
        
        # Run plugins
        total_records = 0
        output_dir, _ = self._get_output_paths(host)
        
        for plugin in plugins:
            records, error = self._run_plugin(plugin, img_path, host, os_family)
            
            if error:
                errors.append(f"{plugin}: {error}")
            
            if records:
                output_file = output_dir / f"{plugin.replace('.', '_')}.jsonl"
                count = finalize_worker_records(
                    records,
                    output_path=output_file,
                    tool="dissect",
                    module=plugin,
                    host=host,
                    metadata={
                        "image_path": str(img_path),
                        "os_family": os_family,
                    },
                )
                total_records += count
        
        self.logger.log_worker_complete(
            "dissect",
            host=host,
            record_count=total_records,
            output_path=output_dir,
        )
        
        return WorkerResult(path=output_dir, count=total_records, errors=errors)
    
    def _get_output_paths(self, host: str) -> Tuple[Path, Path]:
        """Get output and log directories."""
        from .utils import wade_paths
        return wade_paths(self.env, host, self.tool, self.module)
