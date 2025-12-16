from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, List, Tuple, Optional

import yaml

# Normalize classification aliases
CLASS_ALIASES = {
    "mem": "memory",
    "memory": "memory",
    "e01": "e01",
    "disk_raw": "disk_raw",
    "vm_disk": "vm_disk",
    "vm_package": "vm_package",
    "network_config": "network_config",
    "network_doc": "network_doc",
    "malware": "malware",
    "misc": "misc",
    "unknown": "unknown",
}

# Default matrix (can be overridden in YAML `routing.defaults`)
DEFAULT_MATRIX: Dict[Tuple[str, str], List[str]] = {
    ("e01",       "full"):  ["dissect", "hayabusa", "autopsy", "bulk_extractor"],
    ("e01",       "light"): ["dissect", "hayabusa"],

    ("disk_raw",  "full"):  ["dissect", "hayabusa", "autopsy", "bulk_extractor"],
    ("disk_raw",  "light"): ["dissect"],

    ("memory",    "full"):  ["volatility", "yara_mem", "autopsy"],
    ("memory",    "light"): ["volatility"],

    ("vm_disk",   "full"):  ["dissect"],
    ("vm_package","full"):  ["dissect"],

    ("network_config", "full"): ["netcfg"],
    ("network_doc",   "full"): ["netdoc"],
}

def _norm_class(cls: str) -> str:
    return CLASS_ALIASES.get((cls or "").lower(), "unknown")

def _parse_list(value: str) -> List[str]:
    return [p.strip() for p in value.split(",") if p.strip()]

def _apply_add_remove(base: List[str], expr: str) -> List[str]:
    # "+a,-b,c" → additive/removal; if no +/- anywhere, replace entire list
    parts = _parse_list(expr)
    if not parts:
        return base
    if not any(p.startswith(("+", "-")) for p in parts):
        # replace mode
        return parts
    result = list(dict.fromkeys(base))  # preserve order
    for p in parts:
        if p.startswith("+"):
            v = p[1:]
            if v not in result:
                result.append(v)
        elif p.startswith("-"):
            v = p[1:]
            result = [x for x in result if x != v]
        else:
            if p not in result:
                result.append(p)
    return result

class ToolRouting:
    """
    Load routing config and compute tools for (classification, profile, details).

    YAML schema (config.yaml):
      routing:
        defaults:
          e01:
            full:  [dissect, hayabusa, autopsy, bulk_extractor]
            light: [dissect, hayabusa]
          memory:
            full:  [volatility, yara_mem, autopsy]
            light: [volatility]
        disabled_tools: [autopsy]           # optional, global disable
        os_overrides:
          windows:
            add:
              memory.full: [hayabusa]
            remove:
              memory.full: [autopsy]
        location_overrides:
          datacenterA:
            add:
              e01.full: [yara_mem]
            remove:
              disk_raw.light: [dissect]
    """
    def __init__(self, config_path: Optional[Path] = None, env: Optional[Dict[str, str]] = None):
        self.env = env or dict(os.environ)
        self.config_path = Path(config_path or self.env.get("WADE_CONFIG_PATH", "/etc/wade/config.yaml"))
        self.cfg = self._load_cfg()

    def _load_cfg(self) -> Dict:
        if self.config_path.exists():
            try:
                return yaml.safe_load(self.config_path.read_text()) or {}
            except Exception:
                return {}
        return {}

    def _get_defaults(self) -> Dict[Tuple[str, str], List[str]]:
        res = dict(DEFAULT_MATRIX)
        routing = (self.cfg.get("routing") or {}).get("defaults") or {}
        # Merge YAML defaults
        for cls, profiles in routing.items():
            clsn = _norm_class(cls)
            if isinstance(profiles, dict):
                for prof, tools in profiles.items():
                    key = (clsn, (prof or "full").lower())
                    if isinstance(tools, list):
                        res[key] = [str(t) for t in tools]
        return res

    def select_tools(
        self,
        classification: str,
        profile: str,
        details: Optional[Dict] = None,
        location: Optional[str] = None,
    ) -> List[str]:
        clsn = _norm_class(classification)
        prof = (profile or "full").lower()
        details = details or {}

        matrix = self._get_defaults()
        tools = list(matrix.get((clsn, prof), []))

        # Global disables from YAML
        disabled_yaml = set(((self.cfg.get("routing") or {}).get("disabled_tools") or []))

        # OS-based overrides
        os_family = (details.get("os_family") or "").lower()
        os_over = ((self.cfg.get("routing") or {}).get("os_overrides") or {}).get(os_family) or {}
        tools = self._apply_over_block(tools, os_over, clsn, prof)

        # Location-based overrides (if location provided by detect_profile)
        if location:
            loc_over = ((self.cfg.get("routing") or {}).get("location_overrides") or {}).get(location) or {}
            tools = self._apply_over_block(tools, loc_over, clsn, prof)

        # Env override per (CLASS, PROFILE), e.g., WADE_ROUTE_E01_FULL
        env_key = f"WADE_ROUTE_{clsn.upper()}_{prof.upper()}"
        if env_key in self.env and self.env[env_key]:
            tools = _apply_add_remove(tools, self.env[env_key])

        # Global disable list via env, comma-separated
        disabled_env = set(_parse_list(self.env.get("WADE_DISABLE_TOOLS", "")))
        enabled_env = set(_parse_list(self.env.get("WADE_ENABLE_TOOLS", "")))  # allow opt-in even if disabled

        # Platform sanity: remove hayabusa if not windows
        if os_family and "windows" not in os_family:
            tools = [t for t in tools if t != "hayabusa"]

        # Apply disables (YAML + env), then re-add any WADE_ENABLE_TOOLS explicitly
        tools = [t for t in tools if t not in disabled_yaml and t not in disabled_env] + [t for t in enabled_env if t not in tools]

        # Remove duplicates, preserve order
        uniq = []
        for t in tools:
            if t not in uniq:
                uniq.append(t)
        return uniq

    def _apply_over_block(self, tools: List[str], block: Dict, clsn: str, prof: str) -> List[str]:
        # block schema: { add: { "memory.full": [x] }, remove: {...} }
        def apply(op: str, base: List[str]) -> List[str]:
            changes = (block.get(op) or {})
            key = f"{clsn}.{prof}"
            if key in changes and isinstance(changes[key], list):
                expr = ",".join(("+" if op == "add" else "-") + str(x) for x in changes[key])
                return _apply_add_remove(base, expr)
            return base
        tools = apply("add", tools)
        tools = apply("remove", tools)
        return tools
