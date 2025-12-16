"""
Module/plugin configuration system for WADE tools.

Supports loading module lists from YAML config with environment variable
overrides. Makes it easy to enable/disable modules or add custom ones
without code changes.

Configuration priority (highest to lowest):
  1. Environment variables (WADE_<TOOL>_MODULES)
  2. YAML config file
  3. Code defaults

Example YAML:
    volatility:
      modules:
        - windows.pslist
        - windows.netscan
      disabled_modules:
        - windows.malfind
      
    dissect:
      windows_plugins:
        - amcache.general
        - prefetch
      linux_plugins:
        - log.authlog
        - history.bashhistory

Example env override:
    export WADE_VOLATILITY_MODULES="windows.pslist,windows.netscan,windows.cmdline"
    export WADE_DISSECT_WINDOWS_PLUGINS="+regf.shellbags,-prefetch"  # add/remove syntax
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List, Optional, Set
import yaml


class ModuleConfig:
    """Registry for tool modules/plugins with YAML and env override support.
    
    Example usage:
        config = ModuleConfig.from_yaml(Path("wade_config.yaml"))
        
        # Get modules for volatility
        vol_modules = config.get_modules(
            "volatility",
            default=["windows.pslist", "windows.netscan"]
        )
        
        # Get OS-specific dissect plugins
        win_plugins = config.get_modules(
            "dissect",
            key="windows_plugins",
            default=WINDOWS_DEFAULTS
        )
    """
    
    def __init__(self, config_data: Optional[Dict] = None):
        """
        Create a ModuleConfig instance from an optional configuration mapping.
        
        Parameters:
            config_data (Optional[Dict]): Configuration mapping (typically the result of parsing a YAML file). When omitted or None, an empty configuration is used and stored internally.
        """
        self._config = config_data or {}
    
    @classmethod
    def from_yaml(cls, path: Path) -> ModuleConfig:
        """
        Create a ModuleConfig populated from the contents of a YAML file.
        
        Parameters:
            path (Path): Filesystem path to the YAML configuration file to read.
        
        Returns:
            ModuleConfig: Instance populated with the parsed YAML mapping (empty mapping if the file is empty).
        
        Raises:
            FileNotFoundError: If the specified YAML file does not exist.
        """
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        
        return cls(data)
    
    @classmethod
    def from_env(cls) -> ModuleConfig:
        """
        Load module configuration from an environment-specified or default file path.
        
        Searches these locations in order and loads the first existing YAML file: the path in
        the WADE_CONFIG_PATH environment variable, /etc/wade/config.yaml, then ./wade_config.yaml.
        
        Returns:
            ModuleConfig: The loaded configuration, or an empty ModuleConfig if no config file is found.
        """
        candidates = [
            os.environ.get("WADE_CONFIG_PATH"),
            "/etc/wade/config.yaml",
            "./wade_config.yaml",
        ]
        
        for candidate in candidates:
            if candidate:
                path = Path(candidate)
                if path.exists():
                    return cls.from_yaml(path)
        
        # No config found - return empty config
        return cls({})
    
    def get_tool_config(self, tool: str) -> Dict:
        """
        Retrieve the configuration mapping for the given tool.
        
        Parameters:
            tool (str): Tool name, e.g., "volatility" or "dissect".
        
        Returns:
            dict: Configuration dictionary for the tool; empty dict if the tool is not configured.
        """
        return self._config.get(tool, {})
    
    def get_modules(
        self,
        tool: str,
        key: str = "modules",
        default: Optional[List[str]] = None,
        env_var: Optional[str] = None,
    ) -> List[str]:
        """
        Resolve a tool's module list using defaults, YAML configuration, and optional environment-variable overrides.
        
        Parameters:
            tool (str): Tool section name in the configuration (e.g., "volatility").
            key (str): Key inside the tool config that contains the module list (default: "modules").
            default (Optional[List[str]]): Fallback module list used when neither YAML nor env provides modules.
            env_var (Optional[str]): Explicit environment variable name to read overrides from. If omitted, the
                environment variable WADE_<TOOL>_<KEY> (uppercased) is used.
        
        Behavior:
            Priority for determining the final module list is:
              1. Environment variable (if set)
              2. YAML config at config[tool][key]
              3. The provided `default` list
        
            If the tool config contains a `disabled_<key>` list, those module names are removed from the resolved list.
            Environment overrides support an add/remove syntax:
              - A value without '+' or '-' replaces the entire list.
              - Entries starting with '+' are added (preserving order where possible).
              - Entries starting with '-' are removed.
              - Mixed forms (some entries with +/- and some without) treat non-prefixed entries as additions.
        
        Returns:
            List[str]: The resolved ordered list of module names.
        """
        # Start with default
        modules = list(default or [])
        
        # Override from YAML if present
        tool_cfg = self.get_tool_config(tool)
        if key in tool_cfg:
            yaml_modules = tool_cfg[key]
            if isinstance(yaml_modules, list):
                modules = [str(m) for m in yaml_modules]
        
        # Check for disabled modules in YAML
        disabled_key = f"disabled_{key}"
        if disabled_key in tool_cfg:
            disabled = tool_cfg[disabled_key]
            if isinstance(disabled, list):
                disabled_set = {str(m) for m in disabled}
                modules = [m for m in modules if m not in disabled_set]
        
        # Apply env override
        if env_var is None:
            env_var = f"WADE_{tool.upper()}_{key.upper()}"
        
        env_value = os.environ.get(env_var, "").strip()
        if env_value:
            modules = self._apply_env_override(modules, env_value)
        
        return modules
    
    def _apply_env_override(self, base: List[str], env_value: str) -> List[str]:
        """
        Resolve an environment-style override string against a base module list using replacement or incremental +/- operations.
        
        The env_value is a comma-separated list of tokens. If none of the tokens start with "+" or "-", the token list replaces the base list. If any token starts with "+" or "-", tokens modify the base list incrementally: "+" adds the module, "-" removes it, and tokens without a sign are treated as additions. When modifying incrementally, the function preserves the order of modules from the base list and appends newly added modules at the end.
        
        Parameters:
            base (List[str]): The original ordered list of module names.
            env_value (str): Comma-separated override string (e.g., "a,b" or "+a,-b,c").
        
        Returns:
            List[str]: The resulting ordered list of module names after applying the override.
        """
        parts = [p.strip() for p in env_value.split(",") if p.strip()]
        if not parts:
            return base
        
        # Check if any part starts with +/- (incremental mode)
        has_modifiers = any(p.startswith(("+", "-")) for p in parts)
        
        if not has_modifiers:
            # Replace mode - entire new list
            return parts
        
        # Incremental mode - start with base
        result = set(base)
        
        for part in parts:
            if part.startswith("+"):
                # Add module
                result.add(part[1:])
            elif part.startswith("-"):
                # Remove module
                result.discard(part[1:])
            else:
                # No modifier - treat as add
                result.add(part)
        
        # Preserve order of original list where possible
        ordered = [m for m in base if m in result]
        # Add new modules at end
        for m in result:
            if m not in ordered:
                ordered.append(m)
        
        return ordered


# Singleton for global config
_global_config: Optional[ModuleConfig] = None


def get_global_config() -> ModuleConfig:
    """Get or initialize global module configuration.
    
    Loads from environment on first call, caches result.
    
    Returns:
        Global ModuleConfig instance
    """
    global _global_config
    if _global_config is None:
        _global_config = ModuleConfig.from_env()
    return _global_config


def reload_global_config() -> ModuleConfig:
    """
    Reload the global ModuleConfig from environment-determined sources.
    
    Returns:
        ModuleConfig: The reloaded ModuleConfig instance.
    """
    global _global_config
    _global_config = ModuleConfig.from_env()
    return _global_config