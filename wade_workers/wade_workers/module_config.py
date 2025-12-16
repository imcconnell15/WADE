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
        """Initialize with config dictionary (typically from YAML).
        
        Args:
            config_data: Config dict, usually from YAML.load()
        """
        self._config = config_data or {}
    
    @classmethod
    def from_yaml(cls, path: Path) -> ModuleConfig:
        """Load configuration from YAML file.
        
        Args:
            path: Path to YAML config file
        
        Returns:
            ModuleConfig instance
        
        Raises:
            FileNotFoundError: If YAML file doesn't exist
        """
        if not path.exists():
            raise FileNotFoundError(f"Config file not found: {path}")
        
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        
        return cls(data)
    
    @classmethod
    def from_env(cls) -> ModuleConfig:
        """Load config from default location specified in env.
        
        Checks WADE_CONFIG_PATH env var, falls back to /etc/wade/config.yaml
        then ./wade_config.yaml.
        
        Returns:
            ModuleConfig instance (may be empty if no config found)
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
        """Get entire config section for a tool.
        
        Args:
            tool: Tool name (e.g., "volatility", "dissect")
        
        Returns:
            Config dict for tool (empty if not found)
        """
        return self._config.get(tool, {})
    
    def get_modules(
        self,
        tool: str,
        key: str = "modules",
        default: Optional[List[str]] = None,
        env_var: Optional[str] = None,
    ) -> List[str]:
        """Get module list for a tool with env override support.
        
        Priority:
          1. Environment variable (if env_var specified)
          2. YAML config[tool][key]
          3. default parameter
        
        Supports add/remove syntax in env vars:
          "+module1,+module2,-module3" adds module1, module2 and removes module3
        
        Args:
            tool: Tool name (e.g., "volatility")
            key: Config key to look up (default: "modules")
            default: Default module list if not configured
            env_var: Environment variable name (default: WADE_<TOOL>_<KEY>)
        
        Returns:
            List of module names
        
        Example:
            # YAML: volatility.modules: [windows.pslist, windows.netscan]
            # ENV: WADE_VOLATILITY_MODULES="+windows.cmdline,-windows.netscan"
            # Result: [windows.pslist, windows.cmdline]
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
        """Apply environment variable override with add/remove syntax.
        
        Syntax:
          - "module1,module2,module3" - replace entire list
          - "+module1,+module2" - add modules to list
          - "-module1,-module2" - remove modules from list
          - "+module1,-module2,module3" - mixed: add module1, remove module2, add module3
        
        Args:
            base: Base module list
            env_value: Comma-separated env value
        
        Returns:
            Modified module list
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
    """Force reload of global configuration.
    
    Useful for testing or when config file changes at runtime.
    
    Returns:
        Newly loaded ModuleConfig instance
    """
    global _global_config
    _global_config = ModuleConfig.from_env()
    return _global_config
