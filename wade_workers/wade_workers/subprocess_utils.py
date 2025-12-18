"""
Unified subprocess execution with consistent error handling and logging.

This module provides a standardized interface for running external tools,
making it easy to add new tools without reimplementing command execution logic.
"""
from __future__ import annotations

import logging
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Protocol

logger = logging.getLogger(__name__)


@dataclass
class CommandResult:
    """Result of a command execution.
    
    Attributes:
        cmd: Command that was executed
        rc: Return code
        stdout: Standard output (truncated if > 4000 chars)
        stderr: Standard error (truncated if > 4000 chars)
        duration_sec: Execution time in seconds
        timed_out: Whether the command timed out
    """
    cmd: List[str]
    rc: int
    stdout: str
    stderr: str
    duration_sec: float
    timed_out: bool = False
    
    @property
    def success(self) -> bool:
        """True if command succeeded (rc=0 and didn't timeout)."""
        return self.rc == 0 and not self.timed_out
    
    def truncated_stderr(self, max_chars: int = 200) -> str:
        """Return truncated stderr for safe logging."""
        if len(self.stderr) <= max_chars:
            return self.stderr
        return self.stderr[:max_chars] + f"... ({len(self.stderr)} total chars)"


class ToolDiscovery(Protocol):
    """Protocol for tool discovery strategies.
    
    Implement this protocol to add custom tool discovery logic
    (e.g., checking virtual environments, conda, modules).
    """
    def find_tool(self, tool_name: str) -> Optional[Path]:
        """Return path to tool if found, None otherwise."""
        ...


class SystemPathDiscovery:
    """Find tools on system PATH."""
    
    def find_tool(self, tool_name: str) -> Optional[Path]:
        """Search for tool in PATH."""
        try:
            result = subprocess.run(
                ["which", tool_name],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return Path(result.stdout.strip())
        except (subprocess.SubprocessError, OSError):
            pass
        return None


class EnvVarDiscovery:
    """Find tools using environment variable overrides.
    
    Example: WADE_VOLATILITY_PATH=/opt/vol3/vol.py
    """
    
    def __init__(self, env_prefix: str = "WADE_"):
        self.env_prefix = env_prefix
    
    def find_tool(self, tool_name: str) -> Optional[Path]:
        """Check for WADE_<TOOL>_PATH environment variable."""
        import os
        env_var = f"{self.env_prefix}{tool_name.upper()}_PATH"
        tool_path = os.environ.get(env_var)
        if tool_path:
            path = Path(tool_path)
            if path.exists() and path.is_file():
                return path
        return None


class ToolRegistry:
    """Registry for discovering and caching tool locations.
    
    Example usage:
        registry = ToolRegistry()
        registry.add_discovery(EnvVarDiscovery())
        registry.add_discovery(SystemPathDiscovery())
        
        vol_path = registry.find_tool("volatility3")
        if not vol_path:
            raise ToolNotFoundError("volatility3")
    """
    
    def __init__(self):
        self._discoveries: List[ToolDiscovery] = []
        self._cache: Dict[str, Optional[Path]] = {}
    
    def add_discovery(self, discovery: ToolDiscovery) -> None:
        """Add a discovery strategy (checked in order added)."""
        self._discoveries.append(discovery)
    
    def find_tool(self, tool_name: str) -> Optional[Path]:
        """Find tool using registered discovery strategies.
        
        Results are cached to avoid repeated searches.
        """
        if tool_name in self._cache:
            return self._cache[tool_name]
        
        for discovery in self._discoveries:
            path = discovery.find_tool(tool_name)
            if path:
                logger.debug(f"Found {tool_name} at {path} using {discovery.__class__.__name__}")
                self._cache[tool_name] = path
                return path
        
        logger.warning(f"Tool not found: {tool_name}")
        self._cache[tool_name] = None
        return None
    
    def require_tool(self, tool_name: str) -> Path:
        """Find tool or raise ToolNotFoundError."""
        path = self.find_tool(tool_name)
        if not path:
            raise ToolNotFoundError(f"Required tool not found: {tool_name}")
        return path
    
    def clear_cache(self) -> None:
        """Clear the tool location cache."""
        self._cache.clear()


# Global default registry
_default_registry = ToolRegistry()
_default_registry.add_discovery(EnvVarDiscovery())
_default_registry.add_discovery(SystemPathDiscovery())


def get_default_registry() -> ToolRegistry:
    """Get the global default tool registry."""
    return _default_registry


class ToolNotFoundError(Exception):
    """Raised when a required tool cannot be found."""
    pass


class CommandExecutionError(Exception):
    """Raised when a command fails and check=True."""
    
    def __init__(self, result: CommandResult):
        self.result = result
        super().__init__(
            f"Command failed with rc={result.rc}: {' '.join(result.cmd)}\n"
            f"stderr: {result.truncated_stderr()}"
        )


def safe_run(
    cmd: List[str],
    timeout: int = 60,
    check: bool = False,
    log_output: bool = True,
    env: Optional[Dict[str, str]] = None,
    cwd: Optional[Path] = None,
    max_output_chars: int = 4000,
) -> CommandResult:
    """Run command with consistent error handling and logging.
    
    Args:
        cmd: Command and arguments to execute
        timeout: Timeout in seconds (default: 60)
        check: Raise CommandExecutionError if rc != 0
        log_output: Log command execution (default: True)
        env: Environment variables (merged with os.environ)
        cwd: Working directory
        max_output_chars: Truncate stdout/stderr to this length
    
    Returns:
        CommandResult with execution details
    
    Raises:
        CommandExecutionError: If check=True and command fails
        subprocess.TimeoutExpired: If command times out
    
    Example:
        result = safe_run(["volatility3", "-f", "mem.raw", "windows.pslist"])
        if result.success:
            parse_volatility_output(result.stdout)
    """
    start = time.time()
    timed_out = False
    
    if log_output:
        logger.info(f"Executing: {' '.join(cmd)} (timeout={timeout}s)")
    
    # Merge environment
    merged_env = None
    if env:
        import os
        merged_env = {**os.environ, **env}
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=merged_env,
            cwd=cwd,
        )
        rc = result.returncode
        stdout = result.stdout[:max_output_chars] if result.stdout else ""
        stderr = result.stderr[:max_output_chars] if result.stderr else ""
        
    except subprocess.TimeoutExpired as e:
        timed_out = True
        rc = -1
        stdout = e.stdout.decode()[:max_output_chars] if e.stdout else ""
        stderr = e.stderr.decode()[:max_output_chars] if e.stderr else ""
        logger.warning(f"Command timed out after {timeout}s: {' '.join(cmd)}")
    
    duration = time.time() - start
    
    cmd_result = CommandResult(
        cmd=cmd,
        rc=rc,
        stdout=stdout,
        stderr=stderr,
        duration_sec=round(duration, 2),
        timed_out=timed_out,
    )
    
    if log_output:
        logger.info(f"Command completed: rc={rc}, duration={duration:.2f}s")
        if stderr and rc != 0:
            logger.warning(f"Command stderr: {cmd_result.truncated_stderr()}")
    
    if check and not cmd_result.success:
        raise CommandExecutionError(cmd_result)
    
    return cmd_result


def run_tool(
    tool_name: str,
    args: List[str],
    registry: Optional[ToolRegistry] = None,
    **run_kwargs,
) -> CommandResult:
    """Run a tool by name, automatically discovering its path.
    
    Args:
        tool_name: Name of tool to run (e.g., "volatility3")
        args: Arguments to pass to the tool
        registry: ToolRegistry to use (default: global registry)
        **run_kwargs: Additional arguments passed to safe_run()
    
    Returns:
        CommandResult
    
    Raises:
        ToolNotFoundError: If tool cannot be found
    
    Example:
        result = run_tool("volatility3", ["-f", "mem.raw", "windows.pslist"])
    """
    if registry is None:
        registry = get_default_registry()
    
    tool_path = registry.require_tool(tool_name)
    cmd = [str(tool_path)] + args
    return safe_run(cmd, **run_kwargs)
