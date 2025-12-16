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
        """
        Indicates whether the command completed successfully.
        
        Returns:
            `true` if the return code is 0 and the command did not time out, `false` otherwise.
        """
        return self.rc == 0 and not self.timed_out
    
    def truncated_stderr(self, max_chars: int = 200) -> str:
        """
        Return a safely truncated version of the stored stderr suitable for logs.
        
        Truncates stderr to at most `max_chars` characters and appends an indicator with the total original character count when truncation occurs.
        
        Parameters:
            max_chars (int): Maximum number of characters to keep from stderr before truncation.
        
        Returns:
            str: The original stderr if its length is less than or equal to `max_chars`, otherwise a truncated stderr followed by "... (<total> total chars)".
        """
        if len(self.stderr) <= max_chars:
            return self.stderr
        return self.stderr[:max_chars] + f"... ({len(self.stderr)} total chars)"


class ToolDiscovery(Protocol):
    """Protocol for tool discovery strategies.
    
    Implement this protocol to add custom tool discovery logic
    (e.g., checking virtual environments, conda, modules).
    """
    def find_tool(self, tool_name: str) -> Optional[Path]:
        """
        Find the filesystem path for a named tool using the registry's configured discovery strategies.
        
        Parameters:
            tool_name (str): Tool name to locate.
        
        Returns:
            Optional[Path]: Path to the tool if found (first match of configured discoveries); `None` if no discovery locates the tool. The result is cached for subsequent lookups.
        """
        ...


class SystemPathDiscovery:
    """Find tools on system PATH."""
    
    def find_tool(self, tool_name: str) -> Optional[Path]:
        """
        Locate an executable on the system PATH by name.
        
        Parameters:
            tool_name (str): The executable name to look up.
        
        Returns:
            Optional[Path]: Path to the executable if found, `None` otherwise.
        """
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
        """
        Initialize the EnvVarDiscovery with a prefix for environment variable overrides.
        
        Parameters:
            env_prefix (str): Prefix used to build environment variable names for tool overrides.
                For a tool named "foo", the discovery will look for an environment variable
                formed by uppercasing the tool name and surrounding it with this prefix and
                the suffix "_PATH" (for example, "WADE_FOO_PATH" when using the default prefix).
        """
        self.env_prefix = env_prefix
    
    def find_tool(self, tool_name: str) -> Optional[Path]:
        """
        Resolve a tool path from an environment-variable override.
        
        Checks the environment variable formed as `"<env_prefix><TOOL>_PATH"` (where `<TOOL>` is the uppercased tool_name) and returns its Path if it exists and is a file.
        
        Parameters:
            tool_name (str): Canonical name of the tool to look up.
        
        Returns:
            Optional[Path]: Path to the tool if the environment variable points to an existing file, `None` otherwise.
        """
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
        """
        Create an empty ToolRegistry.
        
        Initializes the ordered list of discovery strategies (applied in registration order) and an empty cache that maps tool names to a resolved Path or None to avoid repeated discovery work.
        """
        self._discoveries: List[ToolDiscovery] = []
        self._cache: Dict[str, Optional[Path]] = {}
    
    def add_discovery(self, discovery: ToolDiscovery) -> None:
        """Add a discovery strategy (checked in order added)."""
        self._discoveries.append(discovery)
    
    def find_tool(self, tool_name: str) -> Optional[Path]:
        """
        Locate a tool by querying registered discovery strategies in order and cache the result.
        
        Searches each registered discovery in sequence until one returns a path; the resolved path (or None if not found) is stored in the registry cache to avoid repeated lookups.
        
        Returns:
            Optional[Path]: Path to the tool if found, None otherwise.
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
        """
        Resolve a tool name to its filesystem path or raise an error if it cannot be located.
        
        Returns:
            Path: Filesystem path to the discovered tool executable.
        
        Raises:
            ToolNotFoundError: If no discovery strategy can locate the tool.
        """
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
        """
        Initialize the exception with the failing command's result and build its error message.
        
        Parameters:
            result (CommandResult): The command execution outcome that caused the exception. Stored on the exception as the `result` attribute. The exception message includes the return code, the joined command, and a truncated version of the command's stderr.
        """
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
    """
    Execute a subprocess command with standardized logging, output truncation, and failure handling.
    
    Parameters:
        cmd (List[str]): Command and arguments to execute.
        timeout (int): Maximum execution time in seconds (default 60).
        check (bool): If True, raise CommandExecutionError when the command exits non‑zero.
        log_output (bool): If True, log start, completion, and error summaries.
        env (Optional[Dict[str, str]]): Environment overrides merged on top of the current environment.
        cwd (Optional[Path]): Working directory for the command.
        max_output_chars (int): Maximum number of characters to keep from stdout/stderr.
    
    Returns:
        CommandResult: Execution details including return code, truncated stdout/stderr, duration, and timeout flag.
    
    Raises:
        CommandExecutionError: When `check` is True and the command did not succeed.
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
    """
    Run a named tool by resolving its filesystem path and executing it with the provided arguments.
    
    Parameters:
        tool_name (str): Name of the tool to locate and run (e.g., "volatility3").
        args (List[str]): Argument list to pass to the tool executable.
        registry (Optional[ToolRegistry]): Registry used to resolve the tool path; uses the module's default registry when None.
        **run_kwargs: Additional keyword arguments forwarded to safe_run (e.g., timeout, check, env, cwd).
    
    Returns:
        CommandResult: Execution result including return code, stdout/stderr, duration, and timeout flag.
    
    Raises:
        ToolNotFoundError: If the tool cannot be located by the registry.
    """
    if registry is None:
        registry = get_default_registry()
    
    tool_path = registry.require_tool(tool_name)
    cmd = [str(tool_path)] + args
    return safe_run(cmd, **run_kwargs)