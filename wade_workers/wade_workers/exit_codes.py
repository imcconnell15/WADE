"""
WADE Exit Codes

Standard exit codes for CLI and worker processes.
"""
from enum import IntEnum
from typing import Type


class ExitCode(IntEnum):
    """Standard exit codes for WADE processes."""
    
    # Success
    SUCCESS = 0
    
    # General errors
    GENERAL_ERROR = 1
    
    # Configuration errors
    CONFIG_ERROR = 2
    TOOL_NOT_FOUND = 3
    
    # Input errors
    INVALID_TICKET = 10
    FILE_NOT_FOUND = 11
    FILE_ACCESS_ERROR = 12
    
    # Execution errors
    TOOL_EXECUTION_ERROR = 20
    TOOL_TIMEOUT = 21
    PARSE_ERROR = 22
    WORKER_ERROR = 23
    
    # System errors
    PERMISSION_DENIED = 30
    RESOURCE_UNAVAILABLE = 31


def get_exit_code(exception: Exception) -> ExitCode:
    """Map exception to appropriate exit code.
    
    Args:
        exception: Exception that was raised
    
    Returns:
        ExitCode enum value
    
    Example:
        try:
            worker.run(ticket)
        except Exception as e:
            sys.exit(get_exit_code(e))
    """
    from .exceptions import (
        WadeException,
        ToolNotFoundError,
        ToolExecutionError,
        ToolTimeoutError,
        ParseError,
        TicketValidationError,
        FileAccessError,
        ConfigurationError,
        WorkerExecutionError,
    )
    
    # Map specific exceptions
    exception_map = {
        ToolNotFoundError: ExitCode.TOOL_NOT_FOUND,
        ConfigurationError: ExitCode.CONFIG_ERROR,
        TicketValidationError: ExitCode.INVALID_TICKET,
        FileAccessError: ExitCode.FILE_ACCESS_ERROR,
        ToolExecutionError: ExitCode.TOOL_EXECUTION_ERROR,
        ToolTimeoutError: ExitCode.TOOL_TIMEOUT,
        ParseError: ExitCode.PARSE_ERROR,
        WorkerExecutionError: ExitCode.WORKER_ERROR,
    }
    
    # Check exception type
    for exc_type, exit_code in exception_map.items():
        if isinstance(exception, exc_type):
            return exit_code
    
    # Permission errors
    if isinstance(exception, PermissionError):
        return ExitCode.PERMISSION_DENIED
    
    # File not found errors
    if isinstance(exception, FileNotFoundError):
        return ExitCode.FILE_NOT_FOUND
    
    # Default to general error
    return ExitCode.GENERAL_ERROR


def exit_code_name(code: int) -> str:
    """Get human-readable name for exit code.
    
    Args:
        code: Exit code value
    
    Returns:
        Name of exit code (e.g., "SUCCESS", "TOOL_NOT_FOUND")
    
    Example:
        >>> exit_code_name(0)
        'SUCCESS'
        >>> exit_code_name(3)
        'TOOL_NOT_FOUND'
    """
    try:
        return ExitCode(code).name
    except ValueError:
        return f"UNKNOWN_({code})"
