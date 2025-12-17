"""
WADE Exception Hierarchy

Structured exceptions for error handling and reporting.
"""
from typing import Optional, Dict, Any


class WadeException(Exception):
    """Base exception for all WADE errors.
    
    Provides structured error information with details and suggestions.
    """
    
    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        suggestion: Optional[str] = None,
    ):
        """Initialize exception.
        
        Args:
            message: Human-readable error message
            details: Additional context (e.g., {"path": "/foo/bar"})
            suggestion: Suggestion for fixing the issue
        """
        super().__init__(message)
        self.message = message
        self.details = details or {}
        self.suggestion = suggestion
    
    def __str__(self) -> str:
        """Format error message with details and suggestion."""
        parts = [self.message]
        
        if self.details:
            details_str = ", ".join(f"{k}={v}" for k, v in self.details.items())
            parts.append(f"Details: {details_str}")
        
        if self.suggestion:
            parts.append(f"Suggestion: {self.suggestion}")
        
        return " | ".join(parts)


class ToolNotFoundError(WadeException):
    """Raised when a required tool cannot be found."""
    
    def __init__(
        self,
        message: str,
        tool: Optional[str] = None,
        suggestion: Optional[str] = None,
    ):
        """Initialize tool not found error.
        
        Args:
            message: Error message
            tool: Tool name that was not found
            suggestion: How to fix (e.g., "Install volatility3")
        """
        details = {"tool": tool} if tool else {}
        if not suggestion and tool:
            suggestion = f"Install {tool} or set WADE_{tool.upper()}_PATH"
        super().__init__(message, details=details, suggestion=suggestion)
        self.tool = tool


class ToolExecutionError(WadeException):
    """Raised when a tool execution fails."""
    
    def __init__(
        self,
        message: str,
        tool: Optional[str] = None,
        returncode: Optional[int] = None,
        stderr: Optional[str] = None,
        suggestion: Optional[str] = None,
    ):
        """Initialize tool execution error.
        
        Args:
            message: Error message
            tool: Tool name
            returncode: Exit code
            stderr: Error output
            suggestion: How to fix
        """
        details = {}
        if tool:
            details["tool"] = tool
        if returncode is not None:
            details["returncode"] = returncode
        if stderr:
            details["stderr"] = stderr[:200]  # Truncate
        
        super().__init__(message, details=details, suggestion=suggestion)
        self.tool = tool
        self.returncode = returncode
        self.stderr = stderr


class ToolTimeoutError(WadeException):
    """Raised when a tool execution times out."""
    
    def __init__(
        self,
        message: str,
        tool: Optional[str] = None,
        timeout_sec: Optional[int] = None,
        suggestion: Optional[str] = None,
    ):
        """Initialize timeout error.
        
        Args:
            message: Error message
            tool: Tool name
            timeout_sec: Timeout value in seconds
            suggestion: How to fix
        """
        details = {}
        if tool:
            details["tool"] = tool
        if timeout_sec:
            details["timeout_sec"] = timeout_sec
        
        if not suggestion:
            suggestion = "Increase timeout or check if tool is hung"
        
        super().__init__(message, details=details, suggestion=suggestion)
        self.tool = tool
        self.timeout_sec = timeout_sec


class ParseError(WadeException):
    """Raised when output parsing fails."""
    
    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        suggestion: Optional[str] = None,
    ):
        """Initialize parse error.
        
        Args:
            message: Error message
            details: Context (e.g., {"module": "windows.pslist"})
            suggestion: How to fix
        """
        if not suggestion:
            suggestion = "Check tool output format or version"
        super().__init__(message, details=details, suggestion=suggestion)


class TicketValidationError(WadeException):
    """Raised when ticket validation fails."""
    
    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        suggestion: Optional[str] = None,
    ):
        """Initialize ticket validation error.
        
        Args:
            message: Error message
            details: Context
            suggestion: How to fix
        """
        if not suggestion:
            suggestion = "Check ticket schema and required fields"
        super().__init__(message, details=details, suggestion=suggestion)


class FileAccessError(WadeException):
    """Raised when file access fails."""
    
    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        suggestion: Optional[str] = None,
    ):
        """Initialize file access error.
        
        Args:
            message: Error message
            details: Context (e.g., {"path": "/foo/bar"})
            suggestion: How to fix
        """
        if not suggestion:
            suggestion = "Check file exists and permissions are correct"
        super().__init__(message, details=details, suggestion=suggestion)


class ConfigurationError(WadeException):
    """Raised when configuration is invalid."""
    
    def __init__(
        self,
        message: str,
        details: Optional[Dict[str, Any]] = None,
        suggestion: Optional[str] = None,
    ):
        """Initialize configuration error.
        
        Args:
            message: Error message
            details: Context
            suggestion: How to fix
        """
        if not suggestion:
            suggestion = "Check config.yaml and environment variables"
        super().__init__(message, details=details, suggestion=suggestion)


class WorkerExecutionError(WadeException):
    """Raised when worker execution fails."""
    
    def __init__(
        self,
        message: str,
        worker: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        suggestion: Optional[str] = None,
    ):
        """Initialize worker execution error.
        
        Args:
            message: Error message
            worker: Worker name
            details: Context
            suggestion: How to fix
        """
        if worker:
            details = details or {}
            details["worker"] = worker
        super().__init__(message, details=details, suggestion=suggestion)
        self.worker = worker
