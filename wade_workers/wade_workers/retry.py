"""
WADE Retry Logic

Provides configurable retry decorators with exponential backoff for tool execution.
"""
import time
import functools
from typing import Callable, Optional, Dict, Any
from dataclasses import dataclass


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""
    
    max_attempts: int = 3
    initial_delay: float = 1.0
    max_delay: float = 30.0
    exponential_base: float = 2.0
    retry_on: tuple = (Exception,)
    
    # Tool-specific defaults
    _TOOL_DEFAULTS: Dict[str, Dict[str, Any]] = {
        "volatility": {
            "max_attempts": 2,
            "initial_delay": 2.0,
            "max_delay": 10.0,
        },
        "hayabusa": {
            "max_attempts": 2,
            "initial_delay": 1.0,
        },
        "dissect": {
            "max_attempts": 2,
            "initial_delay": 1.0,
        },
        "yara": {
            "max_attempts": 3,
            "initial_delay": 0.5,
            "max_delay": 5.0,
        },
        "bulk_extractor": {
            "max_attempts": 2,
            "initial_delay": 2.0,
        },
        "plaso": {
            "max_attempts": 1,  # Plaso is slow; don't retry
            "initial_delay": 0.0,
        },
    }
    
    @classmethod
    def for_tool(cls, tool_name: str) -> "RetryConfig":
        """Get retry config for a specific tool.
        
        Args:
            tool_name: Tool name (e.g., "volatility")
        
        Returns:
            RetryConfig with tool-specific or default settings
        """
        defaults = cls._TOOL_DEFAULTS.get(tool_name, {})
        return cls(**defaults)
    
    @classmethod
    def get_retry_decorator(cls, tool_name: str) -> Callable:
        """Get a retry decorator configured for a specific tool.
        
        Args:
            tool_name: Tool name
        
        Returns:
            Decorator function
        
        Example:
            retry = RetryConfig.get_retry_decorator("volatility")
            
            @retry
            def execute_module():
                return run_tool("volatility3", args)
        """
        config = cls.for_tool(tool_name)
        return config.create_decorator()
    
    def create_decorator(self) -> Callable:
        """Create a retry decorator from this config.
        
        Returns:
            Decorator function
        """
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            def wrapper(*args, **kwargs):
                last_exception = None
                delay = self.initial_delay
                
                for attempt in range(1, self.max_attempts + 1):
                    try:
                        return func(*args, **kwargs)
                    except self.retry_on as e:
                        last_exception = e
                        
                        # Don't retry on last attempt
                        if attempt >= self.max_attempts:
                            break
                        
                        # Don't retry on certain errors
                        if self._should_not_retry(e):
                            break
                        
                        # Wait before retry
                        if delay > 0:
                            time.sleep(delay)
                        
                        # Exponential backoff
                        delay = min(delay * self.exponential_base, self.max_delay)
                
                # All retries exhausted
                if last_exception:
                    raise last_exception
            
            return wrapper
        return decorator
    
    def _should_not_retry(self, exception: Exception) -> bool:
        """Determine if an exception should not be retried.
        
        Args:
            exception: Exception that was raised
        
        Returns:
            True if we should not retry
        """
        # Import here to avoid circular dependency
        from .exceptions import (
            ToolNotFoundError,
            TicketValidationError,
            FileAccessError,
            ConfigurationError,
        )
        
        # Don't retry config/validation errors
        if isinstance(exception, (
            ToolNotFoundError,
            TicketValidationError,
            FileAccessError,
            ConfigurationError,
        )):
            return True
        
        # Don't retry if error message indicates permanent failure
        error_msg = str(exception).lower()
        permanent_indicators = [
            "not found",
            "permission denied",
            "invalid",
            "unsupported",
            "no such file",
        ]
        
        return any(indicator in error_msg for indicator in permanent_indicators)


def retry_on_timeout(
    max_attempts: int = 3,
    initial_delay: float = 2.0,
    max_delay: float = 30.0,
) -> Callable:
    """Simple decorator for retrying on timeout errors.
    
    Args:
        max_attempts: Maximum number of attempts
        initial_delay: Initial delay in seconds
        max_delay: Maximum delay in seconds
    
    Returns:
        Decorator function
    
    Example:
        @retry_on_timeout(max_attempts=3)
        def slow_operation():
            return run_tool("tool", args, timeout=60)
    """
    from .exceptions import ToolTimeoutError
    
    config = RetryConfig(
        max_attempts=max_attempts,
        initial_delay=initial_delay,
        max_delay=max_delay,
        retry_on=(ToolTimeoutError,),
    )
    return config.create_decorator()
