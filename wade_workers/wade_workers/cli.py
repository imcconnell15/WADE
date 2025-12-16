"""
WADE Workers CLI (Updated with error handling)

Handles command-line execution with proper exception handling and exit codes.
"""
import argparse
import json
import logging
import sys
from pathlib import Path
from typing import Optional

from .base import BaseWorker
from .exceptions import (
    WadeException,
    ToolNotFoundError,
    TicketValidationError,
    ConfigurationError,
    WorkerExecutionError,
    get_exit_code,
)
from .exit_codes import ExitCode, exit_code_name
from .logging import EventLogger


logger = logging.getLogger("wade.cli")


def setup_logging(verbose: bool = False) -> None:
    """
    Configure the root logger used by the CLI and set a consistent message and timestamp format.
    
    Parameters:
        verbose (bool): If True, set the logging level to DEBUG; otherwise set it to INFO.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def load_ticket(ticket_path: Path) -> dict:
    """
    Load and parse a ticket JSON file from the given path.
    
    Parameters:
        ticket_path (Path): Path to the JSON ticket file.
    
    Returns:
        dict: Parsed ticket data.
    
    Raises:
        TicketValidationError: If the file does not exist or contains invalid JSON.
    """
    if not ticket_path.exists():
        raise TicketValidationError(
            f"Ticket file not found: {ticket_path}",
            suggestion="Check queue directory and ticket path"
        )
    
    try:
        ticket_data = json.loads(ticket_path.read_text())
    except json.JSONDecodeError as e:
        raise TicketValidationError(
            f"Invalid ticket JSON: {e}",
            details={"path": str(ticket_path)},
            suggestion="Check ticket file format"
        )
    
    return ticket_data


def run_worker(
    worker_class: type,
    ticket_path: Path,
    env: Optional[dict] = None,
) -> int:
    """
    Run the specified worker class using the ticket at ticket_path and return an exit code representing the outcome.
    
    The function loads and validates the ticket, instantiates the worker (passing `env` if provided), executes the worker, emits structured CLI events, and maps observed conditions to an integer exit code.
    
    Parameters:
        worker_class (type): Worker class to instantiate and run.
        ticket_path (Path): Filesystem path to the ticket JSON file.
        env (Optional[dict]): Optional environment mapping to pass to the worker constructor.
    
    Returns:
        int: Process exit code indicating the result:
            - ExitCode.SUCCESS: Worker produced records (returned even if there were per-record errors).
            - ExitCode.TOOL_NOT_FOUND: Required external tool was not found during worker initialization.
            - ExitCode.CONFIG_ERROR: Worker configuration was invalid during initialization.
            - ExitCode.VALIDATION_ERROR: Ticket validation failed while running the worker.
            - ExitCode.UNKNOWN_ERROR: An unexpected exception occurred.
            - For WADE-specific exceptions, the exit code returned by get_exit_code(e) (mapped from the exception).
            - KeyboardInterrupt is treated as non-error and returns ExitCode.SUCCESS.
    """
    event_logger = EventLogger.get_logger("cli")
    
    try:
        # Load ticket
        ticket = load_ticket(ticket_path)
        
        # Instantiate worker
        try:
            worker = worker_class(env=env)
        except ToolNotFoundError as e:
            logger.error(f"Tool not found: {e}")
            logger.error(f"Suggestion: {e.suggestion}")
            event_logger.log_event(
                "cli.worker_init_failed",
                status="error",
                worker=worker_class.__name__,
                error=str(e),
            )
            return ExitCode.TOOL_NOT_FOUND
        except ConfigurationError as e:
            logger.error(f"Configuration error: {e}")
            return ExitCode.CONFIG_ERROR
        
        # Run worker
        logger.info(f"Running {worker_class.__name__} with ticket {ticket_path.name}")
        
        try:
            result = worker.run(ticket)
        except TicketValidationError as e:
            logger.error(f"Ticket validation failed: {e}")
            if e.suggestion:
                logger.error(f"Suggestion: {e.suggestion}")
            event_logger.log_event(
                "cli.ticket_validation_failed",
                status="error",
                worker=worker_class.__name__,
                ticket_path=str(ticket_path),
                error=str(e),
            )
            return ExitCode.VALIDATION_ERROR
        
        # Check result
        if result.errors:
            logger.warning(f"Worker completed with {len(result.errors)} errors:")
            for error in result.errors:
                logger.warning(f"  - {error}")
        
        logger.info(f"Worker completed: {result.count} records, output: {result.path}")
        event_logger.log_event(
            "cli.worker_complete",
            status="success",
            worker=worker_class.__name__,
            records=result.count,
            errors=len(result.errors),
        )
        
        # Return success even with partial errors (records were produced)
        return ExitCode.SUCCESS
    
    except WadeException as e:
        # WADE-specific exceptions
        logger.error(f"{e.__class__.__name__}: {e}")
        if e.suggestion:
            logger.error(f"Suggestion: {e.suggestion}")
        
        event_logger.log_event(
            "cli.worker_failed",
            status="error",
            worker=worker_class.__name__ if worker_class else "unknown",
            error_type=e.__class__.__name__,
            error=str(e),
        )
        
        # Map exception to exit code
        exit_code = get_exit_code(e)
        logger.error(f"Exiting with code {exit_code} ({exit_code_name(exit_code)})")
        return exit_code
    
    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        event_logger.log_event("cli.interrupted", status="warning")
        return ExitCode.SUCCESS  # Not an error
    
    except Exception as e:
        # Unexpected exceptions
        logger.exception(f"Unexpected error: {e}")
        event_logger.log_event(
            "cli.unexpected_error",
            status="error",
            error_type=e.__class__.__name__,
            error=str(e),
        )
        return ExitCode.UNKNOWN_ERROR


def main():
    """
    CLI entry point for the WADE Workers command-line interface.
    
    Parses command-line arguments (worker name, ticket path, optional --verbose and --env-file), loads a simple key=value environment file when provided, validates and dynamically imports the selected worker class from the internal worker mapping, invokes the worker via run_worker, and exits the process with the resulting exit code.
    """
    parser = argparse.ArgumentParser(
        description="WADE Worker CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument(
        "worker",
        help="Worker name (e.g., volatility, dissect, yara)"
    )
    parser.add_argument(
        "ticket",
        type=Path,
        help="Path to ticket JSON file"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug logging"
    )
    parser.add_argument(
        "--env-file",
        type=Path,
        help="Path to environment file"
    )
    
    args = parser.parse_args()
    
    setup_logging(args.verbose)
    
    # Load environment
    env = {}
    if args.env_file and args.env_file.exists():
        # Simple key=value parser
        for line in args.env_file.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                env[key.strip()] = value.strip()
    
    # Import worker class
    worker_map = {
        "volatility": "VolatilityWorker",
        "dissect": "DissectWorker",
        "yara": "YaraWorker",
        "hayabusa": "HayabusaWorker",
        "bulkextractor": "BulkExtractorWorker",
    }
    
    if args.worker not in worker_map:
        logger.error(f"Unknown worker: {args.worker}")
        logger.error(f"Available workers: {', '.join(worker_map.keys())}")
        return ExitCode.CONFIG_ERROR
    
    try:
        # Dynamically import worker
        module_name = f"wade_workers.{args.worker}_worker"
        worker_class_name = worker_map[args.worker]
        
        module = __import__(module_name, fromlist=[worker_class_name])
        worker_class = getattr(module, worker_class_name)
    except ImportError as e:
        logger.error(f"Failed to import worker {args.worker}: {e}")
        return ExitCode.CONFIG_ERROR
    
    # Run worker
    exit_code = run_worker(worker_class, args.ticket, env)
    
    sys.exit(exit_code)


if __name__ == "__main__":
    main()