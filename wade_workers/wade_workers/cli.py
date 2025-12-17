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
)
from .exit_codes import ExitCode, exit_code_name
from .logging import EventLogger


logger = logging.getLogger("wade.cli")


def setup_logging(verbose: bool = False) -> None:
    """Configure logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def load_ticket(ticket_path: Path) -> dict:
    """Load ticket from JSON file.
    
    Args:
        ticket_path: Path to ticket file
    
    Returns:
        Ticket dictionary
    
    Raises:
        TicketValidationError: If ticket cannot be loaded
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
        ) from e
    
    return ticket_data


def run_worker(
    worker_class: type,
    ticket_path: Path,
    env: Optional[dict] = None,
) -> int:
    """Run a worker with a ticket.
    
    Args:
        worker_class: Worker class to instantiate
        ticket_path: Path to ticket file
        env: Optional environment dict
    
    Returns:
        Exit code
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
            if e.suggestion:
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
        return 130  # Standard Ctrl+C exit code (128 + SIGINT)
    
    except Exception as e:
        # Unexpected exceptions
        logger.exception("Unexpected error")
        event_logger.log_event(
            "cli.unexpected_error",
            status="error",
            error_type=e.__class__.__name__,
            error=str(e),
        )
        return ExitCode.GENERAL_ERROR


def main():
    """CLI entry point."""
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
                key = key.strip()
                if key:
                    env[key] = value.strip()
                else:
                    logger.warning(f"Skipping malformed env line: {line}")
    
    # Import worker class
    worker_map = {
        "volatility": "VolatilityWorker",
        "dissect": "DissectWorker",
        "plaso": "PlasoWorker",
        "yara": "YaraWorker",
        "hayabusa": "HayabusaWorker",
        "bulk_extractor": "BulkExtractorWorker",
        "autopsy": "AutopsyManifestWorker",
        "netcfg": "NetworkConfigWorker",
        "netdoc": "NetworkDocWorker",
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
