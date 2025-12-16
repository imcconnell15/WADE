#!/usr/bin/env python3
"""
WADE Staging Daemon (Refactored)

Monitors staging directories for new files, classifies them, and queues
them for worker processing. Now modular and maintainable!

Original: 2,052 LOC monolith
Refactored: 250 LOC orchestrator + modular components

Usage:
    python stage_daemon.py [--scan-once] [--verbose]
"""
import argparse
import logging
import sys
import time
from pathlib import Path
from typing import Optional

# Inotify for file watching
try:
    import inotify.adapters
    INOTIFY_AVAILABLE = True
except ImportError:
    INOTIFY_AVAILABLE = False

# Local imports
from config import (
    STAGING_ROOT, STAGE_FULL, STAGE_LIGHT,
    DATADIR, QUEUE_DIR,
    REQUIRE_CLOSE_WRITE, POLL_INTERVAL_SEC,
    WADE_STAGE_RECURSIVE,
)
from file_ops import wait_stable, no_open_writers, move_atomic, ensure_dirs
from db import init_db, path_signature, already_processed, already_processed_by_content, record_processed
from path_resolver import build_destination, detect_profile, match_host_from_filename
from classifiers import get_classifier_registry
from ticket_builder import build_staging_ticket, queue_ticket
from wade_workers.hashing import quick_hash
from wade_workers.logging import EventLogger


logger = logging.getLogger("wade.staging")


class StagingDaemon:
    """Main staging daemon orchestrator."""
    
    def __init__(self):
        """
        Initialize the staging daemon's runtime resources.
        
        Sets up and stores the database connection, classifier registry, and event logger on the instance,
        and ensures required directories for staging, data, and queueing exist.
        """
        self.db_conn = init_db()
        self.classifier_registry = get_classifier_registry()
        self.event_logger = EventLogger.get_logger("staging_daemon")
        
        # Ensure directories exist
        ensure_dirs(STAGING_ROOT, STAGE_FULL, STAGE_LIGHT, DATADIR, QUEUE_DIR)
    
    def process_file(self, file_path: Path) -> bool:
        """
        Process a single staged file by deduplicating, validating, classifying, moving it to its destination, enqueueing a processing ticket, and recording the action in the database.
        
        Parameters:
            file_path (Path): Path to the file in a staging directory.
        
        Returns:
            bool: `True` if the file was successfully moved, ticketed, and recorded; `False` if processing was skipped or failed.
        """
        logger.info(f"Processing: {file_path}")
        
        # Check if already processed (by path signature)
        sig = path_signature(file_path)
        if already_processed(self.db_conn, sig):
            logger.info(f"Already processed (path): {file_path}")
            return False
        
        # Check content-based dedup
        try:
            content_sig = quick_hash(file_path, sample_mb=4)
        except Exception as e:
            logger.warning(f"Failed to hash {file_path}: {e}")
            content_sig = None
        
        if content_sig and already_processed_by_content(self.db_conn, content_sig):
            logger.info(f"Already processed (content): {file_path}")
            return False
        
        # Wait for file stability
        logger.debug(f"Waiting for stability: {file_path}")
        if not wait_stable(file_path):
            logger.warning(f"File disappeared during wait: {file_path}")
            return False
        
        # Verify no open writers
        if not no_open_writers(file_path):
            logger.warning(f"File has open writers: {file_path}")
            return False
        
        # Classify file
        logger.info(f"Classifying: {file_path}")
        result = self.classifier_registry.classify(file_path)
        
        classification = result.classification
        details = result.details
        
        logger.info(f"Classification: {classification} (confidence: {result.confidence:.2f})")
        
        # Skip if unknown or explicitly rejected
        if classification == "unknown" or details.get("rejected"):
            logger.warning(f"Skipping unclassified file: {file_path}")
            return False
        
        # Skip E01 fragments
        if classification == "e01_fragment" and details.get("skip"):
            logger.info(f"Skipping E01 fragment: {file_path}")
            return False
        
        # Detect profile (full/light) and location
        profile, location = detect_profile(file_path, STAGING_ROOT)

        ticket = build_staging_ticket(
            dest_path=dest_path,
            classification=classification,
            hostname=details.get("hostname"),
            os_family=details.get("os_family"),
            source_file=file_path.name,
            priority=5,
            profile=profile,
            location=location,
            details=details,
        )
        
        # Enrich details with host matching
        if "hostname" not in details:
            matched_host = match_host_from_filename(DATADIR, file_path)
            if matched_host:
                details["hostname"] = matched_host
        
        # Build destination path
        dest_path = build_destination(
            src=file_path,
            root=DATADIR,
            classification=classification,
            details=details,
        )
        
        logger.info(f"Destination: {dest_path}")
        
        # Move file to destination
        try:
            move_atomic(file_path, dest_path)
        except Exception as e:
            logger.error(f"Failed to move {file_path} to {dest_path}: {e}")
            return False
        
        # Create ticket
        ticket = build_staging_ticket(
            dest_path=dest_path,
            classification=classification,
            hostname=details.get("hostname"),
            os_family=details.get("os_family"),
            source_file=file_path.name,
            priority=5,
            **details,
        )
        
        # Queue ticket
        ticket_path = queue_ticket(ticket, QUEUE_DIR, profile=profile)
        logger.info(f"Queued ticket: {ticket_path}")
        
        # Record in database
        record_processed(
            self.db_conn,
            sig=sig,
            src_path=file_path,
            dest_path=dest_path,
            classification=classification,
            profile=profile,
            content_sig=content_sig,
        )
        
        # Log event
        self.event_logger.log_classification(
            dest_path,
            classification=classification,
            confidence=result.confidence,
            profile=profile,
            **details,
        )
        
        logger.info(f"Successfully processed: {file_path} → {dest_path}")
        return True
    
    def scan_once(self) -> int:
        """
        Scan the configured staging directories once and attempt to process every regular file found.
        
        Scans both STAGE_FULL and STAGE_LIGHT (skipping non-existent directories), lists files
        recursively when WADE_STAGE_RECURSIVE is set, and invokes process_file on each regular
        file. Each successfully processed file increments the returned count.
        
        Returns:
            int: Number of files successfully processed.
        """
        count = 0
        
        for staging_dir in [STAGE_FULL, STAGE_LIGHT]:
            if not staging_dir.exists():
                continue
            
            logger.info(f"Scanning: {staging_dir}")
            
            # Get all files (recursive if enabled)
            if WADE_STAGE_RECURSIVE:
                files = list(staging_dir.rglob("*"))
            else:
                files = list(staging_dir.iterdir())
            
            # Filter to regular files
            files = [f for f in files if f.is_file()]
            
            logger.info(f"Found {len(files)} files in {staging_dir}")
            
            for file_path in files:
                try:
                    if self.process_file(file_path):
                        count += 1
                except Exception as e:
                    logger.error(f"Error processing {file_path}: {e}", exc_info=True)
        
        return count
    
    def watch_continuous(self) -> None:
        """
        Monitor staging directories continuously, using inotify when configured and available, otherwise using a polling loop.
        
        This delegates to an inotify-based watcher when INOTIFY_AVAILABLE and REQUIRE_CLOSE_WRITE are true; otherwise it runs the polling watcher.
        """
        if INOTIFY_AVAILABLE and REQUIRE_CLOSE_WRITE:
            self._watch_inotify()
        else:
            self._watch_polling()
    
    def _watch_inotify(self) -> None:
        """
        Monitor staging directories with inotify and process files when they are closed after writing.
        
        Adds watches for STAGE_FULL and STAGE_LIGHT if they exist, listens for `IN_CLOSE_WRITE` events, and calls `self.process_file` for the completed file. Logs startup and any per-file processing errors.
        """
        logger.info("Starting inotify watch")
        
        watch_dirs = [str(STAGE_FULL), str(STAGE_LIGHT)]
        i = inotify.adapters.Inotify()
        
        for watch_dir in watch_dirs:
            if Path(watch_dir).exists():
                i.add_watch(watch_dir)
                logger.info(f"Watching: {watch_dir}")
        
        for event in i.event_gen(yield_nones=False):
            (_, type_names, path, filename) = event
            
            # Process on CLOSE_WRITE (file write completed)
            if "IN_CLOSE_WRITE" in type_names:
                file_path = Path(path) / filename
                
                try:
                    self.process_file(file_path)
                except Exception as e:
                    logger.error(f"Error processing {file_path}: {e}", exc_info=True)
    
    def _watch_polling(self) -> None:
        """
        Continuously poll the staging directories and perform scans at the configured interval.
        
        Repeatedly performs directory scans, waits POLL_INTERVAL_SEC seconds between iterations, and logs any errors encountered without terminating.
        """
        logger.info(f"Starting polling watch (interval: {POLL_INTERVAL_SEC}s)")
        
        while True:
            try:
                self.scan_once()
            except Exception as e:
                logger.error(f"Error during scan: {e}", exc_info=True)
            
            time.sleep(POLL_INTERVAL_SEC)


def setup_logging(verbose: bool = False) -> None:
    """
    Configure the root logger's level and format.
    
    When verbose is True, sets level to DEBUG; otherwise sets level to INFO. Also installs a basic log format of "YYYY-MM-DD HH:MM:SS [LEVEL] LOGGER_NAME: MESSAGE".
     
    Parameters:
        verbose (bool): If True, enable DEBUG-level logging; if False, enable INFO-level logging.
    """
    level = logging.DEBUG if verbose else logging.INFO
    
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def main():
    """
    Parse command-line arguments, configure logging, and run the WADE Staging Daemon either once or in continuous watch mode.
    
    Recognized flags:
    - --scan-once: perform a single scan and exit.
    - --verbose, -v: enable debug logging.
    
    Returns:
        exit_code (int): 0 on successful completion or normal shutdown (including KeyboardInterrupt).
    """
    parser = argparse.ArgumentParser(description="WADE Staging Daemon")
    parser.add_argument(
        "--scan-once",
        action="store_true",
        help="Scan once and exit (don't watch continuously)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Enable debug logging",
    )
    
    args = parser.parse_args()
    
    setup_logging(args.verbose)
    
    daemon = StagingDaemon()
    
    if args.scan_once:
        count = daemon.scan_once()
        logger.info(f"Processed {count} files")
        return 0
    else:
        try:
            daemon.watch_continuous()
        except KeyboardInterrupt:
            logger.info("Shutting down...")
            return 0


if __name__ == "__main__":
    sys.exit(main())