#!/usr/bin/env python3
"""
Validate WADE ticket integrity and metadata completeness.

Usage:
    python validate_tickets.py /path/to/queue [--verbose] [--json]
"""
import argparse
import json
import sys
from pathlib import Path
from typing import Dict, List

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from wade_workers.ticket_schema import WorkerTicket, validate_ticket
from wade_workers.utils import load_env


def validate_queue(queue_root: Path, verbose: bool = False) -> Dict[str, List]:
    """
    Validate all WADE ticket JSON files under the given queue root and categorize results.
    
    Iterates ticket files beneath `queue_root`, skipping backup/temp filenames, validates each ticket, and groups outcomes into valid entries, warnings, and errors.
    
    Parameters:
        queue_root (Path): Root directory containing the queue subdirectories with ticket JSON files.
        verbose (bool): If True, print OK lines for valid tickets and warning details; errors are always printed.
    
    Returns:
        results (Dict[str, List]): Dictionary with three keys:
            - "valid": list of ticket file paths (str) that passed validation.
            - "warnings": list of {"path": str, "issues": [str, ...]} entries for tickets with non-critical issues.
            - "errors": list of {"path": str, "issues": [str, ...]} entries for tickets with critical issues or load failures (load failures use an issue string starting with "Load failed:").
    """
    results = {
        "valid": [],
        "warnings": [],
        "errors": [],
    }
    
    for ticket_path in queue_root.glob("*/*/*.json"):
        if ".bak" in ticket_path.name or ".tmp" in ticket_path.name:
            continue
        
        try:
            ticket = WorkerTicket.load(ticket_path)
            issues = validate_ticket(ticket)
            
            if not issues:
                results["valid"].append(str(ticket_path))
                if verbose:
                    print(f"[+] {ticket_path.name}: OK")
            else:
                # Categorize issues
                errors = [i for i in issues if "Missing" in i or "does not exist" in i]
                warnings = [i for i in issues if i not in errors]
                
                if errors:
                    results["errors"].append({
                        "path": str(ticket_path),
                        "issues": errors,
                    })
                    print(f"[!] {ticket_path.name}:")
                    for issue in errors:
                        print(f"    ERROR: {issue}")
                
                if warnings:
                    results["warnings"].append({
                        "path": str(ticket_path),
                        "issues": warnings,
                    })
                    if verbose:
                        print(f"[*] {ticket_path.name}:")
                        for issue in warnings:
                            print(f"    WARN: {issue}")
        
        except Exception as e:
            results["errors"].append({
                "path": str(ticket_path),
                "issues": [f"Load failed: {e}"],
            })
            print(f"[!] {ticket_path.name}: LOAD ERROR: {e}")
    
    return results


def main():
    """
    Parse CLI arguments, validate WADE tickets in a queue directory, and print a summary or JSON report.
    
    When a positional queue_root is provided, it is used; otherwise the queue root is derived from environment variables
    (WADE_OWNER_USER, WADE_DATADIR, WADE_QUEUE_DIR) under /home/{owner}. Exits immediately if the queue root does not exist.
    Runs validate_queue on the resolved path, prints progress and a human-readable summary to stderr unless --json is
    specified (which prints the raw JSON results to stdout). The --verbose flag causes per-ticket valid messages and
    warnings to be printed.
    
    Returns:
        exit_code (int): 1 if the queue root was missing or any tickets produced errors, 0 otherwise.
    """
    parser = argparse.ArgumentParser(description="Validate WADE tickets")
    parser.add_argument("queue_root", nargs="?", help="Queue root directory")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show all tickets including valid")
    parser.add_argument("--json", action="store_true", help="Output JSON report")
    
    args = parser.parse_args()
    
    # Determine queue root
    if args.queue_root:
        queue_root = Path(args.queue_root)
    else:
        env = load_env()
        owner = env.get("WADE_OWNER_USER", "autopsy")
        datadir = env.get("WADE_DATADIR", "DataSources")
        qdir = env.get("WADE_QUEUE_DIR", "_queue")
        queue_root = Path(f"/home/{owner}") / datadir / qdir
    
    if not queue_root.exists():
        print(f"[!] Queue root not found: {queue_root}", file=sys.stderr)
        return 1
    
    print(f"[*] Validating tickets in {queue_root}", file=sys.stderr)
    results = validate_queue(queue_root, verbose=args.verbose)
    
    # Summary
    total = len(results["valid"]) + len(results["warnings"]) + len(results["errors"])
    
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print(f"\n[*] Validation Summary:", file=sys.stderr)
        print(f"    Total: {total}", file=sys.stderr)
        print(f"    Valid: {len(results['valid'])}", file=sys.stderr)
        print(f"    Warnings: {len(results['warnings'])}", file=sys.stderr)
        print(f"    Errors: {len(results['errors'])}", file=sys.stderr)
    
    return 1 if results["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())