#!/usr/bin/env python3
import argparse
import sys
import os
from dotenv import load_dotenv

# Load environment variables from .env file at application startup
load_dotenv()

# Add the ASTRA root to sys.path so we can import orchestrator as a package
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from orchestrator.core import engine, utils

def main():
    parser = argparse.ArgumentParser(
        description="ASTRA: Centralized & Adaptive Security Scanner Orchestrator"
    )
    parser.add_argument("target", help="Target (IP, domain, or URL)")
    parser.add_argument(
        "--enable",
        help="Comma-separated list of scanners to enable (or 'all')",
        default="all"
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=5,
        help="Maximum number of concurrent tool executions."
    )
    # --- NEW: Add a mode selector ---
    parser.add_argument(
        "--mode",
        choices=['static', 'dynamic'],
        default='static',
        help="Scanning mode: 'static' runs a fixed plan, 'dynamic' adapts based on findings."
    )
    parser.add_argument(
        "--dry-run",
        help="Print commands without executing",
        action="store_true"
    )

    args = parser.parse_args()

    if not utils.is_valid_target(args.target):
        print(f"[!] Invalid target format: {args.target}")
        utils.log_error(f"Invalid target supplied: {args.target}")
        return

    # The engine is a generator, so we iterate through its output to print live logs.
    for log_line in engine.run_orchestrator(
        primary_target=args.target,
        enable_arg=args.enable,
        concurrency=args.concurrency,
        mode=args.mode,
        dry_run=args.dry_run
    ):
        print(log_line, end="")

if __name__ == "__main__":
    main()

