import argparse
from cli.interface import start_cli
from core.integrity_check import run_integrity_check  
from core.state import NetworkStateMonitor

def main():
    # ── CLI Flags ─────────────────────────────────────────────────────────
    parser = argparse.ArgumentParser(
        prog="atm",
        description="ATM — Adaptive Threat Model: Sovereign Cryptographic Seed Lifecycle"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose output (entropy fingerprints, full commitment hash)"
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress informational [i] output"
    )
    parser.add_argument(
        "--audit",
        action="store_true",
        help="Jump directly to entropy commitment audit"
    )
    args = parser.parse_args()

    monitor = NetworkStateMonitor()
    monitor.verify_air_gap_startup()   # Step 1 — air-gap first
    run_integrity_check()              # Step 2 — integrity second      

    start_cli(verbose=args.verbose, quiet=args.quiet, audit=args.audit, monitor=monitor)

if __name__ == "__main__":
    main()