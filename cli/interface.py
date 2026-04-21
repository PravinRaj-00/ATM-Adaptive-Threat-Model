import os
from core.lifecycle import LifecycleController
from utils.display import print_banner, print_help, atm_prompt
from core.state import NetworkStateMonitor

def start_cli(verbose=False, quiet=False, audit=False, monitor=None):
    print_banner()

    controller = LifecycleController(verbose=verbose, quiet=quiet, monitor=monitor)

    # ── --audit flag: jump directly to entropy commitment audit ──────────
    if audit:
        print("\n[--audit] Jumping directly to entropy commitment audit mode.")
        controller.start_entropy_audit()
        return

    while True:
        print("\nAdaptive Sovereign Seed System")
        print("--------------------------------")
        print("1. Generate Seed")
        print("2. Recover Seed")
        print("3. Verify Backup")
        print("4. Exit")
        print()

        choice = input(atm_prompt()).strip().lower()

        if choice == "1":
            controller.start_generation()
        elif choice == "2":
            controller.start_recovery()
        elif choice == "3":
            controller.start_verification()
        elif choice == "4" or choice == "exit":
            print("Exiting...")
            break
        elif choice == "help":
            print_help()
        elif choice == "clear":
            os.system('cls' if os.name == 'nt' else 'clear')
            print_banner()
        else:
            print("Invalid selection.")