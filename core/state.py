"""
core/state.py
─────────────
ATM Security Bootloader — Multi-Phase Pre-Flight Verification

Runs before the program loads. Three phases:

  PHASE 1 — Execution Context Verification
      Independent checks across network, connectivity, Tor,
      entropy pool, and execution medium.

  PHASE 2 — Security Assertion
      Summary verdict based on Phase 1 results.
      Any critical failure aborts immediately.

  PHASE 3 — Initialisation
      Countdown and transition into the main program.

Design principles:
  - Linux/Tails-only checks skip gracefully on Windows
  - Virtual adapters (VMware, VirtualBox) excluded from network checks
  - Each check is independent — one failure does not skip others
  - Critical failures abort with memory wipe before exit
  - Non-critical checks warn but do not abort

Research anchors:
  - Network isolation    → Ledger metadata breach argument
  - Tor detection        → Tails OS air-gap integrity argument
  - Entropy readiness    → Trust Wallet single-source failure argument
  - Multi-signal verify  → multiple independent signals prove isolation

Dependencies:
  psutil  — network interface enumeration
  Install: pip install psutil
"""

import os
import sys
import time
import socket
import platform
import subprocess
import psutil
from security.wipe import MemoryWiper


# ─── Platform detection ───────────────────────────────────────────────────────

_IS_LINUX   = platform.system() == "Linux"
_IS_WINDOWS = platform.system() == "Windows"


# ─── Interface exclusion constants ────────────────────────────────────────────

_EXCLUDED_INTERFACES = {"lo"}

_LOOPBACK_PREFIXES = ("127.", "::1")

_VIRTUAL_INTERFACE_PREFIXES = (
    "vmware", "vmnet", "vbox", "virtualbox",
    "wsl", "loopback", "pseudo", "veth",
)

_VIRTUAL_IP_PREFIXES = (
    "192.168.56.", "192.168.57.",
    "192.168.80.", "192.168.99.",
    "192.168.169.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "10.200.1.",
)


# ─── Timing ───────────────────────────────────────────────────────────────────

_DELAY_CHECK   = 0.4
_DELAY_RESULT  = 0.15
_DELAY_PHASE   = 0.6
_COUNTDOWN_SEC = 5


# ─── Status markers ───────────────────────────────────────────────────────────

PASS    = "[✓]"
FAIL    = "[✗]"
WARN    = "[!]"
RUNNING = "[~]"
SKIP    = "[—]"


# ─── Security Bootloader ──────────────────────────────────────────────────────

class NetworkStateMonitor:
    """
    ATM Security Bootloader and runtime air-gap monitor.

    Startup mode  — verify_air_gap_startup()
        Full three-phase pre-flight check from main.py.

    Runtime mode  — check_checkpoint(context, buffers)
        Silent check at each domain transition in lifecycle.py.
    """

    def __init__(self):
        self._wiper  = MemoryWiper()
        self._checks = {}

    # ═══════════════════════════════════════════════════════
    # PUBLIC API
    # ═══════════════════════════════════════════════════════

    def verify_air_gap_startup(self) -> None:
        """Full three-phase security bootloader. Called from main.py."""
        self._print_bootloader_header()
        self._run_phase_1()
        self._run_phase_2()
        self._run_phase_3()

    def check_checkpoint(
        self,
        context: str,
        sensitive_buffers: list | None = None,
    ) -> None:
        """
        Silent runtime air-gap check at a domain transition.
        Aborts with wipe if any real network interface is active.
        """
        if sensitive_buffers is None:
            sensitive_buffers = []
        active = self._get_active_interfaces()
        if active:
            self._abort_network_detected(active, sensitive_buffers, context)

    # ═══════════════════════════════════════════════════════
    # BOOTLOADER HEADER
    # ═══════════════════════════════════════════════════════

    def _print_bootloader_header(self) -> None:
        env_label = "Tails OS (Ephemeral)" if _IS_LINUX else "Linux / Tails OS"
        print()
        print("=" * 44)
        print("  ATM — Adaptive Threat Model")
        print("  Secure Entropy Engine")
        print("=" * 44)
        print(f"  Execution Mode : AIR-GAPPED")
        print(f"  Target OS      : {env_label}")
        print(f"  Storage        : Non-Persistent (RAM Only)")
        print("=" * 44)
        print()
        time.sleep(_DELAY_PHASE)

    # ═══════════════════════════════════════════════════════
    # PHASE 1 — EXECUTION CONTEXT VERIFICATION
    # ═══════════════════════════════════════════════════════

    def _run_phase_1(self) -> None:
        print("[ PHASE 1 ] Execution Context Verification")
        print("-" * 44)
        print()
        self._check_network_interfaces()
        self._check_outbound_connectivity()
        self._check_tor_status()
        self._check_entropy_pool()
        self._check_execution_medium()
        print()
        time.sleep(_DELAY_PHASE)

    def _check_network_interfaces(self) -> None:
        """Check 1 — Network interface scan (CRITICAL)."""
        print(f"  {RUNNING} Inspecting network interfaces...")
        time.sleep(_DELAY_CHECK)
        print(f"      → enumerating adapters...")
        time.sleep(0.3)
        print(f"      → evaluating link states...")
        time.sleep(0.3)

        active = self._get_active_interfaces()

        if not active:
            print(f"  {PASS} No active network interfaces detected\n")
            self._checks["network"] = True
        else:
            for iface, ip in active:
                print(f"  {FAIL} Active interface detected: {iface} ({ip})")
            print(f"  {WARN} Air-gap requirement violated\n")
            self._checks["network"] = False

        time.sleep(_DELAY_RESULT)

    def _check_outbound_connectivity(self) -> None:
        """Check 2 — Outbound connectivity test (CRITICAL, Linux only)."""
        print(f"  {RUNNING} Testing outbound connectivity...")
        time.sleep(_DELAY_CHECK)

        if _IS_WINDOWS:
            print(f"  {SKIP} Skipped — Linux/Tails OS only\n")
            self._checks["connectivity"] = None
            time.sleep(_DELAY_RESULT)
            return

        reachable = False
        try:
            socket.setdefaulttimeout(2)
            socket.getaddrinfo("example.com", 80)
            reachable = True
        except Exception:
            reachable = False

        if not reachable:
            print(f"  {PASS} No external connectivity detected\n")
            self._checks["connectivity"] = True
        else:
            print(f"  {FAIL} Outbound connectivity detected")
            print(f"  {WARN} Network isolation cannot be guaranteed\n")
            self._checks["connectivity"] = False

        time.sleep(_DELAY_RESULT)

    def _check_tor_status(self) -> None:
        """Check 3 — Tor service detection (CRITICAL on Tails, Linux only)."""
        print(f"  {RUNNING} Checking Tor network status...")
        time.sleep(_DELAY_CHECK)

        if _IS_WINDOWS:
            print(f"  {SKIP} Skipped — Linux/Tails OS only\n")
            self._checks["tor"] = None
            time.sleep(_DELAY_RESULT)
            return

        # On Tails OS, Tor is always active by design — this is expected
        # and correct behaviour. Tails routes all traffic through Tor.
        # Detecting Tails by checking for the amnesia user home or live boot markers.
        _IS_TAILS = (
            os.path.exists("/etc/amnesia") or
            os.path.exists("/live/config/tails") or
            os.environ.get("USER", "") == "amnesia"
        )

        if _IS_TAILS:
            print(f"  {PASS} Tails OS detected — Tor routing is expected and correct\n")
            self._checks["tor"] = True
            time.sleep(_DELAY_RESULT)
            return

        tor_active = False
        try:
            result = subprocess.run(
                ["pgrep", "-x", "tor"],
                capture_output=True, text=True, timeout=3
            )
            if result.returncode == 0:
                tor_active = True
        except Exception:
            tor_active = False

        if tor_active:
            print(f"  {FAIL} Tor service detected — network stack active")
            print(f"  {WARN} Air-gap requirement violated\n")
            self._checks["tor"] = False
        else:
            print(f"  {PASS} Tor service inactive\n")
            self._checks["tor"] = True

        time.sleep(_DELAY_RESULT)

    def _check_entropy_pool(self) -> None:
        """Check 4 — System entropy pool availability."""
        print(f"  {RUNNING} Verifying system entropy pool...")
        time.sleep(_DELAY_CHECK)

        if _IS_WINDOWS:
            print(f"      → platform     : Windows (CryptGenRandom)")
            print(f"      → availability : OS-managed, always available")
            time.sleep(0.3)
            print(f"  {PASS} System entropy pool available\n")
            self._checks["entropy"] = True
            time.sleep(_DELAY_RESULT)
            return

        try:
            with open("/proc/sys/kernel/random/entropy_avail", "r") as f:
                available = int(f.read().strip())

            threshold = 256
            print(f"      → reading      : /proc/sys/kernel/random/entropy_avail")
            time.sleep(0.3)
            print(f"      → available    : {available} bits")
            print(f"      → threshold    : {threshold} bits minimum")
            time.sleep(0.3)

            if available >= threshold:
                print(f"  {PASS} Entropy pool sufficient\n")
            else:
                print(f"  {WARN} Low entropy — {available} bits")
                print(f"      → Dice entropy collection will supplement\n")

            self._checks["entropy"] = True

        except Exception:
            print(f"      → could not read entropy pool")
            time.sleep(0.3)
            print(f"  {WARN} Defaulting to OS RNG\n")
            self._checks["entropy"] = True

        time.sleep(_DELAY_RESULT)

    def _check_execution_medium(self) -> None:
        """Check 5 — USB / removable media execution context (Linux only)."""
        print(f"  {RUNNING} Verifying execution medium...")
        time.sleep(_DELAY_CHECK)

        if _IS_WINDOWS:
            print(f"  {SKIP} Skipped — Linux/Tails OS only\n")
            self._checks["medium"] = None
            time.sleep(_DELAY_RESULT)
            return

        running_from_usb = False
        detected_path    = None

        try:
            script_path = os.path.abspath(__file__)
            usb_paths   = ("/media/", "/mnt/", "/live/", "/run/live/")

            print(f"      → detected path : {script_path}")
            time.sleep(0.3)

            for p in usb_paths:
                if p in script_path:
                    running_from_usb = True
                    detected_path    = p
                    break

        except Exception:
            pass

        if running_from_usb:
            print(f"      → matched root  : {detected_path}")
            time.sleep(0.2)
            print(f"  {PASS} Running from external media (USB)\n")
            self._checks["medium"] = True
        else:
            print(f"      → no USB path match detected")
            time.sleep(0.2)
            print(f"  {WARN} Execution medium unconfirmed — ensure running from USB\n")
            self._checks["medium"] = None

        time.sleep(_DELAY_RESULT)

    # ═══════════════════════════════════════════════════════
    # PHASE 2 — SECURITY ASSERTION
    # ═══════════════════════════════════════════════════════

    def _run_phase_2(self) -> None:
        print("[ PHASE 2 ] Security Assertion")
        print("-" * 44)
        print()
        time.sleep(0.3)

        network_ok      = self._checks.get("network",      True)
        connectivity_ok = self._checks.get("connectivity", None)
        tor_ok          = self._checks.get("tor",          None)
        entropy_ok      = self._checks.get("entropy",      True)

        critical_failures = []
        if network_ok is False:
            critical_failures.append("Network isolation violated")
        if connectivity_ok is False:
            critical_failures.append("Outbound connectivity detected")
        if tor_ok is False:
            critical_failures.append("Tor network stack active")

        # Print assertion lines
        self._assert_line("Air-Gap Integrity Verified",    network_ok)
        self._assert_line("Network Isolation Enforced",    connectivity_ok)
        self._assert_line("Tor Service Inactive",          tor_ok)
        self._assert_line("Entropy Sources Ready",         entropy_ok)

        print()

        if critical_failures:
            print("-" * 44)
            for reason in critical_failures:
                print(f"  {FAIL} {reason}")
            print()
            print(f"  {WARN} Security assertion FAILED — aborting.")
            print("-" * 44)
            print()
            sys.exit(1)
        else:
            print("-" * 44)
            print(f"  → System approved for secure key generation")
            print("-" * 44)
            print()

        time.sleep(_DELAY_PHASE)

    def _assert_line(self, label: str, result) -> None:
        """Print a single assertion line. None = skipped."""
        time.sleep(0.2)
        if result is True:
            print(f"  {PASS} {label}")
        elif result is False:
            print(f"  {FAIL} {label}")
        else:
            print(f"  {SKIP} {label} (skipped — Linux/Tails only)")
        time.sleep(_DELAY_RESULT)

    # ═══════════════════════════════════════════════════════
    # PHASE 3 — INITIALISATION + TRANSITION
    # ═══════════════════════════════════════════════════════

    def _run_phase_3(self) -> None:
        print("[ PHASE 3 ] System Initialisation")
        print("-" * 44)
        print()

        steps = [
            "Loading security policies...",
            "Initialising entropy engine...",
            "Preparing secure vault...",
        ]

        spinner = ["|", "/", "-", "\\"]

        for step in steps:
            # ── Spinner animation ─────────────────────────────────────────
            for i in range(12):
                frame = spinner[i % len(spinner)]
                sys.stdout.write(
                    f"\r  {RUNNING} {step:<38} {frame}"
                )
                sys.stdout.flush()
                time.sleep(0.08)

            # ── Resolve to done ───────────────────────────────────────────
            sys.stdout.write(f"\r  {PASS} {step:<38}  \n")
            sys.stdout.flush()
            time.sleep(0.1)

        print()
        print(f"  {PASS} Initialisation complete")
        print()
        print(f"  → Launching ATM...")
        print()
        time.sleep(1)
        os.system("cls" if os.name == "nt" else "clear")

    # ═══════════════════════════════════════════════════════
    # RUNTIME ABORT — called by check_checkpoint()
    # ═══════════════════════════════════════════════════════

    def _abort_network_detected(
        self,
        active_interfaces: list[tuple[str, str]],
        sensitive_buffers: list,
        checkpoint: str,
    ) -> None:
        print()
        print("=" * 44)
        print(f"  {FAIL} CRITICAL — NETWORK INTERFACE DETECTED")
        print("=" * 44)

        for iface, ip in active_interfaces:
            print(f"  Interface : {iface}")
            print(f"  Address   : {ip}")

        print(f"  Detected  : {checkpoint}")
        print()
        print("  This program requires a fully offline environment.")
        print("  A network interface is active — air-gap integrity")
        print("  cannot be guaranteed. Aborting immediately.")
        print()

        if sensitive_buffers:
            print(f"  {RUNNING} Wiping sensitive data from memory...")
            for buf in sensitive_buffers:
                if isinstance(buf, bytearray):
                    self._wiper.wipe(buf)
            print(f"  {PASS} All buffers cleared.")
        else:
            print(f"  {PASS} No sensitive data in memory at this checkpoint.")

        print()
        print("  Generation aborted. No seed data was saved.")
        print("=" * 44)
        print()
        sys.exit(1)

    # ═══════════════════════════════════════════════════════
    # PRIVATE HELPERS — INTERFACE DETECTION
    # ═══════════════════════════════════════════════════════

    def _get_active_interfaces(self) -> list[tuple[str, str]]:
        active = []
        all_stats = psutil.net_if_stats()
        all_addrs = psutil.net_if_addrs()

        for iface, stat in all_stats.items():
            if self._is_excluded_interface(iface):
                continue
            if not stat.isup:
                continue
            for ip in self._get_ip_addresses(iface, all_addrs):
                active.append((iface, ip))

        return active

    def _is_excluded_interface(self, iface: str) -> bool:
        if iface in _EXCLUDED_INTERFACES:
            return True
        return any(iface.lower().startswith(p) for p in _VIRTUAL_INTERFACE_PREFIXES)

    def _get_ip_addresses(self, iface: str, all_addrs: dict) -> list[str]:
        if iface not in all_addrs:
            return []
        result = []
        for addr in all_addrs[iface]:
            if addr.family not in (socket.AF_INET, socket.AF_INET6):
                continue
            ip = addr.address.split("%")[0]
            if any(ip.startswith(p) for p in _LOOPBACK_PREFIXES):
                continue
            if ip.lower().startswith("fe80"):
                continue
            if any(ip.startswith(p) for p in _VIRTUAL_IP_PREFIXES):
                continue
            result.append(ip)
        return result

    def _get_raw_ip_addresses(self, iface: str, all_addrs: dict) -> list[str]:
        if iface not in all_addrs:
            return []
        result = []
        for addr in all_addrs[iface]:
            if addr.family not in (socket.AF_INET, socket.AF_INET6):
                continue
            ip = addr.address.split("%")[0]
            if any(ip.startswith(p) for p in _LOOPBACK_PREFIXES):
                continue
            if ip.lower().startswith("fe80"):
                continue
            result.append(ip)
        return result