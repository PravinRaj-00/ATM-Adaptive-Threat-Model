import sys
import time
import os
import random


# ----------------------------------------------------------------
# ANSI Colour Codes — no external dependencies
# Works on Linux, macOS, Tails OS
# ----------------------------------------------------------------

class Colours:
    GREEN        = "\033[92m"
    ORANGE       = "\033[38;5;208m"   # True orange (256-colour)
    RED          = "\033[91m"
    WHITE        = "\033[97m"
    GREY         = "\033[90m"
    CYAN         = "\033[96m"
    YELLOW       = "\033[93m"
    PURPLE       = "\033[38;5;141m"
    BOLD         = "\033[1m"
    DIM          = "\033[2m"
    RESET        = "\033[0m"


# ----------------------------------------------------------------
# Core Print Helpers
# ----------------------------------------------------------------

def c(text: str, colour: str) -> str:
    """Wrap text in a colour code."""
    return f"{colour}{text}{Colours.RESET}"


def print_success(message: str):
    """Green success message."""
    print(c(f"[✓] {message}", Colours.GREEN))


def print_error(message: str):
    """Red error message."""
    print(c(f"[✗] {message}", Colours.RED))


def print_warning(message: str):
    """Orange warning message."""
    print(c(f"[!] {message}", Colours.ORANGE))


def print_info(message: str):
    """Grey informational message."""
    print(c(f"[i] {message}", Colours.GREY))


def print_section(title: str):
    """
    Green section header — used at domain transition points.
    """
    width = 44
    border = c("━" * width, Colours.GREEN)
    label = c(f"  {title}", Colours.GREEN + Colours.BOLD)
    print(f"\n{border}")
    print(label)
    print(f"{border}\n")


def print_bitcoin(message: str):
    """Orange highlight — used for seed/mnemonic related output."""
    print(c(message, Colours.ORANGE + Colours.BOLD))


# ----------------------------------------------------------------
# Progress Bar
# ----------------------------------------------------------------

def print_progress_bar(label: str, width: int = 20, delay: float = 0.03):
    """
    Animated progress bar for domain transitions.
    Fills left to right then prints COMPLETE.
    """
    sys.stdout.write(f"  {Colours.WHITE}{label:<35}{Colours.RESET} [")
    sys.stdout.flush()

    for _ in range(width):
        time.sleep(delay)
        sys.stdout.write(c("█", Colours.GREEN))
        sys.stdout.flush()

    sys.stdout.write(f"] {c('COMPLETE', Colours.GREEN)}\n")
    sys.stdout.flush()


def print_pipeline_status(completed_domains: list):
    """
    Displays animated pipeline progress for completed domains.
    """
    print()
    for domain in completed_domains:
        print_progress_bar(domain)
        time.sleep(0.1)
    print()


# ----------------------------------------------------------------
# Subtitle — Metasploit-style info block
# Replaces old subtitle and tagline under both banner variants
# ----------------------------------------------------------------

def _print_subtitle():
    """Prints Metasploit-style info block below the banner."""
    W  = Colours.WHITE
    C  = Colours.CYAN
    R  = Colours.RESET

    # Fixed width — all ] align at the same column
    width = 48

    def top_row(text):
        pad = width - len(text)
        print(f"{W}       ={C}[ {W}  {text}{' ' * pad}  {C}]{R}")

    def info_row(text, colour=None):
        pad = width - len(text)
        col = colour if colour else W
        print(f"{W}+ -- --={C}[ {col}  {text}{' ' * pad}  {C}]{R}")

    print()
    top_row("Adaptive Threat Model — ATM v1.0")
    info_row("Threat-Adaptive Sovereign Seed Lifecycle")
    info_row("BIP39  |  SLIP39  |  AES-256-GCM  |  Argon2id")
    info_row("Air-Gapped  -  Tails OS  -  Amnesic")
    info_row("Developed by Pravin Raj Morgan", Colours.YELLOW)
    print()


# ----------------------------------------------------------------
# Variant 1 — Bitcoin ASCII Art
# Orange x characters + white bold Bitcoin structure
# ----------------------------------------------------------------

BITCOIN_ASCII = '''
                   .,:ldxxxxdl:,.                   
              .':oxxxxxxxxxxxxxxxxo:,.              
           'cdxxxxxxxxxxxxxxxxxxxxxxxxxc'           
        .cxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxc.        
      .lxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxl.      
     cxxxxxxxxxxxxxxxxxx0MMKxxK0Oxxxxxxxxxxxxxc     
   .dxxxxxxxxxxxxkK0OkkxWMMkxKMMXxxxxxxxxxxxxxxd.   
  .xxxxxxxxxxxxxxKMMMMMMMMWK0WMMkxxxxxxxxxxxxxxxx.  
 .xxxxxxxxxxxxxxxxxkXMMMMMMMMMMMNX0kxxxxxxxxxxxxxx. 
 dxxxxxxxxxxxxxxxxxxXMMMMXkO0KNMMMMMXxxxxxxxxxxxxxd 
.xxxxxxxxxxxxxxxxxxkMMMMMkxxxxxOMMMMMKxxxxxxxxxxxxx.
lxxxxxxxxxxxxxxxxxxXMMMMNkxxxxkKMMMMM0xxxxxxxxxxxxxo
xxxxxxxxxxxxxxxxxxOMMMMMMMMWWWMMMMMW0xxxxxxxxxxxxxxx
dxxxxxxxxxxxxxxxxxNMMMMXO0KXNMMMMMNOxxxxxxxxxxxxxxxd
.xxxxxxxxxxxxxxxxOMMMMMkxxxxxkKMMMMMKxxxxxxxxxxxxxx.
 xxxxxxxxxxxxONXXWMMMMKxxxxxxxkMMMMMWxxxxxxxxxxxxxx 
 .xxxxxxxxxxkNMMMMMMMMWXXK00KXWMMMMMKxxxxxxxxxxxxx. 
  lxxxxxxxxxxxxkO0WMMWMMMMMMMMMMMMWKxxxxxxxxxxxxxo  
   lxxxxxxxxxxxxxkMMWxxNMMKKKXXKKOxxxxxxxxxxxxxxo   
    .xxxxxxxxxxxxKWM0xOMMWxxxxxxxxxxxxxxxxxxxxx.    
      dxxxxxxxxxxxxxxxOKXOxxxxxxxxxxxxxxxxxxxx      
        xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx        
          .xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.          
             .xxxxxxxxxxxxxxxxxxxxxxxx.             
                   xxxxxxxxxxxxxx.                  
                         lo
'''


def _print_banner_bitcoin():
    """Prints Bitcoin ASCII art — orange x + white bold structure."""
    for line in BITCOIN_ASCII.splitlines():
        coloured_line = ""
        for char in line:
            if char == 'x':
                coloured_line += Colours.ORANGE + char + Colours.RESET
            elif char in ['M', '0', 'K', 'W', 'N', 'X']:
                coloured_line += Colours.WHITE + Colours.BOLD + char + Colours.RESET
            else:
                coloured_line += char
        print(coloured_line)


# ----------------------------------------------------------------
# Variant 2 — Tails OS / Neofetch Style
# Purple — privacy and Tails OS theme
# ----------------------------------------------------------------

TAILS_ASCII = r"""
       ./yhNh
     syy/Nshh      .:o/
    N:dsNshh      `ohNMMd
    N-/+Nshh      `yMMMMd
    N-yhMshh   ₿   yMMMMd
    N-s:hshh       yMMMMd so//.
    N-oyNsyh       yMMMMd d  Mms.
    N:hohhhd:.     yMMMMd  syMMM+
    Nsyh+-..+y+-   yMMMMd   :mMM+
    +hy-     -ss/ `yMMMM     `+d+
      :sy/.    ./yNMMMMm
        .+ys- `:shNMMMMMy/`
           `hNmmMMMMMMMMMMMMdo.
           dMMMMMMMMMMMMMMMMNh :
           +hMMMMMMMMMMMMMMMMmy .
            -oNMMMMMMMMMMmy+.
              `:yNMMMds/.
                 .//`
"""


def _print_banner_tails():
    """Prints Tails OS Neofetch-style ASCII art in purple."""
    for line in TAILS_ASCII.splitlines():
        print(c(line, Colours.PURPLE))


# ----------------------------------------------------------------
# Main Banner Entry Point — random variant selection
# ----------------------------------------------------------------

BANNER_VARIANTS = [
    _print_banner_bitcoin,
    _print_banner_tails,
]


def print_banner():
    """
    Prints a randomly selected ATM startup banner
    followed by the shared subtitle and tagline.

    Variants:
      1. Bitcoin ASCII art — orange/white
      2. Tails OS Neofetch style — purple

    Called once at program startup from cli/interface.py.
    """
    os.system('cls' if os.name == 'nt' else 'clear')

    variant = random.choice(BANNER_VARIANTS)
    variant()

    _print_subtitle()

def print_help():
    """
    Displays the ATM in-program help panel.
    Triggered by typing 'help' at the main atm > prompt.
    """
    W      = Colours.WHITE
    B      = Colours.BOLD
    R      = Colours.RESET
    border = f"{W}{'=' * 58}{R}"
    LEFT_W = 24

    def section(title, div_len=18):
        print()
        print(f"{W}{B}  {title:<{LEFT_W}}DESCRIPTION{R}")
        print(f"{W}  {'-' * div_len}{' ' * (LEFT_W - div_len)}{'-' * 30}{R}")

    def row(left, right):
        print(f"{W}  {left:<{LEFT_W}}{R}{right}")

    # ── Header ────────────────────────────────────────────────────────────
    print()
    print(border)
    print(f"{W}{B}  ATM — Adaptive Threat Model{R}")
    print(f"{W}  Sovereign Cryptographic Seed Lifecycle{R}")
    print(border)

    # ── Commands ──────────────────────────────────────────────────────────
    section("COMMANDS", 18)
    row("generate",  "Generate a new BIP39 seed phrase")
    row("recover",   "Recover your seed from backup or shares")
    row("verify",    "Verify backup integrity or audit entropy")
    row("help",      "Show this help panel")
    row("clear",     "Clear the terminal and redraw the banner")
    row("exit",      "Exit ATM")

    # ── Threat Profile ────────────────────────────────────────────────────
    section("THREAT PROFILE", 22)
    row("Tier 1  LOW",     "Basic self-custody, single-factor encrypted backup")
    row("Tier 2  MEDIUM",  "Three-factor encrypted backup with keyfile")
    row("Tier 3  HIGH",    "Shamir 3-of-5 shares, passphrase enforced")
    row("Tier 4  EXTREME", "Single-use vault, extreme adversary model")

    # ── Key Concepts ──────────────────────────────────────────────────────
    section("KEY CONCEPTS", 18)
    row("Seed Fingerprint",   "XXXX-XXXX-XXXX-XXXX — your wallet identity")
    row("Entropy Commitment", "Raw hex — proves honest entropy before generation")
    row("Shamir Shares",      "3 of 5 shares required to reconstruct your seed")
    row("Passphrase",         "BIP39 extension — adds plausible deniability")
    row(".atm file",          "Encrypted entropy backup (Tier 1 / Tier 2)")
    row(".atm-map file",      "Encrypted share location map (Tier 3 / Tier 4)")
    row("CommitmentLock",     "Seals entropy before mnemonic generation")
    row("Air-Gap",            "Runs fully offline on Tails OS")

    # ── CLI Flags ─────────────────────────────────────────────────────────
    section("CLI FLAGS", 14)
    row("--verbose", "Show entropy fingerprints and full commitment hash")
    row("--quiet",   "Suppress informational [i] output")
    row("--audit",   "Jump directly to entropy commitment audit on launch")

    # ── Footer ────────────────────────────────────────────────────────────
    print()
    print(border)
    print(f"{W}  Type a number to navigate. Type 'help' at the main prompt.{R}")
    print(border)
    print()



# ── Prompt colour constants ───────────────────────────────────────────────
_WHITE  = "\033[97m"
_RED    = "\033[91m"
_RESET  = "\033[0m"


def atm_prompt(context: str = "") -> str:
    """
    Returns a styled Metasploit-style ATM prompt string for use in input() calls.

    Usage:
        input(atm_prompt("generation/entropy"))
        → atm (generation/entropy) > _

        input(atm_prompt())
        → atm > _

    Parameters
    ----------
    context : str
        The current navigation context path, e.g. "generation/entropy".
        If empty, renders as plain "atm > ".

    Returns
    -------
    str — styled prompt string, ready to pass directly into input().
    """
    if context:
        return f"{_WHITE}atm{_RESET} ({_RED}{context}{_RESET}){_WHITE} > {_RESET}"
    return f"{_WHITE}atm{_RESET}{_WHITE} > {_RESET}"