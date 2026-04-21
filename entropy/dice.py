# entropy/dice.py

import hashlib
import math

# ===== Entropy Configuration =====
MIN_DICE_BITS = 128  # Minimum physical entropy contribution required
BITS_PER_ROLL = math.log2(6)  # ≈ 2.585 bits per fair 6-sided die roll
MIN_ROLLS = math.ceil(MIN_DICE_BITS / BITS_PER_ROLL)


def collect_dice_entropy(min_rolls: int = MIN_ROLLS) -> bytes:
    """
    Collects entropy from physical dice rolls.
    Converts base-6 input into bytes and normalizes via SHA-256.
    Returns 32 bytes of hashed entropy.

    Parameters
    ----------
    min_rolls : int
        Minimum number of dice rolls required. Defaults to MIN_ROLLS (50).
        Pass a higher value for higher security tiers (e.g. 100 for Tier 4).
    """

    print(f"Minimum required rolls: {min_rolls}")
    print("Roll a fair 6-sided die and enter results as a continuous string.")
    print("Example: 1635251436...")

    while True:
        rolls = input("Dice rolls: ").strip()

        # Basic validation
        if not rolls.isdigit():
            print("Invalid input. Only digits 1-6 are allowed.")
            continue

        if any(c not in "123456" for c in rolls):
            print("Invalid dice values detected. Use only numbers 1-6.")
            continue

        if len(rolls) < min_rolls:
            print(f"Please enter at least {min_rolls} rolls.")
            continue

        break

    # ===== Base-6 → Integer Conversion =====
    entropy_int = 0
    for digit in rolls:
        entropy_int = entropy_int * 6 + (int(digit) - 1)

    # ===== Integer → Bytes Conversion =====
    byte_length = (entropy_int.bit_length() + 7) // 8
    entropy_bytes = entropy_int.to_bytes(byte_length, byteorder="big")

    # ===== Normalize Distribution via SHA-256 =====
    hashed_entropy = hashlib.sha256(entropy_bytes).digest()

    physical_bits = len(rolls) * BITS_PER_ROLL

    print("[✓] Dice entropy collected and normalized.")
    print(f"[i] Physical entropy contribution: ~{physical_bits:.2f} bits")

    return hashed_entropy, physical_bits