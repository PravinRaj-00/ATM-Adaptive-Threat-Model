from shamir_mnemonic import combine_mnemonics
from seed.bip39 import BIP39


class ReconstructionError(Exception):
    pass


def reconstruct_mnemonic(shares: list[str]) -> str:
    """
    Reconstruct the original BIP39 mnemonic from SLIP39 shares.

    Combines shares to recover entropy bytes, then converts
    entropy back to the original mnemonic via BIP39.

    Parameters
    ----------
    shares : list[str]
        At least threshold number of SLIP39 shares.

    Returns
    -------
    str
        Original BIP39 mnemonic phrase.
    """

    try:
        # Reconstruct entropy bytes from shares
        entropy = combine_mnemonics(shares)

        # Convert entropy back to mnemonic
        # BIP39 checksum verification runs internally —
        # invalid entropy will raise BIP39Error automatically
        mnemonic = BIP39.entropy_to_mnemonic(entropy)

        return mnemonic

    except Exception as e:
        raise ReconstructionError(f"Share reconstruction failed: {e}")