from seed.bip39 import BIP39


class Slip39GenerationError(Exception):
    pass


def generate_shares(mnemonic: str, threshold: int = 3, total: int = 5):
    """
    Generate SLIP39 shares from a BIP39 mnemonic.

    Recovers the original entropy from the mnemonic and splits
    it into SLIP39 shares. Reconstruction reproduces the entropy
    which can then be converted back to the original mnemonic.

    Parameters
    ----------
    mnemonic : str
        BIP39 mnemonic phrase.
    threshold : int
        Minimum shares required for reconstruction.
    total : int
        Total shares to generate.

    Returns
    -------
    list[str]
        List of SLIP39 share phrases.
    """

    if threshold > total:
        raise Slip39GenerationError("Threshold cannot exceed total shares.")

    try:
        # Lazy import — only loads shamir_mnemonic when actually needed
        # Allows Tier 1 and Tier 2 to run without shamir_mnemonic installed
        from shamir_mnemonic import generate_mnemonics

        # Recover original entropy from mnemonic
        # This is the reversible secret — BIP39 can reconstruct
        # the mnemonic from these bytes on the recovery side
        secret = BIP39.mnemonic_to_entropy(mnemonic)

        groups = [(threshold, total)]

        mnemonics = generate_mnemonics(
            group_threshold=1,
            groups=groups,
            master_secret=secret
        )

        # Flatten share list
        shares = [share for group in mnemonics for share in group]

        return shares

    except ImportError:
        raise Slip39GenerationError(
            "shamir-mnemonic is not installed. "
            "Run: pip install --no-index --find-links=wheelhouse shamir-mnemonic --break-system-packages"
        )
    except Exception as e:
        raise Slip39GenerationError(f"SLIP39 share generation failed: {e}")