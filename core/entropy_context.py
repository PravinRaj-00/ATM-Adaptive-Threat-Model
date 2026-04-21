from dataclasses import dataclass


@dataclass
class EntropyContext:
    """
    Stores collected entropy material and metadata.
    This class is purely a container and does not perform enforcement.
    """

    system_entropy: bytes = b""
    dice_entropy: bytes = b""
    external_entropy: bytes = b""

    system_bits: int = 0
    dice_bits: int = 0
    external_bits: int = 0  # informational only
    