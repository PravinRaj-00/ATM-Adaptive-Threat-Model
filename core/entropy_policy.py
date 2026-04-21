from dataclasses import dataclass


@dataclass(frozen=True)
class EntropyPolicy:
    """
    Defines the entropy acquisition requirements for a given threat tier.
    This class is purely declarative. It does not perform enforcement.
    """

    require_system: bool
    require_dice: bool
    require_external: bool
    require_passphrase: bool

    min_dice_bits: int
    total_required_bits: int