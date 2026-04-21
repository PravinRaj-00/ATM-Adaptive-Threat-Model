class EntropyPolicyError(Exception):
    """Base class for entropy policy violations."""
    pass


class MissingRequiredSourceError(EntropyPolicyError):
    pass


class DiceEntropyTooLowError(EntropyPolicyError):
    pass


class TotalEntropyThresholdError(EntropyPolicyError):
    pass