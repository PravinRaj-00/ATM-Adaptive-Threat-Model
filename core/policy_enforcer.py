from core.exceptions import (
    MissingRequiredSourceError,
    DiceEntropyTooLowError,
    TotalEntropyThresholdError,
)


class EntropyPolicyEnforcer:

    @staticmethod
    def validate(policy, context):
        """
        Validates collected entropy against the defined EntropyPolicy.
        Raises custom exceptions if requirements are not met.
        """

        # 1 Check required sources
        if policy.require_system and not context.system_entropy:
            raise MissingRequiredSourceError("System entropy is required but missing.")

        if policy.require_dice and not context.dice_entropy:
            raise MissingRequiredSourceError("Dice entropy is required but missing.")

        if policy.require_external and not context.external_entropy:
            raise MissingRequiredSourceError("External entropy is required but missing.")

        # 2 Check minimum dice bits
        if policy.require_dice and context.dice_bits < policy.min_dice_bits:
            raise DiceEntropyTooLowError(
                f"Minimum dice entropy not met. "
                f"Required: {policy.min_dice_bits} bits, "
                f"Current: {context.dice_bits} bits."
            )

        # 3 Check total entropy threshold
        total_bits = context.system_bits + context.dice_bits

        if total_bits < policy.total_required_bits:
            raise TotalEntropyThresholdError(
                f"Total entropy threshold not met. "
                f"Required: {policy.total_required_bits} bits, "
                f"Current: {total_bits} bits."
            )

        return True