from enum import Enum
from security.tier_policy import TierLevel


class RevealStage(Enum):
    STAGE_0 = 0  # Nothing revealed
    STAGE_1 = 1  # Hash preview only
    STAGE_2 = 2  # Mnemonic reveal
    STAGE_3 = 3  # Seed reveal
    STAGE_4 = 4  # Raw private key export


# Max reveal stage allowed per tier
TIER_MAX_STAGE = {
    TierLevel.TIER_1: RevealStage.STAGE_4,
    TierLevel.TIER_2: RevealStage.STAGE_3,
    TierLevel.TIER_3: RevealStage.STAGE_3,
    TierLevel.TIER_4: RevealStage.STAGE_2,
}


class ProgressiveRevealError(Exception):
    pass


class ProgressiveRevealController:
    """
    Governs exposure stages for sensitive material.
    Tracks escalation and enforces tier-based maximums.
    """

    def __init__(self, tier: TierLevel):
        self.tier = tier
        self.current_stage = RevealStage.STAGE_0

    def get_current_stage(self) -> RevealStage:
        return self.current_stage

    def get_max_allowed_stage(self) -> RevealStage:
        return TIER_MAX_STAGE[self.tier]

    def can_escalate_to(self, target_stage: RevealStage) -> bool:
        # Cannot downgrade
        if target_stage.value < self.current_stage.value:
            return False

        # Cannot exceed tier maximum
        if target_stage.value > self.get_max_allowed_stage().value:
            return False

        return True

    def escalate(self, target_stage: RevealStage):
        if not self.can_escalate_to(target_stage):
            raise ProgressiveRevealError(
                f"Cannot escalate to {target_stage.name} under tier {self.tier.name}"
            )

        self.current_stage = target_stage

    def required_confirmation_level(self) -> str:
        """
        Returns confirmation requirement based on current stage.
        This does not perform confirmation — only signals requirement.
        """

        if self.current_stage == RevealStage.STAGE_2:
            return "simple_confirmation"

        elif self.current_stage == RevealStage.STAGE_3:
            return "typed_phrase"

        elif self.current_stage == RevealStage.STAGE_4:
            return "typed_phrase_plus_tier_check"

        return "none"

    def __repr__(self):
        return f"<ProgressiveRevealController tier={self.tier.name} stage={self.current_stage.name}>"