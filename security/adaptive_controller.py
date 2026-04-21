import hashlib
from security.wipe import MemoryWiper
from security.tier_policy import TierPolicy, TierLevel, TierPolicyError
from security.seed_vault import SeedVault
from interaction.progressive_reveal import (ProgressiveRevealController, RevealStage, ProgressiveRevealError)
from interaction.confirmation_guard import ConfirmationGuard, ConfirmationError
from security.integrity_guard import IntegrityGuard, IntegrityError


class AdaptiveSeedController:
    """
    Enforces TierPolicy rules and mediates access to SeedVault.
    """

    def __init__(self, mnemonic: str, tier: TierLevel, passphrase: str = ""):
        self.policy = TierPolicy(tier)
        self.access_count = 0
        self.reveal_controller = ProgressiveRevealController(tier)
        self.confirmation_guard = ConfirmationGuard()

        # Enforce passphrase requirement
        if self.policy.get_rule("require_passphrase") and not passphrase:
            raise TierPolicyError("Passphrase required for this tier.")

        # Create vault immediately
        self.vault = SeedVault.from_mnemonic(mnemonic, passphrase)

        # Get seed copy for IntegrityGuard and commitment — vault stays alive
        seed = self.vault.get_seed()

        # Initialise IntegrityGuard
        self.integrity_guard = IntegrityGuard(seed)

        # Compute one-way seed commitment fingerprint
        # Safe to store and display — cannot be reversed to obtain seed
        seed_buffer = bytearray(seed)
        raw = hashlib.sha256(
        b"SEED_COMMITMENT_V1" + bytes(seed_buffer)
        ).hexdigest()[:16].upper()
        self.seed_commitment = "-".join(raw[i:i+4] for i in range(0, len(raw), 4))

        # Wipe local seed copy immediately after use
        MemoryWiper().wipe(seed_buffer)
        del seed_buffer
        del seed

    def _check_access_limit(self):
        max_access = self.policy.get_rule("max_access_count")

        if max_access is not None and self.access_count >= max_access:
            raise TierPolicyError("Maximum access count exceeded.")

    def _increment_access(self):
        self.access_count += 1

        # Enforce single-use rule (Tier 4)
        if self.policy.get_rule("require_single_use") and self.access_count > 1:
            raise TierPolicyError("Single-use policy enforced for this tier.")

    def get_seed(self) -> bytes:
        if not self.policy.get_rule("allow_get_seed"):
            raise TierPolicyError("get_seed() not allowed under this tier.")

        if self.reveal_controller.get_current_stage().value < RevealStage.STAGE_3.value:
            raise ProgressiveRevealError(
                "Reveal stage insufficient. Escalate to STAGE_3 before accessing seed."
            )

        self._check_access_limit()

        seed = self.vault.get_seed()

        # 🔐 Integrity check
        self.integrity_guard.verify(seed)

        self._increment_access()

        if self.policy.get_rule("force_auto_destroy"):
            self.vault.destroy()

        return seed

    def consume_seed(self) -> bytes:
        if not self.policy.get_rule("allow_consume_seed"):
            raise TierPolicyError("consume_seed() not allowed under this tier.")

        self._check_access_limit()
        seed = self.vault.consume_seed()
        self.integrity_guard.verify(seed)
        self._increment_access()
        return seed

    def secure_access(self):
        if not self.policy.get_rule("allow_secure_access"):
            raise TierPolicyError("secure_access() not allowed under this tier.")

        self._check_access_limit()
        self._increment_access()
        return self.vault.secure_access()
    
    def request_reveal(self, stage: RevealStage, user_input: str | None = None):
        """
        Attempts to escalate reveal stage with required confirmation validation.
        """

        # Check if escalation is allowed under tier
        if not self.reveal_controller.can_escalate_to(stage):
            raise ProgressiveRevealError(
                f"Cannot escalate to {stage.name} under tier {self.policy.tier.name}"
            )

        # Temporarily simulate escalation to determine confirmation requirement
        current_stage_backup = self.reveal_controller.get_current_stage()

        self.reveal_controller.escalate(stage)
        confirmation_type = self.reveal_controller.required_confirmation_level()

        try:
            # Validate confirmation requirement
            self.confirmation_guard.validate(confirmation_type, user_input)
        except ConfirmationError:
            # Revert stage if confirmation fails
            self.reveal_controller.current_stage = current_stage_backup
            raise

        return confirmation_type