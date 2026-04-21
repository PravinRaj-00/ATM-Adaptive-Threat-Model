from enum import Enum


class TierLevel(Enum):
    TIER_1 = 1  # Low Risk
    TIER_2 = 2  # Moderate Risk
    TIER_3 = 3  # High Risk
    TIER_4 = 4  # Extreme / Adversarial


class TierPolicyError(Exception):
    """Raised when tier policy rules are violated."""
    pass


# Declarative policy mapping
TIER_RULES = {
    TierLevel.TIER_1: {
        "allow_get_seed": True,
        "allow_consume_seed": True,
        "allow_secure_access": True,
        "max_access_count": None,  # Unlimited
        "require_passphrase": False,
        "force_auto_destroy": False,
        "restrict_full_seed_display": False,
        "require_confirmation": False,
        "require_single_use": False,
    },
    TierLevel.TIER_2: {
        "allow_get_seed": True,
        "allow_consume_seed": True,
        "allow_secure_access": True,
        "max_access_count": 3,
        "require_passphrase": False,
        "force_auto_destroy": True,
        "restrict_full_seed_display": False,
        "require_confirmation": True,
        "require_single_use": False,
    },
    TierLevel.TIER_3: {
        "allow_get_seed": False,
        "allow_consume_seed": True,
        "allow_secure_access": True,
        "max_access_count": 1,
        "require_passphrase": True,
        "force_auto_destroy": True,
        "restrict_full_seed_display": True,
        "require_confirmation": True,
        "require_single_use": False,
    },
    TierLevel.TIER_4: {
        "allow_get_seed": False,
        "allow_consume_seed": True,
        "allow_secure_access": True,
        "max_access_count": 1,
        "require_passphrase": True,
        "force_auto_destroy": True,
        "restrict_full_seed_display": True,
        "require_confirmation": True,
        "require_single_use": True,
    },
}


class TierPolicy:
    """
    Defines adaptive operational security rules based on threat tier.
    Purely declarative. Does not enforce behavior.
    """

    def __init__(self, level: TierLevel):
        if level not in TIER_RULES:
            raise TierPolicyError("Invalid tier level.")

        self.level = level
        self.tier = level
        self.rules = TIER_RULES[level]

    def get_rule(self, rule_name: str):
        if rule_name not in self.rules:
            raise TierPolicyError(f"Unknown rule: {rule_name}")
        return self.rules[rule_name]

    def __repr__(self):
        return f"<TierPolicy level={self.level.name}>"