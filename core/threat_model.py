from core.entropy_policy import EntropyPolicy

# ----------------------------------------------------------------
# Threat Level Constants
# ----------------------------------------------------------------

class ThreatLevel:
    LOW     = "Tier 1 - Casual User"
    MEDIUM  = "Tier 2 - Targeted Theft Risk"
    HIGH    = "Tier 3 - State-Level Surveillance"
    EXTREME = "Tier 4 - Extreme Adversary"


# ----------------------------------------------------------------
# Threat Profile
# ----------------------------------------------------------------

class ThreatProfile:
    def __init__(
        self,
        level,
        score,
        description,
        entropy_bits,
        recovery_required,
        shamir_required,
        passphrase_required,
        single_key_allowed,
        shamir_threshold=None,
        shamir_total_shares=None,
        entropy_policy=None
    ):
        self.level               = level
        self.score               = score
        self.description         = description
        self.entropy_bits        = entropy_bits
        self.recovery_required   = recovery_required
        self.shamir_required     = shamir_required
        self.passphrase_required = passphrase_required
        self.single_key_allowed  = single_key_allowed
        self.shamir_threshold    = shamir_threshold
        self.shamir_total_shares = shamir_total_shares
        self.entropy_policy      = entropy_policy

    def display(self):
        # ── Resolve human-readable values per tier ────────────────────────────

        # Passphrase
        passphrase_val    = "Required"     if self.passphrase_required else "Not required"
        passphrase_status = "REQUIRED"     if self.passphrase_required else "—"

        # Single key
        single_key_val    = "Allowed"      if self.single_key_allowed  else "Not allowed"

        # Shamir shares
        if self.shamir_required:
            shamir_val    = f"{self.shamir_threshold} of {self.shamir_total_shares} shares"
            shamir_status = "REQUIRED"
        else:
            shamir_val    = "Not required"
            shamir_status = "—"

        # Recovery backup — always tier-aware, independent of recovery_required flag
        if self.level == ThreatLevel.LOW:
            recovery_val    = "PBKDF2 + AES-256-GCM encrypted file"
            recovery_status = "REQUIRED"
        elif self.level == ThreatLevel.MEDIUM:
            recovery_val    = "Argon2 + (keyfile) + AES-256-GCM"
            recovery_status = "REQUIRED"
        elif self.level == ThreatLevel.HIGH:
            recovery_val    = "Shamir SLIP39"
            recovery_status = "REQUIRED"
        else:  # EXTREME
            recovery_val    = "Shamir SLIP39 (single-use)"
            recovery_status = "REQUIRED"

        # ── Build table rows ──────────────────────────────────────────────────
        rows = [
            ("Assigned Tier",       self.level,                  "ACTIVE"),
            ("Threat Score",        f"{self.score} / 11",        "—"),
            ("Profile Summary",     self.description,            "—"),
            ("Entropy Requirement", f"{self.entropy_bits} bits", "REQUIRED"),
            ("Passphrase",          passphrase_val,              passphrase_status),
            ("Recovery Backup",     recovery_val,                recovery_status),
            ("Shamir Shares",       shamir_val,                  shamir_status),
            ("Single Key",          single_key_val,              "—"),
        ]

        # ── Column widths ─────────────────────────────────────────────────────
        col1 = 22   # Name
        col2 = 42   # Value — widened to fit full profile summary
        col3 = 8    # Status

        # ── Print table ───────────────────────────────────────────────────────
        print("\n[Threat Profile — Active Configuration]\n")
        print(f"  {'Name':<{col1}} {'Value':<{col2}} {'Status':<{col3}}")
        print(f"  {'----':<{col1}} {'-----':<{col2}} {'------':<{col3}}")

        for name, value, status in rows:
            # Truncate value if too long to keep table aligned
            if len(str(value)) > col2 - 1:
                value = str(value)[:col2 - 4] + "..."
            print(f"  {name:<{col1}} {str(value):<{col2}} {status:<{col3}}")

        print()


# ----------------------------------------------------------------
# Tier Descriptions — used in override menu
# ----------------------------------------------------------------

TIER_DESCRIPTIONS = {
    ThreatLevel.LOW: {
        "name":        "Tier 1 — Casual User",
        "description": "Basic protection against device loss or opportunistic malware.",
        "requires":    "System + dice entropy. No passphrase. No recovery shares.",
    },
    ThreatLevel.MEDIUM: {
        "name":        "Tier 2 — Targeted Theft Risk",
        "description": "Increased protection against targeted digital theft.",
        "requires":    "System + dice entropy. No passphrase. Vault auto-destroys after 3 accesses.",
    },
    ThreatLevel.HIGH: {
        "name":        "Tier 3 — State-Level Surveillance",
        "description": "Protection against surveillance and advanced attack models.",
        "requires":    "Passphrase + external entropy + Shamir recovery shares (3-of-5).",
    },
    ThreatLevel.EXTREME: {
        "name":        "Tier 4 — Extreme Adversary",
        "description": "Assumes full device compromise and coercive adversary.",
        "requires":    "Strong passphrase + external entropy + Shamir shares. Single-use vault.",
    },
}


# ----------------------------------------------------------------
# Threat Model Engine
# ----------------------------------------------------------------

class ThreatModelEngine:

    def assess(self):
        """
        Option 3 Combined Approach:
        1. Guided 6-question weighted questionnaire
        2. Recommended tier displayed with explanation
        3. User accepts or manually overrides
        4. Profile confirmed → entropy collection begins
        """

        print("\n[Threat Assessment]")
        print("----------------------------------------")
        print("We will ask you a few questions to recommend")
        print("the appropriate security profile for your needs.")
        print("You can accept our recommendation or choose manually.")
        print("----------------------------------------\n")

        score = 0
        sovereignty_ready = True

        # ---- Q1: Holdings Value (weighted 0-3) ----
        print("Q1. What is the approximate value of the crypto holdings")
        print("    you are securing?")
        print("      1. Under £1,000")
        print("      2. £1,000 – £10,000")
        print("      3. £10,000 – £100,000")
        print("      4. Over £100,000")

        while True:
            q1 = input("    Your choice (1-4): ").strip()
            if q1 in ("1", "2", "3", "4"):
                score += int(q1) - 1
                break
            print("    [!] Please enter 1, 2, 3, or 4.")

        # ---- Q2: Digital Threat (weight: 2) ----
        print("\nQ2. Are you concerned about targeted phishing, malware,")
        print("    or compromised devices? (y/n): ", end="")
        q2 = input().strip().lower()
        if q2 == "y":
            score += 2

        # ---- Q3: Physical Threat (weight: 3) ----
        print("\nQ3. Is physical coercion, theft, or confiscation")
        print("    a realistic concern for you? (y/n): ", end="")
        q3 = input().strip().lower()
        if q3 == "y":
            score += 3

        # ---- Q4: Internet Connectivity (weight: 2) ----
        print("\nQ4. Will this device or USB ever connect")
        print("    to the internet? (y/n): ", end="")
        q4 = input().strip().lower()
        if q4 == "y":
            score += 2

        # ---- Q5: Private Location (weight: 1) ----
        print("\nQ5. Are you generating this key in a private,")
        print("    secure location? (y/n): ", end="")
        q5 = input().strip().lower()
        if q5 == "n":
            score += 1   # answering no increases risk score

        # ---- Q6: Sovereignty Readiness (capability gate) ----
        print("\nQ6. Are you comfortable managing your own recovery shares")
        print("    without any third-party backup service? (y/n): ", end="")
        q6 = input().strip().lower()
        if q6 == "n":
            sovereignty_ready = False

        # ---- Classify recommendation ----
        recommended_level = self._classify_score(score)

        # Apply sovereignty gate — cap at Tier 2 if not ready
        if not sovereignty_ready and recommended_level in (
            ThreatLevel.HIGH, ThreatLevel.EXTREME
        ):
            recommended_level = ThreatLevel.MEDIUM
            sovereignty_capped = True
        else:
            sovereignty_capped = False

        # ---- Display recommendation ----
        tier_info = TIER_DESCRIPTIONS[recommended_level]

        print("\n========================================")
        print("        THREAT ASSESSMENT RESULT")
        print("========================================")
        print(f"  Score:           {score} / 11")
        print(f"  Recommended:     {tier_info['name']}")
        print(f"  Description:     {tier_info['description']}")
        print(f"  Requirements:    {tier_info['requires']}")

        if sovereignty_capped:
            print()
            print("  [!] Note: Tier 3 and Tier 4 require managing Shamir")
            print("      recovery shares without third-party assistance.")
            print("      Based on your answer, Tier 2 is recommended as")
            print("      the highest appropriate tier for your current")
            print("      operational setup. You may still override below.")

        print("========================================\n")

        # ---- Accept or override ----
        accept = input("Accept recommendation? (y/n): ").strip().lower()

        if accept == "y":
            final_level = recommended_level
        else:
            final_level = self._manual_override()

        # ---- Build and return profile ----
        profile = self._build_profile(final_level, score)
        profile.entropy_policy = self._build_entropy_policy(profile)

        # Confirm profile selection before returning to lifecycle
        tier_info = TIER_DESCRIPTIONS[final_level]
        print()
        print(f"[✓] Security profile confirmed: {tier_info['name']}")
        print()

        return profile

    def _classify_score(self, score: int) -> str:
        """Maps score to threat level."""
        if score <= 2:
            return ThreatLevel.LOW
        elif score <= 5:
            return ThreatLevel.MEDIUM
        elif score <= 8:
            return ThreatLevel.HIGH
        else:
            return ThreatLevel.EXTREME

    def _manual_override(self) -> str:
        """
        Displays all four tiers with descriptions.
        User selects their preferred tier manually.
        """
        print("\n[Manual Tier Selection]")
        print("----------------------------------------")

        tiers = [
            ThreatLevel.LOW,
            ThreatLevel.MEDIUM,
            ThreatLevel.HIGH,
            ThreatLevel.EXTREME,
        ]

        for i, level in enumerate(tiers, 1):
            info = TIER_DESCRIPTIONS[level]
            print(f"\n  {i}. {info['name']}")
            print(f"     {info['description']}")
            print(f"     Requires: {info['requires']}")

        print()

        while True:
            choice = input("Your choice (1-4): ").strip()
            if choice in ("1", "2", "3", "4"):
                return tiers[int(choice) - 1]
            print("[!] Please enter 1, 2, 3, or 4.")

    def _build_profile(self, level: str, score: int) -> ThreatProfile:
        """Builds a ThreatProfile from the confirmed tier level."""

        if level == ThreatLevel.LOW:
            return ThreatProfile(
                level=ThreatLevel.LOW,
                score=score,
                description="Basic protection against device loss or opportunistic malware.",
                entropy_bits=256,
                recovery_required=False,
                shamir_required=False,
                passphrase_required=False,
                single_key_allowed=True,
                shamir_threshold=None,
                shamir_total_shares=None,
            )

        elif level == ThreatLevel.MEDIUM:
            return ThreatProfile(
                level=ThreatLevel.MEDIUM,
                score=score,
                description="Increased protection against targeted digital theft.",
                entropy_bits=256,
                recovery_required=True,
                shamir_required=False,
                passphrase_required=False,
                single_key_allowed=True,
                shamir_threshold=None,
                shamir_total_shares=None,
            )

        elif level == ThreatLevel.HIGH:
            return ThreatProfile(
                level=ThreatLevel.HIGH,
                score=score,
                description="Protection against surveillance and advanced attack models.",
                entropy_bits=384,
                recovery_required=True,
                shamir_required=True,
                passphrase_required=True,
                single_key_allowed=True,
                shamir_threshold=3,
                shamir_total_shares=5,
            )

        else:  # EXTREME
            return ThreatProfile(
                level=ThreatLevel.EXTREME,
                score=score,
                description="Assumes full device compromise and coercive adversary.",
                entropy_bits=512,
                recovery_required=True,
                shamir_required=True,
                passphrase_required=True,
                single_key_allowed=False,
                shamir_threshold=3,
                shamir_total_shares=5,
            )

    def _build_entropy_policy(self, profile: ThreatProfile) -> EntropyPolicy:
        """Builds the EntropyPolicy for the confirmed profile."""

        if profile.level == ThreatLevel.LOW:
            return EntropyPolicy(
                require_system=True,
                require_dice=True,
                require_external=False,
                require_passphrase=False,
                min_dice_bits=128,
                total_required_bits=256,
            )

        elif profile.level == ThreatLevel.MEDIUM:
            return EntropyPolicy(
                require_system=True,
                require_dice=True,
                require_external=False,
                require_passphrase=False,
                min_dice_bits=128,
                total_required_bits=256,
            )

        elif profile.level == ThreatLevel.HIGH:
            return EntropyPolicy(
                require_system=True,
                require_dice=True,
                require_external=True,
                require_passphrase=True,
                min_dice_bits=128,
                total_required_bits=384,
            )

        else:  # EXTREME
            return EntropyPolicy(
                require_system=True,
                require_dice=True,
                require_external=True,
                require_passphrase=True,
                min_dice_bits=256,
                total_required_bits=512,
            )