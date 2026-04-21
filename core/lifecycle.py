from entropy.system import get_system_entropy
from entropy.dice import collect_dice_entropy
from entropy.external_file import collect_external_entropy
from entropy.mixer import mix_entropy
from entropy.commitment_lock import CommitmentLock
from core.threat_model import ThreatModelEngine, ThreatLevel
from core.entropy_context import EntropyContext
from core.policy_enforcer import EntropyPolicyEnforcer
from core.exceptions import EntropyPolicyError
from seed.bip39 import BIP39
from security.passphrase import enforce_passphrase
from security.wipe import MemoryWiper
from security.adaptive_controller import AdaptiveSeedController
from security.tier_policy import TierLevel
from interaction.progressive_reveal import RevealStage
from seed.display import display_mnemonic, clear_screen
from seed.verify import verify_user_recorded_mnemonic
from recovery.slip39 import generate_shares
from utils.qr import print_qr
from utils.display import atm_prompt, c, Colours
from core.state import NetworkStateMonitor
import hashlib
import random

# ----------------------------------------------------------------
# Domain 1 → Domain 3 Tier Mapping
# Maps ThreatLevel string constants to TierLevel enum values.
# ----------------------------------------------------------------

THREAT_TO_TIER = {
    ThreatLevel.LOW:     TierLevel.TIER_1,
    ThreatLevel.MEDIUM:  TierLevel.TIER_2,
    ThreatLevel.HIGH:    TierLevel.TIER_3,
    ThreatLevel.EXTREME: TierLevel.TIER_4,
}


class LifecycleController:

    def __init__(self, verbose=False, quiet=False, monitor=None):
        self.state   = None
        self.verbose = verbose
        self.quiet   = quiet
        self.monitor = monitor  # NetworkStateMonitor instance

    def _checkpoint(self, context: str, buffers: list = None) -> None:
        if self.monitor:
            self.monitor.check_checkpoint(context, sensitive_buffers=buffers or [])

    # ---------------- Secure Memory Utilities ----------------

    @staticmethod
    def secure_wipe(buffer):
        """
        Overwrite a bytearray in-place with zeros.
        """
        if isinstance(buffer, bytearray):
            for i in range(len(buffer)):
                buffer[i] = 0

    @staticmethod
    def fingerprint(data: bytes) -> str:
        """
        Deterministic 8-byte (16 hex char) fingerprint.
        """
        return hashlib.sha256(data).hexdigest()[:16]

    # ---------------- Generation Flow ----------------

    def start_generation(self):
        print("\n[Generation Mode]")

        # ----------------------------------------------------------------
        # DOMAIN 1 — Entropy Generation
        # ----------------------------------------------------------------

        # 1️⃣ Threat Assessment
        engine = ThreatModelEngine()
        profile = engine.assess()
        profile.display()
        self._checkpoint("generation/entropy")

        # ── Transition: profile confirmed → entropy collection ────────────
        print("----------------------------------------")
        print("Threat profile confirmed. Ready to begin entropy collection.")
        print("----------------------------------------")
        print()
        input(atm_prompt("generation/entropy") + " Press ENTER to begin entropy collection...")
        print()

        # 2️⃣ Entropy Collection (Policy-Governed)
        context = EntropyContext()
        policy = profile.entropy_policy

        try:
            # --- System Entropy ---
            if policy.require_system:
                import time as _time
                print("[+] Collecting System Entropy")
                print("----------------------------------------")
                _time.sleep(0.3)
                print("    → reading from OS CSPRNG...")
                _time.sleep(0.5)
                print("    → verifying output size...")
                _time.sleep(0.5)
                system_entropy, system_score = get_system_entropy(profile.entropy_bits)

                if not system_entropy or not isinstance(system_entropy, bytes):
                    raise ValueError("System entropy invalid")

                context.system_entropy = bytearray(system_entropy)
                context.system_bits = profile.entropy_bits
                print(f"[✓] System entropy collected — {profile.entropy_bits} bits (distribution: {system_score:.4f} bits/byte)")
                print()

            # --- Dice Entropy ---
            if policy.require_dice:
                # Tier-aware minimum roll requirement
                if profile.level == ThreatLevel.EXTREME:
                    min_rolls = 100
                else:
                    min_rolls = 50

                print("[+] Dice Entropy Collection")
                print("----------------------------------------")
                print("This step collects physical entropy from dice rolls.")
                print("Your physical input adds true randomness that no")
                print("software source alone can replicate.")
                print()
                print("You will need:")
                print("  → A fair 6-sided die")
                print(f"  → At least {min_rolls} rolls")
                print()
                print("  ★ Pro tip: Casino-grade dice are precision-manufactured")
                print("    for fairness and will produce higher quality entropy.")
                print("----------------------------------------")
                print()
                input(atm_prompt("generation/entropy") + " Press ENTER when you are ready to begin rolling...")
                print()
                dice_entropy, dice_physical_bits = collect_dice_entropy(min_rolls=min_rolls)

                if not dice_entropy or not isinstance(dice_entropy, bytes):
                    raise ValueError("Dice entropy invalid")

                context.dice_entropy = bytearray(dice_entropy)
                context.dice_bits = int(dice_physical_bits)

            # --- External Entropy ---
            print()
            if policy.require_external:
                print("[+] External Entropy Collection")
                print("----------------------------------------")
                print("This tier requires an external entropy file.")
                print("Any file type is accepted — the file's SHA-256 hash")
                print("is used as the entropy contribution.")
                print()
                print("  → Use a unique personal file (photo, document, custom data)")
                print("  → The file fingerprint will be recorded for verification")
                print("----------------------------------------")
                print()
            else:
                print("[+] External Entropy Collection (Optional)")
                print("----------------------------------------")
                print("You may provide any file as an additional entropy source.")
                print("Its SHA-256 hash will be mixed into the entropy pool.")
                print("Press ENTER to skip if you do not have one.")
                print("----------------------------------------")
                print()

            external_data = collect_external_entropy()

            if external_data:
                external_entropy, fingerprint_value, raw_size = external_data
                context.external_entropy = bytearray(external_entropy)
                context.external_bits = raw_size * 8
                context.external_fingerprint = fingerprint_value
                print(f"[✓] External entropy loaded — {context.external_bits} bits")
                print()

            elif policy.require_external:
                from core.exceptions import MissingRequiredSourceError
                raise MissingRequiredSourceError(
                    "External entropy is required for this threat tier."
                )
            else:
                if not self.quiet:
                    print("[i] External entropy skipped.")
                print()

            # --- Policy Validation ---
            EntropyPolicyEnforcer.validate(
                policy=policy,
                context=context,
            )

        except EntropyPolicyError as e:
            print(f"\n[Policy Violation] {str(e)}")
            print("Entropy requirements not satisfied. Aborting generation.")
            return None

        # 3️⃣ Pre-Mix Fingerprints
        system_fp   = self.fingerprint(context.system_entropy)   if context.system_entropy   else None
        dice_fp     = self.fingerprint(context.dice_entropy)     if context.dice_entropy     else None
        external_fp = context.external_fingerprint               if context.external_entropy else None

        # 4️⃣ Entropy Governance Report
        col1 = 22
        col2 = 27
        border     = f"+{'-' * (col1 + 2)}+{'-' * (col2 + 2)}+"
        header_row = lambda a, b: f"| {a:<{col1}} | {b:<{col2}} |"

        print("\n========================================")
        print("        ENTROPY GOVERNANCE REPORT")
        print("========================================")

        if self.verbose:
            print("\n[SOURCE INTEGRITY]")
            print(border)
            print(header_row("Source", "Fingerprint"))
            print(border)
            if system_fp:
                print(header_row("System", system_fp))
            if dice_fp:
                print(header_row("Dice", dice_fp))
            if external_fp:
                print(header_row("External", external_fp))
            print(border)

        total_bits = (
            (context.system_bits or 0) +
            (context.dice_bits or 0) +
            (context.external_bits or 0)
        )

        print("\n[PRE-MIX ENTROPY ACCOUNTING]")
        print(border)
        print(header_row("Source", "Contribution"))
        print(border)

        if context.system_entropy:
            print(header_row("System entropy", f"{context.system_bits} bits"))
        if context.dice_entropy:
            print(header_row("Dice entropy", f"{context.dice_bits} bits (physical est.)"))
        if context.external_entropy:
            print(header_row("External entropy", f"{context.external_bits} bits (informational)"))
        else:
            print(header_row("External entropy", "Not provided"))

        print(border)
        print(header_row("Total measurable", f"{total_bits} bits"))
        print(header_row("Policy threshold", f"{policy.total_required_bits} bits"))
        print(header_row("Status", "SATISFIED"))
        print(border)
        print("========================================\n")

        input(atm_prompt("generation/entropy") + " Press ENTER to begin entropy mixing...")
        print()

        # 5️⃣ Entropy Mixing
        entropy_sources = [
            context.system_entropy,
            context.dice_entropy,
            context.external_entropy,
        ]
        entropy_sources = [src for src in entropy_sources if src]

        mixed = mix_entropy(*entropy_sources)
        final_entropy = bytearray(mixed)

        print("[+] Mixing complete.")
        print(f"[+] Final entropy size: {len(final_entropy) * 8} bits")
        self._checkpoint("generation/entropy/commit")

        # 6️⃣ Commitment Lock — Domain 1 Boundary Seal
        commitment = CommitmentLock(bytes(final_entropy))

        print("\n[ENTROPY COMMITMENT LOCK]")
        print("----------------------------------------")
        print(f"Commitment fingerprint: {commitment.fingerprint()}")

        if self.verbose:
            print(f"Full commitment hash:   {commitment.full_hash()}")
            print("\n[FINAL ENTROPY]")
            print("----------------------------------------")
            print(f"Output size:   {len(final_entropy) * 8} bits")
            print(f"Fingerprint:   {self.fingerprint(final_entropy)}")

        print("----------------------------------------")
        print()
        print("  This fingerprint proves the entropy state was sealed before")
        print("  your mnemonic was generated. Advanced users may record this")
        print("  for audit purposes. It is not required for wallet recovery.")
        print("----------------------------------------\n")

        input(atm_prompt("generation/entropy/commit") + " Press ENTER to continue...")
        print()

        # 7️⃣ Secure Source Cleanup
        print("[Secure Cleanup] Overwriting source entropy buffers...")

        for src in entropy_sources:
            self.secure_wipe(src)

        if context.system_entropy:
            self.secure_wipe(context.system_entropy)
        if context.dice_entropy:
            self.secure_wipe(context.dice_entropy)
        if context.external_entropy:
            self.secure_wipe(context.external_entropy)

        del entropy_sources
        del context

        print("[Secure Cleanup] Source entropy wiped.\n")
        self._checkpoint("generation/seed")

        # ----------------------------------------------------------------
        # DOMAIN 2 — BIP39 Mnemonic Generation
        # ----------------------------------------------------------------

        print("[Domain 2] Generating BIP39 mnemonic...")

        mnemonic = BIP39.entropy_to_mnemonic(bytes(final_entropy))

        # Wipe final_entropy immediately — Domain 2 owns it and is done with it
        self.secure_wipe(final_entropy)
        del final_entropy

        print(c("[+] Mnemonic generated.", Colours.GREEN))
        print("[Secure Cleanup] Final entropy wiped.\n")

        input(atm_prompt("generation/seed") + " Press ENTER to continue to security hardening...")
        print()

        # ----------------------------------------------------------------
        # DOMAIN 1 → DOMAIN 3 BRIDGE — Tier Mapping
        # ----------------------------------------------------------------
        self._checkpoint(
            "generation/security",
            buffers=[bytearray(mnemonic.encode())]
        )
        tier = THREAT_TO_TIER[profile.level]

        print(f"[Domain 3] Security tier assigned: {tier.name}")

        # ----------------------------------------------------------------
        # DOMAIN 3 — Seed Security Hardening
        # ----------------------------------------------------------------

        # 1️⃣ Passphrase enforcement (only if tier policy requires it)
        if profile.passphrase_required:
            print("\n[Domain 3] Passphrase protection required for this threat tier.")
            passphrase = enforce_passphrase(profile)
        else:
            passphrase = ""
            print("[Domain 3] Passphrase not required for this threat tier.")

        # 2️⃣ Construct AdaptiveSeedController
        # This internally creates SeedVault + IntegrityGuard
        # and enforces all TierPolicy rules from this point forward.
        print("\n[Domain 3] Initialising adaptive seed controller...")

        controller = AdaptiveSeedController(mnemonic, tier, passphrase)

        print(f"[+] Controller ready — Tier: {tier.name}")

        # 3️⃣ Progressive Reveal — STAGE 1
        # Hash preview only. No confirmation required.
        controller.request_reveal(RevealStage.STAGE_1)

        print("\n[Progressive Reveal — Stage 1]")
        print("----------------------------------------")
        print(f"Entropy commitment fingerprint: {commitment.fingerprint()}")
        print("Commitment anchors the entropy state prior to seed derivation.")
        print("----------------------------------------")

        input(atm_prompt("generation/entropy") + " Press ENTER to continue to mnemonic reveal...")

        # 4️⃣ Progressive Reveal — STAGE 2
        # Mnemonic reveal. Requires simple "yes" confirmation.
        print("\n[Progressive Reveal — Stage 2]")
        print("----------------------------------------")
        print("You are about to view your 24-word mnemonic seed phrase.")
        print("Ensure no cameras, screens, or unauthorised persons are present.")
        print("----------------------------------------")

        user_input = input(atm_prompt("generation/seed") + ' Type "yes" to reveal your mnemonic: ').strip()
        controller.request_reveal(RevealStage.STAGE_2, user_input)

        print("\n[MNEMONIC — WRITE THIS DOWN SECURELY]")
        print("========================================")
        print("Do NOT photograph this. Write it on paper. Store it offline.")

        display_mnemonic(mnemonic)

        input(atm_prompt("generation/seed") + " Press ENTER once you have written down your mnemonic...")

        clear_screen()

        try:
            verify_user_recorded_mnemonic(mnemonic)
        except Exception as e:
            print(f"\n[Verification Failed] {str(e)}")
            print("Restart generation to ensure seed safety.")
            return None

        # 5️⃣ Seed Fingerprint — displayed for all tiers
        # Computed at controller construction — no vault access required
        # Tier 3 + 4 require typed confirmation before display

        if tier in (TierLevel.TIER_3, TierLevel.TIER_4):
            print("\n[Seed Fingerprint Access]")
            print("----------------------------------------")
            print("Your seed fingerprint is about to be displayed.")
            print("This fingerprint is derived from your seed.")
            print("Required confirmation phrase:")
            print('  "I UNDERSTAND THIS IS DERIVED FROM MY SEED"')
            print("----------------------------------------")

            user_input = input(atm_prompt("generation/security") + " Type confirmation phrase exactly: ").strip()

            if user_input != "I UNDERSTAND THIS IS DERIVED FROM MY SEED":
                print("\n[!] Confirmation phrase incorrect.")
                print("[!] Seed fingerprint will not be displayed.")
                print("[!] You can still verify later using your mnemonic and passphrase.")
            else:
                print("\n[SEED FINGERPRINT]")
                print("----------------------------------------")
                print(f"Seed fingerprint: {controller.seed_commitment}")
                print("Record this alongside your mnemonic.")
                print("Use for future verification without re-exposing your seed.")
                print("----------------------------------------")

                print_qr(controller.seed_commitment, label="Seed Fingerprint")

                input(atm_prompt("generation/security") + " Press ENTER once you have recorded your seed fingerprint...")

                clear_screen()

                # Confirm user recorded the fingerprint — random group challenge
                groups = controller.seed_commitment.split("-")
                index = random.randint(0, len(groups) - 1)

                print("\n[Seed Fingerprint Verification]")
                print("----------------------------------------")
                print("Confirm you recorded the fingerprint correctly.")
                print("----------------------------------------")

                while True:
                    recorded = input(atm_prompt("generation/security") + f" Enter group #{index + 1} of the fingerprint: ").strip().upper()

                    if recorded == groups[index]:
                        print("\n[✓] Verification successful.")
                        print("Fingerprint recorded correctly.\n")
                        input(atm_prompt("generation/security") + " Press ENTER to continue...")
                        clear_screen()
                        break
                    else:
                        print("[!] Incorrect. Check your recording and try again.")
        else:
            print("\n[SEED FINGERPRINT]")
            print("----------------------------------------")
            print(f"Seed fingerprint: {controller.seed_commitment}")
            print("Record this alongside your mnemonic.")
            print("Use for future verification without re-exposing your seed.")
            print("----------------------------------------")

            print_qr(controller.seed_commitment, label="Seed Fingerprint")

            input(atm_prompt("generation/security") + " Press ENTER once you have recorded your seed fingerprint...")

            clear_screen()

            # Confirm user recorded the fingerprint — random group challenge
            groups = controller.seed_commitment.split("-")
            index = random.randint(0, len(groups) - 1)

            print("\n[Seed Fingerprint Verification]")
            print("----------------------------------------")
            print("Confirm you recorded the fingerprint correctly.")
            print("----------------------------------------")

            while True:
                recorded = input(atm_prompt("generation/security") + f" Enter group #{index + 1} of the fingerprint: ").strip().upper()

                if recorded == groups[index]:
                    print("\n[✓] Verification successful.")
                    print("Fingerprint recorded correctly.\n")
                    input(atm_prompt("generation/security") + " Press ENTER to continue...")
                    clear_screen()
                    break
                else:
                    print("[!] Incorrect. Check your recording and try again.")

        print("\n[Domain 3] Seed hardening complete.")
        print("[Domain 3] Vault will auto-destroy per tier policy.\n")
        self._checkpoint("generation/recovery")

        # ----------------------------------------------------------------
        # DOMAIN 4 — Recovery Backup (tier-adaptive)
        # ----------------------------------------------------------------

        from seed.bip39 import BIP39 as BIP39Local

        # Recover entropy from mnemonic for backup encryption
        backup_entropy = BIP39Local.mnemonic_to_entropy(mnemonic)

        if profile.shamir_required:
            # ---- Tier 3 + 4 — Shamir SLIP39 shares ----
            shares = generate_shares(mnemonic)
            labels = {}   # share index → location label string

            # Extract Share Set ID from commitment fingerprint (first 6 chars)
            share_set_id = commitment.fingerprint()[:6].upper()

            print("\n[RECOVERY SHARE BACKUP]")
            print("----------------------------------------")
            print("SLIP39 recovery shares will now be displayed.")
            print("You must record each share carefully.")
            print(f"Total shares: {len(shares)} | Threshold: 3 of {len(shares)} required")
            print("----------------------------------------")
            input(atm_prompt("generation/recovery") + " Press ENTER to begin...")

            for i, share in enumerate(shares, 1):

                clear_screen()

                # ── Display share ─────────────────────────────────────────
                print(f"\n[Share {i} of {len(shares)}]")
                print("========================================")
                print("Write this share down exactly as shown.")
                print("========================================\n")
                print(share)
                print("\n----------------------------------------")
                input(atm_prompt("generation/recovery") + " Press ENTER once you have written this share...")

                clear_screen()

                # ── Per-share word challenge ───────────────────────────────
                words     = share.split()
                challenge = random.randint(0, len(words) - 1)

                print(f"\n[Share {i} Verification]")
                print("----------------------------------------")
                print(f"Confirm you recorded Share {i} correctly.")
                print("----------------------------------------")

                while True:
                    answer = input(
                        atm_prompt("generation/recovery") +
                        f" Enter word #{challenge + 1} of Share {i}: "
                    ).strip().lower()

                    if answer == words[challenge]:
                        print(f"[✓] Share {i} verified correctly.\n")
                        break
                    else:
                        print(f"[!] Incorrect. Check your recording of Share {i} and try again.")

                # ── Optional location label ────────────────────────────────
                raw_label = input(
                    atm_prompt("generation/recovery") +
                    f" Location label for Share {i} (press ENTER to skip): "
                ).strip()

                if raw_label:
                    if len(raw_label) > 30:
                        raw_label = raw_label[:30]
                        print(f"[!] Label trimmed to 30 characters: '{raw_label}'")
                    labels[i] = raw_label
                    print(f"[✓] Label recorded: '{raw_label}'\n")

            # ── Post-shares: distribution map ─────────────────────────────
            clear_screen()
            print("\nAll recovery shares have been displayed.")
            print("Ensure they are stored in separate secure locations.\n")

            if labels:
                self._display_distribution_map(
                    labels=labels,
                    share_set_id=share_set_id,
                    total_shares=len(shares),
                    threshold=3,
                )
            else:
                if not self.quiet:
                    if not self.quiet:
                        print("[i] No location labels entered — distribution map skipped.\n")

        else:
            # ---- Tier 1 + 2 — Encrypted backup ----
            from recovery.encrypted_backup import (
                encrypt_tier1, encrypt_tier2, generate_keyfile,
                save_backup_file, EncryptedBackupError
            )

            import getpass as _getpass

            # Collect password — shared for both tiers
            print("\n[ENCRYPTED BACKUP]")
            print("----------------------------------------")
            print("Your entropy will be encrypted with a backup password.")
            print("You will need this password to recover your mnemonic.")
            print("----------------------------------------\n")

            while True:
                backup_password = _getpass.getpass(
                    "Enter backup password: "
                ).strip()
                confirm_password = _getpass.getpass(
                    "Confirm backup password: "
                ).strip()
                if not backup_password:
                    print("[!] Password cannot be empty. Try again.")
                    continue
                if backup_password != confirm_password:
                    print("[!] Passwords do not match. Try again.")
                    continue
                break

            if tier == TierLevel.TIER_1:
                # ---- Tier 1 — Single factor encrypted file ----
                print("\n[Tier 1 Recovery — Encrypted File Backup]")
                print("----------------------------------------")
                print("Your encrypted backup will be saved as a .atm file.")
                print("Specify the path to your backup USB drive.")
                print("Example: E:\\mybackup  or  /media/usb/mybackup")
                print("----------------------------------------")

                while True:
                    filepath = input(atm_prompt("generation/recovery") + " Enter save path (without extension): ").strip()

                    if not filepath:
                        print("[!] No path provided.")
                        retry = input("    Try again? (y/n): ").strip().lower()
                        if retry != "y":
                            print("[i] Backup not saved.")
                            break
                        continue

                    try:
                        payload = encrypt_tier1(backup_entropy, backup_password)
                        save_backup_file(payload, filepath)
                        print(f"\n[✓] Backup saved: {filepath}.atm")
                        print("[✓] Store this USB in a safe offline location.")
                        print("[✓] Remember your backup password.")
                        break
                    except EncryptedBackupError as e:
                        print(f"\n[!] Failed to save backup: {e}")
                        retry = input("    Try a different path? (y/n): ").strip().lower()
                        if retry != "y":
                            print("[i] Backup not saved.")
                            break

            else:
                # ---- Tier 2 — Three-factor encrypted backup ----
                print("\n[Tier 2 Recovery — Three-Factor Encrypted Backup]")
                print("----------------------------------------")
                print("Recovery requires THREE factors:")
                print("  1. Encrypted backup file (.atm)")
                print("  2. Your backup password")
                print("  3. Your keyfile (store on a separate USB)")
                print("----------------------------------------\n")

                # Keyfile — generate or provide
                print("Keyfile options:")
                print("  1. Generate a random keyfile now")
                print("  2. Use an existing keyfile (VeraCrypt, KeePassXC, etc.)")

                while True:
                    kf_choice = input(atm_prompt("generation/recovery") + " Your choice (1-2): ").strip()
                    if kf_choice in ("1", "2"):
                        break
                    print("[!] Please enter 1 or 2.")

                if kf_choice == "1":
                    print("\nSpecify where to save the generated keyfile.")
                    print("Example: E:\\mykeyfile.key  or  /media/usb/mykeyfile.key")

                    while True:
                        keyfile_path = input(atm_prompt("generation/recovery") + " Keyfile save path: ").strip()
                        if not keyfile_path:
                            print("[!] No path provided.")
                            retry = input("    Try again? (y/n): ").strip().lower()
                            if retry != "y":
                                print("[i] Keyfile not saved. Aborting.")
                                return None
                            continue
                        try:
                            generate_keyfile(keyfile_path)
                            print(f"\n[✓] Keyfile generated: {keyfile_path}")
                            print("[!] Store this keyfile on a SEPARATE USB from the backup.")
                            print("[!] You MUST have this keyfile to recover your seed.")
                            break
                        except EncryptedBackupError as e:
                            print(f"\n[!] Failed to generate keyfile: {e}")
                            retry = input("    Try a different path? (y/n): ").strip().lower()
                            if retry != "y":
                                print("[i] Keyfile not saved. Aborting.")
                                return None
                else:
                    keyfile_path = input(atm_prompt("generation/recovery") + " Enter path to your existing keyfile: ").strip()
                    if not keyfile_path:
                        print("[!] No keyfile path provided. Aborting.")
                        return None

                # Save backup
                print("\nSpecify where to save the encrypted backup file.")
                print("Example: E:\\mybackup  or  /media/usb/mybackup")

                while True:
                    filepath = input(atm_prompt("generation/recovery") + " Backup save path (without extension): ").strip()

                    if not filepath:
                        print("[!] No path provided.")
                        retry = input("    Try again? (y/n): ").strip().lower()
                        if retry != "y":
                            print("[i] Backup not saved.")
                            break
                        continue

                    try:
                        payload = encrypt_tier2(
                            backup_entropy, backup_password, keyfile_path
                        )
                        save_backup_file(payload, filepath)
                        print(f"\n[✓] Encrypted backup saved: {filepath}.atm")
                        print("[✓] Store backup file and keyfile in SEPARATE locations.")
                        print("[✓] Remember your backup password.")
                        print("[!] All three are required to recover your seed.")
                        break
                    except EncryptedBackupError as e:
                        print(f"\n[!] Encryption failed: {e}")
                        retry = input("    Try a different path? (y/n): ").strip().lower()
                        if retry != "y":
                            print("[i] Backup not saved.")
                            break

        # Wipe backup entropy from memory
        backup_entropy_buf = bytearray(backup_entropy)
        MemoryWiper().wipe(backup_entropy_buf)
        del backup_entropy_buf
        del backup_entropy

        # Wipe mnemonic from memory
        mnemonic_buffer = bytearray(mnemonic.encode())
        MemoryWiper().wipe(mnemonic_buffer)
        del mnemonic_buffer
        del mnemonic

        print("\n[Secure Cleanup] Mnemonic wiped from memory.")
        print("[Generation complete.]\n")

        # Nothing sensitive leaves start_generation()
        return None
    

    def _display_distribution_map(
        self,
        labels: dict,
        share_set_id: str,
        total_shares: int,
        threshold: int,
    ) -> None:
        """
        Displays the share distribution map and offers save options.

        Called after Shamir share generation if at least one location
        label was entered. The map contains no cryptographic material —
        only operational metadata about where shares are stored.
        """
        import datetime

        generated_date = datetime.date.today().isoformat()

        # ── Build map lines ───────────────────────────────────────────────
        map_lines = []
        map_lines.append(f"ATM Share Distribution Map")
        map_lines.append(f"Share Set ID : {share_set_id}")
        map_lines.append(f"Generated    : {generated_date}")
        map_lines.append(f"Threshold    : {threshold} of {total_shares} shares required")
        map_lines.append(f"")
        for idx in range(1, total_shares + 1):
            label = labels.get(idx, "(no label)")
            map_lines.append(f"Share {idx}  →  {label}")

        # ── Display map as text ───────────────────────────────────────────
        print("\n[SHARE DISTRIBUTION MAP]")
        print("=" * 44)
        for line in map_lines:
            print(f"  {line}")
        print("=" * 44)
        print()
        print("  This map contains no cryptographic material.")
        print("  Record it separately from your shares.")
        print()

        # ── Offer save options ────────────────────────────────────────────
        print("  How would you like to save this map?")
        print()
        print("  [1] Save as encrypted .atm-map file to USB")
        print("  [2] Display formatted map (photograph it)")
        print("  [3] Text display only (I have recorded it manually)")
        print("  [4] Skip")
        print()

        while True:
            choice = input(atm_prompt("generation/recovery") + " Your choice (1-4): ").strip()
            if choice in ("1", "2", "3", "4"):
                break
            print("[!] Please enter 1, 2, 3, or 4.")

        if choice == "1":
            self._save_distribution_map(map_lines, share_set_id)

        elif choice == "2":
            # Display as bordered photographable text block
            width = 42
            border_top    = "┌" + "─" * width + "┐"
            border_bottom = "└" + "─" * width + "┘"

            print()
            print(border_top)

            def _map_row(text=""):
                padding = width - len(text)
                return f"│  {text}{' ' * (padding - 2)}│"

            print(_map_row("ATM — SHARE DISTRIBUTION MAP"))
            print(_map_row())
            print(_map_row(f"Share Set ID : {share_set_id}"))
            print(_map_row(f"Generated    : {generated_date}"))
            print(_map_row(f"Threshold    : {threshold} of {total_shares} required"))
            print(_map_row())

            for idx in range(1, total_shares + 1):
                label = labels.get(idx, "(no label)")
                print(_map_row(f"Share {idx}  →  {label}"))

            print(_map_row())
            print(_map_row("Photograph this and store safely."))
            print(_map_row("No cryptographic material included."))
            print(border_bottom)
            print()
            input(atm_prompt("generation/recovery") + " Press ENTER once you have photographed this map...")

        elif choice == "3":
            print()
            print("  [✓] Map recorded manually. Proceeding.")
            print()

        elif choice == "4":
            print()
            print("  [i] Distribution map save skipped.")
            print()

    def _save_distribution_map(
        self,
        map_lines: list,
        share_set_id: str,
    ) -> None:
        """
        Saves the share distribution map as an encrypted .atm-map file.

        The file contains only location metadata — no entropy, no mnemonic,
        no shares. It is password protected so only the user can read it,
        and must be loaded through the ATM program.
        """
        import json
        import getpass as _getpass
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes
        import secrets

        print()
        print("[Encrypted Map File]")
        print("----------------------------------------")
        print("This file will be password protected.")
        print("You will need this password to view the map later.")
        print("----------------------------------------\n")

        # ── Collect password ──────────────────────────────────────────────
        while True:
            password = _getpass.getpass("Enter map password: ").strip()
            confirm  = _getpass.getpass("Confirm map password: ").strip()
            if not password:
                print("[!] Password cannot be empty. Try again.")
                continue
            if password != confirm:
                print("[!] Passwords do not match. Try again.")
                continue
            break

        # ── Encrypt map content ───────────────────────────────────────────
        try:
            salt = secrets.token_bytes(16)
            kdf  = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=260000,
            )
            key        = kdf.derive(password.encode())
            plaintext  = "\n".join(map_lines).encode()
            nonce      = secrets.token_bytes(12)
            aesgcm     = AESGCM(key)
            ciphertext = aesgcm.encrypt(nonce, plaintext, None)

            payload = {
                "format":     "atm:map:v1",
                "set_id":     share_set_id,
                "salt":       salt.hex(),
                "nonce":      nonce.hex(),
                "ciphertext": ciphertext.hex(),
            }

        except Exception as e:
            print(f"\n[!] Encryption failed: {e}")
            print("[!] Record your distribution map manually.\n")
            return

        # ── Save file — retry loop ─────────────────────────────────────────
        print("\nSpecify where to save the map file.")
        print("Example: E:\\mymap  or  /media/usb/mymap")
        print("(Ensure the directory already exists.)\n")

        while True:
            filepath = input(
                atm_prompt("generation/recovery") +
                " Save path (without extension): "
            ).strip()

            if not filepath:
                print("[!] No path provided.")
                retry = input("    Try again? (y/n): ").strip().lower()
                if retry != "y":
                    if not self.quiet:
                        print("[i] Map file not saved. Record your map manually.\n")
                    return
                continue

            full_path = filepath + ".atm-map"

            # Attempt save
            try:
                with open(full_path, "w") as f:
                    json.dump(payload, f, indent=2)

                print(f"\n[✓] Distribution map saved: {full_path}")
                print("[✓] Store this file separately from your shares.")
                if not self.quiet:
                    print("[i] This file contains no cryptographic material.")
                    print("[i] Load it through ATM to view your share locations.\n")
                return

            except Exception as e:
                print(f"\n[!] Failed to save map file: {e}")
                retry = input("    Try a different path? (y/n): ").strip().lower()
                if retry != "y":
                    if not self.quiet:
                        print("[i] Map file not saved. Record your map manually.\n")
                    return

    def _view_distribution_map(self) -> None:
        """
        Loads and decrypts an encrypted .atm-map file and displays
        the share distribution map exactly as it was originally shown.

        The file contains only location metadata — no entropy, no mnemonic,
        no shares. Password protected with PBKDF2 + AES-256-GCM.
        """
        import json
        import getpass as _getpass
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        from cryptography.hazmat.primitives import hashes

        print("\n[View Share Distribution Map]")
        print("----------------------------------------")
        print("Provide the path to your .atm-map file.")
        print("----------------------------------------\n")

        # ── File load retry loop ──────────────────────────────────────────
        import os
        while True:
            filepath = input(
                atm_prompt("verify/map") + " Enter path to .atm-map file: "
            ).strip()

            if not filepath.endswith(".atm-map"):
                filepath += ".atm-map"

            if not os.path.exists(filepath):
                print(f"\n[!] File not found: {filepath}")
                retry = input("    Try again? (y/n): ").strip().lower()
                if retry != "y":
                    print("[i] Cancelled.")
                    return
                print()
                continue

            try:
                with open(filepath, "r") as f:
                    payload = json.load(f)
                break
            except json.JSONDecodeError:
                print("\n[!] Invalid .atm-map file — file may be corrupted.")
                retry = input("    Try again? (y/n): ").strip().lower()
                if retry != "y":
                    print("[i] Cancelled.")
                    return
                print()
            except Exception as e:
                print(f"\n[!] Failed to load map file: {e}")
                retry = input("    Try again? (y/n): ").strip().lower()
                if retry != "y":
                    print("[i] Cancelled.")
                    return
                print()

        # ── Validate format ───────────────────────────────────────────────
        if payload.get("format") != "atm:map:v1":
            print("\n[!] Unrecognised file format. This may not be an ATM map file.")
            return

        # ── Collect password ──────────────────────────────────────────────
        password = _getpass.getpass("Enter map password: ").strip()

        if not password:
            print("\n[!] Password cannot be empty.")
            return

        # ── Decrypt ───────────────────────────────────────────────────────
        try:
            salt               = bytes.fromhex(payload["salt"])
            nonce              = bytes.fromhex(payload["nonce"])
            ciphertext_with_tag = bytes.fromhex(payload["ciphertext"])

            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=260000,
            )
            key = kdf.derive(password.encode())

            aesgcm    = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)

        except Exception:
            print("\n[!] Decryption failed. Incorrect password or corrupted file.")
            return

        # ── Display map ───────────────────────────────────────────────────
        map_lines = plaintext.decode().split("\n")

        print("\n[SHARE DISTRIBUTION MAP]")
        print("=" * 44)
        for line in map_lines:
            print(f"  {line}")
        print("=" * 44)
        print()
        print("  This map contains no cryptographic material.")
        print()
        input(atm_prompt("verify/map") + " Press ENTER to return to verification menu...")

    # ---------------- Recovery Flow ----------------

    def start_recovery(self):
        print("\n[Recovery Mode]")
        print("----------------------------------------")
        print("Select your recovery method:")
        print("  1. Encrypted backup  (Tier 1 / Tier 2)")
        print("  2. Shamir shares     (Tier 3 / Tier 4)")
        print("  3. Back")
        print("----------------------------------------")

        while True:
            method = input(atm_prompt("recovery") + " Your choice (1-3): ").strip()
            if method in ("1", "2", "3"):
                break
            print("[!] Please enter 1, 2, or 3.")

        if method == "1":
            self._recover_encrypted_file()
        elif method == "2":
            self._recover_shamir()
        elif method == "3":
            return

    # ----------------------------------------------------------------
    # Reconstruct Mnemonic from Shares
    # ----------------------------------------------------------------

    def _recover_shamir(self):
        """Recovery via Shamir SLIP39 shares — Tier 3 / Tier 4."""
        print("\n[Shamir Recovery]")
        print("You will need at least 3 of your 5 SLIP39 recovery shares.\n")

        shares = []
        for i in range(1, 4):
            print(f"[Share {i} of 3]")
            share = input(atm_prompt("recovery/shares") + f" Enter share {i}: ").strip()
            if not share:
                print("[!] Empty share entered. Recovery aborted.")
                return None
            shares.append(share)
            print(f"[✓] Share {i} recorded.\n")

        print("[Recovery] Reconstructing mnemonic from shares...")

        try:
            from recovery.reconstruct import reconstruct_mnemonic
            mnemonic = reconstruct_mnemonic(shares)
        except Exception as e:
            print(f"\n[!] Reconstruction failed: {e}")
            return None

        print(c("[+] Mnemonic successfully reconstructed.\n", Colours.GREEN))
        self._display_and_verify_recovered_mnemonic(mnemonic)

    def _recover_encrypted_file(self):
        """Recovery via encrypted .atm file — Tier 1 or Tier 2."""
        print("\n[Encrypted File Recovery]")
        print("Provide the path to your .atm backup file.\n")

        from recovery.encrypted_backup import (
            load_backup_file, decrypt_tier1, decrypt_tier2,
            EncryptedBackupError
        )

        # ── File load retry loop ──────────────────────────────────────────
        while True:
            filepath = input(atm_prompt("recovery/encrypted") + " Enter path to .atm file: ").strip()
            try:
                payload = load_backup_file(filepath)
                break
            except Exception as e:
                print(f"\n[!] Failed to load backup file: {e}")
                retry = input("    Try again? (y/n): ").strip().lower()
                if retry != "y":
                    print("[i] Recovery cancelled.")
                    return None
                print()

        import getpass as _getpass
        password = _getpass.getpass("Enter backup password: ").strip()

        # Detect tier from format field
        fmt = payload.get("format", "")

        try:
            if fmt == "atm:tier1:v1":
                entropy = decrypt_tier1(payload, password)

            elif fmt == "atm:tier2:v1":
                print("\nProvide your keyfile (possession factor).")
                keyfile_path = input(atm_prompt("recovery/encrypted") + " Enter path to keyfile: ").strip()
                entropy = decrypt_tier2(payload, password, keyfile_path)

            else:
                print("[!] Unknown backup format.")
                return None

        except Exception as e:
            print(f"\n[!] Decryption failed: {e}")
            return None

        from seed.bip39 import BIP39
        mnemonic = BIP39.entropy_to_mnemonic(entropy)

        # Wipe entropy immediately
        entropy_buf = bytearray(entropy)
        MemoryWiper().wipe(entropy_buf)
        del entropy_buf
        del entropy

        print(c("[+] Backup decrypted successfully.\n", Colours.GREEN))
        self._display_and_verify_recovered_mnemonic(mnemonic)

    def _display_and_verify_recovered_mnemonic(self, mnemonic: str):
        """
        Shared display and verification flow for all recovery paths.
        Displays mnemonic, optional verification, then wipes from memory.
        """
        from seed.display import display_mnemonic, clear_screen
        from seed.verify import verify_user_recorded_mnemonic

        input(atm_prompt("recovery") + " Press ENTER to display your recovered mnemonic...")
        clear_screen()
        display_mnemonic(mnemonic)
        input(atm_prompt("recovery") + " Press ENTER once you have verified your mnemonic...")
        clear_screen()

        verify_choice = input(
            atm_prompt("recovery") + " Run word verification challenge? (y/n): "
        ).strip().lower()

        if verify_choice == "y":
            try:
                verify_user_recorded_mnemonic(mnemonic)
            except Exception as e:
                print(f"\n[!] Verification failed: {e}")

        # Wipe mnemonic
        mnemonic_buffer = bytearray(mnemonic.encode())
        MemoryWiper().wipe(mnemonic_buffer)
        del mnemonic_buffer
        del mnemonic

        print("\n[Secure Cleanup] Recovered mnemonic wiped from memory.")
        print("[Recovery complete.]\n")
        return None
    
    # ---------------- Verification Flow ----------------

    def start_verification(self):
        print("\n[Verification Mode]")
        print("----------------------------------------")
        print("  1. Encrypted backup         (Tier 1 / Tier 2)")
        print("  2. Shamir shares            (Tier 3 / Tier 4)")
        print("  3. Entropy commitment audit (Advanced)")
        print("  4. View share distribution map")
        print("  5. Back")
        print("----------------------------------------")

        while True:
            method = input(atm_prompt("verify") + " Your choice (1-5): ").strip()
            if method in ("1", "2", "3", "4", "5"):
                break
            print("[!] Please enter 1, 2, 3, 4, or 5.")

        if method == "1":
            self._verify_encrypted_backup()
        elif method == "2":
            self._verify_shamir()
        elif method == "3":
            self.start_entropy_audit()
        elif method == "4":
            self._view_distribution_map()
        elif method == "5":
            return

    def start_entropy_audit(self):
        """
        Entropy Commitment Audit — Advanced.

        Closes the commit-reveal loop. The user decrypts their backup or
        reconstructs from shares — the program recovers the mnemonic internally,
        recomputes the entropy commitment fingerprint, and displays it for
        the user to compare against what they recorded during generation.

        No passphrase involved — entropy commitment is derived from raw entropy
        only. No seed derivation occurs. Mnemonic is wiped on exit.
        """
        print("\n[Entropy Commitment Audit — Advanced]")
        print("========================================")
        print("This verifies that your mnemonic was honestly derived from")
        print("the entropy this tool committed to before generation.")
        print()
        print("This is an audit feature — not required for wallet recovery.")
        print("Use this if you want cryptographic proof that no tampering")
        print("occurred between entropy commitment and seed generation.")
        print()
        print("You will need:")
        print("  * Your backup (.atm file or Shamir shares)")
        print("  * Your entropy commitment fingerprint (raw hex, e.g. 58848A68...)")
        print("    Note: this is NOT your seed fingerprint (XXXX-XXXX-XXXX format)")
        print("========================================\n")

        print("Select your recovery method:")
        print("  1. Encrypted backup  (Tier 1 / Tier 2)")
        print("  2. Shamir shares     (Tier 3 / Tier 4)")
        print("  3. Back")
        print("----------------------------------------")

        while True:
            method = input(atm_prompt("verify/audit") + " Your choice (1-3): ").strip()
            if method in ("1", "2", "3"):
                break
            print("[!] Please enter 1, 2, or 3.")

        if method == "3":
            return

        if method == "1":
            mnemonic = self._audit_decrypt_backup()
        elif method == "2":
            mnemonic = self._audit_reconstruct_shares()

        if mnemonic is None:
            return

        # Hand off to commitment recomputation — no passphrase, no seed derivation
        self._audit_entropy_commitment(mnemonic)

    def _audit_decrypt_backup(self) -> str | None:
        """
        Decrypts an encrypted .atm backup and returns the mnemonic internally.
        Used exclusively by the entropy commitment audit path.
        No passphrase collected — audit only needs the mnemonic.
        """
        print("\n[Audit] Encrypted Backup")
        print("Provide the path to your .atm backup file.\n")

        filepath = input(atm_prompt("verify/encrypted") + " Enter path to .atm file: ").strip()

        try:
            from recovery.encrypted_backup import (
                load_backup_file, decrypt_tier1, decrypt_tier2,
                EncryptedBackupError
            )
            payload = load_backup_file(filepath)
        except Exception as e:
            print(f"\n[!] Failed to load backup file: {e}")
            return None

        import getpass as _getpass
        password = _getpass.getpass("Enter backup password: ").strip()

        fmt = payload.get("format", "")

        try:
            if fmt == "atm:tier1:v1":
                entropy = decrypt_tier1(payload, password)

            elif fmt == "atm:tier2:v1":
                print("\nProvide your keyfile (possession factor).")
                keyfile_path = input(atm_prompt("verify/encrypted") + " Enter path to keyfile: ").strip()
                entropy = decrypt_tier2(payload, password, keyfile_path)

            else:
                print("[!] Unknown backup format.")
                return None

        except Exception as e:
            print(f"\n[!] Decryption failed: {e}")
            return None

        # Recover mnemonic from entropy, wipe entropy immediately
        mnemonic = BIP39.entropy_to_mnemonic(entropy)

        entropy_buf = bytearray(entropy)
        MemoryWiper().wipe(entropy_buf)
        del entropy_buf
        del entropy

        return mnemonic

    def _audit_reconstruct_shares(self) -> str | None:
        """
        Reconstructs mnemonic from Shamir shares and returns it internally.
        Used exclusively by the entropy commitment audit path.
        No passphrase collected — audit only needs the mnemonic.
        """
        print("\n[Audit] Shamir Share Reconstruction")
        print("You will need at least 3 of your 5 SLIP39 recovery shares.\n")

        shares = []
        for i in range(1, 4):
            print(f"[Share {i} of 3]")
            share = input(atm_prompt("verify/audit") + f" Enter share {i}: ").strip()
            if not share:
                print("[!] Empty share entered. Audit aborted.")
                return None
            shares.append(share)
            print(f"[✓] Share {i} recorded.\n")

        print("[Audit] Reconstructing mnemonic from shares...")

        try:
            from recovery.reconstruct import reconstruct_mnemonic
            mnemonic = reconstruct_mnemonic(shares)
        except Exception as e:
            print(f"\n[!] Reconstruction failed: {e}")
            print("[!] Ensure you have entered valid and matching shares.")
            return None

        print(c("[+] Shares verified — mnemonic reconstructed internally.\n", Colours.GREEN))
        return mnemonic

    def _audit_entropy_commitment(self, mnemonic: str) -> None:
        """
        Recomputes the entropy commitment fingerprint from a mnemonic and
        displays it for the user to compare against their recorded value.

        This is the audit-specific comparison path:
            mnemonic → entropy bytes → SHA256("ENTROPY_COMMITMENT_V1" + entropy)
            → first 16 bytes → 32 uppercase hex characters → display

        No passphrase. No seed derivation. No seed fingerprint.
        Mnemonic wiped on exit regardless of outcome.
        """
        from entropy.commitment_verify import verify_entropy_commitment

        print("\n[Audit] Enter your recorded entropy commitment fingerprint.")
        print("(raw hex, 32 characters — with or without dashes)")
        fingerprint_input = input(atm_prompt("verify/audit") + " Commitment fingerprint: ").strip()

        print("\n[Verifying...]")
        result = verify_entropy_commitment(mnemonic, fingerprint_input)

        # Wipe mnemonic immediately after use
        mnemonic_buf = bytearray(mnemonic.encode())
        MemoryWiper().wipe(mnemonic_buf)
        del mnemonic_buf
        del mnemonic

        # Handle input/parse errors
        if result.error:
            print(f"\n[!] Audit error: {result.error}")
            print("[Audit aborted.]\n")
            return

        # Display both fingerprints side by side
        print()
        print(f"  Recorded fingerprint  : {result.recorded}")
        print(f"  Recomputed fingerprint: {result.recomputed}")
        print()

        if result.matched:
            print("========================================")
            print("   [✓] AUDIT PASSED")
            print("========================================")
            print("Your mnemonic is cryptographically linked to this commitment.")
            print("The entropy was honestly committed before seed generation.")
            print("No tampering occurred between commitment and derivation.\n")
        else:
            print("========================================")
            print("   [✗] AUDIT FAILED — MISMATCH")
            print("========================================")
            print("The mnemonic does not match this commitment fingerprint.")
            print()
            print("Possible causes:")
            print("  — Wrong commitment fingerprint recorded")
            print("  — Wrong backup file or shares used")
            print("  — Mnemonic was generated from different entropy")
            print()
            print("Your seed fingerprint (XXXX-XXXX-XXXX format) is unaffected.")
            print("Use options 1 or 2 to verify your backup is still intact.\n")

        print("[Secure Cleanup] Audit data wiped from memory.")
        print("[Audit complete.]\n")
        return None

    def _verify_encrypted_backup(self):
        """
        Verification via encrypted .atm file — Tier 1 or Tier 2.
        Decrypts backup, derives seed, computes fingerprint.
        Mnemonic never displayed.
        """
        print("\n[Encrypted Backup Verification]")
        print("Provide the path to your .atm backup file.\n")

        from recovery.encrypted_backup import (
            load_backup_file, decrypt_tier1, decrypt_tier2,
            EncryptedBackupError
        )

        # ── File load retry loop ──────────────────────────────────────────
        while True:
            filepath = input(atm_prompt("verify/encrypted") + " Enter path to .atm file: ").strip()
            try:
                payload = load_backup_file(filepath)
                break
            except Exception as e:
                print(f"\n[!] Failed to load backup file: {e}")
                retry = input("    Try again? (y/n): ").strip().lower()
                if retry != "y":
                    print("[i] Verification cancelled.")
                    return None
                print()

        import getpass as _getpass
        password = _getpass.getpass("Enter backup password: ").strip()

        fmt = payload.get("format", "")

        try:
            if fmt == "atm:tier1:v1":
                entropy = decrypt_tier1(payload, password)

            elif fmt == "atm:tier2:v1":
                print("\nProvide your keyfile (possession factor).")
                keyfile_path = input(atm_prompt("verify/encrypted") + " Enter path to keyfile: ").strip()
                entropy = decrypt_tier2(payload, password, keyfile_path)

            else:
                print("[!] Unknown backup format.")
                return None

        except Exception as e:
            print(f"\n[!] Decryption failed: {e}")
            return None

        # Recover mnemonic from entropy
        mnemonic = BIP39.entropy_to_mnemonic(entropy)

        # Wipe entropy immediately
        entropy_buf = bytearray(entropy)
        MemoryWiper().wipe(entropy_buf)
        del entropy_buf
        del entropy

        # Collect passphrase if one was used
        print("\nEnter your passphrase if one was used during generation.")
        print("Leave blank and press ENTER if no passphrase was used.")
        passphrase = _getpass.getpass("Passphrase (leave blank if none): ").strip()

        # Derive seed and compute fingerprint
        self._compare_fingerprint(mnemonic, passphrase)

    def _verify_shamir(self):
        """
        Verification via Shamir SLIP39 shares — Tier 3 / Tier 4.
        Reconstructs mnemonic from shares, derives seed, computes fingerprint.
        Mnemonic never displayed.
        """
        print("\n[Shamir Verification]")
        print("You will need at least 3 of your 5 SLIP39 recovery shares.\n")

        shares = []
        for i in range(1, 4):
            print(f"[Share {i} of 3]")
            share = input(atm_prompt("verify/shares") + f" Enter share {i}: ").strip()
            if not share:
                print("[!] Empty share entered. Verification aborted.")
                return None
            shares.append(share)
            print(f"[✓] Share {i} recorded.\n")

        print("[Verification] Reconstructing mnemonic from shares...")

        try:
            from recovery.reconstruct import reconstruct_mnemonic
            mnemonic = reconstruct_mnemonic(shares)
        except Exception as e:
            print(f"\n[!] Reconstruction failed: {e}")
            print("[!] Ensure you have entered valid and matching shares.")
            return None

        print(c("[+] Shares verified — mnemonic reconstructed internally.\n", Colours.GREEN))

        # Collect passphrase
        import getpass as _getpass
        print("Enter your passphrase if one was used during generation.")
        print("Leave blank and press ENTER if no passphrase was used.")
        passphrase = _getpass.getpass("Passphrase (leave blank if none): ").strip()

        # Derive seed and compute fingerprint
        self._compare_fingerprint(mnemonic, passphrase)

    def _compare_fingerprint(self, mnemonic: str, passphrase: str):
        """
        Shared fingerprint comparison logic for all verification paths.
        Derives seed, computes fingerprint, compares with recorded value.
        Mnemonic wiped on exit regardless of result.
        """
        print("\n[Verification] Deriving seed and computing fingerprint...")

        try:
            from security.seed_vault import SeedVault

            vault = SeedVault.from_mnemonic(mnemonic, passphrase)

            with vault.secure_access() as seed:
                seed_buffer = bytearray(seed)
                raw = hashlib.sha256(
                    b"SEED_COMMITMENT_V1" + bytes(seed_buffer)
                ).hexdigest()[:16].upper()
                computed_fingerprint = "-".join(
                    raw[i:i+4] for i in range(0, len(raw), 4)
                )
                MemoryWiper().wipe(seed_buffer)
                del seed_buffer

        except Exception as e:
            print(f"\n[!] Seed derivation failed: {e}")
            mnemonic_buffer = bytearray(mnemonic.encode())
            MemoryWiper().wipe(mnemonic_buffer)
            del mnemonic_buffer
            del mnemonic
            return None

        # Collect recorded fingerprint
        print("\nEnter your recorded seed fingerprint.")
        print("Format: XXXX-XXXX-XXXX-XXXX (uppercase, grouped)")
        recorded_fingerprint = input(atm_prompt("verify") + " Recorded fingerprint: ").strip().upper()

        print("\n[Verification] Comparing fingerprints...")

        if computed_fingerprint == recorded_fingerprint:
            print("\n========================================")
            print("   [✓] VERIFICATION SUCCESSFUL")
            print("========================================")
            print("Your backup reconstructs the correct seed.")
            print("Passphrase verified correctly.")
            print("Recorded fingerprint matches.\n")
        else:
            print("\n========================================")
            print("   [✗] VERIFICATION FAILED")
            print("========================================")
            print("The computed fingerprint does not match your recorded fingerprint.")
            print("\nPossible causes:")
            print("  — Wrong password or keyfile provided")
            print("  — Wrong passphrase provided (or passphrase missing)")
            print("  — Fingerprint was recorded incorrectly")
            print("\nNo seed or mnemonic has been exposed.\n")

        # Final cleanup
        mnemonic_buffer = bytearray(mnemonic.encode())
        MemoryWiper().wipe(mnemonic_buffer)
        del mnemonic_buffer
        del mnemonic

        print("[Secure Cleanup] Verification data wiped from memory.")
        print("[Verification complete.]\n")
        return None