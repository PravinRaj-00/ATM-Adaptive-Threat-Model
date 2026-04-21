import getpass

MIN_LENGTH = 16
MIN_WORDS = 4


def enforce_passphrase(profile):
    """
    Enforces passphrase policy based on threat profile.
    Returns validated passphrase.
    """

    while True:
        print("\n[Passphrase Required]")
        print("Use a long passphrase of at least 16 characters.")
        print("Include at least 4 words separated by spaces.")
        print("Example: Zebra Computing Default Variable Brain")

        passphrase = getpass.getpass("Enter passphrase: ").strip()

        valid, message = validate_passphrase(passphrase)

        if valid:
            confirm = getpass.getpass("Confirm passphrase: ").strip()
            if confirm != passphrase:
                print("[!] Passphrases do not match. Try again.")
                continue

            print("[✓] Passphrase accepted.")
            return passphrase

        print(f"[!] {message}")

        # Tier 3: allow override
        if profile.single_key_allowed:
            choice = input("Proceed anyway? (y/n): ").lower()
            if choice == "y":
                print("[!] Weak passphrase accepted under Tier 3 policy.")
                return passphrase

        # Tier 4: no override
        print("[!] Strong passphrase required under current threat model.")


def validate_passphrase(passphrase):
    """
    Basic strength validation.
    """

    if len(passphrase) < MIN_LENGTH:
        return False, f"Passphrase must be at least {MIN_LENGTH} characters."

    if passphrase.isdigit():
        return False, "Passphrase cannot be numeric only."

    words = passphrase.split()
    if len(words) < MIN_WORDS:
        return False, f"Passphrase must contain at least {MIN_WORDS} words separated by spaces."

    return True, "Valid"
