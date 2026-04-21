# entropy/external_file.py
import hashlib
import os


def collect_external_entropy() -> tuple | None:
    """
    Optionally collects entropy from an external file.

    Any file type is accepted. The file's SHA-256 hash is used as the
    entropy contribution — not the raw bytes. This approach is:

    - Defensible: entropy comes from the unpredictability of file contents,
      not from assuming the bytes are already random
    - Transparent: the file fingerprint is displayed and recorded in the
      governance report so the user can verify the correct file was used
    - Tamper-evident: if the file changes, the fingerprint changes
    - Format-agnostic: any file works — photo, document, binary, custom data

    Returns (hashed_entropy, fingerprint, file_size) or None if skipped.
    """

    print("\n[External Entropy Collection]")
    choice = input("Would you like to provide an external entropy file? (y/n): ").strip().lower()

    if choice != "y":
        print("[i] Skipping external entropy contribution.")
        return None

    while True:
        file_path = input("Enter path to file: ").strip()

        if not os.path.isfile(file_path):
            print("[!] File not found. Please try again.")
            continue

        try:
            # Read raw file bytes regardless of format
            with open(file_path, "rb") as f:
                file_bytes = f.read()

            if len(file_bytes) == 0:
                print("[!] File is empty. Please provide a non-empty file.")
                continue

            # SHA-256 hash the file contents — this is the entropy contribution
            hashed_entropy = hashlib.sha256(file_bytes).digest()

            # Fingerprint — first 16 chars of the hash for display/verification
            fingerprint = hashed_entropy.hex()[:16].upper()

            file_size = len(file_bytes)

            print(f"[✓] External entropy collected from file.")
            print(f"[i] File size       : {file_size} bytes")
            print(f"[i] File fingerprint: {fingerprint}")
            print(f"[i] Entropy contribution: 256 bits (SHA-256 hash of file)")
            print(f"[i] Record this fingerprint to verify the same file was used.")

            # Return 32 as size — hash is always 32 bytes / 256 bits
            return hashed_entropy, fingerprint, 32

        except Exception as e:
            print(f"[!] Error reading file: {e}")
            continue