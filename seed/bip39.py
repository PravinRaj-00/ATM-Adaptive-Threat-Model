import os
import hashlib
import unicodedata
from typing import List, Dict


class BIP39Error(Exception):
    """Custom exception for BIP39-related errors."""
    pass


class BIP39:

    _wordlist: List[str] = None
    _wordmap: Dict[str, int] = None

    @staticmethod
    def _secure_wipe(byte_array):
        """
        Best-effort memory wipe for bytearrays.
        """
        if isinstance(byte_array, bytearray):
            for i in range(len(byte_array)):
                byte_array[i] = 0

    @classmethod
    def _load_wordlist(cls) -> List[str]:
        """
        Load and validate the BIP39 English wordlist.
        Ensures exactly 2048 words.
        Builds a fast lookup map for word → index.
        """

        if cls._wordlist is not None:
            return cls._wordlist

        current_dir = os.path.dirname(os.path.abspath(__file__))
        wordlist_path = os.path.join(current_dir, "wordlist_english.txt")

        if not os.path.exists(wordlist_path):
            raise BIP39Error("BIP39 wordlist file not found.")

        with open(wordlist_path, "r", encoding="utf-8") as f:
            words = [line.strip() for line in f.readlines()]

        if len(words) != 2048:
            raise BIP39Error(
                f"Wordlist must contain exactly 2048 words. Found {len(words)}."
            )

        if any(not word.islower() for word in words):
            raise BIP39Error("Wordlist contains non-lowercase entries.")

        cls._wordlist = words
        cls._wordmap = {word: idx for idx, word in enumerate(words)}

        return cls._wordlist

    @classmethod
    def get_wordlist(cls) -> List[str]:
        """Public accessor for wordlist."""
        return cls._load_wordlist()

    @classmethod
    def entropy_to_mnemonic(cls, entropy: bytes) -> str:
        """
        Convert 256-bit entropy (32 bytes) into a 24-word BIP39 mnemonic.
        """

        if not isinstance(entropy, bytes):
            raise BIP39Error("Entropy must be bytes.")

        if len(entropy) != 32:
            raise BIP39Error("Entropy must be exactly 32 bytes (256 bits).")

        wordlist = cls._load_wordlist()

        entropy_bits = ''.join(f"{byte:08b}" for byte in entropy)

        hash_bytes = hashlib.sha256(entropy).digest()
        hash_bits = ''.join(f"{byte:08b}" for byte in hash_bytes)

        checksum_length = 256 // 32
        checksum_bits = hash_bits[:checksum_length]

        full_bitstring = entropy_bits + checksum_bits

        indices = [
            int(full_bitstring[i:i + 11], 2)
            for i in range(0, len(full_bitstring), 11)
        ]

        if len(indices) != 24:
            raise BIP39Error("Mnemonic generation failed (invalid chunk count).")

        words = [wordlist[index] for index in indices]

        return " ".join(words)

    @classmethod
    def mnemonic_to_entropy(cls, mnemonic: str) -> bytes:
        """
        Convert a 24-word BIP39 mnemonic back to 256-bit entropy.
        Verifies checksum before returning entropy.
        """

        if not isinstance(mnemonic, str):
            raise BIP39Error("Mnemonic must be a string.")

        mnemonic = unicodedata.normalize("NFKD", mnemonic.strip())

        words = mnemonic.split()

        if len(words) != 24:
            raise BIP39Error("Mnemonic must contain exactly 24 words.")

        cls._load_wordlist()

        indices = []

        for word in words:
            if word not in cls._wordmap:
                raise BIP39Error(f"Invalid word in mnemonic: '{word}'")
            indices.append(cls._wordmap[word])

        full_bitstring = ''.join(f"{index:011b}" for index in indices)

        if len(full_bitstring) != 264:
            raise BIP39Error("Invalid mnemonic bit length.")

        entropy_bits = full_bitstring[:256]
        checksum_bits = full_bitstring[256:]

        entropy_bytes = bytes(
            int(entropy_bits[i:i + 8], 2)
            for i in range(0, 256, 8)
        )

        hash_bytes = hashlib.sha256(entropy_bytes).digest()
        hash_bits = ''.join(f"{byte:08b}" for byte in hash_bytes)
        expected_checksum = hash_bits[:8]

        if checksum_bits != expected_checksum:
            raise BIP39Error("Checksum verification failed.")

        return entropy_bytes

    @classmethod
    def validate_mnemonic(cls, mnemonic: str) -> bool:
        """
        Validate a 24-word mnemonic.
        Returns True if valid, False otherwise.
        """

        try:
            cls.mnemonic_to_entropy(mnemonic)
            return True
        except BIP39Error:
            return False

    @classmethod
    def mnemonic_to_seed(cls, mnemonic: str, passphrase: str = "") -> bytes:
        """
        Derive a 64-byte seed from mnemonic and optional passphrase
        using PBKDF2-HMAC-SHA512 (2048 iterations).
        """

        if not isinstance(mnemonic, str):
            raise BIP39Error("Mnemonic must be a string.")

        if not isinstance(passphrase, str):
            raise BIP39Error("Passphrase must be a string.")

        mnemonic = unicodedata.normalize("NFKD", mnemonic.strip())
        passphrase = unicodedata.normalize("NFKD", passphrase)

        if not cls.validate_mnemonic(mnemonic):
            raise BIP39Error("Invalid mnemonic. Cannot derive seed.")

        salt = "mnemonic" + passphrase

        seed = hashlib.pbkdf2_hmac(
            "sha512",
            mnemonic.encode("utf-8"),
            salt.encode("utf-8"),
            2048,
            dklen=64
        )

        return seed