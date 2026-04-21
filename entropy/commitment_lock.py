import hashlib
import hmac

DOMAIN_TAG = b"ENTROPY_COMMITMENT_V1"


class CommitmentLock:
    """
    Sealed immutable commitment object for entropy integrity.

    Computes SHA-256 over domain-separated entropy bytes and exposes
    limited fingerprint interface. Object is immutable after creation.
    """

    __slots__ = ("__full_hash", "__sealed")

    def __init__(self, entropy_bytes: bytes):

        if not isinstance(entropy_bytes, bytes):
            raise TypeError("Entropy must be raw bytes.")

        if len(entropy_bytes) != 32:
            raise ValueError("Entropy must be exactly 32 bytes (256 bits).")

        # Compute commitment immediately with domain separation
        object.__setattr__(
            self,
            "_CommitmentLock__full_hash",
            hashlib.sha256(DOMAIN_TAG + entropy_bytes).digest()
        )

        # Seal object
        object.__setattr__(self, "_CommitmentLock__sealed", True)

    def __setattr__(self, name, value):
        if hasattr(self, "_CommitmentLock__sealed"):
            raise AttributeError(
                "CommitmentLock is immutable and cannot be modified."
            )
        super().__setattr__(name, value)

    def fingerprint(self) -> str:
        """
        Returns first 16 bytes (32 hex characters)
        as an integrity fingerprint.
        """
        return self.__full_hash[:16].hex().upper()

    def full_hash(self) -> str:
        """
        Returns full 32-byte SHA-256 commitment in hex.
        """
        return self.__full_hash.hex().upper()

    def __eq__(self, other):
        if not isinstance(other, CommitmentLock):
            return False
        return hmac.compare_digest(self.__full_hash, other.__full_hash)

    def __repr__(self):
        return f"CommitmentLock(fingerprint={self.fingerprint()})"