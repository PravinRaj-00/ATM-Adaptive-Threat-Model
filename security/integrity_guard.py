import hashlib


class IntegrityError(Exception):
    pass


class IntegrityGuard:
    """
    Maintains a cryptographic commitment to a seed
    and verifies integrity before sensitive exposure.
    """

    def __init__(self, seed_bytes: bytes):
        self._commitment = self._hash(seed_bytes)

    def _hash(self, data: bytes) -> bytes:
        return hashlib.sha256(data).digest()

    def verify(self, current_seed: bytes):
        
        if not isinstance(current_seed, bytes):
            raise IntegrityError("Seed must be bytes.")
        
        current_hash = self._hash(current_seed)

        if current_hash != self._commitment:
            raise IntegrityError("Seed integrity verification failed.")

        return True