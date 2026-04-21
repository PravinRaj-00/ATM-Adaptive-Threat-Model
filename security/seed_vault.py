from seed.bip39 import BIP39
from security.wipe import MemoryWiper

class SeedVaultError(Exception):
    """Custom exception for SeedVault-related errors."""
    pass


class SeedVault:
    """
    Controls lifecycle of a 64-byte seed.
    Handles storage, controlled access, and destruction.
    """

    def __init__(self, seed: bytes):
        if not isinstance(seed, bytes):
            raise SeedVaultError("Seed must be bytes.")

        if len(seed) != 64:
            raise SeedVaultError("Seed must be exactly 64 bytes.")

        # Store as mutable bytearray for overwrite capability
        self._seed = bytearray(seed)
        self._destroyed = False
        self._wiper = MemoryWiper(passes=2)

    def get_seed(self) -> bytes:
        """
        Returns a copy of the seed.
        Raises error if vault is destroyed.
        """
        if self._destroyed:
            raise SeedVaultError("SeedVault has been destroyed.")

        # Return immutable copy
        return bytes(self._seed)

    def destroy(self):
        if self._destroyed:
            return

        if self._seed is not None:
            self._wiper.wipe(self._seed)

        self._seed = None
        self._destroyed = True

    def is_destroyed(self) -> bool:
        """Return True if vault has been destroyed."""
        return self._destroyed

    def consume_seed(self) -> bytes:
        """
        Return the seed and immediately destroy the vault.
        This is a one-time access pattern.
        """
        
        if self._destroyed:
            raise SeedVaultError("SeedVault has been destroyed.")

        # Copy seed before destruction
        seed_copy = bytes(self._seed)

        # Destroy internal state
        self.destroy()

        return seed_copy
    
    @classmethod
    def from_mnemonic(cls, mnemonic: str, passphrase: str = "") -> "SeedVault":
        """
        Factory method:
        Derives seed from mnemonic and immediately wraps it in a SeedVault.
        Attempts to minimize raw seed exposure.
        """

        # Derive seed using Domain 2
        seed = BIP39.mnemonic_to_seed(mnemonic, passphrase)

        # Create vault immediately
        vault = cls(seed)

        # Attempt to wipe temporary seed variable
        # (Best-effort — Python cannot guarantee full memory erasure)
        temp = bytearray(seed)
        wiper = MemoryWiper()
        wiper.wipe(temp)

        seed = None
        temp = None

        return vault
    
    class _SecureAccessContext:
        def __init__(self, vault: "SeedVault"):
            self._vault = vault

        def __enter__(self) -> bytes:
            if self._vault._destroyed:
                raise SeedVaultError("SeedVault has been destroyed.")

            # Return a copy of the seed
            return bytes(self._vault._seed)

        def __exit__(self, exc_type, exc_value, traceback):
            # Always destroy vault when leaving context
            try:
                self._vault.destroy()
            except SeedVaultError:
                pass  # If already destroyed, ignore
            return False  # Do not suppress exceptions

    def secure_access(self):
        """
        Provides scoped access to the seed.
        The vault is automatically destroyed after exiting the context.
        """
        if self._destroyed:
            raise SeedVaultError("SeedVault has been destroyed.")

        return self._SecureAccessContext(self)