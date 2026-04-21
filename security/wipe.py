class WipeError(Exception):
    pass


class MemoryWiper:
    """
    Centralized memory wiping utility.
    Implements deterministic overwrite discipline.
    """

    def __init__(self, passes: int = 1):
        if passes < 1:
            raise ValueError("Passes must be >= 1")
        self.passes = passes

    def wipe(self, buffer: bytearray):
        if not isinstance(buffer, bytearray):
            raise WipeError("MemoryWiper requires a bytearray buffer.")

        length = len(buffer)

        # Multi-pass overwrite
        for _ in range(self.passes):
            for i in range(length):
                buffer[i] = 0x00

        # Final overwrite with 0xFF for symbolic second pattern
        for i in range(length):
            buffer[i] = 0xFF

        # Clear again to 0x00 for final state
        for i in range(length):
            buffer[i] = 0x00