import hashlib


MIXER_DOMAIN = b"WALLET_ENTROPY_MIX_V1"


def mix_entropy(*sources):
    """
    Securely combines entropy sources using domain-separated hashing.

    Accepts:
        bytes or bytearray entropy sources.

    Returns:
        final_entropy (bytes)
    """

    if not sources:
        raise ValueError("No entropy sources provided to mixer.")

    hasher = hashlib.sha256()

    # Mixer domain separation
    hasher.update(MIXER_DOMAIN)

    for index, source in enumerate(sources):

        if not isinstance(source, (bytes, bytearray)) or len(source) == 0:
            raise ValueError("Invalid entropy source provided.")

        normalized = bytes(source)

        # Pre-hash each source
        source_digest = hashlib.sha256(normalized).digest()

        # Source domain separation
        source_tag = f"SOURCE_{index}".encode()

        hasher.update(source_tag)
        hasher.update(source_digest)

    final_entropy = hasher.digest()

    return final_entropy