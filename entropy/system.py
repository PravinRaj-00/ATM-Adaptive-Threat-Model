import secrets
import math
from collections import Counter


def get_system_entropy(bits=256):
    byte_length = bits // 8

     # Actual entropy used for seed
    entropy = secrets.token_bytes(byte_length)

    # Larger independent sample for statistical validation
    scoring_sample = secrets.token_bytes(1024)
    score = shannon_entropy(scoring_sample)

    if score < 7.5:
        raise ValueError(
            f"System entropy validation failed: {score:.4f} bits/byte"
        )

    return entropy, score

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0

    counter = Counter(data)
    length = len(data)

    entropy = 0
    for count in counter.values():
        p_x = count / length
        entropy -= p_x * math.log2(p_x)

    return entropy
