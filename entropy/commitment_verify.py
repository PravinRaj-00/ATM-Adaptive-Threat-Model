"""
entropy/commitment_verify.py
────────────────────────────
Entropy Commitment Verifier — Audit Mode

Closes the commit-reveal loop by proving that a mnemonic was honestly
derived from the entropy that produced a given commitment fingerprint.

Verification chain:
    mnemonic
        → BIP39.mnemonic_to_entropy()     ← reverses BIP39 derivation
        → SHA256("ENTROPY_COMMITMENT_V1" + entropy_bytes)
        → first 16 bytes → 32 uppercase hex characters
        → compare with user's recorded commitment fingerprint

A MATCH proves the full chain is intact:
    entropy was committed before seed generation, and the mnemonic
    genuinely came from that entropy. No tampering occurred between
    commitment and derivation.

This module is purely functional — no UI, no state, no side effects.
All display and user interaction lives in lifecycle.py.

Note on fingerprint formats
───────────────────────────
The entropy commitment fingerprint is displayed as raw hex during generation:
    e.g.  58848A689DED159EA65A6DEF8814C0E5

This is intentionally different from the seed fingerprint (Domain 3),
which uses grouped 4-char blocks:
    e.g.  3FA4-91B2-CC18-A4D1

The visual difference reinforces that these are different things:
  • Entropy commitment — audit trail, proves tool honesty, optional to record
  • Seed fingerprint   — wallet identity, used for recovery verification, must record

This verifier accepts both raw hex and grouped format (dashes stripped on input).
"""

import hashlib
import hmac
from dataclasses import dataclass

from seed.bip39 import BIP39


# ─── Constants ────────────────────────────────────────────────────────────────

COMMITMENT_DOMAIN_TAG = b"ENTROPY_COMMITMENT_V1"
FINGERPRINT_HEX_LENGTH = 32   # 16 bytes → 32 hex chars


# ─── Result Object ────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class CommitmentVerifyResult:
    """
    Immutable result returned by verify_entropy_commitment().

    Attributes
    ----------
    matched    : True if recorded fingerprint matches recomputed fingerprint.
    recomputed : Fingerprint recomputed from the mnemonic (32 uppercase hex chars).
    recorded   : Normalised fingerprint as entered by the user (32 uppercase hex chars).
    error      : Human-readable error string if verification could not be attempted.
                 None on clean success or mismatch — a mismatch is a valid result,
                 not an exception. Only input/parse errors set this field.
    """
    matched:    bool
    recomputed: str
    recorded:   str
    error:      str | None = None


# ─── Input Normalisation ──────────────────────────────────────────────────────

def _normalise_fingerprint(raw: str) -> str | None:
    """
    Accept grouped or raw hex input.

    Strips dashes and spaces, uppercases, validates exactly
    FINGERPRINT_HEX_LENGTH valid hex characters.
    Returns normalised string on success, None if invalid.
    """
    stripped = raw.replace("-", "").replace(" ", "").upper()

    if len(stripped) != FINGERPRINT_HEX_LENGTH:
        return None

    try:
        int(stripped, 16)
    except ValueError:
        return None

    return stripped


# ─── Core Recomputation ───────────────────────────────────────────────────────

def _recompute_fingerprint(entropy_bytes: bytes) -> str:
    """
    Recompute the commitment fingerprint from entropy bytes.

    Matches CommitmentLock.fingerprint() exactly:
        SHA256("ENTROPY_COMMITMENT_V1" || entropy_bytes)
        → first 16 bytes → 32 uppercase hex characters
    """
    digest = hashlib.sha256(COMMITMENT_DOMAIN_TAG + entropy_bytes).digest()
    return digest[:16].hex().upper()


# ─── Public API ───────────────────────────────────────────────────────────────

def verify_entropy_commitment(
    mnemonic: str,
    recorded_fingerprint: str,
) -> CommitmentVerifyResult:
    """
    Verify that a mnemonic was derived from the entropy behind a commitment fingerprint.

    Parameters
    ----------
    mnemonic             : The 24-word BIP39 mnemonic string.
    recorded_fingerprint : The commitment fingerprint recorded during generation.
                           Accepts raw hex (58848A68...) or grouped (3FA4-91B2-...).

    Returns
    -------
    CommitmentVerifyResult — always returned, never raises.
    A MISMATCH is a valid result with matched=False and error=None.
    Only malformed input or BIP39 parse failure sets the error field.

    Security notes
    --------------
    - Entropy bytes are wiped from memory after recomputation.
    - Comparison uses hmac.compare_digest — constant-time, no timing leak.
    - This function has no side effects — all display is handled by the caller.
    """

    # ── Step 1: Normalise recorded fingerprint ────────────────────────────────
    normalised = _normalise_fingerprint(recorded_fingerprint)
    if normalised is None:
        return CommitmentVerifyResult(
            matched=False,
            recomputed="",
            recorded=recorded_fingerprint,
            error=(
                f"Invalid fingerprint. Expected {FINGERPRINT_HEX_LENGTH} hex characters "
                f"(dashes optional). Got: '{recorded_fingerprint}'"
            ),
        )

    # ── Step 2: Recover entropy from mnemonic ─────────────────────────────────
    try:
        entropy_bytes = BIP39.mnemonic_to_entropy(mnemonic.strip())
    except Exception as exc:
        return CommitmentVerifyResult(
            matched=False,
            recomputed="",
            recorded=normalised,
            error=f"Failed to recover entropy from mnemonic: {exc}",
        )

    # ── Step 3: Recompute and wipe ─────────────────────────────────────────────
    try:
        recomputed = _recompute_fingerprint(entropy_bytes)
    finally:
        # Wipe entropy bytes from memory regardless of outcome
        entropy_buf = bytearray(entropy_bytes)
        for i in range(len(entropy_buf)):
            entropy_buf[i] = 0
        del entropy_buf

    # ── Step 4: Constant-time comparison ──────────────────────────────────────
    matched = hmac.compare_digest(recomputed, normalised)

    return CommitmentVerifyResult(
        matched=matched,
        recomputed=recomputed,
        recorded=normalised,
        error=None,
    )