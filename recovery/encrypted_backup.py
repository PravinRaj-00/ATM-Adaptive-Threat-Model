"""
ATM — Encrypted Backup Module
==============================
Provides AES-256-GCM encrypted backup and recovery.

Tier 1 — Single factor: AES-256-GCM + PBKDF2 password key derivation
          Output: .atm file saved to USB

Tier 2 — Three factor: AES-256-GCM + Argon2 key derivation
          Factors: encrypted backup file + password + keyfile (possession)
          Output: .atm file saved to USB
          Keyfile stored separately on a second USB

Secret: entropy bytes (32) — reversible via BIP39.entropy_to_mnemonic()

Dependencies:
    pip install cryptography argon2-cffi
"""

import base64
import hashlib
import json
import os
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ----------------------------------------------------------------
# Custom Exceptions
# ----------------------------------------------------------------

class EncryptedBackupError(Exception):
    pass


# ----------------------------------------------------------------
# Constants
# ----------------------------------------------------------------

NONCE_SIZE       = 12     # bytes — standard for AES-GCM
KEY_SIZE         = 32     # bytes — AES-256
KEYFILE_SIZE     = 64     # bytes — generated keyfile size

# Tier 1 — PBKDF2 parameters
PBKDF2_SALT_SIZE = 32
PBKDF2_ITERS     = 310000  # OWASP 2023 recommended

# Tier 2 — Argon2 parameters
ARGON2_SALT_SIZE = 32
ARGON2_TIME_COST = 3       # iterations
ARGON2_MEMORY    = 65536   # 64 MB memory cost
ARGON2_PARALLEL  = 2       # parallelism
ARGON2_HASH_LEN  = 32      # output key length


# ----------------------------------------------------------------
# Internal Utilities
# ----------------------------------------------------------------

def _b64encode(data: bytes) -> str:
    """URL-safe base64 encode without padding."""
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64decode(s: str) -> bytes:
    """URL-safe base64 decode with padding restoration."""
    padding = 4 - len(s) % 4
    if padding != 4:
        s += "=" * padding
    return base64.urlsafe_b64decode(s)


def _aes_encrypt(key: bytes, plaintext: bytes) -> tuple:
    """
    Encrypts plaintext with AES-256-GCM.
    Returns (nonce, ciphertext, tag).
    """
    nonce = os.urandom(NONCE_SIZE)
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)
    ciphertext = ciphertext_with_tag[:-16]
    tag = ciphertext_with_tag[-16:]
    return nonce, ciphertext, tag


def _aes_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    """
    Decrypts ciphertext with AES-256-GCM.
    Raises EncryptedBackupError on authentication failure.
    """
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, ciphertext + tag, None)
    except Exception:
        raise EncryptedBackupError(
            "Decryption failed. Incorrect password or corrupted backup."
        )


# ================================================================
# TIER 1 — PBKDF2 + AES-256-GCM
# Single factor: password only
# ================================================================

def _derive_key_pbkdf2(password: str, salt: bytes) -> bytes:
    """Derives AES-256 key from password using PBKDF2-HMAC-SHA256."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERS,
        dklen=KEY_SIZE,
    )


def encrypt_tier1(entropy: bytes, password: str) -> dict:
    """
    Tier 1 encryption — PBKDF2 + AES-256-GCM.

    Parameters
    ----------
    entropy : bytes
        32-byte entropy to encrypt.
    password : str
        User backup password.

    Returns
    -------
    dict
        Encrypted backup payload ready to save as .atm file.
    """
    if not isinstance(entropy, bytes) or len(entropy) != 32:
        raise EncryptedBackupError("Entropy must be exactly 32 bytes.")
    if not password:
        raise EncryptedBackupError("Password cannot be empty.")

    salt = os.urandom(PBKDF2_SALT_SIZE)
    key = _derive_key_pbkdf2(password, salt)
    nonce, ciphertext, tag = _aes_encrypt(key, entropy)

    return {
        "format":    "atm:tier1:v1",
        "version":   "1.0",
        "salt":      _b64encode(salt),
        "nonce":     _b64encode(nonce),
        "ciphertext": _b64encode(ciphertext),
        "tag":       _b64encode(tag),
        "note":      "ATM Tier 1 encrypted entropy backup. Requires password to recover.",
    }


def decrypt_tier1(payload: dict, password: str) -> bytes:
    """
    Tier 1 decryption — PBKDF2 + AES-256-GCM.

    Parameters
    ----------
    payload : dict
        Loaded .atm file contents.
    password : str
        User backup password.

    Returns
    -------
    bytes
        Original 32-byte entropy.
    """
    try:
        salt       = _b64decode(payload["salt"])
        nonce      = _b64decode(payload["nonce"])
        ciphertext = _b64decode(payload["ciphertext"])
        tag        = _b64decode(payload["tag"])
    except (KeyError, Exception):
        raise EncryptedBackupError("Invalid backup file — missing or corrupted fields.")

    key = _derive_key_pbkdf2(password, salt)
    entropy = _aes_decrypt(key, nonce, ciphertext, tag)

    if len(entropy) != 32:
        raise EncryptedBackupError("Decrypted data is not valid entropy.")

    return entropy


# ================================================================
# TIER 2 — Argon2 + SHA256(keyfile) + AES-256-GCM
# Three factors: backup file + password + keyfile
# ================================================================

def _derive_key_argon2(combined_secret: bytes, salt: bytes) -> bytes:
    """
    Derives AES-256 key using Argon2id (memory-hard).
    combined_secret = password_bytes || SHA256(keyfile_bytes)
    """
    try:
        from argon2.low_level import hash_secret_raw, Type
    except ImportError:
        raise EncryptedBackupError(
            "argon2-cffi is required for Tier 2 encryption. "
            "Install with: pip install argon2-cffi"
        )

    return hash_secret_raw(
        secret=combined_secret,
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY,
        parallelism=ARGON2_PARALLEL,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID,
    )


def _hash_keyfile(keyfile_path: str) -> bytes:
    """
    Reads keyfile and returns SHA256 hash of raw bytes.
    File name, extension, and metadata are ignored.
    Only raw file content is used.
    """
    if not os.path.exists(keyfile_path):
        raise EncryptedBackupError(f"Keyfile not found: {keyfile_path}")

    with open(keyfile_path, "rb") as f:
        keyfile_bytes = f.read()

    if len(keyfile_bytes) == 0:
        raise EncryptedBackupError("Keyfile is empty.")

    return hashlib.sha256(keyfile_bytes).digest()


def generate_keyfile(output_path: str):
    """
    Generates a cryptographically random keyfile and saves it.
    Used by Tier 2 users who don't have an existing keyfile.

    Parameters
    ----------
    output_path : str
        Path where the keyfile should be saved.
    """
    keyfile_bytes = secrets.token_bytes(KEYFILE_SIZE)

    try:
        with open(output_path, "wb") as f:
            f.write(keyfile_bytes)
    except OSError as e:
        raise EncryptedBackupError(f"Failed to write keyfile: {e}")


def encrypt_tier2(entropy: bytes, password: str, keyfile_path: str) -> dict:
    """
    Tier 2 encryption — Argon2 + SHA256(keyfile) + AES-256-GCM.

    Three factors required:
      1. Encrypted backup file (this output)
      2. Password (knowledge)
      3. Keyfile (possession — store separately)

    Parameters
    ----------
    entropy : bytes
        32-byte entropy to encrypt.
    password : str
        User backup password.
    keyfile_path : str
        Path to the keyfile (possession factor).

    Returns
    -------
    dict
        Encrypted backup payload ready to save as .atm file.
    """
    if not isinstance(entropy, bytes) or len(entropy) != 32:
        raise EncryptedBackupError("Entropy must be exactly 32 bytes.")
    if not password:
        raise EncryptedBackupError("Password cannot be empty.")

    # Hash keyfile bytes — only raw content, no metadata
    keyfile_hash = _hash_keyfile(keyfile_path)

    # Combine password + keyfile hash as the secret
    combined_secret = password.encode("utf-8") + keyfile_hash

    # Generate salt for Argon2
    salt = os.urandom(ARGON2_SALT_SIZE)

    # Derive key using Argon2id
    key = _derive_key_argon2(combined_secret, salt)

    # Encrypt entropy
    nonce, ciphertext, tag = _aes_encrypt(key, entropy)

    return {
        "format":      "atm:tier2:v1",
        "version":     "1.0",
        "argon2": {
            "time_cost":   ARGON2_TIME_COST,
            "memory_cost": ARGON2_MEMORY,
            "parallelism": ARGON2_PARALLEL,
            "hash_len":    ARGON2_HASH_LEN,
        },
        "salt":        _b64encode(salt),
        "nonce":       _b64encode(nonce),
        "ciphertext":  _b64encode(ciphertext),
        "tag":         _b64encode(tag),
        "note":        (
            "ATM Tier 2 encrypted entropy backup. "
            "Requires: backup file + password + keyfile to recover."
        ),
    }


def decrypt_tier2(payload: dict, password: str, keyfile_path: str) -> bytes:
    """
    Tier 2 decryption — Argon2 + SHA256(keyfile) + AES-256-GCM.

    Parameters
    ----------
    payload : dict
        Loaded .atm file contents.
    password : str
        User backup password.
    keyfile_path : str
        Path to the keyfile used during encryption.

    Returns
    -------
    bytes
        Original 32-byte entropy.
    """
    try:
        argon2_params = payload["argon2"]
        salt       = _b64decode(payload["salt"])
        nonce      = _b64decode(payload["nonce"])
        ciphertext = _b64decode(payload["ciphertext"])
        tag        = _b64decode(payload["tag"])
    except (KeyError, Exception):
        raise EncryptedBackupError("Invalid backup file — missing or corrupted fields.")

    # Hash keyfile
    keyfile_hash = _hash_keyfile(keyfile_path)

    # Reconstruct combined secret
    combined_secret = password.encode("utf-8") + keyfile_hash

    # Re-derive key using stored Argon2 parameters
    try:
        from argon2.low_level import hash_secret_raw, Type
    except ImportError:
        raise EncryptedBackupError(
            "argon2-cffi is required for Tier 2 recovery. "
            "Install with: pip install argon2-cffi"
        )

    key = hash_secret_raw(
        secret=combined_secret,
        salt=salt,
        time_cost=argon2_params["time_cost"],
        memory_cost=argon2_params["memory_cost"],
        parallelism=argon2_params["parallelism"],
        hash_len=argon2_params["hash_len"],
        type=Type.ID,
    )

    entropy = _aes_decrypt(key, nonce, ciphertext, tag)

    if len(entropy) != 32:
        raise EncryptedBackupError("Decrypted data is not valid entropy.")

    return entropy


# ================================================================
# File I/O — shared for Tier 1 and Tier 2
# ================================================================

def save_backup_file(payload: dict, filepath: str):
    """
    Saves encrypted backup payload to a .atm file.

    Parameters
    ----------
    payload : dict
        Encrypted backup payload from encrypt_tier1() or encrypt_tier2().
    filepath : str
        Path where the .atm file should be saved.
    """
    if not filepath.endswith(".atm"):
        filepath += ".atm"

    try:
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
    except OSError as e:
        raise EncryptedBackupError(f"Failed to write backup file: {e}")


def load_backup_file(filepath: str) -> dict:
    """
    Loads and parses a .atm backup file.

    Parameters
    ----------
    filepath : str
        Path to the .atm file.

    Returns
    -------
    dict
        Parsed backup payload.
    """
    if not os.path.exists(filepath):
        raise EncryptedBackupError(f"Backup file not found: {filepath}")

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except json.JSONDecodeError:
        raise EncryptedBackupError("Invalid .atm file — file may be corrupted.")
    except OSError as e:
        raise EncryptedBackupError(f"Failed to read backup file: {e}")

    if "format" not in payload:
        raise EncryptedBackupError("Invalid .atm file — missing format field.")

    return payload