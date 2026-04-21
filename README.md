# ATM — Adaptive Threat Model

**A Sovereign, Threat-Adaptive Cryptographic Seed Lifecycle for Secure Wallet Generation, Verification and Recovery**

ATM is a fully offline, open-source Python entropy engine that generates cryptographically verifiable BIP39 seed phrases. It is designed to run air-gapped on Tails OS from a USB drive with no persistent state, no network dependency, and no manufacturer trust required.

Built as a Final Year Project — BSc (Honours) Cybercrime and IT Security, SETU IT Carlow (2024/2025).

---

## The Problem

Modern hardware wallets generate your Bitcoin seed phrase inside a closed-source Secure Element chip. You cannot audit the entropy, inspect the firmware, or verify the randomness. You trust the manufacturer completely — the same trust model that enabled Operation RUBICON, the Trust Wallet vulnerability (CVE-2023-31290), and the Ledger data breach.

ATM eliminates that trust requirement entirely.

---

## What ATM Does

- Collects entropy from **multiple independent sources** — OS CSPRNG, physical dice rolls, and an optional external file
- Mixes them using a **domain-separated SHA-256 construction** so no single source can determine the output
- Produces a **cryptographic commitment fingerprint** before any seed is generated — independently auditable after the fact
- Generates a **BIP39-compliant 24-word mnemonic** via spec-correct PBKDF2-HMAC-SHA512
- Applies **adaptive security hardening** based on the user's actual threat level
- Creates a **tier-appropriate recovery mechanism** — encrypted backup or Shamir Secret Sharing
- Runs entirely **offline** on Tails OS — no data written to disk unencrypted, no identity linkage, no persistent trace

---

## The Four-Tier System

ATM adapts its security posture to the user's threat level through a weighted six-question assessment:

| Tier | Threat Level | Entropy Collected | Recovery Mechanism | Passphrase |
|------|-------------|-------------------|--------------------|------------|
| Tier 1 | LOW | 256 bits | PBKDF2 + AES-256-GCM encrypted `.atm` file | Optional |
| Tier 2 | MEDIUM | 256 bits | Argon2id + keyfile + AES-256-GCM (3-factor) | Optional |
| Tier 3 | HIGH | 384 bits | SLIP39 Shamir 3-of-5 shares | Enforced |
| Tier 4 | EXTREME | 512 bits | SLIP39 Shamir 3-of-5 shares (single-use vault) | Enforced |

---

## Architecture

ATM is organised into four cryptographically isolated domains:

- **Domain 1 — Entropy Generation:** Multi-source collection, bit-accounting governance, domain-separated SHA-256 mixing, CommitmentLock seal
- **Domain 2 — Deterministic Seed Generation:** Spec-correct BIP39 mnemonic via PBKDF2-HMAC-SHA512
- **Domain 3 — Adaptive Security Hardening:** AdaptiveSeedController, SeedVault, TierPolicy enforcement, progressive reveal, memory wiping
- **Domain 4 — Adaptive Recovery:** Tier 1/2 AES-256-GCM encrypted backup, Tier 3/4 SLIP39 Shamir 3-of-5 with geographic distribution map

All domains are orchestrated by `core/lifecycle.py` with a runtime `NetworkStateMonitor` that kills the process and wipes memory if network connectivity is detected at any point during the pipeline.

---

## Security Properties

- **No manufacturer trust** — fully open source, every line auditable
- **No identity linkage** — runs on Tails OS, leaves no trace on the host machine
- **No single entropy source** — domain-separated multi-source mixing
- **Cryptographic commitment audit** — independently verify that backup entropy matches generation entropy
- **Active memory wiping** — `bytearray` + `ctypes.memset` multi-pass overwrite across all domains
- **Pre-execution integrity check** — SHA-256 manifest verification of all 29 source files before launch
- **Air-gap kill switch** — runtime network detection aborts with memory wipe at every domain boundary

---

## Running ATM

### Recommended: Tails OS (Air-Gapped)

ATM is designed to run on Tails OS from a USB drive. Tails provides RAM-only operation, no swap, memory scrub on shutdown, and Tor as the system-level network gateway.

**Setup on Tails:**

```bash
# Install the only dependency not pre-installed on Tails
bash install.sh

# Run ATM
python3 main.py
```

All other dependencies (`cryptography`, `argon2-cffi`, `qrcode`, `psutil`) are pre-installed on Tails by default.

### Standard Machine (Testing/Development)

```bash
# Install dependencies
pip install -r requirements.txt

# Run ATM
python3 main.py
```

### CLI Flags

```
python3 main.py --verbose    # Full commitment hashes and entropy detail
python3 main.py --quiet      # Suppress non-essential output
python3 main.py --audit      # Jump directly to entropy commitment audit
```

---

## Dependencies

| Package | Purpose | Pre-installed on Tails |
|---------|---------|----------------------|
| `cryptography` | AES-256-GCM, PBKDF2 | ✅ Yes |
| `argon2-cffi` | Argon2id KDF (Tier 2) | ✅ Yes |
| `qrcode` | ASCII QR terminal display | ✅ Yes |
| `psutil` | Network interface monitoring | ✅ Yes |
| `shamir-mnemonic` | SLIP39 Shamir shares (Tier 3/4) | ❌ Bundled in `wheelhouse/` |

---

## Project Structure

```
atm/
├── main.py                  ← Entry point
├── checksums.json           ← Integrity manifest (29 files)
├── requirements.txt         ← Standard install
├── install.sh               ← Tails offline installer
├── wheelhouse/              ← Bundled shamir-mnemonic wheel
├── cli/                     ← CLI interface layer
├── core/                    ← Orchestration, threat model, air-gap enforcement
├── entropy/                 ← Domain 1 — entropy sources, mixer, commitment
├── seed/                    ← Domain 2 — BIP39 mnemonic generation
├── security/                ← Domain 3 — vault, hardening, memory wipe
├── interaction/             ← Domain 3 — progressive reveal, confirmation gates
├── recovery/                ← Domain 4 — encrypted backup, Shamir SLIP39
└── utils/                   ← Display helpers, atm_prompt(), colour, banners
```

---

## Academic Context

This project was developed as a Final Year Project for the BSc (Honours) in Cybercrime and IT Security at South East Technological University, IT Carlow.

- **Student:** Pravin Raj Morgan (C00313630)
- **Supervisor:** Richard Butler
- **Programme:** Y4 ZPROC4204
- **Academic Year:** 2024/2025

The threat model and design rationale are grounded in documented real-world incidents: Operation RUBICON (CIA/BND Crypto AG compromise), CVE-2023-31290 (Trust Wallet entropy failure), the Ledger data breach (2020), and Edward Snowden's 2024 warning on AI-powered financial surveillance.

---

## Disclaimer

ATM is an academic research project. It implements cryptographic standards correctly and has been tested on Tails OS, but it has not undergone a formal third-party security audit. Use in production is at your own risk. The project addresses the key generation problem only — on-chain privacy tools are explicitly out of scope.

---

## Licence

MIT License — see `LICENSE` file for details.