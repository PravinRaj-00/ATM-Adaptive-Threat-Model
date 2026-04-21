#!/bin/bash
# ATM — Adaptive Threat Model
# Offline dependency installer for Tails OS
# Installs shamir-mnemonic directly from wheelhouse without pip or internet

echo "[ATM] Installing shamir-mnemonic from wheelhouse..."

sudo python3 -c "
import zipfile, sys, os
whl = os.path.join(os.path.dirname(os.path.abspath('$0')), 'wheelhouse/shamir_mnemonic-0.3.0-py3-none-any.whl')
target = '/usr/local/lib/python3.13/dist-packages/'
zipfile.ZipFile(whl).extractall(target)
print('[✓] shamir-mnemonic installed successfully.')
"

echo "[ATM] Verifying installation..."
python3 -c "from shamir_mnemonic import generate_mnemonics; print('[✓] shamir_mnemonic verified and ready.')"