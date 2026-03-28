#!/bin/bash
set -e

WORKSPACE_DIR="data/morpho-workspace"

echo "=========================================="
echo " Setting up Morpho Multi-Repo Workspace   "
echo "=========================================="

mkdir -p "$WORKSPACE_DIR"
cd "$WORKSPACE_DIR"

# 1. Morpho Blue (Lending Core)
if [ ! -d "morpho-blue" ]; then
    echo "[+] Cloning Morpho Blue..."
    git clone https://github.com/morpho-org/morpho-blue.git
else
    echo "[-] Morpho Blue already exists."
fi

# 2. MetaMorpho (ERC-4626 Vaults)
if [ ! -d "metamorpho" ]; then
    echo "[+] Cloning MetaMorpho..."
    git clone https://github.com/morpho-org/metamorpho.git
else
    echo "[-] MetaMorpho already exists."
fi

# 3. Morpho Oracles (Price feeds/oracles)
# Correct repo name: morpho-blue-oracles (not morpho-oracles)
if [ ! -d "morpho-blue-oracles" ]; then
    echo "[+] Cloning Morpho Blue Oracles..."
    git clone https://github.com/morpho-org/morpho-blue-oracles.git
else
    echo "[-] Morpho Blue Oracles already exists."
fi

# 4. Morpho Blue Bundlers (Atomic multicall execution - key attack surface)
if [ ! -d "morpho-blue-bundlers" ]; then
    echo "[+] Cloning Morpho Blue Bundlers..."
    git clone https://github.com/morpho-org/morpho-blue-bundlers.git
else
    echo "[-] Morpho Blue Bundlers already exists."
fi

echo ""
echo "=========================================="
echo " Morpho repos cloned into: $WORKSPACE_DIR"
echo "   morpho-blue         (lending core)"
echo "   metamorpho          (ERC-4626 vaults)"
echo "   morpho-blue-oracles (price feeds)"
echo "   morpho-blue-bundlers (atomic bundling)"
echo ""
echo " Run Critikal with:"
echo "   python -m src.main --repo data/morpho-workspace --auto-ingest"
echo "=========================================="
