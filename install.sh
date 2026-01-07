#!/usr/bin/env bash

set -e

echo "[*] ShellCraft dependency installer"
echo "[*] Checking environment..."

# Require Linux
if [[ "$(uname -s)" != "Linux" ]]; then
    echo "[-] Unsupported OS. Linux required."
    exit 1
fi

# Require root
if [[ "$EUID" -ne 0 ]]; then
    echo "[-] Please run as root (sudo ./install.sh)"
    exit 1
fi

echo "[*] Detecting package manager..."

if command -v apt >/dev/null 2>&1; then
    PM="apt"
elif command -v dnf >/dev/null 2>&1; then
    PM="dnf"
elif command -v pacman >/dev/null 2>&1; then
    PM="pacman"
else
    echo "[-] Unsupported package manager"
    exit 1
fi

echo "[*] Using package manager: $PM"

install_apt() {
    apt update
    apt install -y \
        python3 \
        python3-pip \
        mingw-w64 \
        metasploit-framework
}

install_dnf() {
    dnf install -y \
        python3 \
        python3-pip \
        mingw64-gcc-c++ \
        metasploit-framework
}

install_pacman() {
    pacman -Sy --noconfirm \
        python \
        mingw-w64-gcc \
        metasploit
}

echo "[*] Installing dependencies..."

case "$PM" in
    apt) install_apt ;;
    dnf) install_dnf ;;
    pacman) install_pacman ;;
esac

echo "[*] Verifying tools..."

REQUIRED_TOOLS=(
    python3
    msfvenom
    x86_64-w64-mingw32-g++
)

for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "[-] Missing tool: $tool"
        exit 1
    fi
done

echo "[+] All dependencies installed successfully"
echo "[*] You can now run: python3 shellcraft.py"
