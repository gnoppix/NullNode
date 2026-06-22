#!/bin/bash
#-------------------------------------------------------------------------------
# Name: Gnoppix Linux - Services
# Architecture: all
# Date: 2002-2026 by Gnoppix Linux
# Author: Andreas Mueller
# Website: https://www.gnoppix.com
# Licence: Business Source License (BSL / BUSL)
# You can use the code for free if your company or organisation doesn't have more than 2 people.
#-------------------------------------------------------------------------------
# NullNode installer — downloads source from GitHub, checks dependencies,
# and sets up a fresh node.
#
# Usage:
#   Interactive (download + run):
#     curl -fsSL https://raw.githubusercontent.com/gnoppix/NullNode/main/install.sh | bash
#
#   Or save first, then run:
#     curl -fsSL -o install.sh https://raw.githubusercontent.com/gnoppix/NullNode/main/install.sh
#     chmod +x install.sh
#     ./install.sh
#
#   Options:
#     --force       skip confirmation prompts
#     --no-download  skip repo download (use when running from a cloned repo)
#-------------------------------------------------------------------------------

set -euo pipefail

# ── colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()    { echo -e "${CYAN}[*]${NC} $*"; }
ok()      { echo -e "${GREEN}[✓]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
fail()    { echo -e "${RED}[✗]${NC} $*"; }

# ── version helper ───────────────────────────────────────────────────────────
ver_ge() {
    dpkg --compare-versions "$1" ge "$2" 2>/dev/null
}

# ── required versions ────────────────────────────────────────────────────────
REQ_PYTHON="3.13"
REQ_GPG="2.5.20"
REQ_WEBSOCKETS="12"

# ── GitHub source ────────────────────────────────────────────────────────────
REPO_URL="https://github.com/gnoppix/NullNode.git"
REPO_ARCHIVE_URL="https://github.com/gnoppix/NullNode/archive/refs/heads/main.tar.gz"
REPO_RAW_URL="https://raw.githubusercontent.com/gnoppix/NullNode/main"

# Files we need from the repo
REPO_FILES=(
    client.py
    crypto.py
    dht.py
    nat.py
    p2p.py
    protocol.py
    ratelimit.py
    relay.py
    nullnode.sh
    requirements.txt
    Dockerfile
    go.mod
)

# ── parse args ───────────────────────────────────────────────────────────────
FORCE=false
NO_DOWNLOAD=false
for arg in "$@"; do
    case "$arg" in
        --force)       FORCE=true ;;
        --no-download) NO_DOWNLOAD=true ;;
        -h|--help)
            sed -n '2,15p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
    esac
done

# ── determine install dir ────────────────────────────────────────────────────
# If running from a pipe (curl | bash), $0 is not a real file → use cwd.
# If running from a downloaded/cloned file, use its directory.
if [[ -f "$0" ]]; then
    INSTALL_DIR="$(cd "$(dirname "$0")" && pwd)"
else
    INSTALL_DIR="${PWD}/NullNode"
fi
VENV_DIR="${INSTALL_DIR}/venv"

echo ""
echo -e "${BOLD}============================================="
echo "  NullNode Installer — Gnoppix Messenger"
echo -e "=============================================${NC}"
echo ""

# ── 0. download source from GitHub ───────────────────────────────────────────
if ! $NO_DOWNLOAD; then
    # Check if we were piped from curl (no real $0 file) or if install.sh
    # is the only file present (no source files yet)
    NEED_DOWNLOAD=false
    if [[ ! -f "$0" ]]; then
        NEED_DOWNLOAD=true
    else
        # Check if source files already exist alongside install.sh
        for f in client.py crypto.py dht.py; do
            if [[ ! -f "${INSTALL_DIR}/${f}" ]]; then
                NEED_DOWNLOAD=true
                break
            fi
        done
    fi

    if $NEED_DOWNLOAD; then
        info "Downloading NullNode source from GitHub..."

        # Prefer tarball download (single request, preserves structure)
        DOWNLOAD_OK=false

        if command -v curl &>/dev/null; then
            TMPDIR="$(mktemp -d)"
            info "Fetching ${REPO_ARCHIVE_URL}..."
            if curl -fsSL -o "${TMPDIR}/nullnode.tar.gz" "$REPO_ARCHIVE_URL" 2>/dev/null; then
                info "Extracting..."
                tar xzf "${TMPDIR}/nullnode.tar.gz" -C "$TMPDIR"
                EXTRACTED="$(find "$TMPDIR" -maxdepth 2 -name "client.py" -printf '%h\n' 2>/dev/null | head -1)"
                if [[ -n "$EXTRACTED" ]]; then
                    # Move extracted contents to INSTALL_DIR
                    if [[ "$INSTALL_DIR" != "$EXTRACTED" ]]; then
                        mkdir -p "$INSTALL_DIR"
                        cp -f "${EXTRACTED}/"* "${INSTALL_DIR}/"
                    fi
                    DOWNLOAD_OK=true
                fi
            fi
            rm -rf "$TMPDIR"
        fi

        if ! $DOWNLOAD_OK && command -v git &>/dev/null; then
            info "Falling back to git clone..."
            if git clone --depth 1 "$REPO_URL" "$INSTALL_DIR" 2>/dev/null; then
                DOWNLOAD_OK=true
            fi
        fi

        if ! $DOWNLOAD_OK; then
            # Last resort: download individual files via raw URL
            info "Falling back to individual file download..."
            mkdir -p "$INSTALL_DIR"
            ALL_OK=true
            for f in "${REPO_FILES[@]}"; do
                if command -v curl &>/dev/null; then
                    if ! curl -fsSL -o "${INSTALL_DIR}/${f}" "${REPO_RAW_URL}/${f}" 2>/dev/null; then
                        warn "Failed to download: ${f}"
                        ALL_OK=false
                    fi
                elif command -v wget &>/dev/null; then
                    if ! wget -q -O "${INSTALL_DIR}/${f}" "${REPO_RAW_URL}/${f}" 2>/dev/null; then
                        warn "Failed to download: ${f}"
                        ALL_OK=false
                    fi
                else
                    fail "Neither curl nor wget available."
                    exit 1
                fi
            done
            $ALL_OK && DOWNLOAD_OK=true
        fi

        if ! $DOWNLOAD_OK; then
            fail "Could not download NullNode source."
            echo "  Please clone manually:"
            echo "    git clone ${REPO_URL}"
            echo "  Then re-run install.sh with --no-download"
            exit 1
        fi

        ok "Source downloaded to ${INSTALL_DIR}"

        # Re-execute from the downloaded install.sh so $0 is a real file
        if [[ ! -f "$0" ]] || [[ "$0" != "${INSTALL_DIR}/install.sh" ]]; then
            if [[ -f "${INSTALL_DIR}/install.sh" ]]; then
                info "Restarting installer from downloaded copy..."
                echo ""
                exec bash "${INSTALL_DIR}/install.sh" --no-download "$([[ "$FORCE" == true ]] && echo --force)"
            fi
        fi
    else
        ok "Source files already present in ${INSTALL_DIR}"
    fi
fi

# Verify required files are present
MISSING=false
for f in client.py crypto.py dht.py nat.py p2p.py protocol.py ratelimit.py relay.py nullnode.sh requirements.txt; do
    if [[ ! -f "${INSTALL_DIR}/${f}" ]]; then
        fail "Missing required file: ${f}"
        MISSING=true
    fi
done
if $MISSING; then
    fail "Source is incomplete. Re-run without --no-download to fetch from GitHub."
    exit 1
fi
ok "All source files present"

# ── 1. check running as root ─────────────────────────────────────────────────
if [[ "$(id -u)" -eq 0 ]]; then
    fail "Do not run this installer as root."
    fail "NullNode runs as a regular user for security."
    exit 1
fi
ok "Running as user $(whoami)"

# ── 2. check OS ─────────────────────────────────────────────────────────────
if [[ ! -f /etc/debian_version ]]; then
    warn "This installer is designed for Debian-based systems."
    warn "Continuing anyway — some checks may not apply."
else
    DEBIAN_VER="$(cat /etc/debian_version)"
    info "Debian version: ${DEBIAN_VER}"
fi

# ── 3. check Python 3 ───────────────────────────────────────────────────────
info "Checking Python 3..."
PYTHON_BIN=""
for cmd in python3 python3.13 python3.14; do
    if command -v "$cmd" &>/dev/null; then
        PYTHON_BIN="$(command -v "$cmd")"
        break
    fi
done

if [[ -z "$PYTHON_BIN" ]]; then
    fail "Python 3 not found."
    echo "  Install with:  sudo apt install python3"
    exit 1
fi

PYTHON_VER="$("$PYTHON_BIN" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
if ver_ge "$PYTHON_VER" "$REQ_PYTHON"; then
    ok "Python ${PYTHON_VER} (${PYTHON_BIN}) >= ${REQ_PYTHON}"
else
    fail "Python ${PYTHON_VER} is too old (need >= ${REQ_PYTHON})."
    echo "  Install a newer Python or use pyenv."
    exit 1
fi

# ── 4. check python3-venv ───────────────────────────────────────────────────
info "Checking python3-venv module..."
if "$PYTHON_BIN" -c "import venv" 2>/dev/null; then
    ok "venv module available"
else
    fail "Python venv module missing."
    echo "  Install with:  sudo apt install python3-venv"
    exit 1
fi

# ── 5. check GnuPG ──────────────────────────────────────────────────────────
info "Checking GnuPG..."
if ! command -v gpg &>/dev/null; then
    fail "gpg binary not found."
    echo "  Install with:  sudo apt install gnupg"
    exit 1
fi

GPG_VER="$(gpg --version 2>&1 | head -1 | awk '{print $3}')"
if ver_ge "$GPG_VER" "$REQ_GPG"; then
    ok "GnuPG ${GPG_VER} >= ${REQ_GPG}"
else
    fail "GnuPG ${GPG_VER} is too old (need >= ${REQ_GPG})."
    echo "  GnuPG 2.5+ is required for post-quantum (Kyber) support."
    exit 1
fi

if gpg --version 2>&1 | grep -qi "kyber"; then
    ok "GnuPG has Kyber (ML-KEM) support"
else
    fail "GnuPG does not list Kyber support."
    echo "  You need GnuPG >= 2.5.20 built with --enable-experimental-pqc."
    exit 1
fi

# ── 6. check websockets (pip or deb) ────────────────────────────────────────
info "Checking websockets library..."
WEBSOCKETS_OK=false

if "$PYTHON_BIN" -c "import websockets" 2>/dev/null; then
    SYS_WS_VER="$("$PYTHON_BIN" -c 'import websockets; print(websockets.__version__)')"
    if ver_ge "$SYS_WS_VER" "$REQ_WEBSOCKETS"; then
        ok "websockets ${SYS_WS_VER} (system) >= ${REQ_WEBSOCKETS}"
        WEBSOCKETS_OK=true
    else
        warn "System websockets ${SYS_WS_VER} is too old (need >= ${REQ_WEBSOCKETS})."
    fi
fi

if ! $WEBSOCKETS_OK; then
    DEB_WS_VER="$(dpkg-query -W -f='${Version}' python3-websockets 2>/dev/null || true)"
    if [[ -n "$DEB_WS_VER" ]]; then
        DEB_WS_CLEAN="$(echo "$DEB_WS_VER" | sed 's/^[0-9]*://; s/-.*//')"
        if ver_ge "$DEB_WS_CLEAN" "$REQ_WEBSOCKETS"; then
            ok "python3-websockets ${DEB_WS_VER} (deb) >= ${REQ_WEBSOCKETS}"
            WEBSOCKETS_OK=true
        else
            warn "python3-websockets ${DEB_WS_VER} is too old."
        fi
    fi
fi

if ! $WEBSOCKETS_OK; then
    warn "websockets not found or too old — will install into venv."
fi

# ── 7. check optional packages ──────────────────────────────────────────────
info "Checking optional packages..."

if command -v git &>/dev/null; then
    ok "git $(git --version | awk '{print $3}')"
else
    warn "git not found (optional)"
fi

if command -v curl &>/dev/null; then
    ok "curl available"
elif command -v wget &>/dev/null; then
    ok "wget available"
else
    warn "Neither curl nor wget found"
fi

# ── 8. create virtual environment ────────────────────────────────────────────
echo ""
if [[ -d "$VENV_DIR" ]]; then
    if $FORCE; then
        info "Removing existing venv (--force)..."
        rm -rf "$VENV_DIR"
    else
        warn "Virtual environment already exists: ${VENV_DIR}"
        read -rp "  Re-create it? [y/N] " answer
        if [[ "$answer" =~ ^[Yy]$ ]]; then
            rm -rf "$VENV_DIR"
        else
            info "Keeping existing venv."
        fi
    fi
fi

if [[ ! -d "$VENV_DIR" ]]; then
    info "Creating virtual environment in ${VENV_DIR}..."
    "$PYTHON_BIN" -m venv "$VENV_DIR"
    ok "Virtual environment created"
fi

# ── 9. install / upgrade pip and websockets ─────────────────────────────────
info "Installing dependencies in venv..."
"$VENV_DIR/bin/pip" install --upgrade pip -q
"$VENV_DIR/bin/pip" install --upgrade "websockets>=${REQ_WEBSOCKETS}" -q
ok "websockets installed"

INSTALLED_WS_VER="$("$VENV_DIR/bin/python" -c 'import websockets; print(websockets.__version__)')"
ok "websockets ${INSTALLED_WS_VER} active in venv"

# ── 10. verify nullnode.sh is executable ────────────────────────────────────
if [[ -x "${INSTALL_DIR}/nullnode.sh" ]]; then
    ok "nullnode.sh is executable"
else
    info "Making nullnode.sh executable..."
    chmod +x "${INSTALL_DIR}/nullnode.sh"
    ok "nullnode.sh is now executable"
fi

# ── 11. create .nullnode directory ──────────────────────────────────────────
NULLNODE_HOME="${HOME}/.nullnode"
if [[ ! -d "$NULLNODE_HOME" ]]; then
    info "Creating ${NULLNODE_HOME}..."
    mkdir -p "$NULLNODE_HOME"
    chmod 700 "$NULLNODE_HOME"
    ok "Created ${NULLNODE_HOME} (mode 700)"
else
    ok "${NULLNODE_HOME} already exists"
fi

# ── 12. summary ─────────────────────────────────────────────────────────────
echo ""
echo -e "${BOLD}============================================="
echo "  Installation complete!"
echo -e "=============================================${NC}"
echo ""
echo "  Source dir:    ${INSTALL_DIR}"
echo "  Virtual env:   ${VENV_DIR}"
echo "  NullNode home: ${NULLNODE_HOME}"
echo "  Python:        ${PYTHON_VER}"
echo "  GnuPG:         ${GPG_VER}"
echo "  websockets:    ${INSTALLED_WS_VER}"
echo ""
echo "  Next steps:"
echo ""
echo "    1. Create your identity:"
echo "       ${INSTALL_DIR}/nullnode.sh init"
echo ""
echo "    2. Show your Null ID:"
echo "       ${INSTALL_DIR}/nullnode.sh id"
echo ""
echo "    3. Export your public key:"
echo "       ${INSTALL_DIR}/nullnode.sh export > mykey.asc"
echo ""
echo "    4. Start your P2P node:"
echo "       ${INSTALL_DIR}/nullnode.sh p2p --port 9001"
echo ""
echo "  For full documentation see README.md and DEVELOPER.md."
echo ""
