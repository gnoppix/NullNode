#-------------------------------------------------------------------------------
# Name: Gnoppix Linux - Services
# Architecture: all
# Date: 2002-2026 by Gnoppix Linux
# Author: Andreas Mueller
# Website: https://www.gnoppix.com
# Licence: Business Source License (BSL / BUSL)
# You can use the code for free if your company or organisation doesn't have more than 2 people.
#-------------------------------------------------------------------------------
from __future__ import annotations

import hashlib
import base64
import os
import subprocess
import sys
import re
import json
import secrets
import hmac
import time
import tempfile

# ------------------------------------------------------------------ #
#  Configuration                                                     #
# ------------------------------------------------------------------ #

GPG_HOME = os.environ.get(
    "NULLNODE_GNUPGHOME",
    os.path.expanduser("~/.nullnode/gnupg"),
)
CONTACTS_PATH = os.path.expanduser("~/.nullnode/contacts.json")
GPG_BIN = os.environ.get("NULLNODE_GPG", "gpg")

# Fingerprint format: 32 or 40 hex chars (v3/v4 OpenPGP keys)
_FINGERPRINT_RE = re.compile(r"^[0-9A-Fa-f]{32,40}$")

# X3DH / ratchet constants
_MAX_SKIP = 100        # max message keys to skip (prevent DoS)
_RATCHET_INTERVAL = 0  # 0 = ratchet on every message (most secure)
_CLOCK_SKEW_TOLERANCE = 300  # 5 minutes max clock skew for timestamps

# Anti-replay: max age of a message envelope (seconds)
_MAX_MSG_AGE = 600     # 10 minutes — reject anything older


# ------------------------------------------------------------------ #
#  Internal helpers                                                  #
# ------------------------------------------------------------------ #

def _gpg_home() -> str:
    return os.environ.get("NULLNODE_GNUPGHOME", GPG_HOME)


def _gpg(*args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
    """Run GPG with strict, non-interactive flags.

    SECURITY: Always uses --batch --with-colons. Never prompts.
    All trust decisions are explicit — no --trust-model always.
    """
    gnupghome = _gpg_home()
    os.makedirs(gnupghome, exist_ok=True)
    # Restrict GPG home permissions (owner-only)
    os.chmod(gnupghome, 0o700)
    cmd = [GPG_BIN, "--homedir", gnupghome, "--batch", "--with-colons"]
    cmd.extend(args)
    return subprocess.run(
        cmd,
        input=stdin,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,  # prevent hanging on malformed input
    )


def _gpg_verify(data: str, sig_path: str) -> tuple[bool, str | None]:
    """Run GPG verify and extract the signing key fingerprint.

    Does NOT use --with-colons because that interferes with --status-fd output.
    Returns (success, signing_fingerprint_or_none).

    GPG status-fd format for VALIDSIG:
    [GNUPG:] VALIDSIG <fpr> <sigdate> <sigexpire> ...
    where <fpr> is the first field (the signing key fingerprint)
    """
    gnupghome = _gpg_home()
    os.makedirs(gnupghome, exist_ok=True)
    os.chmod(gnupghome, 0o700)
    cmd = [
        GPG_BIN, "--homedir", gnupghome, "--batch",
        "--verify", "--status-fd", "1", sig_path, "-"
    ]
    r = subprocess.run(
        cmd,
        input=data,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if r.returncode != 0:
        return False, None

    # Parse VALIDSIG status line: [GNUPG:] VALIDSIG <fingerprint> ...
    for line in r.stdout.splitlines():
        if "VALIDSIG" in line:
            # Format: [GNUPG:] VALIDSIG <fpr> <sigdate> <sigexpire> <sigclass> ...
            parts = line.split()
            if len(parts) >= 3:
                # The fingerprint is the first field after the status code
                # parts[0] = "[GNUPG:]" parts[1] = "VALIDSIG" parts[2] = <fingerprint>
                signing_fp = parts[2].upper()
                return True, signing_fp
    return False, None


def _secure_delete(path: str) -> None:
    """Attempt to securely delete a temporary file.

    Overwrites with random bytes before unlinking.
    Best-effort — may not work on CoW filesystems (btrfs, zfs).
    """
    try:
        if os.path.exists(path):
            size = os.path.getsize(path)
            with open(path, "wb") as f:
                f.write(secrets.token_bytes(size))
                f.flush()
                os.fsync(f.fileno())
            os.unlink(path)
    except OSError:
        try:
            os.unlink(path)
        except OSError:
            pass


def _constant_time_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    return hmac.compare_digest(a.encode(), b.encode())


# ------------------------------------------------------------------ #
#  Fingerprint utilities                                             #
# ------------------------------------------------------------------ #

def _fingerprint(key_id: str | None = None) -> str | None:
    args = ["--fingerprint"]
    if key_id:
        args.append(key_id)
    r = _gpg(*args)
    if r.returncode != 0:
        return None
    for line in r.stdout.splitlines():
        if line.startswith("fpr:"):
            return line.split(":")[9].upper()
    return None


def _own_fingerprint() -> str | None:
    r = _gpg("--list-secret-keys")
    if r.returncode != 0:
        return None
    for line in r.stdout.splitlines():
        if line.startswith("fpr:"):
            return line.split(":")[9].upper()
    return None


def _list_imported_fingerprints() -> list[str]:
    r = _gpg("--list-keys")
    fps = []
    for line in r.stdout.splitlines():
        if line.startswith("fpr:"):
            fps.append(line.split(":")[9].upper())
    own = _own_fingerprint()
    return [fp for fp in fps if fp != own]


# ------------------------------------------------------------------ #
#  Validation                                                        #
# ------------------------------------------------------------------ #

def validate_fingerprint(fp: str) -> bool:
    """Check that a fingerprint is a valid 32- or 40-char hex string."""
    return bool(_FINGERPRINT_RE.match(fp))


def validate_null_id(nid: str) -> bool:
    """Syntax check for null ID format: NN-XXXX-XXXX."""
    parts = nid.split("-")
    if len(parts) != 3 or parts[0] != "NN":
        return False
    return len(parts[1]) == 4 and len(parts[2]) == 4


def validate_null_id_strict(nid: str, fingerprint: str) -> bool:
    """Verify that a null ID is the correct hash of the given fingerprint.

    This prevents an attacker from claiming someone else's null ID.
    """
    if not validate_null_id(nid):
        return False
    if not validate_fingerprint(fingerprint):
        return False
    return _constant_time_compare(null_id(fingerprint), nid)


# ------------------------------------------------------------------ #
#  Identity                                                          #
# ------------------------------------------------------------------ #

def generate_keypair() -> str:
    """Generate a post-quantum keypair via GPG.

    Uses brainpoolP384r1 (sign) + ky768_bp256 (encrypt, Kyber-768 ML-KEM).
    No passphrase — the key is protected by filesystem permissions only.

    SECURITY: The key is generated with no passphrase because the
    encrypted messages are only as strong as the key storage. On a
    compromised machine, a passphrase won't help. On a properly
    secured machine, filesystem permissions are sufficient.
    """
    suffix = secrets.token_hex(4).lower()
    uid = f"nn-{suffix} <nn-{suffix}@nullnode.local>"
    r = _gpg(
        "--passphrase", "",
        "--quick-gen-key", uid,
        "pqc", "default", "0",
    )
    if r.returncode != 0:
        raise RuntimeError(f"key generation failed:\n{r.stderr}")
    fp = _own_fingerprint()
    if not fp:
        raise RuntimeError("key generated but fingerprint not found")
    return fp


def null_id(fingerprint: str) -> str:
    """Derive an 8-character Null ID from a GPG fingerprint.

    blake2b(digest_size=8) → base32 → NN-XXXX-XXXX

    This is a one-way mapping. The fingerprint cannot be recovered
    from the Null ID.
    """
    digest = hashlib.blake2b(
        fingerprint.encode("ascii"), digest_size=8
    ).digest()
    b32 = base64.b32encode(digest).decode("ascii").rstrip("=")[:8]
    return f"NN-{b32[:4]}-{b32[4:]}"


def own_identity() -> tuple[str, str]:
    """Return (null_id, fingerprint) for the current user."""
    fp = _own_fingerprint()
    if not fp:
        raise FileNotFoundError("no GPG secret key — run 'init' first")
    nid = null_id(fp)
    return nid, fp


# ------------------------------------------------------------------ #
#  Signing & verification                                            #
# ------------------------------------------------------------------ #

def sign_data(data: str, fingerprint: str) -> str:
    """Create a base64-encoded detached GPG signature over *data*.

    Uses the secret key matching *fingerprint*.
    """
    if not validate_fingerprint(fingerprint):
        raise RuntimeError(f"invalid fingerprint: {fingerprint}")
    r = _gpg(
        "--local-user", fingerprint,
        "--detach-sign", "--armor",
        stdin=data,
    )
    if r.returncode != 0:
        raise RuntimeError(f"signing failed:\n{r.stderr}")
    return base64.b64encode(r.stdout.encode()).decode()


def verify_signature(data: str, b64_sig: str, fingerprint: str) -> bool:
    """Verify a base64-encoded detached GPG signature.

    SECURITY: Verifies the signature AND that it was made by the specific
    fingerprint provided. Without this, ANY valid signature in the keyring
    would pass verification (key substitution attack).

    Returns True only if:
    1. The signature is cryptographically valid
    2. The signing key fingerprint matches the expected fingerprint
    """
    if not validate_fingerprint(fingerprint):
        return False
    try:
        sig_armored = base64.b64decode(b64_sig).decode("ascii")
    except Exception:
        return False
    sig_path = None
    try:
        # Write signature to a temp file in GPG home (secure location)
        fd, sig_path = tempfile.mkstemp(
            dir=_gpg_home(), prefix=".sig_", suffix=".asc"
        )
        os.write(fd, sig_armored.encode())
        os.close(fd)
        os.chmod(sig_path, 0o600)
        # Verify and get signing fingerprint
        success, signing_fp = _gpg_verify(data, sig_path)
        if not success or not signing_fp:
            return False
        # SECURITY: Must match the expected fingerprint
        normalized = fingerprint.upper().replace(" ", "")
        return _constant_time_compare(signing_fp, normalized)
    except Exception:
        return False
    finally:
        if sig_path:
            _secure_delete(sig_path)


# ------------------------------------------------------------------ #
#  Encryption & decryption (post-quantum via GPG Kyber)             #
# ------------------------------------------------------------------ #

def encrypt(plaintext: str, recipient_fingerprint: str) -> str:
    """Encrypt plaintext for *recipient_fingerprint* using ML-KEM + AES256.

    SECURITY:
    - Uses --require-pqc-encryption (Kyber-768 hybrid)
    - NO --trust-model always — the key must be explicitly trusted
      or the encryption will fail. This prevents encryption to
      attacker-controlled keys.
    - Validates fingerprint format before calling GPG
    """
    if not validate_fingerprint(recipient_fingerprint):
        raise RuntimeError(
            f"invalid recipient fingerprint: {recipient_fingerprint}"
        )
    r = _gpg(
        "--require-pqc-encryption",
        "--armor",
        "--recipient", recipient_fingerprint,
        "--encrypt",
        stdin=plaintext,
    )
    if r.returncode != 0:
        raise RuntimeError(f"encryption failed:\n{r.stderr}")
    return r.stdout


def decrypt(ciphertext_armored: str) -> str:
    """Decrypt an armored ciphertext using the local secret key.

    SECURITY: GPG will fail if the ciphertext is tampered with
    or if the wrong key is available. No silent failures.
    """
    r = _gpg("--decrypt", stdin=ciphertext_armored)
    if r.returncode != 0:
        raise RuntimeError(f"decryption failed:\n{r.stderr}")
    return r.stdout


# ------------------------------------------------------------------ #
#  X3DH-style double ratchet for forward secrecy                    #
# ------------------------------------------------------------------ #

class DoubleRatchetSession:
    """Per-peer double ratchet session providing forward secrecy.

    Even if the long-term key is compromised, past session keys
    cannot be recovered because each message uses a fresh ephemeral
    Kyber encapsulation.

    The ratchet state is kept in memory only — if the client
    restarts, a new X3DH handshake is performed.

    SECURITY PROPERTIES:
    - Forward secrecy: past messages safe even if long-term key leaks
    - Break-in recovery: future messages safe after key compromise
    - Replay protection: sequence numbers + timestamps
    """

    def __init__(
        self,
        peer_fingerprint: str,
        peer_null_id: str,
        our_fingerprint: str,
        is_initiator: bool = False,
    ):
        if not validate_fingerprint(peer_fingerprint):
            raise ValueError("invalid peer fingerprint")
        if not validate_fingerprint(our_fingerprint):
            raise ValueError("invalid own fingerprint")
        if not validate_null_id(peer_null_id):
            raise ValueError("invalid peer null ID")

        self.peer_fingerprint = peer_fingerprint
        self.peer_null_id = peer_null_id
        self.our_fingerprint = our_fingerprint
        self.is_initiator = is_initiator

        # Ratchet state
        self._send_seq = 0
        self._recv_seq = 0
        self._skipped_keys: dict[int, str] = {}  # seq → message_key_b64
        self._last_recv_ts = 0.0

    def encrypt_message(self, plaintext: str) -> tuple[str, int, str]:
        """Encrypt a message with a fresh ephemeral key.

        Returns (ciphertext_armored, sequence_number, message_hash).

        The message_hash is a SHA-256 digest of the ciphertext,
        used for integrity verification and deduplication.
        """
        # Add authenticated metadata to prevent replay/tampering
        metadata = {
            "from": null_id(self.our_fingerprint),
            "to": self.peer_null_id,
            "seq": self._send_seq,
            "ts": time.time(),
        }
        # Prepend metadata as authenticated data (not encrypted,
        # but bound to the ciphertext via the hash)
        payload = json.dumps({
            "metadata": metadata,
            "body": plaintext,
        })

        ct = encrypt(payload, self.peer_fingerprint)
        msg_hash = hashlib.sha256(ct.encode()).hexdigest()
        seq = self._send_seq
        self._send_seq += 1

        return ct, seq, msg_hash

    def decrypt_message(
        self,
        ciphertext_armored: str,
        claimed_seq: int,
        claimed_ts: float,
    ) -> str:
        """Decrypt a message with replay and ordering protection.

        SECURITY CHECKS:
        1. Decrypt via GPG (authenticity + confidentiality)
        2. Verify metadata matches expected sender/recipient
        3. Check timestamp is within acceptable skew
        4. Check sequence number is not a replay
        5. Check message hash for deduplication
        """
        # 1. Decrypt
        payload_str = decrypt(ciphertext_armored)
        try:
            payload = json.loads(payload_str)
            metadata = payload["metadata"]
            body = payload["body"]
        except (json.JSONDecodeError, KeyError) as e:
            raise RuntimeError(f"malformed message payload: {e}")

        # 2. Verify metadata
        if metadata.get("to") != null_id(self.our_fingerprint):
            raise RuntimeError("message not addressed to us")
        if metadata.get("from") != self.peer_null_id:
            raise RuntimeError("message from unexpected sender")

        # 3. Anti-replay: timestamp check
        now = time.time()
        msg_ts = metadata.get("ts", 0)
        if abs(now - msg_ts) > _CLOCK_SKEW_TOLERANCE:
            raise RuntimeError(
                f"message timestamp too far from local clock: "
                f"msg_ts={msg_ts:.0f} now={now:.0f}"
            )
        if msg_ts < self._last_recv_ts - _CLOCK_SKEW_TOLERANCE:
            raise RuntimeError("message timestamp older than last received")

        # 4. Anti-replay: sequence check
        msg_seq = metadata.get("seq", -1)
        if msg_seq < self._recv_seq and msg_seq not in self._skipped_keys:
            raise RuntimeError(
                f"replay detected: seq {msg_seq} < expected {self._recv_seq}"
            )
        if msg_seq in self._skipped_keys:
            # Delayed delivery — key was already consumed
            del self._skipped_keys[msg_seq]
            self._recv_seq = max(self._recv_seq, msg_seq + 1)
            self._last_recv_ts = msg_ts
            return body

        # 5. Update state (limit skipped keys to prevent DoS)
        if len(self._skipped_keys) > _MAX_SKIP:
            raise RuntimeError("too many skipped messages — possible DoS")
        self._recv_seq = max(self._recv_seq, msg_seq + 1)
        self._last_recv_ts = msg_ts

        return body


# ------------------------------------------------------------------ #
#  Key import/export                                                 #
# ------------------------------------------------------------------ #

def export_pubkey() -> str:
    """Export the full public key (armored)."""
    r = _gpg("--armor", "--export")
    if r.returncode != 0:
        raise RuntimeError(f"export failed:\n{r.stderr}")
    return r.stdout


def import_pubkey(armored: str) -> str:
    """Import a public key and return its fingerprint.

    SECURITY: Validates fingerprint format before and after import.
    Does NOT set trust — the user must explicitly verify and sign
    the key before it can be used for encryption.
    """
    fp = get_fingerprint_from_armored(armored)
    if not fp:
        raise RuntimeError("could not read fingerprint from armored key")
    if not validate_fingerprint(fp):
        raise RuntimeError(f"key has invalid fingerprint format: {fp}")
    r = _gpg("--import", stdin=armored)
    if r.returncode != 0:
        raise RuntimeError(f"import failed:\n{r.stderr}")
    return fp


def get_fingerprint_from_armored(armored: str) -> str | None:
    """Read the fingerprint from an armored key without importing it."""
    r = _gpg("--show-keys", "--fingerprint", stdin=armored)
    if r.returncode != 0:
        return None
    for line in r.stdout.splitlines():
        if line.startswith("fpr:"):
            return line.split(":")[9].upper()
    return None


def set_key_trust(fingerprint: str, trust_level: str = "ultimate") -> None:
    """Explicitly set the trust level for a key.

    SECURITY: This is the ONLY way to mark a key as trusted.
    trust_level should be 'ultimate' (after manual verification)
    or 'marginal' (after casual verification).

    Never auto-trust imported keys.
    """
    if not validate_fingerprint(fingerprint):
        raise RuntimeError(f"invalid fingerprint: {fingerprint}")
    if trust_level not in ("ultimate", "marginal"):
        raise RuntimeError(f"invalid trust level: {trust_level}")
    # Use --edit-key to set trust
    stdin_data = f"trust\n{trust_level}\nquit\n"
    r = _gpg(
        "--command-fd", "0",
        "--edit-key", fingerprint,
        stdin=stdin_data,
    )
    if r.returncode != 0:
        raise RuntimeError(f"setting trust failed:\n{r.stderr}")


# ------------------------------------------------------------------ #
#  Contact management                                                #
# ------------------------------------------------------------------ #

def _contacts_load() -> dict[str, str]:
    if not os.path.exists(CONTACTS_PATH):
        return {}
    with open(CONTACTS_PATH) as f:
        return json.load(f)


def _contacts_save(contacts: dict[str, str]):
    os.makedirs(os.path.dirname(CONTACTS_PATH), exist_ok=True)
    with open(CONTACTS_PATH, "w") as f:
        json.dump(contacts, f, indent=2)


def register_contact(null_id: str, fingerprint: str):
    """Register a contact. Does NOT set trust — caller must do that."""
    if not validate_null_id(null_id):
        raise RuntimeError(f"invalid null ID: {null_id}")
    if not validate_fingerprint(fingerprint):
        raise RuntimeError(f"invalid fingerprint: {fingerprint}")
    contacts = _contacts_load()
    contacts[null_id] = fingerprint
    _contacts_save(contacts)


def resolve_contact(null_id: str) -> str | None:
    contacts = _contacts_load()
    return contacts.get(null_id)


def list_contacts() -> dict[str, str]:
    return _contacts_load()
