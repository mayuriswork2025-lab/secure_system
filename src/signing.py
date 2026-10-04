"""Ed25519 digital signatures.

Each client holds a long-lived identity key pair. It signs its DH public
value and every encrypted chat message with the private half; peers
verify with the public half. A valid signature proves the payload came
from the holder of that private key and was not modified afterwards.

Phase 3 limitation: the public signing key travels alongside the DH
public value, unauthenticated, so a man-in-the-middle could substitute
its own. Phase 4's certificate authority closes that gap by binding each
signing key to a username.
"""

import json
from typing import Any, Dict

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

try:
    from src.crypto import b64decode, b64encode
except ImportError:
    from crypto import b64decode, b64encode


class SigningIdentity:
    """A client's Ed25519 key pair."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self.private_key = private_key
        public_bytes = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        self.public_key_b64 = b64encode(public_bytes)

    @classmethod
    def generate(cls) -> "SigningIdentity":
        return cls(Ed25519PrivateKey.generate())

    def sign(self, fields: Dict[str, Any]) -> str:
        return b64encode(self.private_key.sign(canonical_bytes(fields)))


def verify(public_key_b64: str, fields: Dict[str, Any], signature_b64: str) -> bool:
    """Return True only if signature_b64 is a valid signature of fields under the key."""
    try:
        public_key = Ed25519PublicKey.from_public_bytes(b64decode(public_key_b64))
        public_key.verify(b64decode(signature_b64), canonical_bytes(fields))
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def canonical_bytes(fields: Dict[str, Any]) -> bytes:
    """Serialize fields deterministically so signer and verifier hash identical bytes.

    Plain json.dumps() may order keys or space values differently between
    calls; sorting keys and fixing separators gives one byte string per
    set of fields.
    """
    return json.dumps(fields, sort_keys=True, separators=(",", ":")).encode("utf-8")


if __name__ == "__main__":
    alice = SigningIdentity.generate()
    fields = {"type": "chat", "sender": "alice", "target": "bob", "ciphertext": "abc"}
    signature = alice.sign(fields)

    print(f"Alice's public key: {alice.public_key_b64}")
    print(f"Signature:          {signature}")
    print(f"Valid:              {verify(alice.public_key_b64, fields, signature)}")

    tampered = dict(fields, ciphertext="abd")
    print(f"Tampered valid:     {verify(alice.public_key_b64, tampered, signature)}")
