"""DAPPrincipal — creates and signs agent credentials."""

from __future__ import annotations

import time
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

from .types import AgentCredentialPayload, Verification


def _parse_duration(s: str) -> int:
    """Parse a duration string like '24h', '7d', '30m' into seconds."""
    unit = s[-1]
    value = int(s[:-1])
    if unit == "h":
        return value * 3600
    if unit == "d":
        return value * 86400
    if unit == "m":
        return value * 60
    if unit == "s":
        return value
    raise ValueError(f"Unknown duration unit: {unit}")


class DAPPrincipal:
    """Represents a principal that can issue agent credentials."""

    def __init__(
        self,
        *,
        principal_id: str,
        name: str,
        private_key: Ed25519PrivateKey,
        public_key: Ed25519PublicKey,
    ) -> None:
        self.principal_id = principal_id
        self.name = name
        self._private_key = private_key
        self._public_key = public_key

    @classmethod
    def generate(cls, *, principal_id: str, name: str) -> DAPPrincipal:
        """Generate a new principal with a fresh Ed25519 keypair."""
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return cls(principal_id=principal_id, name=name, private_key=private_key, public_key=public_key)

    def issue_credential(
        self,
        *,
        agent_id: str,
        scope: list[str],
        principal_type: str = "organization",
        purpose: str | None = None,
        contact_email: str | None = None,
        expires_in: str = "24h",
        issuer_id: str | None = None,
        verification: Verification | None = None,
        constraints: dict[str, Any] | None = None,
    ) -> str:
        """Issue a signed JWT credential for an agent."""
        now = int(time.time())
        exp = now + _parse_duration(expires_in)

        payload = AgentCredentialPayload(
            spec_version="dap/0.1",
            agent_id=agent_id,
            principal_id=self.principal_id,
            principal_name=self.name,
            principal_type=principal_type,
            scope=scope,
            purpose=purpose,
            contact_email=contact_email,
            issuer_id=issuer_id,
            verification=verification,
            constraints=constraints,
        )

        claims = payload.to_dict()
        claims["iat"] = now
        claims["exp"] = exp

        return jwt.encode(
            claims,
            self._private_key,
            algorithm="EdDSA",
            headers={"typ": "dap-agent-credential+jwt"},
        )

    def export_public_key(self) -> Ed25519PublicKey:
        """Return the public key object."""
        return self._public_key

    def export_public_key_pem(self) -> bytes:
        """Export the public key in PEM format."""
        return self._public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
