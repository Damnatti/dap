"""DAPService — accepts and verifies agent registrations."""

from __future__ import annotations

import base64
import json
import re
import secrets
import time
from typing import Any, Awaitable, Callable

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .types import (
    AgentCredentialPayload,
    DAPError,
    RegisterRequest,
    RegisterResponse,
)

# Verification levels ordered by strength
_VERIFICATION_LEVELS = ["self", "email", "phone", "oauth", "domain", "document", "organization"]


def _level_index(level: str) -> int:
    try:
        return _VERIFICATION_LEVELS.index(level)
    except ValueError:
        return -1


def _extract_principal_scheme(principal_id: str) -> str:
    """Extract scheme from a principal ID.

    Examples:
        did:web:example.com -> did:web
        https://example.com -> https
        mailto:user@example.com -> mailto
    """
    if principal_id.startswith("did:"):
        parts = principal_id.split(":")
        if len(parts) >= 3:
            return f"{parts[0]}:{parts[1]}"
        return "did"
    if "://" in principal_id:
        return principal_id.split("://")[0]
    if ":" in principal_id:
        return principal_id.split(":")[0]
    return principal_id


class DAPService:
    """A service that accepts DAP agent registrations."""

    def __init__(
        self,
        *,
        name: str,
        base_url: str,
        resolve_public_key: Callable[[str], Ed25519PublicKey | Awaitable[Ed25519PublicKey]],
        validate_credential: Callable[[AgentCredentialPayload], bool | Awaitable[bool]] | None = None,
        min_verification_level: str = "self",
        trusted_issuers: list[str] | None = None,
        accepted_principal_schemes: list[str] | None = None,
    ) -> None:
        self.name = name
        self.base_url = base_url
        self._resolve_public_key = resolve_public_key
        self._validate_credential = validate_credential
        self._min_verification_level = min_verification_level
        self._trusted_issuers = trusted_issuers
        self._accepted_principal_schemes = accepted_principal_schemes

    def discovery_document(self) -> dict[str, Any]:
        """Return the discovery document to serve at /.well-known/dap."""
        return {
            "dap_version": "0.1",
            "dap_endpoint": f"{self.base_url}/dap/v1",
            "supported_formats": ["jwt"],
            "supported_signature_algorithms": ["EdDSA"],
            "requirements": {
                "principal_types": ["organization", "individual"],
                "min_scope": ["register"],
                "requires_contact_email": False,
                "min_verification_level": self._min_verification_level,
            },
            "service_info": {"name": self.name},
        }

    async def handle_register(self, req: RegisterRequest) -> RegisterResponse:
        """Verify a registration request and return a response.

        Checks (in order):
        1. Format check (JWT typ header)
        2. spec_version check (unsigned — preliminary only)
        3. Signature verification (issuer_id logic)
        4. Trusted issuer check (post-verification)
        5. Principal scheme check (post-verification)
        6. Verification level check (post-verification)
        7. Scope check (post-verification)
        8. Custom validation
        """
        # 1. Decode header — format check
        try:
            header_b64 = req.credential.split(".")[0]
            # Add padding if needed
            padding = 4 - len(header_b64) % 4
            if padding != 4:
                header_b64 += "=" * padding
            header = json.loads(base64.urlsafe_b64decode(header_b64))
        except Exception:
            raise DAPError("invalid_credential_format", "Cannot decode JWT header")

        if header.get("typ") != "dap-agent-credential+jwt":
            raise DAPError("invalid_credential_format", "Expected typ: dap-agent-credential+jwt")

        # 2. Decode payload — spec_version check (preliminary, unsigned)
        try:
            payload_b64 = req.credential.split(".")[1]
            padding = 4 - len(payload_b64) % 4
            if padding != 4:
                payload_b64 += "=" * padding
            raw_payload = json.loads(base64.urlsafe_b64decode(payload_b64))
        except Exception:
            raise DAPError("invalid_credential_format", "Cannot decode JWT payload")

        if raw_payload.get("spec_version") != "dap/0.1":
            raise DAPError("unsupported_version", f"Unknown spec version: {raw_payload.get('spec_version')}")

        # 3. Determine which key to use: issuer_id present -> issuer key, else principal key
        key_id = raw_payload.get("issuer_id") or raw_payload.get("principal_id")
        if not key_id:
            raise DAPError("invalid_credential_format", "Missing principal_id")

        try:
            result = self._resolve_public_key(key_id)
            # Support both sync and async resolve functions
            if hasattr(result, "__await__"):
                public_key = await result  # type: ignore[misc]
            else:
                public_key = result  # type: ignore[assignment]
        except DAPError:
            raise
        except Exception:
            raise DAPError("invalid_signature", f"Cannot resolve public key for {key_id}")

        # 4. Verify signature — PyJWT handles expiry via require: ["exp"]
        try:
            verified_claims = jwt.decode(
                req.credential,
                public_key,
                algorithms=["EdDSA"],
                options={"require": ["exp", "iat"]},
            )
        except jwt.ExpiredSignatureError:
            raise DAPError("credential_expired", "Credential has expired")
        except Exception:
            raise DAPError("invalid_signature", "Signature verification failed")

        verified = AgentCredentialPayload.from_dict(verified_claims)

        # --- All checks below use verified (signed) claims only ---

        # 5. Trusted issuer check
        if verified.issuer_id and self._trusted_issuers is not None:
            if verified.issuer_id not in self._trusted_issuers:
                raise DAPError(
                    "untrusted_issuer",
                    f"Issuer '{verified.issuer_id}' is not in the trusted issuers list",
                )

        # 6. Principal scheme check
        if self._accepted_principal_schemes is not None:
            scheme = _extract_principal_scheme(verified.principal_id)
            if scheme not in self._accepted_principal_schemes:
                raise DAPError(
                    "unsupported_principal_scheme",
                    f"Principal scheme '{scheme}' is not accepted; accepted schemes: {', '.join(self._accepted_principal_schemes)}",
                )

        # 7. Verification level check
        cred_level = "self"
        if verified.verification is not None:
            cred_level = verified.verification.level
        if _level_index(cred_level) < _level_index(self._min_verification_level):
            raise DAPError(
                "insufficient_verification",
                f"Verification level '{cred_level}' is below minimum '{self._min_verification_level}'",
            )

        # 8. Scope check — credential must include "register"
        if "register" not in verified.scope:
            raise DAPError("insufficient_scope", "Credential scope must include 'register'")

        # 9. Custom validation
        if self._validate_credential is not None:
            result = self._validate_credential(verified)
            if hasattr(result, "__await__"):
                ok = await result  # type: ignore[misc]
            else:
                ok = result  # type: ignore[assignment]
            if not ok:
                raise DAPError("principal_blocked", "Custom validation rejected this credential")

        # 10. Issue access token
        safe_principal = re.sub(r"[^a-zA-Z0-9]", "_", verified.principal_id)
        account_id = f"acc_{safe_principal}_{verified.agent_id[-8:]}"
        # Warning: Demo only: not signed. Production implementations must use signed JWTs or opaque tokens.
        access_token = base64.urlsafe_b64encode(
            json.dumps({
                "account_id": account_id,
                "scope": verified.scope,
                "exp": int(time.time()) + 86400,
            }).encode()
        ).decode()

        return RegisterResponse(
            status="registered",
            session_id=f"ses_{secrets.token_hex(4)}",
            access_token=access_token,
            granted_scope=verified.scope,
            account_id=account_id,
            principal_display=verified.principal_name,
            token_type="Bearer",
            expires_in=86400,
        )
