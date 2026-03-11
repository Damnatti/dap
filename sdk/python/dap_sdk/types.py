"""DAP SDK type definitions."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Verification:
    """Principal verification information."""
    level: str  # self, email, phone, oauth, domain, document, organization
    method: str  # e.g. "did:web", "google_oauth2", "sumsub_kyc"
    verified_at: int | None = None
    verified_by: str | None = None


@dataclass
class AgentCredentialPayload:
    """Payload of a DAP agent credential JWT."""
    spec_version: str  # "dap/0.1"
    agent_id: str
    principal_id: str
    principal_name: str
    principal_type: str  # "individual" | "organization"
    scope: list[str]
    purpose: str | None = None
    contact_email: str | None = None
    issuer_id: str | None = None
    verification: Verification | None = None
    constraints: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "spec_version": self.spec_version,
            "agent_id": self.agent_id,
            "principal_id": self.principal_id,
            "principal_name": self.principal_name,
            "principal_type": self.principal_type,
            "scope": self.scope,
        }
        if self.purpose is not None:
            d["purpose"] = self.purpose
        if self.contact_email is not None:
            d["contact_email"] = self.contact_email
        if self.issuer_id is not None:
            d["issuer_id"] = self.issuer_id
        if self.verification is not None:
            v: dict[str, Any] = {"level": self.verification.level, "method": self.verification.method}
            if self.verification.verified_at is not None:
                v["verified_at"] = self.verification.verified_at
            if self.verification.verified_by is not None:
                v["verified_by"] = self.verification.verified_by
            d["verification"] = v
        if self.constraints is not None:
            d["constraints"] = self.constraints
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> AgentCredentialPayload:
        verification = None
        if "verification" in d:
            v = d["verification"]
            verification = Verification(
                level=v["level"],
                method=v["method"],
                verified_at=v.get("verified_at"),
                verified_by=v.get("verified_by"),
            )
        return cls(
            spec_version=d["spec_version"],
            agent_id=d["agent_id"],
            principal_id=d["principal_id"],
            principal_name=d["principal_name"],
            principal_type=d["principal_type"],
            scope=d["scope"],
            purpose=d.get("purpose"),
            contact_email=d.get("contact_email"),
            issuer_id=d.get("issuer_id"),
            verification=verification,
            constraints=d.get("constraints"),
        )


@dataclass
class AgentCard:
    """Agent card presented during registration."""
    name: str
    description: str | None = None
    version: str | None = None
    capabilities: list[str] | None = None


@dataclass
class RegisterRequest:
    """Registration request sent by an agent."""
    credential: str  # signed JWT
    agent_card: AgentCard


@dataclass
class RegisterResponse:
    """Successful registration response."""
    status: str  # "registered"
    session_id: str
    access_token: str
    granted_scope: list[str]
    account_id: str
    principal_display: str
    token_type: str = "Bearer"
    expires_in: int = 86400


@dataclass
class DAPError(Exception):
    """DAP protocol error."""
    error: str
    error_description: str

    def __post_init__(self) -> None:
        super().__init__(self.error, self.error_description)

    def __str__(self) -> str:
        return f"{self.error}: {self.error_description}"
