"""DAPAgent — discovers services and registers."""

from __future__ import annotations

from typing import Any

import httpx

from .types import AgentCard, DAPError, RegisterResponse


class DAPAgent:
    """An agent that registers at DAP-compatible services."""

    def __init__(self, credential: str, card: AgentCard) -> None:
        self.credential = credential
        self.card = card

    async def register(self, service_url: str) -> RegisterResponse:
        """Discover the service and register with the credential."""
        async with httpx.AsyncClient() as client:
            # Step 1: Discovery
            discovery_resp = await client.get(f"{service_url}/.well-known/dap")
            discovery_resp.raise_for_status()
            discovery: dict[str, Any] = discovery_resp.json()

            if "jwt" not in discovery.get("supported_formats", []):
                raise DAPError("unsupported_format", "Service does not support JWT credentials")

            # Step 2: Register
            agent_card_dict: dict[str, Any] = {"name": self.card.name}
            if self.card.description is not None:
                agent_card_dict["description"] = self.card.description
            if self.card.version is not None:
                agent_card_dict["version"] = self.card.version
            if self.card.capabilities is not None:
                agent_card_dict["capabilities"] = self.card.capabilities

            body = {
                "credential": self.credential,
                "agent_card": agent_card_dict,
            }

            register_resp = await client.post(
                f"{discovery['dap_endpoint']}/register",
                json=body,
            )

            try:
                data = register_resp.json()
            except Exception:
                raise DAPError(
                    "registration_failed",
                    f"Service returned non-JSON response with status {register_resp.status_code}",
                )

            if not register_resp.is_success:
                raise DAPError(
                    data.get("error", "registration_failed"),
                    data.get("error_description", f"Registration failed with status {register_resp.status_code}"),
                )

            return RegisterResponse(
                status=data["status"],
                session_id=data["session_id"],
                access_token=data["access_token"],
                granted_scope=data["granted_scope"],
                account_id=data["account_id"],
                principal_display=data["principal_display"],
                token_type=data.get("token_type", "Bearer"),
                expires_in=data.get("expires_in", 86400),
            )
