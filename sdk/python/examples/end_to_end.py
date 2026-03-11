"""
DAP end-to-end example

Shows a complete flow:
  1. Principal generates keys and issues a credential to an agent
  2. A mock service verifies the credential
  3. Agent "registers" and gets an access token
  4. Tampered credential is rejected
  5. Unknown principal is rejected

Run: python examples/end_to_end.py
"""

import asyncio

from dap_sdk import (
    AgentCard,
    DAPError,
    DAPPrincipal,
    DAPService,
    RegisterRequest,
    Verification,
)


async def main() -> None:
    print("-- DAP end-to-end example --\n")

    # -- Step 1: Principal generates keys --
    print("1. Generating principal keypair...")
    principal = DAPPrincipal.generate(
        principal_id="did:web:romashka.example",
        name="OOO Romashka",
    )
    print(f"   Principal: {principal.name} ({principal.principal_id})\n")

    # -- Step 2: Principal issues a credential to the agent --
    print("2. Issuing agent credential...")
    credential = principal.issue_credential(
        agent_id="urn:dap:agent:procurement-bot-v1",
        scope=["register", "read_data", "submit_forms"],
        principal_type="organization",
        purpose="Supplier procurement automation",
        contact_email="tech@romashka.example",
        expires_in="24h",
        verification=Verification(level="domain", method="did:web"),
    )
    print(f"   Credential (JWT): {credential[:60]}...\n")

    # -- Step 3: Set up a service that accepts DAP agents --
    print("3. Setting up service...")
    # Store known principal public keys
    known_keys = {principal.principal_id: principal.export_public_key()}

    service = DAPService(
        name="Supplier Portal",
        base_url="https://supplier-portal.example",
        resolve_public_key=lambda pid: _resolve(known_keys, pid),
        min_verification_level="self",
    )
    print(f"   Service ready: {service.discovery_document()['service_info']['name']}\n")

    # -- Step 4: Agent registers at the service --
    print("4. Agent registers at service...")
    result = await service.handle_register(
        RegisterRequest(
            credential=credential,
            agent_card=AgentCard(
                name="Procurement Bot v1",
                description="Supplier procurement agent for OOO Romashka",
                version="1.0.0",
                capabilities=["search", "compare", "request_quote"],
            ),
        )
    )

    print("   Registered!")
    print(f"   Status:          {result.status}")
    print(f"   Account ID:      {result.account_id}")
    print(f"   Principal:       {result.principal_display}")
    print(f"   Granted scope:   {', '.join(result.granted_scope)}")
    print(f"   Access token:    {result.access_token[:40]}...\n")

    # -- Step 5: Tampered credential should be rejected --
    print("5. Tampered credential (should fail)...")
    tampered = credential[:-10] + "TAMPERED00"
    try:
        await service.handle_register(
            RegisterRequest(
                credential=tampered,
                agent_card=AgentCard(name="Evil Bot"),
            )
        )
        print("   FAIL: Should have been rejected!")
    except DAPError as e:
        print(f"   Correctly rejected: {e.error}")

    # -- Step 6: Unknown principal should be rejected --
    print("\n6. Unknown principal (should fail)...")
    stranger = DAPPrincipal.generate(principal_id="did:web:evil.example", name="Evil Corp")
    stranger_credential = stranger.issue_credential(
        agent_id="urn:dap:agent:spy",
        scope=["register"],
    )
    try:
        await service.handle_register(
            RegisterRequest(
                credential=stranger_credential,
                agent_card=AgentCard(name="Spy Bot"),
            )
        )
        print("   FAIL: Should have been rejected!")
    except DAPError as e:
        print(f"   Correctly rejected: {e.error}")

    print("\n-- Done --")


def _resolve(known_keys: dict, principal_id: str):
    """Simple key resolver for the example."""
    if principal_id not in known_keys:
        raise KeyError(f"Unknown principal: {principal_id}")
    return known_keys[principal_id]


if __name__ == "__main__":
    asyncio.run(main())
