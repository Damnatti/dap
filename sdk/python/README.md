# dap-sdk (Python)

Python SDK for the **Delegated Agent Protocol (DAP) v0.1** — an open protocol for AI agent onboarding at external services.

- Spec: [github.com/dap-protocol/dap](https://github.com/dap-protocol/dap/blob/main/spec/v0.1.md)
- TypeScript SDK: [github.com/dap-protocol/dap/sdk/typescript](https://github.com/dap-protocol/dap/tree/main/sdk/typescript)

## Installation

```bash
pip install dap-sdk
```

Or from source:

```bash
pip install -e .
```

## Quick start

### Principal: generate keys and issue a credential

```python
from dap_sdk import DAPPrincipal, Verification

principal = DAPPrincipal.generate(
    principal_id="did:web:romashka.example",
    name="OOO Romashka",
)

credential = principal.issue_credential(
    agent_id="urn:dap:agent:procurement-bot-v1",
    scope=["register", "read_data"],
    principal_type="organization",
    expires_in="24h",
    verification=Verification(level="domain", method="did:web"),
)
```

### Service: verify a credential

```python
import asyncio
from dap_sdk import DAPService, RegisterRequest, AgentCard

# In production, implement a real key resolver that fetches public keys
# from a registry, DID document, or other trusted source.
def resolve_public_key(principal_id: str):
    # Placeholder: replace with actual key lookup logic, e.g.:
    #   - fetch DID document for did:web identifiers
    #   - query a key registry database
    #   - retrieve from a JWKS endpoint
    raise NotImplementedError(f"Key resolution not configured for {principal_id}")

service = DAPService(
    name="Supplier Portal",
    base_url="https://supplier-portal.example",
    resolve_public_key=resolve_public_key,
)

# Serve at GET /.well-known/dap
discovery = service.discovery_document()

async def main():
    # Handle POST /dap/v1/register
    result = await service.handle_register(
        RegisterRequest(
            credential=jwt_string,
            agent_card=AgentCard(name="My Agent"),
        )
    )
    print(result.access_token)

asyncio.run(main())
```

### Agent: discover and register

```python
import asyncio
from dap_sdk import DAPAgent, AgentCard

agent = DAPAgent(
    credential=jwt_string,
    card=AgentCard(
        name="Procurement Bot",
        version="1.0.0",
        capabilities=["search", "compare"],
    ),
)

async def main():
    result = await agent.register("https://supplier-portal.example")
    print(result.access_token)

asyncio.run(main())
```

## Key concepts

| Class | Role |
|-------|------|
| `DAPPrincipal` | Generates Ed25519 keys, issues signed JWT credentials |
| `DAPAgent` | Discovers services via `/.well-known/dap`, registers with a credential |
| `DAPService` | Publishes discovery document, verifies credentials on registration |

## Verification flow

`DAPService.handle_register` performs the following checks:

1. **Format** — JWT `typ` header is `dap-agent-credential+jwt`
2. **Spec version** — `spec_version` is `dap/0.1`
3. **Signature** — verified using issuer key (if `issuer_id` present) or principal key
4. **Trusted issuer** — if `trusted_issuers` is configured, issuer must be in the list
5. **Principal scheme** — if `accepted_principal_schemes` is configured, principal ID scheme must match
6. **Verification level** — meets the service's `min_verification_level`
7. **Scope** — credential includes `register`
8. **Custom validation** — optional callback

## New in spec v0.1

- `issuer_id` field for delegated credentials (third-party issuers)
- `verification` object: `level`, `method`, `verified_at`, `verified_by`
- Verification levels: `self`, `email`, `phone`, `oauth`, `domain`, `document`, `organization`

## Running the example

```bash
cd dap/sdk/python
pip install -e .
python examples/end_to_end.py
```

## License

Apache 2.0
