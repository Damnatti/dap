# DAP — Delegated Agent Protocol

An open protocol for verifiable agent identity.

When an AI agent shows up at a service, the service needs to answer one question: **who is responsible for this thing?** Not "what can it do" — that comes later. First: who's behind it, how do I verify that, and who do I contact when something goes wrong.

That's what DAP does. The agent carries a signed credential that links it to a real person or organization — the **principal**. The service verifies the credential and knows exactly who it's dealing with.

```
Principal (person or company)
  │
  └─ signs an Agent Credential
       │  - who the principal is
       │  - how they were verified
       │  - what the agent is allowed to do
       │
       └─► Agent presents credential to the service
                │
                └─► Service verifies identity and grants access
```

## What DAP is

**An identity layer for agents.** It answers "who are you and who's responsible for you" — the question that every service needs answered before giving an agent access to anything.

- A company's agent carries a credential signed by that company
- A person's agent carries a credential issued by a trusted provider (like a DAP Wallet) that verified their identity through Google, a phone number, or a government ID
- The service checks the credential, sees who the principal is, sees how they were verified, and decides whether that's good enough

## What DAP is not

**DAP is not an authorization framework.** It doesn't manage OAuth tokens, consent flows, or fine-grained permissions. If you need "user X granted agent Y permission to read their calendar" — that's OAuth. DAP handles the step before that: establishing who the agent is and who stands behind it.

**DAP is not a runtime protocol.** It handles onboarding — the moment an agent first shows up at a service. What happens after (API calls, sessions, token refresh) is up to the service.

## Who it's for

**Service operators** who want to accept AI agents without guessing who's behind them. Add two endpoints (discovery + register), verify credentials, know who to call if things break.

**Agent developers** who need their agents to register on external services programmatically — no form-filling, no CAPTCHAs, no screen-scraping.

**Individuals** who want their personal agents to act on their behalf with a verifiable identity, without needing a company or a domain.

## Verification levels

Services set their own bar. A pizza delivery app needs less assurance than a bank.

| Level | What's verified | Typical use |
|-------|----------------|-------------|
| `self` | Nothing — self-signed | Dev, testing |
| `email` | Email address | Low-risk services |
| `phone` | Phone number | Delivery, messaging |
| `oauth` | Account at identity provider | Most consumer services |
| `domain` | Domain ownership | B2B |
| `document` | Government ID | Finance, regulated industries |
| `organization` | Legal entity verified | B2B, fintech, government |

The service declares what it requires. The agent either meets the bar or doesn't get in.

## The protocol

Four steps, all programmatic:

**1. Discovery** — Service publishes what it accepts at `/.well-known/dap`

**2. Register** — Agent sends its signed credential to `/dap/v1/register`

**3. Work** — Agent uses the service with the issued access token

**4. Revoke** — Principal revokes the agent's credential when needed

## Quick example (TypeScript)

```ts
import { DAPPrincipal, DAPService } from "dap-sdk";
import { importJWK } from "jose";

// 1. Principal issues a credential to the agent
const principal = await DAPPrincipal.generate({
  id: "did:web:romashka.example",
  name: "Romashka LLC",
});

const credential = await principal.issueCredential({
  agentId: "urn:dap:agent:my-bot",
  scope: ["register", "read_data"],
  purpose: "Procurement automation",
  expiresIn: "24h",
});

// 2. Service verifies the credential
const service = new DAPService({
  name: "Supplier Portal",
  baseUrl: "https://supplier-portal.com",
  resolvePublicKey: async (id) => importJWK(await getKey(id), "EdDSA"),
});

const result = await service.handleRegister({
  credential,
  agent_card: { name: "Procurement Bot", version: "1.0.0" },
});
// → { status: 'registered', access_token: '...', session_id: '...', account_id: '...', principal_display: 'Romashka LLC' }
```

## Quick example (Python)

```python
from dap_sdk import DAPPrincipal, DAPService, RegisterRequest, AgentCard

# 1. Principal issues a credential
principal = DAPPrincipal.generate(principal_id="did:web:romashka.example", name="Romashka LLC")
credential = principal.issue_credential(
    agent_id="urn:dap:agent:my-bot",
    scope=["register", "read_data"],
    purpose="Procurement automation",
)

# 2. Service verifies
service = DAPService(
    name="Supplier Portal",
    base_url="https://supplier-portal.com",
    resolve_public_key=get_principal_key,
)
result = service.handle_register(RegisterRequest(
    credential=credential,
    agent_card=AgentCard(name="Procurement Bot"),
))
# → {"status": "registered", "access_token": "...", "account_id": "...", "principal_display": "Romashka LLC"}
```

## What's in this repo

```
spec/           Specification v0.1
sdk/
  typescript/   TypeScript/Node.js SDK
  python/       Python SDK
examples/
  credentials/  Sample credentials (JWT, W3C VC, discovery doc)
  integration-guide.md
CONTRIBUTING.md
```

## Status

**v0.1 — draft, open for feedback.**

The protocol covers identity and onboarding. Payments, document signing, agent-to-agent communication, and a centralized registry are planned for future versions.

If you're building agents or running services that agents interact with — [open an issue](https://github.com/dap-protocol/dap/issues). We want to know what doesn't work for your use case.

## Where DAP fits

DAP handles **identity** — the layer below authorization and tooling:

- **MCP** defines how agents use tools. DAP defines how agents prove who they are before getting access to those tools.
- **OAuth 2.1** handles authorization ("user X permits action Y"). DAP handles the prerequisite: establishing verifiable identity for the agent and its principal.
- **W3C Verifiable Credentials** and **DID** are the building blocks DAP uses for credential format and principal identification.

An agent might use DAP to onboard, then OAuth for authorization, then MCP for tool access. Each layer does one thing.

## License

Apache 2.0 — see [LICENSE](LICENSE).
