# dap-sdk

Minimal TypeScript SDK for the [Delegated Agent Protocol (DAP)](https://github.com/dap-protocol/dap) v0.1.

## Installation

```bash
npm install dap-sdk
```

## Quick start

```typescript
import { DAPPrincipal, DAPService } from "dap-sdk";
import { importJWK } from "jose";

async function main() {
  // 1. Principal generates keys and issues a credential
  const principal = await DAPPrincipal.generate({
    id: "did:web:example.com",
    name: "Example Corp",
  });

  const credential = await principal.issueCredential({
    agentId: "urn:dap:agent:my-bot",
    scope: ["register", "read_data"],
    verification: { level: "domain", method: "did:web" },
  });

  // 2. Service verifies the credential
  const publicKeyJWK = await principal.exportPublicKeyJWK();

  const service = new DAPService({
    name: "My Service",
    baseUrl: "https://my-service.example",
    resolvePublicKey: async (id) => importJWK(publicKeyJWK, "EdDSA"),
  });

  const result = await service.handleRegister({
    credential,
    agent_card: { name: "My Bot", version: "1.0.0" },
  });

  console.log(result.status); // "registered"
}

main().catch(console.error);
```

## API overview

### `DAPPrincipal`

Represents a principal (person or organization) that issues credentials to agents.

- `DAPPrincipal.generate({ id, name })` -- create a new principal with an Ed25519 keypair
- `principal.issueCredential({ agentId, scope, ... })` -- sign and return a JWT credential
  - Optional: `issuerId` (for delegated issuance), `verification` (level, method, verified_at, verified_by)
- `principal.exportPublicKeyJWK()` -- export the public key in JWK format

### `DAPAgent`

Client that performs discovery and registration against a remote service.

- `new DAPAgent(credential, agentCard)`
- `agent.register(serviceUrl)` -- discover and register at a DAP-enabled service

### `DAPService`

Server-side handler that verifies credentials and issues access tokens.

- `new DAPService(config)` -- configure the service
  - `config.resolvePublicKey(id)` -- resolve a public key by principal_id or issuer_id
  - `config.minVerificationLevel` -- minimum verification level (default: `"self"`)
  - `config.trustedIssuers` -- list of accepted delegated issuer IDs
  - `config.acceptedPrincipalSchemes` -- list of accepted URI schemes for principal_id
  - `config.validateCredential` -- optional custom validation function
- `service.discoveryDocument()` -- returns the `/.well-known/dap` JSON
- `service.handleRegister(request)` -- verify credential and return a `RegisterResponse`

### Error codes

| Code | Description |
|------|-------------|
| `invalid_credential_format` | JWT `typ` header is wrong |
| `unsupported_version` | Unknown `spec_version` |
| `unsupported_principal_scheme` | `principal_id` scheme not in `acceptedPrincipalSchemes` |
| `untrusted_issuer` | `issuer_id` not in `trustedIssuers` |
| `insufficient_verification` | Verification level below `minVerificationLevel` |
| `invalid_signature` | Signature verification or key resolution failed |
| `credential_expired` | JWT has expired |
| `principal_blocked` | Custom `validateCredential` returned false |

### Verification levels (ordered)

`self` < `email` < `phone` < `oauth` < `domain` < `document` < `organization`

## Demo

Run the interactive demo with 4 real-world scenarios:

```bash
npm run demo
```

Or run the basic end-to-end example:

```bash
npm run example
```

## Spec

Full protocol specification: [DAP v0.1](https://github.com/dap-protocol/dap/blob/main/spec/v0.1.md)

## License

Apache-2.0
