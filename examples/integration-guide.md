# DAP Integration Guide for Services

How to accept AI agents on your platform using the Delegated Agent Protocol (v0.1).

This guide walks through what a service needs to implement. If you just want examples, see the `credentials/` directory next to this file.

---

## 1. Publish a Discovery Document

Your service needs to tell agents what it expects. Publish a JSON document at:

```
GET https://your-service.com/.well-known/dap
```

Minimal example:

```json
{
  "dap_version": "0.1",
  "dap_endpoint": "https://your-service.com/dap/v1",
  "supported_formats": ["jwt"],
  "supported_signature_algorithms": ["EdDSA"],
  "requirements": {
    "principal_types": ["organization"],
    "min_scope": ["register"],
    "requires_contact_email": true
  }
}
```

If you also accept individuals (delegated credentials from wallet providers), add the verification and issuer fields:

```json
{
  "requirements": {
    "principal_types": ["organization", "individual"],
    "min_verification_level": "oauth",
    "accepted_principal_schemes": ["did:web", "https", "mailto"],
    "trusted_issuers": [
      "https://dap-wallet.example"
    ]
  }
}
```

Key fields:

- `min_verification_level` -- the lowest verification level you'll accept. Levels from weakest to strongest: `self`, `email`, `phone`, `oauth`, `domain`, `document`, `organization`. Each level implies the ones below it.
- `accepted_principal_schemes` -- which URI schemes you allow for `principal_id`. Omit this to accept anything.
- `trusted_issuers` -- which delegated issuers you trust. If omitted, you accept any issuer whose signature is valid. If present, only listed issuers are accepted.

---

## 2. Implement the Register Endpoint

Handle `POST /dap/v1/register`. The request body looks like this:

```json
{
  "credential": "<signed JWT or W3C VC>",
  "agent_card": {
    "name": "Procurement Agent v2",
    "description": "Supplier matching for Acme Inc",
    "version": "2.1.0",
    "capabilities": ["search", "compare"],
    "callback_url": "https://acme-corp.example/agents/abc123/callback"
  }
}
```

### Verification pseudocode

```python
def register_agent(request):
    credential = parse_credential(request.credential)

    # 1. Verify the cryptographic signature first
    if credential.issuer_id:
        # Delegated credential -- signed by a third-party issuer
        signing_key = resolve_public_key(credential.issuer_id)
    else:
        # Self-issued credential -- signed by the principal
        signing_key = resolve_public_key(credential.principal_id)

    if not verify_signature(credential, signing_key):
        return error(401, "invalid_signature")

    # 2. Basic checks
    if credential.spec_version != "dap/0.1":
        return error(400, "unsupported_version")

    if credential.expires_at and credential.expires_at < now():
        return error(401, "credential_expired")

    # 3. Check issuer trust
    if credential.issuer_id:
        if config.trusted_issuers and credential.issuer_id not in config.trusted_issuers:
            return error(403, "untrusted_issuer")

    # 4. Check verification level
    cred_level = credential.verification.level if credential.verification else "self"
    if not meets_minimum_level(cred_level, config.min_verification_level):
        return error(403, "insufficient_verification")

    # 5. Check principal_id scheme
    scheme = get_uri_scheme(credential.principal_id)
    if config.accepted_principal_schemes and scheme not in config.accepted_principal_schemes:
        return error(400, "unsupported_principal_scheme")

    # 6. Check scope
    if not set(required_scope).issubset(set(credential.scope)):
        return error(403, "insufficient_scope")

    # 7. Check revocation (if endpoint provided)
    if credential.revocation_endpoint:
        if is_revoked(credential.revocation_endpoint, credential.agent_id):
            return error(401, "credential_revoked")

    # 8. Create account and issue token
    account = create_account(
        principal_id=credential.principal_id,
        principal_name=credential.principal_name,
        agent_id=credential.agent_id,
        granted_scope=credential.scope,
        issuer_id=credential.issuer_id,  # may be None for self-issued
    )
    token = issue_access_token(account, expires_in=86400)

    # 9. Audit log
    log_registration(
        agent_id=credential.agent_id,
        principal_id=credential.principal_id,
        principal_type=credential.principal_type,
        issuer_id=credential.issuer_id,
        verification_level=cred_level,
        granted_scope=credential.scope,
        timestamp=now(),
    )

    return {
        "status": "registered",
        "session_id": account.session_id,
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": 86400,
        "granted_scope": credential.scope,
        "account_id": account.id,
        "principal_display": credential.principal_name,
    }
```

### Resolving public keys

For `did:web:example.com`: fetch `https://example.com/.well-known/did.json` and extract the verification key.

For HTTPS issuer URIs (like `https://dap-wallet.example`): fetch `https://dap-wallet.example/.well-known/dap/jwks.json` and use the appropriate key.

---

## 3. Accepting Individual Credentials (Delegated Issuers)

When `issuer_id` is present, the credential was not signed by the principal themselves. Instead, a trusted issuer (like a DAP Wallet) verified the principal's identity and signed the credential on their behalf.

This is the typical flow for individuals:

1. A person authenticates with a wallet provider (e.g., via Google OAuth)
2. The wallet verifies their identity and issues a credential with `issuer_id` pointing to itself
3. The agent presents this credential to your service
4. Your service verifies the signature using the *issuer's* public key (not the principal's)

What to check:

- Is `issuer_id` in your `trusted_issuers` list? If you maintain one, reject unknown issuers.
- Does the `verification.level` meet your minimum? An `oauth`-level credential from a trusted issuer is reasonable for most consumer services.
- The `principal_id` for individuals is typically an HTTPS URI (OAuth provider account) or a `mailto:` address.

Key resolution differs from self-issued credentials:

- **Self-issued (organization):** resolve the public key from `principal_id` (e.g., `did:web:acme-corp.example` -> fetch `https://acme-corp.example/.well-known/did.json`)
- **Delegated (individual):** resolve the public key from `issuer_id` (e.g., `https://dap-wallet.example` -> fetch `https://dap-wallet.example/.well-known/dap/jwks.json`)

The `principal_id` in a delegated credential identifies who the agent acts for, but the cryptographic trust chain goes through the issuer. Your service trusts the issuer's assertion that the principal is who they claim to be.

If you only serve organizations and don't want to deal with delegated issuers, set `principal_types: ["organization"]` in your discovery document.

---

## 4. Signature Verification

The rule is simple:

- No `issuer_id` -> self-issued. Verify against the principal's public key.
- Has `issuer_id` -> delegated. Verify against the issuer's public key.

Supported algorithms: `EdDSA` (Ed25519) and `RS256`.

Both JWT and W3C VC credentials carry the same data. JWT is more common in practice; W3C VC is useful if you're already in the DID/VC ecosystem.

---

## 5. Audit Log

Every registration attempt (successful or not) should be logged with:

- `agent_id`
- `principal_id` and `principal_type`
- `issuer_id` (if present)
- `verification.level`
- Timestamp
- Result (registered, rejected, error code)
- `granted_scope` (on success)

When something goes wrong, this gives you exactly who is responsible and how to reach them.

---

## 6. Revocation

Two sides to this:

**Checking revocation at registration time:** If the credential includes a `revocation_endpoint`, query it. A `GET` to that endpoint with the `agent_id` should return the revocation status. If the credential is revoked, reject with `credential_revoked`.

**Revoking an agent registered on your service:** Implement `POST /dap/v1/revoke` so principals can deactivate their agents. The request includes `agent_id` and `reason`. Invalidate the agent's access token and session.

---

## 7. Checklist

Before going live:

- [ ] Discovery document at `/.well-known/dap` returns valid JSON
- [ ] `POST /dap/v1/register` accepts JWT credentials
- [ ] Signature verification works for self-issued credentials (`did:web`)
- [ ] Signature verification works for delegated credentials (`issuer_id` present)
- [ ] `issuer_id` is checked against `trusted_issuers` (if configured)
- [ ] `verification.level` is checked against `min_verification_level`
- [ ] `principal_id` scheme is checked against `accepted_principal_schemes` (if configured)
- [ ] Expired credentials are rejected
- [ ] Standard error codes are returned (see the Error Codes section in the spec)
- [ ] Audit log captures all registration attempts
- [ ] Rate limiting is enabled on `/dap/v1/register`
- [ ] All endpoints are HTTPS-only
- [ ] Access tokens have a bounded lifetime (24h recommended max)
- [ ] `POST /dap/v1/revoke` is implemented
