/**
 * dap-sdk — minimal TypeScript implementation of Delegated Agent Protocol v0.1
 * https://github.com/dap-protocol/dap
 */

import { SignJWT, jwtVerify, exportJWK, generateKeyPair, importJWK } from "jose";
import type { KeyObject } from "node:crypto";

type KeyLike = CryptoKey | KeyObject;

// ─── Verification levels (ordered lowest → highest) ──────────────────────────

const VERIFICATION_LEVELS = ["self", "email", "phone", "oauth", "domain", "document", "organization"] as const;
export type VerificationLevel = (typeof VERIFICATION_LEVELS)[number];

function verificationLevelIndex(level: string): number {
  const idx = VERIFICATION_LEVELS.indexOf(level as VerificationLevel);
  return idx === -1 ? -1 : idx;
}

// ─── Types ────────────────────────────────────────────────────────────────────

export interface Verification {
  level: VerificationLevel;
  method: string;
  verified_at?: number;
  verified_by?: string;
}

export interface AgentCredentialPayload {
  spec_version: "dap/0.1";
  agent_id: string;
  principal_id: string;
  principal_name: string;
  principal_type: "individual" | "organization";
  scope: string[];
  issuer_id?: string;
  verification?: Verification;
  purpose?: string;
  contact_email?: string;
  constraints?: Record<string, unknown>;
}

export interface AgentCard {
  name: string;
  description?: string;
  version?: string;
  capabilities?: string[];
}

export interface RegisterRequest {
  credential: string; // signed JWT
  agent_card: AgentCard;
}

export interface RegisterResponse {
  status: "registered";
  session_id: string;
  access_token: string;
  token_type: "Bearer";
  expires_in: number;
  granted_scope: string[];
  account_id: string;
  principal_display: string;
}

export interface DAPError {
  error: string;
  error_description: string;
}

// ─── Principal — creates and signs credentials ────────────────────────────────

export class DAPPrincipal {
  private privateKey: KeyLike;
  public publicKey: KeyLike;
  public readonly id: string;
  public readonly name: string;

  constructor(opts: { id: string; name: string; privateKey: KeyLike; publicKey: KeyLike }) {
    this.id = opts.id;
    this.name = opts.name;
    this.privateKey = opts.privateKey;
    this.publicKey = opts.publicKey;
  }

  static async generate(opts: { id: string; name: string }): Promise<DAPPrincipal> {
    const { privateKey, publicKey } = await generateKeyPair("EdDSA", { crv: "Ed25519" });
    return new DAPPrincipal({ ...opts, privateKey, publicKey });
  }

  async issueCredential(opts: {
    agentId: string;
    scope: string[];
    principalType?: "individual" | "organization";
    purpose?: string;
    contactEmail?: string;
    expiresIn?: string; // e.g. "24h", "7d"
    constraints?: Record<string, unknown>;
    /** Set when acting as a delegated issuer (issuer signs on behalf of another principal) */
    issuerId?: string;
    /** Override principal_id (useful when issuing as a delegated issuer) */
    principalId?: string;
    /** Override principal_name (useful when issuing as a delegated issuer) */
    principalName?: string;
    verification?: Verification;
  }): Promise<string> {
    const payload: AgentCredentialPayload = {
      spec_version: "dap/0.1",
      agent_id: opts.agentId,
      principal_id: opts.principalId ?? this.id,
      principal_name: opts.principalName ?? this.name,
      principal_type: opts.principalType ?? "organization",
      scope: opts.scope,
      purpose: opts.purpose,
      contact_email: opts.contactEmail,
      constraints: opts.constraints,
      issuer_id: opts.issuerId,
      verification: opts.verification,
    };

    return new SignJWT(payload as unknown as Record<string, unknown>)
      .setProtectedHeader({ alg: "EdDSA", typ: "dap-agent-credential+jwt" })
      .setIssuedAt()
      .setExpirationTime(opts.expiresIn ?? "24h")
      .sign(this.privateKey);
  }

  async exportPublicKeyJWK(): Promise<Record<string, unknown>> {
    return exportJWK(this.publicKey) as Promise<Record<string, unknown>>;
  }
}

// ─── DAPAgent — registers at services ─────────────────────────────────────────

export class DAPAgent {
  constructor(
    private readonly credential: string,
    private readonly card: AgentCard
  ) {}

  async register(serviceUrl: string): Promise<RegisterResponse> {
    // Step 1: discovery
    const discovery = await fetch(`${serviceUrl}/.well-known/dap`).then((r) => r.json());

    if (!discovery.supported_formats?.includes("jwt")) {
      throw new Error("Service does not support JWT credentials");
    }

    // Step 2: register
    const body: RegisterRequest = {
      credential: this.credential,
      agent_card: this.card,
    };

    const res = await fetch(`${discovery.dap_endpoint}/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });

    const data = await res.json();

    if (!res.ok) {
      const err = data as DAPError;
      throw new Error(`DAP registration failed: ${err.error} — ${err.error_description}`);
    }

    return data as RegisterResponse;
  }
}

// ─── DAPService — accepts agents ──────────────────────────────────────────────

export interface ServiceConfig {
  name: string;
  baseUrl: string;
  /** Resolve a public key for a given principal_id or issuer_id */
  resolvePublicKey: (id: string) => Promise<KeyLike>;
  /** Optional: extra business validation */
  validateCredential?: (payload: AgentCredentialPayload) => Promise<boolean>;
  /** Minimum verification level required (default: "self") */
  minVerificationLevel?: VerificationLevel;
  /** List of trusted issuer IDs for delegated credentials. If set, only these issuers are accepted. */
  trustedIssuers?: string[];
  /** Accepted principal_id URI schemes. If set, only these schemes are allowed. */
  acceptedPrincipalSchemes?: string[];
}

export class DAPService {
  constructor(private config: ServiceConfig) {}

  /** Returns the discovery document (serve at /.well-known/dap) */
  discoveryDocument() {
    return {
      dap_version: "0.1",
      dap_endpoint: `${this.config.baseUrl}/dap/v1`,
      supported_formats: ["jwt"],
      supported_signature_algorithms: ["EdDSA"],
      requirements: {
        principal_types: ["organization", "individual"],
        min_scope: ["register"],
        requires_contact_email: false,
        ...(this.config.minVerificationLevel && {
          min_verification_level: this.config.minVerificationLevel,
        }),
        ...(this.config.acceptedPrincipalSchemes && {
          accepted_principal_schemes: this.config.acceptedPrincipalSchemes,
        }),
        ...(this.config.trustedIssuers && {
          trusted_issuers: this.config.trustedIssuers,
        }),
      },
      service_info: { name: this.config.name },
    };
  }

  /** Verifies a registration request and returns a response */
  async handleRegister(req: RegisterRequest): Promise<RegisterResponse> {
    // 1. Parse header (typ check)
    const [headerB64] = req.credential.split(".");
    const header = JSON.parse(Buffer.from(headerB64, "base64url").toString());

    if (header.typ !== "dap-agent-credential+jwt") {
      throw this.error("invalid_credential_format", "Expected typ: dap-agent-credential+jwt");
    }

    // 2. Decode payload (before sig verification) to get principal_id / issuer_id and check spec_version
    const [, payloadB64] = req.credential.split(".");
    const rawPayload = JSON.parse(Buffer.from(payloadB64, "base64url").toString()) as AgentCredentialPayload;

    if (rawPayload.spec_version !== "dap/0.1") {
      throw this.error("unsupported_version", `Unknown spec version: ${rawPayload.spec_version}`);
    }

    // 3. Determine which key to use: issuer_id (delegated) or principal_id (self-issued)
    const keyId = rawPayload.issuer_id ?? rawPayload.principal_id;

    // 4. Resolve public key and verify signature + expiry FIRST (before any trust decisions)
    let publicKey: KeyLike;
    try {
      publicKey = await this.config.resolvePublicKey(keyId);
    } catch {
      throw this.error("invalid_signature", `Cannot resolve public key for ${keyId}`);
    }

    let verified: AgentCredentialPayload;
    try {
      const { payload } = await jwtVerify(req.credential, publicKey, { algorithms: ["EdDSA"] });
      verified = payload as unknown as AgentCredentialPayload;
    } catch (e: unknown) {
      if ((e as any)?.code === "ERR_JWT_EXPIRED") {
        throw this.error("credential_expired", "Credential has expired");
      }
      throw this.error("invalid_signature", "Signature verification failed");
    }

    // 5. Check accepted principal schemes (on verified payload)
    if (this.config.acceptedPrincipalSchemes?.length) {
      const scheme = this.extractScheme(verified.principal_id);
      if (!this.config.acceptedPrincipalSchemes.includes(scheme)) {
        throw this.error(
          "unsupported_principal_scheme",
          `Principal scheme "${scheme}" is not accepted. Accepted: ${this.config.acceptedPrincipalSchemes.join(", ")}`
        );
      }
    }

    // 6. If issuer_id present, check trusted_issuers (on verified payload)
    if (verified.issuer_id && this.config.trustedIssuers?.length) {
      if (!this.config.trustedIssuers.includes(verified.issuer_id)) {
        throw this.error(
          "untrusted_issuer",
          `Issuer "${verified.issuer_id}" is not in the trusted issuers list`
        );
      }
    }

    // 7. Check verification level (on verified payload)
    const minLevel = this.config.minVerificationLevel ?? "self";
    const credLevel = verified.verification?.level ?? "self";
    const minIdx = verificationLevelIndex(minLevel);
    const credIdx = verificationLevelIndex(credLevel);

    if (credIdx < minIdx) {
      throw this.error(
        "insufficient_verification",
        `Verification level "${credLevel}" is below the required minimum "${minLevel}"`
      );
    }

    // 8. Business validation (optional)
    if (this.config.validateCredential) {
      const ok = await this.config.validateCredential(verified);
      if (!ok) throw this.error("principal_blocked", "Custom validation rejected this credential");
    }

    // 9. Issue access token
    const accountId = `acc_${verified.principal_id.replace(/[^a-z0-9]/gi, "_")}_${verified.agent_id.slice(-8)}`;
    // ⚠️ Demo only: this token is not signed. Production implementations MUST use signed JWTs or opaque tokens.
    const accessToken = Buffer.from(
      JSON.stringify({ account_id: accountId, scope: verified.scope, exp: Date.now() + 86400_000 })
    ).toString("base64url");

    return {
      status: "registered",
      session_id: `ses_${crypto.randomUUID().slice(0, 12)}`,
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 86400,
      granted_scope: verified.scope,
      account_id: accountId,
      principal_display: verified.principal_name,
    };
  }

  private extractScheme(uri: string): string {
    // did:web:... → "did:web", https://... → "https", mailto:... → "mailto"
    if (uri.startsWith("did:")) {
      const parts = uri.split(":");
      return `${parts[0]}:${parts[1]}`;
    }
    const colonIdx = uri.indexOf(":");
    if (colonIdx === -1) return uri;
    return uri.slice(0, colonIdx);
  }

  private error(code: string, description: string): Error & { dapError: DAPError } {
    const err = new Error(description) as Error & { dapError: DAPError };
    err.dapError = { error: code, error_description: description };
    return err;
  }
}
