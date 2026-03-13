/**
 * DAP end-to-end example
 *
 * Shows two flows:
 *   A. Self-issued: principal signs its own credential
 *   B. Delegated issuer: a trusted third party signs the credential on behalf of a principal
 *
 * Run: npx tsx examples/end-to-end.ts
 */

import { DAPPrincipal, DAPService } from "../src/index.js";
import { importJWK } from "jose";

async function main() {
  console.log("== DAP end-to-end example ==\n");

  // ═══════════════════════════════════════════════════════════════════════════
  // Flow A: Self-issued credential (organization)
  // ═══════════════════════════════════════════════════════════════════════════

  console.log("--- Flow A: Self-issued credential ---\n");

  // Step 1: Principal generates keys
  console.log("1. Generating principal keypair...");
  const principal = await DAPPrincipal.generate({
    id: "did:web:acme-corp.example",
    name: "Acme Inc",
  });
  console.log(`   Principal: ${principal.name} (${principal.id})\n`);

  // Step 2: Issue credential (self-issued, no issuer_id)
  console.log("2. Issuing agent credential (self-issued)...");
  const credential = await principal.issueCredential({
    agentId: "urn:dap:agent:procurement-bot-v1",
    scope: ["register", "read_data", "submit_forms"],
    principalType: "organization",
    purpose: "Supplier procurement automation",
    contactEmail: "tech@acme-corp.example",
    expiresIn: "24h",
    verification: { level: "domain", method: "did:web" },
  });
  console.log("   Credential (JWT):", credential.slice(0, 60) + "...\n");

  // Step 3: Set up a service
  console.log("3. Setting up service...");
  const principalPublicJWK = await principal.exportPublicKeyJWK();

  const service = new DAPService({
    name: "Supplier Portal",
    baseUrl: "https://supplier-portal.example",
    minVerificationLevel: "self",
    acceptedPrincipalSchemes: ["did:web", "https", "mailto"],
    resolvePublicKey: async (id) => {
      if (id === principal.id) return importJWK(principalPublicJWK, "EdDSA");
      throw new Error(`Unknown id: ${id}`);
    },
  });
  console.log("   Service ready:", service.discoveryDocument().service_info.name, "\n");

  // Step 4: Register
  console.log("4. Agent registers at service...");
  const result = await service.handleRegister({
    credential,
    agent_card: {
      name: "Procurement Bot v1",
      description: "Supplier procurement agent for Acme Inc",
      version: "1.0.0",
      capabilities: ["search", "compare", "request_quote"],
    },
  });

  console.log("   Registered!");
  console.log("   Status:         ", result.status);
  console.log("   Account ID:     ", result.account_id);
  console.log("   Principal:      ", result.principal_display);
  console.log("   Granted scope:  ", result.granted_scope.join(", "));
  console.log("   Access token:   ", result.access_token.slice(0, 40) + "...\n");

  // Step 5: Tampered credential should be rejected
  console.log("5. Tampered credential (should fail)...");
  const tampered = credential.slice(0, -10) + "TAMPERED00";
  try {
    await service.handleRegister({ credential: tampered, agent_card: { name: "Evil Bot" } });
    console.log("   FAIL: Should have been rejected!");
  } catch (e: unknown) {
    const err = e as Error & { dapError?: { error: string } };
    console.log(`   Correctly rejected: ${err.dapError?.error ?? err.message}`);
  }

  // Step 6: Unknown principal should be rejected
  console.log("\n6. Unknown principal (should fail)...");
  const stranger = await DAPPrincipal.generate({ id: "did:web:evil.example", name: "Evil Corp" });
  const strangerCredential = await stranger.issueCredential({
    agentId: "urn:dap:agent:spy",
    scope: ["register"],
  });
  try {
    await service.handleRegister({ credential: strangerCredential, agent_card: { name: "Spy Bot" } });
    console.log("   FAIL: Should have been rejected!");
  } catch (e: unknown) {
    const err = e as Error & { dapError?: { error: string } };
    console.log(`   Correctly rejected: ${err.dapError?.error ?? err.message}`);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Flow B: Delegated issuer (individual via third-party issuer)
  // ═══════════════════════════════════════════════════════════════════════════

  console.log("\n\n--- Flow B: Delegated issuer credential ---\n");

  // Step 7: Issuer generates keys (e.g. a DAP Wallet provider)
  console.log("7. Generating issuer keypair (DAP Wallet)...");
  const issuer = await DAPPrincipal.generate({
    id: "https://dap-wallet.example",
    name: "DAP Wallet",
  });
  const issuerPublicJWK = await issuer.exportPublicKeyJWK();
  console.log(`   Issuer: ${issuer.name} (${issuer.id})\n`);

  // Step 8: Issuer issues a credential on behalf of a human principal.
  // The issuer signs with its own key, sets issuer_id to itself,
  // and sets principal_id/principal_name to the actual user.
  console.log("8. Issuer issues credential for individual principal...");
  const delegatedCredential = await issuer.issueCredential({
    agentId: "urn:dap:agent:booking-bot-v1",
    scope: ["register", "search", "book"],
    principalType: "individual",
    // Override principal identity to the actual user (not the issuer)
    principalId: "https://accounts.google.com/user/12345",
    principalName: "James Wilson",
    issuerId: "https://dap-wallet.example",
    purpose: "Restaurant search and booking",
    contactEmail: "james.w@example.com",
    expiresIn: "12h",
    verification: {
      level: "oauth",
      method: "google_oauth2",
      verified_at: Math.floor(Date.now() / 1000),
      verified_by: "https://dap-wallet.example",
    },
  });
  console.log("   Credential (JWT):", delegatedCredential.slice(0, 60) + "...\n");

  // Step 9: Set up a service that requires oauth-level verification and trusts the issuer
  console.log("9. Setting up booking service (requires oauth, trusts dap-wallet.example)...");
  const bookingService = new DAPService({
    name: "Restaurant Booking",
    baseUrl: "https://restaurant-booking.example",
    minVerificationLevel: "oauth",
    trustedIssuers: ["https://dap-wallet.example"],
    acceptedPrincipalSchemes: ["did:web", "https", "mailto"],
    resolvePublicKey: async (id) => {
      if (id === principal.id) return importJWK(principalPublicJWK, "EdDSA");
      if (id === "https://dap-wallet.example") return importJWK(issuerPublicJWK, "EdDSA");
      throw new Error(`Unknown id: ${id}`);
    },
  });
  const disc = bookingService.discoveryDocument();
  console.log("   Service:", disc.service_info.name);
  console.log("   min_verification_level:", disc.requirements.min_verification_level);
  console.log("   trusted_issuers:", disc.requirements.trusted_issuers, "\n");

  // Step 10: Register with delegated credential -- should succeed
  console.log("10. Agent registers with delegated credential...");
  const delegatedResult = await bookingService.handleRegister({
    credential: delegatedCredential,
    agent_card: {
      name: "Booking Bot v1",
      description: "Restaurant booking agent for James Wilson",
      version: "1.0.0",
      capabilities: ["search", "book"],
    },
  });

  console.log("   Registered!");
  console.log("   Status:         ", delegatedResult.status);
  console.log("   Account ID:     ", delegatedResult.account_id);
  console.log("   Principal:      ", delegatedResult.principal_display);
  console.log("   Granted scope:  ", delegatedResult.granted_scope.join(", "));
  console.log("   Access token:   ", delegatedResult.access_token.slice(0, 40) + "...\n");

  // Step 11: Untrusted issuer should be rejected
  console.log("11. Untrusted issuer (should fail)...");
  const rogueIssuer = await DAPPrincipal.generate({
    id: "https://rogue-issuer.example",
    name: "Rogue Issuer",
  });
  const rogueCredential = await rogueIssuer.issueCredential({
    agentId: "urn:dap:agent:rogue-bot",
    scope: ["register"],
    principalId: "https://accounts.google.com/user/99999",
    principalName: "Hacker",
    issuerId: "https://rogue-issuer.example",
    verification: { level: "oauth", method: "custom_oauth" },
  });
  try {
    await bookingService.handleRegister({ credential: rogueCredential, agent_card: { name: "Rogue Bot" } });
    console.log("   FAIL: Should have been rejected!");
  } catch (e: unknown) {
    const err = e as Error & { dapError?: { error: string } };
    console.log(`   Correctly rejected: ${err.dapError?.error ?? err.message}`);
  }

  // Step 12: Insufficient verification level should be rejected
  console.log("\n12. Insufficient verification level (self < oauth, should fail)...");
  const lowVerifCredential = await principal.issueCredential({
    agentId: "urn:dap:agent:low-verif-bot",
    scope: ["register"],
    // No verification field => defaults to "self", below "oauth" minimum
  });
  try {
    await bookingService.handleRegister({ credential: lowVerifCredential, agent_card: { name: "Low Verif Bot" } });
    console.log("   FAIL: Should have been rejected!");
  } catch (e: unknown) {
    const err = e as Error & { dapError?: { error: string } };
    console.log(`   Correctly rejected: ${err.dapError?.error ?? err.message}`);
  }

  // Step 13: Unsupported principal scheme should be rejected
  console.log("\n13. Unsupported principal scheme (tel: not in accepted list, should fail)...");
  const telPrincipal = await DAPPrincipal.generate({
    id: "tel:+79001234567",
    name: "Anna",
  });
  const telCredential = await telPrincipal.issueCredential({
    agentId: "urn:dap:agent:tel-bot",
    scope: ["register"],
    principalType: "individual",
    verification: { level: "phone", method: "sms" },
  });
  try {
    await bookingService.handleRegister({ credential: telCredential, agent_card: { name: "Tel Bot" } });
    console.log("   FAIL: Should have been rejected!");
  } catch (e: unknown) {
    const err = e as Error & { dapError?: { error: string } };
    console.log(`   Correctly rejected: ${err.dapError?.error ?? err.message}`);
  }

  console.log("\n== Done ==");
}

main().catch(console.error);
