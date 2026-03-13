/**
 * DAP Interactive Demo
 *
 * Runs 4 real-world scenarios showing the full Delegated Agent Protocol flow.
 * Each scenario spins up a real HTTP server and executes:
 *   discovery → register → API call
 *
 * Run: npx tsx examples/demo.ts
 */

import { DAPPrincipal, type ServiceConfig, type AgentCard, type Verification } from "../src/index.js";
import { importJWK } from "jose";
import { startDemoService } from "./demo-server.js";

// ─── Colors (ANSI, no dependencies) ────────────────────────────────────────

const c = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  green: "\x1b[32m",
  blue: "\x1b[34m",
  magenta: "\x1b[35m",
  cyan: "\x1b[36m",
  red: "\x1b[31m",
  bgGreen: "\x1b[42m",
  bgRed: "\x1b[41m",
  white: "\x1b[37m",
};

function header(n: number, title: string, subtitle: string) {
  console.log();
  console.log(`${c.bold}${c.blue}${"═".repeat(70)}${c.reset}`);
  console.log(`${c.bold}${c.blue}  SCENARIO ${n}: ${title}${c.reset}`);
  console.log(`${c.dim}  ${subtitle}${c.reset}`);
  console.log(`${c.bold}${c.blue}${"═".repeat(70)}${c.reset}`);
  console.log();
}

function step(label: string, detail?: string) {
  const d = detail ? `  ${c.dim}${detail}${c.reset}` : "";
  console.log(`  ${c.cyan}→${c.reset} ${label}${d}`);
}

function ok(label: string, value?: string) {
  const v = value ? `  ${c.green}${value}${c.reset}` : "";
  console.log(`  ${c.green}✓${c.reset} ${label}${v}`);
}

function info(label: string, value: string) {
  console.log(`    ${c.dim}${label}:${c.reset} ${value}`);
}

function apiCall(method: string, path: string) {
  console.log(`  ${c.magenta}⤷${c.reset} ${c.bold}${method}${c.reset} ${path}`);
}

function apiResult(data: any) {
  const json = JSON.stringify(data, null, 2)
    .split("\n")
    .map((l) => `    ${c.dim}${l}${c.reset}`)
    .join("\n");
  console.log(json);
}

function banner(text: string, success: boolean) {
  const bg = success ? c.bgGreen : c.bgRed;
  console.log(`\n  ${bg}${c.white}${c.bold} ${text} ${c.reset}\n`);
}

// ─── Scenario definition ───────────────────────────────────────────────────

interface Scenario {
  number: number;
  title: string;
  subtitle: string;
  port: number;

  principalId: string;
  principalName: string;
  principalType: "individual" | "organization";

  issuer?: { id: string; name: string };

  agentId: string;
  agentCard: AgentCard;
  scope: string[];
  verification: Verification;
  purpose: string;
  contactEmail: string;

  serviceName: string;
  serviceConfig: Partial<ServiceConfig>;

  apiDemo: {
    method: string;
    path: string;
    description: string;
    requestBody?: any;
    responseBody: any;
  };
}

async function runScenario(s: Scenario) {
  header(s.number, s.title, s.subtitle);

  const isDelegated = !!s.issuer;

  // 1. Create keys
  let signerPrincipal: DAPPrincipal;
  let signerJWK: Record<string, unknown>;

  if (isDelegated) {
    step("Issuer generates keypair", s.issuer!.name);
    signerPrincipal = await DAPPrincipal.generate({ id: s.issuer!.id, name: s.issuer!.name });
    signerJWK = await signerPrincipal.exportPublicKeyJWK();
    ok("Issuer ready", s.issuer!.id);
  } else {
    step("Principal generates keypair", s.principalName);
    signerPrincipal = await DAPPrincipal.generate({ id: s.principalId, name: s.principalName });
    signerJWK = await signerPrincipal.exportPublicKeyJWK();
    ok("Principal ready", s.principalId);
  }

  // 2. Issue credential
  step("Issuing agent credential", isDelegated ? "delegated" : "self-issued");
  const credential = await signerPrincipal.issueCredential({
    agentId: s.agentId,
    scope: s.scope,
    principalType: s.principalType,
    principalId: isDelegated ? s.principalId : undefined,
    principalName: isDelegated ? s.principalName : undefined,
    issuerId: isDelegated ? s.issuer!.id : undefined,
    purpose: s.purpose,
    contactEmail: s.contactEmail,
    expiresIn: "24h",
    verification: s.verification,
  });
  ok("Credential issued");
  info("Agent", s.agentId);
  info("Principal", `${s.principalName} (${s.principalType})`);
  info("Verification", `${s.verification.level} via ${s.verification.method}`);
  if (isDelegated) {
    info("Issuer", s.issuer!.id);
  }

  // 3. Start service
  console.log();
  step("Starting service", s.serviceName);

  const keyId = isDelegated ? s.issuer!.id : s.principalId;
  const serviceConfig: ServiceConfig = {
    ...s.serviceConfig,
    name: s.serviceName,
    baseUrl: `http://localhost:${s.port}`,
    resolvePublicKey: async (id) => {
      if (id === keyId) return importJWK(signerJWK, "EdDSA");
      throw new Error(`Unknown key: ${id}`);
    },
  };

  const server = await startDemoService(
    {
      serviceConfig,
      mockRoutes: [
        {
          method: s.apiDemo.method,
          path: s.apiDemo.path,
          handler: () => ({ status: 200, body: s.apiDemo.responseBody }),
        },
      ],
    },
    s.port,
  );

  ok("Service running", server.url);

  // 4. Discovery
  console.log();
  apiCall("GET", `${server.url}/.well-known/dap`);
  const discoveryRes = await fetch(`${server.url}/.well-known/dap`);
  if (!discoveryRes.ok) {
    banner(`Discovery failed: HTTP ${discoveryRes.status}`, false);
    await server.close();
    return;
  }
  const discovery = (await discoveryRes.json()) as any;
  ok("Discovery complete");
  info("DAP endpoint", discovery.dap_endpoint);
  info("Min verification", discovery.requirements.min_verification_level ?? "self");
  if (discovery.requirements.trusted_issuers) {
    info("Trusted issuers", discovery.requirements.trusted_issuers.join(", "));
  }

  // 5. Register
  console.log();
  apiCall("POST", `${discovery.dap_endpoint}/register`);
  const registerRes = await fetch(`${discovery.dap_endpoint}/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ credential, agent_card: s.agentCard }),
  });
  const registerData = (await registerRes.json()) as any;

  if (!registerRes.ok) {
    banner(`REJECTED: ${registerData.error}`, false);
    await server.close();
    return;
  }

  ok("Registered successfully");
  info("Session", registerData.session_id);
  info("Account", registerData.account_id);
  info("Principal", registerData.principal_display);
  info("Scope", registerData.granted_scope.join(", "));
  info("Token", registerData.access_token.slice(0, 30) + "...");

  // 6. API call with token
  console.log();
  step(s.apiDemo.description);
  apiCall(s.apiDemo.method, `${server.url}${s.apiDemo.path}`);

  const fetchOpts: RequestInit = {
    method: s.apiDemo.method,
    headers: {
      Authorization: `Bearer ${registerData.access_token}`,
      "Content-Type": "application/json",
    },
  };
  if (s.apiDemo.requestBody) {
    fetchOpts.body = JSON.stringify(s.apiDemo.requestBody);
  }

  const apiRes = await fetch(`${server.url}${s.apiDemo.path}`, fetchOpts);
  if (!apiRes.ok) {
    banner(`API call failed: HTTP ${apiRes.status}`, false);
    await server.close();
    return;
  }
  const apiData = await apiRes.json();
  ok("API response received");
  apiResult(apiData);

  banner("SCENARIO COMPLETE", true);
  await server.close();
}

// ─── Scenarios ─────────────────────────────────────────────────────────────

const scenarios: Scenario[] = [
  // 1. API Marketplace — email, delegated
  {
    number: 1,
    title: "API Marketplace",
    subtitle: "Individual developer browses and subscribes to APIs (email verification)",
    port: 9101,
    principalId: "mailto:alex.r@example.com",
    principalName: "Alex Rivera",
    principalType: "individual",
    issuer: { id: "https://dap-wallet.example", name: "DAP Wallet" },
    agentId: "urn:dap:agent:api-scout-v1",
    agentCard: {
      name: "API Scout",
      description: "Discovers, compares, and subscribes to APIs",
      version: "1.0.0",
      capabilities: ["search", "compare", "subscribe"],
    },
    scope: ["register", "search_apis", "subscribe"],
    verification: {
      level: "email",
      method: "email_verification",
      verified_at: Math.floor(Date.now() / 1000),
      verified_by: "https://dap-wallet.example",
    },
    purpose: "API discovery and subscription management",
    contactEmail: "alex.r@example.com",
    serviceName: "APIHub Marketplace",
    serviceConfig: {
      minVerificationLevel: "email",
      trustedIssuers: ["https://dap-wallet.example"],
      acceptedPrincipalSchemes: ["mailto", "https", "did:web"],
    },
    apiDemo: {
      method: "GET",
      path: "/api/v1/search",
      description: "Searching for weather APIs",
      responseBody: {
        results: [
          { name: "OpenWeather API", price: "$0/mo", rating: 4.5, endpoints: 12 },
          { name: "WeatherStack", price: "$9.99/mo", rating: 4.2, endpoints: 8 },
          { name: "Tomorrow.io", price: "$19/mo", rating: 4.8, endpoints: 24 },
        ],
      },
    },
  },

  // 2. Food Delivery — phone, delegated
  {
    number: 2,
    title: "Food Delivery",
    subtitle: "Personal agent orders lunch from a delivery service (phone verification)",
    port: 9102,
    principalId: "tel:+14155551234",
    principalName: "Marcus Lee",
    principalType: "individual",
    issuer: { id: "https://dap-wallet.example", name: "DAP Wallet" },
    agentId: "urn:dap:agent:delivery-bot-v1",
    agentCard: {
      name: "Delivery Bot",
      description: "Orders food from restaurants and delivery services",
      version: "1.0.0",
      capabilities: ["search", "order", "track"],
    },
    scope: ["register", "search_restaurants", "place_order"],
    verification: {
      level: "phone",
      method: "sms_otp",
      verified_at: Math.floor(Date.now() / 1000),
      verified_by: "https://dap-wallet.example",
    },
    purpose: "Food ordering and delivery tracking",
    contactEmail: "marcus.l@example.com",
    serviceName: "FoodDash",
    serviceConfig: {
      minVerificationLevel: "phone",
      trustedIssuers: ["https://dap-wallet.example"],
      acceptedPrincipalSchemes: ["tel", "mailto", "https"],
    },
    apiDemo: {
      method: "POST",
      path: "/api/v1/orders",
      description: "Placing an order at Burger Palace",
      requestBody: {
        restaurant: "Burger Palace",
        items: ["Classic Burger", "Fries", "Coke"],
        delivery_address: "123 Main St, San Francisco, CA",
      },
      responseBody: {
        order_id: "ord_8f2k9x",
        status: "confirmed",
        restaurant: "Burger Palace",
        items: ["Classic Burger", "Fries", "Coke"],
        total: "$18.50",
        estimated_delivery: "35 min",
      },
    },
  },

  // 3. Doctor Appointment — document, delegated
  {
    number: 3,
    title: "Doctor Appointment",
    subtitle:
      "Personal agent books a medical appointment (document verification via driver's license)",
    port: 9103,
    principalId: "https://id.dap-wallet.example/users/sarah-j-1990",
    principalName: "Sarah Johnson",
    principalType: "individual",
    issuer: { id: "https://dap-wallet.example", name: "DAP Wallet" },
    agentId: "urn:dap:agent:medical-assistant-v2",
    agentCard: {
      name: "Medical Assistant",
      description: "Manages medical appointments and health records access",
      version: "2.1.0",
      capabilities: ["search_providers", "book_appointment", "manage_records"],
    },
    scope: ["register", "search_providers", "book_appointment"],
    verification: {
      level: "document",
      method: "drivers_license",
      verified_at: Math.floor(Date.now() / 1000),
      verified_by: "https://dap-wallet.example",
    },
    purpose: "Medical appointment scheduling",
    contactEmail: "sarah.j@example.com",
    serviceName: "CityHealth Clinic",
    serviceConfig: {
      minVerificationLevel: "document",
      trustedIssuers: ["https://dap-wallet.example"],
      acceptedPrincipalSchemes: ["https", "did:web"],
    },
    apiDemo: {
      method: "GET",
      path: "/api/v1/appointments/available",
      description: "Finding available appointment slots",
      responseBody: {
        provider: "Dr. Emily Chen, MD",
        specialty: "General Practice",
        available_slots: [
          { date: "2026-03-17", time: "09:00 AM", duration: "30 min" },
          { date: "2026-03-17", time: "02:30 PM", duration: "30 min" },
          { date: "2026-03-18", time: "11:00 AM", duration: "30 min" },
        ],
      },
    },
  },

  // 4. Bank Transfer — organization, self-issued
  {
    number: 4,
    title: "Bank Transfer",
    subtitle:
      "Corporate finance bot initiates a wire transfer (organization verification, self-issued)",
    port: 9104,
    principalId: "did:web:acme-corp.example",
    principalName: "Acme Inc",
    principalType: "organization",
    agentId: "urn:dap:agent:finance-bot-v3",
    agentCard: {
      name: "Finance Bot",
      description: "Manages corporate payments and treasury operations",
      version: "3.0.0",
      capabilities: ["check_balance", "initiate_transfer", "view_history"],
    },
    scope: ["register", "check_balance", "initiate_transfer"],
    verification: {
      level: "organization",
      method: "did:web",
      verified_at: Math.floor(Date.now() / 1000),
      verified_by: "did:web:acme-corp.example",
    },
    purpose: "Corporate treasury management",
    contactEmail: "treasury@acme-corp.example",
    serviceName: "TrustBank Business API",
    serviceConfig: {
      minVerificationLevel: "organization",
      acceptedPrincipalSchemes: ["did:web"],
    },
    apiDemo: {
      method: "POST",
      path: "/api/v1/transfers",
      description: "Initiating wire transfer to supplier",
      requestBody: {
        to: "Meridian Supply Co.",
        amount: 15000,
        currency: "USD",
        reference: "INV-2026-0342",
      },
      responseBody: {
        transfer_id: "txn_7m3p2q",
        status: "pending_approval",
        from: "Acme Inc (****4521)",
        to: "Meridian Supply Co.",
        amount: "$15,000.00",
        reference: "INV-2026-0342",
        estimated_settlement: "1 business day",
      },
    },
  },
];

// ─── Main ──────────────────────────────────────────────────────────────────

async function main() {
  console.log();
  console.log(`${c.bold}  DAP — Delegated Agent Protocol${c.reset}`);
  console.log(`${c.dim}  Interactive demo: 4 real-world scenarios${c.reset}`);
  console.log(
    `${c.dim}  Each scenario runs a real HTTP server and executes the full protocol flow.${c.reset}`,
  );

  for (const scenario of scenarios) {
    await runScenario(scenario);
  }

  console.log(`${c.bold}${c.blue}${"═".repeat(70)}${c.reset}`);
  console.log(`${c.bold}  All 4 scenarios completed.${c.reset}`);
  console.log();
  console.log(`${c.dim}  What you just saw:${c.reset}`);
  console.log(
    `${c.dim}  1. API Marketplace  — email verification, delegated credential${c.reset}`,
  );
  console.log(
    `${c.dim}  2. Food Delivery    — phone verification, delegated credential${c.reset}`,
  );
  console.log(
    `${c.dim}  3. Doctor Appt      — document verification, delegated credential${c.reset}`,
  );
  console.log(
    `${c.dim}  4. Bank Transfer    — organization verification, self-issued credential${c.reset}`,
  );
  console.log();
  console.log(
    `${c.dim}  Each agent proved its identity, the service verified it, and access was granted.${c.reset}`,
  );
  console.log(
    `${c.dim}  No API keys. No passwords. Just signed, verifiable credentials.${c.reset}`,
  );
  console.log();
  console.log(`${c.dim}  Learn more: https://github.com/dap-protocol/dap${c.reset}`);
  console.log();
}

main().catch((e) => {
  console.error(`${c.red}Fatal: ${e.message}${c.reset}`);
  process.exit(1);
});
