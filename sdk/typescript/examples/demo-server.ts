/**
 * Lightweight HTTP server wrapper around DAPService.
 * Serves /.well-known/dap, POST /dap/v1/register, and custom mock API routes.
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { DAPService, type ServiceConfig, type RegisterRequest, type DAPError } from "../src/index.js";

export interface MockRoute {
  method: string;
  path: string;
  handler: (req: IncomingMessage, body: any) => { status: number; body: any };
}

export interface DemoServiceConfig {
  serviceConfig: ServiceConfig;
  mockRoutes?: MockRoute[];
}

export async function startDemoService(config: DemoServiceConfig, port: number) {
  const service = new DAPService(config.serviceConfig);
  const discovery = service.discoveryDocument();

  // Override dap_endpoint to use localhost
  (discovery as any).dap_endpoint = `http://localhost:${port}/dap/v1`;

  const server = createServer(async (req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url!, `http://localhost:${port}`);

    // Discovery endpoint
    if (req.method === "GET" && url.pathname === "/.well-known/dap") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(discovery));
      return;
    }

    // Register endpoint
    if (req.method === "POST" && url.pathname === "/dap/v1/register") {
      const body = await readBody(req);
      try {
        const result = await service.handleRegister(JSON.parse(body) as RegisterRequest);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify(result));
      } catch (e: any) {
        const dapErr: DAPError = e.dapError ?? { error: "server_error", error_description: e.message };
        const status = errorStatus(dapErr.error);
        res.writeHead(status, { "Content-Type": "application/json" });
        res.end(JSON.stringify(dapErr));
      }
      return;
    }

    // Mock API routes
    for (const route of config.mockRoutes ?? []) {
      if (req.method === route.method && url.pathname === route.path) {
        // Demo only: we check for token presence but skip validation.
        // Production services MUST verify the access token (e.g. signed JWT or opaque token lookup).
        const auth = req.headers.authorization;
        if (!auth?.startsWith("Bearer ")) {
          res.writeHead(401, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: "unauthorized", message: "Missing Bearer token" }));
          return;
        }
        let body = null;
        if (req.method !== "GET") {
          try {
            body = JSON.parse(await readBody(req));
          } catch {
            res.writeHead(400, { "Content-Type": "application/json" });
            res.end(JSON.stringify({ error: "bad_request", message: "Invalid JSON body" }));
            return;
          }
        }
        const result = route.handler(req, body);
        res.writeHead(result.status, { "Content-Type": "application/json" });
        res.end(JSON.stringify(result.body));
        return;
      }
    }

    res.writeHead(404);
    res.end("Not found");
  });

  await new Promise<void>((resolve) => server.listen(port, resolve));

  return {
    port,
    url: `http://localhost:${port}`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (chunk) => (data += chunk));
    req.on("end", () => resolve(data));
    req.on("error", (err) => reject(err));
  });
}

function errorStatus(code: string): number {
  switch (code) {
    case "invalid_signature":
    case "credential_expired":
    case "credential_revoked":
      return 401;
    case "insufficient_scope":
    case "untrusted_issuer":
    case "insufficient_verification":
    case "principal_blocked":
      return 403;
    default:
      return 400;
  }
}
