import http from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";
import react from "@vitejs/plugin-react";
import type { Plugin } from "vite";
import { defineConfig } from "vitest/config";

// UI assets and the Vite client stay on this dev server.
// Everything else, including /api, /oauth, /openapi.json, and a configured
// REST prefix, is forwarded to the daemon. Host is preserved so the
// authorization redirect matches the page origin.
function isUiPath(url: string): boolean {
  const path = url.split("?")[0] ?? "/";
  if (path === "/" || path === "/index.html") return true;
  const spa = ["/flows", "/traffic", "/talkers", "/asn", "/reputation", "/map", "/globe", "/callback", "/credentials"];
  if (spa.includes(path)) return true;
  if (path === "/src" || path.startsWith("/src/")) return true;
  if (path.startsWith("/@")) return true;
  if (path.startsWith("/node_modules/")) return true;
  if (path.startsWith("/__vite")) return true;
  return false;
}

function daemonProxy(): Plugin {
  return {
    name: "daemon-proxy",
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        const url = req.url ?? "/";
        if (isUiPath(url)) {
          next();
          return;
        }
        proxy(req, res);
      });
    },
  };
}

function proxy(req: IncomingMessage, res: ServerResponse): void {
  const headers: http.OutgoingHttpHeaders = { ...req.headers };
  delete headers.connection;
  delete headers["proxy-connection"];
  delete headers["keep-alive"];
  delete headers["transfer-encoding"];
  delete headers.upgrade;
  const preq = http.request(
    {
      protocol: "http:",
      hostname: "127.0.0.1",
      port: 8080,
      method: req.method,
      path: req.url,
      headers,
    },
    (pres) => {
      res.writeHead(pres.statusCode ?? 502, pres.headers);
      pres.pipe(res);
    },
  );
  preq.on("error", () => {
    if (!res.headersSent) res.writeHead(502, { "content-type": "text/plain; charset=utf-8" });
    res.end("daemon unavailable");
  });
  req.pipe(preq);
}

export default defineConfig({
  plugins: [react(), daemonProxy()],
  test: {
    environment: "node",
    // The Playwright spec starts browsers. Vitest must not collect it.
    exclude: ["**/node_modules/**", "**/dist/**", "e2e/**"],
  },
});
