import { spawn, type ChildProcess } from "node:child_process";
import { rmSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { expect, test, type Page, type Request } from "playwright/test";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const origin = "http://127.0.0.1:5173";
const pageHost = "127.0.0.1";
const db = path.join(tmpdir(), "vibecollector-globe-e2e.db");

let daemon: ChildProcess | undefined;
let vite: ChildProcess | undefined;

// The daemon, the Vite dev server, and localhost are one host. The port is not the host.
function loopback(host: string): boolean {
  const name = host.toLowerCase().replace(/^\[|\]$/g, "");
  return name === "localhost" || name === "127.0.0.1" || name === "::1";
}

function foreignHost(url: string): string | null {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return url;
  }
  if (parsed.protocol === "data:" || parsed.protocol === "blob:" || parsed.protocol === "about:") return null;
  const host = parsed.hostname;
  if (host === pageHost || (loopback(host) && loopback(pageHost))) return null;
  return host || url;
}

function track(page: Page): string[] {
  const bad: string[] = [];
  const onRequest = (req: Request) => {
    const host = foreignHost(req.url());
    if (host) bad.push(req.url());
  };
  page.on("request", onRequest);
  return bad;
}

function kill(child: ChildProcess | undefined): void {
  if (!child?.pid) return;
  try {
    process.kill(-child.pid, "SIGTERM");
  } catch {
    try {
      child.kill("SIGTERM");
    } catch {
      /* already gone */
    }
  }
}

function logs(child: ChildProcess): { text: () => string } {
  let buf = "";
  const add = (chunk: Buffer) => {
    buf = (buf + chunk.toString()).slice(-6000);
  };
  child.stdout?.on("data", add);
  child.stderr?.on("data", add);
  return { text: () => buf };
}

async function waitForHTTP(url: string, child: ChildProcess, note: { text: () => string }): Promise<void> {
  const deadline = Date.now() + 120_000;
  let last = "";
  while (Date.now() < deadline) {
    if (child.exitCode !== null) throw new Error(`${url} exited ${child.exitCode}\n${note.text()}`);
    try {
      const res = await fetch(url);
      if (res.ok) return;
      last = String(res.status);
    } catch (err) {
      last = err instanceof Error ? err.message : "down";
    }
    await new Promise((resolve) => setTimeout(resolve, 300));
  }
  throw new Error(`timed out waiting for ${url}: ${last}\n${note.text()}`);
}

test.beforeAll(async () => {
  for (const suffix of ["", "-wal", "-shm"]) rmSync(db + suffix, { force: true });
  daemon = spawn(
    "go",
    ["run", "./cmd/vibecollector", "-http", "127.0.0.1:8080", "-udp", "127.0.0.1:20551", "-db", db],
    {
      cwd: root,
      detached: true,
      env: { ...process.env, CGO_ENABLED: "0" },
      stdio: ["ignore", "pipe", "pipe"],
    },
  );
  const daemonLog = logs(daemon);
  vite = spawn(process.execPath, [path.join(root, "ui/node_modules/vite/bin/vite.js"), "--host", "127.0.0.1", "--port", "5173", "--strictPort"], {
    cwd: path.join(root, "ui"),
    detached: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const viteLog = logs(vite);
  const stop = () => {
    kill(daemon);
    kill(vite);
  };
  process.on("exit", stop);
  await waitForHTTP("http://127.0.0.1:8080/openapi.json", daemon, daemonLog);
  await waitForHTTP(origin + "/", vite, viteLog);
}, 180_000);

test.afterAll(() => {
  kill(daemon);
  kill(vite);
  for (const suffix of ["", "-wal", "-shm"]) rmSync(db + suffix, { force: true });
});

test("map and globe stay on the page host", async ({ page }) => {
  test.setTimeout(120_000);
  const bad = track(page);
  await page.goto(origin + "/map", { waitUntil: "domcontentloaded" });
  await page.locator("h1", { hasText: "Map" }).waitFor({ timeout: 60_000 });
  await page.locator(".map svg").waitFor({ timeout: 60_000 });
  await page.goto(origin + "/globe", { waitUntil: "domcontentloaded" });
  await page.locator("h1", { hasText: "Globe" }).waitFor({ timeout: 60_000 });
  await page.locator(".globe canvas").waitFor({ timeout: 60_000 });
  await page.evaluate(
    () =>
      new Promise<void>((resolve) => {
        requestAnimationFrame(() => requestAnimationFrame(() => resolve()));
      }),
  );
  expect(bad, bad.join("\n")).toEqual([]);
});
