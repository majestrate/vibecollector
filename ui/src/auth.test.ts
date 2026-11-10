import { afterEach, expect, test, vi } from "vitest";
import { finishCallback } from "./auth";
import { setAccessToken } from "./session";

afterEach(() => {
  setAccessToken(null);
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

test("a cleaned-up callback does not consume the return path", async () => {
  const mem = new Map<string, string>([
    ["vibecollector.return", "/talkers?day=2026-03-08&tz=America/New_York"],
    ["vibecollector.pkce_state", "state1"],
    ["vibecollector.pkce_verifier", "verifier-verifier-verifier-verifier-verifier"],
  ]);
  vi.stubGlobal("sessionStorage", {
    getItem: (key: string) => mem.get(key) ?? null,
    setItem: (key: string, value: string) => {
      mem.set(key, value);
    },
    removeItem: (key: string) => {
      mem.delete(key);
    },
  });
  vi.stubGlobal("window", {
    location: {
      pathname: "/callback",
      search: "?code=abc&state=state1",
      origin: "http://127.0.0.1:5173",
    },
  });
  let release!: (value: Response) => void;
  const pending = new Promise<Response>((resolve) => {
    release = resolve;
  });
  vi.stubGlobal("fetch", () => pending);

  let cancelFirst = false;
  const paths: string[] = [];
  const search = "?code=abc&state=state1";
  const first = finishCallback(search, () => cancelFirst, (path) => {
    paths.push(path);
  });
  cancelFirst = true;
  const second = finishCallback(search, () => false, (path) => {
    paths.push(path);
  });
  release(Response.json({ access_token: "mem-token" }));
  expect(await first).toBe(false);
  expect(await second).toBe(true);
  expect(paths).toEqual(["/talkers?day=2026-03-08&tz=America/New_York"]);
  expect(mem.has("vibecollector.return")).toBe(false);
});
