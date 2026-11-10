import { afterEach, expect, test, vi } from "vitest";
import { dropSession, finishCallback, refreshAccess } from "./auth";
import { accessToken, refreshToken, rememberSession } from "./session";

afterEach(() => {
  dropSession();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  vi.useRealTimers();
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
  release(
    Response.json({
      access_token: "mem-token",
      refresh_token: "mem-refresh",
      expires_in: 3600,
      token_type: "bearer",
      scope: "read",
    }),
  );
  expect(await first).toBe(false);
  expect(await second).toBe(true);
  expect(paths).toEqual(["/talkers?day=2026-03-08&tz=America/New_York"]);
  expect(mem.has("vibecollector.return")).toBe(false);
});

test("refresh posts one shared request and replaces both tokens", async () => {
  rememberSession("old-access", "old-refresh");
  let calls = 0;
  let release!: (value: Response) => void;
  const pending = new Promise<Response>((resolve) => {
    release = resolve;
  });
  vi.stubGlobal("fetch", (_url: string, init?: RequestInit) => {
    calls += 1;
    expect(String(init?.body)).toBe(
      "grant_type=refresh_token&refresh_token=old-refresh&client_id=vibecollector-ui&scope=read",
    );
    return pending;
  });
  const first = refreshAccess();
  const second = refreshAccess();
  release(
    Response.json({
      access_token: "new-access",
      refresh_token: "new-refresh",
      expires_in: 3600,
      token_type: "bearer",
      scope: "read",
    }),
  );
  await Promise.all([first, second]);
  expect(calls).toBe(1);
  expect(accessToken()).toBe("new-access");
  expect(refreshToken()).toBe("new-refresh");
});

test("a failed refresh clears both tokens", async () => {
  rememberSession("old-access", "old-refresh");
  vi.stubGlobal("fetch", async () => new Response("no", { status: 400 }));
  await expect(refreshAccess()).rejects.toMatchObject({ name: "NeedsLogin", redirectStarted: true });
  expect(accessToken()).toBeNull();
  expect(refreshToken()).toBeNull();
});
