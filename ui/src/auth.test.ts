import { afterEach, expect, test, vi } from "vitest";
import { dropSession, finishCallback, openCredentials, refreshAccess, startLogin } from "./auth";
import { bytesToBase64Url, sha256Bytes } from "./sha256";
import { accessToken, clientCreds, refreshToken, rememberSession, saveClientCreds } from "./session";

afterEach(() => {
  dropSession();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  vi.useRealTimers();
});

function storage(seed: Record<string, string> = {}): Map<string, string> {
  const mem = new Map(Object.entries(seed));
  vi.stubGlobal("sessionStorage", {
    getItem: (key: string) => mem.get(key) ?? null,
    setItem: (key: string, value: string) => {
      mem.set(key, value);
    },
    removeItem: (key: string) => {
      mem.delete(key);
    },
  });
  return mem;
}

test("sign-in builds an S256 challenge and keeps the secret off the authorize URL", async () => {
  const mem = storage();
  saveClientCreds("probe", "s3cret");
  const realRandom = crypto.getRandomValues.bind(crypto);
  vi.stubGlobal("crypto", {
    getRandomValues: realRandom,
    subtle: { digest: () => Promise.reject(new Error("insecure")) },
  });
  let assigned = "";
  vi.stubGlobal("window", {
    location: {
      pathname: "/flows",
      search: "",
      origin: "http://10.1.0.232:8080",
      assign: (url: string) => {
        assigned = url;
      },
    },
  });
  await startLogin();
  const u = new URL(assigned, "http://10.1.0.232:8080");
  const verifier = mem.get("vibecollector.pkce_verifier") ?? "";
  const challenge = bytesToBase64Url(sha256Bytes(new TextEncoder().encode(verifier)));
  expect(u.pathname).toBe("/oauth/authorize");
  expect(u.searchParams.get("response_type")).toBe("code");
  expect(u.searchParams.get("client_id")).toBe("probe");
  expect(u.searchParams.get("redirect_uri")).toBe("http://10.1.0.232:8080/callback");
  expect(u.searchParams.get("scope")).toBe("read");
  expect(u.searchParams.get("code_challenge")).toBe(challenge);
  expect(u.searchParams.get("code_challenge_method")).toBe("S256");
  expect(u.searchParams.get("state")).toBe(mem.get("vibecollector.pkce_state"));
  expect(u.searchParams.has("code_verifier")).toBe(false);
  expect(u.searchParams.has("client_secret")).toBe(false);
  expect(assigned).not.toContain("s3cret");
});

test("a tab with no client pair opens the credentials form", async () => {
  const mem = storage();
  let assigned = "";
  vi.stubGlobal("window", {
    location: {
      pathname: "/talkers",
      search: "?tz=UTC",
      origin: "http://10.1.0.232:8080",
      assign: (url: string) => {
        assigned = url;
      },
    },
  });
  await openCredentials();
  expect(assigned).toBe("/credentials");
  expect(mem.get("vibecollector.return")).toBe("/talkers?tz=UTC");
});

test("a cleaned-up callback does not consume the return path", async () => {
  const mem = storage({
    "vibecollector.return": "/talkers?day=2026-03-08&tz=America/New_York",
    "vibecollector.client_id": "probe",
    "vibecollector.client_secret": "s3cret",
    "vibecollector.pkce_verifier": "verifier-1",
    "vibecollector.pkce_state": "state1",
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
  vi.stubGlobal("fetch", (_url: string, init?: RequestInit) => {
    const body = String(init?.body);
    expect(body).toContain("grant_type=authorization_code");
    expect(body).toContain("code=abc");
    expect(body).toContain("state=state1");
    expect(body).toContain("code_verifier=verifier-1");
    expect(body).toContain("client_id=probe");
    expect(body).toContain("client_secret=s3cret");
    expect(body).not.toContain("code_challenge");
    return pending;
  });

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
  expect(mem.has("vibecollector.pkce_verifier")).toBe(false);
  expect(mem.get("vibecollector.client_secret")).toBe("s3cret");
});

test("refresh posts one shared request and replaces both tokens", async () => {
  storage();
  saveClientCreds("probe", "s3cret");
  rememberSession("old-access", "old-refresh");
  let calls = 0;
  let release!: (value: Response) => void;
  const pending = new Promise<Response>((resolve) => {
    release = resolve;
  });
  vi.stubGlobal("fetch", (_url: string, init?: RequestInit) => {
    calls += 1;
    expect(String(init?.body)).toBe(
      "grant_type=refresh_token&refresh_token=old-refresh&client_id=probe&client_secret=s3cret&scope=read",
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

test("a failed refresh clears both tokens and keeps the saved pair", async () => {
  storage();
  saveClientCreds("probe", "s3cret");
  rememberSession("old-access", "old-refresh");
  vi.stubGlobal("fetch", async () => new Response("no", { status: 400 }));
  await expect(refreshAccess()).rejects.toMatchObject({ name: "NeedsLogin", redirectStarted: true });
  expect(accessToken()).toBeNull();
  expect(refreshToken()).toBeNull();
  expect(clientCreds()).toEqual({ clientId: "probe", clientSecret: "s3cret" });
});

test("a rejected client secret opens the credentials form", async () => {
  const mem = storage();
  saveClientCreds("probe", "s3cret");
  rememberSession("old-access", "old-refresh");
  let assigned = "";
  vi.stubGlobal("window", {
    location: {
      pathname: "/flows",
      search: "",
      origin: "http://10.1.0.232:8080",
      assign: (url: string) => {
        assigned = url;
      },
    },
  });
  vi.stubGlobal("fetch", async () => Response.json({ error: "invalid_client" }, { status: 401 }));
  await expect(refreshAccess()).rejects.toMatchObject({ name: "NeedsLogin", redirectStarted: true });
  expect(assigned).toBe("/credentials");
  expect(mem.get("vibecollector.auth_error")).toBe("The client id or secret was rejected.");
  expect(clientCreds()?.clientSecret).toBe("s3cret");
  expect(accessToken()).toBeNull();
});
