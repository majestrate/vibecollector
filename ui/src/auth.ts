import { setAccessToken } from "./session";

const CLIENT_ID = "vibecollector-ui";
const REDIRECT_PATH = "/callback";
const VERIFIER_KEY = "vibecollector.pkce_verifier";
const STATE_KEY = "vibecollector.pkce_state";
const RETURN_KEY = "vibecollector.return";

let loginFlight: Promise<void> | null = null;
let exchangeFlight: Promise<void> | null = null;

/**
 * s256Challenge returns the PKCE S256 challenge for verifier.
 * verifier is the raw code_verifier string.
 * The result is base64url without padding of SHA-256(verifier).
 * It rejects when the digest cannot be computed.
 */
export async function s256Challenge(verifier: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  return base64url(new Uint8Array(digest));
}

/**
 * redirectURI is the same-origin callback this shell owns.
 * The result is an absolute URL with no fragment. It throws when window is missing.
 */
export function redirectURI(): string {
  return window.location.origin + REDIRECT_PATH;
}

/**
 * rememberReturn stores the current path so login can come back to it.
 * The access token is not included. A callback URL is left unchanged.
 */
export function rememberReturn(): void {
  if (typeof window === "undefined") return;
  if (window.location.pathname === REDIRECT_PATH) return;
  const path = window.location.pathname + window.location.search;
  if (!path.startsWith("/") || path.startsWith("//")) return;
  sessionStorage.setItem(RETURN_KEY, path);
}

/**
 * peekReturnSearch is the query string to apply before the callback page
 * has navigated back. On the callback it reads the stored return path.
 * Elsewhere it is window.location.search. It does not remove the stored path.
 */
export function peekReturnSearch(): string {
  if (typeof window === "undefined") return "";
  try {
    if (window.location.pathname === REDIRECT_PATH) {
      const stored = sessionStorage.getItem(RETURN_KEY) ?? "";
      const q = stored.indexOf("?");
      return q >= 0 ? stored.slice(q) : "";
    }
    return window.location.search;
  } catch {
    return "";
  }
}

/**
 * consumeReturn removes and returns the stored path after the code exchange.
 * An unsafe or empty value becomes /flows. The token is never read from it.
 */
export function consumeReturn(): string {
  let stored = "";
  try {
    stored = sessionStorage.getItem(RETURN_KEY) ?? "";
    sessionStorage.removeItem(RETURN_KEY);
  } catch {
    stored = "";
  }
  if (!stored.startsWith("/") || stored.startsWith("//") || stored.includes("://") || stored.includes("code=")) {
    return "/flows";
  }
  if (stored === "/" || stored.startsWith("/?")) {
    return "/flows" + stored.slice(1);
  }
  if (stored === REDIRECT_PATH || stored.startsWith(REDIRECT_PATH + "?")) {
    return "/flows";
  }
  return stored;
}

/**
 * startLogin redirects the browser through the authorization-code grant.
 * The verifier and state survive the navigation in sessionStorage.
 * The access token is not stored. It rejects when the challenge cannot be built.
 * A missing window resolves without navigating, so unit tests can call the fetch path.
 */
export function startLogin(): Promise<void> {
  if (typeof window === "undefined") return Promise.resolve();
  if (!loginFlight) {
    loginFlight = runLogin().catch((err: unknown) => {
      loginFlight = null;
      throw err;
    });
  }
  return loginFlight;
}

/**
 * finishLogin exchanges the authorization code for an access token.
 * search is the callback query string, including code and state.
 * The token is kept in memory only. It rejects when state, the verifier,
 * or the token response does not check out.
 */
export function finishLogin(search: string): Promise<void> {
  if (!exchangeFlight) {
    exchangeFlight = runExchange(search).catch((err: unknown) => {
      exchangeFlight = null;
      throw err;
    });
  }
  return exchangeFlight;
}

async function runLogin(): Promise<void> {
  const verifier = randomToken();
  const state = randomToken();
  sessionStorage.setItem(VERIFIER_KEY, verifier);
  sessionStorage.setItem(STATE_KEY, state);
  const challenge = await s256Challenge(verifier);
  const q = new URLSearchParams({
    response_type: "code",
    client_id: CLIENT_ID,
    redirect_uri: redirectURI(),
    code_challenge: challenge,
    code_challenge_method: "S256",
    state,
    scope: "read",
  });
  rememberReturn();
  window.location.assign("/oauth/authorize?" + q.toString());
}

async function runExchange(search: string): Promise<void> {
  const q = new URLSearchParams(search);
  const code = q.get("code");
  const state = q.get("state");
  const expect = sessionStorage.getItem(STATE_KEY);
  const verifier = sessionStorage.getItem(VERIFIER_KEY);
  sessionStorage.removeItem(STATE_KEY);
  sessionStorage.removeItem(VERIFIER_KEY);
  if (!code || !state || !verifier || state !== expect) {
    throw new Error("Sign-in failed.");
  }
  const form = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectURI(),
    client_id: CLIENT_ID,
    code_verifier: verifier,
    scope: "read",
  });
  const res = await fetch("/oauth/token", {
    method: "POST",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: form.toString(),
  });
  if (!res.ok) {
    throw new Error("Sign-in failed.");
  }
  const tok: unknown = await res.json();
  if (!isRecord(tok) || typeof tok.access_token !== "string" || tok.access_token === "") {
    throw new Error("Sign-in failed.");
  }
  setAccessToken(tok.access_token);
}

function randomToken(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return base64url(bytes);
}

function base64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null;
}
