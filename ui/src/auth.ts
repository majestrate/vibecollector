import { clearSession, clientCreds, refreshToken, rememberSession } from "./session";
import { bytesToBase64Url, sha256 } from "./sha256";

const REDIRECT_PATH = "/callback";
const CREDENTIALS_PATH = "/credentials";
const RETURN_KEY = "vibecollector.return";
const PKCE_VERIFIER_KEY = "vibecollector.pkce_verifier";
const PKCE_STATE_KEY = "vibecollector.pkce_state";
const AUTH_ERROR_KEY = "vibecollector.auth_error";

let loginFlight: Promise<void> | null = null;
let exchangeFlight: Promise<void> | null = null;
let refreshFlight: Promise<void> | null = null;
let refreshTimer: ReturnType<typeof setTimeout> | null = null;

/**
 * NeedsLogin means the session could not be renewed.
 * redirectStarted is true when the browser is already navigating to sign in.
 * message is why the navigation did not start when redirectStarted is false.
 */
export class NeedsLogin extends Error {
  readonly redirectStarted: boolean;

  constructor(message: string, redirectStarted: boolean) {
    super(message);
    this.name = "NeedsLogin";
    this.redirectStarted = redirectStarted;
  }
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
 * The access token is not included. The callback and credentials pages are left unchanged.
 */
export function rememberReturn(): void {
  if (typeof window === "undefined") return;
  if (window.location.pathname === REDIRECT_PATH || window.location.pathname === CREDENTIALS_PATH) return;
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
 * consumeReturn removes and returns the stored path after sign-in.
 * An unsafe or empty value becomes /flows. The token is never read from it.
 * The credentials page and the callback become /flows.
 */
export function consumeReturn(): string {
  let stored = "";
  try {
    stored = sessionStorage.getItem(RETURN_KEY) ?? "";
    sessionStorage.removeItem(RETURN_KEY);
  } catch {
    stored = "";
  }
  if (!stored.startsWith("/") || stored.startsWith("//") || stored.includes("://") || stored.includes("code=") || stored.includes("client_secret=")) {
    return "/flows";
  }
  if (stored === "/" || stored.startsWith("/?")) {
    return "/flows" + stored.slice(1);
  }
  if (stored === REDIRECT_PATH || stored.startsWith(REDIRECT_PATH + "?") || stored === CREDENTIALS_PATH || stored.startsWith(CREDENTIALS_PATH + "?")) {
    return "/flows";
  }
  return stored;
}

/**
 * setAuthError stores a message for the credentials form.
 * message is shown once on that page. The client secret is not included.
 * A missing sessionStorage drops the message.
 */
export function setAuthError(message: string): void {
  if (typeof sessionStorage === "undefined") return;
  sessionStorage.setItem(AUTH_ERROR_KEY, message);
}

/**
 * peekAuthError reads the credentials-form message.
 * The result is null when no message is stored. It does not remove the message.
 */
export function peekAuthError(): string | null {
  if (typeof sessionStorage === "undefined") return null;
  try {
    const value = sessionStorage.getItem(AUTH_ERROR_KEY);
    return value && value !== "" ? value : null;
  } catch {
    return null;
  }
}

/**
 * clearAuthError removes the credentials-form message.
 * The client id and secret stay in sessionStorage.
 */
export function clearAuthError(): void {
  if (typeof sessionStorage === "undefined") return;
  try {
    sessionStorage.removeItem(AUTH_ERROR_KEY);
  } catch {
    // The form already copied the message.
  }
}

/**
 * openCredentials sends the browser to the client id and secret form.
 * The current path is stored first, except on the form itself.
 * A missing window resolves without navigating.
 * It throws when sessionStorage rejects the return path.
 */
export function openCredentials(): Promise<void> {
  if (typeof window === "undefined") return Promise.resolve();
  rememberReturn();
  if (window.location.pathname !== CREDENTIALS_PATH) {
    window.location.assign(CREDENTIALS_PATH);
  }
  return Promise.resolve();
}

/**
 * startLogin begins the authorization-code grant with PKCE.
 * The page creates the verifier and the S256 challenge. The client id comes from
 * sessionStorage. The client secret is not placed on the authorize URL.
 * A tab with no saved pair opens the credentials form instead.
 * A missing window resolves without navigating, so unit tests can call the fetch path.
 */
export function startLogin(): Promise<void> {
  if (typeof window === "undefined") return Promise.resolve();
  if (!loginFlight) {
    loginFlight = runLogin().finally(() => {
      loginFlight = null;
    });
  }
  return loginFlight;
}

/**
 * finishLogin exchanges the authorization code for an opaque access token and refresh token.
 * search is the callback query string, including code and state.
 * The tokens are kept in memory. The verifier and client secret are posted to /oauth/token.
 * It rejects when code, state, or the token response does not check out.
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

/**
 * finishCallback exchanges the code and sends the operator back to the stored path.
 * search is the callback query string.
 * cancelled is true when this caller was cleaned up. That caller does not read
 * or delete the return path and does not navigate.
 * navigate receives the path to restore, such as /talkers.
 * The promise resolves true when this caller navigated.
 * It rejects when the code exchange fails.
 */
export async function finishCallback(search: string, cancelled: () => boolean, navigate: (path: string) => void): Promise<boolean> {
  await finishLogin(search);
  if (cancelled()) return false;
  navigate(consumeReturn());
  return true;
}

async function runLogin(): Promise<void> {
  const creds = clientCreds();
  rememberReturn();
  if (!creds) {
    if (window.location.pathname !== CREDENTIALS_PATH) {
      window.location.assign(CREDENTIALS_PATH);
    }
    return;
  }
  const verifier = randomURL(32);
  const challenge = bytesToBase64Url(await sha256(new TextEncoder().encode(verifier)));
  const state = randomURL(16);
  sessionStorage.setItem(PKCE_VERIFIER_KEY, verifier);
  sessionStorage.setItem(PKCE_STATE_KEY, state);
  const q = new URLSearchParams({
    response_type: "code",
    client_id: creds.clientId,
    redirect_uri: redirectURI(),
    scope: "read",
    code_challenge: challenge,
    code_challenge_method: "S256",
    state,
  });
  window.location.assign("/oauth/authorize?" + q.toString());
}

async function runExchange(search: string): Promise<void> {
  const q = new URLSearchParams(search);
  const code = q.get("code");
  const state = q.get("state");
  const creds = clientCreds();
  const verifier = readItem(PKCE_VERIFIER_KEY);
  const storedState = readItem(PKCE_STATE_KEY);
  clearPKCE();
  if (!code || !state || !creds || !verifier || storedState !== state) {
    throw new Error("Sign-in failed.");
  }
  const form = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: redirectURI(),
    client_id: creds.clientId,
    client_secret: creds.clientSecret,
    code_verifier: verifier,
    state,
    scope: "read",
  });
  const res = await postToken(form);
  if (res.status === 401) {
    throw new Error("The client id or secret was rejected.");
  }
  if (!res.ok) {
    throw new Error("Sign-in failed.");
  }
  storeTokenResponse(await res.json());
}

/**
 * refreshAccess trades the in-memory refresh token for a new pair.
 * Concurrent callers share one POST. The body is grant_type refresh_token
 * plus the client id and secret from sessionStorage.
 * A failure clears both tokens. It throws NeedsLogin when the session is gone.
 * redirectStarted on that error means navigation to sign-in already ran.
 */
export function refreshAccess(): Promise<void> {
  if (!refreshFlight) {
    refreshFlight = runRefresh().finally(() => {
      refreshFlight = null;
    });
  }
  return refreshFlight;
}

/**
 * dropSession forgets both tokens and cancels the refresh timer.
 * The client id and secret in sessionStorage stay. The PKCE verifier is removed.
 */
export function dropSession(): void {
  if (refreshTimer) clearTimeout(refreshTimer);
  refreshTimer = null;
  clearSession();
  clearPKCE();
}

function storeTokenResponse(tok: unknown): void {
  if (!isRecord(tok) || typeof tok.access_token !== "string" || tok.access_token === "") {
    throw new Error("Sign-in failed.");
  }
  if (typeof tok.refresh_token !== "string" || tok.refresh_token === "") {
    throw new Error("Sign-in failed.");
  }
  if (typeof tok.expires_in !== "number" || tok.expires_in < 1) {
    throw new Error("Sign-in failed.");
  }
  rememberSession(tok.access_token, tok.refresh_token);
  armRefresh(tok.expires_in);
}

function armRefresh(expiresIn: number): void {
  if (refreshTimer) clearTimeout(refreshTimer);
  const skew = 60;
  const seconds = expiresIn > skew ? expiresIn - skew : Math.max(1, Math.floor(expiresIn / 2));
  refreshTimer = setTimeout(() => {
    refreshTimer = null;
    void refreshAccess().catch(() => {});
  }, seconds * 1000);
}

async function runRefresh(): Promise<void> {
  const current = refreshToken();
  const creds = clientCreds();
  if (!current || !creds) {
    dropSession();
    throw await loginAfterRefresh();
  }
  const form = new URLSearchParams({
    grant_type: "refresh_token",
    refresh_token: current,
    client_id: creds.clientId,
    client_secret: creds.clientSecret,
    scope: "read",
  });
  let res: Response;
  try {
    res = await postToken(form);
  } catch {
    dropSession();
    throw await loginAfterRefresh();
  }
  if (res.status === 401) {
    dropSession();
    setAuthError("The client id or secret was rejected.");
    throw await credentialsAfterFailure();
  }
  if (!res.ok) {
    dropSession();
    throw await loginAfterRefresh();
  }
  try {
    storeTokenResponse(await res.json());
  } catch {
    dropSession();
    throw await loginAfterRefresh();
  }
}

async function postToken(form: URLSearchParams): Promise<Response> {
  return fetch("/oauth/token", {
    method: "POST",
    credentials: "same-origin",
    headers: {
      Accept: "application/json",
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: form.toString(),
  });
}

async function loginAfterRefresh(): Promise<NeedsLogin> {
  try {
    await startLogin();
  } catch (err) {
    const message = err instanceof Error ? err.message : "Sign-in failed.";
    return new NeedsLogin(message, false);
  }
  return new NeedsLogin("unauthorized", true);
}

async function credentialsAfterFailure(): Promise<NeedsLogin> {
  try {
    await openCredentials();
  } catch (err) {
    const message = err instanceof Error ? err.message : "Sign-in failed.";
    return new NeedsLogin(message, false);
  }
  return new NeedsLogin("unauthorized", true);
}

function randomURL(n: number): string {
  const buf = new Uint8Array(n);
  if (typeof crypto === "undefined" || typeof crypto.getRandomValues !== "function") {
    throw new Error("Sign-in failed.");
  }
  crypto.getRandomValues(buf);
  return bytesToBase64Url(buf);
}

function readItem(key: string): string {
  try {
    return sessionStorage.getItem(key) ?? "";
  } catch {
    return "";
  }
}

function clearPKCE(): void {
  if (typeof sessionStorage === "undefined") return;
  try {
    sessionStorage.removeItem(PKCE_VERIFIER_KEY);
    sessionStorage.removeItem(PKCE_STATE_KEY);
  } catch {
    // The next sign-in overwrites both keys.
  }
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null;
}
