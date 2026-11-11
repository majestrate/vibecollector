/** In-memory bearer. Not written to sessionStorage, localStorage, or the query string. */
let token: string | null = null;

/** In-memory refresh token. Same storage rules as the bearer. */
let refresh: string | null = null;

/** REST prefix read from the served OpenAPI paths. Null until that read. */
let prefix: string | null = null;

/**
 * accessToken returns the bearer the shell holds in memory.
 * It does not read localStorage. Null means the shell has not signed in.
 */
export function accessToken(): string | null {
  return token;
}

/**
 * refreshToken returns the opaque refresh token held in memory.
 * Null means the page has nothing to exchange at /oauth/token.
 * It does not read localStorage or the query string.
 */
export function refreshToken(): string | null {
  return refresh;
}

/**
 * setAccessToken replaces the in-memory bearer.
 * next null forgets the bearer and leaves the refresh token in place.
 * The value is not written to localStorage.
 */
export function setAccessToken(next: string | null): void {
  token = next;
}

/**
 * rememberSession stores a new access token and refresh token in memory.
 * Neither value is written to localStorage or the query string.
 */
export function rememberSession(access: string, nextRefresh: string): void {
  token = access;
  refresh = nextRefresh;
}

/**
 * clearSession forgets the access token and the refresh token.
 * It does not remove the client id and secret in sessionStorage.
 */
export function clearSession(): void {
  token = null;
  refresh = null;
}

const CLIENT_ID_KEY = "vibecollector.client_id";
const CLIENT_SECRET_KEY = "vibecollector.client_secret";

/** ClientCreds is the OAuth client id and secret saved for this tab. */
export type ClientCreds = {
  clientId: string;
  clientSecret: string;
};

/**
 * clientCreds reads the OAuth client id and secret from sessionStorage.
 * Both values must be non-empty. Null means this tab has no saved pair.
 * The access token is not read. A storage failure returns null.
 */
export function clientCreds(): ClientCreds | null {
  if (typeof sessionStorage === "undefined") return null;
  try {
    const clientId = sessionStorage.getItem(CLIENT_ID_KEY) ?? "";
    const clientSecret = sessionStorage.getItem(CLIENT_SECRET_KEY) ?? "";
    if (clientId === "" || clientSecret === "") return null;
    return { clientId, clientSecret };
  } catch {
    return null;
  }
}

/**
 * saveClientCreds stores the OAuth client id and secret in sessionStorage.
 * clientId is the id the operator entered. clientSecret is the matching secret.
 * A later load in this tab reads them with clientCreds.
 * The access token is not written. It throws when sessionStorage rejects the write.
 */
export function saveClientCreds(clientId: string, clientSecret: string): void {
  sessionStorage.setItem(CLIENT_ID_KEY, clientId);
  sessionStorage.setItem(CLIENT_SECRET_KEY, clientSecret);
}

/**
 * hasAPIPrefix reports whether the OpenAPI document has been read.
 * True means apiPrefix can be called.
 */
export function hasAPIPrefix(): boolean {
  return prefix !== null;
}

/**
 * setAPIPrefix records the REST prefix from the OpenAPI document.
 * next is an absolute path with no trailing slash, such as /api/v1.
 */
export function setAPIPrefix(next: string): void {
  prefix = next;
}

/**
 * apiPrefix returns the REST prefix from the OpenAPI document.
 * It throws if that document has not been read yet.
 */
export function apiPrefix(): string {
  if (!prefix) {
    throw new Error("api prefix is not loaded");
  }
  return prefix;
}
