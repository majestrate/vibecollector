/** In-memory bearer. Never written to localStorage or the query string. */
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
 * It does not touch localStorage.
 */
export function clearSession(): void {
  token = null;
  refresh = null;
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
