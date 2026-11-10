/** In-memory bearer. Never written to localStorage or the query string. */
let token: string | null = null;

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
 * setAccessToken replaces the in-memory bearer.
 * next null forgets it. The value is not written to localStorage.
 */
export function setAccessToken(next: string | null): void {
  token = next;
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
