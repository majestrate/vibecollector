import { startLogin } from "./auth";
import type { Filters } from "./filters";
import { accessToken, apiPrefix, setAccessToken } from "./session";

const DATA_ROUTES = ["health", "stats", "exporters", "flows", "timeseries", "talkers", "asns", "reputation", "geo"] as const;

const FILTER_KEYS = ["src", "dst", "port", "src_port", "dst_port", "proto", "exporter", "country", "asn", "reputation", "sampled"] as const;

/**
 * Unauthorized is a rejected REST call with status 401 after the login redirect has started.
 * The previous body is not data.
 */
export class Unauthorized extends Error {
  constructor() {
    super("unauthorized");
    this.name = "Unauthorized";
  }
}

/**
 * LoginFailed is a 401 whose login redirect did not start.
 * message is why. The shell shows it with a Sign in action.
 */
export class LoginFailed extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LoginFailed";
  }
}

/**
 * prefixFromSpec reads the configured REST prefix from the nine data paths.
 * spec is the served OpenAPI document. OAuth and /openapi.json paths are ignored.
 * The result is the absolute prefix with no trailing slash.
 * It throws when those nine paths are not present under one prefix.
 */
export function prefixFromSpec(spec: unknown): string {
  if (!isRecord(spec) || !isRecord(spec.paths)) {
    throw new Error("openapi: paths");
  }
  const keys = Object.keys(spec.paths);
  for (const key of keys) {
    if (!key.endsWith("/health")) continue;
    const prefix = key.slice(0, -"/health".length);
    if (!prefix.startsWith("/") || prefix.endsWith("/")) continue;
    if (DATA_ROUTES.every((name) => keys.includes(`${prefix}/${name}`))) {
      return prefix;
    }
  }
  throw new Error("openapi: prefix");
}

/**
 * parseJSON parses an API body without turning an integer above 2^53 into a number.
 * text is the raw JSON. Decimal strings stay strings.
 * An integer outside Number.MAX_SAFE_INTEGER is returned as a decimal string.
 * It throws SyntaxError when text is not JSON.
 */
export function parseJSON(text: string): unknown {
  let out = "";
  for (let i = 0; i < text.length; ) {
    const c = text[i] ?? "";
    if (c === '"') {
      const start = i;
      i++;
      while (i < text.length) {
        if (text[i] === "\\") {
          i += 2;
          continue;
        }
        if (text[i] === '"') {
          i++;
          break;
        }
        i++;
      }
      out += text.slice(start, i);
      continue;
    }
    if (c === "-" || (c >= "0" && c <= "9")) {
      const start = i;
      if (text[i] === "-") i++;
      const digitsAt = i;
      while (i < text.length && text[i]! >= "0" && text[i]! <= "9") i++;
      const digitCount = i - digitsAt;
      let integer = digitCount > 0;
      if (text[i] === ".") {
        integer = false;
        i++;
        while (i < text.length && text[i]! >= "0" && text[i]! <= "9") i++;
      }
      if (text[i] === "e" || text[i] === "E") {
        integer = false;
        i++;
        if (text[i] === "+" || text[i] === "-") i++;
        while (i < text.length && text[i]! >= "0" && text[i]! <= "9") i++;
      }
      const token = text.slice(start, i);
      if (integer && unsafeInteger(token)) {
        out += JSON.stringify(token);
      } else {
        out += token;
      }
      continue;
    }
    out += c;
    i++;
  }
  return JSON.parse(out);
}

/**
 * filterSearch encodes the shared filter set.
 * Unset fields are omitted. preset is not a query parameter.
 * The token is not included.
 */
export function filterSearch(filters: Filters): URLSearchParams {
  const q = new URLSearchParams();
  q.set("start", filters.start);
  q.set("end", filters.end);
  q.set("tz", filters.tz);
  for (const key of FILTER_KEYS) {
    const value = filters[key];
    if (value !== undefined && value !== "") q.set(key, value);
  }
  return q;
}

/**
 * apiSend performs one GET under the configured REST prefix.
 * route is the path after the prefix, such as /flows.
 * query is the parameter set. fresh sends Cache-Control: no-store.
 * The result is the status and the parsed body.
 * It rejects with Unauthorized on 401 after the login redirect starts.
 * It rejects with LoginFailed when that redirect cannot start.
 * The bearer comes from memory. It does not read localStorage or the query string.
 */
export async function apiSend(route: string, opts?: { query?: URLSearchParams; fresh?: boolean }): Promise<{ status: number; body: unknown }> {
  const query = opts?.query;
  const qs = query && [...query.keys()].length > 0 ? `?${query.toString()}` : "";
  const url = apiPrefix() + route + qs;
  const headers = new Headers({ Accept: "application/json" });
  const token = accessToken();
  if (token) headers.set("Authorization", "Bearer " + token);
  if (opts?.fresh) headers.set("Cache-Control", "no-store");
  const res = await fetch(url, { headers, redirect: "error" });
  if (res.status === 401) {
    await res.body?.cancel();
    setAccessToken(null);
    try {
      await startLogin();
    } catch (err) {
      const message = err instanceof Error ? err.message : "Sign-in failed.";
      throw new LoginFailed(message);
    }
    throw new Unauthorized();
  }
  const text = await res.text();
  return { status: res.status, body: text ? parseJSON(text) : null };
}

function unsafeInteger(token: string): boolean {
  const digits = token.startsWith("-") ? token.slice(1) : token;
  if (digits.length < 16) return false;
  if (digits.length > 16) return true;
  return digits > "9007199254740991";
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null;
}
