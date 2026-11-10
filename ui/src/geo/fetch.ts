import { apiSend, filterSearch } from "../api";
import type { Filters } from "../filters";

/** GeoCountry is one row of the geo response. Octet totals are decimal strings. */
export interface GeoCountry {
  iso_a2: string;
  iso_num: string;
  octets: string;
  packets: string;
  flows: string;
}

/** GeoPath is one directed aggregate. kind is country, city, or coord. */
export interface GeoPath {
  src: GeoPlace;
  dst: GeoPlace;
  octets: string;
  packets: string;
  flows: string;
}

/** GeoPlace is one end of a path. kind is country, city, or coord. */
export interface GeoPlace {
  kind: "country" | "city" | "coord";
  iso_a2: string;
  region?: string;
  city?: string;
  lat?: number;
  lon?: number;
}

/**
 * GeoResponse is the body of GET /api/v1/geo.
 * source is rollup or flows. bytes_are is endpoint_touch.
 * paths has at most path_cap entries. other_octets is the decimal string of
 * octets not in those paths. countries and paths are empty when the stub
 * provider has no geography. The same value feeds the flat map and the globe.
 */
export interface GeoResponse {
  source: "rollup" | "flows";
  start: string;
  end: string;
  tz: string;
  boundary_adjusted: boolean;
  bytes_are: "endpoint_touch";
  approximate: boolean;
  countries: GeoCountry[];
  paths: GeoPath[];
  path_cap: number;
  paths_omitted: number;
  other_octets: string;
}

/**
 * fetchGeo loads GET /api/v1/geo for filters.
 * It sends every set field. It does not drop a filter the route cannot apply.
 * The promise resolves to the response body.
 * It rejects with FilterOutsideRaw when the status is 400 and error is
 * filter_outside_raw. That error carries raw_available_from.
 * It rejects with QueryTimeout when the status is 503 and error is query_timeout.
 * It sends Authorization: Bearer with the access token the shell holds in
 * memory. It does not read a token from localStorage or put one in the
 * query string. It rejects when the status is 401.
 */
export function fetchGeo(filters: Filters): Promise<GeoResponse> {
  return getJSON<GeoResponse>("/geo", { filters });
}

/**
 * FilterOutsideRaw is the 400 filter_outside_raw rejection.
 * rawAvailableFrom is the RFC 3339 raw-retention floor from the body.
 */
export class FilterOutsideRaw extends Error {
  rawAvailableFrom: string;
  constructor(rawAvailableFrom: string) {
    super("filter_outside_raw");
    this.name = "FilterOutsideRaw";
    this.rawAvailableFrom = rawAvailableFrom;
  }
}

/**
 * QueryTimeout is the 503 query_timeout rejection.
 * The response was not a partial body.
 */
export class QueryTimeout extends Error {
  constructor() {
    super("query_timeout");
    this.name = "QueryTimeout";
  }
}

/**
 * getJSON loads one REST route for filters.
 * route is the path after the prefix, such as /flows.
 * filters, when set, are sent in full. extra adds route parameters such as limit.
 * fresh bypasses the hot-query cache. The result is the parsed body.
 * It rejects with FilterOutsideRaw, QueryTimeout, or Unauthorized.
 * Decimal strings and integers above 2^53 stay strings.
 */
export async function getJSON<T>(route: string, opts?: {
  filters?: Filters;
  extra?: Record<string, string | undefined>;
  fresh?: boolean;
}): Promise<T> {
  const query = new URLSearchParams();
  if (opts?.filters) {
    filterSearch(opts.filters).forEach((value, key) => {
      query.set(key, value);
    });
  }
  if (opts?.extra) {
    for (const [key, value] of Object.entries(opts.extra)) {
      if (value !== undefined && value !== "") query.set(key, value);
    }
  }
  const { status, body } = await apiSend(route, { query, fresh: opts?.fresh });
  if (status === 400 && isRecord(body) && body.error === "filter_outside_raw") {
    const from = body.raw_available_from;
    throw new FilterOutsideRaw(typeof from === "string" ? from : "");
  }
  if (status === 503 && isRecord(body) && body.error === "query_timeout") {
    throw new QueryTimeout();
  }
  if (status !== 200) {
    const msg = isRecord(body) && typeof body.error === "string" ? body.error : "request failed";
    throw new Error(msg);
  }
  return body as T;
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null;
}
