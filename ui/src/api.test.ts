import { createHash } from "node:crypto";
import { afterEach, expect, test, vi } from "vitest";
import { parseJSON, prefixFromSpec } from "./api";
import { s256Challenge } from "./auth";
import type { Filters } from "./filters";
import { fetchGeo, FilterOutsideRaw, QueryTimeout } from "./geo/fetch";
import { setAccessToken, setAPIPrefix } from "./session";

const filters: Filters = {
  start: "2026-11-09T00:00:00Z",
  end: "2026-11-09T01:00:00Z",
  tz: "America/New_York",
  preset: "custom",
  src: "203.0.113.5",
  dst: "198.51.100.9",
  port: "53",
  src_port: "1",
  dst_port: "2",
  proto: "6",
  exporter: "192.0.2.9",
  country: "US",
  asn: "64496",
  reputation: "malware",
  sampled: "true",
};

afterEach(() => {
  setAccessToken(null);
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

test("pkce challenge is S256 of the verifier", async () => {
  const verifier = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
  const want = createHash("sha256").update(verifier).digest("base64url");
  expect(await s256Challenge(verifier)).toBe(want);
});

test("data fetch sends the bearer and does not read localStorage", async () => {
  setAccessToken("mem-token");
  setAPIPrefix("/collector/v1");
  const getItem = vi.fn(() => null);
  vi.stubGlobal("localStorage", {
    getItem,
    setItem: vi.fn(),
    removeItem: vi.fn(),
    clear: vi.fn(),
    key: vi.fn(),
    length: 0,
  });
  const body = {
    source: "rollup",
    start: filters.start,
    end: filters.end,
    tz: "UTC",
    boundary_adjusted: false,
    bytes_are: "endpoint_touch",
    approximate: false,
    countries: [{ iso_a2: "US", iso_num: "840", octets: "9007199254740993", packets: "10", flows: "2" }],
    paths: [],
    path_cap: 100,
    paths_omitted: 9007199254740993,
    other_octets: "0",
  };
  const raw = JSON.stringify({ ...body, paths_omitted: 0 }).replace('"paths_omitted":0', '"paths_omitted":9007199254740993');
  const fetchMock = vi.fn(async () => new Response(raw, { status: 200, headers: { "Content-Type": "application/json" } }));
  vi.stubGlobal("fetch", fetchMock);
  const got = await fetchGeo(filters);
  expect(fetchMock).toHaveBeenCalledTimes(1);
  const call = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
  const url = String(call[0]);
  const init = call[1];
  expect(url.startsWith("/collector/v1/geo?")).toBe(true);
  for (const [key, value] of Object.entries(filters)) {
    if (key === "preset") continue;
    expect(url).toContain(`${encodeURIComponent(key)}=${encodeURIComponent(String(value))}`);
  }
  expect(url).not.toContain("mem-token");
  expect(url).not.toContain("access_token");
  const headers = new Headers(init.headers);
  expect(headers.get("Authorization")).toBe("Bearer mem-token");
  expect(getItem).not.toHaveBeenCalled();
  expect(got.countries[0]?.octets).toBe("9007199254740993");
  expect(typeof got.countries[0]?.octets).toBe("string");
  const omitted: unknown = got.paths_omitted;
  expect(omitted).toBe("9007199254740993");
  expect(typeof omitted).toBe("string");
});

test("filter_outside_raw and query_timeout and 401 reject", async () => {
  setAccessToken("mem-token");
  setAPIPrefix("/api/v1");
  const fetchMock = vi.fn();
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockResolvedValueOnce(Response.json({ error: "filter_outside_raw", raw_available_from: "2026-11-09T06:00:00Z" }, { status: 400 }));
  await expect(fetchGeo(filters)).rejects.toBeInstanceOf(FilterOutsideRaw);
  fetchMock.mockResolvedValueOnce(Response.json({ error: "filter_outside_raw", raw_available_from: "2026-11-09T06:00:00Z" }, { status: 400 }));
  try {
    await fetchGeo(filters);
  } catch (err) {
    expect(err).toBeInstanceOf(FilterOutsideRaw);
    expect((err as FilterOutsideRaw).rawAvailableFrom).toBe("2026-11-09T06:00:00Z");
  }
  fetchMock.mockResolvedValueOnce(Response.json({ error: "query_timeout" }, { status: 503 }));
  await expect(fetchGeo(filters)).rejects.toBeInstanceOf(QueryTimeout);
  fetchMock.mockResolvedValueOnce(Response.json({ error: "unauthorized" }, { status: 401 }));
  await expect(fetchGeo(filters)).rejects.toMatchObject({ name: "Unauthorized" });
});

test("prefix comes from the nine data paths", () => {
  const names = ["health", "stats", "exporters", "flows", "timeseries", "talkers", "asns", "reputation", "geo"];
  const paths: Record<string, unknown> = { "/oauth/authorize": {}, "/oauth/token": {} };
  for (const name of names) paths[`/collector/v1/${name}`] = {};
  expect(prefixFromSpec({ paths })).toBe("/collector/v1");
  const defaults: Record<string, unknown> = {};
  for (const name of names) defaults[`/api/v1/${name}`] = {};
  expect(prefixFromSpec({ paths: defaults })).toBe("/api/v1");
  expect(() => prefixFromSpec({ paths: { "/api/v1/health": {} } })).toThrow(/prefix/);
});

test("parseJSON keeps decimal strings and unsafe integers", () => {
  const parsed = parseJSON(
    '{"packets":"10","n":9007199254740993,"edge":9007199254740992,"safe":10,"max":9007199254740991,"neg":-9007199254740993,"s":"12345678901234567890"}',
  ) as {
    packets: string;
    n: string;
    edge: string;
    safe: number;
    max: number;
    neg: string;
    s: string;
  };
  expect(parsed.packets).toBe("10");
  expect(parsed.n).toBe("9007199254740993");
  expect(parsed.edge).toBe("9007199254740992");
  expect(parsed.safe).toBe(10);
  expect(parsed.max).toBe(9007199254740991);
  expect(parsed.neg).toBe("-9007199254740993");
  expect(parsed.s).toBe("12345678901234567890");
});
