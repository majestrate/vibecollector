import { afterEach, expect, test, vi } from "vitest";
import {
  lookupProtocolName,
  lookupServiceName,
  protocolText,
  resetNetdbCache,
  resolveFlowLabels,
} from "./netdb";
import { setAccessToken, setAPIPrefix } from "./session";

afterEach(() => {
  resetNetdbCache();
  setAccessToken(null);
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

test("protocol cell keeps the number when a name is absent", () => {
  expect(protocolText(6, "tcp")).toBe("tcp (6)");
  expect(protocolText(6, undefined)).toBe("6");
  expect(protocolText(null, "tcp")).toBe("");
});

test("flow labels use the protocol and service lookup API once per value", async () => {
  setAccessToken("mem-token");
  setAPIPrefix("/api/v1");
  const fetchMock = vi.fn(async (url: string, _init?: RequestInit) => {
    const u = new URL(url, "http://collector.example");
    if (u.pathname === "/api/v1/protocol") {
      const number = u.searchParams.get("number");
      if (number === "6") return json({ name: "tcp", number: 6, aliases: ["TCP"] });
      if (number === "254") return json({ name: "vc-extra", number: 254, aliases: ["VX"] });
      if (number === "1") return json({ name: "icmp", number: 1, aliases: [] });
      return json({ error: "not_found" }, 404);
    }
    if (u.pathname === "/api/v1/service") {
      const port = u.searchParams.get("port");
      const protocol = u.searchParams.get("protocol");
      if (port === "80" && protocol === "tcp") return json({ name: "http", port: 80, protocol: "tcp", aliases: ["www"] });
      if (port === "443" && protocol === "tcp") return json({ name: "https", port: 443, protocol: "tcp", aliases: [] });
      if (port === "59999" && protocol === "vc-extra") {
        return json({ name: "vc-echo", port: 59999, protocol: "vc-extra", aliases: [] });
      }
      return json({ error: "not_found" }, 404);
    }
    return json({ error: "not_found" }, 404);
  });
  vi.stubGlobal("fetch", fetchMock);

  const labels = await resolveFlowLabels([
    { proto: 6, src_port: 80, dst_port: 443 },
    { proto: 6, src_port: 80, dst_port: 443 },
    { proto: 254, src_port: 59999, dst_port: 9 },
    { proto: 1, src_port: 0, dst_port: 0x0800 },
    { proto: 17, src_port: 53, dst_port: 53 },
  ]);

  expect(labels.protocols.get(6)).toBe("tcp");
  expect(labels.protocols.get(254)).toBe("vc-extra");
  expect(labels.protocols.get(1)).toBe("icmp");
  expect(labels.protocols.has(17)).toBe(false);
  expect(labels.services.get("80\ntcp")).toBe("http");
  expect(labels.services.get("443\ntcp")).toBe("https");
  expect(labels.services.get("59999\nvc-extra")).toBe("vc-echo");
  expect(labels.services.has("9\nvc-extra")).toBe(false);
  expect(labels.services.has("2048\nicmp")).toBe(false);
  expect(labels.services.has("53\nudp")).toBe(false);

  const urls = fetchMock.mock.calls.map((call) => String(call[0]));
  expect(urls.filter((url) => url.includes("/protocol?"))).toHaveLength(4);
  expect(urls.filter((url) => url.includes("/service?"))).toHaveLength(4);
  expect(urls.some((url) => url.includes("protocol=6"))).toBe(false);
  expect(urls.some((url) => url.includes("start="))).toBe(false);
  for (const call of fetchMock.mock.calls) {
    expect(new Headers(call[1]?.headers).get("Authorization")).toBe("Bearer mem-token");
  }

  const again = await resolveFlowLabels([{ proto: 6, src_port: 80, dst_port: 443 }]);
  expect(again.protocols.get(6)).toBe("tcp");
  expect(again.services.get("80\ntcp")).toBe("http");
  expect(fetchMock).toHaveBeenCalledTimes(urls.length);
});

test("a failed lookup is not cached and a missing name is", async () => {
  setAccessToken("mem-token");
  setAPIPrefix("/api/v1");
  const fetchMock = vi.fn<typeof fetch>();
  fetchMock.mockRejectedValueOnce(new Error("offline"));
  vi.stubGlobal("fetch", fetchMock);
  expect(await lookupProtocolName(6)).toBeNull();
  fetchMock.mockResolvedValueOnce(json({ name: "tcp", number: 6, aliases: [] }));
  expect(await lookupProtocolName(6)).toBe("tcp");
  expect(await lookupProtocolName(6)).toBe("tcp");
  expect(fetchMock).toHaveBeenCalledTimes(2);

  fetchMock.mockResolvedValueOnce(json({ error: "not_found" }, 404));
  expect(await lookupServiceName(9, "tcp")).toBeNull();
  expect(await lookupServiceName(9, "tcp")).toBeNull();
  expect(fetchMock).toHaveBeenCalledTimes(3);
});

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}
