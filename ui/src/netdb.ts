import { useEffect, useRef, useState } from "react";
import { apiSend } from "./api";
import { useRefresh } from "./query";

/**
 * FlowPorts is the protocol number and ports on one flow row.
 * proto is the IP protocol number. srcPort and dstPort are the stored ports.
 * Protocols 1 and 58 store ICMP type and code in the destination port.
 */
export interface FlowPorts {
  proto?: number | null;
  src_port?: number | null;
  dst_port?: number | null;
}

/**
 * FlowLabels is the names resolved for one page of flows.
 * protocols maps a protocol number to its official name.
 * services maps serviceKey(port, protocol name) to the official service name.
 * A missing key means the table has no entry, or the lookup has not been stored.
 */
export interface FlowLabels {
  protocols: ReadonlyMap<number, string>;
  services: ReadonlyMap<string, string>;
}

const EMPTY_LABELS: FlowLabels = { protocols: new Map(), services: new Map() };

let epoch = 0;
const protoDone = new Map<number, string | null>();
const protoFlight = new Map<number, Promise<string | null>>();
const svcDone = new Map<string, string | null>();
const svcFlight = new Map<string, Promise<string | null>>();

/**
 * resetNetdbCache drops cached protocol and service names.
 * The next lookup reads the API again. In-flight results from before the
 * reset are not stored.
 */
export function resetNetdbCache(): void {
  epoch += 1;
  protoDone.clear();
  protoFlight.clear();
  svcDone.clear();
  svcFlight.clear();
}

/**
 * serviceKey identifies one service lookup.
 * port is the stored port. protocol is the official protocol name.
 * The result is the map key used in FlowLabels.services.
 */
export function serviceKey(port: number, protocol: string): string {
  return `${port}\n${protocol}`;
}

/**
 * protocolText is the protocol cell.
 * number is the IP protocol number. name is the official name, when known.
 * The result is the name and number, or the number alone when name is absent.
 */
export function protocolText(number: number | null | undefined, name: string | undefined): string {
  if (number === null || number === undefined) return "";
  if (!name) return String(number);
  return `${name} (${number})`;
}

/**
 * lookupProtocolName reads GET /protocol?number=.
 * number is the IP protocol number. The result is the official name.
 * A missing entry is null. A failed request is null and is not cached.
 */
export function lookupProtocolName(number: number): Promise<string | null> {
  if (!Number.isInteger(number)) return Promise.resolve(null);
  const hit = protoDone.get(number);
  if (hit !== undefined) return Promise.resolve(hit);
  const flight = protoFlight.get(number);
  if (flight) return flight;
  const started = epoch;
  const pending = fetchName("/protocol", { number: String(number) }).then(
    (name) => {
      protoFlight.delete(number);
      if (started === epoch) protoDone.set(number, name);
      return name;
    },
    () => {
      protoFlight.delete(number);
      return null;
    },
  );
  protoFlight.set(number, pending);
  return pending;
}

/**
 * lookupServiceName reads GET /service?port=&protocol=.
 * port is the stored port. protocol is the official protocol name.
 * The result is the official service name. A missing entry is null.
 * A failed request is null and is not cached.
 */
export function lookupServiceName(port: number, protocol: string): Promise<string | null> {
  if (!Number.isInteger(port) || port < 0 || port > 65535 || protocol === "") return Promise.resolve(null);
  const key = serviceKey(port, protocol);
  const hit = svcDone.get(key);
  if (hit !== undefined) return Promise.resolve(hit);
  const flight = svcFlight.get(key);
  if (flight) return flight;
  const started = epoch;
  const pending = fetchName("/service", { port: String(port), protocol }).then(
    (name) => {
      svcFlight.delete(key);
      if (started === epoch) svcDone.set(key, name);
      return name;
    },
    () => {
      svcFlight.delete(key);
      return null;
    },
  );
  svcFlight.set(key, pending);
  return pending;
}

/**
 * resolveFlowLabels loads the protocol and service names for flows.
 * flows are the rows on the current page. Each protocol number is requested once.
 * Each port is requested with that protocol's official name.
 * Protocols 1 and 58 do not request a service, because the destination port
 * is an ICMP type and code. The result contains only names the API returned.
 */
export async function resolveFlowLabels(flows: readonly FlowPorts[]): Promise<FlowLabels> {
  const numbers = new Set<number>();
  for (const flow of flows) {
    if (typeof flow.proto === "number" && Number.isInteger(flow.proto)) numbers.add(flow.proto);
  }
  const protocols = new Map<number, string>();
  await Promise.all(
    [...numbers].map(async (number) => {
      const name = await lookupProtocolName(number);
      if (name) protocols.set(number, name);
    }),
  );
  const services = new Map<string, string>();
  const jobs: Promise<void>[] = [];
  const seen = new Set<string>();
  for (const flow of flows) {
    if (typeof flow.proto !== "number" || flow.proto === 1 || flow.proto === 58) continue;
    const protocol = protocols.get(flow.proto);
    if (!protocol) continue;
    for (const port of [flow.src_port, flow.dst_port]) {
      if (typeof port !== "number" || !Number.isInteger(port)) continue;
      const key = serviceKey(port, protocol);
      if (seen.has(key)) continue;
      seen.add(key);
      jobs.push(
        lookupServiceName(port, protocol).then((name) => {
          if (name) services.set(key, name);
        }),
      );
    }
  }
  await Promise.all(jobs);
  return { protocols, services };
}

/**
 * serviceLabel reads one resolved service name.
 * labels is the page result. port is the stored port.
 * protocol is the official protocol name for that flow.
 * The result is undefined when that pair was not resolved.
 */
export function serviceLabel(
  labels: FlowLabels,
  port: number | null | undefined,
  protocol: string | undefined,
): string | undefined {
  if (typeof port !== "number" || !protocol) return undefined;
  return labels.services.get(serviceKey(port, protocol));
}

/**
 * useFlowLabels resolves protocol and service names for the current flow page.
 * flows is the page returned by GET /flows. A refresh clears the cache and
 * reads the API again. The result updates when those reads finish.
 */
export function useFlowLabels(flows: readonly FlowPorts[]): FlowLabels {
  const rev = useRefresh();
  const revRef = useRef<number | null>(null);
  const [labels, setLabels] = useState<FlowLabels>(EMPTY_LABELS);
  useEffect(() => {
    if (revRef.current !== null && revRef.current !== rev) resetNetdbCache();
    revRef.current = rev;
    let cancel = false;
    void resolveFlowLabels(flows).then((next) => {
      if (!cancel) setLabels(next);
    });
    return () => {
      cancel = true;
    };
  }, [rev, flows]);
  return labels;
}

async function fetchName(route: string, params: Record<string, string>): Promise<string | null> {
  const query = new URLSearchParams(params);
  const { status, body } = await apiSend(route, { query });
  if (status === 404) return null;
  if (status !== 200) throw new Error("netdb");
  if (typeof body !== "object" || body === null || !("name" in body)) throw new Error("netdb");
  const name = (body as { name?: unknown }).name;
  if (typeof name !== "string" || name === "") throw new Error("netdb");
  return name;
}
