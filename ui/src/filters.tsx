import { createContext, useContext, useState, type Context, type ReactElement, type ReactNode } from "react";
import { peekReturnSearch } from "./auth";

/** Active operator filters. Times are RFC 3339 UTC. Unset filters are omitted. */
export interface Filters {
  start: string;
  end: string;
  tz: string;
  preset: "15m" | "1h" | "6h" | "24h" | "day" | "custom";
  src?: string;
  dst?: string;
  port?: string;
  src_port?: string;
  dst_port?: string;
  proto?: string;
  exporter?: string;
  country?: string;
  asn?: string;
  reputation?: string;
  sampled?: "true" | "false";
}

/**
 * calendarRange returns the half-open UTC day that contains the civil day.
 * day is YYYY-MM-DD. tz is an IANA name. An empty tz means UTC.
 * A repeated local time returns the earlier instant. A skipped local time
 * returns the next valid instant and sets boundaryAdjusted.
 * The instants match decode.CalendarDay, including America/New_York
 * 2026-03-08 00:00:00Z-offset, 2026-11-01 00:00:00, and skipped 02:30.
 * The function throws RangeError when day or tz cannot be resolved.
 */
export function calendarRange(day: string, tz: string): {
  start: string;
  end: string;
  boundaryAdjusted: boolean;
} {
  const parsed = parseDay(day);
  const zone = normalizeZone(tz);
  const start = resolve(parsed.y, parsed.m, parsed.d, 0, 0, 0, zone);
  const next = nextDay(parsed.y, parsed.m, parsed.d);
  const end = resolve(next.y, next.m, next.d, 0, 0, 0, zone);
  return {
    start: rfc(start.ms),
    end: rfc(end.ms),
    boundaryAdjusted: start.adjusted || end.adjusted,
  };
}

/**
 * civilInstant maps one civil time in tz to a UTC instant.
 * civil is YYYY-MM-DDTHH:mm:ss or YYYY-MM-DDTHH:mm. tz is an IANA name.
 * An empty tz means UTC. The fold and gap rule matches calendarRange.
 * utc is RFC 3339. boundaryAdjusted is true when the civil time was skipped.
 * It throws RangeError when civil or tz cannot be resolved.
 */
export function civilInstant(civil: string, tz: string): { utc: string; boundaryAdjusted: boolean } {
  const match = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2}))?$/.exec(civil);
  if (!match) throw new RangeError("bad civil time");
  const y = Number(match[1]);
  const m = Number(match[2]);
  const d = Number(match[3]);
  const h = Number(match[4]);
  const mi = Number(match[5]);
  const s = match[6] ? Number(match[6]) : 0;
  if (h > 23 || mi > 59 || s > 59) throw new RangeError("bad civil time");
  assertDay(y, m, d);
  const zone = normalizeZone(tz);
  const hit = resolve(y, m, d, h, mi, s, zone);
  return { utc: rfc(hit.ms), boundaryAdjusted: hit.adjusted };
}

/**
 * formatInZone renders an RFC 3339 UTC instant as a civil time in tz.
 * tz is an IANA name. An empty tz means UTC.
 * The result is YYYY-MM-DD HH:mm:ss in that zone.
 * It throws RangeError when utc or tz cannot be resolved.
 */
export function formatInZone(utc: string, tz: string): string {
  const ms = Date.parse(utc);
  if (Number.isNaN(ms)) throw new RangeError("bad utc");
  const zone = normalizeZone(tz);
  const w = wall(ms, zone);
  return `${pad(w.y, 4)}-${pad(w.m)}-${pad(w.d)} ${pad(w.h)}:${pad(w.mi)}:${pad(w.s)}`;
}

/**
 * knownZone reports whether tz is an IANA name Intl can resolve.
 * An empty string is UTC and returns true. The function does not throw.
 */
export function knownZone(tz: string): boolean {
  if (tz === "") return true;
  try {
    formatter(tz);
    return true;
  } catch {
    return false;
  }
}

/** FilterContext holds the one filter set every view reads. */
export const FilterContext: Context<Filters> = createContext<Filters>({
  start: "",
  end: "",
  tz: "UTC",
  preset: "1h",
});

const Setter = createContext<((next: Filters) => void) | null>(null);

/**
 * useFilters returns the shared filter set and the setter.
 * The setter replaces the whole set. Views do not delete keys they cannot apply.
 * Outside FilterContext the function throws.
 */
export function useFilters(): {
  filters: Filters;
  setFilters: (next: Filters) => void;
} {
  const filters = useContext(FilterContext);
  const setFilters = useContext(Setter);
  if (setFilters === null) {
    throw new Error("useFilters called outside FilterContext");
  }
  return { filters, setFilters };
}

/**
 * FilterProvider holds the one filter set every view reads.
 * children are the shell and its routes.
 * The initial set is the shared link's calendar day, or the last hour.
 */
export function FilterProvider({ children }: { children: ReactNode }): ReactElement {
  const [filters, setFilters] = useState(loadInitial);
  return (
    <FilterContext.Provider value={filters}>
      <Setter.Provider value={setFilters}>{children}</Setter.Provider>
    </FilterContext.Provider>
  );
}

const RELATIVE_MS = {
  "15m": 15 * 60_000,
  "1h": 3_600_000,
  "6h": 6 * 3_600_000,
  "24h": 24 * 3_600_000,
} as const;

/**
 * relativeWindow returns an absolute [start, end) ending now.
 * preset is 15m, 1h, 6h, or 24h. The window does not keep moving.
 */
export function relativeWindow(preset: keyof typeof RELATIVE_MS): { start: string; end: string } {
  const end = Date.now();
  return { start: rfc(end - RELATIVE_MS[preset]), end: rfc(end) };
}

function loadInitial(): Filters {
  const stored = storedTZ();
  const q = new URLSearchParams(peekReturnSearch());
  const linkTZ = q.get("tz");
  const zone = linkTZ && knownZone(linkTZ) ? linkTZ : stored;
  if (linkTZ && knownZone(linkTZ)) {
    try {
      localStorage.setItem(TZ_KEY, linkTZ);
    } catch {
      /* private mode */
    }
  }
  const day = q.get("day");
  if (day) {
    try {
      const range = calendarRange(day, zone);
      return { start: range.start, end: range.end, tz: zone, preset: "day" };
    } catch {
      /* the shared link was not a civil day */
    }
  }
  const window = relativeWindow("1h");
  return { ...window, tz: zone, preset: "1h" };
}

const TZ_KEY = "vibecollector.tz";

function storedTZ(): string {
  try {
    if (typeof localStorage === "undefined") return "UTC";
    const value = localStorage.getItem(TZ_KEY);
    if (value && knownZone(value)) return value;
  } catch {
    /* unavailable */
  }
  return "UTC";
}

interface Wall {
  y: number;
  m: number;
  d: number;
  h: number;
  mi: number;
  s: number;
}

const formatters = new Map<string, Intl.DateTimeFormat>();

function formatter(tz: string): Intl.DateTimeFormat {
  let existing = formatters.get(tz);
  if (!existing) {
    existing = new Intl.DateTimeFormat("en-US", {
      timeZone: tz,
      hourCycle: "h23",
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
    formatters.set(tz, existing);
  }
  return existing;
}

function wall(utcMs: number, tz: string): Wall {
  const map: Record<string, string> = {};
  for (const part of formatter(tz).formatToParts(new Date(utcMs))) {
    if (part.type !== "literal") map[part.type] = part.value;
  }
  let h = Number(map.hour);
  if (h === 24) h = 0;
  return {
    y: Number(map.year),
    m: Number(map.month),
    d: Number(map.day),
    h,
    mi: Number(map.minute),
    s: Number(map.second),
  };
}

function offsetSeconds(utcMs: number, tz: string): number {
  const w = wall(utcMs, tz);
  const asUTC = Date.UTC(w.y, w.m - 1, w.d, w.h, w.mi, w.s);
  return Math.round((asUTC - utcMs) / 1000);
}

function wallEqual(utcMs: number, tz: string, y: number, m: number, d: number, h: number, mi: number, s: number): boolean {
  const w = wall(utcMs, tz);
  return w.y === y && w.m === m && w.d === d && w.h === h && w.mi === mi && w.s === s;
}

// Walk back one minute at a time. A fixed one-hour subtract returns the
// later instant when the overlap is shorter than an hour.
function fold(y: number, m: number, d: number, h: number, mi: number, s: number, tz: string): number | null {
  const guess = Date.UTC(y, m - 1, d, h, mi, s);
  const off1 = offsetSeconds(guess, tz);
  const step = guess - off1 * 1000;
  const off2 = offsetSeconds(step, tz);
  const result = guess - off2 * 1000;
  if (!wallEqual(result, tz, y, m, d, h, mi, s)) return null;
  let earliest = result;
  for (let i = 1; i <= 180; i++) {
    const prev = result - i * 60_000;
    if (wallEqual(prev, tz, y, m, d, h, mi, s)) earliest = prev;
  }
  return earliest;
}

function resolve(y: number, m: number, d: number, h: number, mi: number, s: number, tz: string): { ms: number; adjusted: boolean } {
  const hit = fold(y, m, d, h, mi, s, tz);
  if (hit !== null) return { ms: hit, adjusted: false };
  const cursor = Date.UTC(y, m - 1, d, h, mi, s);
  for (let i = 1; i <= 180; i++) {
    const n = new Date(cursor + i * 60_000);
    const got = fold(n.getUTCFullYear(), n.getUTCMonth() + 1, n.getUTCDate(), n.getUTCHours(), n.getUTCMinutes(), n.getUTCSeconds(), tz);
    if (got !== null) return { ms: got, adjusted: true };
  }
  throw new RangeError("skipped civil time");
}

function normalizeZone(tz: string): string {
  const zone = tz === "" ? "UTC" : tz;
  try {
    formatter(zone);
  } catch {
    throw new RangeError(zone);
  }
  return zone;
}

function parseDay(day: string): { y: number; m: number; d: number } {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(day);
  if (!match) throw new RangeError("bad day");
  const y = Number(match[1]);
  const m = Number(match[2]);
  const d = Number(match[3]);
  assertDay(y, m, d);
  return { y, m, d };
}

function assertDay(y: number, m: number, d: number): void {
  const t = new Date(Date.UTC(y, m - 1, d));
  if (t.getUTCFullYear() !== y || t.getUTCMonth() !== m - 1 || t.getUTCDate() !== d) {
    throw new RangeError("bad day");
  }
}

function nextDay(y: number, m: number, d: number): { y: number; m: number; d: number } {
  const t = new Date(Date.UTC(y, m - 1, d));
  t.setUTCDate(t.getUTCDate() + 1);
  return { y: t.getUTCFullYear(), m: t.getUTCMonth() + 1, d: t.getUTCDate() };
}

function rfc(ms: number): string {
  return new Date(ms).toISOString().replace(/\.\d{3}Z$/, "Z");
}

function pad(n: number, width = 2): string {
  return String(n).padStart(width, "0");
}
