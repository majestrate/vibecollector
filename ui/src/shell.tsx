import { useEffect, useState, type FormEvent, type ReactElement } from "react";
import { NavLink, Route, Routes } from "react-router-dom";
import { getJSON } from "./geo/fetch";
import {
  calendarRange,
  civilInstant,
  type Filters,
  formatInZone,
  knownZone,
  relativeWindow,
  useFilters,
} from "./filters";
import { asText, bumpQueries, QueryNotice, useRefresh } from "./query";
import { ASNView } from "./views/ASNView";
import { FlowsView } from "./views/FlowsView";
import { GlobeView } from "./views/GlobeView";
import { MapView } from "./views/MapView";
import { ReputationView } from "./views/ReputationView";
import { TalkersView } from "./views/TalkersView";
import { TrafficView } from "./views/TrafficView";

const TZ_KEY = "vibecollector.tz";

const FIELD_KEYS = ["src", "dst", "port", "src_port", "dst_port", "proto", "exporter", "country", "asn", "reputation"] as const;

const FIELD_LABELS: { key: (typeof FIELD_KEYS)[number]; label: string }[] = [
  { key: "src", label: "Source" },
  { key: "dst", label: "Destination" },
  { key: "port", label: "Port" },
  { key: "src_port", label: "Source port" },
  { key: "dst_port", label: "Destination port" },
  { key: "proto", label: "Protocol" },
  { key: "exporter", label: "Exporter" },
  { key: "country", label: "Country" },
  { key: "asn", label: "ASN" },
  { key: "reputation", label: "Reputation" },
];

type Draft = Record<(typeof FIELD_KEYS)[number], string> & { sampled: "" | "true" | "false" };

/**
 * Shell is the operator chrome: one filter set, the exporter strip, and the view routes.
 * It does not strip a filter a view cannot apply.
 */
export function Shell(): ReactElement {
  const { filters, setFilters } = useFilters();
  const [day, setDay] = useState(() =>
    filters.preset === "day" ? civilDay(filters.start, filters.tz) : civilDay(new Date().toISOString(), filters.tz),
  );
  const [adjusted, setAdjusted] = useState(() => initialAdjusted(filters));
  const [tzDraft, setTzDraft] = useState(filters.tz);
  const [tzError, setTzError] = useState("");
  const [rangeError, setRangeError] = useState("");
  const [draft, setDraft] = useState(() => draftFrom(filters));

  useEffect(() => {
    setTzDraft(filters.tz);
    setDraft(draftFrom(filters));
  }, [filters]);

  useEffect(() => {
    const url = new URL(window.location.href);
    url.searchParams.delete("code");
    url.searchParams.delete("state");
    if (filters.preset === "day") {
      url.searchParams.set("day", day);
      url.searchParams.set("tz", filters.tz);
    } else {
      url.searchParams.delete("day");
      url.searchParams.delete("tz");
    }
    const next = url.pathname + url.search + url.hash;
    const now = window.location.pathname + window.location.search + window.location.hash;
    if (next !== now) {
      // react-router keeps its history index on this state. null would drop it.
      const prior: unknown = window.history.state;
      window.history.replaceState(prior !== null && typeof prior === "object" ? { ...prior } : prior, "", next);
    }
  }, [filters, day]);

  function applyRelative(preset: "15m" | "1h" | "6h" | "24h"): void {
    const window = relativeWindow(preset);
    setAdjusted(false);
    setRangeError("");
    setFilters({ ...filters, ...window, preset });
  }

  function refresh(): void {
    if (filters.preset === "day") {
      try {
        const range = calendarRange(day, filters.tz);
        setAdjusted(range.boundaryAdjusted);
        setRangeError("");
        setFilters({ ...filters, start: range.start, end: range.end });
      } catch (err) {
        setRangeError(err instanceof Error ? err.message : "bad day");
      }
    } else if (filters.preset !== "custom") {
      applyRelative(filters.preset);
    }
    bumpQueries();
  }

  function commitTZ(next: string): void {
    const zone = next.trim();
    if (!knownZone(zone)) {
      setTzError("unknown time zone");
      return;
    }
    const tz = zone === "" ? "UTC" : zone;
    setTzError("");
    try {
      localStorage.setItem(TZ_KEY, tz);
    } catch {
      /* private mode */
    }
    if (filters.preset === "day") {
      try {
        const range = calendarRange(day, tz);
        setAdjusted(range.boundaryAdjusted);
        setFilters({ ...filters, tz, start: range.start, end: range.end });
      } catch (err) {
        setRangeError(err instanceof Error ? err.message : "bad day");
      }
      return;
    }
    setFilters({ ...filters, tz });
  }

  function onDay(value: string): void {
    if (!value) return;
    try {
      const range = calendarRange(value, filters.tz);
      setDay(value);
      setAdjusted(range.boundaryAdjusted);
      setRangeError("");
      setFilters({ ...filters, preset: "day", start: range.start, end: range.end });
    } catch (err) {
      setRangeError(err instanceof Error ? err.message : "bad day");
    }
  }

  function commitCustom(which: "start" | "end", value: string): void {
    if (!value) return;
    const civil = value.length === 16 ? `${value}:00` : value;
    try {
      const hit = civilInstant(civil, filters.tz);
      const start = which === "start" ? hit.utc : filters.start;
      const end = which === "end" ? hit.utc : filters.end;
      if (Date.parse(end) <= Date.parse(start)) {
        setRangeError("end must be after start");
        return;
      }
      setRangeError("");
      setAdjusted(hit.boundaryAdjusted);
      setFilters({ ...filters, preset: "custom", start, end });
    } catch {
      setRangeError("that civil time could not be resolved");
    }
  }

  const linkSearch = filters.preset === "day" ? `?${new URLSearchParams({ day, tz: filters.tz }).toString()}` : "";

  function apply(event: FormEvent): void {
    event.preventDefault();
    const next: Filters = { start: filters.start, end: filters.end, tz: filters.tz, preset: filters.preset };
    for (const key of FIELD_KEYS) {
      const value = draft[key].trim();
      if (value) next[key] = value;
    }
    if (draft.sampled === "true" || draft.sampled === "false") next.sampled = draft.sampled;
    setFilters(next);
  }

  function clearFilters(): void {
    setFilters({ start: filters.start, end: filters.end, tz: filters.tz, preset: filters.preset });
  }

  return (
    <>
      <header className="top">
        <strong>VibeCollector</strong>
        <nav>
          <NavLink to={`/flows${linkSearch}`}>Flows</NavLink>
          <NavLink to={`/traffic${linkSearch}`}>Traffic</NavLink>
          <NavLink to={`/talkers${linkSearch}`}>Talkers</NavLink>
          <NavLink to={`/asn${linkSearch}`}>ASN</NavLink>
          <NavLink to={`/reputation${linkSearch}`}>Reputation</NavLink>
          <NavLink to={`/map${linkSearch}`}>Map</NavLink>
          <NavLink to={`/globe${linkSearch}`}>Globe</NavLink>
        </nav>
      </header>
      <ExporterStrip />
      <div className="bar">
        <div className="row">
          <button type="button" className={filters.preset === "15m" ? "on" : ""} onClick={() => applyRelative("15m")}>
            Last 15 minutes
          </button>
          <button type="button" className={filters.preset === "1h" ? "on" : ""} onClick={() => applyRelative("1h")}>
            Last 1 hour
          </button>
          <button type="button" className={filters.preset === "6h" ? "on" : ""} onClick={() => applyRelative("6h")}>
            Last 6 hours
          </button>
          <button type="button" className={filters.preset === "24h" ? "on" : ""} onClick={() => applyRelative("24h")}>
            Last 24 hours
          </button>
          <button type="button" className={filters.preset === "day" ? "on" : ""} onClick={() => onDay(day)}>
            Calendar day
          </button>
          <button
            type="button"
            className={filters.preset === "custom" ? "on" : ""}
            onClick={() => {
              setAdjusted(false);
              setFilters({ ...filters, preset: "custom" });
            }}
          >
            Custom
          </button>
          <button type="button" onClick={refresh}>
            Refresh
          </button>
          <label>
            Timezone
            <input
              list="zones"
              value={tzDraft}
              onChange={(e) => setTzDraft(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter") commitTZ(tzDraft);
              }}
            />
          </label>
          <button type="button" onClick={() => commitTZ(tzDraft)}>
            Set zone
          </button>
          <datalist id="zones">
            <option value="UTC" />
            <option value="America/New_York" />
            <option value="America/Chicago" />
            <option value="America/Denver" />
            <option value="America/Los_Angeles" />
            <option value="Europe/London" />
            <option value="Europe/Berlin" />
            <option value="Asia/Tokyo" />
            <option value="Australia/Lord_Howe" />
          </datalist>
          <label>
            Day
            <input type="date" value={day} onChange={(e) => onDay(e.target.value)} />
          </label>
          {filters.preset === "custom" ? (
            <>
              <label>
                Start
                <input type="datetime-local" step={1} value={inputValue(filters.start, filters.tz)} onChange={(e) => commitCustom("start", e.target.value)} />
              </label>
              <label>
                End
                <input type="datetime-local" step={1} value={inputValue(filters.end, filters.tz)} onChange={(e) => commitCustom("end", e.target.value)} />
              </label>
            </>
          ) : null}
        </div>
        {adjusted ? <p className="warn">day boundary adjusted</p> : null}
        {tzError ? <p className="warn">{tzError}</p> : null}
        {rangeError ? <p className="warn">{rangeError}</p> : null}
        <p className="note">
          {safeWall(filters.start, filters.tz)} → {safeWall(filters.end, filters.tz)} ({filters.tz || "UTC"})
        </p>
        <form className="row" onSubmit={apply}>
          {FIELD_LABELS.map((field) => (
            <label key={field.key}>
              {field.label}
              <input value={draft[field.key]} onChange={(e) => setDraft({ ...draft, [field.key]: e.target.value })} />
            </label>
          ))}
          <label>
            Sampled
            <select
              value={draft.sampled}
              onChange={(e) => setDraft({ ...draft, sampled: e.target.value as Draft["sampled"] })}
            >
              <option value="">any</option>
              <option value="true">true</option>
              <option value="false">false</option>
            </select>
          </label>
          <button type="submit">Apply</button>
          <button type="button" onClick={clearFilters}>
            Clear
          </button>
        </form>
      </div>
      <main>
        <Routes>
          <Route path="/flows" element={<FlowsView />} />
          <Route path="/traffic" element={<TrafficView />} />
          <Route path="/talkers" element={<TalkersView />} />
          <Route path="/asn" element={<ASNView />} />
          <Route path="/reputation" element={<ReputationView />} />
          <Route path="/map" element={<MapView />} />
          <Route path="/globe" element={<GlobeView />} />
          <Route path="*" element={<FlowsView />} />
        </Routes>
      </main>
    </>
  );
}

interface ExporterRow {
  exporter: string;
  domain: number | string;
  version: number | string;
  last_seen: string;
  malformed: number | string;
  missing_template: number | string;
  gap_flows: number | string;
  gap_packets: number | string;
  gap_records: number | string;
}

function ExporterStrip(): ReactElement {
  const { filters } = useFilters();
  const rev = useRefresh();
  const [rows, setRows] = useState<ExporterRow[]>([]);
  const [stats, setStats] = useState<Record<string, number | string> | null>(null);
  const [error, setError] = useState<unknown>(null);

  useEffect(() => {
    let current = 0;
    let cancel = false;
    async function load(): Promise<void> {
      const seq = ++current;
      try {
        const [exporters, counters] = await Promise.all([
          getJSON<{ exporters: ExporterRow[] }>("/exporters", { fresh: true }),
          getJSON<Record<string, number | string>>("/stats", { fresh: true }),
        ]);
        if (cancel || seq !== current) return;
        setRows(exporters.exporters ?? []);
        setStats(counters);
        setError(null);
      } catch (err) {
        if (cancel || seq !== current) return;
        setRows([]);
        setStats(null);
        setError(err);
      }
    }
    void load();
    const id = setInterval(() => void load(), 5000);
    return () => {
      cancel = true;
      clearInterval(id);
    };
  }, [rev]);

  return (
    <div className="strip">
      {stats ? (
        <p className="note">
          process malformed {asText(stats.malformed)}, missing template {asText(stats.missing_template)}
        </p>
      ) : null}
      <QueryNotice error={error} />
      {!error && rows.length === 0 ? <p className="note">No exporters yet.</p> : null}
      {!error && rows.length > 0 ? (
        <table>
          <thead>
            <tr>
              <th>Exporter</th>
              <th>Domain</th>
              <th>Version</th>
              <th>Last packet</th>
              <th>Malformed</th>
              <th>Missing template</th>
              <th>Gap flows</th>
              <th>Gap packets</th>
              <th>Gap records</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={`${row.exporter}-${row.domain}`}>
                <td>{row.exporter}</td>
                <td>{asText(row.domain)}</td>
                <td>{asText(row.version)}</td>
                <td>{safeWall(row.last_seen, filters.tz)}</td>
                <td>{asText(row.malformed)}</td>
                <td>{asText(row.missing_template)}</td>
                <td>{asText(row.gap_flows)}</td>
                <td>{asText(row.gap_packets)}</td>
                <td>{asText(row.gap_records)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
    </div>
  );
}

function draftFrom(filters: Filters): Draft {
  return {
    src: filters.src ?? "",
    dst: filters.dst ?? "",
    port: filters.port ?? "",
    src_port: filters.src_port ?? "",
    dst_port: filters.dst_port ?? "",
    proto: filters.proto ?? "",
    exporter: filters.exporter ?? "",
    country: filters.country ?? "",
    asn: filters.asn ?? "",
    reputation: filters.reputation ?? "",
    sampled: filters.sampled ?? "",
  };
}

function initialAdjusted(filters: Filters): boolean {
  if (filters.preset !== "day") return false;
  try {
    return calendarRange(civilDay(filters.start, filters.tz), filters.tz).boundaryAdjusted;
  } catch {
    return false;
  }
}

function civilDay(utc: string, tz: string): string {
  return formatInZone(utc, tz).slice(0, 10);
}

function safeWall(utc: string, tz: string): string {
  try {
    return formatInZone(utc, tz);
  } catch {
    return utc;
  }
}

function inputValue(utc: string, tz: string): string {
  try {
    return formatInZone(utc, tz).replace(" ", "T");
  } catch {
    return "";
  }
}
