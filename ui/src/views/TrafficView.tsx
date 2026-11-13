import { useState, type ReactElement } from "react";
import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { formatInZone, useFilters } from "../filters";
import { intervalMax, intervalToken, parseInterval, type TrafficInterval } from "../interval";
import { plotNumber, QueryBody, useGET } from "../query";
import { formatScale } from "../scale";

const INTERVAL_KEY = "vibecollector.traffic_interval";
const AVERAGE_KEY = "vibecollector.traffic_moving_average";
const SPEED_KEY = "vibecollector.traffic_average_speed";
const RMS_KEY = "vibecollector.traffic_root_mean_square";

type BucketMode = "sum" | "average" | "speed" | "rms";

interface Point {
  t: string;
  octets: string;
  packets: string;
}

interface Series {
  sampled: boolean;
  points: Point[];
}

interface Timeseries {
  source: "rollup" | "flows";
  grain: string;
  series: Series[];
}

interface Row {
  t: string;
  unsampled?: number;
  sampled?: number;
}

/**
 * TrafficView plots octets and packets for the shared filter set.
 * The server sums each series into the interval chosen on this page.
 * Moving average, when checked, asks the server for the rounded mean of the
 * native samples inside each interval. Empty samples count as zero.
 * Average speed, when checked, asks the server for octets per second and
 * packets per second over each interval.
 * Root mean square, when checked, asks the server for the square root of the
 * mean square of the native samples inside each interval. Empty samples count
 * as zero, and the result rounds to the nearest integer.
 * Checking one clears the others.
 * Sampled and unsampled stay separate. Each step holds that value from the
 * bucket start until the next bucket. Neither line is multiplied by N.
 * Axis and tooltip counts use 1000-based prefixes from K through Q.
 */
export function TrafficView(): ReactElement {
  const { filters } = useFilters();
  const [interval, setSpan] = useState(loadInterval);
  const [draft, setDraft] = useState(() => String(interval.n));
  const [mode, setMode] = useState(loadMode);
  const query = useGET<Timeseries>("/timeseries", {
    interval: intervalToken(interval.n, interval.unit),
    moving_average: mode === "average" ? "true" : undefined,
    average_speed: mode === "speed" ? "true" : undefined,
    root_mean_square: mode === "rms" ? "true" : undefined,
  });
  const octets = query.data ? rows(query.data.series, "octets") : [];
  const packets = query.data ? rows(query.data.series, "packets") : [];
  const grain = query.data?.grain ?? "";
  return (
    <section>
      <h1>Traffic</h1>
      <p className="note">
      </p>
      <div className="row interval">
        <label>
          Interval
          <input
            type="number"
            min={1}
            max={intervalMax(interval.unit)}
            step={1}
            inputMode="numeric"
            value={draft}
            onChange={(e) => {
              const raw = e.target.value;
              setDraft(raw);
              const n = Number(raw);
              if (!Number.isInteger(n) || n < 1 || n > intervalMax(interval.unit)) return;
              commit(n, interval.unit, setSpan);
            }}
          />
        </label>
        <label>
          Unit
          <select
            value={interval.unit}
            onChange={(e) => {
              const unit = e.target.value as TrafficInterval["unit"];
              const n = Math.min(Math.max(interval.n, 1), intervalMax(unit));
              setDraft(String(n));
              commit(n, unit, setSpan);
            }}
          >
            <option value="m">minutes</option>
            <option value="h">hours</option>
            <option value="d">days</option>
          </select>
        </label>
        <label className="check">
          <input
            type="checkbox"
            checked={mode === "average"}
            onChange={(e) => {
              chooseMode(e.target.checked ? "average" : "sum", setMode);
            }}
          />
          Moving average
        </label>
        <label className="check">
          <input
            type="checkbox"
            checked={mode === "speed"}
            onChange={(e) => {
              chooseMode(e.target.checked ? "speed" : "sum", setMode);
            }}
          />
          Average speed
        </label>
        <label className="check">
          <input
            type="checkbox"
            checked={mode === "rms"}
            onChange={(e) => {
              chooseMode(e.target.checked ? "rms" : "sum", setMode);
            }}
          />
          Root mean square
        </label>
      </div>
      <QueryBody loading={query.loading} error={query.error} source={query.data?.source}>
        <h2>{mode === "speed" ? "Octets/s" : "Octets"}</h2>
        <Chart rows={octets} tz={filters.tz} grain={grain} />
        <h2>{mode === "speed" ? "Packets/s" : "Packets"}</h2>
        <Chart rows={packets} tz={filters.tz} grain={grain} />
        {grain ? <p className="note">{seriesNote(grain, mode)}</p> : null}
      </QueryBody>
    </section>
  );
}

function loadMode(): BucketMode {
  try {
    if (localStorage.getItem(AVERAGE_KEY) === "true") return "average";
    if (localStorage.getItem(SPEED_KEY) === "true") return "speed";
    if (localStorage.getItem(RMS_KEY) === "true") return "rms";
    return "sum";
  } catch {
    return "sum";
  }
}

function chooseMode(mode: BucketMode, setMode: (next: BucketMode) => void): void {
  setMode(mode);
  try {
    localStorage.setItem(AVERAGE_KEY, mode === "average" ? "true" : "false");
    localStorage.setItem(SPEED_KEY, mode === "speed" ? "true" : "false");
    localStorage.setItem(RMS_KEY, mode === "rms" ? "true" : "false");
  } catch {
    /* private mode */
  }
}

function seriesNote(grain: string, mode: BucketMode): string {
  if (mode === "speed") return `Interval ${grain}, average speed`;
  if (mode === "average") return `Interval ${grain}, moving average`;
  if (mode === "rms") return `Interval ${grain}, root mean square`;
  return `Interval ${grain}`;
}

function loadInterval(): TrafficInterval {
  try {
    return parseInterval(localStorage.getItem(INTERVAL_KEY)) ?? { n: 1, unit: "m" };
  } catch {
    return { n: 1, unit: "m" };
  }
}

function commit(n: number, unit: TrafficInterval["unit"], setSpan: (next: TrafficInterval) => void): void {
  const next = { n, unit };
  setSpan(next);
  try {
    localStorage.setItem(INTERVAL_KEY, intervalToken(n, unit));
  } catch {
    /* private mode */
  }
}

function Chart({ rows: data, tz, grain }: { rows: Row[]; tz: string; grain: string }): ReactElement {
  if (data.length === 0) return <p>No traffic in this range.</p>;
  return (
    <div className="chart">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="t" minTickGap={24} tickFormatter={(value: unknown) => tick(value, tz, grain)} />
          <YAxis width={72} tickFormatter={(value: unknown) => formatScale(magnitude(value))} />
          <Tooltip
            labelFormatter={(value: unknown) => tick(value, tz, grain)}
            formatter={(value: unknown) => formatScale(magnitude(value))}
          />
          <Legend />
          <Line type="stepAfter" dataKey="unsampled" name="unsampled" dot={false} stroke="#1f4e79" connectNulls={false} />
          <Line type="stepAfter" dataKey="sampled" name="sampled" dot={false} stroke="#c47b00" connectNulls={false} />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}

function rows(series: Series[], field: "octets" | "packets"): Row[] {
  const map = new Map<string, Row>();
  for (const item of series) {
    for (const point of item.points) {
      const row = map.get(point.t) ?? { t: point.t };
      const value = plotNumber(point[field]);
      if (item.sampled) row.sampled = value;
      else row.unsampled = value;
      map.set(point.t, row);
    }
  }
  return [...map.values()].sort((a, b) => (a.t < b.t ? -1 : 1));
}

function magnitude(value: unknown): number {
  const n = typeof value === "number" ? value : Number(value);
  return Number.isFinite(n) ? n : Number.NaN;
}

function tick(value: unknown, tz: string, grain: string): string {
  if (typeof value !== "string") return "";
  try {
    const text = formatInZone(value, tz);
    if (grain.endsWith("d")) return text.slice(5, 16);
    return text.slice(11, 16);
  } catch {
    return value;
  }
}
