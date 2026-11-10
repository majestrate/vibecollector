import type { ReactElement } from "react";
import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { formatInZone, useFilters } from "../filters";
import { plotNumber, QueryBody, useGET } from "../query";

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
 * Sampled and unsampled exports are separate lines. Neither line is multiplied by N.
 */
export function TrafficView(): ReactElement {
  const { filters } = useFilters();
  const query = useGET<Timeseries>("/timeseries");
  const octets = query.data ? rows(query.data.series, "octets") : [];
  const packets = query.data ? rows(query.data.series, "packets") : [];
  return (
    <section>
      <h1>Traffic</h1>
      <p className="note">Sampled and unsampled are separate lines. Neither line is multiplied by the sampling interval.</p>
      <QueryBody loading={query.loading} error={query.error} source={query.data?.source}>
        <h2>Octets</h2>
        <Chart rows={octets} tz={filters.tz} />
        <h2>Packets</h2>
        <Chart rows={packets} tz={filters.tz} />
        {query.data ? <p className="note">Grain {query.data.grain}</p> : null}
      </QueryBody>
    </section>
  );
}

function Chart({ rows: data, tz }: { rows: Row[]; tz: string }): ReactElement {
  if (data.length === 0) return <p>No traffic in this range.</p>;
  return (
    <div className="chart">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={data}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="t" minTickGap={24} tickFormatter={(value: unknown) => tick(value, tz)} />
          <YAxis />
          <Tooltip labelFormatter={(value: unknown) => tick(value, tz)} />
          <Legend />
          <Line type="monotone" dataKey="unsampled" name="unsampled" dot={false} stroke="#1f4e79" connectNulls={false} />
          <Line type="monotone" dataKey="sampled" name="sampled" dot={false} stroke="#c47b00" connectNulls={false} />
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

function tick(value: unknown, tz: string): string {
  if (typeof value !== "string") return "";
  try {
    return formatInZone(value, tz).slice(11, 16);
  } catch {
    return value;
  }
}
