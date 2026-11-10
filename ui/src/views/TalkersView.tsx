import { useState, type ReactElement } from "react";
import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useFilters } from "../filters";
import { asText, plotNumber, QueryBody, useGET } from "../query";

interface TalkerRow {
  addr: string;
  octets: string;
  packets: string;
  flows: number | string;
}

interface Talkers {
  source: "rollup" | "flows";
  by: string;
  approximate: boolean;
  other_octets: string;
  rows: TalkerRow[];
}

/**
 * TalkersView ranks sources and destinations for the shared filter set.
 * It does not rank ports and does not keep a second copy of the range.
 */
export function TalkersView(): ReactElement {
  useFilters();
  const [by, setBy] = useState<"src" | "dst">("src");
  const [limit, setLimit] = useState("20");
  const query = useGET<Talkers>("/talkers", { by, limit });
  const data = (query.data?.rows ?? []).map((row) => ({
    label: `${row.addr} · ${asText(row.octets)}`,
    octets: plotNumber(row.octets),
    packets: asText(row.packets),
    flows: asText(row.flows),
  }));
  return (
    <section>
      <h1>Top talkers</h1>
      <p className="note">Ranks sources and destinations. Ports are not ranked.</p>
      <div className="row">
        <button type="button" className={by === "src" ? "on" : ""} onClick={() => setBy("src")}>
          Sources
        </button>
        <button type="button" className={by === "dst" ? "on" : ""} onClick={() => setBy("dst")}>
          Destinations
        </button>
        <Limit value={limit} onChange={setLimit} />
      </div>
      <QueryBody loading={query.loading} error={query.error} source={query.data?.source}>
        {query.data?.approximate ? <p className="note">This ranking is approximate.</p> : null}
        {query.data && query.data.other_octets !== "0" ? <p>Other octets {query.data.other_octets}</p> : null}
        {data.length === 0 ? <p>No rows in this range.</p> : <Bars data={data} />}
      </QueryBody>
    </section>
  );
}

function Bars({ data }: { data: { label: string; octets: number; packets: string; flows: string }[] }): ReactElement {
  return (
    <div className="chart" style={{ height: Math.max(180, data.length * 32 + 40) }}>
      <ResponsiveContainer width="100%" height="100%">
        <BarChart layout="vertical" data={data} margin={{ left: 8 }}>
          <XAxis type="number" />
          <YAxis type="category" dataKey="label" width={240} />
          <Tooltip />
          <Bar dataKey="octets" name="octets" fill="#1f4e79" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}

/**
 * Limit chooses how many rows to request.
 * value is the current limit. onChange replaces it. The maximum is 100.
 */
export function Limit({ value, onChange }: { value: string; onChange: (next: string) => void }): ReactElement {
  return (
    <label>
      Rows
      <select value={value} onChange={(e) => onChange(e.target.value)}>
        <option value="20">20</option>
        <option value="50">50</option>
        <option value="100">100</option>
      </select>
    </label>
  );
}
