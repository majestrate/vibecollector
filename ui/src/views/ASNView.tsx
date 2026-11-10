import { useState, type ReactElement } from "react";
import { Bar, BarChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { useFilters } from "../filters";
import { asText, plotNumber, QueryBody, useGET } from "../query";
import { Limit } from "./TalkersView";

interface AsnRow {
  asn: number | string;
  name: string;
  direction: string;
  from_export: boolean;
  octets: string;
  packets: string;
  flows: number | string;
}

interface Asns {
  source: "rollup" | "flows";
  rows: AsnRow[];
}

/**
 * ASNView charts autonomous systems for the shared filter set.
 * asn -1 is labeled other. from_export rows are labeled from export.
 * It does not keep a second copy of the range.
 */
export function ASNView(): ReactElement {
  useFilters();
  const [limit, setLimit] = useState("20");
  const query = useGET<Asns>("/asns", { limit });
  const data = (query.data?.rows ?? []).map((row) => ({
    label: asnLabel(row),
    octets: plotNumber(row.octets),
    packets: asText(row.packets),
    flows: asText(row.flows),
  }));
  return (
    <section>
      <h1>ASN</h1>
      <Limit value={limit} onChange={setLimit} />
      <QueryBody loading={query.loading} error={query.error} source={query.data?.source}>
        {data.length === 0 ? (
          <p>No rows in this range.</p>
        ) : (
          <div className="chart" style={{ height: Math.max(180, data.length * 32 + 40) }}>
            <ResponsiveContainer width="100%" height="100%">
              <BarChart layout="vertical" data={data} margin={{ left: 8 }}>
                <XAxis type="number" />
                <YAxis type="category" dataKey="label" width={280} />
                <Tooltip />
                <Bar dataKey="octets" name="octets" fill="#1f4e79" />
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}
      </QueryBody>
    </section>
  );
}

function asnLabel(row: AsnRow): string {
  const dir = row.direction ? ` ${row.direction}` : "";
  if (row.asn === -1 || row.asn === "-1") return `other${dir}`;
  const name = row.name ? ` ${row.name}` : "";
  const exp = row.from_export ? " from export" : "";
  return `AS${asText(row.asn)}${name}${dir}${exp}`;
}
