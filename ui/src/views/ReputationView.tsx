import type { ReactElement } from "react";
import { useFilters } from "../filters";
import { asText, QueryBody, useGET } from "../query";

interface RepRow {
  direction: string;
  addr: string;
  category: string;
  octets: string;
  packets: string;
  flows: number | string;
}

interface Reputation {
  source: "rollup" | "flows";
  approximate: boolean;
  other_octets: string;
  rows: RepRow[];
}

/**
 * ReputationView lists reputation hits for the shared filter set.
 * It reads the reputation route and does not keep a second copy of the range.
 */
export function ReputationView(): ReactElement {
  useFilters();
  const query = useGET<Reputation>("/reputation");
  return (
    <section>
      <h1>Reputation</h1>
      <QueryBody loading={query.loading} error={query.error} source={query.data?.source}>
        {query.data?.approximate ? <p className="note">This ranking is approximate.</p> : null}
        {query.data && query.data.other_octets !== "0" ? <p>Other octets {query.data.other_octets}</p> : null}
        <table>
          <thead>
            <tr>
              <th>Direction</th>
              <th>Address</th>
              <th>Category</th>
              <th>Octets</th>
              <th>Packets</th>
              <th>Flows</th>
            </tr>
          </thead>
          <tbody>
            {(query.data?.rows ?? []).map((row, i) => (
              <tr key={`${row.direction}-${row.addr}-${row.category}-${i}`}>
                <td>{row.direction}</td>
                <td>{row.addr}</td>
                <td>{row.category}</td>
                <td>{asText(row.octets)}</td>
                <td>{asText(row.packets)}</td>
                <td>{asText(row.flows)}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {query.data && query.data.rows.length === 0 ? <p>No reputation hits in this range.</p> : null}
      </QueryBody>
    </section>
  );
}
