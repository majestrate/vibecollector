import { useState, type ReactElement } from "react";
import { useFilters } from "../filters";
import { formatInZone } from "../filters";
import { asText, QueryBody, useGET } from "../query";

interface FlowRow {
  id: number | string;
  start: string;
  src: string;
  dst: string;
  src_port?: number | null;
  dst_port?: number | null;
  proto?: number | null;
  packets: string;
  octets: string;
  counter_semantics: string;
  octet_semantics: string;
  flow_direction?: number | null;
  sampled: boolean;
  sampling_interval?: number | string | null;
  clock_clamped: boolean;
  exporter: string;
}

interface FlowPage {
  raw_available_from: string;
  truncated: boolean;
  flows: FlowRow[];
  next_cursor?: string;
}

/**
 * FlowsView is the keyset flow table for the shared filter set.
 * It pages 100 rows at a time. It does not keep a second copy of the range.
 */
export function FlowsView(): ReactElement {
  const { filters } = useFilters();
  const filterKey = JSON.stringify(filters);
  const [stack, setStack] = useState({ key: filterKey, cursors: [""], page: 0 });
  const pageState = stack.key === filterKey ? stack : { key: filterKey, cursors: [""], page: 0 };
  const cursor = pageState.cursors[pageState.page] ?? "";
  const [showEstimate, setShowEstimate] = useState(false);
  const query = useGET<FlowPage>("/flows", { limit: "100", cursor: cursor || undefined });

  function goNext(): void {
    const next = query.data?.next_cursor;
    if (!next) return;
    const cursors = pageState.cursors.slice(0, pageState.page + 1);
    cursors.push(next);
    setStack({ key: filterKey, cursors, page: pageState.page + 1 });
  }

  function goPrev(): void {
    if (pageState.page === 0) return;
    setStack({ key: filterKey, cursors: pageState.cursors, page: pageState.page - 1 });
  }

  return (
    <section>
      <h1>Flows</h1>
      <label>
        <input type="checkbox" checked={showEstimate} onChange={(e) => setShowEstimate(e.target.checked)} /> Show estimate
      </label>
      <QueryBody loading={query.loading} error={query.error}>
        {query.data?.truncated ? <p>raw_available_from {query.data.raw_available_from}</p> : null}
        <table>
          <thead>
            <tr>
              <th>Start</th>
              <th>Source</th>
              <th>Destination</th>
              <th>Ports</th>
              <th>Proto</th>
              <th>Packets</th>
              <th>Octets</th>
              {showEstimate ? <th>estimated, not stored</th> : null}
              <th>Exporter</th>
              <th>Badges</th>
            </tr>
          </thead>
          <tbody>
            {(query.data?.flows ?? []).map((flow) => (
              <tr key={String(flow.id)}>
                <td>{wall(flow.start, filters.tz)}</td>
                <td>{flow.src}</td>
                <td>{flow.dst}</td>
                <td>
                  {flow.src_port ?? ""}→{flow.dst_port ?? ""}
                </td>
                <td>{flow.proto ?? ""}</td>
                <td>{asText(flow.packets)}</td>
                <td>{asText(flow.octets)}</td>
                {showEstimate ? <td>{estimate(flow)}</td> : null}
                <td>{flow.exporter}</td>
                <td>
                  <Badges flow={flow} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {query.data && query.data.flows.length === 0 ? <p>No flows in this range.</p> : null}
        <div className="row">
          <button type="button" onClick={goPrev} disabled={pageState.page === 0}>
            Previous
          </button>
          <span>Page {pageState.page + 1}</span>
          <button type="button" onClick={goNext} disabled={!query.data?.next_cursor}>
            Next
          </button>
        </div>
      </QueryBody>
    </section>
  );
}

function Badges({ flow }: { flow: FlowRow }): ReactElement {
  const items: string[] = [];
  if (flow.sampled) {
    const n = flow.sampling_interval;
    items.push(n === undefined || n === null || n === "" ? "sampled" : `sampled 1:${n}`);
  }
  if (flow.counter_semantics === "total") items.push("total counter");
  if (flow.octet_semantics === "l4_payload") items.push("L4 payload");
  if (flow.clock_clamped) items.push("clock clamped");
  if (flow.flow_direction === 0) items.push("ingress");
  if (flow.flow_direction === 1) items.push("egress");
  return (
    <>
      {items.map((item) => (
        <span key={item} className="badge">
          {item}
        </span>
      ))}
    </>
  );
}

function estimate(flow: FlowRow): string {
  const interval = flow.sampling_interval;
  if (!flow.sampled || interval === undefined || interval === null || interval === "") return "";
  try {
    return (BigInt(flow.octets) * BigInt(interval)).toString();
  } catch {
    return "";
  }
}

function wall(utc: string, tz: string): string {
  try {
    return formatInZone(utc, tz);
  } catch {
    return utc;
  }
}
