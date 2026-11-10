import { useEffect, useRef, useState, type ReactElement, type ReactNode } from "react";
import { Unauthorized } from "./api";
import { useFilters } from "./filters";
import { FilterOutsideRaw, getJSON, QueryTimeout } from "./geo/fetch";

let revision = 0;
const listeners = new Set<() => void>();

/**
 * bumpQueries asks mounted views to load again.
 * A relative preset that is refreshed inside the same second still refetches.
 */
export function bumpQueries(): void {
  revision += 1;
  for (const listener of listeners) listener();
}

/**
 * useRefresh returns a counter that changes when bumpQueries runs.
 * The result starts at the current revision.
 */
export function useRefresh(): number {
  const [value, setValue] = useState(revision);
  useEffect(() => {
    const listener = () => setValue(revision);
    listeners.add(listener);
    return () => {
      listeners.delete(listener);
    };
  }, []);
  return value;
}

interface QueryResult<T> {
  data: T | null;
  error: unknown;
  loading: boolean;
}

/**
 * useGET loads route whenever the shared filters, extra, or a refresh change.
 * route is the path after the prefix. extra is additional query parameters.
 * data is null while loading and after an error, so the previous series is not shown.
 * error is FilterOutsideRaw, QueryTimeout, Unauthorized, or another Error.
 */
export function useGET<T>(route: string, extra?: Record<string, string | undefined>): QueryResult<T> {
  const { filters } = useFilters();
  const rev = useRefresh();
  const extraKey = JSON.stringify(extra ?? null);
  const key = `${rev}\n${route}\n${extraKey}\n${JSON.stringify(filters)}`;
  const [seen, setSeen] = useState(key);
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  if (seen !== key) {
    setSeen(key);
    setData(null);
    setError(null);
    setLoading(true);
  }
  const requestRef = useRef({ filters, extra, route });
  requestRef.current = { filters, extra, route };
  useEffect(() => {
    const current = requestRef.current;
    let cancel = false;
    getJSON<T>(current.route, { filters: current.filters, extra: current.extra })
      .then((body) => {
        if (cancel) return;
        setData(body);
        setError(null);
        setLoading(false);
      })
      .catch((err: unknown) => {
        if (cancel) return;
        setData(null);
        setError(err);
        setLoading(false);
      });
    return () => {
      cancel = true;
    };
  }, [key]);
  return { data, error, loading };
}

/**
 * QueryNotice explains a failed or raw-flow result.
 * error is the rejection from useGET. source is the response source field.
 * FilterOutsideRaw replaces any previous series with the retention sentence.
 * A null result means there is nothing to say.
 */
export function QueryNotice({ error, source }: { error?: unknown; source?: string }): ReactElement | null {
  if (error instanceof Unauthorized) return <p>Signing in…</p>;
  if (error instanceof FilterOutsideRaw) {
    return (
      <p className="warn">
        this filter is only available inside raw retention
        {error.rawAvailableFrom ? ` (${error.rawAvailableFrom})` : ""}
      </p>
    );
  }
  if (error instanceof QueryTimeout) return <p className="warn">The query timed out.</p>;
  if (error) return <p className="warn">The query failed.</p>;
  if (source === "flows") return <p className="note">These numbers were aggregated from raw flows.</p>;
  return null;
}

/**
 * QueryBody renders children only after a successful load.
 * loading and error come from useGET. source is echoed on the body.
 * children are the chart or table for that body.
 */
export function QueryBody({
  loading,
  error,
  source,
  children,
}: {
  loading: boolean;
  error: unknown;
  source?: string;
  children: ReactNode;
}): ReactElement {
  if (loading) return <p>Loading…</p>;
  if (error) return <QueryNotice error={error} />;
  return (
    <>
      <QueryNotice source={source} />
      {children}
    </>
  );
}

/**
 * asText renders a count without coercing a decimal string through a number.
 * value is a JSON string or a safe integer. The result is the decimal text.
 */
export function asText(value: unknown): string {
  if (typeof value === "string") return value;
  if (typeof value === "number" || typeof value === "bigint") return String(value);
  return "";
}

/**
 * plotNumber is the chart coordinate for a decimal count string.
 * value is the API decimal string. The result is finite or zero.
 * The stored display stays the original string.
 */
export function plotNumber(value: string): number {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}
