import { type ComponentProps, type JSX, useEffect, useState } from "react";
import { ComposableMap, Geographies, Geography, Line, ZoomableGroup } from "react-simple-maps";
import world from "world-atlas/countries-50m.json";
import type { Filters } from "../filters";
import { countryCentroid } from "../geo/centroids";
import { fetchGeo, type GeoPlace, type GeoResponse } from "../geo/fetch";
import { iso3166, numericId } from "../geo/iso3166";
import { colorForOctets } from "../geo/scale";
import { asText, QueryBody, useRefresh } from "../query";

/**
 * MapViewProps is the flat map's input.
 * filters is the shared set. MapView passes it to fetchGeo unchanged.
 */
export interface MapViewProps {
  filters: Filters;
}

/**
 * MapView draws the Equal Earth choropleth and at most 100 arcs.
 * It calls fetchGeo and colorForOctets. It imports the world-atlas topology,
 * the string id table, and the centroid helper. It does not import GlobeView.
 * A FilterOutsideRaw or QueryTimeout rejection is rethrown so the shell can
 * show the retention message. The component does not paint a stale unfiltered map.
 */
export function MapView(props: MapViewProps): JSX.Element {
  const rev = useRefresh();
  const key = `${rev}\n${JSON.stringify(props.filters)}`;
  const [seen, setSeen] = useState(key);
  const [data, setData] = useState<GeoResponse | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  if (seen !== key) {
    setSeen(key);
    setData(null);
    setError(null);
    setLoading(true);
  }
  useEffect(() => {
    let cancel = false;
    fetchGeo(props.filters)
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
  }, [key, props.filters]);

  return (
    <section>
      <h1>Map</h1>
      <p className="note">Bytes touching this country.</p>
      <QueryBody loading={loading} error={error} source={data?.source}>
        {data ? <Choropleth data={data} /> : null}
      </QueryBody>
    </section>
  );
}

function Choropleth({ data }: { data: GeoResponse }): JSX.Element {
  const countries = data.countries ?? [];
  const max = largestDecimal(countries.map((country) => country.octets));
  const byId = new Map(countries.map((country) => [country.iso_num, country]));
  const missed = countries.filter((country) => !Object.hasOwn(iso3166, country.iso_num));
  const paths = (data.paths ?? []).slice(0, 100);
  const pathMax = largestDecimal(paths.map((path) => path.octets));
  const arcs = paths.flatMap((path, index) => {
    const from = locate(path.src);
    const to = locate(path.dst);
    if (!from || !to) return [];
    return [{ index, from, to, width: strokeWidth(path.octets, pathMax) }];
  });
  // The default geoEqualEarth scale fits a 960px map and clips this viewBox.
  const projectionScale = 140;
  return (
    <>
      <div className="map">
        <ComposableMap projection="geoEqualEarth" width={800} height={420} projectionConfig={{ scale: projectionScale }}>
          <ZoomableGroup>
            {/* Topology is outside the published geography union. The runtime does not fetch it. */}
            <Geographies geography={world as unknown as ComponentProps<typeof Geographies>["geography"]}>
              {({ geographies }) =>
                geographies.map((geo) => {
                  const id = geo.id;
                  const row = typeof id === "string" ? byId.get(id) : undefined;
                  return (
                    <Geography
                      key={geo.rsmKey}
                      geography={geo}
                      fill={colorForOctets(row?.octets, max)}
                      stroke="#ffffff"
                      strokeWidth={0.35}
                    />
                  );
                })
              }
            </Geographies>
            {arcs.map((arc) => (
              <Line
                key={arc.index}
                from={arc.from}
                to={arc.to}
                stroke="#7c2d12"
                strokeWidth={arc.width}
                strokeLinecap="round"
                fill="none"
              />
            ))}
          </ZoomableGroup>
        </ComposableMap>
      </div>
      {missed.length > 0 ? (
        <>
          <h2>Country totals not on the map</h2>
          <table>
            <thead>
              <tr>
                <th>Country</th>
                <th>ISO numeric</th>
                <th>Octets</th>
                <th>Packets</th>
                <th>Flows</th>
              </tr>
            </thead>
            <tbody>
              {missed.map((country, index) => (
                <tr key={`${country.iso_num}-${index}`}>
                  <td>{country.iso_a2}</td>
                  <td>{country.iso_num}</td>
                  <td>{asText(country.octets)}</td>
                  <td>{asText(country.packets)}</td>
                  <td>{asText(country.flows)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      ) : null}
    </>
  );
}

function locate(place: GeoPlace): [number, number] | null {
  if (place.kind === "country") {
    const id = numericId(place.iso_a2);
    return id ? countryCentroid(id) : null;
  }
  if (typeof place.lat !== "number" || typeof place.lon !== "number") return null;
  if (!Number.isFinite(place.lat) || !Number.isFinite(place.lon)) return null;
  return [place.lon, place.lat];
}

function largestDecimal(values: string[]): string {
  let best = "0";
  for (const value of values) {
    if (compareDecimal(value, best) > 0) best = value;
  }
  return best;
}

function compareDecimal(a: string, b: string): number {
  if (!/^\d+$/.test(a) || !/^\d+$/.test(b)) return 0;
  const left = a.replace(/^0+/, "") || "0";
  const right = b.replace(/^0+/, "") || "0";
  if (left.length !== right.length) return left.length - right.length;
  if (left === right) return 0;
  return left < right ? -1 : 1;
}

function strokeWidth(octets: string, max: string): number {
  const min = 0.75;
  const span = 3.25;
  if (!/^\d+$/.test(octets) || !/^\d+$/.test(max)) return min;
  const whole = BigInt(max);
  if (whole <= 0n) return min;
  const part = BigInt(octets);
  if (part <= 0n) return min;
  if (part >= whole) return min + span;
  return min + (Number((part * 1000n) / whole) / 1000) * span;
}
