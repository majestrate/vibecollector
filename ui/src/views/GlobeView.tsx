import { type JSX, useEffect, useState } from "react";
import Globe from "react-globe.gl";
import { feature } from "topojson-client";
import world from "world-atlas/countries-50m.json";
import type { Filters } from "../filters";
import { countryCentroid } from "../geo/centroids";
import { fetchGeo, type GeoPath, type GeoPlace, type GeoResponse } from "../geo/fetch";
import { numericId } from "../geo/iso3166";
import { colorForOctets } from "../geo/scale";
import { QueryBody, useRefresh } from "../query";

// The layer takes the feature array. feature() is the same countries-50m topology the map imports.
const polygons = feature(world, world.objects.countries).features;

/**
 * GlobeViewProps is the globe's input. filters is the same set MapView uses.
 */
export interface GlobeViewProps {
  filters: Filters;
}

/**
 * GlobeView draws the rotatable sphere from the same GeoResponse.
 * It calls fetchGeo and colorForOctets. It does not import MapView.
 * globeImageUrl, bumpImageUrl, and globeTileEngineUrl are left unset.
 * Rejections propagate the same way as MapView.
 */
export function GlobeView(props: GlobeViewProps): JSX.Element {
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
      <h1>Globe</h1>
      <p className="note">Bytes touching this country.</p>
      <QueryBody loading={loading} error={error} source={data?.source}>
        {data ? <Sphere data={data} /> : null}
      </QueryBody>
    </section>
  );
}

function Sphere({ data }: { data: GeoResponse }): JSX.Element {
  const countries = data.countries ?? [];
  const max = largestDecimal(countries.map((country) => country.octets));
  const byId = new Map(countries.map((country) => [country.iso_num, country]));
  const arcs = pathArcs((data.paths ?? []).slice(0, 100));
  const cap = (polygon: object) => colorForOctets(octetsFor(polygon, byId), max);
  return (
    <div className="globe">
      {/* A truthy image or tile URL is fetched. Omitting the props keeps the black sphere and leaves tiles off. */}
      <Globe width={800} height={420} polygonsData={polygons} polygonCapColor={cap} arcsData={arcs} />
    </div>
  );
}

function octetsFor(polygon: object, byId: Map<string, { octets: string }>): string | undefined {
  if (!("id" in polygon)) return undefined;
  const id = polygon.id;
  if (typeof id !== "string") return undefined;
  return byId.get(id)?.octets;
}

interface Arc {
  startLat: number;
  startLng: number;
  endLat: number;
  endLng: number;
}

function pathArcs(paths: GeoPath[]): Arc[] {
  const arcs: Arc[] = [];
  for (const path of paths) {
    const from = locate(path.src);
    const to = locate(path.dst);
    if (!from || !to) continue;
    arcs.push({ startLat: from.lat, startLng: from.lng, endLat: to.lat, endLng: to.lng });
  }
  return arcs;
}

function locate(place: GeoPlace): { lat: number; lng: number } | null {
  if (place.kind === "country") {
    const id = numericId(place.iso_a2);
    if (!id) return null;
    const point = countryCentroid(id);
    if (!point) return null;
    return { lng: point[0], lat: point[1] };
  }
  if (typeof place.lat !== "number" || typeof place.lon !== "number") return null;
  if (!Number.isFinite(place.lat) || !Number.isFinite(place.lon)) return null;
  return { lat: place.lat, lng: place.lon };
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
