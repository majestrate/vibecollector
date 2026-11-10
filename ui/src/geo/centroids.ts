import { geoArea, geoCentroid } from "d3-geo";
import { feature } from "topojson-client";
import world from "world-atlas/countries-50m.json";

interface Placed {
  point: [number, number];
  area: number;
}

// Id 036 is also Ashmore and Cartier Is. The country arc uses the larger feature.
const placed = new Map<string, Placed>();
const countries = feature(world, world.objects.countries);
for (const item of countries.features) {
  if (typeof item.id !== "string") continue;
  const point = geoCentroid(item);
  if (!Number.isFinite(point[0]) || !Number.isFinite(point[1])) continue;
  const area = geoArea(item);
  const prev = placed.get(item.id);
  if (prev && area <= prev.area) continue;
  placed.set(item.id, { point: [point[0], point[1]], area });
}

/**
 * countryCentroid returns the geographic centroid of a world-atlas country.
 * isoNum is the zero-padded feature id, the same string as GeoCountry.iso_num.
 * The result is [longitude, latitude] in degrees, or null when the id is absent
 * or the centroid is not finite. A null result skips the arc. The country is still shaded.
 * The value is not projected. The map applies geoEqualEarth. It does not throw.
 */
export function countryCentroid(isoNum: string): [number, number] | null {
  return placed.get(isoNum)?.point ?? null;
}
