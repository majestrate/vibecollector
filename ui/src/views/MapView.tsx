import type { ReactElement } from "react";
import { useFilters } from "../filters";

/**
 * MapView is the flat-map route.
 * This build does not draw it. It does not fetch tiles and it does not import the globe.
 */
export function MapView(): ReactElement {
  useFilters();
  return <p>The map view is not in this PR.</p>;
}
