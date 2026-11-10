import type { ReactElement } from "react";
import { useFilters } from "../filters";

/**
 * GlobeView is the globe route.
 * This build does not draw it. It does not fetch tiles and it does not import the map.
 */
export function GlobeView(): ReactElement {
  useFilters();
  return <p>The globe view is not in this PR.</p>;
}
