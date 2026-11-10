import { scaleQuantize } from "d3-scale";

/** neutralFill is the color for zero traffic and for null-id land. */
export const neutralFill = "#d9d9d9";

const steps = ["#c6dbef", "#9ecae1", "#6baed6", "#3182bd", "#08519c"];

/**
 * colorForOctets maps one country total onto the shared quantize scale.
 * octets is the decimal string from GeoResponse. domainMax is the largest
 * octet string in that response. Zero, empty, and missing values return the
 * neutral fill. The return value is a CSS color. The function does not throw
 * on a non-numeric string; it returns the neutral fill.
 * MapView and GlobeView both call this. Neither view builds its own scale.
 */
export function colorForOctets(octets: string | undefined, domainMax: string): string {
  const value = parseDecimal(octets);
  if (value === undefined || value <= 0) return neutralFill;
  const max = parseDecimal(domainMax);
  if (max === undefined || max <= 0) return neutralFill;
  const color = scaleQuantize<string>().domain([0, max]).range(steps)(value);
  return typeof color === "string" ? color : neutralFill;
}

function parseDecimal(value: string | undefined): number | undefined {
  if (typeof value !== "string") return undefined;
  const text = value.trim();
  if (text === "") return undefined;
  const n = Number(text);
  if (Number.isNaN(n)) return undefined;
  if (n === 0) return 0;
  if (!Number.isFinite(n)) return Number.MAX_VALUE;
  return n;
}
