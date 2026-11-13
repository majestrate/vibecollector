/** TrafficInterval is the bucket width sent as the timeseries interval parameter. */
export interface TrafficInterval {
  n: number;
  unit: "m" | "h" | "d";
}

const LIMITS: Record<TrafficInterval["unit"], number> = { m: 1440, h: 24, d: 366 };

/**
 * intervalMax is the largest count the server accepts for unit.
 * unit is m, h, or d. The result is 1440, 24, or 366.
 */
export function intervalMax(unit: TrafficInterval["unit"]): number {
  return LIMITS[unit];
}

/**
 * intervalToken is the timeseries interval query value.
 * n is the count and unit is m, h, or d.
 * The result is the token, such as 15m.
 * It throws RangeError when n is not an integer inside intervalMax.
 */
export function intervalToken(n: number, unit: TrafficInterval["unit"]): string {
  if (!Number.isInteger(n) || n < 1 || n > intervalMax(unit)) {
    throw new RangeError("bad interval");
  }
  return `${n}${unit}`;
}

/**
 * parseInterval reads a stored interval token.
 * token is Nm, Nh, or Nd, with no leading zero. The result is the count and unit.
 * It returns null when the token is missing or outside the server limits.
 */
export function parseInterval(token: string | null): TrafficInterval | null {
  if (!token) return null;
  const match = /^([1-9]\d{0,3})([mhd])$/.exec(token);
  if (!match) return null;
  const n = Number(match[1]);
  const unit = match[2] as TrafficInterval["unit"];
  if (n > intervalMax(unit)) return null;
  return { n, unit };
}
