const PREFIXES = ["", "K", "M", "G", "T", "P", "E", "Z", "Y", "R", "Q"] as const;

/**
 * formatScale renders a count with a 1000-based prefix.
 * value is a finite chart coordinate. The result is a short label such as
 * 0, 12, 1.5K, 2M, 3.25G, 4T, 5P, and on through Q.
 * K is kilo, M mega, G giga, T tera, P peta, E exa, Z zetta, Y yotta,
 * R ronna, and Q quetta. A non-finite value is an empty string.
 */
export function formatScale(value: number): string {
  if (!Number.isFinite(value)) return "";
  const sign = value < 0 ? "-" : "";
  const scaled = choose(Math.abs(value));
  return sign + digits(scaled.n) + PREFIXES[scaled.exp];
}

function choose(abs: number): { n: number; exp: number } {
  let n = abs;
  let exp = 0;
  while (n >= 1000 && exp < PREFIXES.length - 1) {
    n /= 1000;
    exp += 1;
  }
  const places = n >= 100 ? 0 : n >= 10 ? 1 : 2;
  const rounded = Number(n.toFixed(places));
  if (rounded >= 1000 && exp < PREFIXES.length - 1) {
    return { n: rounded / 1000, exp: exp + 1 };
  }
  return { n: rounded, exp };
}

function digits(n: number): string {
  const places = n >= 100 || Number.isInteger(n) ? 0 : n >= 10 ? 1 : 2;
  return n.toFixed(places).replace(/(\.\d*?)0+$/, "$1").replace(/\.$/, "");
}
