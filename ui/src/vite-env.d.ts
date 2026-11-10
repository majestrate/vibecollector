/// <reference types="vite/client" />

declare module "world-atlas/countries-50m.json" {
  const topology: {
    type: string;
    objects: { countries: unknown };
  };
  export default topology;
}

declare module "d3-geo" {
  export function geoCentroid(object: unknown): [number, number];
  export function geoArea(object: unknown): number;
}

declare module "d3-scale" {
  interface QuantizeScale<T> {
    (value: number): T | undefined;
    domain(domain: [number, number]): QuantizeScale<T>;
    range(range: readonly T[]): QuantizeScale<T>;
  }
  export function scaleQuantize<T>(): QuantizeScale<T>;
}

declare module "topojson-client" {
  export function feature(
    topology: unknown,
    object: unknown,
  ): { features: Array<{ id?: string | number | null }> };
}
