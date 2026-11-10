import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { expect, test } from "vitest";
import { countryCentroid } from "./centroids";
import { iso3166, numericId } from "./iso3166";
import { colorForOctets, neutralFill } from "./scale";

const require = createRequire(import.meta.url);

test("every non-null countries-50m id has an alpha-2", () => {
  const path = require.resolve("world-atlas/countries-50m.json");
  const topo = JSON.parse(readFileSync(path, "utf8")) as {
    objects: { countries: { geometries: { id: string | null }[] } };
  };
  const ids = topo.objects.countries.geometries.map((geo) => geo.id);
  expect(ids).toContain("016");
  expect(iso3166["016"]).toBe("AS");
  for (const id of ids) {
    if (id == null) continue;
    expect(iso3166[id], String(id)).toMatch(/^[A-Z]{2}$/);
  }
});

test("country arcs use the larger feature when an id is repeated", () => {
  expect(numericId("US")).toBe("840");
  expect(numericId("AS")).toBe("016");
  const australia = countryCentroid("036");
  expect(australia).not.toBeNull();
  expect(australia![1]).toBeLessThan(-20);
  expect(countryCentroid("016")).not.toBeNull();
  expect(countryCentroid("999")).toBeNull();
});

test("colorForOctets returns neutral fill without throwing", () => {
  expect(colorForOctets(undefined, "10")).toBe(neutralFill);
  expect(colorForOctets("", "10")).toBe(neutralFill);
  expect(colorForOctets("0", "10")).toBe(neutralFill);
  expect(colorForOctets("nope", "10")).toBe(neutralFill);
  expect(colorForOctets("5", "nope")).toBe(neutralFill);
  expect(colorForOctets("5", "10")).not.toBe(neutralFill);
  const huge = "9007199254740993";
  expect(() => colorForOctets(huge, huge)).not.toThrow();
  expect(colorForOctets(huge, huge)).not.toBe(neutralFill);
  expect(() => colorForOctets("1", "9".repeat(400))).not.toThrow();
});
