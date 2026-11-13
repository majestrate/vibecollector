import { expect, test } from "vitest";
import { formatScale } from "./scale";

test("formatScale uses 1000-based prefixes", () => {
  expect(formatScale(0)).toBe("0");
  expect(formatScale(12)).toBe("12");
  expect(formatScale(999)).toBe("999");
  expect(formatScale(1000)).toBe("1K");
  expect(formatScale(1500)).toBe("1.5K");
  expect(formatScale(1490)).toBe("1.49K");
  expect(formatScale(1_000_000)).toBe("1M");
  expect(formatScale(2_500_000_000)).toBe("2.5G");
  expect(formatScale(1e12)).toBe("1T");
  expect(formatScale(2.5e15)).toBe("2.5P");
  expect(formatScale(1e18)).toBe("1E");
  expect(formatScale(1e21)).toBe("1Z");
  expect(formatScale(1e24)).toBe("1Y");
  expect(formatScale(1e27)).toBe("1R");
  expect(formatScale(1e30)).toBe("1Q");
  expect(formatScale(999_500)).toBe("1M");
  expect(formatScale(-1500)).toBe("-1.5K");
  expect(formatScale(Number.NaN)).toBe("");
});
