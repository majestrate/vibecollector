import { expect, test } from "vitest";
import { intervalToken, parseInterval } from "./interval";

test("interval tokens match the server limits", () => {
  expect(intervalToken(15, "m")).toBe("15m");
  expect(intervalToken(24, "h")).toBe("24h");
  expect(intervalToken(366, "d")).toBe("366d");
  expect(parseInterval("90m")).toEqual({ n: 90, unit: "m" });
  expect(parseInterval("01m")).toBeNull();
  expect(parseInterval("1441m")).toBeNull();
  expect(parseInterval("25h")).toBeNull();
  expect(parseInterval("48h")).toBeNull();
  expect(parseInterval(null)).toBeNull();
  expect(() => intervalToken(0, "m")).toThrow(RangeError);
});
