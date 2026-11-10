import { describe, expect, test } from "vitest";
import { calendarRange, civilInstant } from "./filters";

describe("calendar", () => {
  test("fold and gap instants", () => {
    const rows: [string, string, string, boolean][] = [
      ["2026-03-08T00:00:00", "America/New_York", "2026-03-08T05:00:00Z", false],
      ["2026-11-01T00:00:00", "America/New_York", "2026-11-01T04:00:00Z", false],
      ["2026-11-01T01:30:00", "America/New_York", "2026-11-01T05:30:00Z", false],
      ["2026-03-08T02:30:00", "America/New_York", "2026-03-08T07:00:00Z", true],
      ["2026-04-05T01:45:00", "Australia/Lord_Howe", "2026-04-04T14:45:00Z", false],
    ];
    for (const [civil, tz, utc, adjusted] of rows) {
      const got = civilInstant(civil, tz);
      expect(got.utc, civil).toBe(utc);
      expect(got.boundaryAdjusted, civil).toBe(adjusted);
    }
    const spring = calendarRange("2026-03-08", "America/New_York");
    expect(spring.start).toBe("2026-03-08T05:00:00Z");
    expect(spring.end).toBe("2026-03-09T04:00:00Z");
    expect(spring.boundaryAdjusted).toBe(false);
    const fall = calendarRange("2026-11-01", "America/New_York");
    expect(fall.start).toBe("2026-11-01T04:00:00Z");
    expect(fall.end).toBe("2026-11-02T05:00:00Z");
    expect(fall.boundaryAdjusted).toBe(false);
    const utc = calendarRange("2026-11-01", "");
    expect(utc.start).toBe("2026-11-01T00:00:00Z");
    expect(utc.end).toBe("2026-11-02T00:00:00Z");
    expect(utc.boundaryAdjusted).toBe(false);
  });

  test("bad day and zone throw", () => {
    expect(() => calendarRange("2026-02-31", "UTC")).toThrow(RangeError);
    expect(() => calendarRange("2026-03-08", "Not/A_Zone")).toThrow(RangeError);
    expect(() => civilInstant("2026-03-08T02:30:00", "Not/A_Zone")).toThrow(RangeError);
  });
});
