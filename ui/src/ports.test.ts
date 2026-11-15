import { expect, test } from "vitest";
import { portText } from "./ports";

test("transport ports stay numbers", () => {
  expect(portText(6, 80, 443)).toBe("80→443");
  expect(portText(17, 5353, 5353)).toBe("5353→5353");
  expect(portText(2, 0, 0)).toBe("0→0");
  expect(portText(0, 0, 0)).toBe("0→0");
  expect(portText(6, null, null)).toBe("→");
});

test("ICMP destination port is type and code", () => {
  expect(portText(1, 0, 0x0303)).toBe("0→3.3");
  expect(portText(1, 0, 0x0800)).toBe("0→8.0");
  expect(portText(58, 0, 0x8200)).toBe("0→130.0");
  expect(portText(58, 0, 0)).toBe("0→0");
  expect(portText(58, null, null)).toBe("→");
});
