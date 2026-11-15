import { expect, test } from "vitest";
import { addressScope, isYggdrasil } from "./scope";

test("200::/7 is yggdrasil and 2000::/3 is not", () => {
  expect(isYggdrasil("200::")).toBe(true);
  expect(isYggdrasil("200::1")).toBe(true);
  expect(isYggdrasil("200::8.8.8.8")).toBe(true);
  expect(isYggdrasil("200:0:0:0:0:0:0:1")).toBe(true);
  expect(isYggdrasil("300::1")).toBe(true);
  expect(isYggdrasil("3ff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")).toBe(true);
  expect(isYggdrasil("1ff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")).toBe(false);
  expect(isYggdrasil("400::")).toBe(false);
  expect(isYggdrasil("2000::1")).toBe(false);
  expect(isYggdrasil("2001:db8::1")).toBe(false);
  expect(isYggdrasil("2002:808:808::")).toBe(false);
  expect(isYggdrasil("::1")).toBe(false);
  expect(isYggdrasil("::ffff:8.8.8.8")).toBe(false);
  expect(isYggdrasil("8.8.8.8")).toBe(false);
  expect(isYggdrasil("10.1.1.1")).toBe(false);
  expect(isYggdrasil("")).toBe(false);
});

test("the flow badge labels 200::/7 even when the stored scope is global", () => {
  expect(addressScope("200::1", "global")).toBe("yggdrasil");
  expect(addressScope("200::1", undefined)).toBe("yggdrasil");
  expect(addressScope("300::1", "yggdrasil")).toBe("yggdrasil");
  expect(addressScope("2000::1", "global")).toBeUndefined();
  expect(addressScope("2002:808:808::", "global")).toBeUndefined();
  expect(addressScope("8.8.8.8", "global")).toBeUndefined();
  expect(addressScope("10.1.1.1", "private")).toBe("private");
  expect(addressScope("2001:db8::1", "documentation")).toBe("documentation");
  expect(addressScope("not-an-ip", "yggdrasil")).toBe("yggdrasil");
});
