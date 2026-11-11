import { expect, test } from "vitest";
import { appPath, pageBase, rooted } from "./base";

test("page base comes from the browser path", () => {
  expect(pageBase("/flows")).toBe("");
  expect(pageBase("/")).toBe("");
  expect(pageBase("/app")).toBe("/app");
  expect(pageBase("/app/")).toBe("/app");
  expect(pageBase("/app/flows")).toBe("/app");
  expect(pageBase("/app/callback")).toBe("/app");
  expect(pageBase("/app/credentials")).toBe("/app");
  expect(appPath("/app/talkers")).toBe("/talkers");
  expect(appPath("/talkers")).toBe("/talkers");
  expect(appPath("/app/")).toBe("/");
});

test("rooted uses the current page when window is set", () => {
  expect(rooted("/openapi.json")).toBe("/openapi.json");
});
