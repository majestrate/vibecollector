import { afterEach, expect, test, vi } from "vitest";
import { bytesToBase64Url, sha256, sha256Bytes } from "./sha256";

const ABC = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const EMPTY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

afterEach(() => {
  vi.unstubAllGlobals();
});

function hex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

test("in-page SHA-256 matches the empty string and abc", () => {
  const enc = new TextEncoder();
  expect(hex(sha256Bytes(enc.encode("")))).toBe(EMPTY);
  expect(hex(sha256Bytes(enc.encode("abc")))).toBe(ABC);
});

test("PKCE S256 matches the RFC 7636 vector", () => {
  const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  const challenge = bytesToBase64Url(sha256Bytes(new TextEncoder().encode(verifier)));
  expect(challenge).toBe("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
});

test("sha256 uses the in-page hash when subtle.digest rejects", async () => {
  vi.stubGlobal("crypto", {
    subtle: { digest: () => Promise.reject(new Error("insecure")) },
  });
  const got = await sha256(new TextEncoder().encode("abc"));
  expect(hex(got)).toBe(ABC);
  vi.unstubAllGlobals();
});

test("sha256 uses the in-page hash when subtle is missing", async () => {
  vi.stubGlobal("crypto", {});
  const got = await sha256(new TextEncoder().encode("abc"));
  expect(hex(got)).toBe(ABC);
  vi.unstubAllGlobals();
});
