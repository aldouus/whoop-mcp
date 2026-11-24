import { expect, test } from "bun:test";
import { allowlisted, sessionCurrent } from "./session";

test("allowlist is open when no user id is configured", () => {
  expect(allowlisted("42", undefined)).toBe(true);
  expect(allowlisted("42", "")).toBe(true);
  expect(allowlisted("42", " , ")).toBe(true);
  expect(allowlisted("", undefined)).toBe(false);
});

test("allowlist accepts only the configured whoop users", () => {
  expect(allowlisted("42", "42")).toBe(true);
  expect(allowlisted("7", "42, 7")).toBe(true);
  expect(allowlisted("1", "42")).toBe(false);
  expect(allowlisted("", "42")).toBe(false);
});

test("session is current only before its expiry", () => {
  expect(sessionCurrent(1_000, 999)).toBe(true);
  expect(sessionCurrent(1_000, 1_000)).toBe(false);
  expect(sessionCurrent(Number.NaN, 1)).toBe(false);
});
