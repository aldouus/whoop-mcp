import { expect, test } from "bun:test";
import {
  accessTokenTtlSeconds,
  applyTokenResponse,
  needsRefresh,
  REFRESH_SKEW_MS,
  refreshStored,
  shareRefresh,
  type WhoopTokenSet,
} from "./tokens";

const current: WhoopTokenSet = {
  accessToken: "old-access",
  refreshToken: "old-refresh",
  expiresAt: 1_000_000,
};

test("needsRefresh is true inside the skew window", () => {
  expect(needsRefresh(10_000, 10_000 - REFRESH_SKEW_MS)).toBe(true);
  expect(needsRefresh(10_000, 10_000 - REFRESH_SKEW_MS - 1)).toBe(false);
});

test("applyTokenResponse keeps the previous refresh token when whoop omits one", () => {
  const next = applyTokenResponse(current, { access_token: "new-access", expires_in: 3600 }, 5_000);
  expect(next).toEqual({
    accessToken: "new-access",
    refreshToken: "old-refresh",
    expiresAt: 5_000 + 3600 * 1000,
  });
});

test("applyTokenResponse persists a rotated refresh token", () => {
  const next = applyTokenResponse(
    current,
    { access_token: "new-access", refresh_token: "rotated", expires_in: 10 },
    5_000,
  );
  expect(next.refreshToken).toBe("rotated");
  expect(next.expiresAt).toBe(15_000);
});

test("applyTokenResponse rejects a body without an access token", () => {
  expect(() => applyTokenResponse(current, { refresh_token: "rotated" }, 0)).toThrow(
    /access_token/,
  );
});

test("concurrent callers share one refresh and a fresh token is reused", async () => {
  let calls = 0;
  const slot: { current: Promise<WhoopTokenSet> | null } = { current: null };
  let saved: WhoopTokenSet = { ...current, expiresAt: 0 };
  const stale: WhoopTokenSet = { ...current, expiresAt: 0 };
  const run = () =>
    shareRefresh(slot, () =>
      refreshStored(
        async () => saved,
        async (stored) => {
          calls += 1;
          await Promise.resolve();
          return {
            ...stored,
            accessToken: "rotated",
            refreshToken: "rotated",
            expiresAt: 9_000_000,
          };
        },
        async (next) => {
          saved = next;
        },
        stale,
        false,
        10_000,
      ),
    );
  const [first, second] = await Promise.all([run(), run()]);
  expect(calls).toBe(1);
  expect(second).toEqual(first);
  expect(first.refreshToken).toBe("rotated");
  const late = await run();
  expect(calls).toBe(1);
  expect(late).toEqual(first);
});

test("accessTokenTtlSeconds stays at the kv minimum", () => {
  expect(accessTokenTtlSeconds(200_000, 200_000)).toBe(60);
  expect(accessTokenTtlSeconds(200_000 + 500_000, 200_000)).toBe(380);
});
