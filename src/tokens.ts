export const REFRESH_SKEW_MS = 60_000;
const DEFAULT_EXPIRES_IN_SECONDS = 3600;
const MCP_TOKEN_BUFFER_SECONDS = 120;
const MIN_ACCESS_TOKEN_TTL_SECONDS = 60;

export type WhoopTokenSet = {
  accessToken: string;
  refreshToken: string;
  expiresAt: number;
};

export type WhoopTokenResponse = {
  access_token?: string;
  refresh_token?: string;
  expires_in?: number;
};

export function needsRefresh(expiresAt: number, now: number): boolean {
  return now >= expiresAt - REFRESH_SKEW_MS;
}

export function applyTokenResponse(
  current: WhoopTokenSet,
  body: WhoopTokenResponse,
  now: number,
): WhoopTokenSet {
  if (!body.access_token) {
    throw new Error("WHOOP token response missing access_token");
  }
  const expiresIn =
    typeof body.expires_in === "number" ? body.expires_in : DEFAULT_EXPIRES_IN_SECONDS;
  return {
    accessToken: body.access_token,
    refreshToken: body.refresh_token || current.refreshToken,
    expiresAt: now + expiresIn * 1000,
  };
}

export function accessTokenTtlSeconds(expiresAt: number, now: number): number {
  const seconds = Math.floor((expiresAt - now) / 1000) - MCP_TOKEN_BUFFER_SECONDS;
  return Math.max(MIN_ACCESS_TOKEN_TTL_SECONDS, seconds);
}

export function shareRefresh<T>(
  slot: { current: Promise<T> | null },
  run: () => Promise<T>,
): Promise<T> {
  slot.current ??= run().finally(() => {
    slot.current = null;
  });
  return slot.current;
}

export async function refreshStored<T extends WhoopTokenSet>(
  read: () => Promise<T | undefined>,
  refresh: (current: T) => Promise<T>,
  write: (next: T) => Promise<void>,
  fallback: T,
  force: boolean,
  now: number,
): Promise<T> {
  const stored = (await read()) ?? fallback;
  if (!force && !needsRefresh(stored.expiresAt, now)) return stored;
  const next = await refresh(stored);
  await write(next);
  return next;
}
