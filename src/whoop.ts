import { DurableObject } from "cloudflare:workers";
import {
  accessTokenTtlSeconds,
  applyTokenResponse,
  needsRefresh,
  refreshStored,
  shareRefresh,
  type WhoopTokenResponse,
  type WhoopTokenSet,
} from "./tokens";

export const WHOOP_SCOPES = [
  "offline",
  "read:profile",
  "read:body_measurement",
  "read:cycles",
  "read:recovery",
  "read:sleep",
  "read:workout",
] as const;

export type WhoopProps = WhoopTokenSet & {
  userId: string;
  grantId: string;
  scope: string[];
};

const READ_SCOPES = WHOOP_SCOPES.filter((scope) => scope !== "offline");

export function scopesForWhoop(approved: readonly string[]): string[] {
  const granted = new Set(approved);
  return ["offline", ...READ_SCOPES.filter((scope) => granted.has(scope))];
}

export class WhoopError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
    this.name = "WhoopError";
  }
}

function grantStub(env: Env, grantId: string): DurableObjectStub<WhoopGrant> {
  return env.WHOOP_GRANT.get(env.WHOOP_GRANT.idFromName(grantId));
}

export class WhoopGrant extends DurableObject<Env> {
  private inflight: { current: Promise<WhoopProps> | null } = { current: null };

  async save(props: WhoopProps): Promise<void> {
    await this.ctx.storage.put("tokens", props);
  }

  async ensure(props: WhoopProps, force = false): Promise<WhoopProps> {
    return shareRefresh(this.inflight, () =>
      refreshStored(
        () => this.ctx.storage.get<WhoopProps>("tokens"),
        async (stored) => ({ ...stored, ...(await refreshWhoopTokens(this.env, stored)) }),
        (next) => this.ctx.storage.put("tokens", next),
        props,
        force,
        Date.now(),
      ),
    );
  }
}

export async function saveGrantTokens(env: Env, props: WhoopProps): Promise<void> {
  await grantStub(env, props.grantId).save(props);
}

async function tokenRequest(env: Env, body: URLSearchParams): Promise<WhoopTokenResponse> {
  const response = await fetch(env.WHOOP_TOKEN_URL, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body,
  });
  if (!response.ok) {
    throw new WhoopError(`WHOOP token request failed (${response.status})`, response.status);
  }
  return (await response.json()) as WhoopTokenResponse;
}

export async function exchangeAuthorizationCode(
  env: Env,
  code: string,
  redirectUri: string,
  codeVerifier: string,
  now = Date.now(),
): Promise<WhoopTokenSet> {
  const body = await tokenRequest(
    env,
    new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri,
      client_id: env.WHOOP_CLIENT_ID,
      client_secret: env.WHOOP_CLIENT_SECRET,
      code_verifier: codeVerifier,
    }),
  );
  return applyTokenResponse({ accessToken: "", refreshToken: "", expiresAt: 0 }, body, now);
}

export async function refreshWhoopTokens(
  env: Env,
  current: WhoopTokenSet,
  now = Date.now(),
): Promise<WhoopTokenSet> {
  const body = await tokenRequest(
    env,
    new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: current.refreshToken,
      client_id: env.WHOOP_CLIENT_ID,
      client_secret: env.WHOOP_CLIENT_SECRET,
    }),
  );
  return applyTokenResponse(current, body, now);
}

export async function ensureFresh(env: Env, props: WhoopProps): Promise<WhoopProps> {
  return grantStub(env, props.grantId).ensure(props, false);
}

async function forceRefresh(env: Env, props: WhoopProps): Promise<WhoopProps> {
  return grantStub(env, props.grantId).ensure(props, true);
}

export function mcpAccessTtl(props: WhoopProps, now = Date.now()): number {
  return accessTokenTtlSeconds(props.expiresAt, now);
}

export async function whoopGet(
  env: Env,
  accessToken: string,
  path: string,
  params?: Record<string, string | number | undefined>,
): Promise<unknown> {
  const url = new URL(`${env.WHOOP_API_BASE}${path}`);
  for (const [key, value] of Object.entries(params ?? {})) {
    if (value !== undefined) url.searchParams.set(key, String(value));
  }
  const response = await fetch(url, { headers: { authorization: `Bearer ${accessToken}` } });
  if (response.status === 401) throw new WhoopError("WHOOP access token rejected", 401);
  if (response.status === 429) {
    throw new WhoopError(
      `WHOOP rate limit exceeded. Remaining: ${response.headers.get("X-RateLimit-Remaining") ?? "?"}, resets in ${response.headers.get("X-RateLimit-Reset") ?? "?"}s.`,
      429,
    );
  }
  if (!response.ok) {
    throw new WhoopError(
      `WHOOP API error ${response.status}: ${await response.text()}`,
      response.status,
    );
  }
  return response.json();
}

export async function withWhoop<T>(
  env: Env,
  props: WhoopProps,
  run: (accessToken: string) => Promise<T>,
): Promise<T> {
  const tokens = needsRefresh(props.expiresAt, Date.now()) ? await ensureFresh(env, props) : props;
  try {
    return await run(tokens.accessToken);
  } catch (error) {
    if (!(error instanceof WhoopError) || error.status !== 401) throw error;
    const refreshed = await forceRefresh(env, tokens);
    return run(refreshed.accessToken);
  }
}
