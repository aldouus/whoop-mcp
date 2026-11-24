import { refreshStored, shareRefresh, type WhoopTokenSet } from "./tokens";
import {
  allowlisted,
  isHomeState,
  readState,
  seal,
  sessionCurrent,
  signState,
  unseal,
} from "./session";
import { WhoopError, exchangeAuthorizationCode, refreshWhoopTokens, whoopGet } from "./whoop";

const COOKIE = "whoop_session";
const TTL_MS = 7 * 24 * 60 * 60 * 1000;
const STATE_TTL_MS = 10 * 60 * 1000;
const SCOPES = "offline read:profile read:recovery read:sleep read:cycles";

type HomeContext = {
  env: Env;
  req: {
    url: string;
    raw: Request;
    header: (name: string) => string | undefined;
    query: (name: string) => string | undefined;
  };
};

type SessionRecord = WhoopTokenSet & { userId: string; exp: number };

const inflight = new Map<string, { current: Promise<SessionRecord> | null }>();

function encode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function securityHeaders(contentType?: string, formAction = "'self'"): Headers {
  const headers = new Headers({
    "cache-control": "no-store",
    "content-security-policy": `default-src 'none'; form-action ${formAction}; base-uri 'none'; frame-ancestors 'none'`,
    "permissions-policy": "accelerometer=(), camera=(), geolocation=(), microphone=(), payment=()",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "x-content-type-options": "nosniff",
  });
  if (contentType) headers.set("content-type", contentType);
  return headers;
}

function text(body: string, status: number, extra?: Headers): Response {
  const headers = securityHeaders("text/plain; charset=utf-8");
  extra?.forEach((value, key) => {
    if (key.toLowerCase() === "set-cookie") headers.append(key, value);
    else headers.set(key, value);
  });
  return new Response(body, { status, headers });
}

function redirect(location: string, extra?: Headers): Response {
  const headers = securityHeaders();
  headers.set("location", location);
  extra?.forEach((value, key) => {
    if (key.toLowerCase() === "set-cookie") headers.append(key, value);
  });
  return new Response(null, { status: 302, headers });
}

function cookie(value: string, maxAge: number): string {
  return `${COOKIE}=${value}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

function clearCookie(): string {
  return cookie("", 0);
}

function readCookie(header: string | null): string | undefined {
  if (!header) return undefined;
  for (const part of header.split(";")) {
    const [name, ...rest] = part.trim().split("=");
    if (name === COOKIE) return rest.join("=");
  }
  return undefined;
}

async function openCookie(
  secret: string,
  header: string | null,
  now: number,
): Promise<
  | { kind: "missing" }
  | { kind: "rejected" }
  | { kind: "expired" }
  | { kind: "ok"; sid: string; exp: number }
> {
  const token = readCookie(header);
  if (!token) return { kind: "missing" };
  const plain = await unseal(secret, token);
  if (!plain) return { kind: "rejected" };
  let parsed: { sid?: unknown; exp?: unknown };
  try {
    parsed = JSON.parse(plain) as { sid?: unknown; exp?: unknown };
  } catch {
    return { kind: "rejected" };
  }
  if (typeof parsed.sid !== "string" || typeof parsed.exp !== "number") return { kind: "rejected" };
  if (!sessionCurrent(parsed.exp, now)) return { kind: "expired" };
  return { kind: "ok", sid: parsed.sid, exp: parsed.exp };
}

function kvKey(sid: string): string {
  return `stats:${sid}`;
}

async function readRecord(env: Env, sid: string): Promise<SessionRecord | undefined> {
  return (await env.OAUTH_KV.get(kvKey(sid), "json")) ?? undefined;
}

async function writeRecord(env: Env, sid: string, record: SessionRecord): Promise<void> {
  await env.OAUTH_KV.put(kvKey(sid), JSON.stringify(record), {
    expiration: Math.floor(record.exp / 1000),
  });
}

async function freshRecord(env: Env, sid: string, fallback: SessionRecord): Promise<SessionRecord> {
  let slot = inflight.get(sid);
  if (!slot) {
    slot = { current: null };
    inflight.set(sid, slot);
  }
  return shareRefresh(slot, () =>
    refreshStored(
      () => readRecord(env, sid),
      async (stored) => ({ ...stored, ...(await refreshWhoopTokens(env, stored)) }),
      (next) => writeRecord(env, sid, next),
      fallback,
      false,
      Date.now(),
    ),
  );
}

function sameOrigin(request: Request): boolean {
  const origin = request.headers.get("origin");
  return origin !== null && origin === new URL(request.url).origin;
}

function signedOut(): Response {
  const html = `<!doctype html>
<meta charset="utf-8">
<title>WHOOP</title>
<a href="/login">sign in with whoop</a>`;
  return new Response(html, { headers: securityHeaders("text/html; charset=utf-8") });
}

const TZ = "America/New_York";
type Row = Record<string, unknown>;

function rows(body: unknown): Row[] {
  if (!body || typeof body !== "object") return [];
  const list = (body as { records?: unknown }).records;
  return Array.isArray(list)
    ? list.filter((item): item is Row => !!item && typeof item === "object")
    : [];
}

function nyKey(ms: number): string {
  return new Intl.DateTimeFormat("en-CA", {
    timeZone: TZ,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).format(new Date(ms));
}

function nyLabel(key: string): string {
  const [year, month, day] = key.split("-").map(Number);
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: "UTC",
    weekday: "short",
    month: "short",
    day: "numeric",
    year: "numeric",
  }).formatToParts(new Date(Date.UTC(year, month - 1, day)));
  const get = (type: string) => parts.find((part) => part.type === type)?.value ?? "";
  return `${get("weekday")} ${get("month")} ${get("day")} ${get("year")}`.toLowerCase();
}

function dayKeys(now: number): string[] {
  const [year, month, day] = nyKey(now).split("-").map(Number);
  return Array.from({ length: 7 }, (_, index) =>
    new Date(Date.UTC(year, month - 1, day - index)).toISOString().slice(0, 10),
  );
}

function num(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function shown(value: number | undefined, digits: number, suffix = ""): string {
  if (value === undefined) return "-";
  const text = digits === 0 ? String(Math.round(value)) : value.toFixed(digits);
  return `${text}${suffix}`;
}

function sleepDuration(summary: unknown): number | undefined {
  if (!summary || typeof summary !== "object") return undefined;
  const stages = summary as Row;
  const milli = [
    "total_light_sleep_time_milli",
    "total_slow_wave_sleep_time_milli",
    "total_rem_sleep_time_milli",
  ].reduce((sum, key) => sum + (num(stages[key]) ?? 0), 0);
  if (milli <= 0) return undefined;
  return milli / 60_000;
}

function sleepText(minutes: number | undefined): string {
  if (minutes === undefined) return "-";
  const rounded = Math.round(minutes);
  return `${Math.floor(rounded / 60)}h ${rounded % 60}m`;
}

function scoreOf(row: Row | undefined): Row | undefined {
  if (!row || row.score_state !== "SCORED" || !row.score || typeof row.score !== "object")
    return undefined;
  return row.score as Row;
}

let loggedShape = false;

function logShape(cycles: Row[], recoveries: Row[], sleeps: Row[]): void {
  if (loggedShape) return;
  loggedShape = true;
  const shape = (list: Row[], idKey: string) =>
    list.map((row) => ({
      id: row[idKey],
      score_state: row.score_state ?? null,
      score: row.score && typeof row.score === "object" ? Object.keys(row.score) : null,
    }));
  console.log(
    JSON.stringify({
      cycles: shape(cycles, "id"),
      recoveries: shape(recoveries, "cycle_id"),
      sleeps: shape(sleeps, "cycle_id"),
    }),
  );
}

async function renderStats(env: Env, accessToken: string, now: number): Promise<string> {
  const start = new Date(now - 8 * 24 * 60 * 60 * 1000).toISOString();
  const end = new Date(now + 24 * 60 * 60 * 1000).toISOString();
  const params = { limit: 25, start, end };
  const [recoveryBody, sleepBody, cycleBody] = await Promise.all([
    whoopGet(env, accessToken, "/v2/recovery", params),
    whoopGet(env, accessToken, "/v2/activity/sleep", params),
    whoopGet(env, accessToken, "/v2/cycle", params),
  ]);
  const cycles = rows(cycleBody);
  const recoveries = rows(recoveryBody);
  const sleeps = rows(sleepBody);
  logShape(cycles, recoveries, sleeps);
  const recoveryByCycle = new Map(recoveries.map((row) => [String(row.cycle_id), row]));
  const sleepByCycle = new Map<string, Row>();
  for (const sleep of sleeps) {
    const id = String(sleep.cycle_id);
    const current = sleepByCycle.get(id);
    if (!current || (current.nap === true && sleep.nap !== true)) sleepByCycle.set(id, sleep);
  }
  const cycleByDay = new Map<string, Row>();
  for (const cycle of cycles) {
    const when = typeof cycle.end === "string" ? Date.parse(cycle.end) : now;
    if (!Number.isFinite(when)) continue;
    const key = nyKey(when);
    const current = cycleByDay.get(key);
    const startMs = typeof cycle.start === "string" ? Date.parse(cycle.start) : 0;
    const currentStart =
      current && typeof current.start === "string" ? Date.parse(current.start) : 0;
    if (!current || startMs > currentStart) cycleByDay.set(key, cycle);
  }
  const scored = cycles
    .map((cycle) => ({ cycle, score: scoreOf(recoveryByCycle.get(String(cycle.id))) }))
    .filter((item): item is { cycle: Row; score: Row } => item.score !== undefined)
    .sort(
      (a, b) => Date.parse(String(b.cycle.start ?? "")) - Date.parse(String(a.cycle.start ?? "")),
    );
  return dayKeys(now)
    .map((key, index) => {
      const cycle = cycleByDay.get(key);
      const own = cycle ? scoreOf(recoveryByCycle.get(String(cycle.id))) : undefined;
      const recovery = index === 0 ? (own ?? scored[0]?.score) : own;
      const sleepScore = scoreOf(cycle ? sleepByCycle.get(String(cycle.id)) : undefined);
      const cycleScore = scoreOf(cycle);
      const lines = [
        index === 0 ? `${nyLabel(key)} [today]` : nyLabel(key),
        `recovery ${shown(num(recovery?.recovery_score), 0, "%")}`,
        `hrv ${shown(num(recovery?.hrv_rmssd_milli), 0)}`,
        `rhr ${shown(num(recovery?.resting_heart_rate), 0)}`,
        `sleep ${sleepText(sleepDuration(sleepScore?.stage_summary))}`,
        `performance ${shown(num(sleepScore?.sleep_performance_percentage), 0, "%")}`,
        `strain ${shown(num(cycleScore?.strain), 1)}`,
      ];
      return lines.join("\n");
    })
    .join("\n\n-----\n\n");
}

export function homeState(state: string | undefined): boolean {
  return isHomeState(state);
}

export async function handleHome(c: HomeContext): Promise<Response> {
  const now = Date.now();
  const opened = await openCookie(c.env.COOKIE_ENCRYPTION_KEY, c.req.header("cookie") ?? null, now);
  if (opened.kind === "rejected")
    return text("rejected", 401, new Headers({ "set-cookie": clearCookie() }));
  if (opened.kind !== "ok") {
    const headers =
      opened.kind === "expired" ? new Headers({ "set-cookie": clearCookie() }) : undefined;
    const page = signedOut();
    if (headers) headers.forEach((value, key) => page.headers.append(key, value));
    return page;
  }
  const stored = await readRecord(c.env, opened.sid);
  if (
    !stored ||
    !allowlisted(stored.userId, c.env.ALLOWED_WHOOP_USER_ID) ||
    !sessionCurrent(stored.exp, now)
  ) {
    await c.env.OAUTH_KV.delete(kvKey(opened.sid));
    return text("rejected", 401, new Headers({ "set-cookie": clearCookie() }));
  }
  try {
    const fresh = await freshRecord(c.env, opened.sid, stored);
    return text(await renderStats(c.env, fresh.accessToken, now), 200);
  } catch (error) {
    const message = error instanceof WhoopError ? error.message : "WHOOP request failed";
    return text(message, 502);
  }
}

export async function handleLogin(c: HomeContext): Promise<Response> {
  const verifier = encode(crypto.getRandomValues(new Uint8Array(32)));
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(verifier));
  const state = await signState(c.env.COOKIE_ENCRYPTION_KEY, verifier, Date.now() + STATE_TTL_MS);
  const url = new URL(c.env.WHOOP_AUTH_URL);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", c.env.WHOOP_CLIENT_ID);
  url.searchParams.set("redirect_uri", new URL("/callback", c.req.url).href);
  url.searchParams.set("scope", SCOPES);
  url.searchParams.set("code_challenge", encode(new Uint8Array(digest)));
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("state", state);
  return redirect(url.href);
}

export async function handleHomeCallback(c: HomeContext): Promise<Response> {
  const now = Date.now();
  const state = c.req.query("state") ?? "";
  const pending = await readState(c.env.COOKIE_ENCRYPTION_KEY, state, now);
  const code = c.req.query("code");
  if (!pending || !code) return text("missing code", 400);
  const redirectUri = new URL("/callback", c.req.url).href;
  let tokens: WhoopTokenSet;
  try {
    tokens = await exchangeAuthorizationCode(c.env, code, redirectUri, pending.verifier, now);
  } catch (error) {
    const message = error instanceof WhoopError ? error.message : "WHOOP token request failed";
    return text(message, 502);
  }
  let profile: { user_id?: number | string };
  try {
    profile = (await whoopGet(
      c.env,
      tokens.accessToken,
      "/v2/user/profile/basic",
    )) as typeof profile;
  } catch (error) {
    const message = error instanceof WhoopError ? error.message : "WHOOP profile request failed";
    return text(message, 502);
  }
  const userId = String(profile.user_id ?? "");
  if (!allowlisted(userId, c.env.ALLOWED_WHOOP_USER_ID)) return text("forbidden", 403);
  const sid = encode(crypto.getRandomValues(new Uint8Array(32)));
  const exp = now + TTL_MS;
  const record: SessionRecord = { ...tokens, userId, exp };
  await writeRecord(c.env, sid, record);
  const sealed = await seal(c.env.COOKIE_ENCRYPTION_KEY, JSON.stringify({ sid, exp }));
  return redirect("/", new Headers({ "set-cookie": cookie(sealed, Math.floor(TTL_MS / 1000)) }));
}

export async function handleLogout(c: HomeContext): Promise<Response> {
  if (!sameOrigin(c.req.raw)) return text("forbidden", 403);
  const opened = await openCookie(
    c.env.COOKIE_ENCRYPTION_KEY,
    c.req.header("cookie") ?? null,
    Date.now(),
  );
  if (opened.kind === "ok") await c.env.OAUTH_KV.delete(kvKey(opened.sid));
  return text("signed out", 200, new Headers({ "set-cookie": clearCookie() }));
}
