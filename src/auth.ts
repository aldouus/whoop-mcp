import {
  AuthorizationError,
  type AuthRequest,
  type OAuthHelpers,
} from "@cloudflare/workers-oauth-provider";
import { Hono } from "hono";
import { handleHome, handleHomeCallback, handleLogin, handleLogout, homeState } from "./home";
import { allowlisted } from "./session";
import {
  WhoopError,
  exchangeAuthorizationCode,
  saveGrantTokens,
  scopesForWhoop,
  whoopGet,
  type WhoopProps,
} from "./whoop";

type Bindings = Env & { OAUTH_PROVIDER: OAuthHelpers };

const app = new Hono<{ Bindings: Bindings }>();

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => {
    switch (char) {
      case "&":
        return "&amp;";
      case "<":
        return "&lt;";
      case ">":
        return "&gt;";
      case '"':
        return "&quot;";
      default:
        return "&#39;";
    }
  });
}

function mergeHeaders(...groups: Array<Headers | undefined>): Headers {
  const headers = new Headers();
  for (const group of groups) {
    group?.forEach((value, key) => {
      if (key.toLowerCase() === "set-cookie") headers.append(key, value);
      else headers.set(key, value);
    });
  }
  return headers;
}

function authError(error: unknown): Response {
  if (error instanceof AuthorizationError) {
    if (error.redirectTo) return Response.redirect(error.redirectTo, 302);
    return new Response(error.description, { status: 400 });
  }
  console.error(
    JSON.stringify({ message: error instanceof Error ? error.message : "authorize failed" }),
  );
  return new Response("Internal server error", { status: 500 });
}

async function whoopUser(
  env: Env,
  accessToken: string,
): Promise<{ userId: string; label: string } | null> {
  let body: { user_id?: number | string; email?: string; first_name?: string };
  try {
    body = (await whoopGet(env, accessToken, "/v2/user/profile/basic")) as typeof body;
  } catch (error) {
    if (error instanceof WhoopError) return null;
    throw error;
  }
  const userId = String(body.user_id ?? "");
  if (!userId) return null;
  return { userId, label: body.email || body.first_name || userId };
}

async function digestId(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return base64Url(new Uint8Array(digest)).slice(0, 32);
}

function base64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

async function redirectToWhoop(
  c: { env: Bindings; req: { url: string } },
  request: AuthRequest,
  extra?: Headers,
): Promise<Response> {
  const codeVerifier = base64Url(crypto.getRandomValues(new Uint8Array(32)));
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(codeVerifier));
  const upstream = await c.env.OAUTH_PROVIDER.beginUpstream(request, { data: { codeVerifier } });
  const url = new URL(c.env.WHOOP_AUTH_URL);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("client_id", c.env.WHOOP_CLIENT_ID);
  url.searchParams.set("redirect_uri", new URL("/callback", c.req.url).href);
  url.searchParams.set("scope", scopesForWhoop(request.scope).join(" "));
  url.searchParams.set("code_challenge", base64Url(new Uint8Array(digest)));
  url.searchParams.set("code_challenge_method", "S256");
  url.searchParams.set("state", upstream.state);
  const headers = mergeHeaders(extra, upstream.headers);
  headers.set("location", url.href);
  return new Response(null, { status: 302, headers });
}

app.get("/authorize", async (c) => {
  try {
    const request = await c.env.OAUTH_PROVIDER.parseAuthRequest(c.req.raw);
    if (!request.clientId) return c.text("Invalid request", 400);
    const remembered = await c.env.OAUTH_PROVIDER.isConsentRemembered(c.req.raw, request, {
      secret: c.env.COOKIE_ENCRYPTION_KEY,
    });
    if (remembered) return redirectToWhoop(c, request);
    const [consent, described] = await Promise.all([
      c.env.OAUTH_PROVIDER.beginConsent(request),
      c.env.OAUTH_PROVIDER.describeConsent(request),
    ]);
    const headers = mergeHeaders(consent.headers);
    headers.set("content-type", "text/html; charset=utf-8");
    const whoop = new URL(c.env.WHOOP_AUTH_URL).origin;
    const client = new URL(described.redirectUri);
    const clientSource =
      client.protocol === "http:" || client.protocol === "https:" ? client.origin : client.protocol;
    headers.set(
      "content-security-policy",
      `default-src 'none'; form-action 'self' ${whoop} https://id.whoop.com ${clientSource}; base-uri 'none'; frame-ancestors 'none'`,
    );
    headers.set(
      "permissions-policy",
      "accelerometer=(), camera=(), geolocation=(), microphone=(), payment=()",
    );
    const scopes = described.scope.map((scope) => `<li>${escapeHtml(scope)}</li>`).join("");
    const html = `<!doctype html>
<meta charset="utf-8">
<title>Connect WHOOP</title>
<h1>Connect WHOOP</h1>
<p>${escapeHtml(described.clientName)} is asking to read your WHOOP account.</p>
<p>Tokens will be sent to ${escapeHtml(described.redirectHost)}.</p>
<ul>${scopes}</ul>
<form method="post" action="/authorize">
<input type="hidden" name="handle" value="${escapeHtml(consent.handle)}">
<button type="submit" name="approve" value="yes">Allow</button>
<button type="submit" name="approve" value="no">Deny</button>
</form>`;
    return new Response(html, { headers });
  } catch (error) {
    return authError(error);
  }
});

app.post("/authorize", async (c) => {
  try {
    const form = await c.req.formData();
    const handle = form.get("handle");
    if (typeof handle !== "string" || !handle) return c.text("Missing consent handle", 400);
    if (form.get("approve") !== "yes") {
      const denied = await c.env.OAUTH_PROVIDER.denyConsent(c.req.raw, handle);
      const headers = mergeHeaders(denied.headers);
      headers.set("location", denied.redirectTo);
      return new Response(null, { status: 302, headers });
    }
    const approved = await c.env.OAUTH_PROVIDER.approveConsent(c.req.raw, handle, {
      remember: { secret: c.env.COOKIE_ENCRYPTION_KEY },
    });
    return redirectToWhoop(c, approved.request, approved.headers);
  } catch (error) {
    return authError(error);
  }
});

app.get("/", (c) => handleHome(c));
app.get("/login", (c) => handleLogin(c));
app.post("/logout", (c) => handleLogout(c));

app.get("/callback", async (c) => {
  if (homeState(c.req.query("state"))) return handleHomeCallback(c);
  try {
    const resumed = await c.env.OAUTH_PROVIDER.finishUpstream<{ codeVerifier?: string }>(c.req.raw);
    const code = c.req.query("code");
    const codeVerifier = resumed.data?.codeVerifier;
    if (!code || !codeVerifier) return c.text("Missing code", 400);
    const redirectUri = new URL("/callback", c.req.url).href;
    const scope = scopesForWhoop(resumed.request.scope);
    const tokens = await exchangeAuthorizationCode(c.env, code, redirectUri, codeVerifier);
    const user = scope.includes("read:profile") ? await whoopUser(c.env, tokens.accessToken) : null;
    if (scope.includes("read:profile") && !user) return c.text("WHOOP profile request failed", 502);
    const userId = user?.userId ?? (await digestId(tokens.refreshToken));
    if (!userId || userId.includes(":")) return c.text("WHOOP profile missing user id", 502);
    if (!allowlisted(userId, c.env.ALLOWED_WHOOP_USER_ID)) return c.text("forbidden", 403);
    const { redirectTo } = await c.env.OAUTH_PROVIDER.completeAuthorization({
      request: resumed.request,
      userId,
      metadata: { label: user?.label || userId },
      scope,
      props: { ...tokens, userId, grantId: "", scope },
    });
    const grantId = new URL(redirectTo).searchParams.get("code")?.split(":")[1] ?? "";
    if (!grantId) return c.text("Missing grant", 500);
    const props: WhoopProps = { ...tokens, userId, grantId, scope };
    await saveGrantTokens(c.env, props);
    const headers = mergeHeaders(resumed.headers);
    headers.set("location", redirectTo);
    return new Response(null, { status: 302, headers });
  } catch (error) {
    return authError(error);
  }
});

export default app;
