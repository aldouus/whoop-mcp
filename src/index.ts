import { env } from "cloudflare:workers";
import OAuthProvider from "@cloudflare/workers-oauth-provider";
import { createMcpHandler } from "agents/mcp/server";
import auth from "./auth";
import { createWhoopServer } from "./mcp";
import { WHOOP_SCOPES, WhoopGrant, ensureFresh, mcpAccessTtl, type WhoopProps } from "./whoop";

export { WhoopGrant };

const mcpPath = "/mcp";

// OAuthProvider calls fetch(request, env, ctx). createMcpHandler's fetch drops ctx, which holds the verified grant.
const whoopMcp = createMcpHandler(createWhoopServer, { route: mcpPath });

export default new OAuthProvider<Env>({
  apiRoute: mcpPath,
  apiHandler: {
    fetch: (request, _env, ctx) => whoopMcp(request, _env, ctx),
  },
  authorizeEndpoint: "/authorize",
  tokenEndpoint: "/token",
  clientRegistrationEndpoint: "/register",
  defaultHandler: auth,
  scopesSupported: [...WHOOP_SCOPES],
  resourceMetadata: { resource: env.MCP_RESOURCE },
  tokenExchangeCallback: async ({ props, env: workerEnv, grantId, userId }) => {
    const fresh = await ensureFresh(workerEnv, { ...(props as WhoopProps), grantId, userId });
    return { newProps: { ...fresh, grantId, userId }, accessTokenTTL: mcpAccessTtl(fresh) };
  },
});
