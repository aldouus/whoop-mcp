# whoop-mcp

Read-only WHOOP MCP server on a Cloudflare Worker. The worker is the OAuth server (dynamic client registration and PKCE). WHOOP is the upstream identity provider.

## Setup

1. Create a WHOOP developer app. Set the redirect URL to `https://<your-host>/callback`. Request the scopes `offline`, `read:profile`, `read:body_measurement`, `read:cycles`, `read:recovery`, `read:sleep`, and `read:workout`.

2. `OAUTH_KV` in `wrangler.jsonc` is the namespace `be81710cd7d84224928b010cf859fe0e`.

3. `MCP_RESOURCE` is the public MCP URL, `https://<your-host>/mcp`. The authorization server issuer and the WHOOP redirect (`/callback`) follow the request origin. The protected resource is `MCP_RESOURCE`.

4. Set the secrets (do not commit them). `COOKIE_ENCRYPTION_KEY` must be at least 32 characters (`openssl rand -hex 32`). `ALLOWED_WHOOP_USER_ID` is optional: a comma-separated list of WHOOP user ids. When it is non-empty, only those accounts can connect. When it is empty, any WHOOP account can connect.

   ```bash
   bunx wrangler secret put WHOOP_CLIENT_ID
   bunx wrangler secret put WHOOP_CLIENT_SECRET
   bunx wrangler secret put COOKIE_ENCRYPTION_KEY
   bunx wrangler secret put MCP_RESOURCE
   bunx wrangler secret put ALLOWED_WHOOP_USER_ID
   ```

5. Deploy:

   ```bash
   bun install
   bunx wrangler deploy
   ```

6. In the MCP client, add your `MCP_RESOURCE` URL as a custom remote connector.

Local development uses `.dev.vars` (see `.dev.vars.example`) and `bun run dev` on port 8788. Set `MCP_RESOURCE` there to the same value you deploy with.
