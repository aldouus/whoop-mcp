import { env } from "cloudflare:workers";
import { McpServer } from "@modelcontextprotocol/server";
import { getMcpAuthContext } from "agents/mcp/server";
import { z } from "zod";
import { whoopGet, withWhoop, type WhoopProps } from "./whoop";

const listInput = z.object({
  start: z.string().optional().describe("ISO-8601 datetime to filter from"),
  end: z.string().optional().describe("ISO-8601 datetime to filter until"),
  limit: z.number().int().positive().optional().describe("Maximum records in this page"),
  nextToken: z.string().optional().describe("next_token from the previous page"),
});

function text(data: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(data) }] };
}

function failure(error: unknown) {
  const message = error instanceof Error ? error.message : "WHOOP request failed";
  return { content: [{ type: "text" as const, text: message }], isError: true as const };
}

function granted(scope: string): WhoopProps {
  const props = getMcpAuthContext()?.props as WhoopProps | undefined;
  if (!props?.grantId) throw new Error("Not authenticated");
  if (!props.scope.includes(scope)) throw new Error(`Missing scope ${scope}`);
  return props;
}

function call(scope: string, run: (token: string) => Promise<unknown>) {
  try {
    const props = granted(scope);
    return withWhoop(env, props, run).then(text, failure);
  } catch (error) {
    return failure(error);
  }
}

const reads = [
  {
    name: "get_profile",
    description: "Get the authenticated user's WHOOP profile (name, email).",
    scope: "read:profile",
    path: "/v2/user/profile/basic",
  },
  {
    name: "get_body_measurement",
    description: "Get the user's body measurements (height, weight, max heart rate).",
    scope: "read:body_measurement",
    path: "/v2/user/measurement/body",
  },
] as const;

const collections = [
  {
    name: "get_cycles",
    description:
      "List physiological cycles. Each cycle contains strain, kilojoules, and heart rate data.",
    scope: "read:cycles",
    path: "/v2/cycle",
  },
  {
    name: "get_recovery_collection",
    description:
      "List recovery scores. Each record contains recovery %, HRV, resting heart rate, and SpO2.",
    scope: "read:recovery",
    path: "/v2/recovery",
  },
  {
    name: "get_sleep_collection",
    description:
      "List sleep records. Each record contains sleep stages, performance %, respiratory rate, and sleep needed.",
    scope: "read:sleep",
    path: "/v2/activity/sleep",
  },
  {
    name: "get_workout_collection",
    description:
      "List workouts. Each record contains sport type, strain, heart rate zones, distance, and altitude.",
    scope: "read:workout",
    path: "/v2/activity/workout",
  },
] as const;

const byId = [
  {
    name: "get_cycle_by_id",
    description: "Get a single physiological cycle by its ID.",
    scope: "read:cycles",
    param: "cycle_id",
    path: (id: string) => `/v2/cycle/${encodeURIComponent(id)}`,
  },
  {
    name: "get_recovery_by_id",
    description: "Get a single recovery record by its associated cycle ID.",
    scope: "read:recovery",
    param: "cycle_id",
    path: (id: string) => `/v2/cycle/${encodeURIComponent(id)}/recovery`,
  },
  {
    name: "get_sleep_by_id",
    description: "Get a single sleep record by its ID.",
    scope: "read:sleep",
    param: "sleep_id",
    path: (id: string) => `/v2/activity/sleep/${encodeURIComponent(id)}`,
  },
  {
    name: "get_workout_by_id",
    description: "Get a single workout by its ID.",
    scope: "read:workout",
    param: "workout_id",
    path: (id: string) => `/v2/activity/workout/${encodeURIComponent(id)}`,
  },
] as const;

export function createWhoopServer() {
  const server = new McpServer({ name: "whoop", version: "1.0.0" });

  for (const tool of reads) {
    server.registerTool(tool.name, { description: tool.description }, () =>
      call(tool.scope, (token) => whoopGet(env, token, tool.path)),
    );
  }

  for (const tool of collections) {
    server.registerTool(
      tool.name,
      {
        description: `${tool.description} Returns one page; pass nextToken to continue.`,
        inputSchema: listInput,
      },
      (args) => call(tool.scope, (token) => whoopGet(env, token, tool.path, args)),
    );
  }

  for (const tool of byId) {
    server.registerTool(
      tool.name,
      { description: tool.description, inputSchema: z.object({ [tool.param]: z.string() }) },
      (args) => call(tool.scope, (token) => whoopGet(env, token, tool.path(args[tool.param]))),
    );
  }

  return server;
}
