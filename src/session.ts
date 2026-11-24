const SESSION_PREFIX = "h1.";

export function allowlisted(userId: string, allowed: string | undefined): boolean {
  if (userId === "") return false;
  const ids = (allowed ?? "")
    .split(",")
    .map((id) => id.trim())
    .filter((id) => id !== "");
  return ids.length === 0 || ids.includes(userId);
}

export function sessionCurrent(exp: number, now: number): boolean {
  return Number.isFinite(exp) && now < exp;
}

function encode(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function decode(value: string): Uint8Array {
  const pad = (4 - (value.length % 4)) % 4;
  const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat(pad);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++) bytes[index] = binary.charCodeAt(index);
  return bytes;
}

async function aesKey(secret: string): Promise<CryptoKey> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret));
  return crypto.subtle.importKey("raw", digest, "AES-GCM", false, ["encrypt", "decrypt"]);
}

async function macKey(secret: string): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"],
  );
}

export async function seal(secret: string, payload: string): Promise<string> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    await aesKey(secret),
    new TextEncoder().encode(payload),
  );
  return `${encode(iv)}.${encode(new Uint8Array(cipher))}`;
}

export async function unseal(secret: string, token: string): Promise<string | null> {
  const [iv, cipher] = token.split(".");
  if (!iv || !cipher || token.split(".").length !== 2) return null;
  try {
    const plain = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: decode(iv) },
      await aesKey(secret),
      decode(cipher),
    );
    return new TextDecoder().decode(plain);
  } catch {
    return null;
  }
}

export async function signState(secret: string, verifier: string, exp: number): Promise<string> {
  const body = encode(new TextEncoder().encode(JSON.stringify({ v: verifier, e: exp })));
  const mac = await crypto.subtle.sign(
    "HMAC",
    await macKey(secret),
    new TextEncoder().encode(body),
  );
  return `${SESSION_PREFIX}${body}.${encode(new Uint8Array(mac))}`;
}

export async function readState(
  secret: string,
  state: string,
  now: number,
): Promise<{ verifier: string } | null> {
  if (!state.startsWith(SESSION_PREFIX)) return null;
  const [body, mac] = state.slice(SESSION_PREFIX.length).split(".");
  if (!body || !mac) return null;
  const valid = await crypto.subtle.verify(
    "HMAC",
    await macKey(secret),
    decode(mac),
    new TextEncoder().encode(body),
  );
  if (!valid) return null;
  const parsed = JSON.parse(new TextDecoder().decode(decode(body))) as { v?: unknown; e?: unknown };
  if (
    typeof parsed.v !== "string" ||
    typeof parsed.e !== "number" ||
    !sessionCurrent(parsed.e, now)
  ) {
    return null;
  }
  return { verifier: parsed.v };
}

export function isHomeState(state: string | undefined): boolean {
  return typeof state === "string" && state.startsWith(SESSION_PREFIX);
}
