const PUBLIC_ORIGIN = "https://concord-crm-phi.vercel.app";
const SUPABASE_ORIGIN = "https://iwnhxhygtmqmkuxplohq.supabase.co";
const AUTH_ISSUER = `${SUPABASE_ORIGIN}/auth/v1`;
const RESOURCE = `${PUBLIC_ORIGIN}/mcp`;
const RESOURCE_METADATA = `${PUBLIC_ORIGIN}/.well-known/oauth-protected-resource/mcp`;
const REQUEST_HEADERS = [
  "authorization",
  "accept",
  "content-type",
  "mcp-protocol-version",
  "mcp-session-id",
  "last-event-id",
];
const RESPONSE_HEADERS = [
  "content-type",
  "mcp-session-id",
  "mcp-protocol-version",
  "retry-after",
];

function responseHeaders() {
  return new Headers({
    "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, HEAD, POST, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": REQUEST_HEADERS.join(", "),
    "Access-Control-Expose-Headers":
      "WWW-Authenticate, MCP-Session-Id, MCP-Protocol-Version, Retry-After",
  });
}

function unauthorized() {
  const headers = responseHeaders();
  headers.set(
    "WWW-Authenticate",
    `Bearer resource_metadata="${RESOURCE_METADATA}"`,
  );
  return new Response("Unauthorized", { status: 401, headers });
}

export function resourceMetadata(request: Request) {
  const headers = responseHeaders();
  if (request.method === "OPTIONS")
    return new Response(null, { status: 204, headers });
  if (request.method !== "GET" && request.method !== "HEAD") {
    headers.set("Allow", "GET, HEAD, OPTIONS");
    return new Response("Method Not Allowed", { status: 405, headers });
  }
  headers.set("Content-Type", "application/json");
  return new Response(
    request.method === "HEAD"
      ? null
      : JSON.stringify({
          resource: RESOURCE,
          authorization_servers: [AUTH_ISSUER],
          bearer_methods_supported: ["header"],
        }),
    { headers },
  );
}

// Fixed destinations prevent this deployment from becoming an open proxy.
// Tokens still come directly from Supabase; no credentials are stored here.
export function createMcpProxy(fetchImpl: typeof fetch = fetch) {
  return async (request: Request): Promise<Response> => {
    const headers = responseHeaders();
    if (request.method === "OPTIONS")
      return new Response(null, { status: 204, headers });
    if (!["GET", "POST", "DELETE"].includes(request.method)) {
      headers.set("Allow", "GET, POST, DELETE, OPTIONS");
      return new Response("Method Not Allowed", { status: 405, headers });
    }
    if (!request.headers.has("authorization")) return unauthorized();
    const upstreamHeaders = new Headers();
    for (const name of REQUEST_HEADERS) {
      const value = request.headers.get(name);
      if (value !== null) upstreamHeaders.set(name, value);
    }
    try {
      const upstream = await fetchImpl(`${SUPABASE_ORIGIN}/functions/v1/mcp`, {
        method: request.method,
        headers: upstreamHeaders,
        ...(request.method === "POST"
          ? { body: await request.arrayBuffer() }
          : {}),
        redirect: "error",
        signal: AbortSignal.any([request.signal, AbortSignal.timeout(60_000)]),
      });
      if (upstream.status === 401) {
        await upstream.body?.cancel();
        return unauthorized();
      }
      for (const name of RESPONSE_HEADERS) {
        const value = upstream.headers.get(name);
        if (value !== null) headers.set(name, value);
      }
      return new Response(upstream.body, { status: upstream.status, headers });
    } catch {
      // Never retry a mutation or include credential-bearing errors in responses.
      return new Response("CRM upstream unavailable", { status: 502, headers });
    }
  };
}

export function createAuthorizationMetadata(fetchImpl: typeof fetch = fetch) {
  return async (request: Request): Promise<Response> => {
    const headers = responseHeaders();
    if (request.method === "OPTIONS")
      return new Response(null, { status: 204, headers });
    if (request.method !== "GET" && request.method !== "HEAD") {
      headers.set("Allow", "GET, HEAD, OPTIONS");
      return new Response("Method Not Allowed", { status: 405, headers });
    }
    try {
      const upstream = await fetchImpl(
        `${SUPABASE_ORIGIN}/.well-known/oauth-authorization-server/auth/v1`,
        { redirect: "error", signal: AbortSignal.timeout(10_000) },
      );
      if (!upstream.ok) {
        await upstream.body?.cancel();
        return new Response("OAuth discovery unavailable", {
          status: 502,
          headers,
        });
      }
      headers.set("Content-Type", "application/json");
      return new Response(request.method === "HEAD" ? null : upstream.body, {
        headers,
      });
    } catch {
      return new Response("OAuth discovery unavailable", {
        status: 502,
        headers,
      });
    }
  };
}
