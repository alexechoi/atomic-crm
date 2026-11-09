import { describe, expect, it, vi } from "vitest";
import {
  createAuthorizationMetadata,
  createMcpProxy,
  resourceMetadata,
} from "./mcp-proxy.js";

const ORIGIN = "https://concord-crm-phi.vercel.app";
const UPSTREAM = "https://iwnhxhygtmqmkuxplohq.supabase.co";

function mcpRequest(method = "POST") {
  return new Request(`${ORIGIN}/mcp?target=https://untrusted.example`, {
    method,
    headers: {
      authorization: "Bearer test-token",
      accept: "application/json, text/event-stream",
      "content-type": "application/json",
      "mcp-protocol-version": "2025-03-26",
      cookie: "private-browser-cookie",
      "x-forwarded-host": "untrusted.example",
    },
    ...(method === "POST"
      ? { body: '{"jsonrpc":"2.0","id":1,"method":"initialize"}' }
      : {}),
  });
}

describe("MCP discovery compatibility", () => {
  it("advertises the canonical resource and actual Supabase issuer on every discovery alias", async () => {
    for (const path of [
      "/.well-known/oauth-protected-resource",
      "/.well-known/oauth-protected-resource/mcp",
      "/mcp/oauth-protected-resource",
    ]) {
      const response = resourceMetadata(new Request(ORIGIN + path));
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({
        resource: `${ORIGIN}/mcp`,
        authorization_servers: [`${UPSTREAM}/auth/v1`],
        bearer_methods_supported: ["header"],
      });
    }
  });

  it("challenges unauthenticated requests with usable metadata without forwarding them", async () => {
    const fetchMock = vi.fn<typeof fetch>();
    const response = await createMcpProxy(fetchMock)(
      new Request(`${ORIGIN}/mcp`),
    );
    expect(response.status).toBe(401);
    expect(response.headers.get("www-authenticate")).toBe(
      `Bearer resource_metadata="${ORIGIN}/.well-known/oauth-protected-resource/mcp"`,
    );
    expect(response.headers.get("access-control-expose-headers")).toContain(
      "WWW-Authenticate",
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("forwards MCP bodies and authentication to a fixed upstream without browser cookies or host overrides", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValue(Response.json({ result: {} }));
    const request = mcpRequest();
    const expectedBody = await request.clone().text();
    const response = await createMcpProxy(fetchMock)(request);
    expect(response.status).toBe(200);
    expect(fetchMock.mock.calls[0]?.[0]).toBe(`${UPSTREAM}/functions/v1/mcp`);
    const init = fetchMock.mock.calls[0]?.[1];
    expect(init?.method).toBe("POST");
    expect(init?.redirect).toBe("error");
    expect(
      new TextDecoder().decode(
        init?.body instanceof ArrayBuffer ? init.body : undefined,
      ),
    ).toBe(expectedBody);
    const headers = new Headers(init?.headers);
    expect(headers.get("authorization")).toBe("Bearer test-token");
    expect(headers.get("mcp-protocol-version")).toBe("2025-03-26");
    expect(headers.has("cookie")).toBe(false);
    expect(headers.has("x-forwarded-host")).toBe(false);
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("preserves SSE streams and protocol headers but never forwards cookies", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response("event: message\ndata: {}\n\n", {
        headers: {
          "content-type": "text/event-stream",
          "mcp-session-id": "session-1",
          "set-cookie": "upstream-cookie",
        },
      }),
    );
    const response = await createMcpProxy(fetchMock)(mcpRequest("GET"));
    expect(response.headers.get("content-type")).toBe("text/event-stream");
    expect(response.headers.get("mcp-session-id")).toBe("session-1");
    expect(response.headers.has("set-cookie")).toBe(false);
    expect(await response.text()).toBe("event: message\ndata: {}\n\n");
  });

  it("replaces an expired-token challenge with discovery for this endpoint", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValue(
      new Response("expired", {
        status: 401,
        headers: {
          "www-authenticate":
            'Bearer resource_metadata="https://wrong.example"',
        },
      }),
    );
    const response = await createMcpProxy(fetchMock)(mcpRequest());
    expect(response.status).toBe(401);
    expect(response.headers.get("www-authenticate")).toContain(
      `${ORIGIN}/.well-known/oauth-protected-resource/mcp`,
    );
  });

  it("does not retry upstream failures or expose credential-bearing errors", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockRejectedValue(new Error("Bearer test-token"));
    const response = await createMcpProxy(fetchMock)(mcpRequest());
    expect(response.status).toBe(502);
    expect(await response.text()).toBe("CRM upstream unavailable");
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("serves authoritative authorization metadata without passing incoming credentials", async () => {
    const metadata = {
      issuer: `${UPSTREAM}/auth/v1`,
      token_endpoint: `${UPSTREAM}/auth/v1/oauth/token`,
    };
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValue(Response.json(metadata));
    const response = await createAuthorizationMetadata(fetchMock)(
      mcpRequest("GET"),
    );
    expect(await response.json()).toEqual(metadata);
    expect(fetchMock.mock.calls[0]?.[0]).toBe(
      `${UPSTREAM}/.well-known/oauth-authorization-server/auth/v1`,
    );
    expect(fetchMock.mock.calls[0]?.[1]?.headers).toBeUndefined();
  });

  it("handles preflight and rejects unsupported methods without calling upstream", async () => {
    const fetchMock = vi.fn<typeof fetch>();
    for (const handler of [
      createMcpProxy(fetchMock),
      createAuthorizationMetadata(fetchMock),
      resourceMetadata,
    ]) {
      expect(
        (await handler(new Request(`${ORIGIN}/mcp`, { method: "OPTIONS" })))
          .status,
      ).toBe(204);
      expect(
        (await handler(new Request(`${ORIGIN}/mcp`, { method: "PUT" }))).status,
      ).toBe(405);
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
