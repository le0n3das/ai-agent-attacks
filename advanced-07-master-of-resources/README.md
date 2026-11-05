# Advanced 7, Master of Resources: talking to the MCP server directly

![Attack chain: an agent with no tools hands over its MCP server address; a browser is stopped by an Origin check that is not authentication; a scripted client with the platform session cookie completes the MCP handshake, lists a hidden unlock_flag tool and a locked flag resource, calls the tool with no arguments and reads the flag; the right panel shows that hiding a tool from the UI is not access control](diagram.png)

> ARKX Mothership, Advanced track, level 7. Public CTF by CyberArk Labs.

---

## Context

The level presents an "MCP Resource Link". The briefing says the main interface is down and the underlying resource server is still reachable for API calls. The tool panel reads "NO TOOLS AVAILABLE / SYSTEM ACCESS RESTRICTED". The agent says its connection to the MCP server was severed and gives the address: `/level/7/mcp`.

The chat is a dead end by design. The exploit is direct JSON-RPC against the MCP server, so the steps below are HTTP requests and responses, not prompts.

## Recon

The agent discloses the backend endpoint on request. An agent reporting itself offline still names its own server address, which is all the recon the level needs.

## Fingerprint the transport

A browser GET against the endpoint returned a protocol error:

```
-32600 Not Acceptable: Client must accept text/event-stream
```

That error string is the official MCP Python SDK. The endpoint is a Streamable HTTP MCP server.

Probing the transport one request at a time, from both a browser console and curl:

| Request | Result | Meaning |
|---|---|---|
| curl GET, no cookie | 302 to `/` | endpoint sits behind platform auth |
| curl POST, no cookie | 405, `allow: GET` | platform fallback route |
| browser GET, `Accept: text/event-stream` | 200 SSE stream, `: ping` | authenticated session works from the browser |
| browser POST | 403 `Invalid Origin header` | SDK DNS-rebinding protection rejects a browser Origin |

The Origin check is DNS-rebinding protection. Its job is to stop a malicious website from driving a victim's browser. It is not authentication, and the server exposed no other control at the MCP layer.

## Bypass and enumerate

Curl carries the platform session cookie and sends no Origin header, so it is neither an unauthenticated client nor a browser. The MCP handshake completes:

```
initialize -> serverInfo "Weather" 1.27.0, capabilities: resources, tools, prompts
```

The server name does not match its function, a sign that nobody owns an inventory of what it exposes. Enumeration:

```
resources/list            -> resource://flag, resource://super-secret
resources/templates/list  -> empty
tools/list                -> unlock_flag (no arguments)
prompts/list              -> empty
```

The agent UI never displayed `unlock_flag`. Hiding it from the interface did not remove it from the protocol.

## Read the flag

```
resources/read resource://super-secret   -> decoy
resources/read resource://flag           -> "flag is locked"
tools/call unlock_flag {}                 -> "Flag has been unlocked!"
resources/read resource://flag           -> flag
```

The flag was genuinely locked before the call, so the lock is enforced, but only by call order. `unlock_flag` takes no argument, checks no caller identity, and anyone who speaks the protocol can call it.

## Root cause

The MCP server trusts any client that reaches it. Hiding a tool from the agent UI is client-side enforcement of a server-side decision (CWE-602): the server still serves `tools/list` and `tools/call` to anyone who speaks the protocol.

`unlock_flag` is a privileged, state-changing action with no authorization and no caller-identity check (CWE-862). The lock gates the order of calls, not who may call.

Sessions are minted on any authenticated GET with no `initialize`. The only transport control, the Origin check, did its job against browsers and is not an authentication mechanism.

## Impact

High. Any logged-in platform user, with a standard HTTP client, bypasses the agent and calls privileged server functions directly, unlocking and reading protected data. The same pattern in a real deployment exposes every tool and resource behind an "offline" or restricted agent: internal documents, credentials, administrative actions.

## Remediation

- Authenticate and authorize at the MCP server itself. The MCP specification defines OAuth-based authorization for HTTP transports, with per-tool and per-resource scopes.
- Keep the resource server off any route a user can reach.
- Enforce the lock server-side on caller identity, not on call order.
- Do not rely on hiding a tool from the UI. The protocol still lists and serves it.

A note on scope: "never put protected resources in an MCP server" would be the wrong lesson. The MCP spec provides the authorization model. The defect here is its absence per tool and per resource, not the protocol.

---

*ATLAS: T0049 Exploit Public-Facing Application, T0053 AI Agent Tool Invocation. OWASP LLM 2025: LLM06 Excessive Agency, LLM02 Sensitive Information Disclosure. OWASP A01 Broken Access Control. CWE-862, CWE-306 (at the MCP layer), CWE-602.*
