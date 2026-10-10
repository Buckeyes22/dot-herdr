# Authentication and identity approval

dot-herdr is an OAuth protected resource. It can also provide an optional built-in
sign-in service, mounted on the same hostname and port as `/mcp`. It is part of
the same install and is off unless setup selects it. Setup asks for its password
with hidden input entered twice and stores only a scrypt hash. Existing external
providers remain supported and behave as before. See [public reachability](reachability.md).
Sign-in rate limits use exponential backoff capped at 60 seconds. Run
`dot-herdr signin set-password` to change the password; setting it also clears
failed-login counters if the sign-in page is currently rate-limited.
Access tokens last 10 minutes. Refresh tokens rotate on every use, and the whole
refresh family expires 90 days after sign-in; rotation does not extend that
deadline. Authorization codes are single-use and last 60 seconds.

Guided setup takes the existing HTTPS MCP URL, discovers its protected-resource
metadata and sign-in service, checks compatibility and discovers JWKS. If the
server advertises several sign-in services, setup asks you to select one. It does not request a PEM export or typed `sub`.
An authenticated `get_profile` request returns the stable opaque identity
`id = SHA256(canonicalJSON([issuer, sub]))`. Its `openai/profile` marker and declared
output schema support profile-aware clients. The bounded pairing stage records candidate verified identities in
memory and requires local confirmation. Until confirmation there is no Herdr
store, source observation, callback delivery or Herdr tool access.
Credentials and keychains are not read by setup.
An already connected ChatGPT plugin needs a tool call (for example `get_profile`)
during the pairing window to send an authenticated request. Setup displays only a
reason code when such a request is rejected; it never prints the token.

## Verification contract

Configuration accepts exactly one key source: an existing RSA `public_key` file
or a discovered `jwks_url`. Static keys remain supported. Both enforce RS256 and
RSA size 2048–8192 bits, exact issuer/resource audience, required `exp`, `iat`,
nonempty `sub`, string `client_id` and string `scope`. The endpoint requires
`herdr:observe`. Writes additionally require `herdr:control` and the selected
local control/session grant. Client IDs and display names are not principals.
Opaque or HS256 tokens and public no-auth mode are unsupported.

Discovery/JWKS must use the configured issuer's HTTPS origin. Requests use no
redirects, ambient proxy credentials or cookies, with finite time/byte bounds.
Token-controlled key URLs/embedded keys are rejected. JWKS caches last at most
300 seconds; unknown-key fetches are rate limited to one attempt per 30 seconds.
Expired/unavailable keys fail closed. Static-key rotation needs a reviewed key
replacement and restart. Webhook signing-key rotation is a separate mechanism.
Offline doctor/check validates key-source shape, not live issuer ownership or
current account consent.

JWKS refresh is not account revocation. A cryptographically valid access token
can remain valid until expiry after an account is disabled. Local roster
revocation fences access and subscriptions; it is separate from provider grants.
Do not promise instantaneous external disconnection handling. Token expiry blocks
new authenticated requests, not an external revocation feed for existing watches.

## Provider compatibility recipe: Keycloak

Keycloak documents an MCP authorization-server recipe with resource indicators
and Client ID Metadata Documents. See the [official Keycloak MCP authorization server guide](https://www.keycloak.org/securing-apps/mcp-authz-server)
(consulted October 7, 2026).

Have the provider administrator configure and verify:

- HTTPS issuer/discovery, authorization/token/JWKS on the same issuer origin.
- Public authorization-code clients with PKCE S256, the selected client's actual
  callback URLs and either compatible CIMD, allowed DCR or a configured client.
- Advertised/requested `herdr:observe` and `herdr:control` scopes, RS256 access
  tokens, a `client_id` claim mapper and the approved MCP resource as audience.
- Resource-indicator behavior, registration policies and account consent matching
  the actual ChatGPT/Codex client. Allow only the intended callbacks/resources.

The connector's metadata compatibility check verifies advertised facts.
Perform authenticated pairing/profile/read and the guided connection test before
accepting the provider route. A provider advertising registration support still
needs its administrators' permission and correct policy.

Delegated `dot-herdr login` keeps passwords/client secrets/tokens in the provider
and Codex flow. For a pre-registered public client, supply `setup --oauth-client-id`
with the administrator-issued client ID. Setup retains it in the private draft and
uses Codex's supported `oauth.client_id` setting; no client secret is requested.
The provider must accept the selected client's callback URLs.
Codex 0.160.1 loopback/canonical-resource mismatch remains blocked. See
[desktop and tunnel](desktop-and-tunnel.md).

## Provider requirements for Path B

A bring-your-own provider must publish HTTPS authorization-server metadata with a
byte-identical issuer, authorization and token endpoints, and S256 PKCE. The
forwarder must carry the public MCP hostname to `http://127.0.0.1:<local_port>`
(`8000` by default) and send `Host` equal to that public hostname; the connector
checks `Host` and `Origin` before authentication. The forwarder carries the MCP
hostname only; sign-in endpoints are served by your own provider. The provider's
protected-resource metadata must identify the exact MCP `resource` and its
authorization server. Support CIMD (preferred) or compatible DCR; validate
client documents and redirect URIs. Use public-client `none` authentication,
return RFC 9207 `iss` in authorization responses (recommended so ChatGPT can keep
one stable client), copy the requested resource into the token audience, issue
short-lived access tokens and rotate refresh tokens. Do not list
`offline_access`. Enforce `herdr:observe` and grant
`herdr:control` only with explicit consent. OpenAI Secure MCP Tunnel does not
tunnel this authorization server, so a public sign-in service is still required.
