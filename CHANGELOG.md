# Changelog

## 0.4.0 — first public release

First public release. Versions 0.1.0 to 0.3.0 were private development builds.

### Connector

- MCP Events endpoint with attention, completed-turn, lifecycle and coverage-gap
  events; finite subscriptions (default 1 hour), unsubscribe, signing-key rotation,
  epoch fences and triage receipts. A receipt without a subscription key is
  accepted when exactly one of the caller's watches received the event.
- Durable transactional journal and outbox, signed callbacks and bounded
  delivery retries.
- 19 tools, including `get_profile`, scoped state/events, context and health.
- 98 of 102 native Herdr methods (32 queries, 65 actions, bounded event
  collection) with full parameter schemas; four documented transport exclusions.
- Enrolled-agent messages, text/key replies, naming, focus, live state and waits.
  Writes need explicit grants and the OAuth control scope, with durable
  request-ID dedupe. Actions with an unknown outcome are never replayed.
- Bundled connector skill with setup, events and control references, served
  through authenticated MCP skill-import methods.

### Reachability and sign-in

- Optional built-in OAuth sign-in service on the same hostname as `/mcp`:
  RS256 tokens with a JWKS, CIMD with a DCR fallback, S256 PKCE, single-use
  60-second codes, 10-minute access tokens, rotating refresh tokens with reuse
  detection and a 90-day sign-in limit, rate-limited password login with a CSRF
  token, and a scrypt password hash. `dot-herdr signin set-password` changes it.
- Optional `dot-herdr expose cloudflare`: a named Cloudflare Tunnel and DNS
  record for one hostname, created with an API token or `cloudflared tunnel
  login`. `cloudflared` runs under `dot-herdr run` or the user service. An
  ownership record limits `--remove` to objects dot-herdr created.
- Guided setup offers Cloudflare and the built-in sign-in service, and
  `dot-herdr migrate-route --to cloudflare` moves an existing route.
- `dot-herdr status --live` explains Cloudflare 403 challenges, 530/1033 and 524.

### Setup and operation

- Installer (source bootstrap and standalone zipapp) with an owned virtual
  environment, offline demo check and automatic guided setup.
- Guided setup starts from an existing HTTPS MCP URL: it discovers the sign-in
  service and JWKS, selects the running Herdr session and explicit access,
  pairs a verified account for local approval and prepares one ChatGPT client
  (web or desktop app). No JSON editing, PEM export or typed subject.
- Optional connector-owned user service (systemd user unit or LaunchAgent),
  configured to start at login.
- `dot-herdr check-connection`: a guided test that gives you one instruction to
  paste into the dot and shows live progress.
- `dot-herdr status` opens with one `Overall:` verdict and next action; `--live`
  checks public reachability of the MCP URL.
- `dot-herdr access` changes grants or reselects the session without editing
  JSON; revoke-all stops the connector and re-enabling starts it again.
- `dot-herdr migrate-route`, `update` and data-preserving `uninstall`.
- Static RSA public keys remain supported; exactly one key source is required.
  JWKS is pinned to the issuer origin, cached at most 300 seconds, with unknown-key
  refreshes at least 30 seconds apart.
