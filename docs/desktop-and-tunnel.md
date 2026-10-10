# Desktop plugin and selected connection route

Choose one route and one client wiring. Guided setup retains the selection in
its private connection record. Both ChatGPT web and desktop flows use your existing public HTTPS MCP URL and the plugin's
registered connection. Standalone Codex CLI wiring is an advanced alternative.
Secure MCP Tunnel is a separate eligible route.

## ChatGPT in a web browser

For the browser choice, in ChatGPT at chatgpt.com use Settings → Plugins → + → Add custom MCP server →
enter your HTTPS MCP URL → Create as a plugin → password page → back in Settings.
Tick **Also allow Herdr control** on the password page if you selected control.
If the plugin is already connected, use it once in the same ChatGPT web UI
(for example, request `get_profile`) to trigger authenticated pairing. Approve
the verified account in the setup terminal. The dot stays in that ChatGPT web UI.

For Secure MCP Tunnel, you also need an eligible organization/workspace, Use
access, an existing tunnel ID and runtime key. The tunnel supplies transport,
not an OAuth provider or account consent. Consult the
[official tunnel requirements](https://developers.openai.com/api/docs/guides/secure-mcp-tunnels).

`dot-herdr setup` handles the local stages. Existing configurations can use
`dot-herdr connect`. Default `registered-plugin` wiring uses the custom plugin
created in ChatGPT web Settings and prepares no local plugin package.

## Desktop app

The documented desktop route is the Plugins Directory: install and use a Herdr
plugin connected to the approved HTTPS MCP URL. Provider sign-in and account
approval use the same connector flow.

### Explicit local package option

**ChatGPT/Codex desktop app (explicit local package):** Explicit `--app-id` prepares a separate local
plugin package with the registered server mapping, skill and references. That
package contains no OAuth credentials, roster or state. It is added to the
personal marketplace with a Codex desktop app installation handoff.
Restart the Codex desktop app as instructed by that handoff.

## Advanced: Codex CLI

**Codex CLI (advanced):** Explicit `--wiring standalone` registers the approved
MCP URL for Codex CLI. Sign-in uses Codex CLI. This wiring does not establish a
ChatGPT web plugin connection.

### Wiring and migration

`--wiring standalone --route https --endpoint https://your-approved-host/mcp`
registers only the standalone Codex MCP connection. The endpoint must equal the
configured approved resource. `--wiring plugin-http` packages direct HTTP plugin
wiring without also adding standalone registration; legacy `--no-register`
selects that mode. Reruns preserve the selected wiring. Conflicting registrations
reject; previously created dual entries remain until `dot-herdr migrate-route` reviews and confirms an owned migration.

`--no-open` skips explicit desktop local package handoffs, `--no-login` defers setup's delegated login
and `--no-connect` saves source/access setup without preparing the client.
`connect` prepares wiring; use setup to complete pairing/runtime/check or explicit
`login` for an already approved running standalone endpoint.

## Automatic OAuth client setup and sign-in

Standalone setup delegates consent to `codex mcp login`, then requests authenticated
app-server discovery so the auth-only pairing endpoint can observe a verified
identity. Confirm the candidate locally. Missing CLI/discovery, timeout, refused
consent or a provider mismatch leaves the stage pending. No password, client
secret or bearer token is requested in chat/config.

For an enrolled running endpoint, use `dot-herdr login`; `run --login` starts its
listener first. `login --no-open` uses the client's manual callback mode.
Local Codex credentials do not establish a cloud dot connection.

Codex 0.160.1 supports CIMD and DCR against an HTTPS provider with a matching
resource URL. Its loopback URL with a different canonical HTTPS resource fails
even when `oauth_resource` is set. Keep issuer/audience/Host/Origin/TLS checks intact.

## Tunnel runtime

`dot-herdr tunnel-setup --tunnel-id EXISTING_ID` uses an installed official client
or downloads and verifies it, then writes a private profile. `--no-download`
requires a client already on PATH. `tunnel-check` runs redacted client doctor.
Foreground `run --tunnel` supervises the client and connector together; child or
worker failure stops the runtime and Ctrl-C reaps both.

Foreground users can supply `CONTROL_PLANE_API_KEY` through the environment.
An owned service uses `--tunnel --credential-file /absolute/private/tunnel-key`:
a private, owned nonsymlink file read at launch. Only its path enters service
arguments; no literal key enters unit/plist, connection records or logs. Do not
paste secrets into chat or project files. See [operations](operations.md).

Run `dot-herdr check-connection` with a disposable granted target. The tunnel
audience remains the approved canonical HTTPS resource.
