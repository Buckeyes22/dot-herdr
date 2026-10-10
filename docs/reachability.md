# Public reachability and sign-in

dot-herdr can provide an optional sign-in service and an optional Cloudflare
tunnel. The sign-in service is part of the same `dot-herdr` install and version.
It is off unless setup selects it. Existing external providers continue to work.

## Path A: Cloudflare and built-in sign-in (recommended)

Use this path if your domain is on Cloudflare and you do not already run an
OAuth sign-in service. Guided setup walks through the normal flow:

1. Run `dot-herdr setup`.
2. At the route step, choose **Cloudflare (I have a domain on Cloudflare)**.
3. Enter the Cloudflare API token, or choose the `--login` alternative when
   offered. Setup creates the exposure before continuing.
4. At the provider step, choose **Use the built-in sign-in service** and enter
   the password twice at the hidden prompts.
5. Read the Cloudflare bot-protection note and turn protection off for the
   hostname or add a skip rule.
6. Add the plugin at chatgpt.com.

For standalone or advanced use, run `dot-herdr expose cloudflare` and enter the
token at its hidden prompt, or pass `--token-file PATH`. The token is used only
during the command and is never stored. The private `cloudflare/` folder next
to the config contains the ownership journal, plus `tunnel.token` in API mode or
dot-herdr's `config.yml` in `--login` mode. In `--login` mode, `cloudflared tunnel login` leaves the
account-wide `~/.cloudflared/cert.pem`, and `cloudflared tunnel create` writes
the tunnel credentials JSON to `~/.cloudflared/<tunnel id>.json` alongside
`cert.pem`; dot-herdr names and leaves `cert.pem` during removal. Guided setup
runs the same exposure.

Install `cloudflared` from [Cloudflare's downloads page](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/).
dot-herdr detects it and shows its version; it does not install it. Create a
Cloudflare API token with exactly these permissions:

- Account › Cloudflare Tunnel › Edit
- Zone › DNS › Edit
- Zone › Zone › Read

In API-token mode, dot-herdr creates or updates its named remotely managed
tunnel and proxied DNS record, then stores the tunnel run token in a private
0600 file. In `--login` mode, it uses a local tunnel config and credentials
JSON in `~/.cloudflared/<tunnel id>.json`.

`dot-herdr run` and the optional user service supervise `cloudflared`; no root
or separate cloudflared service is needed. `dot-herdr expose cloudflare --remove`
removes only journaled objects. It refuses a tunnel whose ownership changed, and
leaves a DNS record whose content changed in place while finishing the rest of
the cleanup. API mode requires the API token again (or
`--token-file`). Login mode can take an optional API token (prompt or
`--token-file`) to delete its CNAME: `cloudflared` has no DNS-delete command, so
removing the DNS record in `--login` mode requires an API token. Without one,
`--remove` prints the CNAME and keeps its ownership record; run `--remove` again
with an API token to finish, including when you already deleted the CNAME by
hand. It removes its config and tunnel credentials
JSON, but leaves and names
`~/.cloudflared/cert.pem`. `dot-herdr uninstall` also offers removal.
`dot-herdr migrate-route --to cloudflare` keeps the plugin URL and wiring. If
the user service was installed with the OpenAI tunnel, reinstall it with
`dot-herdr service install` (without `--tunnel`).

The built-in sign-in service is mounted on the same hostname and port as `/mcp`.
Its issuer is `https://<hostname>`, with endpoints at
`/.well-known/oauth-authorization-server`, `/.well-known/jwks.json`, `/authorize`,
`/login`, `/token`, `/register` and `/revoke`. Setup asks for a password inline
with hidden input entered twice; only a scrypt hash is saved. Change it later
with `dot-herdr signin set-password`. Tokens and keys stay in private files.
Setting a new password also clears failed-login counters; the page's exponential
lockout backoff is capped at 60 seconds.
The service supports CIMD and S256 PKCE. Access tokens last 10 minutes.
Authorization codes are single-use and last 60 seconds. Refresh tokens rotate on
every use, and the whole refresh family expires 90 days after sign-in; rotation
does not extend that deadline. Tokens use separate observe/control scopes. The
control scope is granted only when you tick **Also allow Herdr control** on the
password page.

Cloudflare's bot protection blocks ChatGPT's calls. Turn it off for this
hostname, or add a rule that skips it for this hostname, before adding the plugin.
dot-herdr never changes zone security settings.

In ChatGPT at chatgpt.com, open Settings → Plugins → + → Add custom MCP server →
enter the HTTPS MCP URL → Create as a plugin → password page (tick **Also allow
Herdr control** if wanted). Approve the verified identity in the setup terminal.

Keep the hostname fixed after setup. The plugin URL, OAuth `resource` and token
`aud` must match, and the issuer is derived from that hostname. Changing it means
updating and verifying all of those values together.

## Path B: HTTPS forwarding and your own sign-in provider

Use any HTTPS reverse proxy or tunnel that carries the public MCP hostname to
`http://127.0.0.1:<local_port>` (default `8000`) and sends `Host` equal to the
public hostname. The connector checks `Host` and `Origin` before authentication.
The forwarder carries the MCP hostname only; sign-in endpoints are served by
your own provider. Configure that OAuth provider to meet
[the OpenAI and MCP requirements](authentication.md#provider-requirements-for-path-b):
issuer and metadata consistency, HTTPS endpoints, S256 PKCE, compatible CIMD or
DCR, resource-bound audience, short-lived access tokens and rotating refresh
tokens. External providers remain fully supported and unchanged.

## Path C: OpenAI Secure MCP Tunnel

The Secure MCP Tunnel can provide MCP transport when eligible and configured,
but it does not tunnel the authorization server. You still need a public sign-in
service, such as the built-in service or your own compatible provider.

## Check reachability

Use `dot-herdr status --live` for public checks. A 403 with a Cloudflare
challenge shows: “Cloudflare's bot protection is blocking requests to <hostname>,
so ChatGPT's calls are blocked too. Turn it off for this hostname, or add a rule
that skips it for this hostname. dot-herdr never changes zone security settings.”
A 530 or error 1033 shows: “The Cloudflare tunnel is down. Check that
cloudflared is running (dot-herdr status shows the cloudflared child; restart
with dot-herdr service restart or dot-herdr run).” A 524 shows: “Cloudflare
timed out waiting for this computer (HTTP 524). Check that the connector is
running and responsive.” Status also reports the `cloudflared` binary, private
credential files and child state.
