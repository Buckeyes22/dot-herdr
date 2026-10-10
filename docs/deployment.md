# Deployment and connectivity

Run one connector beside an existing local Herdr socket. Bind its authenticated
HTTP listener to loopback at port 8000, then use the optional `dot-herdr expose cloudflare` route, a selected Secure MCP
Tunnel, or another HTTPS forwarding route. The optional built-in sign-in service
runs inside the connector; Cloudflare routing is opt-in. The package does not
install cloudflared or manage unrelated remote machines.

Choose transport before declaring live readiness. Tunnel users need an eligible
organization/workspace and authorized existing tunnel ID/key. Public HTTPS users
need a trusted endpoint whose MCP URL equals the approved resource, and either
the built-in sign-in service or a compatible external OAuth provider. All routes
need correct token audience, account consent and client permissions.
See [reachability](reachability.md), [authentication](authentication.md) and [desktop and tunnel](desktop-and-tunnel.md).

Keep issuer/resource trust pinned. Exact Host/Origin checks protect discovery and
authenticated routes; configure approved forwarding without broadening audiences,
trusting arbitrary headers or disabling TLS checks. A tunnel's HTTPS audience is
an identifier even when there is no public listener; prove the actual provider/
transport contract through real login, not by guessing its upstream audience.

Use foreground `dot-herdr run` or opt into a connector-owned user service.
Linux systemd user services and macOS LaunchAgents run in a logged-in user's
session; neither promises pre-login/post-logout availability. No root, Linux
lingering, firewall changes or unattended OAuth loop is installed.
Tunnel services need a private runtime credential file; environment keys remain
available for foreground use. See [operations](operations.md).

`status --live` performs bounded read-only source/discovery probes.
With a Cloudflare exposure, status also reports the `cloudflared` binary, private
credential-file state and child state.
Use `dot-herdr check-connection` and see [troubleshooting](troubleshooting.md) for failures. Plan
storage/backup/revocation limits: no retention pruning or external account
revocation feed is supplied.
