# Setup and troubleshooting

The connector runs one supervised Python runtime beside an existing Herdr 0.9.3
Unix socket, with private SQLite. Source archives include `scripts/install.py`;
installed packages use `dot-herdr setup`, which the interactive installer starts
automatically. Follow setup in a normal terminal outside Herdr and leave Herdr
running. Live use needs a public HTTPS MCP URL backed by a compatible sign-in service.
Setup can use the optional built-in sign-in service and `dot-herdr expose cloudflare`,
or an existing HTTPS route and external provider. Secure MCP Tunnel is a separate
eligible route and still needs a public sign-in service. See the public
reachability guide at https://github.com/Buckeyes22/dot-herdr/blob/main/docs/reachability.md.

Use Python 3.11–3.14 with venv/pip and dependency-network access. Download the
release assets and `SHA256SUMS` from
https://github.com/Buckeyes22/dot-herdr/releases. Verify them with
`sha256sum -c SHA256SUMS` (macOS: `shasum -a 256 -c SHA256SUMS`). Extract the
source archive, enter its top directory and run `python3 scripts/install.py`
in a normal terminal. The source bootstrap needs both `scripts/` and `src/dot_herdr/`.
The interactive installer installs an owned venv/command, runs the offline demo,
prints its absolute command path and starts `dot-herdr setup`. A separate
installer zipapp accepts a wheel/source archive with `--source` and `--sha256`.
Use the printed command path if it is not on PATH. For an
existing installation, run `dot-herdr setup` there. After setup and identity
approval, run `dot-herdr check-connection` in that terminal and complete its
generated test instruction in the intended dot. The command asks for an already
granted disposable target and harmless test authorization; it does not silently
choose or create an agent.

Setup discovers/selects the existing source, asks explicit access/agent/context
choices, rechecks identities and retains private drafts/resume records. Choose Cloudflare exposure or enter the existing HTTPS MCP URL. Choose the built-in
sign-in service (setup asks for its password hidden twice and stores only its scrypt
hash) or use the provider discovered from the URL. Setup never asks for PEM export
or typed sub. Cloudflare bot protection blocks ChatGPT calls: turn it off for the
hostname or add a skip rule before adding the plugin.
Static-key configs remain supported. Auth-only pairing accepts a verified request
and exposes just get_profile; no Herdr data/workers/callbacks run before local
account confirmation. Profile returns opaque issuer/sub identity with openai/profile
metadata; marker support does not force host invocation. Login exit success alone
never enrolls an account. Never read credential files/keychains or ask for secrets.

Choose where the user will use Herdr once during setup: ChatGPT in a web browser
(chatgpt.com), or the ChatGPT/Codex desktop app. The choice is saved in the
connection record and can be changed explicitly with `migrate-route --client-app`.
The connector URL, provider sign-in, local account approval and tools are shared.

For the browser choice, use Settings → Plugins → + → Add custom MCP server →
enter the HTTPS MCP URL → Create as a plugin → password page → back in Settings.
Tick **Also allow Herdr control** on that page if control was selected.
If control was selected, in the Herdr plugin's settings switch tool access from
low-risk only to allow all tools; control actions are marked as write actions,
so the low-risk setting blocks them.
Use the plugin once in the same ChatGPT web UI (for example, request `get_profile`) to
send an authenticated request, then approve the verified identity in the setup
terminal. The dot is in this same web UI.

For the desktop choice, use the ChatGPT/Codex desktop app Plugins Directory to
install and use the Herdr plugin connected to the HTTPS MCP URL. Complete provider
sign-in if prompted, then approve the verified identity in the setup terminal.
If control was selected, tick **Also allow Herdr control** on the password page
and switch tool access in the Herdr plugin settings from low-risk only to allow
all tools; control actions are marked as write actions, so the low-risk setting
blocks them.
Routine desktop setup does not prepare a local package. Explicit `--app-id` is a
separate desktop package option. The public desktop documentation does not give a
separate custom MCP server creation path inside the desktop UI.

An observation-only sign-in can be approved while selected control awaits renewed consent.
Remove the plugin in the chosen app and add it again with the same URL, ticking **Also allow Herdr control**,
then switch tool access in the Herdr plugin settings from low-risk only to allow all tools;
control actions are marked as write actions, so the low-risk setting blocks them.
Then check `dot-herdr status` for `account access: observe+control`.

Codex CLI (advanced) standalone wiring uses approved matching public HTTPS; plugin-http is an
explicit alternative, never a simultaneous default registration. Reruns preserve
route/wiring; run `dot-herdr migrate-route` for an explicit owned migration.
Setup/connect flags can defer opening/login/wiring without claiming completion.

Codex CLI (advanced) standalone setup delegates CIMD/DCR/configured-client consent to Codex CLI, then requests
authenticated discovery to observe the identity. Missing CLI/discovery, consent
refusal or timeout leaves the stage pending. For registered-plugin setup, complete the selected app's sign-in steps above,
then approve the verified identity in the setup terminal. Use the dot in that
same selected app for tools and the connection test.
Existing enrolled endpoints use `dot-herdr login` or `dot-herdr run --login`.
`dot-herdr login --no-open` uses manual callback mode. Codex 0.160.1 loopback
discovery with a different canonical resource is blocked. The real CLI test uses
isolated synthetic HTTPS, random ports and authenticated discovery; it proves no
real account/Herdr/tunnel/dot. Never weaken issuer/audience/TLS/Host/Origin checks
for a workaround.

JWT verification accepts exactly one trusted RSA static key or same-origin JWKS,
RS256 and exact issuer/resource/claims/scopes. JWKS cache is at most 300 seconds,
unknown-key refresh attempts at least 30 seconds apart. JWKS refresh does not
provide account revocation. Keycloak's official MCP recipe has experimental
resource-indicator/CIMD features; administrators must validate PKCE, registration,
public callbacks, scopes, RS256, client_id mapper and approved audience. Metadata
compatibility alone proves neither real token claims nor account consent.

Tunnel setup verifies an official client and writes a private profile. Foreground
run --tunnel supervises both processes; worker/child failure cleans up the runtime.
Use the foreground CONTROL_PLANE_API_KEY environment or an absolute private
runtime-key file for an owned service; never paste the value or store it in unit/
plist/record/chat. Tunnel doctor/readiness is separate from OAuth and Events.

Setup offers optional owned systemd user/LaunchAgent operation and explicit startup
at user login. No root/lingering or pre-login/post-logout promise. Foreground setup
runtime stops on exit; opted-in service continues. dot-herdr service manages only
owned files. dot-herdr access changes initialized grants with before/after choices,
stopped-owner private backup/commit/restart. Content policy can change; replaced
identities receive new subject keys and fence old watches. Revoke-all retains
history inactive; failed restart never silently restores revoked grants. Increased
control may require new OAuth consent. Never kill an arbitrary foreground PID.

dot-herdr status is read-only, with --json and bounded --live source/discovery
probes. It never constructs Store or migrates/recover-sends; stale records are not
running-process proof. Historical auth is not current consent. Unobserved cloud
facts remain unknown. doctor/check are offline; demo is synthetic without network.

dot-herdr check-connection asks for an already granted disposable target and
explicit harmless test authorization, then provides a host instruction. Retain
its stable request ID; inspect unknown outcomes before replay. The dot creates
one `herdr.turn.completed` automation and asks the disposable agent for a nonce
reply. Confirm its new watch in the terminal, then pause the automation. Track authenticated
read, source submission/reply, capture, callback, transport, triage, full nonce in
the intended destination, unsubscribe and no further delivery separately. The ChatGPT web check passed all 10 phases on Linux. A 2xx response or receipt alone never attests to the correct dot. Clean up
only the confirmed finite test watch.

Managed update stages a reviewed artifact/environment and snapshots stopped-owner
config/database before pointer activation. No old database is automatically restored
after possible actions/delivery. Default uninstall retains config/history/backups;
explicit purge previews exact private paths. Cloud grants require provider/app
owner flows. Releases are available from https://github.com/Buckeyes22/dot-herdr/releases with `SHA256SUMS`. No Python-free executable or automatic pruning is promised. The ChatGPT web route was verified live on Linux; desktop app and Secure MCP Tunnel routes were not.

Detached runners may lack HERDR_* while their frontend is in Herdr. Use existing
CLI session list --json and explicitly selected socket/pane/terminal/native IDs;
labels/cwd/focus are clues, never ownership. Do not infer native identity from
CODEX_THREAD_ID. Cloud dots use scoped connector tools instead of assuming a CLI.

Diagnose safe reasons with existing access and status; preserve credentials/callback
secrets/terminal text. Source gaps, expired watches, missing context permission,
identity changes, tunnel keys, provider mismatch and unknown action outcomes call
for a specific scoped next action. Continue useful authorized branches when one
prerequisite is missing. Stop monitoring by unsubscribing the actual watch; that
does not stop Herdr work or recall in-flight delivery.

An administrator-issued public client can be selected with setup --oauth-client-id.
It is retained in the private draft and mapped to supported Codex oauth.client_id;
never collect a client secret. A missing standalone CLI reports client pending
before pairing. An expired/fenced test watch cannot authorize a replay instruction;
keep the stable action ID and inspect existing source/action evidence.

For Cloudflare failures, 403 with a challenge means bot protection blocks ChatGPT; turn it off for this hostname or add a rule that skips it for this hostname. dot-herdr never changes zone security settings. A 530 or 1033 shows: “The Cloudflare tunnel is down. Check that cloudflared is running (dot-herdr status shows the cloudflared child; restart with dot-herdr service restart or dot-herdr run).” A 524 shows: “Cloudflare timed out waiting for this computer (HTTP 524). Check that the connector is running and responsive.” Status reports the cloudflared binary, private credential-file state and child state. Keep the hostname fixed because the plugin URL, resource/audience and issuer all depend on it.
