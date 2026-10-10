# Security and disclosure

Supported version: the latest release (0.4.0). Report vulnerabilities privately by email to
chris@lateapexllc.com; do not open a public issue or publish a sensitive report. Share a synthetic minimal reproduction without callback URLs,
signing keys, bearer tokens, source transcripts, private config or databases.

## Identity and permissions

The connector is an OAuth protected resource and has an optional built-in sign-in
service. It is part of the same distribution, off unless setup selects it;
external providers remain supported. Static RSA public-key configurations also
remain supported. Exactly one trusted key source is required. RS256, RSA
2048–8192 bits, exact issuer/resource audience and required claims/scopes fail
closed. Metadata compatibility does not prove actual account consent, callback
registration or token format.

JWKS/discovery uses the pinned issuer's HTTPS origin, bounded requests/documents,
no redirects or ambient proxy credentials, and no token-controlled key URLs.
JWKS cache lasts at most 300 seconds; unknown-key fetch attempts are at least
30 seconds apart. Expired/unavailable keys fail closed. JWKS rollover is supported
within those limits; it is not an account-revocation feed. Valid access tokens
can remain valid until expiry after provider account disconnection. Local roster
revocation and provider grants are distinct.

Finite auth-only pairing records bounded verified candidates in memory. It
exposes only `get_profile`, whose structured opaque ID derives from issuer/sub;
no Herdr store, source workers, callbacks or source tools are available before
local account confirmation. Setup never reads client token
files or keychains. The one password exception is that setup asks for the built-in
sign-in service password, if chosen, and stores only its scrypt hash. A second
exception is the Cloudflare API token: setup's Cloudflare route choice and
`dot-herdr expose cloudflare` ask for it, use it only during that command, and
never store, print or log it. The Cloudflare tunnel run token is stored in a
private 0600 file. Setup still never asks for private keys or client secrets.
Pending drafts/resume records contain no credentials or callback secrets. The
sign-in service exposes `/authorize`, `/login`, `/token`, `/register`, `/revoke`,
`/.well-known/oauth-authorization-server` and `/.well-known/jwks.json` on the MCP
hostname. Its signing key, password hash and owner id are 0600 files in a 0700
`signin/` folder. Refresh tokens and authorization codes are stored only as
hashes. It uses per-IP and global login limits with backoff, transaction-bound
CSRF, bounded DCR, no forwarded-header trust and no secrets in logs. The
exponential failed-login backoff is capped at 60 seconds; `dot-herdr signin set-password`
also clears failed-login counters. Access tokens last 10 minutes. Refresh tokens
rotate on every use, and the whole refresh family expires 90 days after sign-in;
rotation does not extend that deadline. Authorization codes are single-use and
last 60 seconds. Cloudflare's private
`cloudflare/` folder next to the config contains the config, ownership journal
and (API mode) `tunnel.token`. In login mode, cloudflared's tunnel credentials
JSON and account-wide `cert.pem` live in `~/.cloudflared/`; removal deletes the
journaled tunnel credentials JSON but leaves `cert.pem` and reports its path.

Visible context defaults off, is transient and bounded; heuristic redaction
cannot guarantee all secrets are removed. Source text is untrusted input,
never policy/instructions/approval. Enrolled control is separately opt-in. Session grants expose
broad native reads/control, including commands/plugins/integrations/administration
as the Herdr user. This is remote execution authority, not a sandbox. Writes need
`herdr:control` plus explicit operator grants. Titles, focus and environment
variables do not grant identity or access. No arbitrary filesystem/SQL or remote
maintenance tool is exposed.

## Runtime, access and ownership

Use private 0700 state/config directories and 0600 files, approved source socket
permissions and a trusted TLS/Host/Origin forwarding contract. One runtime owns
SQLite; source/delivery/tunnel failures report failure and clean up workers and
owned children. Foreground stop and owned service stop release store ownership.
Never delete lock files or kill an unrelated listener/PID to bypass contention.

Optional systemd user services/macOS LaunchAgents manage only connector-owned
private files. Service installation journals the paired generated file/receipt,
recovers only unchanged owned states and rejects edits/conflicts. Startup at user
login is explicit, with no root/lingering or pre-login/post-logout availability
promise. Interactive OAuth is never run in a restart loop. Private logs retain
redacted reasons rather than raw credential/client output.

Foreground tunnel use accepts its existing environment key. Services require an
owned private nonsymlink runtime-key file read at launch; only its absolute path
appears in arguments. No literal key enters a unit/plist, connection record or
chat. Only the tunnel runtime key is forwarded to its child; no admin key is
forwarded. The private-file route does not claim native OS credential storage.

Initialized access changes use explicit before/after choices, an owned-service
stop, compare-before-write private config backup/commit and restart. Content
policy can change on the same binding; principal/owner/pane/terminal/native
replacement creates a new subject and fences old watches without deleting
history. Revoke-all commits inactive access and retains data. A failed restart
never silently restores revoked grants. Already in-flight sends cannot be recalled.

## Callback and storage boundaries

Callbacks require public HTTPS port 443, all-address policy checks and numeric
connection pinning with the original TLS hostname. No ambient proxies/redirects.
Signed challenges use a bounded principal/URL/key cache. Webhook key replacement/
60-second overlap, finite subscriptions, epoch fences and exclusive store ownership
are implemented. Native replay and indefinite watches are absent.

Store/backups contain plaintext signing material and native action responses;
session responses may contain sensitive metadata. Input text is fingerprinted
rather than retained. Stable action IDs deduplicate across restart; unknown
outcomes require inspection, never automatic replay under a new ID. Enrolled
write identity checks are preflight checks, not atomic upstream mutation fences.
Status uses read-only logical database summaries without Store migration/recovery;
SQLite may update transient shared-memory WAL read marks.

Installer/update stages owned environments and verifies checks before pointer
activation; update preserves consistent stopped-owner config/database snapshots
and verifies the restarted owned runtime. Schema-change failure requires review;
no old database is restored automatically after possible actions/delivery. Default
uninstall preserves config/history/backups and user-modified shared entries.
Explicit purge previews exact private paths and requires confirmation. External
provider/cloud grants need their supported owner flows.

Encryption at rest, retention, capacity limits, fair queues and external account
revocation are not provided; plan them for your deployment. No automatic
prune/cap admission exists. Use WAL-aware stopped-owner
backup; never mix old main DB with newer WAL/SHM or publish signing material.

## Desktop and tunnel preparation

One selected wiring is prepared: registered cloud plugin, standalone HTTPS or
explicit plugin-http. Conflicting entries reject; previous dual wiring requires
an explicit owned migration. Generated plugin files contain static guidance and
connection metadata, never tokens, enrollments, transcripts or SQLite. App
installation/account consent/computer access remain supported host UI operations.
Shared-config backups may contain preexisting private settings; keep them private.

Tunnel setup verifies the official release asset digest and local client/profile
hashes, retaining notices. Existing clients/profiles are
not silently redirected/upgraded. The tunnel's control plane uses HTTPS and its
MCP/admin listeners are loopback. Tunnel access does not replace MCP OAuth,
Herdr grants, computer permission or cloud Events. Loopback discovery never
changes audience/issuer/scopes; the tested Codex resource mismatch stays blocked.

Run isolation/restart/expiry/rotation/pairing/lifecycle tests before changes. See [operations](docs/operations.md),
[authentication](docs/authentication.md) and [support](docs/support.md).
