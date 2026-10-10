# Configuration reference

Prefer `dot-herdr setup`: it discovers existing sessions/agents, copies identities,
creates private directories and writes config. Setup/check/run share the default
user config directory; `--config` selects a custom path. Pending setup resumes private drafts; initialized configuration proceeds through
connection/runtime/check stages. Use `dot-herdr access` to change its grants. See [guided setup](getting-started.md).

Manual `dot-herdr init-config --output /chosen/private/config.json` remains
available: existing parent must be 0700, file 0600, no overwrite. The
[example](../examples/config.example.json) contains unusable placeholders.

| Field | Type / constraint | How to obtain / meaning |
| --- | --- | --- |
| store | Absolute string path | Dedicated private local state directory; 0700 parent, 0600 files. Connector SQLite, never another app's database |
| socket | Absolute string path | Documented existing local Herdr Unix socket belonging to the approved installation/session. No arbitrary SSH command/remote URL |
| issuer | HTTPS URL without credentials/query/fragment | Exact external authorization issuer used in token iss and discovery; do not guess/truncate trailing paths |
| resource | HTTPS URL without credentials/query/fragment | Exact canonical MCP audience ending `/mcp`; must match OAuth aud and SDK resource metadata. With a private tunnel it remains an HTTPS identifier, without requiring a public MCP listener |
| local_port | Optional integer 1024–65535, default 8000 | Advanced loopback listener port. Set it when another service uses 8000; the public route or forwarder must target this same port. Omit it to preserve the default configuration. |
| jwks_url | HTTPS URL on issuer origin | Discovered provider JWKS; exactly one of jwks_url/public_key is required |
| public_key | Absolute file path | External issuer's RSA **PUBLIC** key, PEM SPKI or PKCS1, 2048–8192 bits, ≤ 16KiB, regular nonsymlink file. Normalized to SPKI internally. Not issuer private key/client secret/bearer token |
| subjects | Array0–32 | Explicit observation roster. Empty is allowed with a session_users grant or an inactive configuration |
| inactive | Optional literal boolean | Revoke-all state; no effective grants, normal startup refused |
| access_accounts | Optional string array | Previously verified accounts retained for explicit access re-enablement; not new grants |
| session_users | Optional array0–32, defaultempty | Exact OAuth token sub values granted broad read/control access to the configured Herdr session; not display names or client IDs |
| subject.key | Unique string1–128 | Stable local opaque subject handle used in subscriptions/tools |
| user_subject | String1–256 | Verified token sub from configured issuer, recorded after local pairing confirmation. Not OAuth client_id, display name or dot ID |
| owner | String1–256 | Locally chosen opaque owner/assignment label |
| pane, terminal | Strings1–256 | Exact approved current Herdr IDs; title/cwd cannot substitute |
| native | Omitted/null or exact object | If present, source/agent/kind/value, each nonempty string≤ 256; copy actual AgentSessionInfo. Do not invent values. Null provides weaker exact pane+terminal binding |
| content | Optional literal boolean, default false | Grants bounded transient visible context. No string `"false"` or broad transcript/file access; enable only for approved content |

| control | Optional literal boolean, default false | Grants enrolled-agent messages, interactive text/keys, naming and focus; writes also require OAuth scope herdr:control |

See [control](control.md) for narrow agent and full session examples. Session access includes terminal content without the bounded enrolled content filter, and terminal input can execute commands as the Herdr user. Set it only for the intended administrator identity. Grants take effect on restart. Existing configs with neither new field remain observation-only.

Root and subject unknown fields are rejected. Paths must be absolute. `.invalid`, `/path/to/…` and `replace-with-…` template markers block check/run. Config ≤ 64KiB, nonsymlink regular file, no group/other access. Doctor checks local files without opening SQLite or connecting the socket. Check validates configuration/key only; it does not obtain tokens.

## Find the source session and pane

The connector can run outside Herdr. It uses the configured `socket`, `pane`
and `terminal`; inherited `HERDR_*` variables are optional context and never
override configuration.

A terminal frontend inside Herdr can have `HERDR_ENV=1` and `HERDR_PANE_ID`
while its detached agent backend or tool runner has neither. Missing variables
or a process tree that ends at a daemon do not establish that the conversation
is outside Herdr. `doctor` reports the available environment context separately
from the configured socket check, without discovering or enrolling panes.

Use the existing Herdr CLI to identify the session you intend to monitor:

```sh
herdr session list --json
```

Select an existing running session and copy its `socket_path`. Inspect that
session explicitly; the path and IDs below are placeholders:

```sh
HERDR_SOCKET_PATH=/absolute/path/to/session/herdr.sock herdr workspace list
HERDR_SOCKET_PATH=/absolute/path/to/session/herdr.sock herdr pane list --workspace w1
HERDR_SOCKET_PATH=/absolute/path/to/session/herdr.sock herdr agent get w1:p1
```

Use workspace/pane labels to locate a candidate, then verify its identity.
Copy `pane_id` and `terminal_id` from the `agent get` response into your subject
configuration. If Herdr reports `agent_session`, copy that exact object into
`native`. Otherwise leave `native` null: a Codex thread ID from a tool runner
is not a substitute for a session identity reported by Herdr. Labels, working
directories and focus alone do not prove which conversation owns a pane; check
the selected pane against your intended agent before enrollment.

Keep the selected socket and IDs together: pane IDs are scoped to one Herdr
server. These commands inspect existing state; they do not start a session or
enroll subjects in the connector. Ordinary setup does not need process scans,
environment dumps, terminal capture or automatic pane discovery.

Principal is SHA256(canonicalJSON([issuer,token.sub])). `get_profile` exposes it
as an opaque ID; normal setup never asks for a typed subject or manually pasted
hash. Enrollment identity remains immutable, while content policy is mutable.
Use `access` for changes: a replacement pane/terminal/native identity receives a
new subject key and the old watch is fenced. Never edit SQLite/delete history to
bypass identity checks. Generation remains 1 for a binding.

The private draft and connection record beside the config retain resume stage,
route/wiring and nonsecret ownership receipts. They contain no OAuth tokens,
passwords, callback secrets or tunnel key. Stage history is a hint, not live proof.
Guided setup discovers JWKS with provider compatibility checks; static-key users
remain supported. Offline doctor/check performs no network JWKS refresh.

Config has no callback URL/signing key fields: ChatGPT supplies those through authenticated events/subscribe; they are privately persisted in the connector store. No private keys, credentials or source transcripts belong in the checkout, fixture files, issues or docs.

For permissions, create only the chosen new directory rather than chmodding a shared parent. Example `mkdir -m 700 /chosen/private/state` assumes its parent exists and you are authorized to create it. `init-config` never chmods another directory. A public key is not secret, but it must come from a trusted issuer channel; replacing it changes trust.
