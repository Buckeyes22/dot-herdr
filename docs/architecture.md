# Architecture and trust boundaries

One supervised runtime, foreground or owned user service, with one exclusive private SQLite store. Source/delivery/request workers are separate; callback latency must not block invalidation draining.

```text
Approved local approval roster ──► exact principal / parent grants
Existing local Herdr ──► invalidations ──► dirty refresh / identity validation
                                         │
                                         ▼
                   SQLite transaction: projection + immutable event + outbox
                                         │
                           authenticated native subscriptions
                                         │
                     public HTTPS pinned callback / bounded retries
                                         ▼
                    subscribed ChatGPT/dot chat
                                         │
                 scoped reads / control tools + observer receipts
                                         │
                         authenticated Herdr source actions
```

## Source facts and uncertainty

AgentInfo identity/counters are refreshed after pushes. The same validated occupant can produce a blocked attention cue or qualified completion counter advance. Source narrative is untrusted text. A restored source session records a coverage gap and takes a baseline; counters across a gap cannot reconstruct episodes/questions/times.

Current source has volatile 512-event history with unchecked specialized paths, no public event epoch/cursor/occurrence timestamp/atomic snapshot watermark. Local durability cannot recover upstream unseen transitions. Current observation time is the connector event's occurrence time, with upstream occurred_at unknown.

## Persistence and ordering

Observation validates identity/status/counters/metadata types and commits state, event and delivery intent in one SQLite transaction. A process lock fences recovery before sending rows become pending. The global journal position orders local commits; per-subject revisions indicate semantic change. Separate immutable event IDs survive retries/restarts. Body bytes freeze once; signing time/attempt is new each retry. Six bounded attempts and ledger stages distinguish accepted/dead_letter/stopped/pending; accepted is not triaged.

A finite subscription's identity is authenticated principal+callback+event+canonical arguments. Expiry/unsubscribe/revocation fence prior epochs. Late terminal responses from an old epoch cannot disable a new watch. Key rotation is a separate brief overlap, not OAuth-key rollover. Native replay is null; application timeline is only captured history. No missing receipt causes resend. Receipt uniqueness is event/sub/phase, exact retry returns original timestamp and conflicting disposition rejects.

## Read/privacy boundary

Metadata events omit terminal content/title/cwd/arbitrary token dictionaries. Current state exposes a typed safe allowlist and cached observation timestamp. Context reads need an explicit content grant, exact generation and matching before/after identity/AgentInfo revision; entitlement is checked after awaits. Max 80 lines/16KiB visible-only transient content; known secret patterns withheld. Enrolled reads do not expose hidden transcripts or arbitrary files. Session grants expose native terminal reads and input, which can execute shell commands as the Herdr user. There is no separate arbitrary filesystem or SQL tool.

External RS256 resource auth and local grants are distinct. Callback-controlled secrets are privately stored; DNS/TLS pinning applies to challenge and event. The chat destination is chosen by authenticated callback flow. Terminal text cannot alter grants/policy or supply command authority.

## Control boundary

The same authenticated endpoint supports enrolled-agent controls and optional
session-wide access. Enrolled writes validate current principal, generation,
pane, terminal and native identity immediately before submission; Herdr does
not provide an atomic expected-identity mutation fence. Session grants permit
broad native reads and controls on the configured socket, including shell input.
Neither titles nor UI focus grant access. OAuth control scope is necessary but
insufficient without a local grant.

The native adapter covers 98 of 102 Herdr 0.9.3 methods: 32 queries, 65 actions and
one bounded event collector. Packaged native parameter schemas provide discovery
for nested inputs. Broad grants include plugins, integration configuration,
metadata/lifecycle authority and server administration. Four foreground-client or
persistent-lease methods remain unsupported; see the native coverage table.

Native event collection opens a separate short-lived socket with time/count/byte
bounds. It preserves captured loss notices and end reasons, never reconnects,
and creates no callback subscription or durable journal entry. The existing
four-event projection and callback workflow continues independently.

Writes are serialized and use a durable principal/request-ID ledger. Only an
operation digest is stored, plus the response; prompt text is not retained.
An unknown result survives restart and deduplicates later calls. This is
at-most-one dispatch per ID. A
crash before dispatch can leave an undelivered operation unknown. Uncertain
operations require source inspection, not automatic retries or a new ID.

The bundled workflow skill is a static authenticated resource, packaged with
the connector and exported through the draft skill import extension. Hosts
control import and loading; updated server instructions do not replace an
already imported snapshot.

## Remaining operational boundaries

Explicit access changes replace identities and fence old watches; no automatic move/rebind, version-schema negotiation, worker/result/approval authority, fair multi-owner queues, retention pruning/cap admission or automated external key/account revocation. Worker/tunnel failures stop and clean up the runtime; disk/queue capacity still needs a local plan. Monitoring failure does not itself stop source work. Authorized interactive keys/input can interrupt or resume an agent. Source action attempts are persisted separately from the event outbox and never automatically retried.

See API/schema, protocol compliance, auth/deployment and operations guides.

## Setup and local lifecycle

CLI arguments delegate to one shared runtime. Guided setup keeps private drafts
and a nonsecret route/wiring resume record, discovers pinned issuer-origin JWKS,
then opens a finite auth-only pairing endpoint. That endpoint exposes only
get_profile; it never constructs Herdr workers, callbacks or Store. A verified
request plus local account confirmation activates approved grants. JWKS/static
verification enforces the same issuer/resource contract; key refresh does not
provide account revocation.

Status reads atomic freshness/process records and read-only database summaries,
with optional bounded source/discovery probes. It never constructs Store.
User services manage only owned files/processes in logged-in sessions.
Access commits a complete stopped-owner config/roster change. Installer/update
stages immutable environments and switches an owned pointer; failure recovery
retains dedupe and never automatically restores an old database.
