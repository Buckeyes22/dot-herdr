# Implemented event and tool catalog

Implemented schemas: [implemented-schemas.json](implemented-schemas.json), exported from the actual catalog and pinned SDK. Endpoint path `/mcp`, protocol 2026-07-28, authenticated shared event/tool methods. Application schema_version 2 is separate from source schema 1 and store schema 2.

| Event | Qualification / meaning |
| --- | --- |
| herdr.attention.detected | Validated enrolled parent changes into detected blocked |
| herdr.turn.completed | Same validated occupant's nonnull completion_seq advances during captured observation |
| herdr.lifecycle.changed | Observed state changes; optional explicit subscription. No default transcript firehose |
| herdr.coverage.changed | Known source observation gap |

All subscriptions take exactly `arguments: {"subject_key":"demo-parent"}`. Discovery is empty for an unenrolled principal. Default native envelope carries stable eventId/name/observation timestamp/cursor:null/data. Data contains opaque subject/owner, generation/revision, source observation basis/history limitations, goal_status unknown and event-specific allowlisted fields. No terminal prompt/title/cwd/arbitrary tokens/host/chat IDs. [Attention example](../examples/attention-event.json).

A subscribe request supplies name/arguments, webhook delivery URL/whsec secret and optional cursor/ttlMs. Omitted/null lifetime gets finite 3600s; finite grants are clamped to 60s–24h. Deterministic identity is principal+URL+name+canonical arguments. Return refreshBefore exactly equals stored expiry. Native cursor is null; nonnull replay requests receive Unsupported. A successful authenticated refresh can replace its key, with 60s dual signatures. Verified principal+URL+key fingerprint cache lasts 60s. Expiry/stop fence prior pending intent; a new same-identity watch does not revive stale nonreplay events.

| Tool | Actual input | Actual result / limit |
| --- | --- | --- |
| get_profile | empty object, no arguments | Structured `{ "id": "opaque-principal" }`; validated issuer/sub identity, `openai/profile: true`, read-only; no display-name/account claims |
| get_observation_capabilities | none | Supported slice, versions/limits and explicit unsupported surfaces |
| get_agent_state | subject_key | Cached state, source timestamp, subject generation/revision, known gap and goal unknown; response time does not freshen source data |
| list_timeline | subject_key,after_position=0,limit=25(max 100) | Captured journal events and next integer application position; not native/upstream replay |
| get_event | event_id | Immutable entitled event body |
| read_visible_context | subject_key,expected_generation,lines=40(max 80) | Explicit content grant, transient visible text ≤ 16KiB, source capture revision 0, AgentInfo revision sandwich, current_read time basis/truncation; not atomic terminal coherence |
| get_connector_health | none | Scoped source last observation/gaps, delivery-state counts and explicit no-auto-prune policy; no callback secrets |
| record_triage_receipt | event_id,phase,disposition,subscription_key? | Observer bookkeeping; subscription_key optional when exactly one of the caller's watches received the event; same event/sub/phase identical retry returns original timestamp; conflict rejects |

Receipt phase started/finished; disposition observed/detail_reviewed/no_action/paused/superseded/human_decision_needed/coverage_uncertain. HTTP acceptance and receipt are different facts. Observer reads are annotated read-only; the control tools below are annotated as writes with potential destructive/external effects and request-ID dedupe; source agent.get has internal reconciliation, requiring live passivity review. Calls reject scope/identity/grant failure. SDK may return generic tool isError rather than exposing internal safe reason; protocol Event errors are mapped separately.

## Bidirectional tools

| Tool | Input | Result / permission |
| --- | --- | --- |
| get_herdr_capabilities | method=null | Entitled grants and coverage; method selects its tool route, permissions, full native parameter schema and connector limits |
| get_live_agent_state | subject_key,expected_generation | Identity-checked current safe state; refreshes the observation projection |
| wait_for_agent | subject_key,expected_generation,until=null,timeout_ms=10000 | Lifecycle wait, maximum 30s, identity recheck; no per-prompt completion claim |
| send_agent_message | subject_key,expected_generation,request_id,text | Ordinary prompt, maximum 16KiB; blocked dialog rejects before dispatch |
| send_agent_keys | subject_key,expected_generation,request_id,keys | Logical UI keys, maximum 32; can interrupt or answer dialogs |
| send_agent_input | subject_key,expected_generation,request_id,text,keys=null | Freeform interactive text and optional submit keys, including blocked questions |
| rename_agent | subject_key,expected_generation,request_id,name=null | Set/clear agent name |
| focus_agent | subject_key,expected_generation,request_id | Change Herdr UI focus |
| herdr_query | method,params | 32 native query methods under session_users grant; native output/content can contain secrets |
| collect_native_events | subscriptions,timeout_ms=10000,limit=25 | Session grant; finite native sample, max 32 filters/30s/100 events/128KiB; no reconnect or replay |
| herdr_action | method,params,request_id | 65 native actions under session_users plus control scope, including plugins/integrations, reporting and server administration |

Enrolled writes require `control: true`, current principal/generation/pane/terminal
and any configured native identity. All writes require OAuth `herdr:control`.
Session access grants broad access to the configured socket independently of
subject enrollment. Methods and parameter fields are discoverable through
capabilities, including full JSON Schemas via its optional method argument; Herdr validates native values.
[Native coverage](native-coverage.md) lists all 102 methods, including four transport
exclusions. The 19 MCP tools expose 98 native methods without one tool per method. Unknown methods/fields reject.
Cloud calls require explicit targets. Creation requires absolute cwd; native
waits are limited to 30s. Prompt submission and lifecycle waiting are separate.

Each intended write needs a unique request_id (1–128 characters). A durable
principal+ID ledger stores an operation digest and result before/after input,
without storing the input text itself. Exact retries return the recorded result;
conflicting reuse rejects. A crash or lost source response leaves `outcome:
unknown`, never an automatic resend. Even native error responses can follow
partial input. Inspect source before sending a new action. `submitted` records
Herdr acknowledgment. Enrolled identity checks precede
writes. See [control examples](control.md).

## Bundled workflow skill

The server declares `io.modelcontextprotocol/skills` and serves authenticated
`skills/list`, `skills/get` and `resources/read` for
`skill://dot-herdr/herdr-connector/SKILL.md`. The catalog provides the
complete frontmatter and SHA256 digests for its entry point and three focused
references (setup, events and control). Each is served by authenticated
resources/read under the same skill URI prefix. No caller file path is resolved.
The entry point provides essential invariants and routes to detail on demand.
Method discovery supplies route, permissions and extra connector constraints
alongside the native schema. See [information layout](guidance.md).

Supported plugin hosts import a static skill snapshot during their server scan;
updated instructions require rescanning and updating the plugin. See the
[official import contract](https://developers.openai.com/plugins/build/mcp-server#import-skills-from-the-mcp-server).

Tool example:

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_agent_state","arguments":{"subject_key":"demo-parent"},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}
```

For a manual authorized request, native metadata/headers must follow the pinned SDK/MCP2 contract: Authorization bearer, Accept JSON/event-stream, MCP-Protocol-Version2026-07-28, Mcp-Method and Mcp-Name for tools/call. Do not log/paste real bearer tokens.

Standard webhook headers: Content-Type application/json, webhook-id identical to eventId, signing-time Unix seconds, exact-byte HMAC webhook-signature, X-MCP-Subscription-Id. One object per POST, ordinary event ≤ 4KiB and transport ≤ 256KiB. Stable body/ID retries, fresh signature timestamps, max 6 attempts/backoff; 410/413 terminal.

See [protocol compliance](protocol-compliance.md) and [architecture](architecture.md).


The full connector has 19 tools; native coverage remains 98 of 102 methods.
The auth-only setup endpoint exports just get_profile and records bounded verified
candidates for local confirmation. Confirmed enrollment, not login exit status,
activates Herdr access. Local setup/status/service/access/update/uninstall
commands are local CLI operations and are not MCP tools.
