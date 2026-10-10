# Protocol compliance

Audit date: 7 October 2026. Governing host profile: [OpenAI MCP Events](https://developers.openai.com/plugins/build/mcp-events). Related references: [authentication](https://developers.openai.com/plugins/build/auth), [security/privacy](https://developers.openai.com/plugins/guides/security-privacy), [linked experimental design](https://github.com/modelcontextprotocol/experimental-ext-triggers-events/blob/main/docs/design-sketch-proposal.md).

| Applicable behavior | Implementation seam |
| --- | --- |
| MCP2 discovery; authenticated event/tool endpoint | endpoint.build + SDK capabilities middleware |
| Stable catalog, scoped filters and closed schemas | catalog, validate_subscription, principal roster |
| Canonical identity / refresh persistence | Store.subscription_identity, activate; sorted canonical JSON |
| Ownership, filters, URL, key and lifetime | subscriptions SQLite |
| Secret validation | decode_secret |
| Verify before activation | verify then store.activate |
| Fresh single-use signed challenge, bounded age | unique random challenge + unique ID, asyncio.wait_for 10s, constant-time echo |
| Bounded verification cache | Store.verifications principal+URL+key fingerprint, 60s |
| HTTPS/public destination at connect, pinned TLS host, no redirects/proxy | destination, PinnedHTTPS, PublicTransport |
| TTL/default/null/expiration | Subscribe.ttlMs, finite default 3600s, 60s min/24h max |
| Signing-key replacement | activate previous_secret/rotation_until; dual signatures 60s |
| Expired lifetime fences prior delivery intent | activate increments epoch and stops pending/sending |
| Same-identity restart after stop; authorized idempotent unsubscribe | unsubscribe; stopped reactivation fences prior epoch |
| Access rechecked through lifetime | subject principal/enabled joins; sync_roster disables subs/epochs |
| One occurrence per POST, stable ID, allowed data/schema/time | transactional immutable journal+delivery; observation time is connector occurrence |
| Summary plus on-demand tools; text is evidence | tiny event allowlist; bounded transient context read |
| ≤ 262144 bytes | MAX_EVENT 4096; PublicTransport MAX_BODY 262144 |
| Exact Standard Webhooks bytes/headers | headers HMAC SHA256 ID.timestamp.body |
| Durable outbox and bounded retries | atomic observe; claim; delivered max 6/backoff |
| 2xx only records transport acceptance | accepted state separate receipts |
| Out-of-order/duplicate-safe write tools | immutable receipt PK(event,sub,phase) |
| Native replay absence | cursor:null; nonnull rejected |
| Crash recovery only after ownership | exclusive lockfile; startup sending→pending; schema migration transaction |
| Auth resource/audience/subject separation | JWTVerifier RS256 exact issuer/audience, SDK scope enforcement |
| Supported host modes only | webhook application events |

For deployment checks and failure recovery, see [operations](operations.md) and [troubleshooting](troubleshooting.md).

