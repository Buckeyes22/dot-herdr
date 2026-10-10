# Troubleshooting

Start with `dot-herdr status` and its `Overall` action; use `status --live --json`
for bounded read-only source, public reachability and discovery checks. The
JSON includes `overall.verdict` and `overall.next_action`. `doctor` and `check`
are offline. None of them logs credentials.
Use the existing CLI/API access before asking for new sign-in. Do not dump
credential files, OAuth replies or terminal transcripts into support reports.
Normal commands hide routine MCP, HTTP, and server logs and the known Pydantic
`RequestParamsMeta` warning. Set `DOT_HERDR_DEBUG=1` for full dependency logs
when diagnosing a problem; keep those logs private because they may contain URLs.

| Observation / safe reason | Next action |
| --- | --- |
| Missing/invalid config or pending draft | Rerun setup with the same absolute config path; completed selections are retained |
| Missing source / unsupported version | Start/select the existing Herdr 0.9.3 protocol 22 session; run `dot-herdr access` to select a running session, or `dot-herdr setup --socket /absolute/path/herdr.sock` during initial setup |
| Occupied port / foreground owner | Stop that owner explicitly; setup/service/access never kills an arbitrary PID |
| Stale runtime record / connector stopped | Start the owned service with `dot-herdr service start`, or run `dot-herdr run` in a normal terminal and keep it open |
| Public route returns HTTP 502 or a network error while the local connector runs | Check the selected URL's route or forwarder to this computer's configured local port |
| Public route responds but metadata mismatches | Keep the hostname, plugin URL, resource/audience and issuer consistent; repair the selected metadata contract |
| HTTP 403 with a Cloudflare challenge | Cloudflare bot protection blocks ChatGPT calls; turn it off for this hostname or add a skip rule before adding the plugin. dot-herdr does not change zone security settings |
| HTTP 530 or Cloudflare error 1033 | The Cloudflare tunnel is down. Check that cloudflared is running (`dot-herdr status` shows the cloudflared child); restart with `dot-herdr service restart` or `dot-herdr run` |
| HTTP 524 | Cloudflare timed out waiting for this computer (HTTP 524). Check that the connector is running and responsive |
| Sign-in page is rate-limited | Run `dot-herdr signin set-password`; setting a new password clears failed-login counters. The exponential lockout backoff is capped at 60 seconds |
| Worker/tunnel failure | Inspect the redacted reason, repair its prerequisite and restart the owned service/foreground runtime |
| Provider metadata rejected | Ask its administrator to verify HTTPS same-origin endpoints, PKCE S256, registration/public callbacks and Herdr scopes |
| Unknown key / bad issuer/audience / expired token | Repair the selected provider contract; never weaken verification or supply synthetic tokens |
| Identity pairing pending | In ChatGPT in a web browser (chatgpt.com), open Settings → Plugins → + → Add custom MCP server → enter URL → Create as a plugin → password page → back in Settings. If already connected, use the Herdr plugin once in ChatGPT (for example, request `get_profile`) so the candidate appears in the setup terminal. No terminal input is needed while waiting; approve the verified candidate when it appears |
| Account access says observation only while control is selected, or `control_scope_required` | In ChatGPT in a web browser (chatgpt.com), open Settings → Plugins, remove the Herdr plugin, add it again with the same URL, and tick **Also allow Herdr control** on the password page. Observation works while control awaits renewed consent; then run an authenticated request and check `dot-herdr status` again |
| Control tools refused or never run | If control was selected, in the Herdr plugin's settings switch tool access from low-risk only to allow all tools; control actions are marked as write actions, so the low-risk setting blocks them |
| Registered plugin not yet visible in ChatGPT web | In ChatGPT in a web browser (chatgpt.com), open Settings → Plugins → + → Add custom MCP server → enter URL → Create as a plugin → password page → back in Settings; return to the setup terminal for verified account approval |
| Route/wiring change rejected | Run `dot-herdr migrate-route` to review and confirm the selected route/wiring; modified and unrelated entries are preserved. If a target file conflicts, move the named file aside and retry |
| Codex loopback resource mismatch | Use approved reachable HTTPS with matching resource; the tested loopback route is blocked |
| Missing tunnel runtime key | Supply the foreground environment or an owned private service credential file; never paste its contents |
| Service manager unavailable | Use foreground operation or repair the logged-in user's service manager |
| Changed/unowned service/config entry | Preserve it for inspection; do not overwrite unrelated or user-modified files |
| Connection test expired or uncertain | Resume the setup terminal to identify a new local watch by subject and event, or paste its exact subscription ID if available. Confirm only the watch created by the dot; unidentified watches remain untouched. Run `dot-herdr check-recovery --recovery inspect`, inspect the saved action, then finish, abandon or start a new request with an explicit unique ID |
| Monitoring expired | Explicitly renew a finite watch in the host; expiry does not stop the source agent |
| Inactive access | Use access to explicitly re-enable the approved account/targets; old watches remain fenced |
| Access saved, restart failed | Repair/restart; revoked grants are not automatically restored |
| Unknown source action outcome | Inspect source state and retain its request_id before another submission |
| Update schema changed / recovery required | Keep service stopped, inspect the update receipt and follow consistent restore; never run an incompatible old binary |
| Callback accepted / triage but destination unknown | Run the guided nonce test in the intended destination |
| Check says ChatGPT did not record handling | The host may have kept an older required-string tool schema. Its test automation must pass `subscription_key=""` to `record_triage_receipt`; refresh the plugin tools in Settings if the receipt still fails. |
| Check says message outcome unknown | Run `dot-herdr check-recovery --recovery inspect`; the saved request ID must not be sent again. |

Grant failures require scoped rechecks, not broader content reads. Use `access`
for initialized changes; changing a pane/native identity creates a new subject
and fences the old watch. Missing `HERDR_*` in a detached runner does not establish
Herdr absence and never overrides configured source identity.

See [reachability](reachability.md), [configuration](configuration.md) and [operations](operations.md).
