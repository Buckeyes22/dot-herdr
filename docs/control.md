# Communicate with agents and control Herdr

Your dot can receive events, inspect the agent, send an instruction or an
interactive reply, and check the result through this connector. Full session
access also supports agent startup, shell commands, topology/worktrees, plugins,
integrations, notifications, metadata and server administration. One connector process handles both directions.

## Choose access

For control of an enrolled agent, set `control: true` on that subject. Keep
`content: true` if the dot should also read its bounded visible context.
Other subjects remain observation-only. Exact pane/terminal/native identity
and subject generation are checked before input.

For broad access to the selected Herdr session, add your OAuth token's exact
`sub` value to `session_users`:

```json
{
  "session_users": ["your-actual-oauth-user-subject"],
  "subjects": []
}
```

These are two fields of the normal configuration, not a complete config.
Keep the existing socket, store, issuer, resource and public_key fields.
Session-only access needs no pre-enrolled pane identities; add subjects when
you want event subscriptions for particular agents. Agents created through the
session API are not automatically added to the observation roster.

All endpoint calls require `herdr:observe`; writes additionally require
`herdr:control` in the OAuth access token. The provider/client consent must
issue both scopes for a controlling dot. Local grants still determine
which targets it can access. Apply config changes by stopping the connector,
editing the private file and restarting. Older configurations work unchanged.

Session access includes native terminal output and commands with the Herdr
user's privileges. It covers the configured local socket, not other sessions
or machines. Its reads do not use the enrolled visible-context redaction filter.
Only grant it to the intended administrator identity.

## Send an enrolled agent a message

First call `get_herdr_capabilities` and `get_agent_state`. Use the returned
subject key and generation:

```json
{
  "name": "send_agent_message",
  "arguments": {
    "subject_key": "selected-agent",
    "expected_generation": 1,
    "request_id": "fix-test-001",
    "text": "Fix the failing test, rerun it, and report the result."
  }
}
```

This is the content of an authenticated tools/call request, not a token or a
complete transport example. A successful result says `outcome: submitted`.
Inspect the reply using `read_visible_context` and `get_live_agent_state`;
`wait_for_agent` provides a finite lifecycle wait. A completed turn or idle
state is not task success.

Ordinary prompts reject blocked dialogs. Inspect the visible question first.
Use `send_agent_input` with `text` and `keys: ["enter"]` for a freeform reply,
or `send_agent_keys` for logical keys such as `esc`, `ctrl+c`, `y` and `enter`.
Keys can interrupt work or answer approval dialogs. The dot must follow your
actual decision authority; an attention event does not grant new authority.
There is no typed approval or task-result API.

## Manage the session

Call `get_herdr_capabilities` for method names, fields and coverage. Supply
`method` to get its complete native parameter JSON Schema, including nested
filters, layouts and invocation contexts, plus connector limits.
`herdr_query(method, params)` exposes 32 queries;
`herdr_action(method, params, request_id)` exposes 65 actions.
`collect_native_events` provides the remaining supported streaming method.
This covers 98 of 102 methods in Herdr 0.9.3 (protocol 22/schema 1); see the
[complete coverage table](native-coverage.md). Herdr validates native values.
Unknown methods or parameter fields are rejected.
Targets must be explicit; cloud tools never rely on UI focus.

Useful examples of method and params:

| Workflow | Method | Params |
| --- | --- | --- |
| Find agents | agent.list | {} |
| Inspect agent | agent.get | target: exact pane ID or unique agent name |
| Read reply | agent.read | target, source: recent_unwrapped, lines: 80, format: text |
| List panes | pane.list | workspace_id optional |
| Split sibling | pane.split | target_pane_id, direction: right/down, absolute cwd, focus: false |
| Start agent in shell | agent.start | pane_id, name, kind, optional args; timeout_ms defaults 30000 |
| Send prompt | agent.prompt | target, text; wait separately |
| Wait for state | agent.wait | target, until: [idle,done,blocked], timeout_ms: 10000 |
| Run shell command | pane.send_input | pane_id of a ready shell, text, keys: [enter] |
| Read terminal | pane.read | pane_id, source: recent_unwrapped, lines: 80, format: text |
| Create workspace | workspace.create | absolute cwd, optional label, focus: false |
| Create tab | tab.create | workspace_id, absolute cwd, optional label, focus: false |
| Rename/focus/close | workspace/tab/pane corresponding method | explicit workspace_id/tab_id/pane_id and native fields |
| Manage layout | layout.export/apply/set_split_ratio | explicit tab/pane/workspace target and native layout fields |
| Manage worktrees | worktree.list/create/open/remove | explicit workspace or cwd; native branch/path/trust/force fields |

Use IDs returned by discovery and creation. Pane IDs belong to one server.
Inspect `pane.process_info` before starting an agent or running a shell command;
a pane label alone does not establish an interactive shell. Creation defaults
to preserving UI focus. Wait/start timeouts are bounded to 30 seconds; repeat
state checks or use events for longer work. Do not close existing panes or
remove worktrees unless that effect is requested. Repository trust and force
removal are explicit choices rather than routine retries.

## Plugins, integrations, reporting and administration

Discover installed plugins with `plugin.list`, actions with `plugin.action.list`
and recent logs with `plugin.log.list` (default 25, max 100). Link an existing
absolute plugin directory with `plugin.link`; enable/disable/unlink by plugin ID.
Invoke installed actions using `plugin.action.invoke` and an explicit context
containing `focused_pane_id`, `tab_id` or `workspace_id`. Open a plugin pane with
its actual plugin ID/entrypoint, explicit target and absolute cwd. Native plugin
execution has the source user's privileges. The connector does not download
plugins or install missing dependencies.

`integration.list`, `.install` and `.uninstall` manage Herdr's supported agent
integrations. Installation changes integration configuration; it does not start
an agent. Use the discovered native target enum, not an invented agent name.
`notification.show` creates a native toast; release/product dismissal changes
native UI state. `agent.view.set/clear` manages the session agent panel; filters
and sort rules are in its parameter schema.

`pane.report_agent`, `.report_agent_session`, `.report_metadata` and
`workspace.report_metadata` publish actual source information. Report only
verified identity and lifecycle evidence. A reported state can influence native
detection, waits and notifications.
Use clear/release authority methods only for the requested repair.

Server methods support configuration/agent-manifest reload, native live handoff
and shutdown. `server.stop` affects the entire configured session and its
workloads. A live handoff needs the installed compatible executable and native
platform support. These actions require the session grant and write scope.

`command.invoke` accepts an actual opaque command ID from the native foreground
client's command manifest and an explicit target. Ordinary JSON session snapshots
do not expose these IDs. Never guess an ID or pass shell text as a command ID;
use terminal input for an authorized shell command.

## Collect native events

`collect_native_events(subscriptions, timeout_ms=10000, limit=25)` opens one
native `events.subscribe` socket, collects a finite sample and closes it. For
example, subscribe to `[{"type":"pane.agent_status_changed","pane_id":"an-exact-pane-id"}]`.
Discover all native subscription kinds through
`get_herdr_capabilities(method="events.subscribe")`.

Limits are 32 subscription filters, 30 seconds of collection, 100 events and
128KiB of event data. Opening the socket can take up to an additional 10 seconds.
The result reports deadline, event/byte limit, source error or disconnect;
`events_lost` remains visible in captured events. It never reconnects. It requires session access and its output can contain secrets.
It is separate from the connector's durable four-event dot monitoring workflow.
Native `events.wait` supports only the pane-agent-status matcher in Herdr 0.9.3;
other native matcher shapes reject rather than suggesting they work.

## Transport limits

Four native methods need a foreground-client or persistent transport:
`client.window_title.set/clear`, `client_shell.surface.set` and
`server.ssh_agent.register`. They remain discoverable with a specific reason,
but cannot be dispatched through the query/action tools. No client-shell binary
protocol or SSH credential-forwarding service is added to this simple connector.

## Handle uncertain results

Use one unique request_id for each intended write. An exact retry with that ID
returns the durable recorded result without submitting again, even after
restart. Reusing an ID for different input rejects. Keep the same store across
upgrades to preserve dedupe.

A lost response, native error, cancellation or crash can leave `outcome:
unknown`. The source may have received some or all input. Inspect current agent
state/output before deciding what to do; blindly using a new request ID can
duplicate the instruction. A crash before sending can also leave unknown.
This provides at-most-one dispatch per stored ID, not guaranteed delivery.

Enrolled identity validation is a preflight check. Herdr's input API has no
atomic expected-pane/terminal/native-session fence, so a replacement racing
that check is still possible. Session-wide controls intentionally act on the
explicit current native target and do not carry an enrollment fence.

The bundled herdr-connector skill teaches these workflows together with setup,
event triage and stopping monitoring. Supported plugin hosts import a static
snapshot during a server scan; update/rescan the plugin after skill changes.

## Worked native calls

These are MCP tool names and arguments. IDs, paths, plugin entrypoints and
source facts are illustrative; replace them with actual discovery results.
Check `get_herdr_capabilities(method)` first for unfamiliar parameters.

Read an agent's response:

```json
{"name":"herdr_query","arguments":{"method":"agent.read","params":{"target":"an-exact-pane-id","source":"recent_unwrapped","lines":80,"format":"text"}}}
```

Find installed plugin actions, then invoke an actual one in an explicit context:

```json
{"name":"herdr_query","arguments":{"method":"plugin.action.list","params":{}}}
```

```json
{"name":"herdr_action","arguments":{"method":"plugin.action.invoke","params":{"plugin_id":"an-installed-plugin-id","action_id":"a-discovered-action-id","context":{"focused_pane_id":"an-exact-pane-id"}},"request_id":"plugin-action-001"}}
```

Open an installed plugin entrypoint in a chosen workspace:

```json
{"name":"herdr_action","arguments":{"method":"plugin.pane.open","params":{"plugin_id":"an-installed-plugin-id","entrypoint":"an-actual-entrypoint","workspace_id":"an-exact-workspace-id","cwd":"/absolute/source-host/project","placement":"tab","focus":false},"request_id":"plugin-pane-001"}}
```

Inspect the current native layout before changing it:

```json
{"name":"herdr_query","arguments":{"method":"layout.export","params":{"tab_id":"an-exact-tab-id"}}}
```

Filter the agent panel to idle agents using a named view:

```json
{"name":"herdr_action","arguments":{"method":"agent.view.set","params":{"source":"dot-view","filter":{"op":"eq","field":"status","value":"idle"},"sort":[{"field":"workspace_order"}]},"request_id":"view-001"}}
```

Publish verified display metadata, without asserting task completion:

```json
{"name":"herdr_action","arguments":{"method":"workspace.report_metadata","params":{"workspace_id":"an-exact-workspace-id","source":"dot-metadata","tokens":{"task":"review"},"ttl_ms":60000},"request_id":"metadata-001"}}
```

Collect a short native status-event sample:

```json
{"name":"collect_native_events","arguments":{"subscriptions":[{"type":"pane.agent_status_changed","pane_id":"an-exact-pane-id"}],"timeout_ms":1000,"limit":10}}
```

For task-specific dot monitoring, use the host Events subscription workflow
instead of repeatedly collecting native samples. See [information layout](guidance.md)
for how the skill, references and method discovery work together.
