# Agent and session control

Call `get_herdr_capabilities` to see your actual grants. Enrolled agent control
needs `control: true` in its configuration and OAuth scope `herdr:control`.
Whole-session access needs your issuer subject in `session_users`; mutation
also needs that OAuth scope. These are operator settings, not permission the
dot can infer or grant itself. Existing observation-only configurations work.

For enrolled agents, use the generation returned by state:

- `send_agent_message(subject_key, expected_generation, request_id, text)`
  submits an ordinary prompt. Herdr rejects ordinary prompts at blocked dialogs.
- `send_agent_keys(..., keys)` sends logical keys, such as `esc`, `ctrl+c`, `y`
  or `enter`. This can interrupt work or answer a dialog.
- `send_agent_input(..., text, keys=["enter"])` types a freeform reply and
  submits it; inspect the current question or approval UI before replying.
- `rename_agent(..., name)` sets or clears a display name; `focus_agent(...)`
  brings it into focus when the user requests that.
- `get_live_agent_state(subject_key, expected_generation)` refreshes source
  state. `wait_for_agent(..., until, timeout_ms)` waits at most 30 seconds,
  defaulting to idle/done/blocked. It tracks lifecycle, not a particular task.

Use a unique `request_id` for each intended action and retain it. Exact retries
return the durable recorded result without sending input again, including
after connector restart. A different operation with that ID rejects. If the
outcome is `unknown`, inspect the source before deciding on a further action;
never blindly submit the same input under a new ID. `submitted` means Herdr
acknowledged the operation, not that the task succeeded. Identity is checked
before enrolled writes; Herdr does not support an atomic expected-identity
write fence, so a replacement racing that check remains a limitation.

With session access, `herdr_query(method, params)` reads native Herdr metadata,
terminal output and bounded waits. `herdr_action(method, params, request_id)`
exposes 65 native actions for agents, topology/worktrees, plugins, integrations,
notifications, views, metadata/lifecycle reporting and server administration.
There are 32 queries and a bounded native event collector, covering 98 of 102
native methods in Herdr 0.9.3, protocol 22, schema 1. The capabilities result
lists names, fields and coverage.
Call `get_herdr_capabilities(method="the.native.method")` for the full native
parameter JSON Schema, nested definitions and connector limits. Herdr
validates native values; unknown methods or fields are rejected. Use IDs
returned by discovery/creation, always within the configured socket's session.
Session access is broad: output can contain secrets, and terminal input can
execute commands with the Herdr user's privileges. Keep sensitive output out
of chat and public files.

Typical workflows:

1. Discover agents with `herdr_query("agent.list", {})`. Read a particular
   agent with `agent.get` (`target`) or `agent.read` (`target`, `source` such as
   `visible` or `recent_unwrapped`, bounded `lines`, `format: "text"`).
2. To start another agent, inspect `pane.list` and `pane.process_info` first.
   Prefer an available shell or a sibling pane. Split with `pane.split` using
   explicit `target_pane_id`, `direction: "right"` or `"down"`, absolute `cwd`
   and `focus: false`. Start with `agent.start`: `pane_id`, unique `name`,
   supported `kind` and optional native `args`; default timeout is 30 seconds.
3. Prompt it with `agent.prompt` (`target`, `text`). Then read/wait separately
   with `agent.wait` (`target`, `until`, finite `timeout_ms`). A prompt during
   working state can be queued; an active turn settling is not proof that
   the new instruction completed. Inspect the actual response.
4. Run a shell command in an explicitly chosen shell pane with `pane.send_input`
   (`pane_id`, `text`, `keys: ["enter"]`). Use `pane.read` or bounded
   `pane.wait_for_output` to inspect it. Never infer shell readiness from a
   pane title. Agent prompt/input tools target agent UIs, not shell commands.
5. Create workspaces/tabs only when the task calls for that topology. Creation
   requires explicit absolute `cwd`, and tabs require `workspace_id`. Keep
   `focus: false` for background work. Do not close existing user panes or
   remove worktrees unless the user requested that effect. Repository trust
   and force deletion are explicit choices, never routine error retries.

## Plugins, integrations, reporting and administration

Use `herdr_query("plugin.list", {})`, `plugin.action.list` and bounded
`plugin.log.list` to discover actual installed capabilities. Link only an
existing absolute plugin path; enable/disable/unlink using discovered IDs.
Invoke a plugin action with its actual ID and explicit context target
(`focused_pane_id`, `tab_id` or `workspace_id`). Plugin panes need an actual
entrypoint, explicit target and absolute cwd. Plugin execution uses the source
user's privileges; no plugin download or dependency installer is provided.

Discover integration targets with `integration.list` and the method schema.
Install/uninstall only when requested; this changes integration configuration,
not agent process startup. Native notifications, release-note dismissal and
agent-panel views use their corresponding methods and actual native schemas.

Source-reporting methods publish metadata, lifecycle and session identities.
Use verified source facts, never guessed IDs or fabricated task completion.
They can influence native detection, waits and notifications. Clear/release
agent authority only for an authorized repair. A successful report is evidence
of publication, not independent evidence that its contents are true.

Server controls can reload configuration/agent manifests, hand off to an
installed compatible binary or stop the entire session. Use these only when
that effect serves the user's request; shutdown affects all workloads.
`command.invoke` needs a real opaque command ID from the native foreground
client manifest and an explicit target. JSON session snapshots do not provide
these IDs. Do not invent IDs or substitute shell text; use explicit terminal
input for shell commands.

`collect_native_events(subscriptions, timeout_ms, limit)` captures a temporary
native event sample: maximum 32 filters, 30 seconds, 100 events and 128 KiB. Socket
connection can take another 10 seconds. Inspect its end reason and `events_lost`;
history is best effort, no reconnect/replay. Subscription kinds and fields are
in the `events.subscribe` method schema. This requires session access and can
expose sensitive content. It does not create or refresh the persistent host
Events watch described above. Native `events.wait` supports only
`pane_agent_status_changed` with explicit pane in Herdr 0.9.3.

Four methods need a different transport: foreground window-title set/clear,
client-shell surface control and persistent SSH-agent registration. Discover
their specific limitations through capabilities; do not claim a no-op worked.

Ask for a human decision only when required by the user's actual authority or
an unresolved choice. Previously authorized routine work does not need a fresh
approval merely because an agent reported attention. Do not interpret a UI
approval as structured connector authority, or claim that a key press proved
an operation was approved or completed.

## Terminal inspection, layout and worktrees

Use `pane.selection.read` for selected text with actual anchor/cursor coordinates
and content revision. `pane.copy_motion` and `pane.copy_search` calculate movement
or matches; they do not copy to the system clipboard. `pane.link.resolve` reads
a link at actual viewport coordinates; `pane.link.activate` activates it and is
an action. Obtain the method schema before using coordinates or revision fences.
`pane.scroll`, `pane.clear`, `pane.edit_scrollback`, `pane.resize` and
`pane.input.set` change terminal or UI behavior. A read may expose sensitive text.

Use `layout.export` to inspect a chosen tab/pane before `layout.apply` or
`layout.set_split_ratio`; inspect the new topology after a change. Exported
layout roots and node paths have nested schemas; load the selected method's
schema instead of guessing their structure. Workspace/tab/pane close and move
can alter or end work. Refresh IDs after moving a pane.

Use `worktree.list` with an explicit workspace or source-host cwd to discover
native repository/worktree state. Creation/open/removal use native fields such
as branch/path/trust/force; retrieve the exact selected schema. Do not infer
that a missing trust grant or dirty worktree authorizes force or deletion.
