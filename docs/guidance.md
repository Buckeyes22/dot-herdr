# How the dot finds and uses connector information

The dot gets a concise workflow skill and loads detail for the current task.
Exact native input definitions come from the running connector. The public
guides explain setup and useful workflows for you.

| Information | Source | When to load |
| --- | --- | --- |
| Tool choice, authority, identity and retry invariants | Bundled SKILL.md | When using the connector |
| Guided install/setup, source selection and troubleshooting | Bundled references/setup.md | Setup or connection problems |
| Monitoring, event triage, receipts and unsubscribe | Bundled references/events.md | Monitoring or delivered events |
| Agent replies, session controls and operation-specific guidance | Bundled references/control.md | Agent/session work |
| Actual grants and supported method names | get_herdr_capabilities() | Establish available access |
| Route, permissions, native schema and extra connector constraints | get_herdr_capabilities(method) | Before an unfamiliar native operation |
| Local configuration and walkthroughs | Public getting-started/configuration/control guides | Local setup and review |
| All 102 native methods and concrete connector restrictions | Generated native coverage table | Complete reference or audit |

The skill catalog includes SHA256 digests for the entry point and all three
references. Supported hosts import the complete bundle as a static snapshot.
The running server also exposes the same reference bytes through authenticated
`resources/read`. A cloud dot needs no checkout, local filesystem or CLI to
read these instructions. Skill import and automatic selection depend on the
host; the connector cannot force instructions into every interaction.

Resource URIs are:

```text
skill://dot-herdr/herdr-connector/SKILL.md
skill://dot-herdr/herdr-connector/references/setup.md
skill://dot-herdr/herdr-connector/references/events.md
skill://dot-herdr/herdr-connector/references/control.md
```

Read only the relevant reference. The catalog is a fixed allowlist: caller
paths, arbitrary files and traversal are never resolved. Reference reads need
normal endpoint authentication; access to session tools remains a separate grant.

## Use discovery to construct a call

For example, `get_herdr_capabilities(method="plugin.pane.open")` returns:

- `tool: herdr_action`, identifying the call route.
- `permissions`, requiring session access and observe/control OAuth scopes.
- `inputSchema`, specifying native plugin ID, entrypoint and optional fields.
- `connector_constraints`, requiring absolute cwd and an explicit pane/workspace
  target, bounded parameter size and a unique write request ID.

The native schema describes source `params`. Extra constraints also describe
MCP tool arguments such as `request_id` and event-collection bounds. They apply
together; native optional targets or null timeouts are not permission to bypass
connector requirements. `fields`/`required` describe the native shape, not an
alternative validation contract.

Use the returned tool route. Query/action tools receive native `method` and
`params`; actions additionally receive a unique `request_id`.
`events.subscribe` instead routes to `collect_native_events`, whose arguments
are `subscriptions`, finite `timeout_ms` and `limit`. Unsupported transport
methods return `tool: null` and a specific `reason`.

Discover IDs, invoke the authorized operation, inspect its result and obtain
verification for the user's actual goal. `submitted` is source acknowledgment.
An uncertain delivery needs inspection; using another ID is not a safe retry.

## Keep documentation and packages consistent

Native parameter schemas and the method catalog are packaged data. Explicit
target/path requirements are shared by validation and discovery. Human method
reference and MCP tool/event schemas are generated from those sources:

```sh
.venv/bin/python scripts/export-reference.py
```

Run that command from the source checkout after changing methods, constraints
or tools. It makes no live source or network connection. Update workflow guides
when behavior changes, run the relevant checks and rebuild both distributions.
The wheel and source archive contain all four skill resources. Refresh/rescan
and update the host plugin to distribute changed skill snapshots.

See [API](api.md), [control examples](control.md), [native coverage](native-coverage.md)
and [operations](operations.md).

## Desktop local plugin installation (explicit option)

ChatGPT/Codex desktop app (explicit `--app-id`): `connect` generates a portable local plugin from the same packaged skill
bytes and references. Local installation makes those files available through
the Codex desktop app; cloud imports still depend on the registered plugin and its
scan. Updating the source directory does not refresh ChatGPT's installed
cache: rescan the ChatGPT web plugin after changes. For an explicit desktop local package, rerun connect, restart it and update its installed local plugin. See
[desktop/tunnel setup](desktop-and-tunnel.md) for local registration, existing
cloud server mappings, and separate Events requirements.
