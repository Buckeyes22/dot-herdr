# Supported platforms

| Component | Supported |
| --- | --- |
| Operating system | Linux, macOS |
| Python | 3.11–3.14 |
| Herdr | 0.9.3, protocol 22, schema 1, over its local Unix socket |
| MCP SDK | `mcp==2.3.0` (pinned) |
| ChatGPT | ChatGPT on the web (chatgpt.com) and the ChatGPT/Codex desktop app |
| Background service | systemd user unit (Linux), LaunchAgent (macOS) |

Releases are on [GitHub](https://github.com/Buckeyes22/dot-herdr/releases).

The connector provides 19 tools and covers 98 of Herdr's 102 native methods
(32 queries, 65 actions and bounded event collection). See
[native coverage](native-coverage.md) for the four excluded methods.

## Support reports

Include the safe reasons, versions, selected route and wiring, and timestamps
from `dot-herdr status --json`. Leave out tokens, signing material, callback
URLs and secrets, and terminal content. See [troubleshooting](troubleshooting.md).

## Lifecycle validation scripts

`python scripts/validate-service.py`, run from an extracted source archive's
Python environment, installs, starts, restarts, stops and removes an isolated
owned user service.

`python scripts/validate-release.py --artifact /absolute/release.whl` installs a
built artifact, starts the owned service, runs a staged update, checks that
config and action deduplication survive, and runs the default uninstall. It
needs package-index access and the logged-in user service manager, and removes
everything it creates.
