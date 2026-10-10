# dot-herdr

dot-herdr connects a running [Herdr](https://github.com/herdrdev/herdr/tree/v0.9.3)
session to a dot in ChatGPT. Your dot is told when an agent needs attention or
finishes a turn. It can then read the agent's state and reply to it, start
agents, run terminal commands and manage the session, all within the access you
grant.

It runs as one local Python process beside Herdr, with a SQLite database. It
serves an MCP endpoint that ChatGPT reaches over HTTPS. Every request needs a
valid OAuth token, and Herdr is reachable only for an account you approved in
your own terminal, limited to the agents and actions you selected.

- **Version:** 0.4.0, the first public release.
- **Platforms:** Linux and macOS. Python 3.11–3.14. Herdr 0.9.3 (protocol 22).
- **License:** connector code is [MIT](LICENSE). Bundled Herdr schema data keeps
  its Apache-2.0 license; see [third-party notices](THIRD-PARTY-NOTICES.md).

## Contents

- [How it works](#how-it-works)
- [What the dot can do](#what-the-dot-can-do)
- [Before you start](#before-you-start)
- [Choose how ChatGPT reaches you](#choose-how-chatgpt-reaches-you)
- [Install](#install)
- [Set up](#set-up)
- [Test the connection](#test-the-connection)
- [Everyday commands](#everyday-commands)
- [Access levels](#access-levels)
- [Security](#security)
- [Files](#files)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [Documentation](#documentation)

## How it works

```text
Herdr session (local socket)
        │  state changes, agent identity
        ▼
dot-herdr  ── 127.0.0.1:8000 ──  MCP endpoint (/mcp) + optional sign-in pages
        │                               ▲
        │ signed event callbacks        │ HTTPS, OAuth bearer token
        ▼                               │
ChatGPT dot  ◄──── public HTTPS route (Cloudflare Tunnel or your own) ────┘
```

1. dot-herdr talks to Herdr over Herdr's own local socket protocol.
2. When an agent you selected needs attention or completes a turn, dot-herdr
   records an event in its database and sends a signed callback to the dot
   that subscribed to it. Failed deliveries are retried a bounded number of
   times.
3. The dot calls back into dot-herdr's MCP tools to read state, reply to the
   agent or run Herdr actions.
4. Each call carries an OAuth access token. dot-herdr checks the token, the
   account you approved, and the local grants before doing anything.

dot-herdr listens on `127.0.0.1` only. ChatGPT reaches it through a public HTTPS
route that you choose during setup.

## What the dot can do

**Events**

| Event | Meaning |
| --- | --- |
| `herdr.attention.detected` | A selected agent became blocked and needs input. |
| `herdr.turn.completed` | A selected agent finished a turn. |
| `herdr.lifecycle.changed` | An agent's observed state changed (opt-in subscription). |
| `herdr.coverage.changed` | dot-herdr missed part of Herdr's history, for example after a restart. |

In ChatGPT on the web, the dot watches these events through ChatGPT
automations.

**Tools.** 19 tools, including:

- `get_profile`, `get_agent_state`, `list_timeline`, `get_event` and
  `get_connector_health` for reading state and history.
- `read_visible_context` for a bounded view of an agent's terminal (80 lines,
  16 KiB), only with the content grant.
- `send_agent_message`, `send_agent_input`, `send_agent_keys`, `rename_agent`,
  `focus_agent` and `wait_for_agent` for working with an agent.
- `herdr_query`, `herdr_action` and `collect_native_events` for 98 of Herdr's 102
  native methods (32 queries, 65 actions and bounded event collection), with full
  parameter schemas.

A short skill ships with the connector and is readable over MCP, so the dot
knows how to use the tools. See the [API reference](docs/api.md),
[control guide](docs/control.md) and [native coverage](docs/native-coverage.md).

## Before you start

You need:

- Linux or macOS.
- Python 3.11–3.14 with `venv` and `pip`.
- Network access to install the pinned Python dependencies.
- Herdr 0.9.3 (protocol 22), already running on this computer.
- A ChatGPT account that can add a custom MCP server in a web browser at
  chatgpt.com.
- A public HTTPS route to this computer. The next section covers the options.

## Choose how ChatGPT reaches you

ChatGPT needs a public HTTPS URL for the MCP endpoint and an OAuth sign-in
service. Pick one path.

### Path A: Cloudflare and the built-in sign-in service (recommended)

Use this if you have a domain on Cloudflare and no OAuth sign-in service of
your own.

- `dot-herdr` creates a named Cloudflare Tunnel and a DNS record for a hostname
  you choose, such as `herdr.example.com`. The tunnel sends that hostname to
  `http://127.0.0.1:8000`, and returns 404 for anything else.
- `cloudflared` makes outbound connections only. No inbound port is opened, and
  you change nothing on your router or firewall.
- `dot-herdr run` (or the user service) starts and supervises `cloudflared`. No
  root or separate cloudflared service is needed.
- The built-in sign-in service runs on the same hostname. You sign in with a
  password you set during setup.

You need:

- [`cloudflared`](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/)
  installed. dot-herdr detects it but does not install it.
- A Cloudflare API token with exactly these permissions:
  - Account › Cloudflare Tunnel › Edit
  - Zone › DNS › Edit
  - Zone › Zone › Read

  Or use `cloudflared tunnel login` instead, through the `--login` option.
- Cloudflare bot protection turned off for the hostname, or a rule that skips
  it for the hostname. Bot protection blocks ChatGPT's calls. dot-herdr never
  changes zone security settings.

The token is used only while the command runs and is never stored.

### Path B: Your own HTTPS route and OAuth provider

Use any HTTPS reverse proxy or tunnel that sends the public hostname to
`http://127.0.0.1:8000` with `Host` set to the public hostname. Your OAuth
provider must meet the [OpenAI and MCP requirements](docs/authentication.md#provider-requirements-for-path-b).
In short, it needs consistent issuer metadata, HTTPS endpoints, S256 PKCE, CIMD or dynamic client
registration, an audience bound to the resource, short-lived access tokens and
rotating refresh tokens.

### Path C: OpenAI Secure MCP Tunnel

The Secure MCP Tunnel can carry MCP traffic if your account is eligible, but it
does not carry the sign-in service. You still need the built-in service or your
own provider on a public HTTPS URL.

Details for all three paths: [reachability and sign-in](docs/reachability.md).

## Install

1. Download these files from the [Releases page](https://github.com/Buckeyes22/dot-herdr/releases):
   - `dot_herdr-0.4.0.tar.gz` (source archive)
   - `dot_herdr-0.4.0-py3-none-any.whl` (wheel)
   - `dot_herdr-0.4.0-installer.pyz` (installer zipapp)
   - `SHA256SUMS`
2. Check them, in the download directory:

   ```sh
   sha256sum -c SHA256SUMS        # Linux
   shasum -a 256 -c SHA256SUMS    # macOS
   ```

3. Open a normal terminal **outside Herdr**, on the computer running Herdr.
   Leave Herdr running.
4. Install with one of the two methods below.

**From the source archive.** Extract it, change into its top directory (the one
containing `scripts/` and `src/dot_herdr/`), and run:

```sh
python3 scripts/install.py
```

**From the wheel, with the installer zipapp.** Use absolute paths and the
digest from `SHA256SUMS`:

```sh
python3 /absolute/path/dot_herdr-0.4.0-installer.pyz \
  --source /absolute/path/dot_herdr-0.4.0-py3-none-any.whl \
  --sha256 EXPECTED_SHA256
```

Both methods create an owned virtual environment under your home directory,
install the dependencies, run an offline demo and print the absolute path of the
`dot-herdr` command. In an interactive terminal, setup starts automatically. If
setup stops, or the command is not on your `PATH`, run the printed path followed
by `setup`.

A plain `pip install` also works, but `dot-herdr update` and `dot-herdr uninstall`
need the installer's ownership record.

## Set up

`dot-herdr setup` walks through each step and keeps a private draft, so you can
stop and run it again to resume.

1. **Herdr session.** Select the running Herdr session. If it is not found, pass
   its socket: `dot-herdr setup --socket /absolute/path/herdr.sock`.
2. **Access.** Select agents by number and choose the access level (see
   [Access levels](#access-levels)). Reading terminal content is a separate
   choice and starts off.
3. **App.** Choose `1` for ChatGPT in a browser.
4. **Route.** Choose **Cloudflare (I have a domain on Cloudflare)** or **I
   already have an HTTPS URL**.
   - Cloudflare asks for the API token at a hidden prompt (or offers
     `--login`), then creates the tunnel and DNS record.
   - For an existing URL, enter the MCP URL, such as
     `https://mcp.example.com/mcp`, or pass `--endpoint` to setup.
5. **Sign-in.** On the Cloudflare route, choose **Use the built-in sign-in
   service** and enter a password twice. With an existing URL, setup uses the
   sign-in service that URL advertises, checks that it is compatible and
   explains any mismatch; if the URL advertises none, setup offers the built-in
   service.
6. **ChatGPT.** At chatgpt.com, open Settings → Plugins → + → Add custom MCP
   server. Enter the HTTPS MCP URL, choose Create as a plugin, and sign in on the
   password page. Tick **Also allow Herdr control** if you chose control.
7. **Tool access.** If you chose control, open the Herdr plugin's settings in
   ChatGPT and switch tool access from low-risk only to allow all tools. Control
   tools are write actions, which the low-risk setting blocks.
8. **Approve.** Back in the setup terminal, wait for the verified account to
   appear and approve it. With one account, answer `y`; with several, enter the
   listed number. Only then do your grants become active. If the account does
   not appear, use the plugin once in ChatGPT (for example, ask it to run
   `get_profile`).
9. **Background service.** Optionally install a user service (systemd user unit
   on Linux, LaunchAgent on macOS) so the connector keeps running after setup
   closes. Without it, run `dot-herdr run` in a normal terminal when you need
   the connection.

Keep the hostname fixed after setup. The plugin URL, the OAuth resource, the
token audience and the issuer all derive from it.

## Test the connection

```sh
dot-herdr check-connection
```

1. Select a disposable agent that you have already approved.
2. Authorize the harmless test.
3. Paste the single instruction it prints into your dot.

The dot creates one `herdr.turn.completed` automation and sends one nonce
message to the agent. The terminal shows each step as it happens, then
asks whether the shortened nonce appeared in the intended chat.

If the test expires or its result is unclear, run
`dot-herdr check-recovery --recovery inspect`, then `finish`, `abandon` or
`start-new --request-id connection-check-<unique suffix>` (for example
`connection-check-retry-20261010`; 18–128 characters, never reused). Never resend an action whose outcome is
unknown.

## Everyday commands

| Command | What it does |
| --- | --- |
| `dot-herdr status` | One `Overall:` verdict and the next action. |
| `dot-herdr status --live` | Adds read-only live checks of Herdr and of the public route and its protected-resource metadata. `--json` gives machine-readable output. |
| `dot-herdr run` | Runs the connector (and `cloudflared`, on Path A) in the foreground. |
| `dot-herdr service install\|start\|stop\|restart\|status\|remove` | Manages the optional user service. |
| `dot-herdr access` | Changes grants or reselects the Herdr session. `--revoke-all` revokes every grant and keeps history. |
| `dot-herdr signin set-password` | Changes the built-in sign-in password and clears failed-login counters. |
| `dot-herdr expose cloudflare` | Creates or updates the Cloudflare route outside setup. `--remove` deletes only what dot-herdr created. |
| `dot-herdr migrate-route` | Reviews and applies a route or app change. `--to cloudflare` keeps the plugin URL. |
| `dot-herdr check-connection` | Runs the guided connection test. |
| `dot-herdr update --source PATH --sha256 DIGEST` | Updates an installer-owned install from a reviewed artifact. |
| `dot-herdr uninstall` | Removes owned runtime files and the service. Config, history and backups stay unless you add `--purge --confirm-purge`. |
| `dot-herdr doctor`, `dot-herdr check`, `dot-herdr demo` | Offline checks and a local demo. |

Run `dot-herdr --help` for every option. See [operations](docs/operations.md).

## Access levels

Setup offers the first three choices; `dot-herdr access` offers all four:

1. **Monitor selected agents.** Events and read-only state.
2. **Monitor and control selected agents.** Also send messages, keys and input
   to those agents.
3. **Whole-session reads and control.** Native Herdr queries and actions across
   the session, including terminal input. This can run shell commands as your
   user, so grant it only to your own account.
4. **Revoke all.**

Two checks apply to every write. The OAuth token must carry the `herdr:control`
scope, which you grant by ticking **Also allow Herdr control** at sign-in. The
local grant must also allow the target. Either one alone is not enough.

## Security

- The connector binds `127.0.0.1` only and checks `Host` and `Origin` before
  authentication.
- Every MCP call needs a valid RS256 access token. Herdr state, events and
  actions also need an account you approved locally and a matching local grant.
- **Built-in sign-in service.** It uses:
  - S256 PKCE, single-use authorization codes that last 60 seconds, and access
    tokens that last 10 minutes.
  - Refresh tokens that rotate on every use, with reuse detection. Each sign-in
    ends 90 days after it starts.
  - Rate-limited login with backoff capped at 60 seconds, and a CSRF token on
    the login form.
  - A scrypt password hash in a private (0600) file. The password itself is
    never stored or logged.
- **Cloudflare.** dot-herdr deletes only tunnels and DNS records it recorded
  creating. It refuses to change one whose owner or content changed. The tunnel
  run token is stored in a private 0600 file.
- Visible terminal content is withheld unless you grant it. Known secret
  patterns are filtered out.

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md). Do
not open a public issue.

## Files

| Path | Contents |
| --- | --- |
| `~/.config/dot-herdr/config.json` | Configuration (honors `XDG_CONFIG_HOME`; override with `--config`). |
| `cloudflare/` next to the config | Tunnel config, ownership record and (API mode) the tunnel run token. |
| `signin/` next to the config | Built-in sign-in password hash, keys and token store. |
| `~/.local/share/dot-herdr` | The installer-owned environment. |

If you use `--config /absolute/path/config.json`, pass the same path to every
later command. Backups contain signing material; see
[operations](docs/operations.md#backup-and-restore) for the backup tool.

## Troubleshooting

Start with `dot-herdr status`, then `dot-herdr status --live`.

| Symptom | Fix |
| --- | --- |
| HTTP 403 with a Cloudflare challenge | Turn off bot protection for the hostname, or add a rule that skips it. |
| HTTP 530 or Cloudflare error 1033 | The tunnel is down. Check that `cloudflared` is running, then `dot-herdr service restart` or `dot-herdr run`. |
| HTTP 524 | Cloudflare timed out waiting for this computer. Check that the connector is running. |
| Sign-in page is rate-limited | Run `dot-herdr signin set-password`. |
| Account appears as observation only | Remove the plugin in ChatGPT, add it again with the same URL, and tick **Also allow Herdr control**. |
| Control tools refused | Switch the plugin's tool access to allow all tools. |
| Account never appears for approval | Use the plugin once in ChatGPT, for example ask it to run `get_profile`. |
| Herdr session not found | Start Herdr 0.9.3, then `dot-herdr access` or `dot-herdr setup --socket PATH`. |
| Port 8000 in use | Stop the other owner. dot-herdr never kills a process it does not own. |

Set `DOT_HERDR_DEBUG=1` for full dependency logs; keep them private. More
cases: [troubleshooting](docs/troubleshooting.md).

## Development

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m pip install --no-deps --no-build-isolation -e .
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m pip wheel --no-deps --no-build-isolation . --wheel-dir dist
```

The tests use temporary stores and fakes. They never contact
Herdr sessions, Cloudflare, OpenAI or real callbacks. See
[contributing](CONTRIBUTING.md) and the [changelog](CHANGELOG.md).

## Documentation

| Topic | Page |
| --- | --- |
| Step-by-step install and connection | [getting-started](docs/getting-started.md) |
| Routes and sign-in | [reachability](docs/reachability.md), [authentication](docs/authentication.md) |
| ChatGPT specifics | [chatgpt](docs/chatgpt.md), [desktop and tunnel](docs/desktop-and-tunnel.md) |
| Tools and events | [api](docs/api.md), [control](docs/control.md), [native coverage](docs/native-coverage.md) |
| Running it | [operations](docs/operations.md), [configuration](docs/configuration.md), [deployment](docs/deployment.md) |
| Design | [architecture](docs/architecture.md), [protocol compliance](docs/protocol-compliance.md), [guidance](docs/guidance.md) |
| Problems | [troubleshooting](docs/troubleshooting.md), [support](docs/support.md) |
| Security | [SECURITY.md](SECURITY.md) |
