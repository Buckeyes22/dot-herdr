# Install and connect dot-herdr

## Before installing

Use Linux or macOS, Python 3.11–3.14 with `venv` and `pip`, and network access to
install the locked Python dependencies. Herdr 0.9.3 (protocol 22) must already
be running on this computer. For reachability and sign-in,
you need either a domain on Cloudflare (Path A, using the optional built-in
sign-in service) or an existing HTTPS MCP URL and compatible OAuth provider
(Path B). You also need a ChatGPT account that can add a custom MCP server and
plugin in a web browser at chatgpt.com, and permission to use your Herdr session.
See
[reachability and sign-in](reachability.md) and [authentication](authentication.md).

Download the wheel, source archive, installer zipapp and `SHA256SUMS` for the
chosen version from the [GitHub Releases page](https://github.com/Buckeyes22/dot-herdr/releases).
Check the downloads in their directory with `sha256sum -c SHA256SUMS` (macOS:
`shasum -a 256 -c SHA256SUMS`). The asset names are
`dot_herdr-<version>-py3-none-any.whl`,
`dot_herdr-<version>.tar.gz`, and
`dot_herdr-<version>-installer.pyz`.
Open a **normal terminal outside Herdr on the computer running Herdr**. Leave
Herdr running.

## Install from the source archive

Extract the source archive, change into its top directory (containing `scripts/`
and `src/dot_herdr/`), then run:

```sh
python3 scripts/install.py
```

This source bootstrap must run from the extracted archive. A standalone copy of
`scripts/install.py` cannot install the package. The installer creates an owned
user installation under your home directory, installs dependencies in its venv,
runs an offline demo, and prints the absolute `dot-herdr` command path. In an
interactive terminal it then starts guided setup automatically. If setup is
interrupted, run the printed absolute command path followed by `setup`. Use that
same path for later commands if the command directory is not on `PATH`.

## Install from a wheel or source archive with the zipapp

The separate standard-library installer zipapp takes a selected artifact. From
the normal terminal, use the actual absolute paths and verified digest from
`SHA256SUMS`:

```sh
python3 /absolute/path/dot_herdr-0.4.0-installer.pyz --source /absolute/path/connector.whl --sha256 EXPECTED_SHA256
```

`--source` can instead name the reviewed source archive. The zipapp has the same
Python, venv/pip and dependency-network requirements, installs the same owned
user environment and command, and starts setup automatically in an interactive
terminal. It prints the absolute command path. A plain `pip install` can install
the command, but managed update and uninstall require the installer's ownership
record. A noninteractive installer prints the absolute command to run with `setup`.

## Finish guided setup

1. **Setup terminal:** Select the running Herdr session and numbered agents.
   Choose observation, agent control or session control explicitly. Visible
   context is a separate choice and starts off. Setup rechecks the selected
   identities. If discovery cannot find the running session, use the existing
   socket with `dot-herdr setup --socket /absolute/path/herdr.sock`.
2. **Choose the app in the setup terminal:** Select `1` for ChatGPT in a
   browser or `2` for the ChatGPT/Codex desktop app. Setup saves this choice and
   does not ask again on resume. Change it explicitly with
   `dot-herdr migrate-route --client-app chatgpt-web` or `--client-app desktop`.
3. **Setup terminal:** At the route step, choose **Cloudflare (I have a domain
   on Cloudflare)** or **I already have an HTTPS URL**. Cloudflare setup asks for
   a token (or offers `--login`) and creates the route before continuing. For the
   existing URL choice, enter your MCP URL, such as
   `https://mcp.example.com/mcp`. On the Cloudflare route, choose **Use the built-in
   sign-in service** at the provider step. With an existing URL, setup uses the
   sign-in service that URL advertises, checks compatibility and explains a
   mismatch; if the URL advertises none, setup offers the built-in service.
   Routine setup does not ask you to invent an issuer or audience.
   An existing URL can be supplied as `dot-herdr setup --endpoint https://mcp.example.com/mcp`.

### ChatGPT in a browser

In ChatGPT at chatgpt.com, use Settings → Plugins → + → Add custom MCP server →
enter your HTTPS MCP URL → Create as a plugin → password page → back in Settings.
Tick **Also allow Herdr control** on the password page if you selected control.
If you selected control, in the Herdr plugin's settings switch tool access from low-risk only to allow all tools; control actions are marked as write actions, so the low-risk setting blocks them.
Use the Herdr plugin and the dot in this same ChatGPT web UI.

### Desktop app

In the ChatGPT/Codex desktop app, open the Plugins Directory and install the
Herdr plugin connected to your HTTPS MCP URL. Complete provider sign-in if
prompted. Tick **Also allow Herdr control** on the password page if you selected
control. If you selected control, in the Herdr plugin's settings switch tool access from low-risk only to allow all tools; control actions are marked as write actions, so the low-risk setting blocks them.
Use the Herdr plugin and the dot in the desktop app. The local plugin package is an explicit `--app-id` option only; routine desktop setup does not
prepare one automatically.

### Shared approval and connection test

4. **Setup terminal:** Wait for the verified account candidate and approve that
   exact account locally. If the plugin is already connected, use it once in your selected app
   (for example, ask it to run `get_profile`) to send the authenticated
   request; no terminal input is needed while waiting. When one account appears,
   answer its `[y/N]` prompt; with several accounts, enter the listed number.
   Invalid input asks again until the ten-minute window ends. Enter or `n`
   refuses. Only the selected Herdr grants then activate. A password page
   closing alone does not prove identity. If the candidate
   does not appear within the pairing window, resume `dot-herdr setup` and repeat
   the selected app sign-in; do not approve an unknown account.
   An observation-only sign-in can still be approved when control was selected.
   Status then shows control pending until you remove the plugin in the selected app, add it again
   with the same URL, and tick the control checkbox on the password page.
5. **Setup terminal:** Choose the optional owned background service or foreground
   operation. With the service, the connector runs after setup closes while your
   user session is logged in. Without it, start `dot-herdr run` in a normal
   terminal when you need the connection; keep that process running. A temporary
   setup runtime stops when setup exits. User-login startup is a separate opt-in.
6. **Setup terminal:** Run `dot-herdr check-connection` if setup has not already
   started it. Select an already approved disposable agent and authorize the
   harmless test. Paste the **single instruction it prints** into the intended
   dot. The dot creates one `herdr.turn.completed` automation and sends one
   nonce request to the agent. The terminal shows each step as it
   arrives and asks only whether the shortened nonce appeared in the intended
   chat. It discovers a single new watch automatically; if several appear, select
   the correct one. If ChatGPT showed the exact subscription ID, pass it with
   `check-connection --subscription-id ID`. Keep the request ID for recovery;
   a callback receipt alone is not destination proof.
   If whole-session access was selected without an agent, setup explains how
   to approve a disposable agent for this check through `dot-herdr access`.

Setup keeps a private draft when a prerequisite is missing. Rerun `dot-herdr setup`
in the normal terminal to resume it. If you used `--config /absolute/path/config.json`,
use that same path on later commands.

## Later use

In a normal terminal, `dot-herdr status --live` shows bounded live checks and
saved connection-test phases. Run `dot-herdr service status` for a selected
background service, or `dot-herdr run` for foreground operation. Run
`dot-herdr access` to change selected grants or reselect a Herdr session;
`dot-herdr access --reselect-session` explicitly treats even the same socket as
a new session. Run `dot-herdr migrate-route` to review and confirm a route or
wiring change. Run `dot-herdr update --source /absolute/path/connector.whl --sha256 EXPECTED_SHA256`
for a reviewed installer-owned update, or `dot-herdr uninstall` to remove owned
runtime files while retaining config, history and backups by default. See
[operations](operations.md) for the details.

If the test expires or becomes uncertain, run `dot-herdr check-recovery --recovery inspect`.
After inspecting the saved request and source outcome, use `--recovery finish` to
finish its remaining checks, `--recovery abandon` to fence it, or
`--recovery start-new --request-id connection-check-<unique suffix>` (18–128
characters, never reused) for a fresh request. Never
replay an action with an unknown outcome. See [troubleshooting](troubleshooting.md).

Codex CLI standalone wiring is an [advanced option](desktop-and-tunnel.md#advanced-codex-cli).
The separate Secure MCP Tunnel route requires its own eligibility and credentials.
`doctor` and `check` are offline checks.
