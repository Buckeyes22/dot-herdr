# Use the connector in ChatGPT in a web browser

Start with
[installation and setup](getting-started.md) in a normal terminal outside Herdr.
Leave your Herdr session running.

1. **Setup terminal:** Select your existing Herdr session and disposable agent,
   choose explicit grants, and enter your existing HTTPS MCP URL. Setup checks
   the URL's protected-resource and sign-in metadata.
2. **ChatGPT in a web browser (chatgpt.com):** Settings → Plugins → + → Add
   custom MCP server → enter your HTTPS MCP URL → Create as a plugin → password
   page. Tick **Also allow Herdr control** if you selected control. If you selected control, in the Herdr plugin's settings switch tool access from low-risk only to allow all tools; control actions are marked as write actions, so the low-risk setting blocks them. Return to
   Settings; the dot stays in this ChatGPT web UI.
3. **Setup terminal:** Approve the verified account candidate. Grants activate
   only after this approval.
4. **Setup terminal:** Run `dot-herdr check-connection` and select the approved
   disposable agent. Paste its one instruction into the **intended dot**. The
   dot makes connector tool calls; it does not handle sign-in.
5. **Intended dot and setup terminal:** Wait while the terminal shows connection,
   watch, message, reply, delivery, handling, and watch-stop progress. Confirm
   that the shortened nonce appeared in the intended chat when asked. The
   connector verifies the other steps locally.

In ChatGPT web, an event watch is a ChatGPT automation. ChatGPT servers send `events/subscribe` and `events/unsubscribe`. A monitored event uses a finite watch. Stop monitoring by pausing the automation
in the dot; the host then unsubscribes. The connector does not stop Herdr agents when monitoring ends.
An event already in flight may still arrive. Use `dot-herdr access` in a normal
terminal to change local grants; also use the ChatGPT web/plugin and provider controls to revoke
external consent. See [operations](operations.md) and [troubleshooting](troubleshooting.md).

The registered-plugin route uses one selected connection. The separate Secure MCP Tunnel route and advanced Codex options are described in
[desktop and tunnel](desktop-and-tunnel.md).
