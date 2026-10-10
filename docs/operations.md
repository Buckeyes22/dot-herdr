# Status, services, access and maintenance

Run these commands in a normal terminal on the computer running Herdr.
Use the same absolute `--config` path throughout when overriding defaults.

## Read status

`dot-herdr status` opens with an overall verdict and a next action, then reports config/source/runtime/workers, selected wiring,
historical authentication, route readiness, saved connection-test phases and
active/unexpired monitoring separately. Tunnel prerequisites appear only for a
selected tunnel. `--json` returns machine-readable observations; `--live` adds bounded
Herdr ping and one bounded unauthenticated protected-resource metadata GET for
public reachability and discovery. A reachable URL with mismatched metadata is
distinct from an unreachable public route. It starts no service, renews no consent
and dispatches no native writes. SQLite summaries use read-only transactions,
not Store construction, migration or recovery. Logical database state/ownership
is unchanged; SQLite can update transient shared-memory WAL read marks.

A stale record is not a running process. A completed guided test with verified
client scopes shows a dated historical account-connection label. An authentication timestamp is history,
not a currently usable token.

## Foreground and user service

```sh
dot-herdr service install --login-start
dot-herdr service start
dot-herdr service status
dot-herdr service restart
dot-herdr service stop
dot-herdr service remove
```

Installation manages only unchanged connector-owned files, with private logs
and absolute executable/config arguments. Startup at user login is explicit;
omit `--login-start` to leave it disabled. Linux uses systemd user services;
macOS uses user LaunchAgents. They require a logged-in user session: no root,
Linux lingering or pre-login/post-logout guarantee. Foreground operation remains
available if the user manager is unavailable. Removing a service retains logs.

For a tunnel service add `--tunnel --credential-file /absolute/private/tunnel-key`
to service install. The owned nonsymlink private file contains the runtime key,
read at launch; only its path enters service arguments. The current implementation
uses this private-file fallback, not a promise of native OS credential storage.
Foreground users can use the existing environment key or `run --credential-file`.
Never put a literal key in a unit/plist, command line, config/record or chat.

One runtime owns SQLite and supervises source/delivery workers and its tunnel
child. Failures are reported and workers/children are cleaned up. Stop reaps the
child and releases ownership; it does not stop Herdr work. Foreground Ctrl-C
stops its runtime. Setup's temporary foreground runtime stops on exit; an
opted-in service continues. Login/consent is interactive, never a service loop.

## Change or revoke access

`dot-herdr access` shows before/after grants and reuses numbered agent/access
choices. Run it to reselect a running Herdr session; `--reselect-session`
explicitly treats even the same socket as a new session. Choose observation, agent control, whole-session access and bounded
visible context explicitly. `access --revoke-all` commits inactive access while
retaining config/history and approved accounts. Startup refuses inactive config;
re-enable with an explicit access selection and new fenced-watch subscription.

Changes stop an owned service, compare and privately back up the original config,
commit the approved config/roster, then restart if active. Stop a foreground owner
explicitly first; no arbitrary PID is killed. Content policy can change on the
same identity. Principal/owner/pane/terminal/native changes create a new subject
and fence the previous identity's subscriptions, retaining history/action dedupe.
Control expansion can require fresh `herdr:control` consent; it stays pending
until granted. Failed restart never silently restores explicitly revoked grants.
An already in-flight request cannot be recalled. There is no hot reload.

## Route and test recovery

Run `dot-herdr migrate-route` in the normal terminal to review a new route and
wiring, then confirm the owned changes. For an explicit HTTPS selection use
`dot-herdr migrate-route --route https --wiring registered-plugin`. Modified
and unrelated entries are preserved.

Run `dot-herdr check-connection` to select a granted disposable agent locally
and paste its single instruction into the intended dot. For an expired or
uncertain test run `dot-herdr check-recovery --recovery inspect`; inspect the
saved action before `--recovery finish`, `--recovery abandon`, or
`--recovery start-new --request-id connection-check-<unique suffix>` (18–128
characters, never reused). The dot is used for tools
and destination verification after ChatGPT web Settings → Plugins authentication and local
account approval.

## Backup and restore

Stop the owner and create a dedicated private backup directory. Use the installed
Python interpreter to run the WAL-aware consistent utility:

```sh
/absolute/installed/bin/python -m dot_herdr.maintenance --source /absolute/private/state/connector.sqlite --output /absolute/private/backups/connector-unique.sqlite
```

It requires absolute paths, private source/lock/output parent, exclusive ownership,
a new nonsymlink output, supported schema and SQLite quick-check. Failed partial
output is removed. Do not copy only a live main database, delete its lock or mix
old main data with newer WAL/SHM files. Backups contain signing material; protect
and encrypt them under your retention policy. Keep matching config, application
version/digest and trusted key provenance.

Restore only with all owners stopped. Quarantine current main/WAL/SHM/lock together,
restore the consistent snapshot to a new isolated private store and matching
config, verify schema/permissions and review watch expiry/authority before startup.
Restoring old state can lose action/delivery dedupe and permit repeats. Review
uncertain outcomes and source gaps; never blindly replay a restored watch.

## Update

```sh
dot-herdr update --source /absolute/reviewed/connector.whl --sha256 EXPECTED_RELEASE_SHA256
```

Use an explicitly selected trusted artifact or HTTPS release URL. Remote downloads
require the expected published digest; a digest from the same release origin
provides integrity against that source, not an independent signature. Update
stages a fresh environment and offline checks/demo before stopping the owned
service, making a consistent database/config snapshot and switching the owned
pointer. It verifies the restarted owned runtime PID, workers and installation prefix,
and keeps the previous installation. Foreground ownership must be stopped.

Failure records a safe recovery action. Only a compatible executable can be
restored automatically; a changed database schema leaves the service stopped
for review. No old database is automatically restored after possible actions or
deliveries. Follow the consistent restore procedure if needed. Current startup
migrates schema 0/1 to 2; future schemas reject. Offline checks never migrate.
No automatic dependency upgrades or public release discovery are supplied.

## Uninstall and capacity

`dot-herdr uninstall` removes only owned runtime/link/service and unchanged owned
shared-config entries. User-modified entries are preserved for inspection.
Config/history/backups remain by default. `--purge` previews exact private paths;
`--purge --confirm-purge` is a separately explicit deletion decision, refusing
symlinks/unrelated destinations and external store layouts. Local uninstall does
not revoke cloud connections/provider grants: use their supported owner flows.

No automatic pruning, fair queues or capacity admission is implemented. Journal,
subscriptions, receipts and signing material persist; visible context is transient.
Monitor disk/queue growth, and establish storage/backup/expiry/revocation policy
before production. Preserve the action ledger on upgrade and restore.
