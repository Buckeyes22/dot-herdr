# Contributing

dot-herdr is MIT-licensed. Bug reports and pull requests are welcome on
[GitHub](https://github.com/Buckeyes22/dot-herdr). Report security
problems privately as described in [SECURITY.md](SECURITY.md), not in a public
issue. Use synthetic reproductions: never attach tokens, signing keys, callback
URLs, private config, databases or real terminal text.

## Development loop

Clone the repository and follow the README's locked development install using
Python 3.11–3.14. Then:

```sh
.venv/bin/dot-herdr doctor
.venv/bin/dot-herdr demo
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m pip wheel --no-index --no-deps --no-build-isolation . --wheel-dir dist
```

Tests use synthetic data, in-process ASGI, fake transport/source streams and temporary stores. Ordinary tests do not connect personal live sessions/callbacks, acquire credentials or launch user services. Opt-in actual-platform lifecycle checks run with isolated synthetic resources; see `scripts/validate-service.py` and `scripts/validate-release.py`. Never use a contributor's account or production agent in a test.

## Review requirements

Keep principal/resource isolation, immutable delivery bytes/IDs, coverage-gap events, private content grants, bounded reads, stop/rotation/expiry fences and receipt idempotency. Preserve explicit source-command grants and scope/identity checks; add no remote maintenance capability. Update schemas/docs/tests for any public tool/event/setup change. Test actual SDK dispatch/auth metadata/results; do not replace all integration tests with mocks. Read current official protocol/security references when changing wire behavior or dependencies.

Pin and review direct and transitive dependencies; private SDK seams need endpoint regression tests. Database changes need versioned transactions, preserved history and rollback/future-version tests. Offline doctor/check/demo must stay network-free. Guided setup and explicit live status/checks use bounded selected-source/provider access and must refuse unrelated overwrite/symlinks. Test identity confirmation, pinned JWKS/cache limits, service/installation journals, stopped-owner access and failure recovery.

For catalog changes regenerate implemented schemas and the native reference with
`scripts/export-reference.py`, then validate the packaged skill frontmatter,
resource digests/bytes and links. Run the supported Python matrix and clean
installed source/wheel checks before a release; `scripts/release-check.py`
verifies checksums, scans the archives for secrets and private data, inventories
licenses and confirms the wheel, source archive and Git HEAD match.
