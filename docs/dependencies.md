# Dependencies, provenance and license status

Original implementation; no vendored Herdr source. Herdr protocol was source-reviewed, not imported as a runtime package. Native
parameter schemas are bundled as attributed Apache-2.0 data for discovery.
No additional runtime dependency is needed for expanded native coverage. Native MCP uses official Python SDK mcp 2.3.0 from PyPI. Direct runtime uses PyJWT[crypto] 2.15.1, pydantic 2.13.5, uvicorn 0.54.0; the lock includes exact transitive versions and setuptools 80.9.0. Test dependencies include httpx2 and jsonschema; demo uses in-process ASGI.

The bundled source installer uses Python venv/pip internally and runs the demo;
ordinary source/wheel installation also resolves dependencies from pyproject.toml.
Guided setup adds no runtime dependency. The exact transitive lock is for repeatable development and offline checks; users do not need to install it separately.

Original connector code uses the **MIT license**, included in source and wheel
distributions. Bundled parameter-schema data comes from Herdr 0.9.3 and retains
Apache-2.0; its full license and [third-party notices](../THIRD-PARTY-NOTICES.md)
are packaged. The combined distribution uses `MIT AND Apache-2.0`. Dependencies retain their own licenses; for security reports, see [SECURITY.md](../SECURITY.md). Public packaging excludes user configurations and databases.

The endpoint uses SDK _lowlevel_server request/capability seams. Retest protocol metadata/resultType/catalog/auth/rotation/errors before SDK upgrades. Source version drift is independent from MCP compatibility. See support, changelog and contributing.
