"""Serve one bundled, static workflow skill; no user-supplied file paths."""
import hashlib
import json
from importlib.resources import files

import mcp.types as types
from mcp.shared.exceptions import MCPError
from pydantic import ConfigDict

SKILL_BASE = 'skill://dot-herdr/herdr-connector/'
SKILL_URI = SKILL_BASE + 'SKILL.md'
SKILL_FILES = ('SKILL.md','references/setup.md','references/events.md','references/control.md')


class ListSkills(types.RequestParams):
    model_config = ConfigDict(extra='forbid')
    cursor: str | None = None


class GetSkill(types.RequestParams):
    model_config = ConfigDict(extra='forbid')
    uri: str


def register_skill(server, authenticate):
    folder = files('dot_herdr').joinpath('skills', 'herdr-connector')
    resources = {SKILL_BASE + path: folder.joinpath(path).read_bytes() for path in SKILL_FILES}
    raw = resources[SKILL_URI]
    text = raw.decode('utf-8')
    # JSON is valid YAML frontmatter and needs no additional parser dependency.
    frontmatter = json.loads(text.split('---\n', 2)[1])
    entry = {
        'uri': SKILL_URI,
        'frontmatter': frontmatter,
        'resources': [{'uri': uri, 'digest': 'sha256:' + hashlib.sha256(body).hexdigest()}
                      for uri, body in resources.items()],
    }
    low = server._lowlevel_server
    low.extensions['io.modelcontextprotocol/skills'] = {}

    async def list_skills(ctx, params):
        authenticate()
        if params.cursor is not None:
            raise MCPError(code=-32602, message='InvalidParams', data={'reason': 'invalid_skill_cursor'})
        return {'resultType': 'complete', 'skills': [entry]}

    async def get_skill(ctx, params):
        authenticate()
        if params.uri != SKILL_URI:
            raise MCPError(code=-32011, message='NotFound', data={'kind': 'skill'})
        return {'resultType': 'complete', 'skill': entry}

    low.add_request_handler('skills/list', ListSkills, list_skills)
    low.add_request_handler('skills/get', GetSkill, get_skill)

    def register_resource(uri, body):
        @server.resource(uri, name=uri.removeprefix(SKILL_BASE),
                         description=frontmatter['description'] if uri==SKILL_URI else 'Focused Herdr connector workflow reference',
                         mime_type='text/markdown')
        def read_skill_resource():
            authenticate()
            return body.decode('utf-8')

    for uri, body in resources.items():register_resource(uri, body)
