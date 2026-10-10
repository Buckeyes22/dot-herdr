# Third-party notices

Original dot-herdr code is licensed under MIT; see LICENSE.

The bundled native parameter data in
`src/dot_herdr/parameter-schemas.json` is extracted from Herdr 0.9.3's bundled
protocol 22 / schema 1 JSON Schema. Herdr is distributed under Apache-2.0.
The upstream license is preserved in
`src/dot_herdr/licenses/HERDR-APACHE-2.0.txt`.

Source: https://github.com/herdrdev/herdr/tree/v0.9.3
License: https://github.com/herdrdev/herdr/blob/v0.9.3/LICENSE

Changes to that data: select request parameter definitions, normalize local
JSON Schema references to #/$defs, and organize them for per-method discovery.
No Herdr Rust implementation code is bundled. The method coverage/access notes
and connector behavior are original connector code/documentation.
