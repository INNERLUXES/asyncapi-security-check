# Changes

## 1.0.0

First release.

- Reads one AsyncAPI document, 3.0 (primary) or 2.6 (secondary), as JSON or as the YAML subset of docs/inputs.md, and reports what the document itself shows about an event-driven integration. Never connects to a broker and never fetches anything.
- Servers: a server with no security scheme (`server-no-security`), a server with a plain protocol (`amqp`, `http`, `kafka`, `mqtt`, `stomp`, `ws`) when the specification lists a secure name for it (`server-plain-protocol`), and a server with no protocol (`server-protocol-missing`).
- Security schemes: an `httpApiKey` in the query (`apikey-in-query`), a scheme that carries a credential on a server with a plain protocol (`credentials-over-plain-transport`), and, for 2.6, a requirement that names a scheme that is not defined (`security-scheme-undefined`).
- Messages: no payload (`message-no-payload`), a payload with no type or no required list (`payload-no-type`, `payload-no-required`), and a payload in another schema format, which is not read (`payload-format-not-read`).
- Operations and channels: a 3.0 operation with no channel reference (`operation-no-channel`), a channel that nothing uses (`channel-unused`), and a request/reply message with no correlation id (`reply-no-correlation-id`, 3.0).
- References: a local `$ref` that points to nothing (`ref-unresolved`), a chain that never ends (`ref-cycle`), and a `$ref` to another file or an address, which is listed and never followed (`ref-remote`).
- Documentation: a message or an operation with no description or summary, and, for 2.6, no `operationId` or `messageId` (`message-no-description`, `operation-no-description`, `operation-no-id`, `message-no-id`).
- Every finding has an id, a severity (error, warning, info), the JSON pointer and the line, a message, a fix, and the sentence of the specification or the protocol page it rests on, with the address. No example, default, enum value or host name is printed.
- The field names, the protocol names and every quoted sentence come from pages that are saved in `research/sources`; a test compares `src/data.js` and the documents with the saved text.
- Reports as text, Markdown, JSON and CSV; `--fail-on` for a pipeline gate; info never fails the run; exit code `2` for a usage or input error.
- Safe input: one file is read, files over 10 MB are refused, JSON nested more than 64 deep is refused, the YAML reader accepts a documented subset only and refuses anchors, aliases and tags, patterns are bounded, and control characters are removed from every text shown.
- Release packages come with a CycloneDX SBOM, SHA-256 checksums and a build provenance attestation.
