# 1. Read the document, not the broker

## Context

The tool needs to say what an event-driven integration shows about its safety before the integration is used. There are richer ways to know whether a broker is exposed: connect to it with no credentials, subscribe to a wildcard topic, publish a malformed message, read the broker configuration. Each of them needs a running system, access, test data and permission to probe it, and the answer comes when the cost of a change is already high. The people who need the answer most often need it earlier: when the document changes in a pull request, in a pipeline with no access to the broker, before a partner is given the document, or in a review of an integration that comes from an agency or a vendor.

A document does not say everything. A broker can enforce access control that the document does not mention, a gateway can add TLS in front of a plain-looking protocol, and a payload with no schema can still be handled carefully by every consumer. A check that treated the absence of a gap in the document as proof of a safe integration would be wrong in the way that matters most. The reverse is true as well: a gap in the document is not proof of an exposed broker.

## Decision

The tool reads one AsyncAPI document as data. It reads the field names, the protocol names and the sentences that it quotes from pages that are saved with their addresses, and a test compares the code with the saved text. It never connects to a broker, never fetches a referenced file, and never runs a program.

Every check says what it can and cannot see. A finding that the document cannot settle is worded as what the tool saw, and the severities are the tool's own and are said to be. A part of the document that the tool could not read (a reference to another file, a payload in another schema format, a version it does not know) is reported or refused, so the gate does not pass a document that was only partly read. Findings carry the JSON pointer and the line, and never a value from the document.

The tool covers the message-driven side only. A request and response API is the subject of `openapi-security-check`, which reads an OpenAPI description against the OWASP API Security Top 10. This tool does not repeat it: it does not look at HTTP operations, paths or parameters, and it refuses an OpenAPI description with a message that names the other tool. Where both tools mention transport security, this one does so for the protocols of a message broker (`amqp`, `kafka`, `mqtt`, `stomp`, `ws`, and `http` as a server protocol), with the AsyncAPI field and the protocol page, and not as an API risk.

AsyncAPI 3.0 is the primary version, and 2.6 is read as the secondary one. The differences are written in docs/versions.md, and a check that does not apply to 2.6 says so in a note instead of passing quietly.

## Consequences

The check runs in a second, on Linux, macOS or Windows, with only Node, no account and no network access, and no input can make it run code or reach out to a host. The same file gives the same report, so it can run on every pull request and gate a release. The cost is that it sees what the file says, not what the broker does: findings turn out to be fine when the broker is configured well, and an exposed broker behind a clean document is not found. The tool says what it left out, lists its limits in docs/limits.md, and leaves the final answer to the people who know the system.
