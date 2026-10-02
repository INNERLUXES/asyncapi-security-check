# asyncapi-security-check

Reads an AsyncAPI document (3.0 or 2.6, JSON or YAML) and reports what makes an event-driven integration unsafe or fragile. You give it the file. It reads the servers, the security schemes, the channels, the operations and the messages, and reports a server that declares no security, a server that uses a plain protocol (`amqp`, `mqtt`, `ws`, `kafka`) where the specification lists a secure name, an API key in the query, a message with no payload schema, a request and a reply with no correlation id, an operation with no channel, a channel that nothing uses, and a `$ref` that leads nowhere. Every finding names the JSON pointer and the line of the place, the severity, a sentence on how to fix it, and the sentence of the specification or the protocol page that it rests on, with its address.

A message-driven integration is read by more people than the one team that built it: partners who connect to the broker, security reviewers, code generators and gateways. The document is also the cheapest place to see the gaps early. A broker that is listed as `amqp://`, a server whose security nobody wrote down, a message that has no schema, a request whose reply cannot be matched to it, a channel that nobody owns: none of these breaks a build, and all of them are visible in the document. This tool reads them in a second, so the check can run on every pull request that changes the document.

It is the event-driven counterpart of [openapi-security-check](https://github.com/INNERLUXES/openapi-security-check). That tool reads request and response APIs (OpenAPI); this one reads message-driven integrations (AsyncAPI). They do not repeat each other: this one never looks at HTTP paths, operations or parameters, and it refuses an OpenAPI description with a message that names the other tool.

- Every finding has an id, a severity (error, warning or info), the JSON pointer and the line, a plain message, a fix, and the quoted sentence of the specification or the protocol page, with the address of the saved page.
- What the document cannot show is said, not guessed. A payload in another schema format is `payload-format-not-read`, a `$ref` to another file is listed and never followed, and a 2.6 document says that the request and reply check was not run.
- AsyncAPI 3.0 is the primary version, and 2.6 is read as well, with the differences written in [docs/versions.md](docs/versions.md).
- Local `$ref` is followed, with limits and a check for cycles. A `$ref` to another file or an address is **never fetched**.
- The field names, the protocol names and every quoted sentence are the ones of the official pages, which are saved in [research/sources](research/sources); a test compares [src/data.js](src/data.js) and the documents with the saved text.
- Reports as text, Markdown, JSON and CSV, with an exit code for a pipeline gate. Info findings never fail the run.
- Plain JavaScript, no dependencies; the same file always gives the same report. The YAML reader is strict: anchors, aliases and tags are refused.

```
npm test
```

```
ℹ tests 144
ℹ pass 139
ℹ fail 0
ℹ skipped 5
```

The five skipped tests are the ones that need a system other than Windows: a symbolic link, a device file, a file name with a control character, and a file name with a backslash. They are guarded with `process.platform`. On Linux and macOS only the test for Windows paths is skipped, and 143 of the 144 run.

## Quick start

Requires Node 22 or newer. There is nothing to install.

```
git clone https://github.com/INNERLUXES/asyncapi-security-check.git
cd asyncapi-security-check
node bin/asyncapi-security-check.js examples/orders-events.yaml
```

Or without a clone, in the folder of your document:

```
npx --yes github:INNERLUXES/asyncapi-security-check asyncapi.yaml
```

`examples/` holds a made-up integration. `examples/orders-events.yaml` is an order service that publishes events and answers status requests, wrong on purpose: a broker at `amqp` with no security, an API key in the query of the dashboard feed, an event with no payload schema, a request and reply with no correlation id, and a channel that no operation uses. `examples/orders-events-fixed.yaml` is the same integration repaired, and passes at the strictest level. `examples/orders-events-2.6.json` is a 2.6 document with its own problems.

## Usage

```
node bin/asyncapi-security-check.js examples/orders-events.yaml --fail-on warning
```

```
asyncapi-security-check: examples/orders-events.yaml
AsyncAPI 3.0.0, yaml, "Orders Events": 3 servers, 5 channels, 3 operations, 4 messages, 2 security schemes
areas:
  Servers                   fail   server-no-security x1, server-plain-protocol x1
  Security schemes          warn   apikey-in-query x1
  Messages                  warn   message-no-payload x1, payload-no-required x1
  Operations and channels   warn   reply-no-correlation-id x2, channel-unused x1
  References                pass   no finding
  Documentation             info   message-no-description x1
findings: 2 error, 5 warning, 2 info

Servers (2 findings)

  ERROR    server-no-security  #/servers/broker  line 7
           The server "broker" declares no security scheme, so the document says nothing about how a client proves who it is when it connects.
           basis: "A declaration of which security schemes can be used with this server." (Server Object, security, https://raw.githubusercontent.com/asyncapi/spec/v3.0.0/spec/asyncapi.md)
           fix: Add the scheme (or the alternatives) that a client has to satisfy to connect, under security of the server.

  ERROR    server-plain-protocol  #/servers/broker/protocol  line 9
           The server "broker" uses the plain protocol amqp, and the specification lists amqps for the same protocol. Messages, and the credentials that go with them, can be read and changed on the way.
           basis: "Supported protocol include, but are not limited to: amqp, amqps, http, https, ibmmq, jms, kafka, kafka-secure, anypointmq, mqtt, secure-mqtt, solace, stomp, stomps, ws, wss, mercure, googlepubsub, pulsar." (Server Object, protocol, version 2.6.0, https://raw.githubusercontent.com/asyncapi/spec/v2.6.0/spec/asyncapi.md)
           fix: Use amqps (TLS) for this server, and keep amqp for a broker on the local machine only.

Security schemes (1 finding)

  WARNING  apikey-in-query  #/components/securitySchemes/feedKey/in  line 77
           The security scheme "feedKey" sends an API key in the query. A key in a URL is shown and logged in many places.
           basis: "The location of the API key. Valid values are "user" and "password" for apiKey and "query", "header" or "cookie" for httpApiKey." (Security Scheme Object, in, https://raw.githubusercontent.com/asyncapi/spec/v3.0.0/spec/asyncapi.md)
           basis: "It is therefore unwise to include information within a URI that is sensitive, personally identifiable, or a risk to disclose." (17.9 Disclosure of Sensitive Information in URIs, https://www.rfc-editor.org/rfc/rfc9110.txt)
           fix: Send the key in a header (in: header) instead.

Messages (2 findings)

  WARNING  message-no-payload  #/components/messages/OrderCancelled  line 92
           The message "OrderCancelled" has no payload schema, so a receiver cannot validate what it gets and a sender cannot tell what it may send.
           basis: "Definition of the message payload." (Message Object, payload, https://raw.githubusercontent.com/asyncapi/spec/v3.0.0/spec/asyncapi.md)
           basis: "A message MAY contain a payload and MAY also contain headers." (Definitions, Message, https://raw.githubusercontent.com/asyncapi/spec/v3.0.0/spec/asyncapi.md)
           fix: Add a payload with a schema (type, properties and required).

  INFO     payload-no-required  #/components/messages/OrderPlaced/payload  line 85
           The payload schema of the message "OrderPlaced" lists 2 properties and no required list, so a message with none of them is valid.
           basis: "The AsyncAPI Schema Object is a JSON Schema vocabulary which extends JSON Schema Core and Validation vocabularies." (Schema Object, https://raw.githubusercontent.com/asyncapi/spec/v3.0.0/spec/asyncapi.md)
           fix: List the properties that every message has under required.

Operations and channels (3 findings)

  WARNING  reply-no-correlation-id  #/components/messages/StatusReply  line 103
           The message "StatusReply" is a reply message of the request/reply operation "askOrderStatus" and has no correlationId, so the reply cannot be matched to its request.
           basis: "Definition of the correlation ID used for message tracing or matching." (Message Object, correlationId, https://raw.githubusercontent.com/asyncapi/spec/v3.0.0/spec/asyncapi.md)
           basis: "If an operation implements the request/reply pattern, the reply object represents the response message." (Operation Reply Object, https://raw.githubusercontent.com/asyncapi/spec/v3.0.0/spec/asyncapi.md)
           fix: Add a correlationId with a location (for example $message.header#/correlationId) to the request and to the reply message.

  WARNING  reply-no-correlation-id  #/components/messages/StatusRequest  line 94
           The message "StatusRequest" is a request message of the request/reply operation "askOrderStatus" and has no correlationId, so the reply cannot be matched to its request.
           basis: "Definition of the correlation ID used for message tracing or matching." (Message Object, correlationId, https://raw.githubusercontent.com/asyncapi/spec/v3.0.0/spec/asyncapi.md)
           basis: "If an operation implements the request/reply pattern, the reply object represents the response message." (Operation Reply Object, https://raw.githubusercontent.com/asyncapi/spec/v3.0.0/spec/asyncapi.md)
           fix: Add a correlationId with a location (for example $message.header#/correlationId) to the request and to the reply message.

  WARNING  channel-unused  #/channels/auditTrail  line 44
           The channel "auditTrail" is not used by any operation of this application, so nothing says who sends to it or receives from it.
           basis: "Holds a dictionary with all the operations this application MUST implement." (Operations Object, https://raw.githubusercontent.com/asyncapi/spec/v3.0.0/spec/asyncapi.md)
           basis: "Sender applications send messages to channels and receiver applications receive messages from channels." (Definitions, Channel, https://raw.githubusercontent.com/asyncapi/spec/v3.0.0/spec/asyncapi.md)
           fix: Add an operation that uses the channel, or remove the channel.

Documentation (1 finding)

  INFO     message-no-description  #/components/messages/OrderCancelled  line 92
           The message "OrderCancelled" has neither a description nor a summary.
           basis: "A verbose explanation of the message." (Message Object, description, https://raw.githubusercontent.com/asyncapi/spec/v3.0.0/spec/asyncapi.md)
           fix: Say in a sentence what the message means and when it is sent.

GATE: FAIL - 2 errors, 5 warnings
```

The exit code is `1`: a server with no security and a server at a plain protocol are errors, and errors fail the run by default. The five warnings do not, unless you run with `--fail-on warning`, as here. The two `info` findings never fail a run. The `basis` lines are quotations: the first finding of the server quotes the list of protocol names of the 2.6.0 specification (the 3.0.0 text names no list, as [docs/versions.md](docs/versions.md) explains), and the others quote the specification or the RFC that the finding rests on.

The repaired integration passes, also with `--fail-on warning`:

```
node bin/asyncapi-security-check.js examples/orders-events-fixed.yaml --fail-on warning
```

```
asyncapi-security-check: examples/orders-events-fixed.yaml
AsyncAPI 3.0.0, yaml, "Orders Events": 3 servers, 4 channels, 3 operations, 4 messages, 3 security schemes
areas:
  Servers                   pass   no finding
  Security schemes          pass   no finding
  Messages                  pass   no finding
  Operations and channels   pass   no finding
  References                pass   no finding
  Documentation             pass   no finding
findings: 0 error, 0 warning, 0 info

no findings

GATE: PASS (--fail-on warning)
```

Passing means that none of the checks found anything in the file. It does not mean that the integration is safe; [docs/limits.md](docs/limits.md) lists what a document cannot show.

```
asyncapi-security-check <asyncapi-file> [options]
```

```
--format <name>     text, markdown, json or csv (default: text)
--fail-on <level>   exit with 1 when a finding is at this level or above: error or warning
                    (default: error); info never fails the run
--help              show the usage
--version           show the version
```

Paths in the report are relative to the folder you run the command in, with forward slashes on every system; a file outside it is shown with its absolute path.

## The checks

| Id | Severity | What it reports |
| --- | --- | --- |
| `server-no-security` | error | A server declares no security scheme |
| `server-plain-protocol` | error | A server uses `amqp`, `http`, `kafka`, `mqtt`, `stomp` or `ws`, and the specification lists `amqps`, `https`, `kafka-secure`, `secure-mqtt`, `stomps` or `wss`; a plain protocol on a local host is not reported |
| `security-scheme-undefined` | error | A 2.6 security requirement names a scheme that is not defined |
| `operation-no-channel` | error | A 3.0 operation has no channel reference |
| `ref-unresolved` | error | A local `$ref` points to nothing |
| `ref-cycle` | error | A chain of `$ref` comes back to itself, or is longer than the limit |
| `server-protocol-missing` | warning | A server has no protocol |
| `credentials-over-plain-transport` | warning | A scheme that sends a user name and password, a key or an HTTP credential is used on a plain server |
| `apikey-in-query` | warning | An `httpApiKey` scheme sends the key in the query |
| `message-no-payload` | warning | A message has no payload schema |
| `reply-no-correlation-id` | warning | A message of a request/reply operation (3.0) has no `correlationId` |
| `channel-unused` | warning | A channel that no operation uses (3.0), or with neither `publish` nor `subscribe` (2.6) |
| `payload-no-type` | info | A payload schema has no type and no composition |
| `payload-no-required` | info | A payload schema lists properties and no `required` list |
| `payload-format-not-read` | info | A payload is in another schema format (Avro, Protobuf and others), so it was not read |
| `ref-remote` | info | A `$ref` points to another file or an address; it is not followed |
| `message-no-description` | info | A message has neither a description nor a summary |
| `operation-no-description` | info | An operation has neither a description nor a summary |
| `operation-no-id` | info | A 2.6 operation has no `operationId` |
| `message-no-id` | info | A 2.6 message has no `messageId` |

[docs/method.md](docs/method.md) gives each check, its exact rule, what it can see and what it cannot. [docs/rules-and-sources.md](docs/rules-and-sources.md) lists every name and every quoted sentence with the saved page it comes from.

## Where the facts come from

| Fact | Source |
| --- | --- |
| The fields, the security scheme types, the request and reply objects, the correlation id | the AsyncAPI Specification 3.0.0 and 2.6.0, saved from https://github.com/asyncapi/spec at the release tags |
| The list of protocol names, with `amqps`, `kafka-secure`, `secure-mqtt`, `stomps` and `wss` | the 2.6.0 Server Object |
| The clear and the secured profile of MQTT | https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html |
| WebSocket over TLS | https://www.rfc-editor.org/rfc/rfc6455.txt |
| The `https` scheme, sensitive information in a URI, the confidentiality of credentials | https://www.rfc-editor.org/rfc/rfc9110.txt |
| The cleartext transmission of Basic authentication | https://www.rfc-editor.org/rfc/rfc7617.txt |

The protocol bindings repository of AsyncAPI says nothing about TLS, so nothing is quoted from it; the Kafka and AMQP names rest on the specification's list.

## Formats

- `text`: for a terminal: the document, the areas with their result, then the findings grouped by area, each with its rule id, pointer, line, message, quotation and fix.
- `markdown`: the same for a pull request comment or the job summary. Pipes, square brackets, backticks, line breaks and angle brackets from the input are escaped, so a name from the file cannot break a table or make a link.
- `json`: the whole report: the document, the areas, every finding with id, severity, area, pointer, line, subject, message, fix, basis and source, the notes and the gate.
- `csv`: one row per finding, quoted as RFC 4180 says. A cell that starts with `=`, `+`, `-` or `@` gets a leading `'`, so a spreadsheet does not run it as a formula.

To put the report in the job summary of a GitHub Actions run:

```yaml
permissions:
  contents: read
steps:
  - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
  - uses: actions/setup-node@820762786026740c76f36085b0efc47a31fe5020 # v7.0.0
    with:
      node-version: 22
  - name: AsyncAPI security report
    run: npx --yes github:INNERLUXES/asyncapi-security-check asyncapi.yaml --format markdown >> "$GITHUB_STEP_SUMMARY"
  - name: AsyncAPI security gate
    run: npx --yes github:INNERLUXES/asyncapi-security-check asyncapi.yaml --fail-on warning
```

It needs no secrets, no running broker and no build; a Linux runner is enough. Start with the default gate (errors only), and move to `--fail-on warning` when the first report is clean.

## Exit codes

`0` no finding at the `--fail-on` level, `1` at least one such finding (by default: an error), `2` a usage or input error (a missing file, a file that is not JSON or the YAML subset, a version other than AsyncAPI 3.0 or 2.6, an OpenAPI description, a file over the size limit, an unknown option).

A `$ref` to another file is not exit code `2`: it is an info finding (`ref-remote`), so the run still checks everything else.

## Limits

The tool reads what the document says, not what the broker does. An access control list, a TLS terminator in front of a plain-looking protocol, a rule at a gateway and the way a consumer handles a message are not seen. A finding is a review item, and a clean report is not a safe integration. Only six protocols have a plain and secure pair; others are not judged, and the protocol bindings are not read. [docs/limits.md](docs/limits.md) lists these, with the size limits and the YAML that is read.

## Related

The tool covers message-driven integrations. It does not repeat its neighbours in the same organization: `openapi-security-check` reads request and response APIs against the OWASP API Security Top 10, and `api-break-check` compares two versions of an API description for breaking changes. Where this tool mentions authentication, a protocol or a payload, it does so for the broker, the channel and the message, with the AsyncAPI field and the page that the finding rests on.

## Background

- How event-driven and message-based systems are connected, secured and documented, with checks like this one in the pipeline: [enterprise application integration services](https://innerluxes.dev/application/integration).

## License

MIT
