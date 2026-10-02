# Method

The tool reads one AsyncAPI document as data and runs the checks below. Every check says what it reports, why it has the severity it has, what it can see and what it cannot, and the sentence of the specification or of a protocol page that it rests on. The pages are saved in [research/sources](../research/sources), and a test compares every quoted sentence with the saved text. Where the tool makes a choice that no page states (a severity, the list of credential schemes, the words that count as a description), the text says so.

Nothing is fetched at run time, and a finding never holds a value of the document: not an example, a default, an enum value, a description or a host name. A finding names the structure: the pointer, the server, the channel, the message, the scheme.

## What is read

For a 3.0 document: the `servers` map (`host`, `protocol`, `security`), the `channels` map (`messages`, `servers`), the `operations` map (`action`, `channel`, `messages`, `security`, `reply`, `traits`, `description`, `summary`), `components.messages`, `components.securitySchemes` and the message and operation traits. For a 2.6 document: the `servers` map (`url`, `protocol`, `security`), each channel item with its `publish` and `subscribe` operations (`operationId`, `message`, `security`), `components.messages` and `components.securitySchemes`. [versions.md](versions.md) lists what differs.

A `$ref` that starts with `#/` is followed inside the file. Any other `$ref` is listed (`ref-remote`) and never opened. [inputs.md](inputs.md) has the details.

## Servers

### `server-no-security` (error)

A server whose `security` list holds no security scheme. In 3.0 an entry is a security scheme object (or a reference to one); in 2.6 an entry is a requirement object that names at least one scheme. An empty list, a missing list, and a 2.6 list of empty requirements all count as none.

The specification says: "A declaration of which security schemes can be used with this server." A server that declares none leaves out how a client proves who it is when it connects. It is an error because every other protection in the document (a scheme on an operation, a TLS protocol) assumes that the connection itself is protected, and the connection is what the server's security describes.

What it can see: the document. What it cannot see: a broker that enforces access control that the document does not describe, or a network that only trusted hosts can reach. Security on an operation does not make a server pass, because the specification asks for the server's security to be satisfied as well: "In cases where Server Security also applies, it MUST also be satisfied."

### `server-plain-protocol` (error)

A server whose `protocol` is one of the plain names `amqp`, `http`, `kafka`, `mqtt`, `stomp` or `ws`, when the specification lists a secure name for the same protocol. The comparison ignores case and surrounding spaces.

| Plain | Secure name the specification lists | Second page quoted |
| --- | --- | --- |
| `amqp` | `amqps` | none |
| `http` | `https` | RFC 9110, section 4.2.2 |
| `kafka` | `kafka-secure` | none |
| `mqtt` | `secure-mqtt` | MQTT 5.0, section 5.4.12.1 |
| `stomp` | `stomps` | none |
| `ws` | `wss` | RFC 6455, section 10.6 |

The list is quoted from the 2.6.0 Server Object: "Supported protocol include, but are not limited to: amqp, amqps, http, https, ibmmq, jms, kafka, kafka-secure, anypointmq, mqtt, secure-mqtt, solace, stomp, stomps, ws, wss, mercure, googlepubsub, pulsar." The 3.0.0 Server Object has no list: it says "The protocol this server supports for connection." and names example protocols in its definitions. The tool applies the same table to both versions, and the report shows the page of the list it quotes.

The tool also accepts `mqtts` as a secure spelling for MQTT, because it is common, although the specification names `secure-mqtt`. It never reports `mqtts`.

A protocol that has no row in the table (`jms`, `solace`, `ibmmq`, `pulsar`, `googlepubsub`, `mercure`, `anypointmq` and anything else) is not judged: the specification lists no plain and secure pair for it, and the tool does not guess. A plain protocol on a local host (`localhost`, a name ending in `.localhost`, `127.x.x.x` and `[::1]`) is not reported, and a note counts the servers left out; a name that only contains the word, such as `localhost.example.test`, is reported.

What it cannot see: a plain-looking protocol name that sits behind a TLS terminator, a secure name whose broker is configured without TLS, or the TLS version and ciphers.

### `server-protocol-missing` (warning)

A server with no `protocol`, or an empty one. The field is required by the specification, and without it the transport cannot be judged. It is a warning because the document is incomplete rather than unsafe.

## Security schemes

### `apikey-in-query` (warning)

A security scheme of type `httpApiKey` whose `in` is `query`. The specification lists the places for the key: "The location of the API key. Valid values are "user" and "password" for apiKey and "query", "header" or "cookie" for httpApiKey." So the only scheme that can put a secret in a URL is `httpApiKey` with `in: query`; a `userPassword` scheme has no `in` at all, and an `apiKey` scheme is sent as the user or the password of the connection.

The reason it is a warning is given by the HTTP specification: "It is therefore unwise to include information within a URI that is sensitive, personally identifiable, or a risk to disclose." The severity is the tool's own: the key is exposed to whoever reads logs, not to anyone on the network, and a server may accept the key only over TLS.

### `credentials-over-plain-transport` (warning)

A security scheme of type `userPassword`, `plain`, `apiKey`, `httpApiKey` or `http` that is used (in a server's `security`, or in the `security` of an operation whose channel is available on the server) on a server that `server-plain-protocol` reports. The list of types is the tool's own choice: these are the types that carry a user name and a password, a key or an HTTP credential, which the receiver reads as sent. The types are the specification's. `oauth2`, `openIdConnect`, `X509`, the encryption types, `scramSha256`, `scramSha512` and `gssapi` are not in the list: they either do not send the secret, or protect it in their own way.

Each pair of scheme and server is reported once, at the place where the scheme is used. The sentence quoted depends on the case: for HTTP basic authentication, RFC 7617 ("Because Basic authentication involves the cleartext transmission of passwords, it SHOULD NOT be used (without enhancements such as HTTPS [RFC2818]) to protect sensitive or valuable information."); for an `http` server, RFC 9110 section 17.16.1; for an `mqtt` server, MQTT 5.0 section 5.4.1; otherwise the page that explains the protocol.

It is a warning on top of the error of the plain protocol: the error says the connection is open, and the warning says what travels on it.

### `security-scheme-undefined` (error, 2.6 only)

A 2.6 security requirement (on a server or an operation) that names a scheme that `components.securitySchemes` does not define. The specification says: "Each name MUST correspond to a security scheme which is declared in the Security Schemes under the Components Object." A requirement that names nothing protects nothing. In 3.0 the entries are scheme objects or references, so the same mistake is a broken reference (`ref-unresolved`).

## Messages

### `message-no-payload` (warning)

A message with no `payload`. The specification says what a message holds: "A message MAY contain a payload and MAY also contain headers." A message without a payload schema cannot be validated by a receiver, and a sender cannot tell what it may send. It is a warning because a message can carry its meaning in its name and headers alone; the specification allows it, and the tool does not.

### `payload-no-type` (info)

A payload schema with no `type`, and none of `allOf`, `anyOf`, `oneOf`, `enum` or `const`, or a payload that is not a schema object. Any value is a valid payload for such a schema. The schema is read as the specification says: "The AsyncAPI Schema Object is a JSON Schema vocabulary which extends JSON Schema Core and Validation vocabularies." The tool looks at the top of the schema only. A composed schema is not called untyped, and a `$ref` is followed.

### `payload-no-required` (info)

A payload schema that lists properties and has no `required` list (or an empty one), so a message with none of the properties is valid. A schema with no properties is not reported: there is nothing to require. Both payload findings are info because many payloads are open on purpose.

### `payload-format-not-read` (info)

A payload written in another schema format (Avro, Protobuf, RAML, OpenAPI schema), which the tool cannot read. In 3.0 the payload is a multi format object with `schemaFormat` and `schema`; in 2.6 the message has a `schemaFormat`. A format that starts with `application/vnd.aai.asyncapi` is read; any other is listed as not read, never as passed.

## Operations and channels

### `operation-no-channel` (error, 3.0 only)

A 3.0 operation with no `channel`, or whose `channel` is written inline instead of as a `$ref`. The specification says: "A $ref pointer to the definition of the channel in which this operation is performed." Without a channel, the operation does not say where messages are sent or received, and nothing can be checked about it. A channel reference that is remote or broken is a reference finding, not this one. In 2.6 an operation is written inside its channel item, so it always has a channel.

### `channel-unused` (warning)

In 3.0, a channel in the root `channels` map that no operation of the root `operations` map names, as its `channel` or as the `channel` of its `reply`. The specification says: "Holds a dictionary with all the operations this application MUST implement." A channel that none of them uses is declared for nothing. Operations under `components.operations` are not counted: the specification puts there the operations that may or may not be implemented by the application. A root channel written as a `$ref` to a component is used when an operation names either place. In 2.6, a channel item with neither `publish` nor `subscribe`: "Describes the operations available on a single channel."

The finding is a warning because an unused channel is not unsafe by itself; it is a sign of a document that is out of date, and a place where a topic or queue may exist with nobody responsible for it.

### `reply-no-correlation-id` (warning, 3.0 only)

A message of an operation that has a `reply` and no `correlationId`. The request messages are the ones the operation lists in `messages`, or all the messages of its channel when it lists none; the reply messages are the ones the reply lists, or all the messages of the reply's channel. A `correlationId` on the message, or on one of its traits, counts. Each message is reported once, however many operations use it, and the finding says whether it is a request or a reply message.

The specification says: "If an operation implements the request/reply pattern, the reply object represents the response message." and "Definition of the correlation ID used for message tracing or matching." Without an identifier, a reply cannot be matched to its request when several are in flight, and a message cannot be traced. It is a warning because a transport can match replies another way (a private reply queue), which the document would then have to say.

2.6 has no reply object, so the check is not run for a 2.6 document, and a note says so.

## References

### `ref-unresolved` (error)

A local `$ref` that points to nothing in the file. The specification says: "A simple object to allow referencing other components in the specification, internally and externally." What the reference stands for was not checked, so the gate fails.

### `ref-cycle` (error)

A chain of `$ref` that comes back to itself, or is longer than 32 links, so it never reaches a value. A schema that contains itself through its properties is not a cycle of references and is not reported: the tool looks at the top of a payload only.

### `ref-remote` (info)

A `$ref` that does not start with `#/`: another file or an address. It is never opened or fetched. Its text is not printed, because it can hold an address with a token. The finding is info, so that a document that is split over files can still be checked for the parts that are in the file; the findings of a bundled document are the complete ones. Bundle the document first when you need the whole.

## Documentation

### `message-no-description`, `operation-no-description` (info)

A message or an operation with neither a `description` nor a `summary` (on itself or on one of its traits). The specification describes the field: "A verbose explanation of the message." and "A verbose explanation of the operation." Either field counts, because the specification offers both. A blank text does not count.

### `operation-no-id`, `message-no-id` (info, 2.6 only)

A 2.6 operation with no `operationId`, or a message with no `messageId`: "Unique string used to identify the operation." and "Unique string used to identify the message." In 3.0 the identifier is the key in the `operations` map, so it is always there: "The field name (operationId) MUST be a string used to identify the operation in the document where it is defined, and its value is case-sensitive."

## Severities and the gate

An error is something that makes the integration unsafe or makes the document unreadable for the tool. A warning is a gap that most reviewers would ask about. Info is a gap in documentation or a thing that was not read. With the default `--fail-on error`, only errors fail the run; `--fail-on warning` fails on warnings too; info never fails. The severities are the tool's own, and the specification does not state them.

When one check finds more than 200 things, the first 200 are listed, in a fixed order, and the rest is counted (the gate uses the full count) and named in a note.
