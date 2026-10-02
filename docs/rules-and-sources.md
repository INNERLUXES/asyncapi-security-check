# Rules and sources

Every name, every protocol and every sentence that the tool quotes comes from a page that is saved in [research/sources](../research/sources), with its address on the first line. `src/data.js` holds them, and `test/data.test.js` compares each one with the saved text. Nothing was added from memory. Change a value only after saving the new page text and updating this file.

## The saved pages

| File | Address | What it is used for |
| --- | --- | --- |
| `asyncapi-3.0.0.txt` | https://raw.githubusercontent.com/asyncapi/spec/v3.0.0/spec/asyncapi.md | the fields of 3.0 (servers, channels, operations, reply, messages, security schemes, correlation id, reference), the schema vocabulary |
| `asyncapi-2.6.0.txt` | https://raw.githubusercontent.com/asyncapi/spec/v2.6.0/spec/asyncapi.md | the fields of 2.6 (servers, channel items, publish and subscribe, messages, requirements), the list of protocol names |
| `mqtt-5.0-security.txt` | https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html | the clear communication profile, the secured transport profile, clear text authentication data |
| `rfc6455-websocket-tls.txt` | https://www.rfc-editor.org/rfc/rfc6455.txt | WebSocket over TLS (`wss`) |
| `rfc9110-https-and-credentials.txt` | https://www.rfc-editor.org/rfc/rfc9110.txt | the `https` scheme, sensitive information in a URI, the confidentiality of credentials |
| `rfc7617-basic-security.txt` | https://www.rfc-editor.org/rfc/rfc7617.txt | the cleartext transmission of Basic authentication |

The two AsyncAPI pages are the markdown of the specification at its release tags in the `asyncapi/spec` repository, which is the source of the pages of the specification on the AsyncAPI site. The saved text keeps the headings, the paragraphs and the field tables of the sections that the tool uses, with links and markup removed and the code examples left out. One example paragraph of the 2.6.0 Operation Object is left out.

The protocol bindings repository of AsyncAPI was read as well, and says nothing about TLS or about secure variants of a protocol, so nothing is quoted from it. The Kafka and AMQP names (`kafka-secure`, `amqps`) rest on the protocol list of the 2.6.0 specification alone, and so does `stomps`.

## The sentences that the findings quote

Each sentence is on its saved page word for word. A sentence marked both is on both AsyncAPI pages and is shown with the page of the version that is checked.

| Key | Used by | Sentence | Page and section |
| --- | --- | --- | --- |
| `protocolList` | `server-plain-protocol`, `server-protocol-missing` (2.6) | "Supported protocol include, but are not limited to: amqp, amqps, http, https, ibmmq, jms, kafka, kafka-secure, anypointmq, mqtt, secure-mqtt, solace, stomp, stomps, ws, wss, mercure, googlepubsub, pulsar." | 2.6.0, Server Object, protocol |
| `protocolV3` | `server-protocol-missing` (3.0) | "The protocol this server supports for connection." | 3.0.0, Server Object, protocol |
| `serverSecurity` | `server-no-security` (3.0) | "A declaration of which security schemes can be used with this server." | 3.0.0, Server Object, security |
| `serverSecurityV2` | `server-no-security` (2.6) | "A declaration of which security mechanisms can be used with this server." | 2.6.0, Server Object, security |
| `operationSecurity` | method | "In cases where Server Security also applies, it MUST also be satisfied." | 3.0.0, Operation Object, security |
| `httpsScheme` | `server-plain-protocol` (http) | `In this context, "secured" specifically means that the server has been authenticated as acting on behalf of the identified authority and all HTTP communication with that server has confidentiality and integrity protection that is acceptable to both client and server.` | RFC 9110, 4.2.2 |
| `websocketTls` | `server-plain-protocol` (ws) | "WebSocket implementations MUST support TLS and SHOULD employ it when communicating with their peers." | RFC 6455, 10.6 |
| `mqttClear` | `server-plain-protocol` (mqtt) | "When using the clear communication profile, the MQTT protocol runs over an open network with no additional secure communication mechanisms in place." | MQTT 5.0, 5.4.12.1 |
| `mqttSecured` | method | "When using the secured transport profile, the MQTT protocol runs over a physical or virtual network and using TLS [RFC5246] which provides authentication, integrity and privacy." | MQTT 5.0, 5.4.12.3 |
| `mqttClearText` | `credentials-over-plain-transport` (mqtt) | "Implementations passing authentication data in clear text, obfuscating such data elements or requiring no authentication data should be aware this can give rise to Man-in-the-Middle and replay attacks." | MQTT 5.0, 5.4.1 |
| `httpCredentials` | `credentials-over-plain-transport` (http) | "Services that depend on individual user authentication require a secured connection prior to exchanging credentials" | RFC 9110, 17.16.1 |
| `basicClearText` | `credentials-over-plain-transport` (basic) | "Because Basic authentication involves the cleartext transmission of passwords, it SHOULD NOT be used (without enhancements such as HTTPS [RFC2818]) to protect sensitive or valuable information." | RFC 7617, 4 |
| `schemeIn` | `apikey-in-query` | `The location of the API key. Valid values are "user" and "password" for apiKey and "query", "header" or "cookie" for httpApiKey.` | 3.0.0 and 2.6.0, Security Scheme Object, in |
| `uriSensitive` | `apikey-in-query` | "It is therefore unwise to include information within a URI that is sensitive, personally identifiable, or a risk to disclose." | RFC 9110, 17.9 |
| `schemeTypes` | method | `Valid values are "userPassword", "apiKey", "X509", "symmetricEncryption", "asymmetricEncryption", "httpApiKey", "http", "oauth2", "openIdConnect", "plain", "scramSha256", "scramSha512", and "gssapi".` | 3.0.0 and 2.6.0, Security Scheme Object, type |
| `requirementName` | `security-scheme-undefined` | "Each name MUST correspond to a security scheme which is declared in the Security Schemes under the Components Object." | 2.6.0, Security Requirement Object |
| `payload` | `message-no-payload`, `payload-format-not-read` | "Definition of the message payload." (both) | Message Object, payload |
| `messageDefinition` | `message-no-payload` (3.0) | "A message MAY contain a payload and MAY also contain headers." | 3.0.0, Definitions, Message |
| `payloadV2` | `message-no-payload` (2.6) | "Definition of the message payload." | 2.6.0, Message Object, payload |
| `schemaVocabulary` | `payload-no-type`, `payload-no-required` | "The AsyncAPI Schema Object is a JSON Schema vocabulary which extends JSON Schema Core and Validation vocabularies." (both) | Schema Object |
| `correlationIdField` | `reply-no-correlation-id` | "Definition of the correlation ID used for message tracing or matching." (both) | Message Object, correlationId |
| `correlationIdObject` | method | "An object that specifies an identifier at design time that can used for message tracing and correlation." | 3.0.0, Correlation ID Object |
| `replyObject` | `reply-no-correlation-id` | "If an operation implements the request/reply pattern, the reply object represents the response message." | 3.0.0, Operation Reply Object |
| `operationChannel` | `operation-no-channel` | "A $ref pointer to the definition of the channel in which this operation is performed." | 3.0.0, Operation Object, channel |
| `operationsDefinition` | `channel-unused` (3.0) | "Holds a dictionary with all the operations this application MUST implement." | 3.0.0, Operations Object |
| `channelDefinition` | `channel-unused` (3.0) | "Sender applications send messages to channels and receiver applications receive messages from channels." | 3.0.0, Definitions, Channel |
| `channelItem` | `channel-unused` (2.6) | "Describes the operations available on a single channel." | 2.6.0, Channel Item Object |
| `operationV2` | `operation-no-description` (2.6) | "Describes a publish or a subscribe operation." | 2.6.0, Operation Object |
| `operationIdField` | `operation-no-id` | "Unique string used to identify the operation." | 2.6.0, Operation Object, operationId |
| `messageIdField` | `message-no-id` | "Unique string used to identify the message." | 2.6.0, Message Object, messageId |
| `operationIdV3` | method | "The field name (operationId) MUST be a string used to identify the operation in the document where it is defined, and its value is case-sensitive." | 3.0.0, Operations Object |
| `messageDescription` | `message-no-description` | "A verbose explanation of the message." (both) | Message Object, description |
| `operationDescription` | `operation-no-description` | "A verbose explanation of the operation." (both) | Operation Object, description |
| `reference` | `ref-unresolved`, `ref-cycle`, `ref-remote` | "A simple object to allow referencing other components in the specification, internally and externally." (both) | Reference Object |

## The findings

| Id | Severity | Area | Specification and protocol pages | Where the rule is written |
| --- | --- | --- | --- | --- |
| `ref-unresolved` | error | References | `reference` | [method.md](method.md#ref-unresolved-error) |
| `ref-cycle` | error | References | `reference` | [method.md](method.md#ref-cycle-error) |
| `server-no-security` | error | Servers | `serverSecurity`, `serverSecurityV2` | [method.md](method.md#server-no-security-error) |
| `server-plain-protocol` | error | Servers | `protocolList` and the page of the protocol | [method.md](method.md#server-plain-protocol-error) |
| `security-scheme-undefined` | error | Security schemes | `requirementName` | [method.md](method.md#security-scheme-undefined-error-26-only) |
| `operation-no-channel` | error | Operations and channels | `operationChannel` | [method.md](method.md#operation-no-channel-error-30-only) |
| `server-protocol-missing` | warning | Servers | `protocolV3`, `protocolList` | [method.md](method.md#server-protocol-missing-warning) |
| `credentials-over-plain-transport` | warning | Security schemes | `basicClearText`, `httpCredentials`, `mqttClearText` | [method.md](method.md#credentials-over-plain-transport-warning) |
| `apikey-in-query` | warning | Security schemes | `schemeIn`, `uriSensitive` | [method.md](method.md#apikey-in-query-warning) |
| `message-no-payload` | warning | Messages | `payload`, `messageDefinition` | [method.md](method.md#message-no-payload-warning) |
| `reply-no-correlation-id` | warning | Operations and channels | `correlationIdField`, `replyObject` | [method.md](method.md#reply-no-correlation-id-warning-30-only) |
| `channel-unused` | warning | Operations and channels | `operationsDefinition`, `channelItem` | [method.md](method.md#channel-unused-warning) |
| `payload-no-type` | info | Messages | `schemaVocabulary` | [method.md](method.md#payload-no-type-info) |
| `payload-no-required` | info | Messages | `schemaVocabulary` | [method.md](method.md#payload-no-required-info) |
| `payload-format-not-read` | info | Messages | `payload` | [method.md](method.md#payload-format-not-read-info) |
| `ref-remote` | info | References | `reference` | [method.md](method.md#ref-remote-info) |
| `message-no-description` | info | Documentation | `messageDescription` | [method.md](method.md#message-no-description-operation-no-description-info) |
| `operation-no-description` | info | Documentation | `operationDescription` | [method.md](method.md#message-no-description-operation-no-description-info) |
| `operation-no-id` | info | Documentation | `operationIdField` | [method.md](method.md#operation-no-id-message-no-id-info-26-only) |
| `message-no-id` | info | Documentation | `messageIdField` | [method.md](method.md#operation-no-id-message-no-id-info-26-only) |

## What the tool decided itself

These are not stated by a page, and the documents say so where they apply:

- the severity of every finding
- the list of plain and secure protocol pairs as one table for both versions, and `mqtts` as an accepted spelling of a secure MQTT protocol
- the list of security scheme types that carry a credential (`userPassword`, `plain`, `apiKey`, `httpApiKey`, `http`)
- the hosts that count as local (`localhost`, a name ending in `.localhost`, `127.x.x.x`, `[::1]`)
- that a description or a summary counts as a description
- that a payload is looked at from the top of its schema only
- the limit of 200 listed findings per check, and the size and depth limits
