# AsyncAPI 3.0 and 2.6

The tool reads two versions of the specification. 3.0 is the primary one, and the checks are written for it. 2.6 is read as well, because many documents still use it, and the differences between the two are the ones in this table. Any other version is refused with exit code `2`: older 2.x files use the same server and security fields, but the tool only reads what it has saved the specification text for.

| What | 3.0.0 | 2.6.0 | What the tool does |
| --- | --- | --- | --- |
| Server address | `host`, with an optional `pathname` | `url` | The host is read from `host` in 3.0 and from `url` in 2.6, only to tell a local host from another |
| Server security | a list of security scheme objects, or references to them | a list of security requirement objects, each naming schemes of `components.securitySchemes` | Both give `server-no-security` when no scheme is named; 2.6 gives `security-scheme-undefined` for a name that is not defined |
| Protocol list | no list; examples are named in the definitions | `amqp`, `amqps`, `http`, `https`, `ibmmq`, `jms`, `kafka`, `kafka-secure`, `anypointmq`, `mqtt`, `secure-mqtt`, `solace`, `stomp`, `stomps`, `ws`, `wss`, `mercure`, `googlepubsub`, `pulsar` | The same table of plain and secure pairs is applied to both; the list that is quoted is the 2.6.0 one |
| Operations | a root `operations` map; each has an `action` (`send` or `receive`), a `channel` reference and `messages` | the `publish` and `subscribe` operations inside a channel item | 3.0: `operation-no-channel`; 2.6: an operation always has its channel |
| Operation id | the key in the `operations` map | optional `operationId` | 2.6 only: `operation-no-id` |
| Channels | a root `channels` map; `address` and a `messages` map | channel items named by the address; operations inside | 3.0: a channel that no operation names is unused; 2.6: a channel item with neither `publish` nor `subscribe` is unused (`channel-unused`) |
| Messages | a map of messages per channel, and `components.messages`; the key is the identifier | the `message` of an operation (or a `oneOf` of messages), and `components.messages`; optional `messageId` | 2.6 only: `message-no-id`; both: `message-no-payload`, the payload findings and `message-no-description` |
| Payload | a schema, a reference, or a multi format object with `schemaFormat` and `schema` | any value; `schemaFormat` is a field of the message | A payload in a format other than the AsyncAPI schema is `payload-format-not-read` in both |
| Request and reply | the operation `reply` object with its channel and messages | not in the specification | 3.0: `reply-no-correlation-id`; 2.6: not run, and a note says so |
| Security scheme types | the same thirteen types | the same thirteen types | The same checks for both |

A document has one version, given by its `asyncapi` field: it has to be a string such as `3.0.0` or `2.6.1`. A version that starts with `3.0` is read as 3.0, one that starts with `2.6` as 2.6. A pre-release suffix is accepted.

## What a finding quotes

A sentence that is word for word on both pages of the specification is shown with the page of the version of the document, so a 2.6 document gets a link to the 2.6.0 page. A sentence that exists in one version only is shown with that version's page. The finding then says which one it is: the protocol list always comes from 2.6.0.

## Moving a document from 2.6 to 3.0

Moving changes what the checks can see. A 2.6 document gets no request and reply check, and its operations cannot be checked for a channel; after the move, `reply-no-correlation-id` and `operation-no-channel` apply, and a channel that no operation names is reported. A document that passed as 2.6 can therefore have findings as 3.0 without any change to what it describes.
