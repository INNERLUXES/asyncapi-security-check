# Limits

## What the tool can know

- **It sees what the document says, not what the broker does.** A document is written by people, often generated from code, and often out of date. A topic that exists on the broker and is missing from the document is not seen. Access control lists, network rules, TLS settings at a gateway or a mesh, and credentials that are rotated outside the document are not seen, and a document that promises more than the broker does passes. The tool reports what the file shows and nothing about the running system.
- **A finding is a review item, not proof.** `server-no-security` does not prove that the broker accepts anyone; it says the document does not say how a client connects. `server-plain-protocol` does not prove that traffic is readable: a plain name can sit behind a TLS terminator. The messages say what the tool saw.
- **A pass is not a safe integration.** A clean report means that none of the checks found anything in the file. It says nothing about the content of messages, who may publish to a topic, how long messages are kept, or how a consumer handles a message it cannot parse.
- **Only some protocols are judged.** The table of plain and secure names covers `amqp`, `http`, `kafka`, `mqtt`, `stomp` and `ws`. A server with another protocol (`jms`, `solace`, `ibmmq`, `pulsar`, `googlepubsub`, `mercure`, `anypointmq`, and any other name) is not judged. The tool does not read the protocol bindings: a Kafka server whose bindings say `PLAINTEXT` while the protocol says `kafka-secure` is not noticed.
- **Names are compared as written.** The protocol is compared in lower case without surrounding spaces. A host is local when it is `localhost`, ends in `.localhost`, is `127.x.x.x` or is `[::1]`; a name from a server variable is not resolved.
- **Security is read as lists.** The tool does not check that an OAuth 2 flow is sound, that a scope is declared, that a scheme named in an operation matches the one of the server, or what an X.509 or SASL scheme requires.
- **Payload checks look at the top of the schema.** A payload is called untyped or without a `required` list from its top level only. A schema that is composed, or is a reference to a schema, is followed one reference at a time and not walked into its properties.
- **A `$ref` is followed inside the file only.** A document split over files has to be bundled first; a remote reference is listed as info (`ref-remote`) and what it points to is not checked.
- **Traits are read for descriptions and correlation ids only.** The merge of traits into an operation or a message is not applied; the tool looks at the traits one by one for the three fields it needs.
- **The YAML reader is a subset.** [inputs.md](inputs.md) lists what it accepts. A document with block scalars, anchors or tags is refused with its line, so the file has to be written in the subset or converted to JSON.
- **Only AsyncAPI 3.0 and 2.6.** Any other version is refused. [versions.md](versions.md) lists what differs between the two.

## What the tool does not check

- Whether the integration is vulnerable. It does not connect to a broker, scan a host, publish a message or read the source of a consumer.
- The correctness of the document itself. It is not a validator; a document with a wrong structure is read as far as it goes. Use a validator for that.
- Request and response APIs. An OpenAPI description is refused, and `openapi-security-check` reads it. This tool covers the message-driven side only.
- Message content: personal data in a payload, secrets in a payload, and the strength of an encryption that a payload applies.
- Quality of the names, versions or semantics of the schemas.

## Size and depth

- A file over 10 MB is refused, from the size of the open file.
- JSON nested deeper than 64 levels, or with more than 200,000 values, is refused. YAML nested deeper than 64 levels, with more than 100,000 lines or a line over 4,000 characters, is refused.
- More than 1,000 servers, 5,000 channels, 5,000 operations or 20,000 messages is refused.
- A chain of `$ref` longer than 32 is a cycle.
- A check that finds more than 200 things lists the first 200 in a fixed order, counts the rest in the totals and the gate, and says so in a note.
- Text from the document shown in a report is cut to a fixed length: 400 characters for a pointer, 200 for a subject, 900 for a message and 500 for a fix.

Every limit is reported, as a finding, a note or a refusal with exit code `2`, so a cut is never silent.
