# Inputs

The tool takes one argument: the path of one AsyncAPI document. It reads that file and nothing else. It follows no `$ref` that leaves the file, opens nothing that a file names, and never reads from standard input. A symbolic link given as the argument is followed, because the person who runs the tool named it; the file it leads to must be a regular file.

## The file

- AsyncAPI 3.0 or 2.6: the `asyncapi` field must be a string of the form `major.minor.patch`, and it must start with `3.0` or `2.6`. Another version is refused with its number. An OpenAPI or Swagger description is refused with a message that names `openapi-security-check`, the tool for those.
- JSON or YAML. The format is chosen from the file name (`.json`, `.yaml`, `.yml`); for any other name the tool reads a file that starts with `{` or `[` as JSON and anything else as YAML.
- A file over 10 MB is refused from the size of the open file, before it is read. A folder, a pipe or a device is refused.
- A document in several files has to be bundled into one first. A `$ref` that does not start with `#/` is reported (`ref-remote`) and never opened.
- An argument that looks like an address (`https://...`) is refused. Nothing is downloaded.

## What is read from the document

| Field | Used for |
| --- | --- |
| `asyncapi` | the version check |
| `info.title` | shown in the report (cleaned and cut) |
| `servers`: `host` (3.0) or `url` (2.6), `protocol`, `security` | `server-no-security`, `server-plain-protocol`, `server-protocol-missing`, `credentials-over-plain-transport` |
| `channels`: `messages` and `servers` (3.0), `publish` and `subscribe` (2.6) | `channel-unused`, the messages that are checked |
| `operations` (3.0): `channel`, `messages`, `security`, `reply`, `traits`, `description`, `summary` | `operation-no-channel`, `reply-no-correlation-id`, `operation-no-description`, `credentials-over-plain-transport` |
| operations in a channel item (2.6): `operationId`, `message`, `security`, `description`, `summary` | `operation-no-id`, `operation-no-description`, `security-scheme-undefined` |
| messages: `payload`, `schemaFormat`, `messageId`, `name`, `correlationId`, `traits`, `description`, `summary` | `message-no-payload`, the payload findings, `reply-no-correlation-id`, `message-no-id`, `message-no-description` |
| payload schemas: `type`, `properties`, `required`, `allOf`, `anyOf`, `oneOf`, `enum`, `const` | `payload-no-type`, `payload-no-required` |
| `components.securitySchemes`: `type`, `in`, `scheme` | `apikey-in-query`, `credentials-over-plain-transport` |
| `components.messages` | the same checks as for the messages of channels |

Not read: `bindings`, `tags`, `externalDocs`, `examples`, `headers`, `parameters`, `components.operations` and `components.channels` as places that count for use (a root channel that is a reference to one is followed), message `examples`, server `variables`, and the values of `default`, `enum` and `const`. Extension fields (`x-...`) are data.

## `$ref`

Only a `$ref` that starts with `#/` is followed, through objects and arrays, with `~1`, `~0` and `%XX` decoded. A chain longer than 32 links is treated as a cycle. A `$ref` inside an `example`, `examples`, `default`, `const`, `enum` or an extension field is data and is not a reference; a property that happens to be called `default` is still read as a property.

## JSON

The JSON reader accepts the JSON of RFC 8259 and nothing more: no comments, no trailing commas, no single quotes, no duplicate keys in one object. A byte order mark at the start is skipped. Nesting deeper than 64 levels, or more than 200,000 values, is refused. A key such as `__proto__` is only a name.

## The YAML subset

The YAML reader accepts what most AsyncAPI files are written with, and refuses everything else with the line, never guessing.

Accepted:

- block mappings and block sequences, indented with spaces
- plain, single-quoted and double-quoted scalars (a double-quoted string may use `\"`, `\\`, `\/`, `\n`, `\t`, `\r`, `\0`, `\b` and `\f`)
- comments that start with `#` after a space or at the start of a line
- flow sequences of scalars on one line (`[a, b]`, `[]`) and the empty flow mapping `{}`
- one document, with or without a leading `---`
- keys with `/`, `{`, `}` and `:` inside, such as `user/signedup:` and `smartylighting.{streetlightId}:`
- values such as `$message.header#/correlationId`, where the `#` does not follow a space

Refused, with the line:

- anchors, aliases, tags (`&`, `*`, `!`), directives, merge keys (`<<`)
- block scalars (`|` and `>`): a multi-line `description` has to be written as one quoted line, or the file converted to JSON
- flow mappings with content (`{a: 1}`), and a flow sequence that is split over lines or nested
- plain values that continue on the next line
- tabs in the indentation, more than one document, a key given twice in one mapping
- more than 100,000 lines, a line over 4,000 characters, nesting deeper than 64 levels

A scalar that looks like a number is a number (`200`, `1.5`), `true`, `false`, `null` and `~` are what they say, and a version such as `3.0.0` is a string.
