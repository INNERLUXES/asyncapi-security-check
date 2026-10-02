# Security

## Reporting a problem

Write to info@innerluxes.dev with the subject line "asyncapi-security-check security", or use private vulnerability reporting on this repository. Please do not open a public issue for a vulnerability.

Include a small made-up AsyncAPI document that shows the problem, what you expected and what happened. Use made-up names, and no real keys, tokens, internal addresses or customer data.

## Scope

In scope:

- an input that makes the tool open a network connection, open a file other than the one it was given, or run a program
- an input that makes the tool print a value of the document that it is documented not to print: an example, a default, an enum value, a description text, a host name or the address of a `$ref`
- a document that makes a reader accept something its documented format does not allow, such as a YAML anchor, an alias or a tag
- an input that makes the tool hang, take very long, or use unbounded memory or stack, such as deep nesting, very many values, a very long string or host, a chain of references that never ends, or a path that is not a regular file
- text from a path, a name, a title or a pointer that breaks a Markdown table, injects a formula into a CSV report, or rewrites the terminal through control or direction characters
- a key such as `__proto__` that changes how objects behave inside the tool
- a finding that docs/method.md says is reported, for an input the tool accepts, that the report leaves out, or a part of a document that the tool did not read and shows as passed
- a sentence in src/data.js that differs from the saved page in research/sources

Out of scope: whether the integration that a document describes is safe (docs/limits.md lists what a document cannot show), the specification and the protocol pages the tool follows, and how your pipeline stores the reports.

Read [docs/threat-model.md](docs/threat-model.md) for the rest.
