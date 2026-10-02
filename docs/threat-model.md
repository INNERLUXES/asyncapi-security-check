# Threat model

## What the tool touches

- It reads the one file named on the command line. Nothing else on the disk is opened.
- It does not follow a path or an address written inside the file. A symbolic link given as the argument is followed, because the person who runs the tool named it; the target must be a regular file.
- It writes only to the screen (standard output and standard error).
- It opens no network connection and runs no program: not a shell, not `git`, not a validator, not a broker client.

## What the input may hold

A document is often checked in a pipeline that runs on pull requests, including pull requests from people outside the team, and it may come from a partner or a vendor. The tool treats the file as possibly hostile. It can be huge, very deeply nested, or hold very many values. It can hold a chain of references that never ends, a reference to itself, or thousands of references that point nowhere. A key can be named `__proto__` or `constructor`. A name, a host or a title can be very long or hold control and direction characters. A host can hold a user name and a password. A `$ref` can name a file or an address. An example can hold anything. A YAML file can use anchors and aliases that expand to far more than the file holds.

## What could go wrong, and what stops it

| Risk | Control |
| --- | --- |
| A huge file, deeply nested JSON or YAML, or very many values exhaust memory or time | A file over 10 MB is refused from the size of the open file before it is read; JSON deeper than 64 levels, or with more than 200,000 values, is refused; YAML has limits on depth, lines and line length; more than 1,000 servers, 5,000 channels, 5,000 operations or 20,000 messages is refused. The readers recurse only as deep as their limits |
| A YAML alias bomb expands a small file into a huge structure | Anchors, aliases and tags are refused with their line; nothing is ever expanded |
| A chain of `$ref`, or a reference to itself, makes the walk run for ever or overflow the stack | A chain longer than 32 counts as a cycle and is reported (`ref-cycle`); the search for references uses a list, not recursion; the payload check looks at the top of a schema and follows one reference at a time |
| Tens of thousands of findings of one kind make the report huge | A check lists its first 200 findings in a fixed order, counts the rest in the totals and the gate, and says so in a note |
| A crafted host, name or protocol makes a pattern run for a very long time | Text is cut to a fixed length before a pattern runs on it; the patterns are anchored and have bounded repeats and no nested repetition. Tests run very long near misses and check the time |
| A `$ref` makes the tool fetch or open another file | The tool has no code that opens a connection or a second file; a `$ref` that does not start with `#/` is reported by place and never opened. A test checks that no module imports a network or process module |
| A key named `__proto__` or `constructor` changes how objects behave | The document is read into objects without a prototype, and a pointer step follows own properties only. A test checks that no prototype changes |
| A name or a path rewrites the terminal through escape sequences, or reorders text with direction characters | Control characters (C0 and C1), line and paragraph separators and Unicode direction controls are replaced by a space before any text reaches a report or an error message, and the length is capped |
| A name breaks the Markdown table in the job summary, makes a link, or hides text as an HTML tag | Pipes, backslashes, square brackets, backticks, line breaks, `<`, `>` and `&` are escaped in every table cell |
| A CSV report runs a formula when opened in a spreadsheet | Cells that start with `=`, `+`, `-`, `@`, a tab or a carriage return get a leading `'`; every cell is quoted as RFC 4180 says |
| A secret in the document (an example value, a default, a user name and a password in a host, a token in a `$ref`) is copied into a report, a job log or the job summary | No value of the document is copied into a finding; only structure is named. The host of a server and the address of a `$ref` are never printed. Tests put marker values in examples, defaults, enums, descriptions and a host and check that they appear in no report |
| A part of the document is skipped, and a check passes without having run | A remote reference is info and says what was not checked, a payload in another format is info, a 2.6 document says that the reply check was not run, a document that cannot be read stops the run with exit code `2`. Nothing is guessed |
| The argument names a URL, so the tool becomes a fetcher | Arguments that look like addresses are refused; reading from standard input is refused |
| A pipe or a device in place of the file makes the tool hang | The type is looked at before the file is opened and again on the open file, and anything that is not a regular file is refused |

## Out of scope

What the broker does at run time, the systems that publish and consume, the secrets that they use, and the correctness of the specification and the protocol pages the tool follows. [limits.md](limits.md) lists what a check of a document cannot see.
