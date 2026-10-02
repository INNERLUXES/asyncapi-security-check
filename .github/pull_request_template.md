## What changes

<!-- One or two sentences. -->

## Checks

- [ ] `npm test`, `npm run check` and `npm run example` pass, and the files under `examples/output` are the ones `npm run example` wrote
- [ ] A change to a check or a reader is described in docs/method.md, says what the check can and cannot see, and has a test with the document written inline and a near miss that must not match
- [ ] A change to a field name, a protocol name or a quoted sentence follows the official pages: the new page text is saved in research/sources, `src/data.js` and docs/rules-and-sources.md match it, and nothing was added from memory
- [ ] A difference between AsyncAPI 3.0 and 2.6 is written in docs/versions.md and has a test for each version
- [ ] Text from the input goes through `safeText`, and no example, default, enum value or host name is copied into a finding
- [ ] The tool still fetches nothing, opens no connection, runs no program, and follows no `$ref` that leaves the file
- [ ] A thing the tool cannot see is reported as a note or an info finding, never as passed or as proven
- [ ] A test that depends on the operating system (a path, a backslash, a link, a file name, a line end) is guarded with `process.platform` or builds its path with `resolve()` from forward-slash names
- [ ] No real secret in fixtures or examples, and no calendar year in the README or the documents
- [ ] The commit messages of this pull request follow Conventional Commits
