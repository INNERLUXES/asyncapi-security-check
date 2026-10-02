import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { FINDINGS, USAGE, VERSION, csvCell, main, mdCell, parseArgs, toCsv, toJson, toMarkdown, toText } from '../src/index.js';
import { base2, base3, check, cli, goodPayload, json, run, with3 } from './helpers.js';

const root = resolve(fileURLToPath(import.meta.url), '..', '..');
const read = (rel) => readFile(resolve(root, rel), 'utf8');

// Runs the tool on files of the repository, with the root of the repository as the base for relative paths.
async function inRoot(argv) {
  let out = '';
  let err = '';
  const code = await main(argv, { out: (t) => { out += t; }, err: (t) => { err += t; } }, undefined, root);
  return { code, out, err };
}

const plain = (extra = {}) => with3({ servers: { prod: { host: 'broker.example.test', protocol: 'amqp', description: 'x' } }, ...extra });

test('text report: the document line, the areas, the counts, each finding with its quotation and fix, the notes and the gate', () => {
  const out = toText(check(plain(), { path: 'doc.json' }));
  const lines = out.split('\n');
  assert.equal(lines[0], 'asyncapi-security-check: doc.json');
  assert.match(lines[1], /^AsyncAPI 3\.0\.0, json, "Demo": 1 server, 1 channel, 1 operation, 1 message, 1 security scheme$/);
  assert.equal(lines[2], 'areas:');
  assert.match(out, /^findings: 2 error, 0 warning, 0 info$/m);
  assert.match(out, /^  ERROR {4}server-plain-protocol {2}#\/servers\/prod\/protocol {2}line \d+$/m);
  assert.match(out, /^ {11}basis: "Supported protocol include, but are not limited to: amqp, amqps/m);
  assert.match(out, /^ {11}fix: Use amqps \(TLS\)/m);
  assert.match(out, /^GATE: FAIL - 2 errors$/m);
  assert.ok(out.endsWith('\n'));
});

test('text report: a clean document says no findings, and a note is printed on its own line before the gate', () => {
  const clean = toText(check(base3()));
  assert.match(clean, /^no findings$/m);
  assert.match(clean, /GATE: PASS \(--fail-on error\)\n$/);
  const note = toText(check(base2()));
  assert.match(note, /\nnote: AsyncAPI 2\.6 has no reply object[^\n]*\n\nGATE: PASS/);
});

test('markdown report: a table per area, escaped cells, the notes as a list and the gate in bold', () => {
  const out = toMarkdown(check(plain(), { path: 'doc.json' }));
  assert.match(out, /^## asyncapi-security-check: 2 error, 0 warning, 0 info$/m);
  assert.match(out, /^\| Area \| Result \| Detail \|$/m);
  assert.match(out, /^### Servers$/m);
  assert.match(out, /^\| Severity \| Check \| Where \| Message \| Basis \| Fix \|$/m);
  assert.match(out, /\*\*Gate failed:\*\* 2 errors\./);
  assert.match(toMarkdown(check(base2())), /^- AsyncAPI 2\.6 has no reply object/m);
  assert.match(toMarkdown(check(base3())), /\*\*Gate passed\*\* \(--fail-on error\)\./);
});

test('markdown report: a pipe, a line break, an angle bracket, a link or a backtick in a name cannot break the table or make markup', () => {
  const evil = 'a|b\nc<script>[click](https://evil.example.test)`x`';
  const r = check(with3({ servers: { [evil]: { host: 'b.example.test', protocol: 'ws', description: 'x', security: [{ type: 'userPassword' }] } } }));
  const out = toMarkdown(r);
  assert.ok(!out.includes('<script>'));
  assert.ok(!out.includes('[click]('));
  assert.ok(out.includes('a\\|b c&lt;script&gt;\\[click\\]'));
  for (const row of out.split('\n').filter((l) => l.startsWith('| error |'))) assert.equal(row.replace(/\\\|/g, '').split('|').length, 8, row.slice(0, 80));
  assert.equal(mdCell('x\r\ny'), 'x y');
  assert.equal(mdCell('\\'), '\\\\');
});

test('json report: the whole report, with the document, the areas, every finding with its basis, the notes and the gate', () => {
  const r = JSON.parse(toJson(check(plain(), { path: 'doc.json', version: '9.9.9' })));
  assert.deepEqual(Object.keys(r), ['tool', 'version', 'document', 'areas', 'findings', 'notes', 'counts', 'gate']);
  assert.equal(r.tool, 'asyncapi-security-check');
  assert.equal(r.version, '9.9.9');
  assert.deepEqual(r.document, { path: 'doc.json', asyncapi: '3.0.0', format: 'json', title: 'Demo', servers: 1, channels: 1, operations: 1, messages: 1, securitySchemes: 1 });
  assert.deepEqual(r.areas.map((a) => a.id), ['servers', 'security', 'messages', 'operations', 'references', 'documentation']);
  assert.deepEqual(Object.keys(r.findings[0]), ['id', 'severity', 'area', 'pointer', 'line', 'subject', 'message', 'fix', 'basis', 'source']);
  assert.deepEqual(Object.keys(r.findings[0].basis[0]), ['text', 'section', 'source']);
  assert.deepEqual(r.gate, { failOn: 'error', pass: false, reason: '2 errors' });
});

test('csv report: RFC 4180, one row per finding, CRLF line ends, quotes doubled, and a leading quote on a cell a spreadsheet would run', () => {
  const r = check(with3({ servers: { '=HYPERLINK("x","y")': { host: 'b.example.test', protocol: 'ws', description: 'x', security: [{ type: 'userPassword' }] } } }));
  const out = toCsv(r);
  const lines = out.split('\r\n');
  assert.equal(lines[0], 'severity,area,id,pointer,line,subject,message,basis,source,fix');
  assert.equal(lines.at(-1), '');
  assert.ok(lines[1].startsWith('error,servers,server-plain-protocol,'));
  assert.ok(out.includes('"\'=HYPERLINK(""x"",""y"")"'));
  assert.equal(csvCell('+1'), "'+1");
  assert.equal(csvCell('-1'), "'-1");
  assert.equal(csvCell('@a'), "'@a");
  assert.equal(csvCell('a,b'), '"a,b"');
  assert.equal(csvCell('say "hi"'), '"say ""hi"""');
  assert.equal(csvCell(null), '');
  assert.equal(csvCell('plain'), 'plain');
});

test('the usage text lists every check and the exit codes', () => {
  for (const f of FINDINGS) assert.ok(USAGE.includes(f.id), f.id);
  assert.match(USAGE, /Exit codes: 0 no finding at the --fail-on level, 1 such a finding, 2 usage or input error\./);
  assert.match(USAGE, /--format <name>/);
  assert.match(USAGE, /info never fails the run/);
});

test('exit code 0: a document with no finding at the level, and --help and --version', async () => {
  assert.equal((await run({ 'a.json': base3() }, ['a.json'])).code, 0);
  assert.equal((await run({ 'a.json': base3() }, ['a.json', '--fail-on', 'warning'])).code, 0);
  const help = await cli(['--help']);
  assert.equal(help.code, 0);
  assert.equal(help.out, USAGE);
  const version = await cli(['--version']);
  assert.equal(version.code, 0);
  assert.equal(version.out, `${VERSION}\n`);
  assert.equal(VERSION, JSON.parse(await read('package.json')).version);
});

test('exit code 1: an error fails the default gate, a warning fails only --fail-on warning, and info never fails', async () => {
  const error = await run({ 'a.json': plain() }, ['a.json']);
  assert.equal(error.code, 1);
  assert.match(error.out, /GATE: FAIL - 2 errors/);
  const warning = with3({ components: { securitySchemes: base3().components.securitySchemes, messages: { Thing: { summary: 'x' } } } });
  assert.equal((await run({ 'a.json': warning }, ['a.json'])).code, 0);
  assert.equal((await run({ 'a.json': warning }, ['a.json', '--fail-on', 'warning'])).code, 1);
  const info = with3({ components: { securitySchemes: base3().components.securitySchemes, messages: { Thing: { summary: 'x', payload: {} } } } });
  const infoRun = await run({ 'a.json': info }, ['a.json', '--fail-on', 'warning']);
  assert.equal(infoRun.code, 0);
  assert.match(infoRun.out, /payload-no-type/);
});

test('exit code 2: a usage error prints the reason and the usage to the error stream, and nothing to the output', async () => {
  for (const [args, message] of [
    [[], /give the path of the AsyncAPI file/],
    [['a.json', '--nope'], /unknown argument --nope/],
    [['a.json', '--format'], /--format needs a value/],
    [['a.json', '--format', 'xml'], /unknown format xml/],
    [['a.json', '--fail-on', 'info'], /--fail-on takes error or warning, not info/],
    [['a.json', 'b.json'], /give one file, not b.json as well/],
    [['https://example.test/a.yaml'], /never fetches a URL/],
    [['-'], /standard input is not supported/]
  ]) {
    const r = await run({ 'a.json': base3() }, args);
    assert.equal(r.code, 2, args.join(' '));
    assert.equal(r.out, '');
    assert.match(r.err, message);
    assert.match(r.err, /Usage: asyncapi-security-check/);
  }
});

test('exit code 2: an input that cannot be read is reported with its name and the reason, never as a pass', async () => {
  const cases = [
    [{}, ['missing.json'], /missing\.json: no such file/],
    [{ 'sub/a.json': '{}' }, ['sub'], /sub: a folder, not a file/],
    [{ 'a.json': '{"asyncapi": "3.0.0",}' }, ['a.json'], /a\.json: the JSON: line 1/],
    [{ 'a.json': '{"asyncapi": "2.3.0"}' }, ['a.json'], /a\.json: AsyncAPI 2\.3\.0 is not supported/],
    [{ 'a.yaml': 'asyncapi: 3.0.0\nx: &a 1\n' }, ['a.yaml'], /a\.yaml: the YAML: line 2/],
    [{ 'a.json': '{"openapi": "3.0.3"}' }, ['a.json'], /use openapi-security-check/],
    [{ 'a.json': '[]' }, ['a.json'], /does not hold an object/]
  ];
  for (const [files, args, message] of cases) {
    const r = await run(files, args);
    assert.equal(r.code, 2, args.join(' '));
    assert.equal(r.out, '');
    assert.match(r.err, message);
  }
});

test('exit code 2: a file over the size limit is refused before it is read', async () => {
  const r = await run({ 'a.json': json(base3()) }, ['a.json'], { maxFileBytes: 20 });
  assert.equal(r.code, 2);
  assert.match(r.err, /a\.json: [\d,]+ bytes is over the 20 byte limit/);
});

test('paths in the report are relative to the base with forward slashes, for a file in a folder', async () => {
  const r = await run({ 'specs/orders/a.json': base3() }, ['specs/orders/a.json']);
  assert.match(r.out, /^asyncapi-security-check: specs\/orders\/a\.json$/m);
  const err = await run({}, ['specs/none.json']);
  assert.match(err.err, /specs\/none\.json: no such file/);
});

test('paths on Windows: a backslash separates the folders, and the report still shows forward slashes', async (t) => {
  if (process.platform !== 'win32') {
    t.skip('a backslash is an ordinary character in a file name on this system');
    return;
  }
  const r = await run({ 'specs/a.json': base3() }, ['specs\\a.json']);
  assert.equal(r.code, 0);
  assert.match(r.out, /^asyncapi-security-check: specs\/a\.json$/m);
});

test('paths on Linux and macOS: a backslash is part of the file name, which is read under that name', async (t) => {
  if (process.platform === 'win32') {
    t.skip('a backslash separates folders on Windows');
    return;
  }
  const r = await run({ 'we\\ird.json': base3() }, ['we\\ird.json']);
  assert.equal(r.code, 0);
  assert.match(r.out, /we\\ird\.json/);
});

test('the example files: the broken one fails with the findings the README names, the fixed one passes at the strictest level', async () => {
  const broken = await inRoot(['examples/orders-events.yaml', '--fail-on', 'warning']);
  assert.equal(broken.code, 1);
  for (const id of ['server-no-security', 'server-plain-protocol', 'apikey-in-query', 'message-no-payload', 'reply-no-correlation-id', 'channel-unused']) assert.ok(broken.out.includes(id), id);
  const fixed = await inRoot(['examples/orders-events-fixed.yaml', '--fail-on', 'warning']);
  assert.equal(fixed.code, 0);
  assert.match(fixed.out, /findings: 0 error, 0 warning, 0 info/);
  const old = await inRoot(['examples/orders-events-2.6.json']);
  assert.equal(old.code, 1);
  assert.match(old.out, /AsyncAPI 2\.6\.0, json/);
});

test('the example output files are the real output, in every format', async () => {
  const args = ['examples/orders-events.yaml', '--fail-on', 'warning'];
  assert.equal((await inRoot(args)).out, await read('examples/output/orders-events.txt'));
  assert.equal((await inRoot([...args, '--format', 'markdown'])).out, await read('examples/output/orders-events.md'));
  assert.equal((await inRoot([...args, '--format', 'json'])).out, await read('examples/output/orders-events.json'));
  const csv = (await inRoot([...args, '--format', 'csv'])).out;
  assert.equal(csv, await read('examples/output/orders-events.csv'));
  assert.ok(csv.includes('\r\n'));
  assert.equal((await inRoot(['examples/orders-events-2.6.json'])).out, await read('examples/output/orders-events-2.6.txt'));
});

test('parseArgs: the defaults, and options in any order', () => {
  assert.deepEqual(parseArgs(['a.yaml']), { file: 'a.yaml', format: 'text', failOn: 'error', help: false, version: false });
  assert.deepEqual(parseArgs(['--fail-on', 'warning', '--format', 'csv', 'a.yaml']), { file: 'a.yaml', format: 'csv', failOn: 'warning', help: false, version: false });
  assert.equal(parseArgs(['-h']).help, true);
  assert.equal(parseArgs(['-v']).version, true);
});

test('a title with control characters is cleaned in every format', () => {
  const title = `Orders${String.fromCharCode(27)}[2J${String.fromCharCode(10)}forged line`;
  const r = check(base3({ info: { title, version: '1' } }));
  for (const render of [toText, toMarkdown, toJson]) assert.ok(!render(r).includes(String.fromCharCode(27)), render.name);
  assert.ok(r.document.title.startsWith('Orders [2J forged'));
});

test('the report of a 3.0 document and of a 2.6 document differ in nothing but what the version means', () => {
  const a = check(base3());
  const b = check(base2());
  assert.deepEqual(a.areas.map((x) => x.result), b.areas.map((x) => x.result));
  assert.equal(a.document.asyncapi, '3.0.0');
  assert.equal(b.document.asyncapi, '2.6.0');
  assert.equal(goodPayload().type, 'object');
});
