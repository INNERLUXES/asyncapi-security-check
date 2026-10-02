import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, symlink, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { DOC_LIMITS, hostOf, parseDocument, toCsv, toMarkdown, toText } from '../src/index.js';
import { base3, check, find, ids, json, run, with3, withFiles } from './helpers.js';

// Hostile input: a document that tries to exhaust the stack, the memory or the time, to make the tool read more than
// it was given, to rewrite the terminal, to break a table or to change how objects behave. Each test also checks the
// time, because a pattern or a walk that grows with the input is a failure even when the answer is right.

const LIMIT = { timeout: 20000 };
const fast = async (fn, ms = 3000) => {
  const start = Date.now();
  const result = await fn();
  assert.ok(Date.now() - start < ms, `took ${Date.now() - start} ms`);
  return result;
};

test('hostile: JSON nested a hundred thousand levels deep is refused with a message, not a stack overflow', LIMIT, async () => {
  const r = await fast(() => run({ 'a.json': `{"asyncapi": "3.0.0", "x": ${'['.repeat(100000)}${']'.repeat(100000)}}` }, ['a.json']));
  assert.equal(r.code, 2);
  assert.match(r.err, /nested more than 64 deep/);
});

test('hostile: YAML nested two hundred levels deep is refused', LIMIT, async () => {
  let text = 'asyncapi: 3.0.0\n';
  for (let i = 0; i < 200; i += 1) text += `${'  '.repeat(i)}k${i}:\n`;
  const r = await fast(() => run({ 'a.yaml': text }, ['a.yaml']));
  assert.equal(r.code, 2);
  assert.match(r.err, /nested more than 64 deep/);
});

test('hostile: three strings of three million characters is read within the size limit, quickly, and never printed', LIMIT, async () => {
  const big = 'A'.repeat(3_000_000);
  const doc = with3({ info: { title: 'Big', version: '1', description: big }, components: { ...base3().components, messages: { Thing: { summary: big, payload: { type: 'object', properties: { a: { type: 'string', default: big } }, required: ['a'] } } } } });
  const r = await fast(() => run({ 'a.json': json(doc) }, ['a.json']), 8000);
  assert.equal(r.code, 0);
  assert.ok(r.out.length < 5000);
});

test('hostile: a file over the default size limit is refused from its size', LIMIT, async () => {
  await withFiles({}, async (dir) => {
    await writeFile(resolve(dir, 'big.json'), `{"asyncapi": "3.0.0", "x": "${'a'.repeat(10 * 1024 * 1024 + 10)}"}`);
    const r = await fast(async () => {
      const { main } = await import('../src/index.js');
      let err = '';
      const code = await main(['big.json'], { out: () => {}, err: (t) => { err += t; } }, undefined, dir);
      return { code, err };
    });
    assert.equal(r.code, 2);
    assert.match(r.err, /over the 10 MB limit/);
  });
});

test('hostile: more values than the limit are refused, and so are very many servers', LIMIT, async () => {
  const many = JSON.stringify({ asyncapi: '3.0.0', x: Array.from({ length: 250000 }, () => 1) });
  const r = await fast(() => run({ 'a.json': many }, ['a.json']));
  assert.equal(r.code, 2);
  assert.match(r.err, /more than 200,000 values/);
  const servers = Object.fromEntries(Array.from({ length: 1500 }, (_, i) => [`s${i}`, { host: 'a.example.test', protocol: 'amqps' }]));
  assert.throws(() => check({ asyncapi: '3.0.0', servers }), /more than 1,000 servers/);
});

test('hostile: a $ref chain of a thousand links, a cycle and a reference to itself end without a hang, as findings', LIMIT, () => {
  const schemas = {};
  for (let i = 0; i < 1000; i += 1) schemas[`s${i}`] = { $ref: `#/components/schemas/s${i + 1}` };
  schemas.s1000 = { type: 'string' };
  schemas.loopA = { $ref: '#/components/schemas/loopB' };
  schemas.loopB = { $ref: '#/components/schemas/loopA' };
  schemas.self = { $ref: '#/components/schemas/self' };
  const r = check(with3({ components: { ...base3().components, schemas } }));
  const cycles = find(r, 'ref-cycle').map((f) => f.pointer);
  assert.ok(cycles.includes('#/components/schemas/loopA/$ref'));
  assert.ok(cycles.includes('#/components/schemas/loopB/$ref'));
  assert.equal(cycles.length, DOC_LIMITS.maxListedPerFinding);
  assert.ok(r.counts.error >= 3 + 960);
  assert.equal(r.gate.pass, false);
});

test('hostile: a payload that is a $ref cycle, or a schema that contains itself, is read without a hang', LIMIT, () => {
  const cyc = check(with3({ components: { ...base3().components, messages: { Thing: { summary: 'x', payload: { $ref: '#/components/schemas/A' } } }, schemas: { A: { $ref: '#/components/schemas/B' }, B: { $ref: '#/components/schemas/A' } } } }));
  assert.deepEqual([...new Set(ids(cyc))], ['ref-cycle']);
  const recursive = check(with3({ components: { ...base3().components, messages: { Thing: { summary: 'x', payload: { $ref: '#/components/schemas/Tree' } } }, schemas: { Tree: { type: 'object', properties: { child: { $ref: '#/components/schemas/Tree' } }, required: ['child'] } } } }));
  assert.deepEqual(ids(recursive), []);
});

test('hostile: tens of thousands of broken references are listed up to the limit, counted in full, and quickly', LIMIT, async () => {
  const schemas = {};
  for (let i = 0; i < 30000; i += 1) schemas[`s${i}`] = { $ref: `#/nowhere/${i}` };
  const r = await fast(() => check(with3({ components: { ...base3().components, schemas } })), 6000);
  assert.equal(find(r, 'ref-unresolved').length, DOC_LIMITS.maxListedPerFinding);
  assert.equal(r.counts.error, 30000);
  assert.equal(r.gate.pass, false);
  assert.ok(r.notes.some((n) => /29,800 more findings of ref-unresolved/.test(n)));
});

test('hostile: YAML anchors, aliases and tags are refused, and an alias bomb is never expanded', LIMIT, async () => {
  const bomb = ['asyncapi: 3.0.0', 'a: &a [x, x, x, x, x, x, x, x, x]', 'b: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]', 'c: &c [*b, *b, *b, *b, *b, *b, *b, *b, *b]', 'd: &d [*c, *c, *c, *c, *c, *c, *c, *c, *c]'].join('\n');
  const r = await fast(() => run({ 'bomb.yaml': bomb }, ['bomb.yaml']));
  assert.equal(r.code, 2);
  assert.match(r.err, /bomb\.yaml: the YAML: line 2/);
  for (const text of ['asyncapi: 3.0.0\nx: *alias\n', 'asyncapi: 3.0.0\nx: !!binary abc\n', 'asyncapi: 3.0.0\nx:\n  <<: *base\n', 'asyncapi: 3.0.0\n&anchor x: 1\n']) {
    const t = await run({ 'a.yaml': text }, ['a.yaml']);
    assert.equal(t.code, 2, text);
  }
});

test('hostile: a YAML line of a hundred thousand characters, and a million lines, are refused', LIMIT, async () => {
  const long = await fast(() => run({ 'a.yaml': `asyncapi: 3.0.0\nx: ${'a'.repeat(100000)}\n` }, ['a.yaml']));
  assert.equal(long.code, 2);
  assert.match(long.err, /a line longer than 4000 characters/);
  const lines = await fast(() => run({ 'a.yaml': `asyncapi: 3.0.0\n${'x: 1\n'.repeat(150000)}` }, ['a.yaml']));
  assert.equal(lines.code, 2);
  assert.match(lines.err, /more than 100,000 lines/);
});

test('hostile: long near misses for the host and protocol patterns take no longer than short ones', LIMIT, async () => {
  await fast(() => {
    assert.equal(hostOf(`${'a:'.repeat(100000)}`), 'a');
    assert.equal(hostOf(`${'['.repeat(100000)}`), '');
    assert.equal(hostOf(`${'a'.repeat(100000)}@${'b'.repeat(100000)}`).length <= 400, true);
    assert.equal(hostOf(`${'x'.repeat(100000)}://host`).length <= 400, true);
    const r = check(with3({ servers: { prod: { host: `${'a'.repeat(100000)}:`, protocol: ` ${' '.repeat(100000)}amqp`, description: 'x', security: [{ type: 'userPassword' }] } } }));
    assert.ok(Array.isArray(r.findings));
  });
});

test('hostile: a name made of control, direction and line separator characters is cleaned in every format', LIMIT, () => {
  const bad = ['x', String.fromCharCode(27), '[31m', String.fromCharCode(0x202e), 'y', String.fromCharCode(0x2028), 'z', String.fromCharCode(0), String.fromCharCode(0x85)].join('');
  const r = check(with3({ servers: { [bad]: { host: 'b.example.test', protocol: 'ws', description: 'x', security: [{ type: 'userPassword' }] } } }));
  for (const out of [toText(r), toMarkdown(r), toCsv(r), JSON.stringify(r)]) {
    for (const code of [27, 0x202e, 0x2028, 0, 0x85]) assert.ok(!out.includes(String.fromCharCode(code)), `character ${code}`);
  }
});

test('hostile: names such as __proto__, constructor and toString are only names, in JSON and in YAML', LIMIT, () => {
  const text = '{"asyncapi": "3.0.0", "servers": {"__proto__": {"host": "a.example.test", "protocol": "ws", "description": "x"}, "constructor": {"host": "a.example.test", "protocol": "amqps"}}, "channels": {"toString": {"address": "x", "messages": {"__proto__": {"summary": "x"}}}}, "operations": {"hasOwnProperty": {"action": "send", "summary": "x", "channel": {"$ref": "#/channels/toString"}}}}';
  const r = check(text);
  assert.deepEqual(find(r, 'server-plain-protocol').map((f) => f.subject), ['__proto__']);
  assert.deepEqual(find(r, 'server-no-security').map((f) => f.subject).sort(), ['__proto__', 'constructor']);
  assert.deepEqual(find(r, 'message-no-payload').map((f) => f.subject), ['__proto__']);
  assert.equal(find(r, 'channel-unused').length, 0);
  assert.equal({}.polluted, undefined);
  assert.equal(Object.getPrototypeOf({}), Object.prototype);
  const viaYaml = check(['asyncapi: 3.0.0', 'servers:', '  __proto__:', '    host: a.example.test', '    protocol: ws', ''].join('\n'), { name: 'a.yaml' });
  assert.deepEqual(find(viaYaml, 'server-plain-protocol').map((f) => f.subject), ['__proto__']);
  assert.equal(Object.keys({}).length, 0);
});

test('hostile: a file with binary bytes, a null byte or a half character is refused or read as text, never a crash', LIMIT, async () => {
  for (const content of [Buffer.from([0, 1, 2, 3, 255, 254]), Buffer.from('{"asyncapi": "3.0.0", "x": "\u0000"}'), Buffer.from([0x7b, 0xc3, 0x28, 0x7d])]) {
    const r = await run({ 'a.json': content }, ['a.json']);
    assert.ok([0, 1, 2].includes(r.code));
  }
  assert.equal((await run({ 'a.json': Buffer.from([0, 1, 2, 3, 255, 254]) }, ['a.json'])).code, 2);
});

test('hostile: an argument that is a URL, a very long path, or a path with control characters is refused or reported cleanly', LIMIT, async () => {
  const url = await run({}, ['https://example.test/spec.yaml']);
  assert.equal(url.code, 2);
  assert.match(url.err, /never fetches a URL/);
  const long = await run({}, [`${'a'.repeat(5000)}.json`]);
  assert.equal(long.code, 2);
  assert.ok(long.err.length < 8000);
  const control = await run({}, [`x${String.fromCharCode(27)}[31mfile.json`]);
  assert.equal(control.code, 2);
  assert.ok(!control.err.includes(String.fromCharCode(27)));
});

test('hostile: a file name with control characters is cleaned in the report, where the system allows such a name', LIMIT, async (t) => {
  if (process.platform === 'win32') {
    t.skip('Windows does not allow a control character in a file name');
    return;
  }
  const name = `evil${String.fromCharCode(27)}[31m.json`;
  let r;
  try {
    r = await run({ [name]: base3() }, [name]);
  } catch (error) {
    if (!['EINVAL', 'EILSEQ', 'ENOENT', 'EPERM', 'EACCES'].includes(error.code)) throw error;
    t.skip(`this file system does not allow the name (${error.code})`);
    return;
  }
  assert.equal(r.code, 0);
  assert.ok(!r.out.includes(String.fromCharCode(27)));
});

test('hostile: a device or a pipe in place of the file is refused without being opened', LIMIT, async (t) => {
  if (process.platform === 'win32') {
    t.skip('there is no device file at this path on Windows');
    return;
  }
  const r = await run({}, ['/dev/null']);
  assert.equal(r.code, 2);
  assert.match(r.err, /not a regular file/);
});

test('hostile: a symbolic link to a folder is refused, and one to a file is followed because the person gave it', LIMIT, async (t) => {
  if (process.platform === 'win32') {
    t.skip('creating a symbolic link needs a privilege on Windows');
    return;
  }
  await withFiles({ 'real.json': json(base3()) }, async (dir) => {
    await mkdir(resolve(dir, 'folder'));
    await symlink(resolve(dir, 'folder'), resolve(dir, 'dirlink'));
    await symlink(resolve(dir, 'real.json'), resolve(dir, 'filelink.json'));
    const { main } = await import('../src/index.js');
    let err = '';
    assert.equal(await main(['dirlink'], { out: () => {}, err: (x) => { err += x; } }, undefined, dir), 2);
    assert.match(err, /a folder, not a file/);
    let out = '';
    assert.equal(await main(['filelink.json'], { out: (x) => { out += x; }, err: () => {} }, undefined, dir), 0);
    assert.match(out, /filelink\.json/);
  });
});

test('hostile: a document made of many channels, messages and operations is checked in time and every limit holds', LIMIT, async () => {
  const channels = {};
  const operations = {};
  const msgs = {};
  for (let i = 0; i < 2000; i += 1) {
    msgs[`M${i}`] = { summary: 'x', payload: { type: 'object', properties: { a: { type: 'string' } }, required: ['a'] } };
    channels[`c${i}`] = { address: `c${i}`, messages: { m: { $ref: `#/components/messages/M${i}` } } };
    operations[`o${i}`] = { action: 'send', summary: 'x', channel: { $ref: `#/channels/c${i}` } };
  }
  const r = await fast(() => check(with3({ channels, operations, components: { ...base3().components, messages: msgs } })), 6000);
  assert.deepEqual(ids(r), []);
  assert.equal(r.document.channels, 2000);
  assert.equal(r.document.operations, 2000);
  assert.equal(r.document.messages, 2000);
});

test('hostile: a document that is valid JSON for the reader but names a version as an object, an array or a huge string is refused', LIMIT, () => {
  assert.throws(() => parseDocument('{"asyncapi": {"a": 1}}', 'a.json'), /no "asyncapi" version field/);
  assert.throws(() => parseDocument('{"asyncapi": ["3.0.0"]}', 'a.json'), /no "asyncapi" version field/);
  assert.throws(() => parseDocument(`{"asyncapi": "${'9'.repeat(100000)}"}`, 'a.json'), (e) => e.message.length < 200);
});
