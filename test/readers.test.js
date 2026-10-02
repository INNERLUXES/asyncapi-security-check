import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, symlink } from 'node:fs/promises';
import { resolve } from 'node:path';
import { DOC_LIMITS, FILE_LIMITS, createResolver, decodePointer, displayPath, escapeToken, fileError, findRefs, getPointer, lineOf, parseDocument, parseJson, parseYaml, pointerOf, readBounded } from '../src/index.js';
import { base3, json, withFiles } from './helpers.js';

const YAML_DOC = `asyncapi: 3.0.0
info:
  title: Demo
  version: "1.0.0"
servers:
  prod:
    host: broker.example.test:5671
    protocol: amqps
channels:
  user/signedup:
    address: 'user.signedup'
    messages:
      signedUp:
        $ref: '#/components/messages/SignedUp'
components:
  messages:
    SignedUp:
      correlationId:
        location: $message.header#/correlationId
      payload:
        type: object
        required: [id, name]
`;

test('parseDocument: JSON and the YAML subset give the same data and the same pointers', () => {
  const fromYaml = parseDocument(YAML_DOC, 'a.yaml');
  const fromJson = parseDocument(JSON.stringify(fromYaml.data), 'a.json');
  assert.deepEqual(fromJson.data, fromYaml.data);
  assert.equal(fromYaml.format, 'yaml');
  assert.equal(fromJson.format, 'json');
  assert.equal(fromYaml.major, 3);
  assert.equal(fromYaml.lines.get('#/channels/user~1signedup/address'), 11);
  assert.equal(fromYaml.data.components.messages.SignedUp.correlationId.location, '$message.header#/correlationId');
  assert.deepEqual(fromYaml.data.components.messages.SignedUp.payload.required, ['id', 'name']);
});

test('parseDocument: the format is read from the name, or from the first character when the name does not say', () => {
  assert.equal(parseDocument(json(base3()), 'spec').format, 'json');
  assert.equal(parseDocument(YAML_DOC, 'spec').format, 'yaml');
  assert.equal(parseDocument(json(base3()), 'spec.txt').format, 'json');
  assert.equal(parseDocument(YAML_DOC, 'spec.yml').format, 'yaml');
  assert.equal(parseDocument(`${String.fromCharCode(0xfeff)}${json(base3())}`, 'spec').format, 'json');
});

test('parseDocument: the version decides the shape: 3.0.x is major 3, 2.6.x is major 2', () => {
  assert.equal(parseDocument('{"asyncapi": "3.0.0"}', 'a.json').major, 3);
  assert.equal(parseDocument('{"asyncapi": "3.0.7"}', 'a.json').major, 3);
  assert.equal(parseDocument('{"asyncapi": "2.6.0"}', 'a.json').major, 2);
  assert.equal(parseDocument('asyncapi: 2.6.0\n', 'a.yaml').asyncapi, '2.6.0');
  assert.equal(parseDocument('{"asyncapi": "3.0.0-rc1"}', 'a.json').major, 3);
});

test('parseDocument: things that are not an AsyncAPI 3.0 or 2.6 document are refused with a reason', () => {
  assert.throws(() => parseDocument('[1, 2]', 'a.json'), /does not hold an object/);
  assert.throws(() => parseDocument('{"info": {}}', 'a.json'), /no "asyncapi" version field/);
  assert.throws(() => parseDocument('{"asyncapi": 3}', 'a.json'), /no "asyncapi" version field/);
  assert.throws(() => parseDocument('{"asyncapi": "2.5.0"}', 'a.json'), /AsyncAPI 2.5.0 is not supported \(3.0 and 2.6 are\)/);
  assert.throws(() => parseDocument('{"asyncapi": "1.2.0"}', 'a.json'), /not supported/);
  assert.throws(() => parseDocument('{"asyncapi": "4.0.0"}', 'a.json'), /not supported/);
  assert.throws(() => parseDocument('{"asyncapi": "3"}', 'a.json'), /major.minor.patch/);
  assert.throws(() => parseDocument('{"asyncapi": "3.0.0", "servers": []}', 'a.json'), /"servers" is not an object/);
  assert.throws(() => parseDocument('{"asyncapi": "3.0.0", "channels": "x"}', 'a.json'), /"channels" is not an object/);
});

test('parseDocument: an OpenAPI description is refused with the name of the tool that reads it', () => {
  assert.throws(() => parseDocument('{"openapi": "3.0.3"}', 'a.json'), /use openapi-security-check/);
  assert.throws(() => parseDocument('{"swagger": "2.0"}', 'a.json'), /OpenAPI or Swagger/);
});

test('parseDocument: YAML outside the documented subset is refused with the line, never guessed', () => {
  const block = 'asyncapi: 3.0.0\ninfo:\n  title: Demo\n  description: |\n    text\n  version: "1"\n';
  assert.throws(() => parseDocument(block, 'a.yaml'), /line 4: .*block scalars/);
  assert.throws(() => parseDocument('asyncapi: 3.0.0\nx: &a 1\n', 'a.yaml'), /line 2/);
  assert.throws(() => parseDocument('asyncapi: 3.0.0\nx: *a\n', 'a.yaml'), /line 2/);
  assert.throws(() => parseDocument('asyncapi: 3.0.0\nx: !!str 1\n', 'a.yaml'), /line 2/);
  assert.throws(() => parseDocument('asyncapi: 3.0.0\n\tx: 1\n', 'a.yaml'), /tab/);
  assert.throws(() => parseDocument('asyncapi: 3.0.0\n---\nx: 1\n', 'a.yaml'), /more than one document/);
  assert.throws(() => parseDocument('asyncapi: 3.0.0\nx: {a: 1}\n', 'a.yaml'), /flow mapping/);
  assert.throws(() => parseDocument('asyncapi: 3.0.0\nx:\n  <<: y\n', 'a.yaml'), /kind of key/);
  assert.throws(() => parseDocument('asyncapi: 3.0.0\nx: 1\nx: 2\n', 'a.yaml'), /appears twice/);
});

test('parseDocument: JSON that is not strict JSON, and a key given twice, are refused', () => {
  assert.throws(() => parseDocument('{"asyncapi": "3.0.0",}', 'a.json'), /line 1/);
  assert.throws(() => parseDocument("{'asyncapi': '3.0.0'}", 'a.json'), /key in quotes/);
  assert.throws(() => parseDocument('{"asyncapi": "3.0.0", "asyncapi": "2.6.0"}', 'a.json'), /appears twice/);
  assert.throws(() => parseDocument('{"asyncapi": "3.0.0"} x', 'a.json'), /text after the end/);
  assert.throws(() => parseDocument('{"asyncapi": "3.0.0", // note\n"a": 1}', 'a.json'), /line 1/);
});

test('parseDocument: a key such as __proto__ is only a name and changes nothing', () => {
  const parsed = parseDocument('{"asyncapi": "3.0.0", "__proto__": {"polluted": true}, "channels": {}}', 'a.json');
  assert.equal(Object.getPrototypeOf(parsed.data), null);
  assert.equal(Object.hasOwn(parsed.data, '__proto__'), true);
  assert.equal({}.polluted, undefined);
  const yaml = parseDocument('asyncapi: 3.0.0\n__proto__:\n  polluted: true\n', 'a.yaml');
  assert.equal(Object.hasOwn(yaml.data, '__proto__'), true);
  assert.equal({}.polluted, undefined);
});

test('parseDocument: nesting deeper than the limit, too many values and too many lines are refused', () => {
  const deep = `{"asyncapi": "3.0.0", "x": ${'['.repeat(70)}${']'.repeat(70)}}`;
  assert.throws(() => parseDocument(deep, 'a.json'), /nested more than 64 deep/);
  const wide = `{"asyncapi": "3.0.0", "x": [${Array.from({ length: 50 }, () => '1').join(',')}]}`;
  assert.throws(() => parseDocument(wide, 'a.json', { ...DOC_LIMITS, maxNodes: 20 }), /more than 20 values/);
  assert.throws(() => parseDocument(`asyncapi: 3.0.0\n${'a: 1\n'.repeat(30)}`, 'a.yaml', { ...DOC_LIMITS, maxYamlLines: 10 }), /more than 10 lines/);
});

test('parseJson and parseYaml: nodes keep the line of every value', () => {
  const node = parseJson('{\n  "a": 1,\n  "b": [\n    2\n  ]\n}', 'x');
  assert.equal(node.props[1].line, 3);
  assert.equal(node.props[1].value.items[0].line, 4);
  const y = parseYaml('a: 1\nb:\n  - 2\n', 'x');
  assert.equal(y.props[1].line, 2);
  assert.equal(y.props[1].value.items[0].line, 3);
});

test('parseYaml: the forms that AsyncAPI files use are read', () => {
  const y = parseYaml(`# comment
a: 'it''s'   # trailing comment
b: "tab\\there"
c: [one, "two, three", 'four']
d:
- x: 1
  y: 2
- z
e: {}
f: ~
g: 10
h: 1.5
i: yes
j: 3.0.0
`, 'x');
  const get = (k) => y.props.find((p) => p.key === k).value;
  assert.equal(get('a').value, "it's");
  assert.equal(get('b').value, 'tab\there');
  assert.deepEqual(get('c').items.map((i) => i.value), ['one', 'two, three', 'four']);
  assert.equal(get('d').items[0].props.length, 2);
  assert.equal(get('d').items[1].value, 'z');
  assert.equal(get('e').t, 'object');
  assert.equal(get('f').t, 'null');
  assert.equal(get('g').value, 10);
  assert.equal(get('h').value, 1.5);
  assert.equal(get('i').value, 'yes');
  assert.equal(get('j').value, '3.0.0');
});

test('pointers: tokens are escaped with ~0 and ~1, and decoded with %XX', () => {
  assert.equal(escapeToken('/a~b'), '~1a~0b');
  assert.equal(pointerOf([]), '#');
  assert.equal(pointerOf(['channels', 'user/signedup', 'address']), '#/channels/user~1signedup/address');
  assert.deepEqual(decodePointer('#/components/messages/A%20B'), ['components', 'messages', 'A B']);
  assert.deepEqual(decodePointer('#/channels/user~1signedup'), ['channels', 'user/signedup']);
  assert.deepEqual(decodePointer('#'), []);
  assert.deepEqual(decodePointer('#/a/%E0%A4%A'), ['a', '%E0%A4%A']);
  assert.throws(() => decodePointer('other.yaml#/a'), /not a local reference/);
});

test('pointers: getPointer follows own properties and array indexes only', () => {
  const data = parseDocument('{"asyncapi": "3.0.0", "a": {"b": [10, 20]}}', 'x.json').data;
  assert.equal(getPointer(data, ['a', 'b', '1']), 20);
  assert.equal(getPointer(data, ['a', 'b', '2']), undefined);
  assert.equal(getPointer(data, ['a', 'b', '01']), undefined);
  assert.equal(getPointer(data, ['a', 'toString']), undefined);
  assert.equal(getPointer(data, ['constructor']), undefined);
  assert.equal(getPointer(data, ['__proto__']), undefined);
});

test('lineOf: a pointer that does not exist gets the line of its nearest ancestor', () => {
  const { lines } = parseDocument('{\n"asyncapi": "3.0.0",\n"channels": {\n"a": {}\n}\n}', 'x.json');
  assert.equal(lineOf(lines, '#/channels/a'), 4);
  assert.equal(lineOf(lines, '#/channels/a/messages/x'), 4);
  assert.equal(lineOf(lines, '#/nothing/at/all'), 1);
});

test('findRefs: a $ref inside a file is local, any other is remote, and data under example, default or x- is not read', () => {
  const data = parseDocument(json({
    asyncapi: '3.0.0',
    a: { $ref: '#/b' },
    b: { $ref: 'other.yaml#/x' },
    c: [{ $ref: 'https://example.test/schema.json' }],
    d: { example: { $ref: 'https://example.test/not-a-reference' }, default: { $ref: 'x' }, examples: [{ $ref: 'y' }], 'x-note': { $ref: 'z' } },
    properties: { default: { $ref: '#/b' }, examples: { $ref: '#/a' } }
  }), 'x.json').data;
  const refs = findRefs(data);
  assert.deepEqual(refs.local.map((r) => r.at).sort(), ['#/a', '#/properties/default', '#/properties/examples']);
  assert.deepEqual(refs.remote.map((r) => r.at).sort(), ['#/b', '#/c/0']);
});

test('createResolver: follows a chain, and stops at a cycle, a broken reference and a remote one', () => {
  const data = parseDocument(json({ asyncapi: '3.0.0', a: { $ref: '#/b' }, b: { $ref: '#/c' }, c: { type: 'string' }, x: { $ref: '#/y' }, y: { $ref: '#/x' }, z: { $ref: '#/nope' }, w: { $ref: 'http://example.test/w' }, self: { $ref: '#/self' } }), 'x.json').data;
  const r = createResolver(data);
  const viaChain = r.resolve(data.a, '#/a');
  assert.deepEqual([JSON.stringify(viaChain.node), viaChain.pointer, viaChain.status], ['{"type":"string"}', '#/c', 'ok']);
  assert.equal(r.resolve(data.x, '#/x').status, 'cycle');
  assert.equal(r.resolve(data.self, '#/self').status, 'cycle');
  assert.equal(r.resolve(data.z, '#/z').status, 'broken');
  assert.equal(r.resolve(data.w, '#/w').status, 'remote');
  assert.deepEqual(r.resolve({ type: 'string' }, '#/q'), { node: { type: 'string' }, pointer: '#/q', status: 'ok' });
});

test('createResolver: a chain longer than the limit counts as a cycle', () => {
  const doc = { asyncapi: '3.0.0' };
  for (let i = 0; i < 40; i += 1) doc[`r${i}`] = { $ref: `#/r${i + 1}` };
  doc.r40 = { type: 'string' };
  const data = parseDocument(json(doc), 'x.json').data;
  assert.equal(createResolver(data).resolve(data.r0, '#/r0').status, 'cycle');
  assert.equal(createResolver(data, { ...DOC_LIMITS, maxRefChain: 64 }).resolve(data.r0, '#/r0').status, 'ok');
});

test('readBounded: reads a regular file whole; a missing file, a folder and a file over the limit are refused with the reason', async () => {
  await withFiles({ 'a.json': '{"x": 1}', 'sub/b.json': '{}', 'big.json': 'x'.repeat(50) }, async (dir) => {
    assert.equal((await readBounded(resolve(dir, 'a.json'))).toString(), '{"x": 1}');
    await assert.rejects(readBounded(resolve(dir, 'none.json')), (e) => e.reason === 'no such file');
    await assert.rejects(readBounded(resolve(dir, 'sub')), (e) => e.reason === 'a folder, not a file');
    await assert.rejects(readBounded(resolve(dir, 'big.json'), 10), (e) => /50 bytes is over the 10 byte limit/.test(e.reason));
    assert.equal(FILE_LIMITS.maxFileBytes, 10 * 1024 * 1024);
    assert.ok(fileError('p', 'why').message === 'p: why');
  });
});

test('readBounded: a symbolic link given as the path is followed, because the person who runs the tool gave it', async (t) => {
  if (process.platform === 'win32') {
    t.skip('creating a symbolic link needs a privilege on Windows');
    return;
  }
  await withFiles({ 'real.json': '{"x": 1}' }, async (dir) => {
    await mkdir(resolve(dir, 'sub'));
    await symlink(resolve(dir, 'real.json'), resolve(dir, 'sub/link.json'));
    assert.equal((await readBounded(resolve(dir, 'sub/link.json'))).toString(), '{"x": 1}');
  });
});

test('displayPath: relative to the base with forward slashes; outside the base it is absolute', async () => {
  await withFiles({ 'a/b.json': '{}' }, async (dir) => {
    assert.equal(displayPath(resolve(dir, 'a/b.json'), dir), 'a/b.json');
    assert.equal(displayPath(dir, dir), '.');
    assert.ok(!displayPath(resolve(dir, 'a/b.json'), resolve(dir, 'a')).includes('\\'));
    assert.ok(!displayPath(resolve(dir, '..', 'elsewhere', 'x.json'), dir).includes('\\'));
  });
});
