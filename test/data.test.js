import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFile, readdir } from 'node:fs/promises';
import { CREDENTIAL_TYPES, DATA_FIELDS, FACTS, FIELDS, FINDINGS, HTTP_API_KEY_IN, MAP_FIELDS, PROTOCOLS, SCHEME_TYPES, SOURCES, VERSIONS, factPage, source } from '../src/index.js';

// These tests read the saved pages again and compare them with src/data.js: every field name, every protocol name and
// every sentence that a finding quotes.

const text = async (id) => readFile(new URL(`../research/sources/${source(id).file}`, import.meta.url), 'utf8');
const quotes = (t) => t.split(String.fromCharCode(0x2019)).join("'").split(String.fromCharCode(0x2018)).join("'").split(String.fromCharCode(0x201c)).join('"').split(String.fromCharCode(0x201d)).join('"');
// Text compared without line breaks, runs of white space, backticks or the typographic quotes.
const flat = (t) => quotes(t).replace(/`/g, '').replace(/\s+/g, ' ').trim();
const has = (page, needle) => flat(page).includes(flat(needle));
const word = (page, name) => new RegExp(`(?:^|[^A-Za-z0-9_$-])${name.replace(/[$]/g, '\\$')}(?:$|[^A-Za-z0-9_-])`).test(page);
// The words of a tool that wrote a text, built from pieces so that this file does not hold them.
const WRITTEN = new RegExp(`\\b(?:${['A', 'I'].join('')}|${['cha', 't'].join('')}|${['clau', 'de'].join('')}|${['anthro', 'pic'].join('')}|${['ope', 'nai'].join('')})\\b`, 'i');

test('sources: every saved page has its address on the first line, as listed in src/data.js, and holds text', async () => {
  for (const s of SOURCES) {
    const page = await text(s.id);
    assert.equal(page.split('\n')[0], `Source: ${s.url}`, s.file);
    assert.ok(page.length > 800, `${s.file} holds the page text`);
    assert.match(s.url, /^https:\/\//);
  }
  assert.equal(SOURCES.length, new Set(SOURCES.map((s) => s.url)).size);
  assert.equal(SOURCES.length, new Set(SOURCES.map((s) => s.file)).size);
  assert.equal(SOURCES.length, new Set(SOURCES.map((s) => s.id)).size);
});

test('sources: every file in research/sources is listed in src/data.js, and the other way round', async () => {
  const files = (await readdir(new URL('../research/sources/', import.meta.url))).sort();
  assert.deepEqual(files, SOURCES.map((s) => s.file).sort());
});

test('sources: the pages come from the AsyncAPI repository at the release tags, OASIS and the RFC editor', () => {
  assert.equal(source('asyncapi-3.0.0').url, 'https://raw.githubusercontent.com/asyncapi/spec/v3.0.0/spec/asyncapi.md');
  assert.equal(source('asyncapi-2.6.0').url, 'https://raw.githubusercontent.com/asyncapi/spec/v2.6.0/spec/asyncapi.md');
  assert.deepEqual(SOURCES.map((s) => new URL(s.url).host).sort(), ['docs.oasis-open.org', 'raw.githubusercontent.com', 'raw.githubusercontent.com', 'www.rfc-editor.org', 'www.rfc-editor.org', 'www.rfc-editor.org']);
  assert.deepEqual(VERSIONS, { v3: '3.0', v2: '2.6' });
});

test('sources: no saved page mentions a tool that wrote it, holds a control byte, a carriage return or a character that is not ASCII', async () => {
  for (const s of SOURCES) {
    const page = await text(s.id);
    assert.doesNotMatch(page, WRITTEN, s.file);
    assert.doesNotMatch(page, new RegExp(`[${String.fromCharCode(1)}-${String.fromCharCode(8)}]`), s.file);
    assert.ok(!page.includes('\r'), s.file);
    assert.ok([...page].every((c) => c.charCodeAt(0) < 128), s.file);
  }
});

test('the saved 3.0.0 and 2.6.0 pages are the versions they say: 3.0 has operations with an action and a reply, 2.6 has publish and subscribe', async () => {
  const v3 = await text('asyncapi-3.0.0');
  const v2 = await text('asyncapi-2.6.0');
  assert.ok(v3.includes('action | "send" | "receive"'));
  assert.ok(v3.includes('#### Operation Reply Object'));
  assert.ok(!v2.includes('Operation Reply Object'));
  assert.ok(v2.includes('subscribe | Operation Object | A definition of the SUBSCRIBE operation'));
  assert.ok(v2.includes('publish | Operation Object | A definition of the PUBLISH operation'));
  assert.ok(v2.includes('messageId | string | Unique string used to identify the message.'));
  assert.ok(!v3.includes(`${String.fromCharCode(10)}messageId |`));
  assert.ok(v3.includes('{messageId} | Message Object | Reference Object | The key represents the message identifier.'));
  assert.ok(word(v3, 'host') && word(v2, 'url'));
});

test('fields: every field name that src uses is on the 3.0.0 page, or for the 2.6 only fields on the 2.6.0 page', async () => {
  const v3 = await text('asyncapi-3.0.0');
  const v2 = await text('asyncapi-2.6.0');
  const only2 = ['url', 'operationId', 'messageId', 'publish', 'subscribe'];
  const only3 = ['host', 'action', 'reply', 'address', 'operations'];
  for (const [key, name] of Object.entries(FIELDS)) {
    if (name === '$ref') continue;
    if (only2.includes(name)) assert.ok(word(v2, name), `2.6 ${key}`);
    else assert.ok(word(v3, name), `3.0 ${key}: ${name}`);
    if (!only3.includes(name) && !only2.includes(name) && !['schema', 'schemaFormat', 'message', 'oneOf', 'enum', 'const', 'allOf', 'anyOf', 'required', 'properties', 'type', 'scheme', 'in', 'name'].includes(name)) assert.ok(word(v2, name), `2.6 ${key}`);
  }
  assert.ok(word(v2, 'message') && word(v2, 'oneOf'));
});

test('fields: the keywords of the payload schema are named by the specification, which says its schema is a JSON Schema vocabulary', async () => {
  for (const id of ['asyncapi-3.0.0', 'asyncapi-2.6.0']) {
    const page = await text(id);
    assert.ok(has(page, FACTS.schemaVocabulary.text), id);
    for (const k of ['type', 'required', 'properties', 'allOf', 'anyOf', 'oneOf', 'enum', 'const']) assert.ok(word(page, k), `${id} ${k}`);
  }
});

test('security scheme types: the list is the one of the Security Scheme Object, in both versions, and the values of in are the ones listed', async () => {
  for (const id of ['asyncapi-3.0.0', 'asyncapi-2.6.0']) {
    const page = await text(id);
    assert.ok(has(page, FACTS.schemeTypes.text), id);
    assert.ok(has(page, FACTS.schemeIn.text), id);
    for (const name of Object.values(SCHEME_TYPES)) assert.ok(page.includes(`"${name}"`), `${id} ${name}`);
    for (const name of Object.values(HTTP_API_KEY_IN)) assert.ok(page.includes(`"${name}"`), `${id} ${name}`);
  }
  assert.equal(Object.keys(SCHEME_TYPES).length, 13);
  for (const t of CREDENTIAL_TYPES) assert.ok(Object.hasOwn(SCHEME_TYPES, t), t);
  assert.ok(!CREDENTIAL_TYPES.includes('oauth2') && !CREDENTIAL_TYPES.includes('X509'));
});

test('protocols: every plain and secure name of the table is in the protocol list of the 2.6.0 Server Object, and mqtts is the one name that is not', async () => {
  const page = await text('asyncapi-2.6.0');
  const listed = FACTS.protocolList.text.replace(/^[^:]*: /, '').replace(/\.$/, '').split(', ');
  assert.ok(has(page, FACTS.protocolList.text));
  assert.equal(listed.length, 19);
  for (const row of PROTOCOLS) {
    assert.ok(listed.includes(row.plain), row.plain);
    assert.ok(listed.includes(row.secure), row.secure);
    assert.ok(row.accepted.includes(row.secure), row.secure);
    assert.notEqual(row.plain, row.secure);
    assert.ok(FACTS[row.why], row.plain);
  }
  const unlisted = PROTOCOLS.flatMap((r) => r.accepted).filter((p) => !listed.includes(p));
  assert.deepEqual(unlisted, ['mqtts']);
  assert.deepEqual(PROTOCOLS.map((r) => r.plain), ['amqp', 'http', 'kafka', 'mqtt', 'stomp', 'ws']);
});

test('protocols: the 3.0.0 page gives no list of values, only example names, which is why the list is quoted from 2.6.0', async () => {
  const v3 = await text('asyncapi-3.0.0');
  assert.ok(!v3.includes('kafka-secure'));
  assert.ok(!v3.includes('secure-mqtt'));
  assert.ok(has(v3, FACTS.protocolV3.text));
  assert.ok(has(v3, 'Example protocols include, but are not limited to, AMQP, HTTP, JMS, Kafka, Anypoint MQ, MQTT, Solace, STOMP, Mercure, WebSocket, Google Pub/Sub, Pulsar.'));
  assert.equal(factPage('protocolList'), source('asyncapi-2.6.0').url);
});

test('facts: every quoted sentence is on its saved page, word for word, with no year and no mention of a tool that wrote it', async () => {
  for (const [key, fact] of Object.entries(FACTS)) {
    assert.ok(SOURCES.some((s) => s.id === fact.source), key);
    assert.ok(has(await text(fact.source), fact.text), `${key}: "${fact.text}"`);
    assert.ok(fact.section.length > 3, key);
    assert.doesNotMatch(fact.text, /\b(?:19|20)\d{2}\b/, key);
    assert.doesNotMatch(fact.text, WRITTEN, key);
    assert.match(fact.text, /[.]$|credentials$/, `${key} ends like a sentence`);
  }
});

test('facts: a sentence marked as on both pages of the specification is on both, and is shown with the page of the version that is checked', async () => {
  const both = Object.entries(FACTS).filter(([, f]) => f.both);
  assert.ok(both.length >= 5);
  for (const [key, fact] of both) {
    assert.equal(fact.source, 'asyncapi-3.0.0', key);
    assert.ok(has(await text('asyncapi-2.6.0'), fact.text), `2.6.0 ${key}`);
    assert.equal(factPage(key, 2), source('asyncapi-2.6.0').url);
    assert.equal(factPage(key, 3), source('asyncapi-3.0.0').url);
  }
  assert.equal(factPage('mqttClear', 2), source('mqtt-5.0').url);
});

test('facts: the protocol pages say what the findings rely on', async () => {
  assert.ok(has(await text('mqtt-5.0'), 'It is strongly recommended that Server implementations that offer TLS [RFC5246] should use TCP port 8883 (IANA service name: secure-mqtt).'));
  assert.ok(has(await text('rfc6455'), 'Connection confidentiality and integrity is provided by running the WebSocket Protocol over TLS (wss URIs).'));
  assert.ok(has(await text('rfc9110'), 'The "https" URI scheme is hereby defined'));
  assert.ok(has(await text('rfc7617'), 'The Basic authentication scheme is not a secure method of user authentication'));
  assert.ok(has(await text('rfc9110'), 'URIs are intended to be shared, not secured, even when they identify secure resources.'));
});

test('fields: the names that the reference scan treats as data or as maps of names are in the specification', async () => {
  const page = `${await text('asyncapi-3.0.0')}\n${await text('asyncapi-2.6.0')}`;
  const unknown = [...DATA_FIELDS, ...MAP_FIELDS].filter((k) => !word(page, k));
  // patternProperties and the binding maps come from JSON Schema and the Components Object tables; a name that no saved
  // page has is not allowed.
  assert.deepEqual(unknown, []);
  assert.ok(page.includes('Specification Extensions'));
  assert.ok(has(page, 'The field name MUST begin with x-'));
});

test('findings: every finding has a valid severity, an area of the list and facts of src/data.js, and the ids are written in kebab case', () => {
  for (const f of FINDINGS) {
    assert.ok(['error', 'warning', 'info'].includes(f.severity), f.id);
    assert.match(f.id, /^[a-z]+(?:-[a-z]+)+$/, f.id);
    assert.ok(f.what.length > 20, f.id);
    for (const k of f.facts) assert.ok(FACTS[k], `${f.id}: ${k}`);
  }
  assert.deepEqual(FINDINGS.filter((f) => f.severity === 'error').map((f) => f.id), ['ref-unresolved', 'ref-cycle', 'server-no-security', 'server-plain-protocol', 'security-scheme-undefined', 'operation-no-channel']);
});

test('src names no field of the specification outside src/data.js', async () => {
  const names = ['securitySchemes', 'correlationId', 'operationId', 'messageId', 'schemaFormat', 'protocol', 'userPassword', 'httpApiKey', 'components', 'publish', 'subscribe', 'oneOf', 'asyncapi'];
  for (const file of ['rules.js', 'check.js', 'doc.js', 'report.js', 'cli.js']) {
    const lines = (await readFile(new URL(`../src/${file}`, import.meta.url), 'utf8')).split(String.fromCharCode(10));
    const code = lines.filter((l) => !l.trim().startsWith('//')).join(String.fromCharCode(10));
    for (const n of names) assert.ok(!code.includes(`'${n}'`) && !code.includes(`"${n}"`), `${file} writes '${n}' itself`);
  }
});

test('docs: every sentence that the documents quote from a saved page is on a saved page', async () => {
  const pages = (await Promise.all(SOURCES.map((s) => text(s.id)))).map(flat).join(' ');
  let checked = 0;
  for (const file of ['docs/method.md', 'docs/rules-and-sources.md', 'docs/versions.md']) {
    const doc = quotes(await readFile(new URL(`../${file}`, import.meta.url), 'utf8'));
    for (const m of doc.matchAll(/"([^"\n]{40,400})"/g)) {
      if (m[1].includes('...')) continue;
      assert.ok(pages.includes(flat(m[1])), `${file}: ${m[1]}`);
      checked += 1;
    }
  }
  assert.ok(checked >= 10, `${checked} quotes checked`);
});

test('docs: docs/rules-and-sources.md names every saved page and every finding', async () => {
  const doc = await readFile(new URL('../docs/rules-and-sources.md', import.meta.url), 'utf8');
  for (const s of SOURCES) {
    assert.ok(doc.includes(s.file), s.file);
    assert.ok(doc.includes(s.url), s.url);
  }
  for (const f of FINDINGS) assert.ok(doc.includes(`\`${f.id}\``), f.id);
});
