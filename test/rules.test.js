import { test } from 'node:test';
import assert from 'node:assert/strict';
import { DOC_LIMITS, FACTS, FINDINGS, LIMITS, PROTOCOLS, hostOf, isLocalHost, plainProtocol } from '../src/index.js';
import { base2, base3, check, find, goodPayload, ids, pointers, with2, with3 } from './helpers.js';

const server3 = (extra) => ({ prod: { host: 'broker.example.test:5671', protocol: 'amqps', description: 'The broker.', security: [{ $ref: '#/components/securitySchemes/login' }], ...extra } });
const server2 = (extra) => ({ prod: { url: 'broker.example.test:5671', protocol: 'amqps', description: 'The broker.', security: [{ login: [] }], ...extra } });
const messages = (m) => ({ messages: { ...base3().components.messages, ...m } });

test('a clean 3.0 document and a clean 2.6 document have no finding, and the gate passes at every level', () => {
  for (const doc of [base3(), base2()]) {
    const r = check(doc, { failOn: 'warning' });
    assert.deepEqual(ids(r), []);
    assert.equal(r.gate.pass, true);
    assert.deepEqual(r.counts, { error: 0, warning: 0, info: 0 });
  }
});

test('server-no-security: a server without security is an error in 3.0, and a server with a scheme is not', () => {
  const r = check(with3({ servers: { prod: { host: 'broker.example.test:5671', protocol: 'amqps', description: 'x' } } }));
  assert.deepEqual(pointers(r, 'server-no-security'), ['#/servers/prod']);
  assert.equal(find(r, 'server-no-security')[0].severity, 'error');
  assert.equal(r.gate.pass, false);
  assert.deepEqual(ids(check(base3())), []);
});

test('server-no-security: an empty list, and an inline scheme object, in 3.0', () => {
  assert.deepEqual(pointers(check(with3({ servers: server3({ security: [] }) })), 'server-no-security'), ['#/servers/prod/security']);
  assert.deepEqual(ids(check(with3({ servers: server3({ security: [{ type: 'userPassword' }] }) }))), []);
  assert.deepEqual(pointers(check(with3({ servers: server3({ security: [{ description: 'no type' }] }) })), 'server-no-security'), ['#/servers/prod/security']);
});

test('server-no-security: in 2.6 a requirement object must name a scheme, and {} names none', () => {
  assert.deepEqual(pointers(check(with2({ servers: server2({ security: [{}] }) })), 'server-no-security'), ['#/servers/prod/security']);
  assert.deepEqual(pointers(check(with2({ servers: { prod: { url: 'broker.example.test:5671', protocol: 'amqps', description: 'x' } } })), 'server-no-security'), ['#/servers/prod']);
  assert.deepEqual(ids(check(with2({ servers: server2({ security: [{ login: [] }] }) }))), []);
});

test('server-plain-protocol: every plain protocol of the table is an error that quotes the specification list, in 3.0 and in 2.6', () => {
  for (const row of PROTOCOLS) {
    const r3 = check(with3({ servers: server3({ protocol: row.plain }) }));
    const f = find(r3, 'server-plain-protocol');
    assert.equal(f.length, 1, row.plain);
    assert.equal(f[0].severity, 'error');
    assert.equal(f[0].pointer, '#/servers/prod/protocol');
    assert.ok(f[0].basis.some((b) => b.text === FACTS.protocolList.text), row.plain);
    assert.ok(f[0].message.includes(row.secure), row.plain);
    assert.equal(find(check(with2({ servers: server2({ protocol: row.plain }) })), 'server-plain-protocol').length, 1, `2.6 ${row.plain}`);
  }
});

test('server-plain-protocol: each secure variant, in any case, passes; protocols with no listed pair are not judged', () => {
  for (const row of PROTOCOLS) for (const secure of row.accepted) assert.deepEqual(ids(check(with3({ servers: server3({ protocol: secure.toUpperCase() }) }))), [], secure);
  for (const other of ['jms', 'solace', 'ibmmq', 'pulsar', 'googlepubsub', 'mercure', 'anypointmq', 'nats', 'redis']) assert.deepEqual(ids(check(with3({ servers: server3({ protocol: other }) }))), [], other);
  assert.equal(find(check(with3({ servers: server3({ protocol: ' AMQP ' }) })), 'server-plain-protocol').length, 1);
});

test('server-plain-protocol: the protocol that explains the risk is quoted with its own page', () => {
  const pageOf = (protocol) => find(check(with3({ servers: server3({ protocol }) })), 'server-plain-protocol')[0].basis.map((b) => b.source.split('/')[2]);
  assert.deepEqual(pageOf('mqtt'), ['raw.githubusercontent.com', 'docs.oasis-open.org']);
  assert.deepEqual(pageOf('ws'), ['raw.githubusercontent.com', 'www.rfc-editor.org']);
  assert.deepEqual(pageOf('http'), ['raw.githubusercontent.com', 'www.rfc-editor.org']);
  assert.deepEqual(pageOf('amqp'), ['raw.githubusercontent.com']);
});

test('server-plain-protocol: a plain protocol on a local host is not reported, and a name that only contains localhost is', () => {
  for (const host of ['localhost:5672', 'LOCALHOST', 'dev.localhost', '127.0.0.1:1883', '[::1]:1883']) {
    const r = check(with3({ servers: server3({ host, protocol: 'amqp' }) }));
    assert.deepEqual(ids(r), [], host);
    assert.ok(r.notes.some((n) => /plain protocol on a local host was not reported/.test(n)), host);
  }
  for (const host of ['localhost.example.test', 'my-localhost.example.test', '127.0.0.1.example.test']) assert.equal(find(check(with3({ servers: server3({ host, protocol: 'amqp' }) })), 'server-plain-protocol').length, 1, host);
  assert.equal(find(check(with2({ servers: server2({ url: 'amqp://user@localhost:5672', protocol: 'amqp' }) })), 'server-plain-protocol').length, 0);
});

test('hostOf, isLocalHost and plainProtocol read the usual forms', () => {
  assert.equal(hostOf('amqp://user:pw@Broker.Example.test:5672/vhost'), 'broker.example.test');
  assert.equal(hostOf('broker.example.test:5671'), 'broker.example.test');
  assert.equal(hostOf('[::1]:5672'), '[::1]');
  assert.equal(hostOf('{env}.example.test'), '{env}.example.test');
  assert.equal(hostOf(42), '');
  assert.equal(isLocalHost('127.5.5.5'), true);
  assert.equal(isLocalHost('128.0.0.1'), false);
  assert.equal(plainProtocol('Kafka').secure, 'kafka-secure');
  assert.equal(plainProtocol('kafka-secure'), null);
  assert.equal(plainProtocol(undefined), null);
});

test('server-protocol-missing: a server without a protocol is a warning, and the version decides which sentence is quoted', () => {
  const r3 = check(with3({ servers: { prod: { host: 'broker.example.test', security: [{ type: 'userPassword' }] } } }));
  assert.deepEqual(ids(r3), ['server-protocol-missing']);
  assert.equal(r3.findings[0].basis[0].text, FACTS.protocolV3.text);
  const r2 = check(with2({ servers: { prod: { url: 'broker.example.test', security: [{ login: [] }] } } }));
  assert.equal(r2.findings[0].basis[0].text, FACTS.protocolList.text);
  assert.deepEqual(ids(check(with3({ servers: server3({ protocol: '  ' }) }))), ['server-protocol-missing']);
});

test('apikey-in-query: an httpApiKey in the query is a warning that quotes the specification and the HTTP page; header, cookie and user are not', () => {
  const doc = (scheme) => with3({ components: { securitySchemes: { login: { type: 'userPassword' }, key: scheme }, messages: base3().components.messages } });
  const r = check(doc({ type: 'httpApiKey', name: 'token', in: 'query' }));
  assert.deepEqual(pointers(r, 'apikey-in-query'), ['#/components/securitySchemes/key/in']);
  assert.equal(find(r, 'apikey-in-query')[0].severity, 'warning');
  assert.equal(find(r, 'apikey-in-query')[0].basis.length, 2);
  for (const where of ['header', 'cookie']) assert.deepEqual(ids(check(doc({ type: 'httpApiKey', name: 'token', in: where }))), [], where);
  assert.deepEqual(ids(check(doc({ type: 'apiKey', in: 'user' }))), []);
});

test('apikey-in-query: an inline scheme object in a server security list is read too, and 2.6 is read the same way', () => {
  const r = check(with3({ servers: server3({ security: [{ type: 'httpApiKey', name: 'k', in: 'query' }] }) }));
  assert.deepEqual(pointers(r, 'apikey-in-query'), ['#/servers/prod/security/0/in']);
  const r2 = check(with2({ components: { securitySchemes: { login: { type: 'httpApiKey', name: 'k', in: 'query' } }, messages: base2().components.messages } }));
  assert.deepEqual(pointers(r2, 'apikey-in-query'), ['#/components/securitySchemes/login/in']);
});

test('credentials-over-plain-transport: a credential scheme on a plain server is a warning, with the page that fits the scheme and the protocol', () => {
  const doc = (scheme, protocol = 'amqp') => with3({ servers: server3({ protocol }), components: { securitySchemes: { login: scheme }, messages: base3().components.messages } });
  const r = check(doc({ type: 'userPassword' }));
  assert.deepEqual(pointers(r, 'credentials-over-plain-transport'), ['#/servers/prod/security/0']);
  assert.equal(find(r, 'credentials-over-plain-transport')[0].severity, 'warning');
  const basic = find(check(doc({ type: 'http', scheme: 'basic' }, 'http')), 'credentials-over-plain-transport')[0];
  assert.deepEqual(basic.basis.map((b) => b.text), [FACTS.basicClearText.text]);
  assert.deepEqual(find(check(doc({ type: 'httpApiKey', name: 'k', in: 'header' }, 'http')), 'credentials-over-plain-transport')[0].basis.map((b) => b.text), [FACTS.httpCredentials.text]);
  assert.deepEqual(find(check(doc({ type: 'plain' }, 'mqtt')), 'credentials-over-plain-transport')[0].basis.map((b) => b.text), [FACTS.mqttClearText.text]);
  for (const type of ['userPassword', 'plain', 'apiKey', 'httpApiKey', 'http']) assert.equal(find(check(doc({ type, in: 'user', name: 'k', scheme: 'bearer' })), 'credentials-over-plain-transport').length, 1, type);
});

test('credentials-over-plain-transport: no finding over TLS, on a local host, or for a scheme that is not a credential', () => {
  const doc = (scheme, protocol, host = 'broker.example.test') => with3({ servers: server3({ protocol, host }), components: { securitySchemes: { login: scheme }, messages: base3().components.messages } });
  assert.equal(find(check(doc({ type: 'userPassword' }, 'amqps')), 'credentials-over-plain-transport').length, 0);
  assert.equal(find(check(doc({ type: 'userPassword' }, 'amqp', 'localhost')), 'credentials-over-plain-transport').length, 0);
  for (const type of ['oauth2', 'X509', 'scramSha256', 'gssapi', 'openIdConnect']) assert.equal(find(check(doc({ type }, 'amqp')), 'credentials-over-plain-transport').length, 0, type);
});

test('credentials-over-plain-transport: a scheme on an operation counts for the servers of its channel, and once for each pair', () => {
  const channelOnPlain = with3({
    servers: { prod: server3().prod, edge: server3({ host: 'edge.example.test', protocol: 'ws', security: [{ type: 'X509' }] }).prod },
    channels: { things: { address: 'things', servers: [{ $ref: '#/servers/edge' }], messages: { thing: { $ref: '#/components/messages/Thing' } } } },
    operations: { sendThing: { action: 'send', channel: { $ref: '#/channels/things' }, summary: 'x', security: [{ $ref: '#/components/securitySchemes/login' }] } }
  });
  const r = check(channelOnPlain);
  assert.deepEqual(pointers(r, 'credentials-over-plain-transport'), ['#/operations/sendThing/security/0']);
  assert.deepEqual(find(r, 'credentials-over-plain-transport')[0].subject, 'login');
  const secureChannel = structuredClone(channelOnPlain);
  secureChannel.channels.things.servers = [{ $ref: '#/servers/prod' }];
  assert.equal(find(check(secureChannel), 'credentials-over-plain-transport').length, 0);
});

test('message-no-payload: a message with no payload is a warning, and a message with one is not', () => {
  const r = check(with3({ components: { ...base3().components, ...messages({ Thing: { summary: 'x' } }) } }));
  assert.deepEqual(pointers(r, 'message-no-payload'), ['#/components/messages/Thing']);
  assert.equal(find(r, 'message-no-payload')[0].severity, 'warning');
  assert.deepEqual(ids(check(base3())), []);
  const r2 = check(with2({ components: { securitySchemes: base2().components.securitySchemes, messages: { Thing: { messageId: 'thing', summary: 'x' } } } }));
  assert.deepEqual(pointers(r2, 'message-no-payload'), ['#/components/messages/Thing']);
  assert.deepEqual(find(r2, 'message-no-payload')[0].basis.map((b) => b.text), [FACTS.payloadV2.text]);
});

test('message-no-payload: the message is named by its reference, and an inline message in a channel is read at its own place', () => {
  const r = check(with3({ channels: { things: { address: 'things', messages: { loose: { summary: 'Inline.' } } } }, operations: {} }));
  assert.deepEqual(pointers(r, 'message-no-payload'), ['#/channels/things/messages/loose']);
  assert.equal(find(r, 'message-no-payload')[0].subject, 'loose');
});

test('payload-no-type and payload-no-required are info findings, and a typed payload with a required list has neither', () => {
  const payload = (p) => check(with3({ components: { ...base3().components, ...messages({ Thing: { summary: 'x', payload: p } }) } }));
  assert.deepEqual(ids(payload({})), ['payload-no-type']);
  assert.deepEqual(ids(payload({ description: 'free text' })), ['payload-no-type']);
  assert.deepEqual(ids(payload(true)), ['payload-no-type']);
  assert.deepEqual(ids(payload({ type: 'object', properties: { a: { type: 'string' } } })), ['payload-no-required']);
  assert.deepEqual(ids(payload({ type: 'object', properties: { a: { type: 'string' } }, required: [] })), ['payload-no-required']);
  assert.deepEqual(ids(payload(goodPayload())), []);
  assert.deepEqual(ids(payload({ type: 'object' })), []);
  assert.deepEqual(ids(payload({ type: ['object', 'null'], properties: { a: { type: 'string' } }, required: ['a'] })), []);
  assert.equal(find(payload({}), 'payload-no-type')[0].severity, 'info');
  assert.equal(payload({}).gate.pass, true);
});

test('a payload that is composed, an enum or a const, is not called untyped, and a reference to a schema is followed', () => {
  const payload = (p, extra = {}) => check(with3({ components: { ...base3().components, ...messages({ Thing: { summary: 'x', payload: p } }), schemas: { Body: goodPayload() }, ...extra } }));
  assert.deepEqual(ids(payload({ oneOf: [{ type: 'string' }, { type: 'number' }] })), []);
  assert.deepEqual(ids(payload({ enum: ['a', 'b'] })), []);
  assert.deepEqual(ids(payload({ const: 'a' })), []);
  assert.deepEqual(ids(payload({ $ref: '#/components/schemas/Body' })), []);
  const loose = payload({ $ref: '#/components/schemas/Body' }, { schemas: { Body: { type: 'object', properties: { a: { type: 'string' } } } } });
  assert.deepEqual(pointers(loose, 'payload-no-required'), ['#/components/schemas/Body']);
});

test('payload-format-not-read: a payload in another schema format is reported as not read, never as passed (3.0 multi-format object and 2.6 schemaFormat)', () => {
  const avro = check(with3({ components: { ...base3().components, ...messages({ Thing: { summary: 'x', payload: { schemaFormat: 'application/vnd.apache.avro;version=1.9.0', schema: { type: 'record', name: 'Thing', fields: [] } } } }) } }));
  assert.deepEqual(ids(avro), ['payload-format-not-read']);
  const native = check(with3({ components: { ...base3().components, ...messages({ Thing: { summary: 'x', payload: { schemaFormat: 'application/vnd.aai.asyncapi+json;version=3.0.0', schema: goodPayload() } } }) } }));
  assert.deepEqual(ids(native), []);
  const v2 = check(with2({ components: { securitySchemes: base2().components.securitySchemes, messages: { Thing: { messageId: 't', summary: 'x', schemaFormat: 'application/vnd.apache.avro;version=1.9.0', payload: { type: 'record' } } } } }));
  assert.deepEqual(ids(v2), ['payload-format-not-read']);
});

test('operation-no-channel: a 3.0 operation with no channel, or with a channel written inline, is an error; a reference is not', () => {
  const op = (o) => check(with3({ operations: { sendThing: { action: 'send', summary: 'x', ...o } } }));
  assert.deepEqual(pointers(op({}), 'operation-no-channel'), ['#/operations/sendThing']);
  assert.deepEqual(pointers(op({ channel: { address: 'things' } }), 'operation-no-channel'), ['#/operations/sendThing/channel']);
  assert.deepEqual(pointers(op({ channel: 'things' }), 'operation-no-channel'), ['#/operations/sendThing/channel']);
  assert.equal(find(op({}), 'operation-no-channel')[0].severity, 'error');
  assert.deepEqual(ids(op({ channel: { $ref: '#/channels/things' } })), []);
});

test('operation-no-channel: a channel reference that is remote or broken is a reference finding, not a missing channel', () => {
  assert.deepEqual(ids(check(with3({ operations: { sendThing: { action: 'send', summary: 'x', channel: { $ref: 'other.yaml#/channels/things' } } } }))).filter((i) => i !== 'channel-unused'), ['ref-remote']);
  assert.deepEqual(ids(check(with3({ operations: { sendThing: { action: 'send', summary: 'x', channel: { $ref: '#/channels/nothing' } } } }))).filter((i) => i !== 'channel-unused'), ['ref-unresolved']);
});

test('channel-unused: a 3.0 channel that no operation uses is a warning; a channel used by an operation or by a reply is not', () => {
  const doc = with3({ channels: { things: base3().channels.things, spare: { address: 'spare', messages: {} } } });
  assert.deepEqual(pointers(check(doc), 'channel-unused'), ['#/channels/spare']);
  assert.equal(find(check(doc), 'channel-unused')[0].severity, 'warning');
  const reply = with3({
    channels: { things: base3().channels.things, answers: { address: 'answers', messages: { a: { $ref: '#/components/messages/Thing' } } } },
    operations: { sendThing: { action: 'send', summary: 'x', channel: { $ref: '#/channels/things' }, reply: { channel: { $ref: '#/channels/answers' } } } }
  });
  assert.equal(find(check(reply), 'channel-unused').length, 0);
});

test('channel-unused: a root channel that is a reference to a component is used when an operation names either place', () => {
  const doc = (target) => with3({
    channels: { things: { $ref: '#/components/channels/Things' } },
    operations: { sendThing: { action: 'send', summary: 'x', channel: { $ref: target } } },
    components: { ...base3().components, channels: { Things: { address: 'things', messages: { thing: { $ref: '#/components/messages/Thing' } } } } }
  });
  assert.equal(find(check(doc('#/channels/things')), 'channel-unused').length, 0);
  assert.equal(find(check(doc('#/components/channels/Things')), 'channel-unused').length, 0);
});

test('channel-unused: without any operation every channel is unused, and a note says so', () => {
  const r = check(with3({ operations: {} }));
  assert.deepEqual(pointers(r, 'channel-unused'), ['#/channels/things']);
  assert.ok(r.notes.some((n) => /No operation was found/.test(n)));
});

test('channel-unused in 2.6: a channel with neither publish nor subscribe is a warning', () => {
  const r = check(with2({ channels: { things: base2().channels.things, 'orders/spare': { description: 'Nothing here.' } } }));
  assert.deepEqual(pointers(r, 'channel-unused'), ['#/channels/orders~1spare']);
  assert.equal(find(check(base2()), 'channel-unused').length, 0);
});

const withReply = (requestExtra = {}, replyExtra = {}, extraOps = {}) => with3({
  channels: {
    ask: { address: 'ask', messages: { question: { $ref: '#/components/messages/Question' } } },
    answer: { address: 'answer', messages: { reply: { $ref: '#/components/messages/Answer' } } }
  },
  operations: {
    askThing: { action: 'send', summary: 'x', channel: { $ref: '#/channels/ask' }, reply: { channel: { $ref: '#/channels/answer' } } },
    ...extraOps
  },
  components: {
    securitySchemes: base3().components.securitySchemes,
    correlationIds: { byHeader: { location: '$message.header#/correlationId' } },
    messages: {
      Question: { summary: 'q', payload: goodPayload(), ...requestExtra },
      Answer: { summary: 'a', payload: goodPayload(), ...replyExtra }
    }
  }
});

test('reply-no-correlation-id: the request and the reply message of a request/reply operation are each a warning without a correlationId', () => {
  const r = check(withReply());
  assert.deepEqual(pointers(r, 'reply-no-correlation-id'), ['#/components/messages/Answer', '#/components/messages/Question']);
  assert.equal(find(r, 'reply-no-correlation-id')[0].severity, 'warning');
  assert.match(find(r, 'reply-no-correlation-id').map((f) => f.message).join(' '), /request message.*reply message|reply message.*request message/);
  assert.deepEqual(ids(check(withReply({ correlationId: { location: '$message.header#/correlationId' } }, { correlationId: { $ref: '#/components/correlationIds/byHeader' } }))), []);
});

test('reply-no-correlation-id: only the message that lacks one is reported, and a correlationId from a trait counts', () => {
  const r = check(withReply({ correlationId: { location: '$message.header#/correlationId' } }));
  assert.deepEqual(pointers(r, 'reply-no-correlation-id'), ['#/components/messages/Answer']);
  const traited = withReply({ traits: [{ $ref: '#/components/messageTraits/Corr' }] }, { traits: [{ correlationId: { location: '$message.header#/id' } }] });
  traited.components.messageTraits = { Corr: { correlationId: { location: '$message.header#/id' } } };
  assert.equal(find(check(traited), 'reply-no-correlation-id').length, 0);
});

test('reply-no-correlation-id: an operation without a reply is not checked, and the messages list narrows the request messages', () => {
  assert.equal(find(check(with3({ components: { ...base3().components, ...messages({ Thing: { summary: 'x', payload: goodPayload() } }) } })), 'reply-no-correlation-id').length, 0);
  const r = check(with3({
    channels: {
      ask: { address: 'ask', messages: { question: { $ref: '#/components/messages/Question' }, other: { $ref: '#/components/messages/Other' } } },
      answer: { address: 'answer', messages: { reply: { $ref: '#/components/messages/Answer' } } }
    },
    operations: { askThing: { action: 'send', summary: 'x', channel: { $ref: '#/channels/ask' }, messages: [{ $ref: '#/channels/ask/messages/question' }], reply: { channel: { $ref: '#/channels/answer' }, messages: [{ $ref: '#/channels/answer/messages/reply' }] } } },
    components: { securitySchemes: base3().components.securitySchemes, messages: { Question: { summary: 'q', payload: goodPayload() }, Other: { summary: 'o', payload: goodPayload() }, Answer: { summary: 'a', payload: goodPayload() } } }
  }));
  assert.deepEqual(pointers(r, 'reply-no-correlation-id'), ['#/components/messages/Answer', '#/components/messages/Question']);
});

test('reply-no-correlation-id: a message shared by two operations is reported once', () => {
  const r = check(withReply({}, {}, { askAgain: { action: 'send', summary: 'x', channel: { $ref: '#/channels/ask' }, reply: { channel: { $ref: '#/channels/answer' } } } }));
  assert.equal(find(r, 'reply-no-correlation-id').length, 2);
});

test('2.6 has no reply object: the check is not run and a note says so', () => {
  const r = check(base2());
  assert.ok(r.notes.includes('AsyncAPI 2.6 has no reply object, so the request/reply correlation check was not run'));
  assert.equal(check(base3()).notes.length, 0);
});

test('documentation findings are info: a message or an operation with neither a description nor a summary', () => {
  const r = check(with3({ components: { ...base3().components, ...messages({ Thing: { payload: goodPayload() } }) }, operations: { sendThing: { action: 'send', channel: { $ref: '#/channels/things' } } } }));
  assert.deepEqual(ids(r), ['message-no-description', 'operation-no-description']);
  for (const f of r.findings) assert.equal(f.severity, 'info');
  assert.equal(r.gate.pass, true);
  const described = check(with3({ components: { ...base3().components, ...messages({ Thing: { description: 'x', payload: goodPayload() } }) }, operations: { sendThing: { action: 'send', channel: { $ref: '#/channels/things' }, description: 'y' } } }));
  assert.deepEqual(ids(described), []);
  const blank = check(with3({ components: { ...base3().components, ...messages({ Thing: { summary: '   ', payload: goodPayload() } }) } }));
  assert.deepEqual(ids(blank), ['message-no-description']);
});

test('a description that comes from a trait counts for a message and an operation', () => {
  const r = check(with3({
    components: { ...base3().components, messageTraits: { Described: { description: 'x' } }, ...messages({ Thing: { traits: [{ $ref: '#/components/messageTraits/Described' }], payload: goodPayload() } }) },
    operations: { sendThing: { action: 'send', channel: { $ref: '#/channels/things' }, traits: [{ summary: 'inline trait' }] } }
  }));
  assert.deepEqual(ids(r), []);
});

test('2.6 documentation findings: operation-no-id and message-no-id, and the ids that are present are not reported', () => {
  const r = check(with2({
    channels: { things: { subscribe: { summary: 'x', message: { $ref: '#/components/messages/Thing' } } } },
    components: { securitySchemes: base2().components.securitySchemes, messages: { Thing: { summary: 'x', payload: goodPayload() } } }
  }));
  assert.deepEqual(ids(r), ['operation-no-id', 'message-no-id']);
  assert.deepEqual(ids(check(base2())), []);
});

test('2.6 messages: an inline message and the messages of a oneOf are read, with a name from the place', () => {
  const r = check(with2({
    channels: {
      a: { publish: { operationId: 'a', summary: 'a', message: { messageId: 'inlineOne', summary: 'x' } } },
      b: { subscribe: { operationId: 'b', summary: 'b', message: { oneOf: [{ messageId: 'one', summary: 'x', payload: goodPayload() }, { summary: 'y' }] } } }
    }
  }));
  const noPayload = find(r, 'message-no-payload');
  assert.deepEqual(noPayload.map((f) => f.subject).sort(), ['b subscribe message 2', 'inlineOne']);
  assert.deepEqual(noPayload.map((f) => f.pointer).sort(), ['#/channels/a/publish/message', '#/channels/b/subscribe/message/oneOf/1']);
});

test('security-scheme-undefined: a 2.6 requirement that names a scheme nobody defined is an error; 3.0 reports a broken reference instead', () => {
  const r = check(with2({ servers: server2({ security: [{ login: [] }, { ghost: [] }] }) }));
  assert.deepEqual(pointers(r, 'security-scheme-undefined'), ['#/servers/prod/security/1/ghost']);
  assert.equal(find(r, 'security-scheme-undefined')[0].severity, 'error');
  const op = check(with2({ channels: { things: { subscribe: { operationId: 'o', summary: 'x', security: [{ ghost: [] }], message: { $ref: '#/components/messages/Thing' } } } } }));
  assert.deepEqual(pointers(op, 'security-scheme-undefined'), ['#/channels/things/subscribe/security/0/ghost']);
  const v3 = check(with3({ servers: server3({ security: [{ $ref: '#/components/securitySchemes/ghost' }] }) }));
  assert.deepEqual(ids(v3), ['ref-unresolved']);
});

test('references: a broken local $ref is an error, with the pointer of the $ref and its line', () => {
  const r = check(with3({ channels: { things: { address: 'things', messages: { thing: { $ref: '#/components/messages/Nothing' } } } } }));
  assert.deepEqual(pointers(r, 'ref-unresolved'), ['#/channels/things/messages/thing/$ref']);
  assert.equal(find(r, 'ref-unresolved')[0].severity, 'error');
  assert.ok(find(r, 'ref-unresolved')[0].line >= 1);
  assert.equal(r.gate.pass, false);
});

test('references: a $ref chain that comes back to itself is an error, and so is a reference to itself', () => {
  const r = check(with3({ components: { ...base3().components, schemas: { A: { $ref: '#/components/schemas/B' }, B: { $ref: '#/components/schemas/A' }, Self: { $ref: '#/components/schemas/Self' } } } }));
  assert.deepEqual(pointers(r, 'ref-cycle'), ['#/components/schemas/A/$ref', '#/components/schemas/B/$ref', '#/components/schemas/Self/$ref']);
  assert.equal(find(r, 'ref-cycle')[0].severity, 'error');
});

test('references: a $ref to another file or an address is info, is not followed, and its text is never printed', () => {
  const secret = 'https://token-marker.example.test/schema.json';
  const r = check(with3({ components: { ...base3().components, schemas: { Remote: { $ref: secret }, File: { $ref: 'common.yaml#/Order' } } } }));
  assert.deepEqual(pointers(r, 'ref-remote'), ['#/components/schemas/File/$ref', '#/components/schemas/Remote/$ref']);
  assert.equal(find(r, 'ref-remote')[0].severity, 'info');
  assert.equal(r.gate.pass, true);
  assert.ok(!JSON.stringify(r).includes('token-marker'));
  assert.ok(!JSON.stringify(r).includes('common.yaml'));
});

test('references: a $ref inside an example, a default, an enum, a const or an extension is data and is not a reference', () => {
  const data = { $ref: '#/nowhere' };
  const r = check(with3({
    components: {
      ...base3().components,
      ...messages({ Thing: { summary: 'x', payload: { type: 'object', properties: { a: { type: 'string', default: data, examples: [data] }, b: { const: data } }, required: ['a'] }, examples: [{ payload: data }], 'x-note': data } })
    }
  }));
  assert.deepEqual(ids(r).filter((i) => i.startsWith('ref-')), []);
  const named = check(with3({ components: { ...base3().components, schemas: { Holder: { type: 'object', properties: { default: { $ref: '#/nowhere' } } } } } }));
  assert.deepEqual(pointers(named, 'ref-unresolved'), ['#/components/schemas/Holder/properties/default/$ref']);
});

test('no value of the document is copied into a report: examples, defaults, descriptions and host names stay out, in every format', async () => {
  const { toText, toMarkdown, toJson, toCsv } = await import('../src/index.js');
  const doc = with3({
    servers: { prod: { host: 'host-marker.example.test:5672', protocol: 'amqp', description: 'description-marker', variables: { port: { default: 'default-marker', enum: ['enum-marker'] } } } },
    components: { ...base3().components, ...messages({ Thing: { summary: 'x', payload: { type: 'object', properties: { a: { type: 'string', default: 'payload-default-marker' } }, required: ['a'] }, examples: [{ payload: { a: 'example-marker' } }] } }) }
  });
  const r = check(doc);
  assert.ok(find(r, 'server-plain-protocol').length === 1);
  for (const render of [toText, toMarkdown, toJson, toCsv]) {
    const out = render(r);
    for (const marker of ['host-marker', 'description-marker', 'default-marker', 'enum-marker', 'example-marker']) assert.ok(!out.includes(marker), `${render.name}: ${marker}`);
  }
});

test('the check ids are unique, each has a fact to quote, and an error finding makes the gate fail while info never does', () => {
  assert.equal(new Set(FINDINGS.map((f) => f.id)).size, FINDINGS.length);
  for (const f of FINDINGS) assert.ok(f.facts.length > 0 && f.facts.every((k) => FACTS[k]), f.id);
  const infoOnly = check(with3({ components: { ...base3().components, ...messages({ Thing: { payload: {} } }) } }), { failOn: 'warning' });
  assert.ok(infoOnly.counts.info >= 1);
  assert.equal(infoOnly.gate.pass, true);
  assert.equal(check(with3({ servers: server3({ protocol: 'ws' }) }), { failOn: 'warning' }).gate.pass, false);
});

test('--fail-on: a warning fails the gate only at the warning level, and the reason counts what failed', () => {
  const doc = with3({ components: { ...base3().components, ...messages({ Thing: { summary: 'x' } }) } });
  assert.equal(check(doc).gate.pass, true);
  const strict = check(doc, { failOn: 'warning' });
  assert.equal(strict.gate.pass, false);
  assert.equal(strict.gate.reason, '1 warning');
  const both = check(with3({ servers: server3({ protocol: 'ws' }), components: { ...base3().components, ...messages({ Thing: { summary: 'x' } }) } }), { failOn: 'warning' });
  assert.equal(both.gate.reason, '1 error, 2 warnings');
  assert.deepEqual(ids(both), ['server-plain-protocol', 'credentials-over-plain-transport', 'message-no-payload']);
});

test('findings are sorted by severity, then area, then check, then pointer, and the same document always gives the same report', () => {
  const doc = with3({ servers: server3({ protocol: 'ws' }), channels: { zeta: { address: 'z', messages: {} }, alpha: { address: 'a', messages: {} }, things: base3().channels.things } });
  const r = check(doc);
  const ranks = r.findings.map((f) => ['error', 'warning', 'info'].indexOf(f.severity));
  assert.deepEqual(ranks, [...ranks].sort((a, b) => a - b));
  assert.deepEqual(pointers(r, 'channel-unused'), ['#/channels/alpha', '#/channels/zeta']);
  assert.deepEqual(JSON.parse(JSON.stringify(check(doc))), JSON.parse(JSON.stringify(r)));
});

test('a name with control or direction characters is cleaned in the finding', () => {
  const evil = `x${String.fromCharCode(27)}[31m${String.fromCharCode(0x202e)}y`;
  const r = check(with3({ servers: { [evil]: { host: 'b.example.test', protocol: 'ws', description: 'x', security: [{ type: 'userPassword' }] } } }));
  const f = find(r, 'server-plain-protocol')[0];
  assert.equal([...`${f.message}${f.subject}`].filter((c) => c.charCodeAt(0) < 32 || c.charCodeAt(0) === 0x202e).length, 0);
  assert.ok(f.subject.includes('x [31m'));
});

test('a finding that is listed too often is cut at the limit, and the rest is counted and named in a note', () => {
  const channels = {};
  for (let i = 0; i < 230; i += 1) channels[`c${i}`] = { address: `c${i}`, messages: {} };
  const r = check(with3({ channels, operations: {} }));
  assert.equal(find(r, 'channel-unused').length, DOC_LIMITS.maxListedPerFinding);
  assert.equal(r.counts.warning, 230);
  assert.ok(r.notes.some((n) => /30 more findings of channel-unused are counted but not listed/.test(n)));
});

test('limits: more operations, channels, servers or messages than the limit is refused with a clear message', () => {
  const small = { ...LIMITS, maxOperations: 3, maxChannels: 3, maxServers: 2, maxMessages: 3 };
  const many = (n, make) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`k${i}`, make(i)]));
  assert.throws(() => check(with3({ operations: many(4, () => ({ action: 'send', channel: { $ref: '#/channels/things' } })) }), { limits: small }), /more than 3 operations/);
  assert.throws(() => check(with3({ channels: many(4, () => ({ messages: {} })) }), { limits: small }), /more than 3 channels/);
  assert.throws(() => check(with3({ servers: many(3, () => ({ host: 'a.example.test', protocol: 'amqps' })) }), { limits: small }), /more than 2 servers/);
  assert.throws(() => check(with3({ components: { ...base3().components, messages: many(4, () => ({ payload: goodPayload() })) } }), { limits: small }), /more than 3 messages/);
});

test('a document with nothing to check says so in a note instead of passing quietly', () => {
  const r = check({ asyncapi: '3.0.0', info: { title: 'Empty', version: '1' } });
  assert.deepEqual(ids(r), []);
  assert.ok(r.notes.some((n) => /nothing to check/.test(n)));
});
