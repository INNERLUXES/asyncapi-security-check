// Shared test helpers: documents built inline, and files written into a temporary folder that is removed after the
// test. Paths are built with resolve() from forward-slash names, so the same test runs on Linux, macOS and Windows.

import { mkdtemp, mkdir, writeFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, resolve } from 'node:path';
import { checkText, main } from '../src/index.js';

export async function withFiles(files, fn) {
  const dir = await mkdtemp(resolve(tmpdir(), 'asyncapi-security-check-'));
  try {
    for (const [rel, content] of Object.entries(files)) {
      await mkdir(dirname(resolve(dir, rel)), { recursive: true });
      await writeFile(resolve(dir, rel), content);
    }
    return await fn(dir);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
}

export const json = (value) => `${JSON.stringify(value, null, 2)}\n`;

// A payload schema with a type, a property and a required list.
export const goodPayload = () => ({ type: 'object', properties: { id: { type: 'string' } }, required: ['id'] });

// An AsyncAPI 3.0 document that has no finding: one server over TLS with a security scheme, a channel that an
// operation uses, and a message with a summary and a payload. Tests change one thing at a time.
export const base3 = (extra = {}) => ({
  asyncapi: '3.0.0',
  info: { title: 'Demo', version: '1.0.0' },
  servers: { prod: { host: 'broker.example.test:5671', protocol: 'amqps', description: 'The broker.', security: [{ $ref: '#/components/securitySchemes/login' }] } },
  channels: { things: { address: 'things', messages: { thing: { $ref: '#/components/messages/Thing' } } } },
  operations: { sendThing: { action: 'send', channel: { $ref: '#/channels/things' }, summary: 'Send a thing.' } },
  components: {
    securitySchemes: { login: { type: 'userPassword' } },
    messages: { Thing: { summary: 'A thing.', payload: goodPayload() } }
  },
  ...extra
});

// The same for AsyncAPI 2.6.
export const base2 = (extra = {}) => ({
  asyncapi: '2.6.0',
  info: { title: 'Demo', version: '1.0.0' },
  servers: { prod: { url: 'broker.example.test:5671', protocol: 'amqps', description: 'The broker.', security: [{ login: [] }] } },
  channels: { things: { subscribe: { operationId: 'onThing', summary: 'Things.', message: { $ref: '#/components/messages/Thing' } } } },
  components: {
    securitySchemes: { login: { type: 'userPassword' } },
    messages: { Thing: { messageId: 'thing', summary: 'A thing.', payload: goodPayload() } }
  },
  ...extra
});

// The same documents with these top-level fields replaced (base3 and base2 already do that), under the names the tests use.
export const with3 = (changes = {}) => base3(changes);
export const with2 = (changes = {}) => base2(changes);

// Checks a document given as an object (written as JSON) or as text.
export function check(doc, options = {}) {
  const text = typeof doc === 'string' ? doc : JSON.stringify(doc);
  return checkText(text, options.name ?? 'document.json', { ...options });
}

export const ids = (report) => report.findings.map((f) => f.id);
export const find = (report, id) => report.findings.filter((f) => f.id === id);
export const pointers = (report, id) => find(report, id).map((f) => f.pointer);

// Writes the files (objects are written as JSON, strings as they are) and runs the command line with these arguments
// (paths relative to the folder).
export async function run(files, args = [], limits) {
  const written = {};
  for (const [name, content] of Object.entries(files)) written[name] = typeof content === 'string' ? content : json(content);
  return withFiles(written, async (dir) => {
    let out = '';
    let err = '';
    const code = await main(args, { out: (t) => { out += t; }, err: (t) => { err += t; } }, limits, dir);
    return { code, out, err };
  });
}

// Runs the command line with exactly these arguments.
export async function cli(argv) {
  let out = '';
  let err = '';
  const code = await main(argv, { out: (t) => { out += t; }, err: (t) => { err += t; } });
  return { code, out, err };
}
