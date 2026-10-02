// Runs the README examples, checks that they report what the README shows, and writes the reports of the first example
// to examples/output. CI runs it and then fails if those files changed, so the example output in the repository is
// always the real output.

import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { main } from '../src/index.js';

const root = resolve(fileURLToPath(import.meta.url), '..', '..');

// Runs the tool on files of the repository; the path shown in the report is relative to the root of the repository.
async function run(argv) {
  let out = '';
  const code = await main(argv, { out: (t) => { out += t; }, err: (t) => process.stderr.write(t) }, undefined, root);
  return { code, out };
}

const problems = [];
function expect(name, result, code, expected, unwanted) {
  const missing = expected.filter((e) => !result.out.includes(e));
  const wrong = unwanted.filter((e) => result.out.includes(e));
  if (result.code !== code || missing.length || wrong.length) {
    problems.push(`${name}: unexpected report (exit code ${result.code}, expected ${code}; missing: ${missing.join(' / ') || 'none'}; should not appear: ${wrong.join(' / ') || 'none'})`);
  }
}

const brokenArgs = ['examples/orders-events.yaml', '--fail-on', 'warning'];
const broken = await run(brokenArgs);
process.stdout.write(broken.out);
expect('orders events', broken, 1, [
  'AsyncAPI 3.0.0, yaml, "Orders Events": 3 servers, 5 channels, 3 operations, 4 messages, 2 security schemes',
  'findings: 2 error, 5 warning, 2 info',
  'ERROR    server-no-security  #/servers/broker',
  'ERROR    server-plain-protocol  #/servers/broker/protocol',
  'WARNING  apikey-in-query  #/components/securitySchemes/feedKey/in',
  'WARNING  message-no-payload  #/components/messages/OrderCancelled',
  'WARNING  reply-no-correlation-id  #/components/messages/StatusRequest',
  'WARNING  reply-no-correlation-id  #/components/messages/StatusReply',
  'WARNING  channel-unused  #/channels/auditTrail',
  'GATE: FAIL - 2 errors, 5 warnings'
], ['GATE: PASS']);

process.stdout.write('\n');
const fixed = await run(['examples/orders-events-fixed.yaml', '--fail-on', 'warning']);
process.stdout.write(fixed.out);
expect('fixed orders events with --fail-on warning', fixed, 0, ['findings: 0 error, 0 warning, 0 info', 'GATE: PASS (--fail-on warning)'], ['ERROR', 'WARNING ']);

const old = await run(['examples/orders-events-2.6.json']);
expect('AsyncAPI 2.6 example', old, 1, [
  'AsyncAPI 2.6.0, json, "Orders Events"',
  'ERROR    security-scheme-undefined',
  'note: AsyncAPI 2.6 has no reply object, so the request/reply correlation check was not run',
  'GATE: FAIL - 3 errors'
], ['GATE: PASS']);

// The README shows the first two runs as they are printed.
const readme = (await readFile(resolve(root, 'README.md'), 'utf8')).split('\r\n').join('\n');
if (!readme.includes(broken.out)) problems.push('README: the sample output of the broken document differs from a real run');
if (!readme.includes(fixed.out)) problems.push('README: the sample output of the fixed document differs from a real run');

// The same document in the other formats, kept as examples of what each one looks like.
await mkdir(resolve(root, 'examples/output'), { recursive: true });
await writeFile(resolve(root, 'examples/output/orders-events.txt'), broken.out);
for (const [format, name] of [['markdown', 'orders-events.md'], ['json', 'orders-events.json'], ['csv', 'orders-events.csv']]) {
  const r = await run([...brokenArgs, '--format', format]);
  if (r.code !== 1) problems.push(`${format}: exit code ${r.code}, expected 1`);
  await writeFile(resolve(root, 'examples/output', name), r.out);
}
await writeFile(resolve(root, 'examples/output/orders-events-2.6.txt'), old.out);

if (problems.length) {
  for (const p of problems) console.error(`example: ${p}`);
  process.exit(1);
}
