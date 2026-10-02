// Reads one AsyncAPI document, runs the checks of src/rules.js and returns one report: the findings grouped by area,
// notes and the gate. docs/method.md gives the reason behind every finding. The tool reads the one file it is given
// and opens no connection.

import { resolve } from 'node:path';
import { FIELDS } from './data.js';
import { DOC_LIMITS, isObj, parseDocument } from './doc.js';
import { FILE_LIMITS, displayPath, readBounded } from './files.js';
import { AREAS, FINDINGS, ORDER, RANK, SEVERITIES, BY_ID_SEVERITY, meetsThreshold, runRules, safeText } from './rules.js';

export const LIMITS = { ...DOC_LIMITS, ...FILE_LIMITS };
export { AREAS, FINDINGS, ORDER, RANK, SEVERITIES, meetsThreshold, safeText };

function plural(count, one, many = `${one}s`) {
  return `${count.toLocaleString('en-US')} ${count === 1 ? one : many}`;
}

// Builds the report for the text of one document. name is the file name shown and used to choose JSON or YAML.
export function checkText(text, name, { failOn = 'error', version = '0.0.0', limits = LIMITS, path = name } = {}) {
  const parsed = parseDocument(text, name, limits);
  const { findings, facts } = runRules(parsed, limits);

  const counts = { error: 0, warning: 0, info: 0 };
  for (const f of findings) counts[f.severity] += 1;
  for (const [id, n] of Object.entries(facts.omitted)) counts[BY_ID_SEVERITY[id]] += n;

  const areas = AREAS.map((a) => {
    const own = findings.filter((f) => f.area === a.id);
    const worst = own.length ? own.reduce((w, f) => (RANK[f.severity] < RANK[w] ? f.severity : w), 'info') : null;
    const result = worst === 'error' ? 'fail' : worst === 'warning' ? 'warn' : worst === 'info' ? 'info' : 'pass';
    const detail = own.length ? [...new Set(own.map((f) => f.id))].map((id) => `${id} x${own.filter((f) => f.id === id).length}`).join(', ') : 'no finding';
    return { id: a.id, title: a.title, result, detail: safeText(detail, 400), findings: own.length };
  });

  const notes = [];
  if (facts.servers === 0 && facts.channels === 0 && facts.operations === 0) notes.push('No server, channel or operation was found, so there was nothing to check');
  else if (facts.operations === 0 && parsed.major === 3) notes.push('No operation was found under operations, so every channel is unused');
  if (facts.localPlain) notes.push(`${plural(facts.localPlain, 'server')} with a plain protocol on a local host ${facts.localPlain === 1 ? 'was' : 'were'} not reported`);
  if (parsed.major === 2) notes.push('AsyncAPI 2.6 has no reply object, so the request/reply correlation check was not run');
  for (const [id, n] of Object.entries(facts.omitted)) notes.push(`${plural(n, 'more finding')} of ${id} ${n === 1 ? 'is' : 'are'} counted but not listed (the limit is ${limits.maxListedPerFinding} listed findings per check)`);
  const info = isObj(parsed.data[FIELDS.info]) ? parsed.data[FIELDS.info] : {};

  const eCount = meetsThreshold('error', failOn) ? counts.error : 0;
  const wCount = meetsThreshold('warning', failOn) ? counts.warning : 0;
  const reason = [eCount ? plural(eCount, 'error') : null, wCount ? plural(wCount, 'warning') : null].filter(Boolean).join(', ');

  return {
    tool: 'asyncapi-security-check',
    version,
    document: {
      path: safeText(path, 400),
      asyncapi: safeText(parsed.asyncapi, 40),
      format: parsed.format,
      title: typeof info[FIELDS.title] === 'string' ? safeText(info[FIELDS.title], 120) : '',
      servers: facts.servers,
      channels: facts.channels,
      operations: facts.operations,
      messages: facts.messages,
      securitySchemes: facts.securitySchemes
    },
    areas,
    findings,
    notes,
    counts,
    gate: { failOn, pass: eCount + wCount === 0, reason }
  };
}

// Reads the file and builds the report. The path in the report is relative to base, with forward slashes.
export async function checkFile(file, { failOn = 'error', version = '0.0.0', limits = LIMITS, base = process.cwd() } = {}) {
  const full = resolve(base, file);
  let text;
  try {
    text = (await readBounded(full, limits.maxFileBytes)).toString('utf8');
  } catch (error) {
    throw new Error(`${displayPath(full, base)}: ${error.reason ?? error.message}`);
  }
  try {
    return checkText(text, full, { failOn, version, limits, path: displayPath(full, base) });
  } catch (error) {
    throw new Error(`${displayPath(full, base)}: ${error.message}`);
  }
}
