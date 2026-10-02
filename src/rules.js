// The checks. Each one reads the document as data and reports what the document itself shows. docs/method.md gives the
// reason behind every finding and says what each check can and cannot see. Nothing here opens a connection or runs a
// program, and no value of an example, a default or an enum of the document, and no host name, is copied into a
// finding: a finding names the structure (a pointer, a server, a channel, a message, a scheme).

import { CREDENTIAL_TYPES, FACTS, FIELDS, HTTP_API_KEY_IN, PROTOCOLS, SCHEME_TYPES, factPage } from './data.js';
import { DOC_LIMITS, createResolver, decodePointer, escapeToken, findRefs, isLocalRef, isObj, lineOf, pointerOf } from './doc.js';

export const SEVERITIES = ['error', 'warning', 'info'];
export const RANK = { error: 0, warning: 1, info: 2 };

// The areas a report is grouped by, in report order.
export const AREAS = [
  { id: 'servers', title: 'Servers' },
  { id: 'security', title: 'Security schemes' },
  { id: 'messages', title: 'Messages' },
  { id: 'operations', title: 'Operations and channels' },
  { id: 'references', title: 'References' },
  { id: 'documentation', title: 'Documentation' }
];

// Every finding, in report order within a severity. facts are the keys of the sentences of src/data.js that the
// finding can quote; the page of the first one is the finding's source.
export const FINDINGS = [
  { id: 'ref-unresolved', severity: 'error', area: 'references', what: 'A local $ref that points to nothing', facts: ['reference'] },
  { id: 'ref-cycle', severity: 'error', area: 'references', what: 'A chain of $ref that leads back to itself, or is longer than the limit, so it never reaches a value', facts: ['reference'] },
  { id: 'server-no-security', severity: 'error', area: 'servers', what: 'A server declares no security scheme', facts: ['serverSecurity', 'serverSecurityV2'] },
  { id: 'server-plain-protocol', severity: 'error', area: 'servers', what: 'A server uses the plain protocol (amqp, http, kafka, mqtt, stomp, ws) when the specification lists a secure variant', facts: ['protocolList'] },
  { id: 'security-scheme-undefined', severity: 'error', area: 'security', what: 'A security requirement names a scheme that components.securitySchemes does not define (2.6)', facts: ['requirementName'] },
  { id: 'operation-no-channel', severity: 'error', area: 'operations', what: 'An operation has no channel reference (3.0)', facts: ['operationChannel'] },
  { id: 'server-protocol-missing', severity: 'warning', area: 'servers', what: 'A server has no protocol, so its transport cannot be judged', facts: ['protocolV3'] },
  { id: 'credentials-over-plain-transport', severity: 'warning', area: 'security', what: 'A security scheme that sends a user name and password, a key or an HTTP credential is used on a server with a plain protocol', facts: ['basicClearText', 'httpCredentials', 'mqttClearText'] },
  { id: 'apikey-in-query', severity: 'warning', area: 'security', what: 'An httpApiKey security scheme sends the key in the query', facts: ['schemeIn', 'uriSensitive'] },
  { id: 'message-no-payload', severity: 'warning', area: 'messages', what: 'A message has no payload schema', facts: ['payload', 'messageDefinition'] },
  { id: 'reply-no-correlation-id', severity: 'warning', area: 'operations', what: 'A message of a request/reply operation has no correlationId (3.0)', facts: ['correlationIdField', 'replyObject'] },
  { id: 'channel-unused', severity: 'warning', area: 'operations', what: 'A channel that no operation uses (3.0), or that has neither a publish nor a subscribe operation (2.6)', facts: ['operationsDefinition', 'channelItem'] },
  { id: 'payload-no-type', severity: 'info', area: 'messages', what: 'A payload schema has no type and no composition', facts: ['schemaVocabulary'] },
  { id: 'payload-no-required', severity: 'info', area: 'messages', what: 'A payload schema lists properties and no required list', facts: ['schemaVocabulary'] },
  { id: 'payload-format-not-read', severity: 'info', area: 'messages', what: 'A payload schema is written in a format other than the AsyncAPI schema, so it was not read', facts: ['payload'] },
  { id: 'ref-remote', severity: 'info', area: 'references', what: 'A $ref that points to another file or an address: it is not followed, so what is behind it was not checked', facts: ['reference'] },
  { id: 'message-no-description', severity: 'info', area: 'documentation', what: 'A message has neither a description nor a summary', facts: ['messageDescription'] },
  { id: 'operation-no-description', severity: 'info', area: 'documentation', what: 'An operation has neither a description nor a summary', facts: ['operationDescription'] },
  { id: 'operation-no-id', severity: 'info', area: 'documentation', what: 'An operation has no operationId (2.6)', facts: ['operationIdField'] },
  { id: 'message-no-id', severity: 'info', area: 'documentation', what: 'A message has no messageId (2.6)', facts: ['messageIdField'] }
];

const BY_ID = Object.fromEntries(FINDINGS.map((f) => [f.id, f]));
export const ORDER = Object.fromEntries(FINDINGS.map((f, i) => [f.id, i]));
export const BY_ID_SEVERITY = Object.fromEntries(FINDINGS.map((f) => [f.id, f.severity]));
export const AREA_ORDER = Object.fromEntries(AREAS.map((a, i) => [a.id, i]));

// Text from the input: control, line separator and direction characters replaced by a space, length capped.
export function safeText(value, max = 300) {
  const s = String(value).replace(UNSAFE_CHARACTERS, ' ');
  return s.length > max ? `${s.slice(0, max - 3)}...` : s;
}

export function meetsThreshold(severity, failOn) {
  return RANK[severity] <= RANK[failOn];
}

// Control characters (C0 and C1), the line and paragraph separators and the Unicode direction controls, built from
// their code points so that this file holds only ASCII.
const span = (a, b) => `${String.fromCharCode(a)}-${String.fromCharCode(b)}`;
const UNSAFE_CHARACTERS = new RegExp(`[${span(0, 0x1f)}${span(0x7f, 0x9f)}${[0x200e, 0x200f, 0x2028, 0x2029].map((c) => String.fromCharCode(c)).join('')}${span(0x202a, 0x202e)}${span(0x2066, 0x2069)}]`, 'g');

const str = (v, max = 2000) => (typeof v === 'string' ? v.slice(0, max) : '');
const sub = (pointer, ...tokens) => `${pointer}${tokens.map((t) => `/${escapeToken(t)}`).join('')}`;
const lastToken = (pointer) => {
  const cut = pointer.lastIndexOf('/');
  let t = cut < 0 ? pointer : pointer.slice(cut + 1);
  try {
    t = decodeURIComponent(t);
  } catch {
    // a lone % stays as it is
  }
  return t.replace(/~1/g, '/').replace(/~0/g, '~');
};

// ---- servers ---------------------------------------------------------------------------------------------------------

// The host of a server address or host field (lower case), or '' when there is none.
export function hostOf(text) {
  let s = str(text, 400).trim().replace(/^[A-Za-z][A-Za-z0-9+.-]{0,20}:\/\//, '');
  const cut = s.search(/[/?#]/);
  if (cut >= 0) s = s.slice(0, cut);
  const at = s.lastIndexOf('@');
  if (at >= 0) s = s.slice(at + 1);
  if (s.startsWith('[')) {
    const end = s.indexOf(']');
    return end > 0 ? s.slice(0, end + 1).toLowerCase() : '';
  }
  const colon = s.indexOf(':');
  if (colon >= 0) s = s.slice(0, colon);
  return s.toLowerCase();
}

export function isLocalHost(host) {
  return host === 'localhost' || host.endsWith('.localhost') || host === '[::1]' || /^127(?:\.\d{1,3}){3}$/.test(host);
}

// The row of PROTOCOLS for a protocol written in the document, when it is the plain one, or null.
export function plainProtocol(protocol) {
  const p = str(protocol, 60).trim().toLowerCase();
  return PROTOCOLS.find((row) => row.plain === p) ?? null;
}

// ---- the run ---------------------------------------------------------------------------------------------------------

export function runRules(parsed, limits = DOC_LIMITS) {
  const { data, lines, major } = parsed;
  const resolver = createResolver(data, limits);
  const found = [];
  const facts = { servers: 0, channels: 0, operations: 0, messages: 0, securitySchemes: 0, localPlain: 0, omitted: {} };

  const basisOf = (keys) => keys.map((k) => ({ text: FACTS[k].text, section: FACTS[k].section, source: factPage(k, major) }));
  function add(id, pointer, subject, message, fix, basis = []) {
    const def = BY_ID[id];
    found.push({
      id,
      severity: def.severity,
      area: def.area,
      pointer: safeText(pointer, 400),
      line: lineOf(lines, pointer),
      subject: safeText(subject, 200),
      message: safeText(message, 900),
      fix: safeText(fix, 500),
      basis: basisOf(basis),
      source: factPage(basis[0] ?? def.facts[0], major)
    });
  }

  // The value behind a $ref chain, or null when the chain does not end in a value (a broken, remote or cyclic
  // reference is reported once, by the reference check, and the checks that need the value skip it).
  const resolve = (node, pointer) => {
    if (node === undefined) return null;
    const r = resolver.resolve(node, pointer);
    return r.status === 'ok' ? r : null;
  };
  const objAt = (node, pointer) => {
    const r = resolve(node, pointer);
    return r && isObj(r.node) ? r : null;
  };
  const mapOf = (value, limit, what) => {
    if (!isObj(value)) return [];
    const keys = Object.keys(value);
    if (keys.length > limit) throw new Error(`more than ${limit.toLocaleString('en-US')} ${what}`);
    return keys.map((k) => [k, value[k]]);
  };
  const components = isObj(data[FIELDS.components]) ? data[FIELDS.components] : {};
  const schemesRoot = isObj(components[FIELDS.securitySchemes]) ? components[FIELDS.securitySchemes] : {};

  // A text field of a node, or of one of its traits.
  function textField(node, pointer, keys) {
    const own = (n) => keys.some((k) => str(n[k]).trim() !== '');
    if (own(node)) return true;
    return (Array.isArray(node[FIELDS.traits]) ? node[FIELDS.traits] : []).slice(0, 50).some((t, i) => {
      const r = objAt(t, sub(pointer, FIELDS.traits, String(i)));
      return r ? own(r.node) : false;
    });
  }
  const hasKey = (node, pointer, key) => {
    if (node[key] !== undefined && node[key] !== null) return true;
    return (Array.isArray(node[FIELDS.traits]) ? node[FIELDS.traits] : []).slice(0, 50).some((t, i) => {
      const r = objAt(t, sub(pointer, FIELDS.traits, String(i)));
      return r ? r.node[key] !== undefined && r.node[key] !== null : false;
    });
  };

  // ---- servers and the security of each one ----
  const servers = [];
  for (const [name, raw] of mapOf(data[FIELDS.servers], limits.maxServers, 'servers')) {
    const own = sub('#', FIELDS.servers, name);
    const r = objAt(raw, own);
    if (r) servers.push({ name, own, pointer: r.pointer, node: r.node });
  }
  facts.servers = servers.length;

  // The entries of a list of security declarations: 3.0 lists security scheme objects (or references to them), 2.6
  // lists requirement objects that name schemes.
  function securityEntries(list, listPointer) {
    const entries = [];
    const undef = [];
    let count = 0;
    if (!Array.isArray(list)) return { entries, undef, count };
    list.slice(0, 200).forEach((item, i) => {
      const at = sub(listPointer, String(i));
      if (!isObj(item)) return;
      if (major === 3) {
        if (typeof item[FIELDS.$ref] === 'string') {
          count += 1;
          const r = objAt(item, at);
          if (r) entries.push({ name: lastToken(r.pointer), node: r.node, pointer: r.pointer, at });
        } else if (typeof item[FIELDS.type] === 'string') {
          count += 1;
          entries.push({ name: `#${i}`, node: item, pointer: at, at });
        }
      } else {
        for (const schemeName of Object.keys(item)) {
          count += 1;
          const schemePointer = sub('#', FIELDS.components, FIELDS.securitySchemes, schemeName);
          const r = Object.hasOwn(schemesRoot, schemeName) ? objAt(schemesRoot[schemeName], schemePointer) : null;
          if (r) entries.push({ name: schemeName, node: r.node, pointer: r.pointer, at: sub(at, schemeName) });
          else if (!Object.hasOwn(schemesRoot, schemeName)) undef.push({ name: schemeName, at: sub(at, schemeName) });
        }
      }
    });
    return { entries, undef, count };
  }

  const usedSchemes = new Map(); // pointer of the scheme -> { name, node }
  const credentialUses = []; // { scheme, server, at }
  const noteScheme = (e) => {
    if (!usedSchemes.has(e.pointer)) usedSchemes.set(e.pointer, { name: e.name, node: e.node });
  };
  const reportedUndefined = new Set();
  const undefinedScheme = (u) => {
    if (reportedUndefined.has(u.at)) return;
    reportedUndefined.add(u.at);
    add('security-scheme-undefined', u.at, u.name, `The security requirement names the scheme "${safeText(u.name, 80)}", and components.securitySchemes does not define it, so the requirement protects nothing.`, 'Define the scheme under components.securitySchemes, or remove the requirement.', ['requirementName']);
  };

  const serverUse = new Map(); // pointer of a server -> { plain, local }
  for (const s of servers) {
    const protocol = s.node[FIELDS.protocol];
    const hostText = major === 3 ? s.node[FIELDS.host] : s.node[FIELDS.url];
    const host = hostOf(hostText);
    const local = isLocalHost(host);
    let plain = null;
    if (typeof protocol !== 'string' || protocol.trim() === '') {
      add('server-protocol-missing', s.pointer, s.name, `The server "${safeText(s.name, 80)}" has no protocol, so the tool cannot tell whether the connection is encrypted.`, 'Set the protocol of the server (for example amqps, kafka-secure, secure-mqtt, wss or https).', [major === 3 ? 'protocolV3' : 'protocolList']);
    } else {
      plain = plainProtocol(protocol);
      if (plain && local) facts.localPlain += 1;
      else if (plain) {
        const keys = ['protocolList'];
        if (plain.why !== 'protocolList') keys.push(plain.why);
        add('server-plain-protocol', sub(s.pointer, FIELDS.protocol), s.name,
          `The server "${safeText(s.name, 80)}" uses the plain protocol ${plain.plain}, and the specification lists ${plain.secure} for the same protocol. Messages, and the credentials that go with them, can be read and changed on the way.`,
          `Use ${plain.secure} (TLS) for this server, and keep ${plain.plain} for a broker on the local machine only.`, keys);
      }
    }
    serverUse.set(s.pointer, { plain: plain && !local ? plain : null, name: s.name });

    const sec = securityEntries(s.node[FIELDS.security], sub(s.pointer, FIELDS.security));
    for (const u of sec.undef) undefinedScheme(u);
    if (sec.count === 0) {
      add('server-no-security', Object.hasOwn(s.node, FIELDS.security) ? sub(s.pointer, FIELDS.security) : s.pointer, s.name,
        `The server "${safeText(s.name, 80)}" declares no security scheme, so the document says nothing about how a client proves who it is when it connects.`,
        'Add the scheme (or the alternatives) that a client has to satisfy to connect, under security of the server.', [major === 3 ? 'serverSecurity' : 'serverSecurityV2']);
    }
    for (const e of sec.entries) {
      noteScheme(e);
      if (serverUse.get(s.pointer).plain && CREDENTIAL_TYPES.includes(str(e.node[FIELDS.type], 40))) credentialUses.push({ scheme: e, server: s.pointer, at: e.at });
    }
  }

  // ---- channels, operations ----
  const channelServers = (channelNode, channelPointer) => {
    const list = channelNode[FIELDS.servers];
    if (!Array.isArray(list) || list.length === 0) return servers.map((s) => s.pointer);
    const out = [];
    list.slice(0, 200).forEach((item, i) => {
      if (major === 3 && isObj(item) && isLocalRef(item[FIELDS.$ref])) {
        const r = resolve(item, sub(channelPointer, FIELDS.servers, String(i)));
        if (r) out.push(r.pointer);
      } else if (major === 2 && typeof item === 'string') {
        const s = servers.find((x) => x.name === item);
        if (s) out.push(s.pointer);
      }
    });
    return out;
  };
  const operationSecurity = (opNode, opPointer, onServers) => {
    const sec = securityEntries(opNode[FIELDS.security], sub(opPointer, FIELDS.security));
    for (const u of sec.undef) undefinedScheme(u);
    for (const e of sec.entries) {
      noteScheme(e);
      if (!CREDENTIAL_TYPES.includes(str(e.node[FIELDS.type], 40))) continue;
      for (const sp of onServers) if (serverUse.get(sp)?.plain) credentialUses.push({ scheme: e, server: sp, at: e.at });
    }
  };

  const messages = new Map(); // pointer of the message -> { node, name }
  // The name of a message in a report: the key it has in a map, else its messageId or name, else a label of the place.
  const addMessage = (raw, pointer, key, fallback = '') => {
    const r = objAt(raw, pointer);
    if (!r || messages.has(r.pointer)) return r;
    if (messages.size >= limits.maxMessages) throw new Error(`more than ${limits.maxMessages.toLocaleString('en-US')} messages`);
    messages.set(r.pointer, { node: r.node, name: (r.pointer !== pointer ? lastToken(r.pointer) : '') || key || str(r.node[FIELDS.messageId], 100) || str(r.node[FIELDS.name], 100) || fallback || lastToken(r.pointer) });
    return r;
  };
  const replyChecks = []; // 3.0: { op, request: [{pointer,node,name}], reply: [...] }
  const description = (node, pointer) => textField(node, pointer, [FIELDS.description, FIELDS.summary]);

  if (major === 3) {
    const used = new Set();
    const channels = new Map();
    for (const [name, raw] of mapOf(data[FIELDS.channels], limits.maxChannels, 'channels')) {
      const own = sub('#', FIELDS.channels, name);
      const r = objAt(raw, own);
      if (!r) continue;
      channels.set(own, { name, own, pointer: r.pointer, node: r.node });
      for (const [mname, mraw] of mapOf(r.node[FIELDS.messages], limits.maxMessages, 'messages')) addMessage(mraw, sub(r.pointer, FIELDS.messages, mname), mname);
    }
    facts.channels = channels.size;
    for (const [name, mraw] of mapOf(components[FIELDS.messages], limits.maxMessages, 'messages')) addMessage(mraw, sub('#', FIELDS.components, FIELDS.messages, name), name);

    // The messages a list of references names, or all the messages of a channel when there is no list.
    const messagesOf = (list, listPointer, channel) => {
      const out = [];
      if (Array.isArray(list)) {
        list.slice(0, 200).forEach((item, i) => {
          const r = objAt(item, sub(listPointer, String(i)));
          if (r) out.push({ pointer: r.pointer, node: r.node, name: lastToken(r.pointer) });
        });
      } else if (channel) {
        for (const [mname, mraw] of mapOf(channel.node[FIELDS.messages], limits.maxMessages, 'messages')) {
          const r = objAt(mraw, sub(channel.pointer, FIELDS.messages, mname));
          if (r) out.push({ pointer: r.pointer, node: r.node, name: mname });
        }
      }
      return out;
    };
    // The channel an operation or a reply names: records it as used, and returns it when the reference leads to one.
    const channelOf = (ref, pointer) => {
      if (!isObj(ref) || typeof ref[FIELDS.$ref] !== 'string') return { named: false, channel: null };
      if (isLocalRef(ref[FIELDS.$ref])) {
        used.add(pointerOf(decodePointer(ref[FIELDS.$ref])));
        const r = objAt(ref, pointer);
        if (r) {
          used.add(r.pointer);
          return { named: true, channel: { node: r.node, pointer: r.pointer } };
        }
      }
      return { named: true, channel: null };
    };

    for (const [id, raw] of mapOf(data[FIELDS.operations], limits.maxOperations, 'operations')) {
      const own = sub('#', FIELDS.operations, id);
      const r = objAt(raw, own);
      if (!r) continue;
      facts.operations += 1;
      const op = r.node;
      const named = channelOf(op[FIELDS.channel], sub(r.pointer, FIELDS.channel));
      if (!named.named) {
        add('operation-no-channel', Object.hasOwn(op, FIELDS.channel) ? sub(r.pointer, FIELDS.channel) : r.pointer, id,
          `The operation "${safeText(id, 80)}" has no channel reference, so it does not say where its messages are sent or received. The channel of an operation has to be a $ref to a channel.`,
          'Add channel with a $ref to the channel of the root channels object that this operation uses.', ['operationChannel']);
      }
      if (!description(op, r.pointer)) add('operation-no-description', r.pointer, id, `The operation "${safeText(id, 80)}" has neither a description nor a summary.`, 'Say in a sentence what the operation does and who relies on it.', ['operationDescription']);
      operationSecurity(op, r.pointer, named.channel ? channelServers(named.channel.node, named.channel.pointer) : servers.map((s) => s.pointer));

      if (op[FIELDS.reply] !== undefined && op[FIELDS.reply] !== null) {
        const reply = objAt(op[FIELDS.reply], sub(r.pointer, FIELDS.reply));
        if (reply) {
          const replyChannel = channelOf(reply.node[FIELDS.channel], sub(reply.pointer, FIELDS.channel)).channel;
          replyChecks.push({
            id,
            request: messagesOf(op[FIELDS.messages], sub(r.pointer, FIELDS.messages), named.channel),
            reply: messagesOf(reply.node[FIELDS.messages], sub(reply.pointer, FIELDS.messages), replyChannel)
          });
        }
      }
    }
    for (const c of channels.values()) {
      if (!used.has(c.own) && !used.has(c.pointer)) {
        add('channel-unused', c.own, c.name, `The channel "${safeText(c.name, 80)}" is not used by any operation of this application, so nothing says who sends to it or receives from it.`,
          'Add an operation that uses the channel, or remove the channel.', ['operationsDefinition', 'channelDefinition']);
      }
    }
  } else {
    const channelEntries = mapOf(data[FIELDS.channels], limits.maxChannels, 'channels');
    for (const [name, raw] of channelEntries) {
      const own = sub('#', FIELDS.channels, name);
      const r = objAt(raw, own);
      if (!r) continue;
      facts.channels += 1;
      const ops = [FIELDS.publish, FIELDS.subscribe].filter((k) => isObj(r.node[k]));
      if (ops.length === 0) {
        add('channel-unused', own, name, `The channel "${safeText(name, 80)}" has neither a publish nor a subscribe operation, so nothing says who sends to it or receives from it.`, 'Add the operation that the application performs on the channel, or remove the channel.', ['channelItem']);
      }
      const onServers = channelServers(r.node, r.pointer);
      for (const k of ops) {
        const opPointer = sub(r.pointer, k);
        const op = r.node[k];
        facts.operations += 1;
        const label = `${name} ${k}`;
        if (str(op[FIELDS.operationId]).trim() === '') add('operation-no-id', opPointer, label, `The ${k} operation of the channel "${safeText(name, 80)}" has no operationId, so tools and people have no stable name for it.`, 'Add a unique operationId.', ['operationIdField']);
        if (!description(op, opPointer)) add('operation-no-description', opPointer, label, `The ${k} operation of the channel "${safeText(name, 80)}" has neither a description nor a summary.`, 'Say in a sentence what the operation does and who relies on it.', ['operationV2']);
        operationSecurity(op, opPointer, onServers);
        const m = op[FIELDS.message];
        if (isObj(m) && Array.isArray(m[FIELDS.oneOf])) m[FIELDS.oneOf].slice(0, 200).forEach((item, i) => addMessage(item, sub(opPointer, FIELDS.message, FIELDS.oneOf, String(i)), '', `${label} message ${i + 1}`));
        else if (m !== undefined) addMessage(m, sub(opPointer, FIELDS.message), '', `${label} message`);
      }
    }
    for (const [name, mraw] of mapOf(components[FIELDS.messages], limits.maxMessages, 'messages')) addMessage(mraw, sub('#', FIELDS.components, FIELDS.messages, name), name);
  }

  // ---- messages ----
  facts.messages = messages.size;
  const payloadChecks = (msgPointer, node, name) => {
    if (node[FIELDS.payload] === undefined || node[FIELDS.payload] === null) {
      add('message-no-payload', msgPointer, name, `The message "${safeText(name, 80)}" has no payload schema, so a receiver cannot validate what it gets and a sender cannot tell what it may send.`, 'Add a payload with a schema (type, properties and required).', major === 3 ? ['payload', 'messageDefinition'] : ['payloadV2']);
      return;
    }
    const pointer = sub(msgPointer, FIELDS.payload);
    const r = resolve(node[FIELDS.payload], pointer);
    if (!r) return;
    let schema = r.node;
    let at = r.pointer;
    let format = typeof node[FIELDS.schemaFormat] === 'string' ? node[FIELDS.schemaFormat] : '';
    if (isObj(schema) && typeof schema[FIELDS.schemaFormat] === 'string' && Object.hasOwn(schema, FIELDS.schema)) {
      format = schema[FIELDS.schemaFormat];
      const inner = resolve(schema[FIELDS.schema], sub(at, FIELDS.schema));
      if (!inner) return;
      schema = inner.node;
      at = inner.pointer;
    }
    if (format !== '' && !format.toLowerCase().startsWith('application/vnd.aai.asyncapi')) {
      add('payload-format-not-read', at, name, `The payload of the message "${safeText(name, 80)}" is written in another schema format than the AsyncAPI schema, so its type and required list were not read.`, 'Check the schema with the tool of its own format.', ['payload']);
      return;
    }
    if (!isObj(schema)) {
      add('payload-no-type', at, name, `The payload schema of the message "${safeText(name, 80)}" is not a schema object, so it constrains nothing.`, 'Give the payload a schema with a type.', ['schemaVocabulary']);
      return;
    }
    const types = Array.isArray(schema[FIELDS.type]) ? schema[FIELDS.type].filter((t) => typeof t === 'string') : typeof schema[FIELDS.type] === 'string' ? [schema[FIELDS.type]] : [];
    const composed = [FIELDS.allOf, FIELDS.anyOf, FIELDS.oneOf, FIELDS.enum].some((k) => Array.isArray(schema[k]) && schema[k].length > 0) || Object.hasOwn(schema, FIELDS.const);
    if (types.length === 0 && !composed) {
      add('payload-no-type', at, name, `The payload schema of the message "${safeText(name, 80)}" has no type and no composition, so any value is a valid payload.`, 'Set type on the payload schema, and describe its properties.', ['schemaVocabulary']);
      return;
    }
    const props = isObj(schema[FIELDS.properties]) ? Object.keys(schema[FIELDS.properties]).length : 0;
    const required = Array.isArray(schema[FIELDS.required]) && schema[FIELDS.required].length > 0;
    if (props > 0 && !required) {
      add('payload-no-required', at, name, `The payload schema of the message "${safeText(name, 80)}" lists ${props.toLocaleString('en-US')} ${props === 1 ? 'property' : 'properties'} and no required list, so a message with none of them is valid.`, 'List the properties that every message has under required.', ['schemaVocabulary']);
    }
  };
  for (const [pointer, m] of messages) {
    payloadChecks(pointer, m.node, m.name);
    if (!description(m.node, pointer)) add('message-no-description', pointer, m.name, `The message "${safeText(m.name, 80)}" has neither a description nor a summary.`, 'Say in a sentence what the message means and when it is sent.', ['messageDescription']);
    if (major === 2 && str(m.node[FIELDS.messageId]).trim() === '') add('message-no-id', pointer, m.name, `The message "${safeText(m.name, 80)}" has no messageId, so tools and people have no stable name for it.`, 'Add a unique messageId.', ['messageIdField']);
  }

  // ---- request and reply: every message of the pair needs a correlation id ----
  const seenCorrelation = new Set();
  for (const rc of replyChecks) {
    for (const [role, list] of [['request', rc.request], ['reply', rc.reply]]) {
      for (const m of list) {
        if (seenCorrelation.has(m.pointer) || hasKey(m.node, m.pointer, FIELDS.correlationId)) continue;
        seenCorrelation.add(m.pointer);
        add('reply-no-correlation-id', m.pointer, m.name, `The message "${safeText(m.name, 80)}" is a ${role} message of the request/reply operation "${safeText(rc.id, 80)}" and has no correlationId, so the reply cannot be matched to its request.`,
          'Add a correlationId with a location (for example $message.header#/correlationId) to the request and to the reply message.', ['correlationIdField', 'replyObject']);
      }
    }
  }

  // ---- security schemes ----
  const allSchemes = new Map(usedSchemes);
  for (const [name, raw] of mapOf(schemesRoot, limits.maxMessages, 'security schemes')) {
    const pointer = sub('#', FIELDS.components, FIELDS.securitySchemes, name);
    const r = objAt(raw, pointer);
    if (r && !allSchemes.has(r.pointer)) allSchemes.set(r.pointer, { name, node: r.node });
  }
  facts.securitySchemes = allSchemes.size;
  for (const [pointer, s] of allSchemes) {
    if (s.node[FIELDS.type] === SCHEME_TYPES.httpApiKey && s.node[FIELDS.in] === HTTP_API_KEY_IN.query) {
      add('apikey-in-query', sub(pointer, FIELDS.in), s.name, `The security scheme "${safeText(s.name, 80)}" sends an API key in the query. A key in a URL is shown and logged in many places.`, 'Send the key in a header (in: header) instead.', ['schemeIn', 'uriSensitive']);
    }
  }
  const reportedCredentials = new Set();
  for (const u of credentialUses) {
    const key = `${u.scheme.pointer}|${u.server}`;
    if (reportedCredentials.has(key)) continue;
    reportedCredentials.add(key);
    const server = serverUse.get(u.server);
    const type = str(u.scheme.node[FIELDS.type], 40);
    let basis = server.plain.why;
    if (type === SCHEME_TYPES.http && str(u.scheme.node[FIELDS.scheme], 20).toLowerCase() === 'basic') basis = 'basicClearText';
    else if (server.plain.plain === 'http') basis = 'httpCredentials';
    else if (server.plain.plain === 'mqtt') basis = 'mqttClearText';
    add('credentials-over-plain-transport', u.at, u.scheme.name,
      `The security scheme "${safeText(u.scheme.name, 80)}" (${type}) is used on the server "${safeText(server.name, 80)}", which uses the plain protocol ${server.plain.plain}, so the secret it carries travels in the clear.`,
      `Use ${server.plain.secure} for the server, so that the secret travels inside TLS.`, [basis]);
  }

  // ---- references ----
  const refs = findRefs(data);
  for (const { ref, at } of refs.local) {
    const r = resolver.resolve({ [FIELDS.$ref]: ref }, at);
    const pointer = sub(at, FIELDS.$ref);
    if (r.status === 'broken') add('ref-unresolved', pointer, lastToken(at), 'A $ref points to a place that does not exist in this file, so what it stands for was not checked.', 'Fix the reference, or add what it points to.', ['reference']);
    else if (r.status === 'cycle') add('ref-cycle', pointer, lastToken(at), 'A chain of $ref leads back to itself or is longer than the limit, so it never reaches a value and what it stands for was not checked.', 'Break the loop: make one of the references point to a real definition.', ['reference']);
  }
  for (const { at } of refs.remote) {
    add('ref-remote', sub(at, FIELDS.$ref), lastToken(at), 'A $ref points outside this file (another file or an address). The tool never opens or fetches it, so what is behind it was not checked.', 'Bundle the document into one file before checking it.', ['reference']);
  }

  // Sorted, and each finding id listed at most maxListedPerFinding times; the rest is counted in omitted.
  const compare = (a, b) => (a < b ? -1 : a > b ? 1 : 0);
  found.sort((a, b) => RANK[a.severity] - RANK[b.severity] || AREA_ORDER[a.area] - AREA_ORDER[b.area] || ORDER[a.id] - ORDER[b.id] || compare(a.pointer, b.pointer) || compare(a.subject, b.subject));
  const shownPerId = {};
  const findings = [];
  for (const f of found) {
    shownPerId[f.id] = (shownPerId[f.id] ?? 0) + 1;
    if (shownPerId[f.id] <= limits.maxListedPerFinding) findings.push(f);
    else facts.omitted[f.id] = (facts.omitted[f.id] ?? 0) + 1;
  }
  return { findings, facts };
}
