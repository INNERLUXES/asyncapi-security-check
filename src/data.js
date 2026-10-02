// The names and sentences the checks rest on. Each one comes from a page that is saved, with its address on the first
// line, in research/sources, and test/data.test.js compares this file with the saved text. Change a value here only
// after saving the new page text and updating docs/rules-and-sources.md. The checks in src/ use these constants and
// never write a field name, a protocol name or a quoted sentence of their own.

export const SOURCES = [
  { id: 'asyncapi-3.0.0', file: 'asyncapi-3.0.0.txt', url: 'https://raw.githubusercontent.com/asyncapi/spec/v3.0.0/spec/asyncapi.md', label: 'AsyncAPI Specification 3.0.0' },
  { id: 'asyncapi-2.6.0', file: 'asyncapi-2.6.0.txt', url: 'https://raw.githubusercontent.com/asyncapi/spec/v2.6.0/spec/asyncapi.md', label: 'AsyncAPI Specification 2.6.0' },
  { id: 'mqtt-5.0', file: 'mqtt-5.0-security.txt', url: 'https://docs.oasis-open.org/mqtt/mqtt/v5.0/os/mqtt-v5.0-os.html', label: 'MQTT Version 5.0, section 5.4 Security' },
  { id: 'rfc6455', file: 'rfc6455-websocket-tls.txt', url: 'https://www.rfc-editor.org/rfc/rfc6455.txt', label: 'RFC 6455 The WebSocket Protocol, section 10.6' },
  { id: 'rfc9110', file: 'rfc9110-https-and-credentials.txt', url: 'https://www.rfc-editor.org/rfc/rfc9110.txt', label: 'RFC 9110 HTTP Semantics, sections 4.2.2, 17.9 and 17.16.1' },
  { id: 'rfc7617', file: 'rfc7617-basic-security.txt', url: 'https://www.rfc-editor.org/rfc/rfc7617.txt', label: 'RFC 7617 The Basic Authentication Scheme, section 4' }
];

export const source = (id) => SOURCES.find((s) => s.id === id);
const page = (id) => source(id).url;

// The versions of the specification the tool reads: the version string has to start with one of these.
export const VERSIONS = { v3: '3.0', v2: '2.6' };

// Field names of the AsyncAPI Specification 3.0.0 and 2.6.0.
export const FIELDS = {
  asyncapi: 'asyncapi',
  info: 'info',
  title: 'title',
  servers: 'servers',
  host: 'host',
  url: 'url',
  protocol: 'protocol',
  security: 'security',
  channels: 'channels',
  address: 'address',
  messages: 'messages',
  message: 'message',
  operations: 'operations',
  action: 'action',
  channel: 'channel',
  reply: 'reply',
  payload: 'payload',
  schema: 'schema',
  schemaFormat: 'schemaFormat',
  correlationId: 'correlationId',
  traits: 'traits',
  description: 'description',
  summary: 'summary',
  operationId: 'operationId',
  messageId: 'messageId',
  publish: 'publish',
  subscribe: 'subscribe',
  oneOf: 'oneOf',
  components: 'components',
  securitySchemes: 'securitySchemes',
  type: 'type',
  name: 'name',
  in: 'in',
  scheme: 'scheme',
  required: 'required',
  properties: 'properties',
  allOf: 'allOf',
  anyOf: 'anyOf',
  enum: 'enum',
  const: 'const',
  $ref: '$ref'
};

// The types of a Security Scheme Object, as the specification lists them in the type field.
export const SCHEME_TYPES = Object.fromEntries(['userPassword', 'apiKey', 'X509', 'symmetricEncryption', 'asymmetricEncryption', 'httpApiKey', 'http', 'oauth2', 'openIdConnect', 'plain', 'scramSha256', 'scramSha512', 'gssapi'].map((name) => [name, name]));

// The values of in for an httpApiKey.
export const HTTP_API_KEY_IN = { query: 'query', header: 'header', cookie: 'cookie' };

// The schemes that carry a secret that the receiver of the connection reads as sent: a user name and a password, a
// key, or an HTTP credential. The tool reads the secret as readable on the way when the server is plain. The names of
// the types are the specification's; the choice of this list is the tool's own (docs/method.md says why).
export const CREDENTIAL_TYPES = ['userPassword', 'plain', 'apiKey', 'httpApiKey', 'http'];

// A plain protocol, the secure variant that the specification lists for it, and the page that says why plain is a
// risk. 'mqtts' is not in the specification's list, which names secure-mqtt; the tool accepts it as secure because it
// is a common spelling, and it reports only the plain name.
export const PROTOCOLS = [
  { plain: 'amqp', secure: 'amqps', accepted: ['amqps'], why: 'protocolList' },
  { plain: 'http', secure: 'https', accepted: ['https'], why: 'httpsScheme' },
  { plain: 'kafka', secure: 'kafka-secure', accepted: ['kafka-secure'], why: 'protocolList' },
  { plain: 'mqtt', secure: 'secure-mqtt', accepted: ['secure-mqtt', 'mqtts'], why: 'mqttClear' },
  { plain: 'stomp', secure: 'stomps', accepted: ['stomps'], why: 'protocolList' },
  { plain: 'ws', secure: 'wss', accepted: ['wss'], why: 'websocketTls' }
];

// Sentences quoted in the findings. Every text is on its saved page word for word (test/data.test.js compares them),
// and holds no year.
export const FACTS = {
  protocolList: { source: 'asyncapi-2.6.0', section: 'Server Object, protocol, version 2.6.0', text: 'Supported protocol include, but are not limited to: amqp, amqps, http, https, ibmmq, jms, kafka, kafka-secure, anypointmq, mqtt, secure-mqtt, solace, stomp, stomps, ws, wss, mercure, googlepubsub, pulsar.' },
  protocolV3: { source: 'asyncapi-3.0.0', section: 'Server Object, protocol', text: 'The protocol this server supports for connection.' },
  serverSecurity: { source: 'asyncapi-3.0.0', section: 'Server Object, security', text: 'A declaration of which security schemes can be used with this server.' },
  serverSecurityV2: { source: 'asyncapi-2.6.0', section: 'Server Object, security', text: 'A declaration of which security mechanisms can be used with this server.' },
  operationSecurity: { source: 'asyncapi-3.0.0', section: 'Operation Object, security', text: 'In cases where Server Security also applies, it MUST also be satisfied.' },
  httpsScheme: { source: 'rfc9110', section: '4.2.2 https URI Scheme', text: 'In this context, "secured" specifically means that the server has been authenticated as acting on behalf of the identified authority and all HTTP communication with that server has confidentiality and integrity protection that is acceptable to both client and server.' },
  websocketTls: { source: 'rfc6455', section: '10.6 Connection Confidentiality and Integrity', text: 'WebSocket implementations MUST support TLS and SHOULD employ it when communicating with their peers.' },
  mqttClear: { source: 'mqtt-5.0', section: '5.4.12.1 Clear communication profile', text: 'When using the clear communication profile, the MQTT protocol runs over an open network with no additional secure communication mechanisms in place.' },
  mqttSecured: { source: 'mqtt-5.0', section: '5.4.12.3 Secured transport profile', text: 'When using the secured transport profile, the MQTT protocol runs over a physical or virtual network and using TLS [RFC5246] which provides authentication, integrity and privacy.' },
  mqttClearText: { source: 'mqtt-5.0', section: '5.4.1 Authentication of Clients by the Server', text: 'Implementations passing authentication data in clear text, obfuscating such data elements or requiring no authentication data should be aware this can give rise to Man-in-the-Middle and replay attacks.' },
  httpCredentials: { source: 'rfc9110', section: '17.16.1 Confidentiality of Credentials', text: 'Services that depend on individual user authentication require a secured connection prior to exchanging credentials' },
  basicClearText: { source: 'rfc7617', section: '4 Security Considerations', text: 'Because Basic authentication involves the cleartext transmission of passwords, it SHOULD NOT be used (without enhancements such as HTTPS [RFC2818]) to protect sensitive or valuable information.' },
  schemeIn: { source: 'asyncapi-3.0.0', section: 'Security Scheme Object, in', text: 'The location of the API key. Valid values are "user" and "password" for apiKey and "query", "header" or "cookie" for httpApiKey.' },
  uriSensitive: { source: 'rfc9110', section: '17.9 Disclosure of Sensitive Information in URIs', text: 'It is therefore unwise to include information within a URI that is sensitive, personally identifiable, or a risk to disclose.' },
  schemeTypes: { source: 'asyncapi-3.0.0', section: 'Security Scheme Object, type', text: 'Valid values are "userPassword", "apiKey", "X509", "symmetricEncryption", "asymmetricEncryption", "httpApiKey", "http", "oauth2", "openIdConnect", "plain", "scramSha256", "scramSha512", and "gssapi".' },
  requirementName: { source: 'asyncapi-2.6.0', section: 'Security Requirement Object', text: 'Each name MUST correspond to a security scheme which is declared in the Security Schemes under the Components Object.' },
  payload: { source: 'asyncapi-3.0.0', both: true, section: 'Message Object, payload', text: 'Definition of the message payload.' },
  messageDefinition: { source: 'asyncapi-3.0.0', section: 'Definitions, Message', text: 'A message MAY contain a payload and MAY also contain headers.' },
  payloadV2: { source: 'asyncapi-2.6.0', section: 'Message Object, payload', text: 'Definition of the message payload.' },
  schemaVocabulary: { source: 'asyncapi-3.0.0', both: true, section: 'Schema Object', text: 'The AsyncAPI Schema Object is a JSON Schema vocabulary which extends JSON Schema Core and Validation vocabularies.' },
  correlationIdField: { source: 'asyncapi-3.0.0', both: true, section: 'Message Object, correlationId', text: 'Definition of the correlation ID used for message tracing or matching.' },
  correlationIdObject: { source: 'asyncapi-3.0.0', section: 'Correlation ID Object', text: 'An object that specifies an identifier at design time that can used for message tracing and correlation.' },
  replyObject: { source: 'asyncapi-3.0.0', section: 'Operation Reply Object', text: 'If an operation implements the request/reply pattern, the reply object represents the response message.' },
  operationChannel: { source: 'asyncapi-3.0.0', section: 'Operation Object, channel', text: 'A $ref pointer to the definition of the channel in which this operation is performed.' },
  operationsDefinition: { source: 'asyncapi-3.0.0', section: 'Operations Object', text: 'Holds a dictionary with all the operations this application MUST implement.' },
  channelDefinition: { source: 'asyncapi-3.0.0', section: 'Definitions, Channel', text: 'Sender applications send messages to channels and receiver applications receive messages from channels.' },
  channelItem: { source: 'asyncapi-2.6.0', section: 'Channel Item Object', text: 'Describes the operations available on a single channel.' },
  operationV2: { source: 'asyncapi-2.6.0', section: 'Operation Object', text: 'Describes a publish or a subscribe operation.' },
  operationIdField: { source: 'asyncapi-2.6.0', section: 'Operation Object, operationId', text: 'Unique string used to identify the operation.' },
  messageIdField: { source: 'asyncapi-2.6.0', section: 'Message Object, messageId', text: 'Unique string used to identify the message.' },
  operationIdV3: { source: 'asyncapi-3.0.0', section: 'Operations Object', text: 'The field name (operationId) MUST be a string used to identify the operation in the document where it is defined, and its value is case-sensitive.' },
  messageDescription: { source: 'asyncapi-3.0.0', both: true, section: 'Message Object, description', text: 'A verbose explanation of the message.' },
  operationDescription: { source: 'asyncapi-3.0.0', both: true, section: 'Operation Object, description', text: 'A verbose explanation of the operation.' },
  reference: { source: 'asyncapi-3.0.0', both: true, section: 'Reference Object', text: 'A simple object to allow referencing other components in the specification, internally and externally.' }
};

// The finding id that rests on each fact is in src/rules.js; the page of a quoted sentence is source(FACTS[key].source).
// The page of a quoted sentence. A sentence that is word for word on both pages of the specification (both: true) is
// shown with the page of the version of the document that is checked.
export const factPage = (key, major = 3) => page(major === 2 && FACTS[key].both ? 'asyncapi-2.6.0' : FACTS[key].source);

// Fields whose value is data (an example, a default, a constant, an enum): a $ref written inside is not a reference.
// Fields whose value is a map of names, where a name such as "default" is the name of an item and not one of these.
// An extension field (x-...) is data too: the specification gives its value no structure.
export const DATA_FIELDS = ['example', 'examples', 'default', 'const', 'enum'];
export const MAP_FIELDS = ['properties', 'patternProperties', 'servers', 'channels', 'operations', 'messages', 'schemas', 'securitySchemes', 'serverVariables', 'parameters', 'correlationIds', 'replies', 'replyAddresses', 'operationTraits', 'messageTraits', 'serverBindings', 'channelBindings', 'operationBindings', 'messageBindings', 'variables'];
