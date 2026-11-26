import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { eventTimeUnixNano, logRecord, normalizeLogRecord } from './log-record-reference.mjs';
import { inventoryEventId } from './siem-reference.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const read = path => readFileSync(resolve(root, path), 'utf8');
const json = path => JSON.parse(read(path));
const schema = json('schemas/beacon-security-log-record-v1.schema.json');
const vectors = json('test-vectors/siem-v1.json').vectors.filter(v => v.name !== 'finding-enriched');
assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema');
assert.deepEqual(schema.required, ['time_unix_nano', 'body', 'attributes']);
assert.deepEqual(schema.properties.attributes.required, ['event_id', 'source']);
const lineBreak = new RegExp(schema.properties.body.not.pattern);

// Decode Body once; read moved metadata natively and retain all other v2 paths.
function receive(record, expected) {
  assert.equal(typeof record.body, 'string');
  assert(!lineBreak.test(record.body));
  const body = JSON.parse(record.body);
  assert.equal(typeof body, 'object');
  assert(!Array.isArray(body));
  assert.equal(body.schema_version, 2);
  assert(!('message' in body));
  assert(!('attributes' in body));
  assert(!('event_id' in body));
  assert(!('observed_at' in body));
  assert(!('occurrence_id' in body));
  const { observed_at, occurrence_id, ...retained } = expected;
  assert.deepEqual(body, retained);
  assert.equal(record.body, JSON.stringify(retained));
  assert.match(record.time_unix_nano, new RegExp(schema.properties.time_unix_nano.pattern));
  assert.equal(record.time_unix_nano, eventTimeUnixNano(expected.observed_at));
  assert(BigInt(record.time_unix_nano) <= 9223372036854775807n);
  assert(!('time_unix_nano' in record.attributes));
  assert.equal(record.attributes.source, body.source);
  assert.equal(record.attributes['event.name'], body.event_name);
  assert.equal(record.attributes.event_id,
    body.event_name === 'beacon.security.finding' ? expected.occurrence_id : inventoryEventId(expected));
  if (body.event_name === 'beacon.security.finding') {
    assert.equal(body.attack_evidence.status, expected.attack_evidence.status);
    assert.equal(body.span_id, expected.span_id);
  } else {
    assert.deepEqual(body.dependencies, expected.dependencies);
  }
}

for (const vector of vectors) {
  const event = json(vector.input);
  const record = logRecord(event);
  assert.deepEqual(record, json(`examples/log-records/${vector.name}.json`), vector.name);
  receive(record, event);
}
const finding = json('examples/finding-v2.json');
const special = { ...finding, stack: ['订单\\目录"query"\n下一行\r末尾', '\u2028'] };
const specialRecord = logRecord(special);
receive(specialRecord, special);
assert(specialRecord.body.includes('\\n'));
assert(specialRecord.body.includes('\\r'));
assert(specialRecord.body.includes('订单'));
const truncated = { ...finding, truncated: true, truncation_reason: 'record_byte_limit',
  evidence_sampled: false, evidence_sample_reason: 'record_byte_limit' };
for (const key of ['sources', 'propagation', 'ranges', 'stack']) delete truncated[key];
receive(logRecord(truncated), truncated);
// JSONL framing belongs to the file sink, not the OTLP Body.
const jsonl = [logRecord(finding), specialRecord].map(r => r.body + '\n').join('');
assert.deepEqual(jsonl.trimEnd().split('\n'), [validBody(finding), validBody(special)]);
function validBody(event) { const { observed_at, occurrence_id, ...body } = event; return JSON.stringify(body); }
for (const invalid of [null, [], { ...finding, schema_version: 1 }]) {
  assert.throws(() => logRecord(invalid));
}
// An envelope, double-encoded JSON, concatenated records, and pretty-printing fail acceptance.
const valid = logRecord(finding);
for (const body of [JSON.stringify({ message: valid.body }), JSON.stringify(valid.body),
  valid.body + '\n' + valid.body, JSON.stringify(finding, null, 2), valid.body + '\n']) {
  assert.throws(() => receive({ ...valid, body }, finding));
}
const parts = ['sbom-part-0', 'sbom-part-1'].map(name => json(`examples/log-records/${name}.json`));
const payloads = parts.map(r => JSON.parse(r.body));
assert.notEqual(parts[0].attributes.event_id, parts[1].attributes.event_id);
assert.equal(payloads[0].instance_id, payloads[1].instance_id);
assert.equal(parts[0].time_unix_nano, parts[1].time_unix_nano);
assert(payloads.every(p => !('observed_at' in p)));
assert.deepEqual(payloads.map(p => p.part_index), [0, 1]);
assert(payloads.every(p => p.part_count === parts.length));
const dependencies = payloads.flatMap(p => p.dependencies);
assert.equal(dependencies.length, 2);
assert.equal(new Set(dependencies.map(d => d.name)).size, dependencies.length);
console.log(`PASS: ${vectors.length} metadata-deduplicated LogRecords, attributes, single-line JSON, receiver paths, and multipart preservation.`);

// Independent expected values catch unit errors and Number precision loss.
assert.equal(eventTimeUnixNano('2026-10-02T00:00:00.000Z'), '1790899200000000000');
assert.equal(eventTimeUnixNano('2026-10-02T00:00:00Z'), '1790899200000000000');
assert.equal(eventTimeUnixNano('2026-10-02T00:00:00.123Z'), '1790899200123000000');
assert.equal(eventTimeUnixNano('2026-10-02T00:00:00.123456789Z'), '1790899200123456789');
assert.equal(eventTimeUnixNano('1970-01-01T00:00:00.000000001Z'), '1');
assert.equal(eventTimeUnixNano('2262-04-11T23:47:16.854775807Z'), '9223372036854775807');
for (const time of ['1970-01-01T00:00:00Z', '1969-12-31T23:59:59Z',
  '2262-04-11T23:47:16.854775808Z', '2026-02-30T00:00:00Z',
  '2026-10-02T00:00:00.1234567891Z', 'invalid']) {
  assert.throws(() => eventTimeUnixNano(time));
}
const precise = { ...finding, observed_at: '2026-10-02T00:00:00.123456789Z' };
const preciseRecord = logRecord(precise);
receive(preciseRecord, precise);
assert.equal(preciseRecord.time_unix_nano, '1790899200123456789');
assert.equal(preciseRecord.attributes.event_id, precise.occurrence_id);
assert.notEqual(preciseRecord.attributes.event_id, precise.finding_id);
const anotherOccurrence = { ...finding, occurrence_id: 'ev-another-request' };
assert.notEqual(logRecord(anotherOccurrence).attributes.event_id, valid.attributes.event_id);
assert.equal(JSON.parse(logRecord(anotherOccurrence).body).finding_id, finding.finding_id);
const earlierInventory = json('examples/sbom-inventory-v2.json');
const laterInventory = { ...earlierInventory, observed_at: '2026-10-02T00:25:00.000Z' };
assert.notEqual(logRecord(earlierInventory).attributes.event_id, logRecord(laterInventory).attributes.event_id);
assert(!('occurrence_id' in JSON.parse(logRecord(earlierInventory).body)));
assert.deepEqual(logRecord(precise), preciseRecord, 'retransmission preserves timestamp and event ID');
console.log('PASS: exact native event nanoseconds, int64 receiver limits, and occurrence/transport ID equivalence.');

// Body schema is exactly the historical v2 schema minus the two moved fields.
const bodySchema = json('schemas/beacon-security-log-body-v1.schema.json');
const fullSchema = json('schemas/beacon-security-event-v2.schema.json');
for (const family of ['finding', 'inventory']) {
  const expected = structuredClone(fullSchema.$defs[family]);
  expected.required = expected.required.filter(k => !['observed_at', 'occurrence_id'].includes(k));
  delete expected.properties.observed_at;
  delete expected.properties.occurrence_id;
  assert.deepEqual(bodySchema.$defs[family], expected);
}
for (const vector of vectors) {
  const record = json(`examples/log-records/${vector.name}.json`);
  const projected = normalizeLogRecord(record, vector.resource, vector.context);
  const legacyProjection = json(vector.expected);
  assert.deepEqual(projected, { ...legacyProjection, message: record.body });
  assert(Buffer.byteLength(record.body) < Buffer.byteLength(JSON.stringify(json(vector.input))));
}
for (const extra of [{ observed_at: finding.observed_at }, { occurrence_id: finding.occurrence_id },
  { event_id: finding.occurrence_id }]) {
  const duplicate = { ...valid, body: JSON.stringify({ ...JSON.parse(valid.body), ...extra }) };
  assert.throws(() => normalizeLogRecord(duplicate));
}
for (const bad of [{ ...valid, time_unix_nano: '0' }, { ...valid, time_unix_nano: '9223372036854775808' },
  { ...valid, attributes: { source: finding.source } }]) assert.throws(() => normalizeLogRecord(bad));
console.log('PASS: no duplicate time/occurrence fields, unchanged remaining Body schema, and downstream metadata mapping.');
