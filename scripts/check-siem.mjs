import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { inventoryEventId, normalize } from './siem-reference.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const read = (path) => readFileSync(resolve(root, path), 'utf8');
const json = (path) => JSON.parse(read(path));
const schema = json('schemas/beacon-security-siem-v1.schema.json');
const vectors = json('test-vectors/siem-v1.json');
const fields = ['time', 'event_id', 'event_class', 'source', 'service', 'tenant_id',
  'actor', 'ip', 'action', 'target', 'target_type', 'outcome', 'status', 'severity', 'message'];
assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema');
assert.match(schema.$id, /beacon-security-siem-v1\.schema\.json$/);
assert.deepEqual(schema.required, fields);
assert.deepEqual(Object.keys(schema.properties), fields);
assert.equal(schema.additionalProperties, false);
assert.equal(vectors.profile, 'beacon-security-siem-v1-draft');

for (const vector of vectors.vectors) {
  const raw = read(vector.input);
  const expected = json(vector.expected);
  const actual = normalize(raw, vector.resource, vector.context);
  assert.deepEqual(actual, expected, vector.name);
  assert.deepEqual(Object.keys(actual), fields, vector.name);
  for (const field of fields) {
    const definition = schema.properties[field];
    assert.equal(typeof actual[field], definition.type, `${vector.name}: ${field}`);
    if ('const' in definition) assert.equal(actual[field], definition.const);
    if (definition.enum) assert(definition.enum.includes(actual[field]));
    if (definition.minLength) assert(actual[field].length >= definition.minLength);
  }
  const families = schema.oneOf.filter(({ properties }) => Object.entries(properties)
    .every(([key, definition]) => (!('const' in definition) || actual[key] === definition.const)
      && (!definition.enum || definition.enum.includes(actual[key]))
      && (!definition.pattern || new RegExp(definition.pattern).test(actual[key]))));
  assert.equal(families.length, 1, vector.name);
  assert.equal(actual.message, raw);
  assert.equal(JSON.parse(JSON.stringify(actual)).message, raw);
  assert.deepEqual(JSON.parse(actual.message), JSON.parse(raw));
}

const findingRaw = read('examples/finding-v2.json');
const finding = JSON.parse(findingRaw);
const absent = normalize(findingRaw);
for (const key of ['service', 'actor', 'ip']) assert.equal(absent[key], '');
assert.equal(absent.tenant_id, 'default');
assert.equal(normalize(findingRaw, { 'tenant.id': ' ' },
  { tenant_id: '' }).tenant_id, 'default');
assert.equal(absent.event_id, finding.occurrence_id);
assert.equal(absent.target, finding.finding_id);
assert.notEqual(absent.event_id, absent.target);
for (const status of ['unknown', 'no_evidence', 'suspected']) {
  for (const code of [200, 403, 500]) {
    const body = { ...finding, attack_evidence: { status, reason: 'test' },
      request: { status_code: code }, triage: { decision: 'accepted_risk' } };
    const converted = normalize(JSON.stringify(body));
    assert.equal(converted.outcome, 'unknown');
    assert.equal(converted.status, 'info');
    assert.equal(converted.severity, 'informational');
  }
}
const escapedRaw = ` \n${JSON.stringify({ ...finding,
  stack: ['订单\\目录"query"\n下一行', '\u2028'],
})}\t\n`;
assert.equal(normalize(escapedRaw).message, escapedRaw);
const escapedSpelling = findingRaw.replace('sql_injection', 'sql_\\u0069njection');
assert.equal(normalize(escapedSpelling).action, 'sql_injection');
assert.equal(normalize(escapedSpelling).message, escapedSpelling);
for (const client_ip of ['192.0.2.10:443', 'proxy.example', 'unknown', 'not-an-ip']) {
  assert.equal(normalize(findingRaw, {}, { client_ip }).ip, '');
}
assert.equal(normalize(findingRaw, {}, { client_ip: '2001:db8::1' }).ip, '2001:db8::1');
assert.equal(normalize(findingRaw, { 'tenant.id': 'configured' },
  { tenant_id: ' ' }).tenant_id, 'configured');

const inventory = json('examples/sbom-inventory-v2.json');
assert.equal(inventoryEventId(inventory), inventoryEventId({ ...inventory, part_index: 0 }));
assert.notEqual(inventoryEventId(inventory), inventoryEventId({ ...inventory, part_index: 1 }));
assert.notEqual(inventoryEventId(inventory), inventoryEventId({ ...inventory,
  observed_at: '2026-10-02T00:25:00.000Z' }));
assert.equal(inventoryEventId(inventory), inventoryEventId({ ...inventory, dependencies: [] }));
const inv = normalize(JSON.stringify(inventory), {}, { actor: 'user', client_ip: '192.0.2.1' });
assert.equal(inv.actor, '');
assert.equal(inv.ip, '');
for (const malformed of ['null', '[]', '{', JSON.stringify({ ...finding, schema_version: 1 }),
  JSON.stringify({ ...finding, source: 'other' }),
  JSON.stringify({ ...inventory, part_index: 2, part_count: 2 })]) {
  assert.throws(() => normalize(malformed));
}
console.log(`PASS: draft SIEM profile, ${vectors.vectors.length} reference vectors, raw preservation, IDs, and semantic boundaries.`);
