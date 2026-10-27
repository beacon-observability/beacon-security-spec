import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const json = (path) => JSON.parse(readFileSync(resolve(root, path), 'utf8'));

const schema = json('schemas/beacon-security-event-v1.schema.json');
assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema');
assert.match(schema.$id, /beacon-security-event-v1\.schema\.json$/);

const replacement = '\uFFFD';
const scalar = (value) => {
  let result = '';
  for (let index = 0; index < value.length; index += 1) {
    const current = value.charCodeAt(index);
    if (current >= 0xD800 && current <= 0xDBFF) {
      const next = index + 1 < value.length ? value.charCodeAt(index + 1) : -1;
      if (next >= 0xDC00 && next <= 0xDFFF) {
        result += value[index] + value[index + 1];
        index += 1;
      } else result += replacement;
    } else if (current >= 0xDC00 && current <= 0xDFFF) result += replacement;
    else result += value[index];
  }
  return result;
};

function fingerprint(input) {
  const fields = ['role', 'function', 'location', 'operation', 'path_role', 'input_part'];
  const signatures = [...new Set(input.source_signatures)].sort();
  const segments = [
    '1', input.application_id, input.language, input.rule,
    ...fields.map((field) => input.sink[field]), ...signatures,
  ];
  const hash = createHash('sha256');
  for (const segment of segments) {
    const bytes = Buffer.from(scalar(segment), 'utf8');
    const length = Buffer.alloc(4);
    length.writeUInt32BE(bytes.length);
    hash.update(length);
    hash.update(bytes);
  }
  return `finding-${hash.digest('hex')}`;
}

const vectors = json('test-vectors/fingerprint-v1.json');
assert.equal(vectors.fingerprint_version, 1);
for (const vector of vectors.vectors) assert.equal(fingerprint(vector.input), vector.expected, vector.name);

const finding = json('examples/finding-v1.json');
assert.equal(finding.schema_version, 1);
assert.equal(finding.source, 'beacon_security');
assert.equal(finding.event_name, 'beacon.security.finding');
assert.equal(finding.fingerprint_version, 1);
assert.equal(finding.finding_id, vectors.vectors[0].expected);
assert.match(finding.application_id, /^app-[0-9a-f]{64}$/);
assert.deepEqual(
  finding.sources.map(({ type, name }) => `${type}|${name}`).sort(),
  [...new Set(vectors.vectors[0].input.source_signatures)].sort(),
);

const sbom = json('examples/sbom-snapshot-v1.json');
assert.equal(sbom.schema_version, 1);
assert.equal(sbom.source, 'beacon_security_sbom');
assert.equal(sbom.event_name, 'beacon.security.sbom.snapshot');
assert.equal(sbom.part_index, 0);
assert.ok(sbom.part_count >= 1);
assert.equal(sbom.component_count, sbom.dependencies.length);

console.log('PASS: Beacon Security schema JSON, examples, and fingerprint v1 vectors are consistent.');

const occurrence = json('examples/finding-occurrence-v1.json');
assert.equal(occurrence.finding_id, finding.finding_id);
assert.notEqual(occurrence.evidence_id, finding.evidence_id);
assert.equal(occurrence.occurrence_id, occurrence.evidence_id);
assert.equal(occurrence.evidence_sampled, false);
assert.equal(occurrence.truncated, true);
for (const field of ['sources', 'propagation', 'ranges', 'stack']) {
  assert.deepEqual(occurrence[field], []);
}
assert.deepEqual(schema.$defs.attackEvidence.properties.status.enum,
  ['unknown', 'no_evidence', 'suspected']);
for (const event of [finding, occurrence]) {
  assert.equal(event.attack_evidence.outcome, 'not_assessed');
  assert(schema.$defs.attackEvidence.properties.status.enum.includes(event.attack_evidence.status));
  for (const field of schema.$defs.finding.allOf[1].required) assert(field in event, field);
}
console.log('PASS: occurrence sampling and request-specific attack evidence examples.');

// V2 is additive to this repository; keep all v1 validation and vectors above unchanged.
const schema2 = json('schemas/beacon-security-event-v2.schema.json');
assert.equal(schema2.$schema, schema.$schema);
assert.match(schema2.$id, /beacon-security-event-v2\.schema\.json$/);
assert.equal(schema2.$defs.finding.properties.schema_version.const, 2);
assert.equal(schema2.$defs.inventory.properties.schema_version.const, 2);
assert.deepEqual(schema2.$defs.finding.properties.attack_evidence.properties.status.enum,
  ['unknown', 'no_evidence', 'suspected']);
assert.deepEqual(schema2.$defs.finding.properties.attack_evidence.required, ['status', 'reason']);
assert.equal(schema2.$defs.finding.additionalProperties, false);
assert.equal(schema2.$defs.inventory.additionalProperties, false);

const finding2 = json('examples/finding-v2.json');
const occurrence2 = json('examples/finding-occurrence-v2.json');
const inventory2 = json('examples/sbom-inventory-v2.json');
for (const event of [finding2, occurrence2, inventory2]) {
  assert.equal(event.schema_version, 2);
  assert.match(event.instance_id, /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/);
  assert(Number.isFinite(Date.parse(event.observed_at)));
  assert(!('application_id' in event));
  const definition = event.event_name === 'beacon.security.finding'
    ? schema2.$defs.finding : schema2.$defs.inventory;
  for (const key of definition.required) assert(key in event, key);
  for (const key of Object.keys(event)) assert(key in definition.properties, key);
}
for (const event of [finding2, occurrence2]) {
  assert.equal(event.finding_id, finding.finding_id);
  assert.equal(event.fingerprint_version, 1);
  assert(!('evidence_id' in event));
  assert(!('outcome' in event.attack_evidence));
  assert.equal(typeof event.evidence_sampled, 'boolean');
  assert.equal(typeof event.collection_complete, 'boolean');
  const normalizedSink = Object.fromEntries(['role', 'function', 'location', 'operation',
    'path_role', 'input_part'].map((field) => [field, event.sink[field] ?? '']));
  assert.equal(fingerprint({ ...vectors.vectors[0].input, sink: normalizedSink }), event.finding_id);
}
assert.notEqual(finding2.occurrence_id, occurrence2.occurrence_id);
assert.equal(occurrence2.evidence_sampled, false);
assert.equal(occurrence2.evidence_sample_reason, 'interval');
assert.equal(occurrence2.collection_complete, true);
assert(!('truncated' in occurrence2));
for (const field of ['sources', 'propagation', 'ranges', 'stack']) assert(!(field in occurrence2));
assert.equal(inventory2.source, 'beacon_security_sbom');
assert.equal(inventory2.event_name, 'beacon.security.sbom.inventory');
assert.equal(typeof inventory2.uptime_ms, 'number');
assert(Number.isSafeInteger(inventory2.uptime_ms) && inventory2.uptime_ms >= 0);
assert.equal(Date.parse(inventory2.observed_at) - Date.parse(inventory2.started_at), inventory2.uptime_ms);
assert(!('part_index' in inventory2));
assert(!('part_count' in inventory2));
assert(!('status' in inventory2));
assert(!('error' in inventory2));
console.log('PASS: schema v2 inventory, compact occurrence examples, and unchanged fingerprint v1.');
