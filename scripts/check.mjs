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
