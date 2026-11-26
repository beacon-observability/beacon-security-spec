// Optional downstream SIEM mapping; never use this envelope as the producer Body.
// Not a runtime exporter or a trust-boundary validator.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { isIP } from 'node:net';

const nonempty = (value) => typeof value === 'string' && value.trim() !== '' ? value : '';

export function inventoryEventId(body) {
  const input = [body.source, body.event_name, body.instance_id, body.observed_at,
    String(body.part_index ?? 0)];
  return `inventory-${createHash('sha256').update(JSON.stringify(input), 'utf8').digest('hex')}`;
}

export function parseEvent(raw) {
  assert.equal(typeof raw, 'string');
  const body = JSON.parse(raw);
  assert(body && typeof body === 'object' && !Array.isArray(body));
  assert.equal(body.schema_version, 2);
  const inventory = body.event_name === 'beacon.security.sbom.inventory';
  assert(inventory || body.event_name === 'beacon.security.finding');
  assert.equal(body.source, inventory ? 'beacon_security_sbom' : 'beacon_security');
  // Callers must validate the full v2 payload before conversion; these checks cover mapping inputs.
  assert.match(body.instance_id, /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/);
  assert.equal(typeof body.observed_at, 'string');
  assert(body.observed_at.endsWith('Z') && Number.isFinite(Date.parse(body.observed_at)));
  if (inventory) {
    assert(Array.isArray(body.dependencies));
    if ('part_index' in body || 'part_count' in body) {
      assert(Number.isSafeInteger(body.part_index) && body.part_index >= 0);
      assert(Number.isSafeInteger(body.part_count) && body.part_count >= 2);
      assert(body.part_index < body.part_count);
    }
  } else {
    assert(nonempty(body.occurrence_id));
    assert.match(body.finding_id, /^finding-[0-9a-f]{64}$/);
    assert(nonempty(body.rule));
  }
  assert(!('server_span_id' in body));
  assert(!('current_span_id' in body));
  if ('span_id' in body) assert.match(body.span_id, /^[0-9a-f]{16}$/);
  if ('trace_id' in body) assert.match(body.trace_id, /^[0-9a-f]{32}$/);
  if ('trace_flags' in body) assert(Number.isInteger(body.trace_flags) && body.trace_flags >= 0 && body.trace_flags <= 255);
  return body;
}

export function normalize(raw, resource = {}, context = {}) {
  const body = parseEvent(raw);
  const inventory = body.event_name === 'beacon.security.sbom.inventory';
  const ip = nonempty(context.client_ip);
  return {
    time: body.observed_at,
    event_id: inventory ? inventoryEventId(body) : body.occurrence_id,
    event_class: inventory ? 'software_inventory_info' : 'security_finding',
    source: body.source,
    service: nonempty(resource['service.name']),
    tenant_id: nonempty(context.tenant_id) || nonempty(resource['tenant.id']) || 'default',
    actor: inventory ? '' : nonempty(context.actor),
    ip: inventory || !isIP(ip) ? '' : ip,
    action: inventory ? 'inventory_snapshot' : body.rule,
    target: inventory ? body.instance_id : body.finding_id,
    target_type: inventory ? 'process' : 'finding',
    outcome: inventory ? 'success' : 'unknown',
    status: 'info',
    severity: 'informational',
    message: raw,
    ...Object.fromEntries(['instance_id', 'trace_id', 'span_id', 'trace_flags']
      .filter(key => key in body).map(key => [key, body[key]])),
  };
}
