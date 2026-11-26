// Logical OTel record representation, not OTLP protobuf JSON or a Body wrapper.
import assert from 'node:assert/strict';
import { inventoryEventId, normalize, parseEvent } from './siem-reference.mjs';

export function eventTimeUnixNano(observedAt) {
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,9}))?Z$/.exec(observedAt);
  assert(match, 'event time must be RFC 3339 UTC with at most nanosecond precision');
  const wholeSecond = `${match[1]}.000Z`;
  const millis = Date.parse(wholeSecond);
  assert(Number.isSafeInteger(millis), 'invalid event time');
  assert.equal(new Date(millis).toISOString(), wholeSecond, 'invalid calendar date');
  const nanos = BigInt(millis) * 1000000n + BigInt((match[2] ?? '').padEnd(9, '0'));
  assert(nanos > 0n && nanos <= 9223372036854775807n, 'event time outside receiver int64 range');
  return nanos.toString();
}

export function logRecord(event) {
  const parsed = parseEvent(JSON.stringify(event));
  const { observed_at, occurrence_id, ...payload } = parsed;
  const body = JSON.stringify(payload);
  return {
    time_unix_nano: eventTimeUnixNano(observed_at),
    body,
    attributes: {
      event_id: parsed.event_name === 'beacon.security.sbom.inventory'
        ? inventoryEventId(parsed) : occurrence_id,
      source: parsed.source,
      'event.name': parsed.event_name,
    },
  };
}

// Optional downstream adapter. Callers validate the full log Body schema first.
// The received Body is never rewritten in message.
export function normalizeLogRecord(record, resource = {}, context = {}) {
  assert.equal(typeof record.body, 'string');
  assert(!/[\r\n]/.test(record.body));
  const body = JSON.parse(record.body);
  assert(body && typeof body === 'object' && !Array.isArray(body));
  assert(!('observed_at' in body) && !('occurrence_id' in body) && !('event_id' in body));
  assert.equal(typeof record.time_unix_nano, 'string');
  assert.match(record.time_unix_nano, /^[1-9][0-9]{0,18}$/);
  const nanos = BigInt(record.time_unix_nano);
  assert(nanos <= 9223372036854775807n);
  const seconds = nanos / 1000000000n;
  const fraction = (nanos % 1000000000n).toString().padStart(9, '0');
  const date = new Date(Number(seconds * 1000n)).toISOString().slice(0, 19);
  const time = `${date}.${fraction.endsWith('000000') ? fraction.slice(0, 3) : fraction}Z`;
  assert.equal(record.attributes.source, body.source);
  assert.equal(typeof record.attributes.event_id, 'string');
  assert(record.attributes.event_id.length > 0);
  const inventory = body.event_name === 'beacon.security.sbom.inventory';
  if (inventory) assert.match(record.attributes.event_id, /^inventory-[0-9a-f]{64}$/);
  const logical = { ...body, observed_at: time,
    ...(inventory ? {} : { occurrence_id: record.attributes.event_id }) };
  return { ...normalize(JSON.stringify(logical), resource, context), time,
    event_id: record.attributes.event_id, message: record.body };
}
