// Logical OTel record representation, not OTLP protobuf JSON or a Body wrapper.
import assert from 'node:assert/strict';
import { inventoryEventId, parseEvent } from './siem-reference.mjs';

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
  const body = JSON.stringify(event);
  const parsed = parseEvent(body);
  return {
    time_unix_nano: eventTimeUnixNano(parsed.observed_at),
    body,
    attributes: {
      event_id: parsed.event_name === 'beacon.security.sbom.inventory'
        ? inventoryEventId(parsed) : parsed.occurrence_id,
      source: parsed.source,
      'event.name': parsed.event_name,
    },
  };
}
