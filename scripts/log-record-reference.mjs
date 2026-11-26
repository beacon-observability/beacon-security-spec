// Logical OTel record representation, not OTLP protobuf JSON or a Body wrapper.
import { inventoryEventId, parseEvent } from './siem-reference.mjs';

export function logRecord(event) {
  const body = JSON.stringify(event);
  const parsed = parseEvent(body);
  return {
    body,
    attributes: {
      event_id: parsed.event_name === 'beacon.security.sbom.inventory'
        ? inventoryEventId(parsed) : parsed.occurrence_id,
      source: parsed.source,
      'event.name': parsed.event_name,
    },
  };
}
