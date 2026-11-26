# Security log binding

## Producer contract

Export each Security finding or dependency inventory event as one OTel LogRecord.
The string Body contains the v2 event JSON object with exactly two metadata fields
moved out at the export boundary:

| Logical input | Only transmitted location | Body rule |
| --- | --- | --- |
| `observed_at` | Native `time_unix_nano`. | Omit `observed_at`; do not add another Body timestamp for the same instant. |
| Finding `occurrence_id` | LogRecord `attributes.event_id`. | Omit `occurrence_id`; do not add `event_id` to the Body. |

These are field moves, not copies. The remaining fields, values, types, and nested
structure MUST remain unchanged. Keep `schema_version` at the top level. Do not
wrap the event in a SIEM envelope or put it inside `message`. Existing evidence
sampling and declared truncation apply before serialization; fingerprint v1 is
unchanged. No new service, runtime, or Resource maps are introduced in the Body.
This correction does not relocate `source` or any other existing Body field.

The Body MUST be compact, single-line JSON: no indentation, literal CR/LF, or
trailing newline. Escape newlines within string values without changing the decoded
value. Each Body contains exactly one object, never an array, multiple concatenated
JSON lines, or a double-encoded JSON string. A JSONL file sink adds one LF delimiter
outside the Body. A standalone Body-only file no longer contains event time or the
finding occurrence ID; a diagnostic sink that needs them must explicitly retain
native timestamp and attributes outside Body. Do not silently reinsert duplicates
into the OTLP Body to support a file format.

## Event timestamp

The event time is the instant represented by logical input `observed_at`. Producers
MUST set native OTel LogRecord `time_unix_nano` from that instant, then omit
`observed_at` from the transmitted Body. It is a native LogRecord field, not an
attribute or an extra JSON member in Body. Native event time is the sole wire
representation of this instant.

OTLP defines this timestamp as an unsigned 64-bit integer. This binding restricts
it to `1..9223372036854775807` for signed-int64 receivers. Zero means unset and is
not valid for new records. Invalid or unrepresentable times must fail export
explicitly rather than use queue flush time or wrap on conversion. Use integer
arithmetic: seconds times `1000000000` plus fractional nanoseconds, or epoch
milliseconds times `1000000` for a millisecond source. Retain available precision
up to nine fractional digits; do not send milliseconds in the nanosecond field or
invent sub-millisecond precision.

Native `observed_time_unix_nano` is the time the OTel collection system observed
the record, a separate lifecycle instant. It must not replace known event time.
Queueing, retries, and batch flushing MUST NOT change event time. Receivers prefer
`time_unix_nano`, falling back to `observed_time_unix_nano` only for older records
with unset event time, following the [OTel log data model](https://opentelemetry.io/docs/specs/otel/logs/data-model/).
New records always set event time; receivers must not require Body `observed_at`.

For example, `2026-10-02T00:00:00.000Z` becomes native nanoseconds
`1790899200000000000`. Logical JSON examples use a decimal string to avoid
JavaScript Number precision loss; the OTLP protobuf field remains a 64-bit integer,
consistent with [ProtoJSON's integer mapping](https://protobuf.dev/programming-guides/json/).
This preserves the instant and its precision, not the original timestamp spelling.

## LogRecord attributes

The following string attributes are required on each record:

| Attribute | Finding | Dependency inventory |
| --- | --- | --- |
| `event_id` | Logical input `occurrence_id`, moved without changing its value. | Deterministic inventory ID below. |
| `source` | `beacon_security`, matching the retained Body `source`. | `beacon_security_sbom`, matching the retained Body `source`. |

These are LogRecord attributes, not Resource attributes and not an `attributes`
member inserted in Body. Existing native event name and `event.name` remain
unchanged. The fifteen SIEM fields are not required producer attributes.

For findings, `event_id` and logical `occurrence_id` mean the same occurrence.
Transmit that value only as `attributes.event_id`; do not generate a second ID.
A new occurrence in another request has a new value; retransmission retains the
same value. `finding_id` is a stable fingerprint shared by multiple occurrences.
`instance_id` and Resource `service.instance.id` describe process/service-instance
identity, not occurrences. They must not replace the per-event ID, and per-event
IDs must not be placed in Resource.

Inventory has no `occurrence_id`. Its `event_id` identifies a collection round and
part. Preserve the existing algorithm: before removing `observed_at`, encode this
ordered array of logical input strings as compact UTF-8 JSON:

```text
[source, event_name, instance_id, observed_at, decimal_part_index]
```

Use zero-based decimal part index without leading zeros, or `"0"` for an
unpartitioned event; literal non-ASCII Unicode scalars and required JSON escapes
only. Prefix the lowercase SHA-256 digest with `inventory-`. This is the unchanged
[SIEM identity algorithm](siem-fields-v1.md#event-identity-and-aggregation), computed
before wire compaction. Receivers retain the supplied ID rather than recomputing
it from a reformatted timestamp. Identical retransmissions retain the ID; rounds
and parts have different IDs. Preserve metadata across retries.

## Transport, receivers, and byte budgets

Keep the existing OTLP transport, endpoint, Resource, Scope, INFO severity, and
native trace/span associations. `span_id` still means the span active at detection;
absent context is not fabricated. Emit no duplicate occurrence.

Receivers read time from native `time_unix_nano` and the per-event ID from
`attributes.event_id`. Parse Body once and read all remaining v2 fields at their
existing paths, including `schema_version`, `event_name`, `attack_evidence`, and
`dependencies`. The only removed Body fields are `observed_at` and `occurrence_id`.
Inventory assembly uses Body `instance_id` plus native event time and Body
`part_index/part_count`. Parts of one collection retain identical native event
time. Missing parts do not clear prior inventory; older rounds do not overwrite
newer completed rounds. Body `started_at` and `uptime_ms` retain their separate
process-start/uptime meanings.

Byte limits, queue accounting, and inventory multipart planning MUST use final
compact UTF-8 Body bytes after these field moves. Attributes and native metadata
also count toward whole-record/request limits. Do not silently truncate Body to
accommodate metadata. Partitioning retains every dependency exactly once.
An optional [SIEM downstream projection](siem-fields-v1.md) must read event time
and ID from native metadata, preserving the received Body exactly in `message`.
It is never the producer Body.

## Schemas, conformance, and migration

The [v2 event schema](../schemas/beacon-security-event-v2.schema.json) continues to
describe the full logical input and historical complete v2 JSON. Validate the new
transmitted Body against the dedicated [log Body schema](../schemas/beacon-security-log-body-v1.schema.json),
which removes only the two moved fields. This transport binding is identified in
pinned implementation provenance; `schema_version=2` alone does not distinguish
historical complete events from this bound Body. Do not silently repurpose the
historical schema or claim unchanged receiver paths for the moved fields.

The [reference binding](../scripts/log-record-reference.mjs),
[examples](../examples/log-records/), and [logical-record schema](../schemas/beacon-security-log-record-v1.schema.json)
use logical `time_unix_nano`, `body`, and `attributes` fields for conformance.
This is not a new Body wrapper or a complete OTLP protobuf JSON representation.

Acceptance must cover absence of duplicate time/occurrence fields, original paths
for retained fields, exact timestamps and IDs across retries, escaped/non-ASCII
values, sampling/truncation, multipart assembly, final byte budgets, and an actual
OTLP-to-receiver path. Reference checks do not prove runtime/backend compatibility.

Updating this specification does not repair released runtimes. Coordinate receiver
and producer adoption of the two explicit field moves; do not require `message`
wrapping or rewrite historical stored records. Historical Body-only archives need
their original decoder; new Body-only archives cannot supply omitted metadata.
