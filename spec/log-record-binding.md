# Security log binding

## Producer contract

Each Security finding or dependency inventory event MUST be exported as one OTel
LogRecord. Its string Body MUST contain the original v2 JSON event object with the
same fields, values, types, and nesting. Producers MUST NOT add a SIEM envelope,
move the event into `message`, or rename, remove, or relocate existing event fields
as a side effect of field mapping. In particular, `schema_version` remains at the
Body object's top level. The v2 event schema and fingerprint v1 remain unchanged.
Existing evidence sampling and declared truncation still apply before serialization.

The Body MUST be compact, single-line JSON: no indentation or literal CR/LF line
breaks. Newlines within string values MUST be JSON-escaped (`\n` or `\r`), without
changing the decoded value. This is a serialization requirement, not a change to
the event structure or a requirement to preserve prior pretty-print whitespace.
One Body contains exactly one JSON object, never an array or multiple concatenated
JSON lines. The OTLP Body has no trailing newline. A JSONL file sink writes this
same Body followed by one LF record delimiter; that delimiter is not part of the
Body. Do not double-encode the object as a JSON string containing quoted JSON.

## Event timestamp

The event time is the instant represented by `body.observed_at`. Keep that Body
field as its existing RFC 3339 UTC string; do not change its type to an integer.
Producers MUST set the native OTel LogRecord timestamp (`time_unix_nano` in OTLP)
to that same instant as Unix epoch nanoseconds. This is a native LogRecord field,
not an attribute or an extra field in the Body. A property named `time_unix_nano`
inside the Body or attributes does not set the native timestamp.

OTLP defines this timestamp as an unsigned 64-bit integer. This binding restricts
it to `1..9223372036854775807` for receivers using signed int64 nanoseconds; zero
means unset in OTLP and is not a valid event timestamp here. Invalid or
unrepresentable times must fail export explicitly rather than silently use the
queue flush time or wrap on conversion. Use integer arithmetic: seconds times
`1000000000` plus fractional nanoseconds, or epoch milliseconds times `1000000`
when the source has millisecond precision. Do not send milliseconds in the
nanosecond field or invent sub-millisecond precision. Retain available precision
up to nine fractional digits without floating-point rounding.

The native `observed_time_unix_nano` is the time the OTel collection system
observed the record. It is separate from the Body field named `observed_at` and
must not replace a known event timestamp. Queueing, retries, and batch flushing
MUST NOT change the event time. Consumers should prefer native `time_unix_nano`
and fall back to native `observed_time_unix_nano` only when event time is unset in
older records, following the [OTel log data model](https://opentelemetry.io/docs/specs/otel/logs/data-model/).
Conforming new records always set the event timestamp; receivers do not need to
parse the Body timestamp to determine the Point time.

For example, `2026-10-02T00:00:00.000Z` corresponds to Unix milliseconds
`1790899200000` and native Unix nanoseconds `1790899200000000000`. Logical JSON
examples encode this 64-bit value as a decimal string to avoid JavaScript Number
precision loss. This does not make the protobuf field a string: OTLP/protobuf
carries the 64-bit integer, and SDK implementations should use the appropriate
integer timestamp API. The quoted decimal representation is also consistent with
[ProtoJSON's 64-bit integer mapping](https://protobuf.dev/programming-guides/json/).

## LogRecord attributes

The following string attributes are required on each record:

| Attribute | Finding | Dependency inventory |
| --- | --- | --- |
| `event_id` | Original `body.occurrence_id`. | Deterministic inventory ID below. |
| `source` | `beacon_security`, equal to `body.source`. | `beacon_security_sbom`, equal to `body.source`. |

These are OTel LogRecord attributes, not Resource attributes and not an
`attributes` member inserted into the Body JSON. Retain `source` in the original
Body as well; mapping it to an attribute does not authorize removing it. Do not add
`event_id` to the Body or rename `occurrence_id`. Existing native event name and
`event.name` attribute remain unchanged. Other existing attributes are preserved.
The fifteen SIEM projection fields are not required producer attributes.

For findings, `attributes.event_id` MUST equal `body.occurrence_id` byte for byte.
They identify the same occurrence and are not two independently generated IDs.
`occurrence_id` is the existing Body field; `event_id` is the common transport
attribute shared across event families. A repeated occurrence in another request
has a new value, while retransmission of an existing occurrence retains its value.
`finding_id` identifies the stable finding fingerprint, so multiple occurrences
may share it. Consumers must not substitute `finding_id` for `event_id`.

Inventory events have no `occurrence_id`. Their `event_id` identifies a collection
round and part, rather than a finding occurrence; do not invent an `occurrence_id`
for these events.
For inventory, encode this ordered array as compact UTF-8 JSON and hash its bytes
with SHA-256:

```text
[body.source, body.event_name, body.instance_id, body.observed_at, decimal_part_index]
```

Every element is a string. Use the zero-based part index as decimal without leading
zeros, or `"0"` for an unpartitioned event. Use literal non-ASCII Unicode scalars
and required JSON string escapes only. The ID is `inventory-` followed by the
lowercase hexadecimal digest. Retransmissions retain their ID; different rounds
or parts have different IDs. This is the same identity algorithm as the downstream
[SIEM mapping](siem-fields-v1.md#event-identity-and-aggregation).

## Transport and receiver compatibility

Retain the existing OTLP transport, endpoint, Resource, Scope, INFO
severity, and native trace/span associations. Set the event timestamp as defined
above rather than using export time. `span_id` continues to identify the
span active at detection; absent context is not fabricated. No parallel copy of
the occurrence is emitted. This binding does not prescribe a new protocol or route.

Receivers read `event_id` and `source` from LogRecord attributes, parse Body once
as a JSON object, and access the original v2 paths. For example,
`body.schema_version`, `body.attack_evidence.status`, and `body.dependencies`
retain their existing meaning and position. Inventory assembly continues to use
`instance_id + observed_at` and `part_index/part_count` from that object.

Size limits, queue byte accounting, and inventory multipart planning use the final
compact UTF-8 Body bytes, without SIEM wrapping or JSON-within-JSON escaping overhead.
Transport attributes also count toward any whole-record or OTLP request limit.
Do not silently truncate the Body to accommodate added attributes. Inventory
partitioning must retain every dependency exactly once.

An explicitly configured receiving pipeline may apply the optional
[SIEM field mapping](siem-fields-v1.md) after reading the original event. That
projection is a separate downstream representation, never the producer Body.

## Conformance and migration

The [reference binding](../scripts/log-record-reference.mjs),
[example records](../examples/log-records/), and
[logical-record schema](../schemas/beacon-security-log-record-v1.schema.json)
describe native timestamp and Body/attribute placement. The examples use logical
`time_unix_nano`, `body`, and `attributes` fields, not a complete OTLP protobuf
JSON representation or a new on-wire wrapper.
Validate decoded Body separately against the unchanged v2 event schema.

Runtime acceptance must cover original-path parsing, single-line serialization,
escaped/newline and non-ASCII values, occurrence and inventory IDs, sampling,
truncation, multipart assembly, exact event timestamps across delayed export and
retransmission, final byte budgets, and an actual OTLP-to-receiver
path. Reference checks alone do not establish runtime or backend compatibility.

This corrects the earlier requirement to emit a SIEM envelope. Already released
runtimes that wrap events need a separately tested implementation fix; updating
this specification does not change their output. Do not modify the receiver to
require a `message` wrapper or rewrite historical stored records as part of this
correction. Rollout of runtime fixes must verify the original receiver contract.
