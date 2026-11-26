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

Finding IDs identify individual occurrences, not finding fingerprints or traces.
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

Retain the existing OTLP transport, endpoint, Resource, Scope, timestamps, INFO
severity, and native trace/span associations. `span_id` continues to identify the
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
describe Body/attribute placement. The examples use a logical `body` / `attributes`
representation, not OTLP protobuf JSON field names or a new on-wire wrapper.
Validate decoded Body separately against the unchanged v2 event schema.

Runtime acceptance must cover original-path parsing, single-line serialization,
escaped/newline and non-ASCII values, occurrence and inventory IDs, sampling,
truncation, multipart assembly, final byte budgets, and an actual OTLP-to-receiver
path. Reference checks alone do not establish runtime or backend compatibility.

This corrects the earlier requirement to emit a SIEM envelope. Already released
runtimes that wrap events need a separately tested implementation fix; updating
this specification does not change their output. Do not modify the receiver to
require a `message` wrapper or rewrite historical stored records as part of this
correction. Rollout of runtime fixes must verify the original receiver contract.
