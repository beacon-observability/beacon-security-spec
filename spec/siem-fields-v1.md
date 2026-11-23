# Security SIEM profile v1

## Status and scope

This is the language-neutral Security export contract. Current producers MUST emit
one SIEM envelope per event on the existing route, with fifteen required base
fields and available process/trace correlation. It is the only current output
format; no format-selection switch or legacy output mode is provided. The complete
serialized v2 evidence remains in `message`. Fingerprint v1 is unchanged.

The [JSON Schema](../schemas/beacon-security-siem-v1.schema.json),
[examples](../examples/siem/), [conformance vectors](../test-vectors/siem-v1.json)
and [reference transformation](../scripts/siem-reference.mjs) define the contract.
Runtime releases and backend acceptance require separate implementation evidence.
Changing this standard does not upgrade already released runtimes.

The target field set comes from the user-provided RunReveal pipeline catalog v8
(`runreveal-pipeline-catalog-v8.html`, catalog date 2026-11-21). The local catalog is an input to
this proposal, not a claim that RunReveal, DataKit, or another backend implements this profile.

## Transformation boundary and raw preservation

The input consists of one serialized Security v2 event and its associated Resource and trusted
ingestion context. Parse a copy of the event. `message` MUST retain the complete input string,
including whitespace, member order, escape spelling, and non-ASCII characters. Do not replace it
with a summary, parsed object, selected properties, or a reserialized equivalent. JSON escaping
in the enclosing record is necessary: after decoding the envelope, `message` MUST equal the input
string exactly. Inputs MUST be valid UTF-8 JSON objects conforming to the applicable v2 contract.
Invalid or unsupported inputs MUST NOT be relabeled as a successful profile conversion.

For an Agent implementation, the input is the v2 event serialized at its existing export boundary,
after its existing evidence sampling and declared truncation. For a Collector implementation, it
is the received LogRecord's string Body. The profile does not recover data the producer did not
collect, sampled out, truncated, or dropped. It must not introduce another silent truncation of
`message`; a conversion that cannot fit its configured budget must be rejected or handled by an
explicit, documented overflow path, never reported as lossless.

Preserving the Body does not preserve the entire OTLP record. Transport Resource, Scope,
attributes, and timestamps must remain in their transport context or be separately archived if
full-record preservation is required. Do not claim full OTLP archival from `message` alone.

## Required fields

The fifteen base fields below MUST be present and have a string value. Missing identities use `""`, except `tenant_id`, which defaults to `"default"`;
unassessed outcomes use `"unknown"`. No top-level `schema_version` or legacy field alias is added. The correlation
fields below are retained when available. Record the profile/version in implementation
provenance; consumers MUST NOT infer
it from `message.schema_version`, which identifies the embedded payload only.

In this table `body` denotes the parsed input, `resource` denotes the associated OTel Resource,
and `context` denotes trusted enrichment bound to that particular event. Resource keys containing
dots are literal keys, not nested JSON paths.

| Field | Finding | Dependency inventory |
| --- | --- | --- |
| `time` | `body.observed_at` | `body.observed_at` |
| `event_id` | `body.occurrence_id` | Deterministic inventory ID defined below. |
| `event_class` | `security_finding` | `software_inventory_info` |
| `source` | `beacon_security` | `beacon_security_sbom` |
| `service` | `resource["service.name"]`, or `""` if unavailable. | Same. |
| `tenant_id` | Trusted `context.tenant_id`, then explicitly configured `resource["tenant.id"]`, otherwise `"default"`. | Same. |
| `actor` | Verified request principal from `context.actor`, otherwise `""`. | `""` (no request actor). |
| `ip` | Request client address from `context.client_ip`, otherwise `""`. | `""` (no request client). |
| `action` | `body.rule`, e.g. `sql_injection`. | `inventory_snapshot` |
| `target` | `body.finding_id` | `body.instance_id` |
| `target_type` | `finding` | `process` |
| `outcome` | `unknown` | `success` |
| `status` | `info` | `info` |
| `severity` | `informational` | `informational` |
| `message` | Complete original input string. | Complete original input string. |

`time` MUST preserve the event's RFC 3339 UTC observation timestamp. It is not the ingestion time,
OTel API emission time, or process start time. A DataKit binding maps this field to the Point
timestamp and `source` to the measurement. This binding does not add a sixteenth ordinary field.

### Event identity and aggregation

Finding `event_id` is an occurrence ID, not a finding fingerprint, Trace ID, or service ID.
Consumers deduplicate within `tenant_id + source + instance_id + event_id`; `instance_id` is read
from `message`. The tenant boundary is enforced by the receiving system even when the exported
tenant field is `"default"`. A different request can have the same `target` but a different `event_id`.
Fingerprint computation and the stable `finding_id` MUST NOT change as a result of projection.

For inventory, build the following ordered array of strings:

```text
[body.source, body.event_name, body.instance_id, body.observed_at, decimal_part_index]
```

`decimal_part_index` is the zero-based index rendered as decimal with no leading zeros; use `"0"`
when the event is not multipart. Encode the array as compact UTF-8 JSON: no separator whitespace,
literal non-ASCII Unicode scalars, required JSON string escapes only. Compute SHA-256 of those
bytes and use `inventory-` followed by the lowercase hexadecimal digest. Do not use delimiter
concatenation, random IDs, platform-specific array formatting, or a hash of the dependency list.
Identical retransmissions keep their ID; different rounds or part indices have different IDs.

Consumers still assemble inventory using `instance_id + observed_at` and `part_index/part_count`
from `message`. They MUST NOT overwrite the previous list until every part is present, or apply
an older round over a newer completed round. A successful empty list retains its v2 meaning.

### Action and target semantics

Finding `action` describes the detected rule, not an assertion that an attack executed. `target`
identifies the finding being reported. It does not identify the database, destination URL, shell
command, or file touched by a sensitive invocation. `sink.function` and `sink.location` remain
in `message` as evidence and MUST NOT be mislabeled as actual destination resources.

This profile deliberately uses one stable target definition per family. Actual operation targets
need a separately specified collection and normalization contract; arbitrary fallbacks between
finding IDs, URLs, code locations, and components would make the field's meaning unstable.

### Outcome, log status, and severity

The baseline producer reports an attempted source-to-sink invocation and does not establish its
completion, exploit success, or a prevention decision. All finding outcomes therefore remain
`unknown`, regardless of HTTP response code or `attack_evidence.status`.

- `suspected` is not operation success, an allowed decision, or a confirmed exploit.
- `no_evidence` is not failure, a denied decision, or proof of safety.
- `unknown` preserves uncertainty; all three classes remain reportable.
- `request.status_code=200` does not prove exploit or sink success; HTTP errors do not prove
  prevention either. `triage.decision` is a review decision, not an execution outcome.

Inventory `success` means successful local dependency collection, not complete dependency
coverage, successful transmission, backend persistence, or freedom from vulnerabilities. Failed
collections still emit no inventory. Consumers must not infer health from silence.

`status=info` reflects the existing OTel INFO log level. Following the catalog's level conversion,
`severity=informational` also reflects that log level; this contract does not claim an assessed risk
severity. Inferring high/critical risk from a rule name, a suspected feature, or the presence of a
finding is forbidden. A future risk grading contract must define its source and assessment rules
and explicitly revise this baseline before emitting different values.

### Enrichment and absent information

Trusted ingestion tenant binding takes precedence over application Resource values. Neither an
arbitrary request header nor a claimed tenant ID can establish tenant authorization. Empty
context values fall through to the next candidate; if none is available, use `"default"`.
`"default"` is a placeholder for unspecified tenant identity, not an authorization or isolation
boundary. This profile does not require additional tenant collection. Do not substitute a process
UUID, hostname, or service name for a tenant identity.

`actor` is an authenticated request user or service principal; it is not the Java process OS user,
Agent name, class name, or parameter name. `ip` is a validated IPv4/IPv6 address without a port.
It is not the destination address or Collector peer address. Resolve proxy headers using a
documented trusted-proxy policy; an untrusted forwarded header alone is insufficient. This profile
does not require new authentication hooks or collection of raw request parameters. If verified
request enrichment is unavailable, use the empty string and document the implementation gap.

## Process and trace correlation

Retain `instance_id` from the embedded event at the top level. Preserve available
`trace_id`, `span_id`, and `trace_flags` with their original values and types.
`trace_id` has 32 lowercase hexadecimal characters; `span_id` has 16.
`trace_flags` is an integer in 0..255, not a string. These fields extend the
fifteen base fields and count toward final serialized byte budgets.

`span_id` is the span active at detection, even when it is the request-entry
span. Omit it if unavailable; do not substitute a different span or fabricate
trace context for inventory. Associate the OTel LogRecord with that same span.
Neither the envelope nor current evidence emits `server_span_id` or
`current_span_id`; these fields have no aliases. Historical stored records
remain unchanged, but are not a current producer output mode.

## What renaming alone cannot supply

| Item | Available from existing v2 events? | Required follow-up |
| --- | --- | --- |
| Service name | Resource only; absent from compact Body. | Bind the associated Resource before projection. |
| Tenant identity | No standard v2 payload field. | Use existing trusted binding or configured `tenant.id` if available; otherwise `"default"`. No additional collection is required. |
| Request actor | No authenticated principal field. | Use existing verified per-event enrichment if available; otherwise empty. No additional collection is required. |
| Request client IP | Not in v2 request context. | Use an existing trusted, validated client address if available; otherwise empty. No additional collection is required. |
| Actual operation target | Sink code location is not a resource address. | A future resource-target contract; baseline target remains the finding/process. |
| Finding execution outcome | An invocation attempt is not its completion. | A future completion/prevention observation contract; baseline remains unknown. |
| Assessed risk severity | INFO is a log level; v2 has no risk grading. | A future risk grading contract; baseline remains informational log severity. |
| Entire OTLP record | `message` retains the Body only. | Preserve transport context or archive the complete incoming record separately. |

Implementations MUST document these gaps rather than claim that adding fifteen non-empty strings
establishes complete SIEM semantics. Projection alone does not authorize or implement new runtime
instrumentation.

## Data retained inside message

The original event continues to carry `schema_version`, `event_name`, `instance_id`,
`finding_id`, `fingerprint_version`, `trace_id` / `span_id`, request/sink context, attack-evidence status
and reason, source/propagation/range/stack evidence, component metadata, sampling flags/reasons,
collection quality, coverage gaps, truncation markers, and optional run/triage context as present.
Inventory retains dependencies, start time, uptime, and optional part metadata. Their v2 semantics
are unchanged. Current producer findings use `span_id` for the current invocation and omit
`server_span_id` / `current_span_id`; a span equal to the server span is retained. Historical
messages remain original and are never rewritten by projection. Optional absence is not replaced with invented values. No additional sensitive
parameter values, SQL, command content, or URLs are introduced by the normalization itself.

## Transport, budgets, and migration

OTel retains the existing scope and native event name / `event.name` / `source` attributes,
INFO severity, and string Body. The Body is the serialized
SIEM envelope, whose `message` is the original v2 payload string. Existing contextual
Resource and Span associations remain intact. Do not emit the profile a second time as a
parallel copy of the same occurrence on the same route.

The envelope adds identity fields and JSON escaping overhead. Size limits, queue byte accounting,
and multipart planning MUST use final serialized envelope bytes, including `message` escaping
and enrichment. Splitting an inventory must retain every dependency exactly once. A collector
must preserve enrichment before cleaning incoming attributes; an Agent must obtain service and
tenant identity before removing duplicated Resource maps from its v2 payload.

Existing v2 consumers must explicitly adopt this profile and parse `message` for detailed evidence
and inventory assembly. They cannot require `event_name`, `observed_at`, `occurrence_id`, or
`dependencies` at the envelope top level. Existing stored records are not rewritten. Historical
v2 JSON Schema validates the embedded event, not the envelope. Preserve old schemas and vectors;
do not silently repurpose them for a different shape.

Before adoption, each implementation must publish evidence for exact raw preservation, field
semantics and absent enrichment, stable IDs, sampled/truncated events, escaped/non-ASCII inputs,
final byte budgets, multipart assembly, and one real OTel-to-collector path. Neither this contract
nor its reference-vector checks establish production support or backend acceptance.
