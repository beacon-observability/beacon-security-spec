# Event Contract

## Envelope

Beacon Security events use JSON objects with `schema_version=1`. Except for the explicitly minimal
truncation envelope, every event contains:

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | integer | Event schema version; currently `1`. |
| `source` | string | `beacon_security` or `beacon_security_sbom`. |
| `event_name` | string | Stable event dispatch name. |
| `observed_at` | RFC 3339 UTC string | Time at which the event was observed or created. |
| `application_id` | string | Stable application identity defined by the identity contract. |
| `instance_id` | string | Process/runtime instance identity. |
| `service` | object | Confirmed OpenTelemetry service resource attributes. |
| `code` | object | Confirmed repository, revision, build, and service-version identity. |
| `runtime` | object | Runtime language, implementation, version, OS, architecture, and details. |
| `identity_status` | string | `configured`, `fallback`, or `incomplete`. |

Unknown values stay empty, null, or absent where allowed. Implementations must not invent business
identity or interpret an observation as a confirmed vulnerability.

## OpenTelemetry Logs mapping

- instrumentation scope name: `io.beacon.security`;
- instrumentation scope version: the implementation version;
- severity: `INFO`;
- native event name: equal to body `event_name`;
- `event.name` attribute: equal to body `event_name`;
- `source` attribute: equal to body `source`;
- body: UTF-8 JSON string conforming to the applicable schema.

An OpenTelemetry API call is not Collector receipt or backend acknowledgement. Implementations
must report delivery semantics accurately and must not claim acknowledgement they cannot observe.

## Finding event

`beacon.security.finding` records one modeled source-to-sink runtime observation. Its source is
`beacon_security`. Required semantics include:

- `evidence_id` identifies this occurrence; `finding_id` is the stable aggregation fingerprint;
- `fingerprint_version=1`;
- `assessment` is `candidate_risk` or `observation`, never automatic confirmation;
- `validation` is initially `unvalidated`;
- `execution_observation=invocation_attempt` means only that the sink invocation was observed;
- trace IDs may correlate evidence but do not guarantee that a backend has the trace;
- `sources`, `propagation`, and `ranges` never contain raw request values;
- `request`, `component`, `stack`, `coverage`, and `coverage_gaps` describe available context and
  known limitations.

The initial canonical rules are `sql_injection`, `command_injection`, `command_execution`, `ssrf`,
`http_request_input`, and `path_traversal`. Implementations document which rules and frameworks
they actually cover.

## Per-request occurrences and evidence sampling

Implementations supporting occurrence delivery export one `beacon.security.finding` per finding
fingerprint per request, including requests inside the full-evidence sampling window. `occurrence_id`
is an alias of that request's `evidence_id`. Deduplicated updates within a request keep that ID.
Trace and span fields describe that occurrence, never a previous representative sample.

The following fields are additive in schema v1; consumers must accept older producers that omit them:

| Field | Meaning |
| --- | --- |
| `evidence_sampled` | Whether detailed evidence was retained in this record. This is not trace sampling. |
| `evidence_sample_reason` | Why evidence was retained or omitted, such as `evidence_upgrade`, `interval_or_run`, `interval`, `finding_capacity`, or `record_byte_limit`. |
| `aggregation_status` | `tracked` or `capacity_exceeded`; process-local aggregation may be full while the occurrence is still exported. |
| `occurrences_total` | Process-local, per-finding count of requests with a detection; absent when aggregation is unavailable. |

When full evidence is sampled out, preserve identity, rule, risk assessment, request-specific attack
evidence, sink, request context, and trace correlation. Keep required arrays (`sources`, `propagation`,
`ranges`, `stack`) present but empty, set `evidence_sampled=false`, `truncated=true`, and declare
`truncation_reason=evidence_sampled_out`. Empty arrays in such records do not mean there was no taint.
Export byte limits may additionally truncate a record; the truncation envelope remains available for
limits too small to preserve normal occurrence fields. Export loss and aggregation loss must remain
observable. Occurrence delivery is bounded, not a promise of durable or lossless delivery.

Stronger request evidence can upgrade a deduplicated occurrence and bypass ordinary full-evidence
sampling. It must not change the fingerprint or overwrite the classification of another request.
A retained representative sample must not regress to weaker evidence when a later ordinary request
arrives. Snapshot `last_trace_id` can therefore differ from the representative's trace ID.

## Request-specific attack evidence

The optional `attack_evidence` object is separate from `assessment` and `validation`:

| Field | Meaning |
| --- | --- |
| `status=unknown` | Evidence is unavailable, imprecise, unsupported, or requires missing policy. |
| `status=no_evidence` | The supported analysis did not identify attack evidence; this is not a safety verdict. |
| `status=suspected` | The supported analysis found evidence of possible exploitation, not proof of intent or success. |
| `reason` | Bounded machine-readable explanation, without raw request values. |
| `outcome=not_assessed` | Exploitation outcome has not been established. |

A normal input may reveal a candidate code risk while carrying no attack evidence. Parameter binding
must be distinguished from concatenating an untrusted SQL template before preparation. Recognizing a
sanitizer or validation call alone is not sufficient to clear taint or declare an operation safe.
Implementations document supported dialects, syntax, boundary policies, and analysis budgets.
Unsupported cases must retain uncertainty. Observing an invocation, a normal return, or an HTTP status
alone does not establish successful exploitation.

Finding summaries and local snapshots may include `attack_evidence_counts`, with `unknown`,
`no_evidence`, and `suspected` counters partitioning their aggregate occurrence count. Counts reflect
the strongest retained evidence for each request's deduplicated finding. They must not be presented
as confirmed attack counts. A snapshot may retain `strongest_attack_evidence` independently of the
latest occurrence. When deduplicating invocations, suspected evidence takes precedence over
unknown, and unknown takes precedence over no evidence so an unsupported invocation is not
hidden by an earlier ordinary one. Older producers and missing fields remain supported.

## Source, propagation, range, and sink

A source has `id`, `type`, `name`, `location`, `value_type`, and `value_length`. Names and locations
identify structure, never captured values.

A propagation node has `id`, nullable `parent_id`, `source_id`, `operation`, and `location`.
`source_id` references a source in the same finding.

A range is a zero-based half-open interval with `source_id`, `start`, nullable `end`, `exact`, and
`unit`. JVM and JavaScript strings use `utf16_code_unit`; Python strings use
`unicode_code_point`; byte sequences use `byte`.

A sink always uses these fields:

```json
{
  "function": "java.sql.Statement.executeQuery",
  "role": "sql_template",
  "location": "example.Orders#find(Orders.java:42)",
  "operation": "",
  "path_role": "",
  "input_part": ""
}
```

Canonical roles include `sql_template`, `shell_script`, `argument`, `executable`,
`destination_address`, `destination_unknown`, `file_path`, and `path_or_query`. File operations
use `read`, `write`, `copy`, `rename`, `delete`, or `unknown`; path roles use `source`, `target`, or
`unknown`. HTTP input parts use `path`, `query`, or `path_or_query`.

## Other event families

| Event | Source | Purpose |
| --- | --- | --- |
| `beacon.security.collection.incomplete` | `beacon_security` | Declares request collection gaps or budget truncation. |
| `beacon.security.finding.summary` | `beacon_security` | Reports bounded occurrence aggregation. |
| `beacon.security.health` | `beacon_security` | Reports process-level configuration, coverage, and delivery health. |
| `beacon.security.snapshot.failed` | `beacon_security` | Reports diagnostic snapshot failure. |
| `beacon.security.export.dropped` | `beacon_security` | Reports bounded security-channel delivery loss. |
| `beacon.security.export.truncated` | original source | Reports a record reduced by byte limits. |
| `beacon.security.sbom.snapshot` | `beacon_security_sbom` | Publishes a complete, possibly multipart runtime dependency snapshot. |
| `beacon.security.sbom.health` | `beacon_security_sbom` | Reports runtime SBOM health and completeness. |
| `beacon.security.sbom.update_failed` | `beacon_security_sbom` | Reports an SBOM refresh failure. |
| `beacon.security.sbom.export.dropped` | `beacon_security_sbom` | Reports bounded SBOM-channel delivery loss. |

Diagnostic payloads may gain fields within schema v1. Consumers must dispatch on `event_name` and
ignore unknown fields. Removing or changing the meaning/type of a required field needs a new schema
version.

## Minimal truncation envelope

If the configured record byte limit cannot hold a normal event, the implementation may emit:

```json
{
  "schema_version": 1,
  "source": "beacon_security",
  "event_name": "beacon.security.export.truncated",
  "truncated": true
}
```

It must preserve the original channel source and must not present the reduced record as complete.
