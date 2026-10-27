# Event contract v2

Schema v2 is an explicitly versioned, incompatible successor to the [v1 event contract](events.md).
The [v2 JSON Schema](../schemas/beacon-security-event-v2.schema.json) defines the wire shape.
V1 schemas and examples remain available for existing consumers. Do not validate a v2 event with
the v1 schema or infer producer support from the existence of this specification.

## Event families and transport

| Event | Source | Trigger |
| --- | --- | --- |
| `beacon.security.finding` | `beacon_security` | A rule-matching source-to-sink observation, deduplicated by finding within one request. |
| `beacon.security.sbom.inventory` | `beacon_security_sbom` | Initial asynchronous dependency collection, then every configured interval, even if unchanged. |

V2 does not export independent health, summary, diagnostic, loss, truncated-record replacement,
SBOM failure, or history events. Security does not add a diagnostic replay backlog; ordinary bounded
queues and configured OpenTelemetry transport behavior still apply. Delivery remains best effort;
receiving fewer events does not establish fewer detections.

The OpenTelemetry Logs mapping remains `io.beacon.security`, implementation scope version,
`INFO` severity, JSON string Body, and native event name / `event.name` / `source` matching the
body. Resource attributes carry service, runtime, host, and VCS metadata instead of duplicating
those maps in each finding. A collector may map its top-level source differently; implementations
must distinguish the body contract from collector-specific presentation.

## Identity and fingerprints

`instance_id` identifies the runtime process. V2 removes exported `application_id` and uses
`occurrence_id` as the only occurrence identifier. A repeated detection in a different request
has a different occurrence ID but may retain the same `finding_id`.

Fingerprint version 1 and its [conformance vectors](../test-vectors/fingerprint-v1.json) are
unchanged. The value called `application_id` in those historical algorithm inputs remains the
internal stable service scope derived from namespace and service name; it is not exported as a
second identity. Compute fingerprints before wire compaction. Missing optional empty sink fields
correspond to empty strings in the v1 fingerprint inputs. Evidence sampling does not change the
fingerprint. Consumers must not attempt to recompute a fingerprint from sampled-out evidence.

Persistent exception rules can use the stable finding ID without binding to a process UUID.

## Findings and attack evidence

Findings preserve rule, location, occurrence/finding IDs, collection time, process identity, and
available request and trace context. A modeled flow to a sensitive call is not a confirmed exploit.

`attack_evidence` contains only a machine-readable `reason` and one of these statuses:

| Status | Meaning |
| --- | --- |
| `unknown` | Analysis is unavailable, unsupported, imprecise, or requires missing policy. |
| `no_evidence` | Supported analysis did not find attack evidence; this is not a safety verdict. |
| `suspected` | Supported analysis found a possible attack feature, not proof of exploit success. |

All three classifications remain reportable. V2 removes the constant outcome and fixed
assessment/validation/severity/confidence fields; `precision` describes retained flow precision.
No raw request values, SQL, or shell scripts may be introduced by compaction or classification.

Request context contains available method, route, HTTP status code, and non-empty error type.
Sink context contains function, role, location, and only applicable non-empty operation/path/input
fields. Source, propagation, range, and stack semantics remain as defined in v1. Non-empty evidence
must not be silently shortened merely to reduce field count. A current span ID equal to the server
span ID is omitted; a distinct current span ID may be retained. Trace IDs do not guarantee that a
backend retained the corresponding trace.

`component`, when resolved, directly contains name, version, and optional real artifact SHA-256;
it no longer references an SBOM ID, revision, or release ID. Optional local debug context may retain
run or triage information. Missing component metadata does not suppress a finding.

## Sampling and incomplete observations

Each occurrence always retains boolean `evidence_sampled` and `collection_complete`, including
false values. When full evidence is omitted, set `evidence_sampled=false`, retain its reason, and
omit empty evidence arrays. This alone does not mean collection or byte truncation.

Only real truncation sets `truncated=true`; an absent flag means false. Retain a non-empty
truncation reason and known coverage gaps when available. An absent gap list is not a claim of
complete runtime coverage. Every implementation must document its modeled coverage and budgets.
The internal ordering of suspected, unknown, and no-evidence observations, evidence upgrades, and
request-level deduplication remains unchanged from v1.

Large findings may omit optional evidence to fit their byte budget while retaining identifying
fields and declaring truncation. If the reduced finding still cannot fit, drop it rather than
exporting a replacement diagnostic event. Consumers aggregate received occurrence IDs themselves;
there is no v2 summary or cumulative count to reconstruct lost delivery.

## Dependency inventory

Each successful collection publishes dependencies plus event, schema, runtime-instance, and timing
fields. Dependencies are observed loaded libraries, not a complete build or reachability graph.
Entries contain `name`, `version`, and an optional real artifact `hash`; do not invent unknown
versions or label synthetic metadata digests as artifact hashes.

| Field | Meaning |
| --- | --- |
| `observed_at` | Collection time in RFC 3339 UTC; strictly increasing within one producer instance. |
| `started_at` | Runtime-process start time in RFC 3339 UTC; fixed for that process, not framework readiness time. |
| `uptime_ms` | Non-negative runtime uptime in milliseconds at collection start. |

Java obtains process start time and uptime from RuntimeMXBean. Other implementations document
their equivalent runtime source. Do not calculate Java uptime by subtracting wall-clock timestamps.
Historical records retain collection-time uptime; they are not live counters or liveness signals.

The collection delay defaults to 300 seconds and supports the implementation binding of
`beacon.security.sbom.refresh.seconds` / `BEACON_SECURITY_SBOM_REFRESH_SECONDS`. Positive integers
are accepted; invalid or zero values fall back to the default. Collection runs serially, with the
delay measured after a collection finishes. Caching may avoid reparsing unchanged artifacts but
must not suppress periodic publication. Timing metadata does not introduce another timer.

Successful collection replaces the previous dependency list. A valid empty list can clear it.
Failed collection or scan/capacity errors that prevent a valid list emit no inventory, so consumers
preserve their last successful list. V2 removes collection status/error fields, SBOM IDs, revisions, release IDs, and history.

Only oversized lists contain zero-based `part_index` and `part_count >= 2`. Parts share
`instance_id`, `observed_at`, `started_at`, and `uptime_ms`. Consumers assemble every part of the
same instance and collection time before atomically replacing the previous list. Missing parts
must not clear or partly replace it; late older rounds must not overwrite a newer completed round.
The next collection republishes current dependencies without accumulating missing historical parts.

Optional local CycloneDX output remains diagnostic; it does not add online event families or a
durable history/replay mechanism. Existing v1 consumers must migrate explicitly before consuming v2.
