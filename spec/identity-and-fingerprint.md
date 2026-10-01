# Identity and Finding Fingerprint

## Application identity

Beacon Security reuses OpenTelemetry resource identity. It does not introduce a second application
name setting.

For identity algorithm version 1:

```text
namespace = service.namespace or ""
name      = service.name or the implementation's documented unknown-service fallback
application_id = "app-" + lowercase_hex(SHA-256(UTF-8(namespace + "|" + name)))
```

Deployments should set `service.name`; `service.namespace` is recommended when the same service
name can occur in multiple logical namespaces. `service.version`, `service.instance.id`,
`deployment.environment.name`, `vcs.repository.url.full`, and `vcs.ref.head.revision` remain normal
OpenTelemetry resource attributes and may enrich event identity.

`instance_id` identifies one runtime process and is not part of the stable application ID.

## Finding fingerprint version 1

The fingerprint input segments, in order, are:

```text
1
application_id
language
rule
sink.role
sink.function
sink.location
sink.operation
sink.path_role
sink.input_part
sorted(unique(source.type + "|" + source.name))
```

Algorithm:

1. Preserve empty segments.
2. Replace any unpaired Unicode surrogate with U+FFFD.
3. Sort unique source signatures by UTF-16 code-unit order, without locale rules.
4. Encode every segment as UTF-8.
5. Before each segment, hash its UTF-8 byte length as an unsigned 4-byte big-endian integer.
6. Hash the length prefix followed by the segment bytes with SHA-256.
7. Return `finding-` followed by the lowercase hexadecimal digest.

Request values, timestamps, trace IDs, instance IDs, evidence IDs, and component revisions are not
fingerprint inputs. Consequently, equivalent observations in separate requests aggregate while
different languages and stable sink locations remain distinct.

The normative examples are in
[fingerprint-v1.json](../test-vectors/fingerprint-v1.json). Implementations claiming fingerprint
v1 conformance must pass every vector exactly.
