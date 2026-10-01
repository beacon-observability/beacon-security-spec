# Beacon Security Specification

This repository is the authoritative, language-neutral contract for Beacon Security telemetry.
It defines names, event shapes, identity, finding fingerprints, configuration semantics, runtime
SBOM exchange, examples, and conformance vectors. Runtime implementations stay in their language
repositories and pin an exact commit from this repository.

## Status

The contract is under development and has no stable release yet. Schema version 1 and fingerprint
version 1 describe the new Beacon namespace; they do not provide compatibility aliases for the
former SecurityContext packages, `security.*` configuration, or `security_context` event source.

Only the Java implementation has local conformance evidence today. A specification does not imply
that every language implements it, that an implementation has passed release acceptance, or that a
backend accepts the data.

| Implementation | Repository | Current evidence |
| --- | --- | --- |
| Java | [beacon-java](https://github.com/beacon-observability/beacon-java) | Implemented and locally validated; release acceptance pending. |
| Other languages | Their future language repositories | Not implemented or validated against this contract. |

## Contract layout

- [Event contract](spec/events.md)
- [Identity and fingerprint](spec/identity-and-fingerprint.md)
- [Configuration](spec/configuration.md)
- [Runtime SBOM](spec/runtime-sbom.md)
- [JSON Schema](schemas/beacon-security-event-v1.schema.json)
- [Examples](examples/)
- [Conformance vectors](test-vectors/)

Validate the repository with Node.js, without installing dependencies:

```bash
node scripts/check.mjs
```

## Adoption rules

An implementation must:

1. pin an immutable commit from this repository;
2. expose its implemented schema and fingerprint versions in build or artifact provenance;
3. pass the conformance vectors it claims;
4. document language-specific coverage, configuration bindings, performance evidence, and known
   gaps in its own repository;
5. avoid claiming support for optional fields or event families it does not emit.

The specification owns shared semantics. It does not own language instrumentation code, builds,
release cadence, Collector deployment, backend processing, or vulnerability confirmation.

## Provenance

The initial contract was derived from the locally validated Java migration of
[GuanceCloud/SecurityContext](https://github.com/GuanceCloud/SecurityContext). The new contract is
intentionally reset before public use: product names, configuration keys, sources, event names,
schema version, and fingerprint version are Beacon-native and have no legacy alias requirement.

## License

Apache License 2.0. See [LICENSE](LICENSE).
