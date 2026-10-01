# Runtime SBOM Contract

Beacon Security distinguishes the standard local CycloneDX document from the bounded OTLP snapshot
event.

## Local CycloneDX

When local diagnostic output is enabled, an implementation may write `application.cdx.json` using
CycloneDX 1.7. It must keep the standard top-level shape and use the standard `properties` array for
Beacon metadata.

Current Beacon property names use the `beacon:security:` namespace. The top-level source marker is
the property `{ "name": "source", "value": "beacon_security" }`. Component references use
`urn:beacon:security:component:<sha256>` where a content identity is available.

Runtime observation does not prove execution reachability, vulnerability, complete dependency
inventory, or build provenance. Completeness and reasons must be explicit. Imported build SBOM
metadata must not be presented as runtime-loaded evidence unless it was independently observed.

## OTLP runtime snapshot

`beacon.security.sbom.snapshot` uses `source=beacon_security_sbom` and carries:

- `sbom_id`, `revision`, `release_id`, `status`, `completeness`, and `reasons`;
- `component_count` for the complete revision;
- `part_index` beginning at zero and `part_count` for bounded multipart delivery;
- `dependencies`, whose entries contain `name`, `version`, and an optional real artifact SHA-256
  `hash`.

Consumers replace an inventory only after receiving every part of the same
`application_id`/`sbom_id`/`revision`. An empty snapshot still has one part so it can clear a prior
inventory. Missing parts do not constitute an empty or complete inventory.

Artifact hashes are hashes of real observed artifacts. Lock-file integrity values, metadata
digests, or synthetic identifiers must not be labeled as artifact SHA-256 values.
