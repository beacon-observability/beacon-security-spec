# Configuration Contract

These settings are the shared public surface. Language repositories document their property,
environment-variable, configuration-file, or SDK binding.

| Canonical key | Environment binding | Type | Default | Meaning |
| --- | --- | --- | --- | --- |
| `beacon.security.enabled` | `BEACON_SECURITY_ENABLED` | boolean | `false` | Enable the Security runtime lifecycle. |
| `beacon.security.sbom.enabled` | `BEACON_SECURITY_SBOM_ENABLED` | boolean | `true` | Enable runtime SBOM while Security is enabled. |
| `beacon.security.local-output.enabled` | `BEACON_SECURITY_LOCAL_OUTPUT_ENABLED` | boolean | `false` | Enable process-local diagnostic files. |
| `beacon.security.output` | `BEACON_SECURITY_OUTPUT` | path | implementation-defined | Diagnostic snapshot directory. |
| `beacon.security.evidence.file` | `BEACON_SECURITY_EVIDENCE_FILE` | path | unset | Optional diagnostic JSONL evidence file. |

Rules:

- Security and local output are opt-in.
- Enabling Security must not silently enable local disk output.
- Runtime SBOM is part of the enabled Security lifecycle unless explicitly disabled.
- Local files are diagnostic snapshots, not durable multi-process aggregation or confirmed backend
  delivery.
- Implementations may add bounded tuning settings in their own repository. Such settings are not
  cross-language contract merely because they use the `beacon.security.*` prefix.

Transport, authentication, resource identity, sampling, TLS, compression, and Collector endpoints
reuse OpenTelemetry configuration such as `OTEL_EXPORTER_OTLP_*`, `OTEL_LOGS_EXPORTER`, and
`OTEL_RESOURCE_ATTRIBUTES`. Beacon Security must not create duplicate transport or service-name
settings.

The former `security.*` properties and `SECURITY_*` environment variables are not aliases in this
contract. Implementations not publicly released before this baseline should fail closed or ignore
unknown legacy keys according to their normal configuration behavior.
