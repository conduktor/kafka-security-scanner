# Audit Status: kafka-security-scanner

Snapshot of remaining work after Codex audits 1–4. Use this file to resume after a context reset.

## Current state (commit `b87aed4`)

- **120 controls** in `policies/enterprise-default.yaml`. Zero attestations, zero placeholder controls (engine `validate()` refuses `condition: "true"` without `covered_by_kafka_flavor`).
- **9 collectors** plugged into `io.kafkascanner.collectors`: AdminClient, JMX, Filesystem, TLS, Process, Connect, SchemaRegistry, RestProxy, Docs.
- **6 statuses**: `pass / fail / na / covered_by_flavor / error`. (`attestation_required` removed.)
- Last benchmark vs single-broker plaintext localhost:19092 with `--collectors=adminclient,filesystem,tls,docs --kafka-config-dir secrets --docs-dir secrets`:
  ```
  Score: 0/100 | Pass: 20 | Fail: 77
    · 23 N/A: required collectors unavailable: process,schemaregistry,connect,jmx,restproxy
  ```
- CI build + docker jobs green on every commit.

## Audit history

| Pass | Commit | Solid | Problems | Δ |
|---|---|---:|---:|---:|
| 1 (before fixes) | `e9884a2` | 28 | 92 | n/a |
| 2 (post `307d14a`) | `307d14a` | 57 | 63 | +29 |
| 3 (post `5935dd1`) | `5935dd1` | 52 | 68 | −5 (introduced docs key regressions) |
| 4 (post `8f573f2`) | `8f573f2` | 68 | 52 | +16 |
| 5 (current) | `b87aed4` | ~76 est | ~44 est | +8 |

The ~44 remaining problems (per Codex pass 4 minus 15 fixed in pass 5) split into:

- **~14 actionable** that need new collectors / fields below.
- **~30 fundamentally bounded** by what a wire-protocol+filesystem scanner can see. These are the hardest to fix without expanding scope.

## What's still wrong, by control

Every entry below is a known gap. The CEL expression in the YAML may pass on a healthy cluster *for the wrong reason* (WEAK_PROOF) or fail on an unrelated cluster (FALSE_NEGATIVE). The "Fix" column says what we'd need.

### Bounded by missing collector data: need new collectors

| Control | Type | Current proof | Real proof needed |
|---|---|---|---|
| MON-001 | WEAK_PROOF | log4j authn+audit logger lines exist | Prometheus alert rule reader: parse `kafka-auth-failures` rule |
| MON-002 | WEAK_PROOF | docs.monitoring_alerts + JMX reachable | Anomaly detection rule artifact (e.g. Datadog monitor JSON) |
| MON-003 | WEAK_PROOF | docs.monitoring_alerts.exists | Parse `alerting_rules.yml` for auth-failure / ACL-change / quota-breach rules |
| MON-005 | WEAK_PROOF | docs.monitoring_alerts + jmx.messages_in | Consumer lag metric (`kafka.consumer:type=consumer-fetch-manager-metrics,records-lag-max`): needs JMX target on consumer JVM, not broker |
| MON-006 | WEAK_PROOF | docs.monitoring_alerts + current health | Replication-health alert rule artifact |
| AUDIT-006 | WEAK_PROOF | docs.audit_pipeline + log4j audit logger | SIEM endpoint discovery (vector/fluentd/splunk-forwarder process detection) |
| AUDIT-007 | WEAK_PROOF | SR auth + docs.schema_audit_log | Schema Registry audit-log endpoint probe (Confluent's `kafka-audit-log` topic) |
| AUDIT-008 | WEAK_PROOF | Connect auth + docs.connect_audit_policy | Connect REST `/connectors/{name}/topics` audit endpoint OR DLQ topic name match |
| AUDIT-010 | WEAK_PROOF | request+auth loggers configured | Inspect log4j layout pattern for `%X{principal} %X{clientId} %X{remoteAddress}` |
| DATA-001 | WEAK_PROOF | classification doc + topic config flag | Schema annotation collector (Avro `@encrypt` annotation, JSON Schema `x-encryption`) |
| DATA-002 | WEAK_PROOF | known KMS provider class in `config.providers` | Trace one config value through the provider to a KMS endpoint (e.g. `${vault:secret/kafka/sasl-password}` → check Vault listening) |
| DATA-003 | WEAK_PROOF | docs presence | SMT inspection on Connect: look for `MaskField` / `RegexRouter` |
| DATA-007 | WEAK_PROOF | connector name substring | Connector config inspector: read `transforms` list |
| DATA-008 | WEAK_PROOF | audit logger configured | Log4j layout pattern parsing for `%message` exposing topic payload |
| DATA-009/010 | WEAK_PROOF | SR subject count + compatibility | Data contract metadata collector (Confluent's `_data_contracts` topic OR Apicurio metadata) |
| DATA-013 | WEAK_PROOF | classification doc + topic config flag | Schema annotation `@tokenized` |
| MM2-001 | WEAK_PROOF | Connect REST + connector name match | Inspect connector config: `source.cluster.security.protocol`, `target.cluster.security.protocol` via `/connectors/{name}/config` |
| SR-002 | WEAK_PROOF | SR auth + docs.schema_auth_policy | Probe `POST /subjects/{}/versions` with no creds: must 401/403 per subject |
| STREAMS-001 | WEAK_PROOF | docs.streams_state_encryption + iac | Streams app config: `state.dir` filesystem permissions on the app host |
| STREAMS-002 | WEAK_PROOF | docs + ACL name match | Streams `application.id` config + per-app ACL coverage |
| ZK-004 | WEAK_PROOF | docs.iac (when zk mode) | ZK admin port `4lw` probe: `echo conf \| nc zk1 2181` parsing for `4lw.commands.whitelist` |
| NET-001 | WEAK_PROOF | listener map has comma | Distinct listener names AND each maps to different protocol class |
| NET-002 | WEAK_PROOF | advertised.listeners ≠ 0.0.0.0 | DNS resolver: validate advertised host resolves to a private subnet |
| NET-003 | WEAK_PROOF | non-0.0.0.0 + docs.network_topology | Cloud SDK collector: SG/firewall ingress rules listed |
| NET-005 | WEAK_PROOF | docs.iac + docs.data_classification | Cluster-placement evidence: e.g. k8s namespace label `data-class=restricted` |
| OPS-002 | WEAK_PROOF | 3 broker config keys checked | Hardening checklist artifact (CIS benchmark output JSON) |
| OPS-005 | WEAK_PROOF | docs.backup_encryption + config.providers | Backup tool config inspection (mirrormaker target topic, snapshot tool encryption flag) |
| OPS-006 | WEAK_PROOF | any `${...}` placeholder in any config | Specifically check `sasl.jaas.config`, `ssl.keystore.password`, `ssl.key.password` use a provider reference |
| OPS-010 | WEAK_PROOF | docs.dlq_config | Connect connector configs: `errors.tolerance=all`, `errors.deadletterqueue.topic.name` set |

### Already actionable: small fixes

~~All 7 closed in pass 6 (commit pending).~~ Each control now uses real collector data instead of a weak proxy:

| Control | Before (weak proxy) | After (real proof) |
|---|---|---|
| AUTH-006 | per-user quota presence | `docs.key_rotation_log.age_days <= 90` |
| AUTH-007 | keystore path presence | `tls.handshake_ok && tls.days_to_expiry > 30 && docs.key_rotation_log.exists` |
| ACL-003 | wildcard absence | every cluster CREATE/DELETE ALLOW principal ∈ `docs.admin_principals.principals` |
| ACL-005 | non-wildcard ALLOW exists | every cluster ALTER/CREATE/DESCRIBE_CONFIGS/ALTER_CONFIGS principal ∈ allowlist |
| QUOTA-004 | string ≠ "0" / "MAX_INT" | `b.config_int['max.connections.per.ip'] > 0 && < 10000` |
| QUOTA-005 | title mentioned max.request.size | title corrected; condition pins `socket.request.max.bytes`, `replica.fetch.max.bytes`, `message.max.bytes` (broker side) |
| AUDIT-004 | `docs.audit_retention.exists` | `fs.audit_log_retention_configured` (log4j RollingFileAppender + retention setting) |

New collector outputs introduced for these:

- `broker.config_int` (typed numeric mirror of `broker.config`; non-numeric keys skipped) — KafkaCollectors.java
- `fs.audit_log_retention_configured` — FilesystemCollector.java
- `docs.admin_principals.principals` (parsed list) — DocsCollector.java

## Collectors to build (priority-ordered)

Work to take this from "honest but limited" → "comprehensive". Each item is a substantial PR.

1. **AlertRuleCollector**: reads `--alertmanager-url` or `--prometheus-url`, fetches `alerting_rules.yml`. Unblocks 5 MON controls.
2. **SiemCollector**: process-list + listening port probe for known shippers (vector/fluentd/splunkforwarder). Unblocks AUDIT-006.
3. **ConnectorConfigCollector**: extends ConnectCollector to GET `/connectors/{name}/config` for every connector. Unblocks MM2-001, AUDIT-008, DATA-007/010, OPS-010.
4. **ZkAdminCollector**: `--zk-admin-host:port` probes `4lw` whitelist via `echo conf`. Unblocks ZK-004.
5. **SchemaContractCollector**: reads schema annotations (Avro/Protobuf/JSON Schema) for `@encrypt`/`@tokenized`/owner metadata. Unblocks DATA-001/006/011/012/013, SR-002.
6. **CloudCollector**: AWS/GCP/Azure SDK; reads SG/firewall/IAM. Unblocks NET-003/005, partial OPS-005.
7. **K8sCollector**: k8s API; reads NetworkPolicies, Secrets, RBAC, Strimzi CRs. Unblocks NET-001/002/005, partial KRAFT-003.
8. **SmtCollector**: Connect SMT classes per connector (extension of ConnectorConfigCollector). Unblocks DATA-003.
9. **CipheredKmsCollector**: traces one config value through `${provider:path}` and probes KMS endpoint. Unblocks DATA-002, OPS-005/006.
10. **ConsumerJmxCollector**: JMX target list (multiple), reads consumer lag MBeans. Unblocks MON-005.

## Engine-level work still pending

- **`requires` semantics for split conditions**: ZK-004 / KRAFT-003 currently inline-check the docs/fs key absence (`!('iac' in docs)`) because the engine treats a single missing collector as N/A for the whole control. A finer model would let a control declare `requires_for_branch_X` so the KRaft branch doesn't drag a docs requirement that only the ZK branch needs. Today we work around it.
- **Severity calibration for doc-only proofs**: still flagged on STREAMS-001 (already lowered to medium). Check the catalogue for any other `docs.X.exists`-only condition rated high/critical.
- **Per-broker collection**: AdminClientCollector pulls broker configs from every node, but JMX/Filesystem/Process collect from the host where the scanner runs. For multi-broker clusters, those collectors need a target list.

## How to resume

1. Read this file end-to-end.
2. Pick a collector from the priority list above.
3. Implement the collector (interface in `src/main/java/io/kafkascanner/collectors/Collector.java`).
4. Add a `--<collector>-url` (or similar) CLI flag in `Main.java`.
5. Wire the collector in `Main.run()` behind `--collectors=<name>`.
6. Add CEL var declarations for new namespace in `PolicyEngine.load()`.
7. Update controls that currently use a weak proxy → reference real collector data.
8. Run `./scripts/test-all-variants.sh` against the matrix, then run a fresh Codex audit:
   ```
   /codex:rescue Re-audit policies/enterprise-default.yaml after commit <sha>. ...
   ```
9. Commit, push, watch CI, repeat.

## Conventions for new controls

- **Always declare `requires:`** for the collectors a control depends on. The engine resolves to `na` when a required collector is unavailable: never silent pass.
- **Never use `condition: "true"`**. The engine refuses to load such policies.
- **Prefer config-level proof over doc-level proof**. `docs.X.exists` is the last resort; if a config field can be checked, do that.
- **Cross-validate when possible**. The same fact verified by AdminClient AND TLS handshake AND filesystem catches drift.
- **Gate emptiness with `*_meta.collected`**. `acls.size() == 0 || ...` is wrong; `acl_meta.collected && ...` is right.
- **For mode-conditional controls** (ZK/KRaft), use positive guards: `cluster.mode == 'kraft' || (cluster.mode == 'zookeeper' && ...)`. The `unknown` value never silently passes.

## File touched in each pass: for context recovery

```
src/main/java/io/kafkascanner/collectors/
  AdminClientCollector.java   ← acl_metadata, topic_metadata, quota_metadata
  KafkaCollectors.java         ← cluster.mode detection, topic config + classification labels, ACL pattern_type, quotas
  FilesystemCollector.java     ← log4j parsing, connect_properties, is_connect_node
  JmxCollector.java            ← put-if-present (no -1 sentinel)
  TlsCollector.java            ← plaintext_endpoint distinction
  ProcessCollector.java        ← /proc/<pid>/status uid; numeric kafka_version_major/minor
  HttpProbe.java               ← always-emit reachable/requires_auth/tls
  ConnectCollector.java        ← connectors, mm2_connector_present, plugin_count
  SchemaRegistryCollector.java ← /subjects, /config, compatibility_protects_consumers
  RestProxyCollector.java      ← /topics
  DocsCollector.java           ← 26 expected artifact names

src/main/java/io/kafkascanner/policy/PolicyEngine.java
  validate() refuses placeholders
  resolve() short-circuits covered_by_flavor → na (requires) → CEL

src/main/java/io/kafkascanner/model/ScanModels.java
  Status enum (pass/fail/na/covered_by_flavor/error)
  Control: condition, requires, covered_by_kafka_flavor, no attestation
  ScanResult: kafka_flavor + collectors_used + collectors_unavailable

policies/enterprise-default.yaml
  120 controls, no attestation blocks, every control has condition or covered_by_kafka_flavor
  Some controls reference docs.* keys: see DocsCollector.EXPECTED for the full list

scripts/test-all-variants.sh
  8 broker variants (Kafka 3.9/4.2 plaintext/SASL/ACL/JMX, 3-broker, Redpanda)
  Asserts MIN_FAILS + MUST_FAIL per variant
```
