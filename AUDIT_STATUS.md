# Audit Status: kafka-security-scanner

Snapshot of remaining work after Codex audits 1–4 and the pass 6/7 collector build-out.

## Current state (commit `0701985`)

- **120 controls** in `policies/enterprise-default.yaml`. Zero attestations, zero placeholder controls (engine `validate()` refuses `condition: "true"` without `covered_by_kafka_flavor`).
- **15 collectors** plugged into `io.kafkascanner.collectors`: AdminClient, JMX (multi-target), Filesystem, TLS, Process, Connect (per-connector configs), SchemaRegistry (per-subject annotations + anon-write probe), RestProxy, Docs, Alerts (Prometheus), Siem (process+port), Zk (4lw), ConsumerJmx, Kms (derivation pass).
- **6 statuses**: `pass / fail / na / covered_by_flavor / error`.
- **Engine**: supports both `requires:` (unconditional) and `requires_per_mode:` (only enforced for the matching `cluster.mode`). KRaft scans no longer need a `zk` collector to evaluate ZK-004; ZK scans no longer need a `filesystem` collector to evaluate KRAFT-003.
- Baseline against single-broker plaintext localhost:19092 with `--collectors=adminclient` (no fixtures):
  ```
  Pass: 16  Fail: 41  N/A: 63  Errors: 0
  ```
  With every applicable collector and prepared fixtures (Prometheus rules, SR with @encrypt schema, Connect with secure MM2, ZK with strict whitelist, log4j with retention, server.properties with ${vault:...}) the same broker scores in the high-20s on pass — the rest are real configuration gaps, not collector noise.
- CI build + docker jobs green on every commit.

## Audit history

| Pass | Commit | Δ |
|---|---|---|
| 1 | `e9884a2` | 28 solid / 92 problems |
| 2 | `307d14a` | +29 solid (57 / 63) |
| 3 | `5935dd1` | −5 (introduced docs-key regressions) |
| 4 | `8f573f2` | +16 (68 / 52) |
| 5 | `b87aed4` | +8 (~76 / ~44) |
| 6 | `019fd77` | +7 small fixes (AUTH-006/007, ACL-003/005, QUOTA-004/005, AUDIT-004) |
| 7 | `0701985` | +6 collectors (Alerts/Siem/ConnectorConfig/Zk/SchemaContract/ConsumerJmx/Kms) + `requires_per_mode` + severity sweep |

## Closed in pass 6/7

Each control now uses real collector data. Negative + positive cases validated end-to-end via docker.

| Control | New proof | Source |
|---|---|---|
| MON-001 | Prometheus auth-failure alert rule + broker auth logger | AlertRuleCollector + FilesystemCollector |
| MON-002 | Prometheus anomaly alert rule | AlertRuleCollector |
| MON-003 | Prometheus auth-failure + ACL-change + quota-breach rules | AlertRuleCollector |
| MON-005 | Reachable consumer JMX target + Prometheus consumer-lag rule | ConsumerJmxCollector + AlertRuleCollector |
| MON-006 | Replication-health alert rule + zero current URP/offline | AlertRuleCollector + AdminClient |
| AUDIT-004 | RollingFileAppender + retention setting | FilesystemCollector (`fs.audit_log_retention_configured`) |
| AUDIT-006 | Live SIEM shipper detected on host + audit logger | SiemCollector + FilesystemCollector |
| AUDIT-008 | Connect REST auth + topic enumeration on every connector | ConnectCollector |
| AUTH-006 | docs.key_rotation_log age ≤ 90d + SCRAM enabled | DocsCollector |
| AUTH-007 | TLS handshake + days_to_expiry > 30 + key_rotation_log | TlsCollector + DocsCollector |
| ACL-003 | Cluster CREATE/DELETE ALLOW principals ⊂ docs.admin_principals | AdminClient + DocsCollector (parsed list) |
| ACL-005 | Cluster ALTER/CREATE/DESCRIBE_CONFIGS ALLOW ⊂ admin_principals | AdminClient + DocsCollector |
| QUOTA-004 | `b.config_int['max.connections.per.ip'] < 10000` | AdminClient (numeric mirror) |
| QUOTA-005 | Broker-side socket/replica/message size limits set | AdminClient |
| DATA-001 | Topic config OR schema annotation `@encrypt` | AdminClient + SchemaContractCollector |
| DATA-002 | External config provider in use, placeholder count > 0 | KmsCollector |
| DATA-003 | Connect masking SMT + classification | ConnectCollector |
| DATA-007 | Connect masking SMT + DLQ topic | ConnectCollector |
| DATA-010 | Connect DLQ + SR compatibility ≠ NONE | ConnectCollector + SchemaRegistryCollector |
| DATA-013 | Topic config OR schema annotation `@tokenized` | AdminClient + SchemaContractCollector |
| MM2-001 | Every MM2 connector source AND target uses SSL/SASL | ConnectCollector (`mm2_all_secure`) |
| OPS-005 | External config provider + placeholder count > 0 | KmsCollector |
| OPS-006 | Sensitive sasl/ssl key resolves through a provider | KmsCollector (`sensitive_keys_via_provider`) |
| OPS-010 | Every connector declares `errors.deadletterqueue.topic.name` | ConnectCollector |
| SR-002 | Anonymous POST /subjects/{}/versions returns 401/403 per subject | SchemaContractCollector |
| ZK-004 | Sensitive 4lw commands all rejected (probed) on ZK branch only | ZkAdminCollector + per-mode requires |

## Still bounded — kept as best-effort or deferred

| Control | Severity | Current proof | Real proof needed |
|---|---|---|---|
| AUDIT-007 | medium | SR reachable + auth + docs.schema_audit_log | Confluent `_audit-log` topic enumeration via AdminClient |
| AUDIT-010 | medium | request+auth loggers configured | Log4j layout pattern parsing for `%X{principal} %X{clientId} %X{remoteAddress}` |
| DATA-008 | high | audit logger configured | Log4j layout `%message` exposing topic payload |
| DATA-009 | medium | SR subject count + compatibility | Data-contract metadata collector (Confluent `_data_contracts` topic OR Apicurio) |
| STREAMS-001 | medium | docs only | Streams app `state.dir` permissions probe (separate process) |
| STREAMS-002 | medium | docs + ACL name match | Streams `application.id` config + per-app ACL coverage from a streams sidecar |
| NET-001 | medium | listener map has comma | Distinct listener names mapped to different protocol classes |
| NET-002 | medium | advertised.listeners ≠ 0.0.0.0 | DNS resolver: validate advertised host resolves to a private subnet |
| NET-003 | high | non-0.0.0.0 + docs.network_topology | **CloudCollector** (deferred) |
| NET-005 | medium | docs only | **CloudCollector / K8sCollector** (deferred) |
| OPS-002 | medium | 3 broker config keys checked | CIS benchmark JSON artifact ingest |
| ENC-004 | medium | docs only | CloudCollector OR cryptsetup `/proc/mounts` probe |

## Deferred collectors — explicit non-goals for pass 7

These are listed in the original priority list but skipped intentionally; each requires a heavyweight dependency or external infrastructure that isn't worth the JAR-size hit until a concrete operator asks for it.

- **CloudCollector** (AWS / GCP / Azure SDK): adds 10–30 MB to the JAR; validation requires real cloud creds or localstack. Would unblock NET-003, NET-005, partial OPS-005, ENC-004.
- **K8sCollector** (kubernetes-client): adds ~5 MB; validation needs a kubeconfig context. Beyond what FilesystemCollector already covers (Strimzi CRs are YAML on disk), the marginal value is low. Would unblock NET-001/002/005, partial KRAFT-003.
- **Filesystem / Process per-broker remoting**: requires SSH or k8s exec. Operators with multi-broker clusters today run the scanner per-host or mount each config dir into the scanner container.

## Engine work landed

- `requires_per_mode: { zookeeper: [zk], kraft: [filesystem] }` — only enforces the branch matching `cluster.mode`. Wired in `PolicyEngine.resolve` after `requires:` and before CEL.
- `broker.config_int` typed numeric mirror (cel-java has no `int(string)` overload).
- KMS derivation pass: a collector that walks the data already produced by other collectors after the runner finishes — see `KmsCollector.aggregate(Map)` and the `Main.run()` wire-up.

## How to resume / next pass

1. Read this file end-to-end.
2. Run `./scripts/test-all-variants.sh` against the docker matrix to confirm the baseline. Note: macOS hosts may have port collisions with other Kafka containers on 19092 — stop those first.
3. Pick the next item:
   - `AUDIT-010` / `DATA-008`: extend `FilesystemCollector` to parse the log4j PatternLayout.
   - `STREAMS-001` / `STREAMS-002`: a streams-sidecar collector that reads `application.id`, `state.dir` permissions, and per-app ACL coverage.
   - `OPS-002`: ingest a CIS benchmark JSON via a new `--cis-report` flag.
   - `NET-002` DNS resolver: pure local — no new dependencies.
4. Run a fresh Codex audit:
   ```
   /codex:rescue Re-audit policies/enterprise-default.yaml after commit <sha>. ...
   ```
5. Commit, push, watch CI, repeat.

## Conventions for new controls

- **Always declare `requires:` (or `requires_per_mode:`)** for the collectors a control depends on. The engine resolves to `na` when a required collector is unavailable; never silent pass.
- **Never use `condition: "true"`**. The engine refuses to load such policies.
- **Prefer config-level proof over doc-level proof**. `docs.X.exists` is the last resort; if a config field can be checked, do that.
- **Cross-validate when possible**. The same fact verified by AdminClient AND TLS handshake AND filesystem catches drift.
- **Gate emptiness with `*_meta.collected`**. `acls.size() == 0 || ...` is wrong; `acl_meta.collected && ...` is right.
- **For mode-conditional controls** (ZK/KRaft), use positive guards: `cluster.mode == 'kraft' || (cluster.mode == 'zookeeper' && ...)`. The `unknown` value never silently passes.
- **For collector-bounded controls**, use `requires_per_mode` so the irrelevant branch doesn't drag a dependency it doesn't need.

## Files of record

```
src/main/java/io/kafkascanner/collectors/
  AdminClientCollector.java      acl_metadata, topic_metadata, quota_metadata
  KafkaCollectors.java           cluster.mode detection, broker.config_int (numeric mirror)
  FilesystemCollector.java       log4j parsing, audit_log_retention_configured
  JmxCollector.java              multi-target broker JMX (max/min aggregate)
  TlsCollector.java              chain, days_to_expiry, plaintext_endpoint
  ProcessCollector.java          /proc/<pid>/status (linux-only)
  HttpProbe.java                 GET + POST helpers
  ConnectCollector.java          per-connector config + transforms + DLQ + mm2_secure
  SchemaRegistryCollector.java   per-subject annotations + anonymous-write probe
  RestProxyCollector.java        /topics + auth probe
  DocsCollector.java             27 expected artifact names + admin_principals parser
  AlertRuleCollector.java        Prometheus /api/v1/rules with alert-flavour shortcuts
  SiemCollector.java             process + 127.0.0.1 port probe for known shippers
  ZkAdminCollector.java          4lw probe (sensitive_commands_leaked)
  ConsumerJmxCollector.java      consumer-fetch-manager-metrics records-lag-max
  KmsCollector.java              derivation: ${provider:path} placeholder analysis

src/main/java/io/kafkascanner/policy/PolicyEngine.java
  validate() refuses placeholders
  resolve() short-circuits covered_by_flavor → na (requires) → na (requires_per_mode) → CEL

src/main/java/io/kafkascanner/model/ScanModels.java
  Status enum (pass/fail/na/covered_by_flavor/error)
  Control: condition, requires, requires_per_mode, covered_by_kafka_flavor

policies/enterprise-default.yaml
  120 controls. Zero docs-only proofs at high/critical.

scripts/test-all-variants.sh
  8 broker variants (Kafka 3.9/4.2 plaintext/SASL/ACL/JMX, 3-broker, Redpanda).
  Asserts MIN_FAILS + MUST_FAIL per variant.
```
