# Audit Status: kafka-security-scanner

Snapshot of remaining work after Codex audits 1–4 and the pass 6/7 collector build-out.

## Current state (commit `354a62d`)

- **138 controls** in `policies/enterprise-default.yaml`. Zero attestations, zero placeholder controls.
- **23 collectors**: AdminClient, JMX (multi-target), Filesystem (log4j layout + cryptsetup probe), TLS, Process, Connect (per-connector), SchemaRegistry, RestProxy, Docs, Alerts (Prometheus), Siem, Zk (4lw), ConsumerJmx, Kms (derivation), ConfluentCloud, AwsMsk (SDK v2), Aiven, Cis, RedpandaCloud, AzureEventHubs, K8sNetworkPolicy (kubectl shell-out).
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
| 8 | `2a387c9` | +2 cloud-native collectors (ConfluentCloud REST + Metrics; AwsMsk via SDK v2) + 6 new controls |
| 9 | `19d2502` | +3 collectors (Aiven REST; Cis report ingest; broker DNS+protocol audit) + 6 reworked controls + 3 AIVEN-* controls |
| 10 | `354a62d` | +4 collectors (cryptsetup probe; RedpandaCloud REST; Azure ARM REST; K8s NetworkPolicy via kubectl) + 6 new controls (RP-001/002/003, AZURE-001/002/003) + ENC-004 promoted high + NET-005 rewritten |

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

## Closed in pass 9

| Control | New proof | Source |
|---|---|---|
| NET-001 | ≥2 distinct protocol classes in listener.security.protocol.map | KafkaCollectors (`broker.listener_protocols_distinct_count`) |
| NET-002 | InetAddress.getAllByName + RFC1918/4193 check on every advertised host | KafkaCollectors (`broker.advertised_hosts_public`) |
| AUDIT-007 | SR auth + confluent-audit-log-events topic on broker | SchemaRegistry + AdminClient (`topic_meta.audit_log_topic_present`) |
| AUDIT-010 | log4j PatternLayout includes %X{principal} + %X{clientId}/%X{remoteAddress} | FilesystemCollector |
| DATA-008 | log4j PatternLayout has no bare %m / %message / %msg | FilesystemCollector |
| DATA-009 | SR compat ≠ NONE + (data-contracts topic OR per-subject @owner) | SR + AdminClient |
| OPS-002 | broker hardening + CIS report ≥ 90% pass | CisCollector |
| AIVEN-001/002/003 | api.aiven.io 401 + ip_filter closed + cert/SASL auth | AivenCollector |

## Still bounded — kept as best-effort or deferred

| Control | Severity | Current proof | Real proof needed |
|---|---|---|---|
| STREAMS-001 | medium | docs only | Streams app `state.dir` permissions probe (separate process / sidecar) |
| STREAMS-002 | medium | docs + ACL name match | Streams `application.id` config + per-app ACL coverage from a streams sidecar |
| NET-003 | high | non-0.0.0.0 + docs.network_topology | GCP firewall SDK; Azure NSG SDK (Azure namespace-level coverage already in AZURE-003) |

## Cloud-native coverage landed in pass 8

| Vendor | Collector | What it proves | New controls |
|---|---|---|---|
| Confluent Cloud | `ConfluentCloudCollector` | REST API + Metrics API auth posture; cluster type / private networking / BYOK from `/cmk/v2/clusters/{id}` when creds + cluster id supplied | KAFKA-CC-001 (auth), KAFKA-CC-002 (dedicated/enterprise tier), KAFKA-CC-003 (private networking) |
| AWS MSK | `AwsMskCollector` (aws-sdk v2: kafka + ec2 + cloudwatch + sts) | Encryption-at-rest, in-transit (client + in-cluster), public-access mode, broker SG ingress, CloudWatch URP / OfflinePartitionsCount | KAFKA-AWS-001 (encryption-at-rest), KAFKA-AWS-002 (public access disabled), KAFKA-AWS-003 (no 0.0.0.0/0 on broker ports) |
| Aiven | `AivenCollector` (REST + Bearer) | api.aiven.io auth posture; service spec (plan, cloud, ip_filter, kafka_authentication_methods) | KAFKA-AIVEN-001 (auth required), KAFKA-AIVEN-002 (closed ip_filter), KAFKA-AIVEN-003 (cert/SASL auth) |
| Redpanda Cloud | `RedpandaCloudCollector` (REST + Bearer) | api.redpanda.com auth posture; cluster spec (connection_type, region, type) | KAFKA-RP-001 (auth required), KAFKA-RP-002 (private connectivity), KAFKA-RP-003 (not serverless for regulated) |
| Azure Event Hubs | `AzureEventHubsCollector` (REST + Bearer) | management.azure.com auth posture; namespace spec (minimumTlsVersion, publicNetworkAccess, privateEndpointConnections, zoneRedundant, disableLocalAuth) | KAFKA-AZURE-001 (auth required), KAFKA-AZURE-002 (TLS >=1.2), KAFKA-AZURE-003 (public access disabled OR private endpoints exist) |
| Kubernetes | `K8sNetworkPolicyCollector` (kubectl shell-out) | NetworkPolicies + Kafka-pod label selectors; default-deny detection | KAFKA-NET-005 (default-deny + kafka-pod-targeting NP) |
| Self-hosted Linux | `FilesystemCollector` cryptsetup mode | /proc/mounts walk: log.dirs on /dev/mapper/* OR crypto_LUKS OR zfs* | KAFKA-ENC-004 (high) |

Activation:
- ConfluentCloud: `--cc-api-key` / `--cc-api-secret` (env `CC_API_KEY` / `CC_API_SECRET`), or auto when bootstrap matches `*.confluent.cloud`.
- AwsMsk: `--aws-region` / `--aws-msk-cluster-arn` (env `AWS_REGION`, default credential chain), or auto when bootstrap matches `*.kafka*.amazonaws.com`.

ENC-004 dropped `aws-msk` and `confluent-cloud` from `covered_by_kafka_flavor` since both flavors now have real checks. `aiven`, `redpanda-cloud`, `azure-eventhubs` stay SLA-covered until similar collectors land.

## Deferred collectors — still on the backlog

- **AivenCollector / RedpandaCloudCollector / AzureEventHubsCollector**: each follows the ConfluentCloud pattern (REST API + Basic auth or OAuth). The first operator request lands them.
- **GcpCollector** / **K8sCollector**: out-of-scope until a clear use case beyond what FilesystemCollector + AwsMsk already cover.
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
  ConfluentCloudCollector.java   api.confluent.cloud + Metrics API probes
  AwsMskCollector.java           aws-sdk-v2 (kafka/ec2/cloudwatch) probes
  AivenCollector.java            api.aiven.io REST + service spec
  CisCollector.java              cis-cat / kube-bench / inspec JSON ingest
  RedpandaCloudCollector.java    api.redpanda.com REST + cluster spec
  AzureEventHubsCollector.java   management.azure.com (ARM) REST
  K8sNetworkPolicyCollector.java kubectl shell-out for NPs + kafka pods

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
