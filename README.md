# kafka-security-scanner

Scan a Kafka cluster against a catalogue of security and reliability controls. Works against Apache Kafka and anything that speaks the protocol.

Give it a bootstrap server (plus credentials if the cluster needs them) and a principal that can `Describe` brokers, topics, and ACLs. You get back a graded report. Hook it into CI to fail PRs that introduce regressions.

## What you get

```
$ kafka-security-scanner --bootstrap broker.prod:9092 --policy enterprise \
    --collectors adminclient,filesystem,tls,siem,alerts,connect,schemaregistry,docs,jmx \
    --kafka-config-dir /etc/kafka --docs-dir ./governance \
    --prometheus-url http://prom:9090 --connect-url http://connect:8083 \
    --schema-registry-url http://sr:8081 --jmx-host-port broker.prod:9999

=== Kafka Security Scanner ===
Bootstrap: broker.prod:9092
Policy:    enterprise-default.yaml  (138 controls)
Kafka flavor: vanilla  (hostname:broker.prod)

Collecting cluster data... brokers=3 topics=42 acls=17
Evaluating 138 controls...

  Score: 72/100  |  Pass: 94  |  Fail: 19  |  N/A: 25  |  Pass Rate: 83%

  Top findings:
    critical  KAFKA-NET-004  PLAINTEXT listener detected
    critical  KAFKA-ENC-001  Inter-broker communication is not encrypted
    high      KAFKA-ACL-006  Default allow policy — unauthenticated users can access resources
    high      KAFKA-AUDIT-010  Audit log layout does not capture principal and/or client identity
    medium    KAFKA-MON-005  Consumer lag is not monitored
    ...

Wrote: reports/report.json   reports/report.sarif   reports/report.html
       reports/report.csv    reports/report.pdf
```

The same run also writes the HTML version (collapsible findings, the list of collectors that ran), a SARIF file for GitHub Code Scanning, a CSV the auditors can filter by `pci_dss`/`soc2`/`iso27001`, and a PDF with a cover page if someone has to sign it off.

## Why a policy engine

Most scanners in this space ship a fixed list of checks compiled into the binary. When your auditor asks "show me every control that maps to PCI-DSS 4.1," you read source code.

Here, controls are data. Each one is a YAML entry with a condition, a severity, a remediation, and the regulations it covers. Want a stricter prod policy and a permissive dev one? Two files. Need to know which controls satisfy a given clause? It's already in the finding's `compliance` block. None of it needs a rebuild.

The control catalogue, and its mappings to CWE, NIST 800-53, PCI-DSS 4.0, SOC2, and ISO 27001, lives in [`conduktor/kafka-security-controls`](https://github.com/conduktor/kafka-security-controls). That's where the regulation discussion happens. This repo runs the result.

## What the scanner actually sees

The scanner refuses to lie. Every control evaluates to a real boolean against collected data OR is explicitly covered by a managed-service contract. There is no "attestation" status — silent placeholder controls (`condition: "true"` with no escape hatch) are rejected at policy load.

Status is one of: `pass`, `fail`, `na` (required collector unavailable), `covered_by_flavor` (managed-service SLA), `error` (CEL eval failure — never happens in steady state).

The split between automatic and N/A shifts as you enable more collectors. The reference catalogue has 138 controls; on a single-broker plaintext cluster with only `--collectors=adminclient`, ~16 pass / ~41 fail / ~63 N/A. Wire in the cloud-native collectors (`--cc-api-key`, `--aws-region`, `--aiven-token`, ...) and the N/A bucket shrinks toward zero.

## Collectors

Each collector populates a slice of the cluster snapshot. Controls declare `requires: [...]` (or `requires_per_mode:` for ZK/KRaft-branched checks) and the engine returns `na` when a required collector isn't running. No collector → no silent pass.

Collectors run concurrently on virtual threads — adding a slow probe doesn't block the cheap ones.

### Core (cluster + host)

| Collector       | Flag(s)                                                       | What it sees                                                                                          |
|-----------------|---------------------------------------------------------------|------------------------------------------------------------------------------------------------------|
| `adminclient`   | enabled by default                                            | Broker configs (incl. `config_int` numeric mirror), topic configs, ACLs, KRaft state, system topics  |
| `filesystem`    | `--kafka-config-dir /etc/kafka`                               | server.properties, log4j layout pattern parser, retention proof, /proc/mounts cryptsetup probe       |
| `jmx`           | `--jmx-host-port host:9999[,host2:9999]`                      | Multi-target broker MBeans: URP, OfflinePartitions, RequestHandlerIdle, GC, FD                       |
| `tls`           | `--collectors=...,tls`                                        | TLS handshake to bootstrap host, leaf cert chain, expiry, key size, SAN, cipher                      |
| `process`       | `--collectors=...,process` (Linux)                            | /proc/<pid>/cmdline + limits: JVM flags, heap, GC, ulimits, Kafka version                            |
| `consumerjmx`   | `--consumer-jmx-host-ports host:1099,...`                     | consumer-fetch-manager-metrics records-lag-max per client                                            |
| `streams`       | `--streams-jmx-host-ports`, `--streams-state-dir`             | Streams app JMX + state.dir POSIX audit                                                              |

### Ecosystem (REST APIs)

| Collector         | Flag(s)                                                                | What it sees                                                                              |
|-------------------|------------------------------------------------------------------------|------------------------------------------------------------------------------------------|
| `connect`         | `--connect-url http://host:8083`                                       | Per-connector config: transforms, MM2 security, DLQ, REST auth posture                   |
| `schemaregistry`  | `--schema-registry-url http://host:8081`                               | Per-subject schema (annotations: `@encrypt` / `@tokenized` / `@owner`); write-auth probes require `--allow-active-probes` |
| `restproxy`       | `--rest-proxy-url http://host:8082`                                    | REST Proxy auth posture                                                                  |
| `alerts`          | `--prometheus-url http://prom:9090`                                    | Prometheus rule scan: auth-failure / ACL-change / quota-breach / anomaly / consumer-lag  |
| `siem`            | `--collectors=...,siem`                                                | Local process + 127.0.0.1 port probe for vector / fluentd / filebeat / splunkforwarder   |
| `zk`              | `--zk-admin-host-port host:2181`                                       | ZK 4lw probe — sensitive_commands_leaked (dump/envi/wchs/...)                           |
| `docs`            | `--docs-dir ./governance`                                              | Governance artefact presence + age (key-rotation-log, admin-principals, ...)            |
| `cis`             | `--cis-report ./cis.json`                                              | cis-cat / kube-bench / inspec JSON ingest → pass_ratio + failed_ids                     |

### Cloud-native (vendor APIs)

| Collector          | Auto-activated on flavor | Flag(s)                                                                                       | What it sees                                                                                |
|--------------------|--------------------------|----------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------|
| `confluentcloud`   | `*.confluent.cloud`      | `--cc-api-key`, `--cc-api-secret`, `--cc-cluster-id` (env CC_API_KEY/CC_API_SECRET/CC_CLUSTER_ID) | api.confluent.cloud + Metrics API auth; cluster spec (dedicated/enterprise, private network, BYOK) |
| `awsmsk`           | `*.kafka*.amazonaws.com` | `--aws-region`, `--aws-msk-cluster-arn` (default cred chain: AWS_PROFILE / IRSA / IMDSv2)    | MSK cluster spec, EC2 SG ingress, CloudWatch URP/OfflinePartitionsCount                    |
| `aiven`            | `*.aivencloud.com`       | `--aiven-token`, `--aiven-project`, `--aiven-service` (env AIVEN_TOKEN)                      | api.aiven.io auth; service spec (plan, ip_filter, kafka_authentication_methods)            |
| `rpcloud`          | `*.cloud.redpanda.com`   | `--rp-token`, `--rp-cluster-id` (env RP_TOKEN)                                               | api.redpanda.com auth; cluster spec (connection_type, region, type)                         |
| `azure`            | `*.servicebus.windows.net` | `--azure-token`, `--azure-subscription-id`, `--azure-resource-group`, `--azure-namespace`  | management.azure.com auth; namespace spec (TLS version, public network access, private endpoints) |
| `gcp`              | n/a (creds-driven)       | `--gcp-token`, `--gcp-project` (env GCP_TOKEN/GCP_PROJECT; obtain via `gcloud auth print-access-token`) | compute.googleapis.com firewall scan: any 0.0.0.0/0 ingress on broker ports               |
| `k8s`              | n/a                      | `--k8s-namespace ns` (uses local `kubectl`)                                                   | NetworkPolicy + kafka-pod selectors + default-deny detection                                 |

### Derived

| Collector | Flag    | What it does                                                                                    |
|-----------|---------|------------------------------------------------------------------------------------------------|
| `kms`     | always  | Walks broker / connect / fs configs for `${provider:path}` placeholders; classifies file/env vs external (vault/aws/gcp/azure) |

### Cross-validation

The same fact can be checked by multiple collectors. Example: TLS posture on the inter-broker listener is reported by AdminClient (`security.inter.broker.protocol`) AND by the TLS collector's handshake (`tls.handshake_ok` + `tls.protocol`). Controls can `&&` both sides, so config drift between what the broker thinks it's serving and what it actually serves becomes visible.

The cloud-native cross-validation is the killer use case: AdminClient says encryption-in-transit is on, AwsMskCollector confirms it via the MSK API, FilesystemCollector confirms /proc/mounts has dm-crypt — drift in any one trips the AND.

### Adding a collector

Implement `io.kafkascanner.collectors.Collector`:

```java
public final class CloudIamCollector implements Collector {
    public String name() { return "cloud-iam"; }
    public boolean isAvailable(CollectorContext c) { return c.cloudCreds() != null; }
    public Map<String, Object> collect(CollectorContext c) {
        return Map.of("cloud_iam", iamSnapshot(c.cloudCreds()));
    }
}
```

Wire it in `Main.java` behind a `--collectors=cloud-iam` flag, expose `cloud_iam` to CEL in `PolicyEngine`, and write controls with `requires: [cloud-iam]`. PRs welcome.

### Flavors

Auto-detected from the first hostname in `--bootstrap`:

| Pattern                              | Flavor              |
|--------------------------------------|---------------------|
| `*.confluent.cloud`                  | `confluent-cloud`   |
| `*.kafka.<region>.amazonaws.com`     | `aws-msk`           |
| `*.aivencloud.com`                   | `aiven`             |
| `*.cloud.redpanda.com`               | `redpanda-cloud`    |
| `*.servicebus.windows.net`           | `azure-eventhubs`   |
| `*.warpstream.com`                   | `warpstream`        |
| `*.conduktor.io` / `.cloud`          | `conduktor-gateway` |
| anything else                        | `vanilla`           |

Override with `--kafka-flavor confluent-cloud` if your hostname doesn't match (private DNS, on-prem with a vanity name, etc.). Flavor is included in every finding's evidence and at the top of the report.

## Quick start

Self-hosted Kafka, broad coverage:

```bash
./install.sh
kafka-security-scanner \
  --bootstrap localhost:9092 \
  --policy enterprise \
  --collectors adminclient,filesystem,tls,siem,docs \
  --kafka-config-dir /etc/kafka \
  --docs-dir ./governance \
  --format terminal,json,sarif,html
```

With SASL:

```bash
kafka-security-scanner \
  --bootstrap broker:9092 \
  --security-protocol SASL_PLAINTEXT \
  --sasl-mechanism SCRAM-SHA-512 \
  --sasl-username admin \
  --sasl-password "$KAFKA_PASSWORD" \
  --policy enterprise
```

For production clusters, prefer a real Kafka client properties file when you
need truststores, keystores, mTLS, OAuth callback handlers, or custom client
settings:

```bash
kafka-security-scanner \
  --bootstrap broker:9093 \
  --kafka-client-config ./client.properties \
  --policy enterprise
```

The scanner is non-mutating by default. Probes that may write to a target
system, such as Schema Registry anonymous-write verification, only run when
`--allow-active-probes` is passed in a controlled environment.

**Confluent Cloud:**

```bash
export CC_API_KEY=...; export CC_API_SECRET=...
kafka-security-scanner \
  --bootstrap pkc-XXXXX.us-east-1.aws.confluent.cloud:9092 \
  --collectors adminclient,confluentcloud,connect,schemaregistry \
  --cc-cluster-id lkc-XXXXX \
  --connect-url https://api.confluent.cloud --schema-registry-url ...
```

**AWS MSK (uses default AWS credential chain):**

```bash
kafka-security-scanner \
  --bootstrap b-1.cluster.kafka.us-east-1.amazonaws.com:9098 \
  --collectors adminclient,awsmsk \
  --aws-region us-east-1 \
  --security-protocol SASL_SSL --sasl-mechanism AWS_MSK_IAM
```

**Aiven / Redpanda Cloud / Azure EventHubs / GCP** — same pattern, see the table above. Each collector self-activates when the bootstrap host matches the flavor's pattern OR when its credential flags are passed.

**Kubernetes-deployed Kafka (Strimzi or otherwise):**

```bash
kafka-security-scanner \
  --bootstrap kafka.kafka:9092 \
  --collectors adminclient,k8s \
  --k8s-namespace kafka
```

**With a CIS hardening report:**

```bash
cis-cat-pro --benchmark "CIS Apache Kafka Benchmark" --output cis-out.json
kafka-security-scanner -b localhost:9092 \
  --collectors adminclient,cis \
  --cis-report cis-out.json
```

Exit codes are picked for CI gates:

- `0` — clean below the `--fail-on` threshold (default `high`)
- `1` — findings at or above the threshold (block the merge)
- `2` — scan itself failed (cluster unreachable, broken policy)

## Reports

| Format     | Audience                                         |
|------------|--------------------------------------------------|
| `terminal` | Engineer running the scan                        |
| `json`     | Pipelines, dashboards, anything downstream       |
| `sarif`    | GitHub Code Scanning, Defender, any SAST tool    |
| `html`     | Stakeholders skimming for the red items          |
| `csv`      | Auditors filtering by control ID or framework    |
| `pdf`      | Sign-off document with cover page and signatures |

Pass any combination via `--format`.

JSON, HTML, and CSV reports include `control_results` for every control, not
only failures. Each result includes redacted evidence, collector availability,
the evaluated condition, flavor coverage proof when relevant, and compliance
mappings.

## Policies

Built-in:

- `enterprise` → `policies/enterprise-default.yaml`, full 118-control catalogue
- `community`, `baseline` → `policies/test-minimal-valid.yaml`, 12-control smoke test
- Or pass a path to your own YAML

What a control looks like:

```yaml
- id: SEC-001
  title: Broker TLS encryption is enabled
  severity: critical
  category: security
  condition: brokers.all(b, b.listeners.all(l, l.protocol in ['SSL', 'SASL_SSL']))
  message: One or more listeners use PLAINTEXT
  remediation: Configure listeners with SSL:// or SASL_SSL://
  compliance:
    pci_dss: ["3.4", "4.1"]
    soc2: ["CC6.1"]
```

Conditions are CEL expressions evaluated by [cel-java](https://github.com/google/cel-java) over the cluster snapshot (`brokers`, `topics`, `acls`, `cluster`). Adding a check means editing YAML; no Java involved.

If you want a new control in the shared catalogue, the PR goes to [`conduktor/kafka-security-controls`](https://github.com/conduktor/kafka-security-controls). The YAML here is the projection.

## CI integration

```yaml
- run: kafka-security-scanner --bootstrap $KAFKA --format sarif --out reports --fail-on high
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: reports/report.sarif
```

## Test matrix

`docker-compose.test-matrix.yaml` ships six broker variants: Apache Kafka 3.9 and 4.2 in PLAINTEXT, SASL_PLAINTEXT, and ACL flavours, plus two Kafka-API-compatible alternatives. The script boots each, scans it, and asserts the expected fail count per variant. Handy when you start tweaking policies and want to know what changed.

```bash
scripts/test-all-variants.sh
scripts/test-all-variants.sh kafka-42-sasl
```

## Build

Java 25 (preview) and Gradle 8.12+, or use the Gradle wrapper.

```bash
gradle build           # compile, linters, tests
gradle installDist     # produces build/install/kafka-security-scanner/
gradle test            # JUnit + Testcontainers; SKIP_INTEGRATION_TESTS=1 to skip
```

## License

Apache 2.0. See [LICENSE](LICENSE).
