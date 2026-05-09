# kafka-security-scanner

Scan a Kafka cluster against a catalogue of security and reliability controls. Works against Apache Kafka and anything that speaks the protocol.

Give it a bootstrap server (plus credentials if the cluster needs them) and a principal that can `Describe` brokers, topics, and ACLs. You get back a graded report. Hook it into CI to fail PRs that introduce regressions.

## What you get

```
$ kafka-security-scanner --bootstrap localhost:9092 --policy enterprise

=== Kafka Security Scanner ===
Bootstrap: localhost:9092
Policy:    enterprise-default.yaml  (118 controls)

Collecting cluster data... brokers=3 topics=42 acls=17
Evaluating 118 controls...

  Score: 72/100  |  Pass: 94  |  Fail: 19  |  N/A: 5  |  Pass Rate: 83%

  Top findings:
    critical  SEC-001  One or more listeners use PLAINTEXT
    critical  SEC-008  Inter-broker communication is not encrypted
    high      SEC-014  ACLs grant wildcard principal '*' on 3 topics
    high      REL-001  min.insync.replicas is below 2 — risk of data loss
    high      REL-004  4 topics have replication factor < 2
    medium    SEC-011  Auto topic creation is enabled
    ...

Wrote: reports/report.json   reports/report.sarif   reports/report.html
       reports/report.csv    reports/report.pdf
```

The same run also writes the HTML version (collapsible findings), a SARIF file for GitHub Code Scanning, a CSV the auditors can filter by `pci_dss`/`soc2`/`iso27001`, and a PDF with a cover page if someone has to sign it off.

## Why a policy engine

Most scanners in this space ship a fixed list of checks compiled into the binary. When your auditor asks "show me every control that maps to PCI-DSS 4.1," you read source code.

Here, controls are data. Each one is a YAML entry with a condition, a severity, a remediation, and the regulations it covers. Want a stricter prod policy and a permissive dev one? Two files. Need to know which controls satisfy a given clause? It's already in the finding's `compliance` block. None of it needs a rebuild.

The 118-control reference catalogue, and its mappings to CWE, NIST 800-53, PCI-DSS 4.0, SOC2, and ISO 27001, lives in [`conduktor/kafka-security-controls`](https://github.com/conduktor/kafka-security-controls). That's where the regulation discussion happens. This repo runs the result.

## What the scanner actually sees

The scanner refuses to lie. Every control either evaluates to a real boolean against collected data, declares it needs operator attestation, or is explicitly covered by a managed-service contract. Silent placeholder controls are rejected at policy load: `condition: "true"` without escape hatch is a build error.

Of the 120 enterprise controls today (against a single-broker plaintext cluster with `--collectors adminclient,filesystem,tls`):

- **~46 evaluated automatically** — combination of AdminClient/filesystem/tls/process collectors actually checking something
- **~70 require operator attestation** — governance, runbook, OS, and ecosystem controls that need a human to confirm. Pass `--attest <file.properties>` mapping `<control_id>=pass|fail|na` to record verdicts. Without it, those controls report `attestation_required` (neither pass nor fail).
- **~3 covered by managed-service contract** — disk encryption, patching, encrypted backups on Confluent Cloud / AWS MSK / Aiven / Redpanda Cloud (auto-detected, see Flavors below).

The split shifts as you enable more collectors and as the catalogue gains new conditions. Adding a JMX-enabled broker and turning on `--collectors=...,jmx` flips ~5 more controls from attestation to automatic.

## Collectors

Each collector populates a slice of the cluster snapshot. Controls declare `requires: [...]` and the engine returns `na` (with rationale) when a required collector isn't running. No collector → no silent pass.

| Collector     | Flag                              | What it sees                                                                                  | Examples of controls it unlocks                              |
|---------------|-----------------------------------|----------------------------------------------------------------------------------------------|---------------------------------------------------------------|
| `adminclient` | enabled by default                | Broker configs, topic configs, ACLs, listeners, KRaft cluster state                          | SASL posture, TLS on listeners, RF/ISR, wildcard ACLs         |
| `filesystem`  | `--kafka-config-dir /etc/kafka`   | Local config dir: parses `server.properties`, lists files with POSIX perms, JAAS presence    | KAFKA-FS-001 JAAS world-readable, keystore perms, log4j path  |
| `jmx`         | `--jmx-host-port host:9999`       | Broker MBeans over RMI: URP, OfflinePartitions, RequestHandlerIdle, MessagesIn, GC, FD usage | KAFKA-JMX-001 broker URP, request queue saturation            |
| `tls`         | `--collectors=...,tls`            | Real TLS handshake to bootstrap host, leaf cert chain, expiry, key size, SAN, cipher suite   | KAFKA-TLS-001 cert >30d to expiry, weak ciphers               |
| `process`     | `--collectors=...,process` (Linux)| `/proc/<pid>/cmdline` + `limits`: JVM flags, heap, GC, ulimits, Kafka version from jar       | KAFKA-OPS-007 ulimit, run-as-non-root, JVM flag policy        |

Combined example:

```bash
kafka-security-scanner \
  --bootstrap broker.prod:9092 \
  --collectors adminclient,filesystem,tls,jmx \
  --kafka-config-dir /etc/kafka \
  --jmx-host-port broker.prod:9999 \
  --policy enterprise \
  --attest attestations.properties \
  --format sarif,html,csv
```

Where `attestations.properties` looks like:

```properties
KAFKA-AVAIL-003 = pass    # quarterly DR drill done 2026-04-12
KAFKA-OPS-001   = pass    # patched within 30d of CVE-2026-1234
KAFKA-DATA-001  = na      # this cluster carries only public data
```

### Cross-validation

The same fact can be checked by multiple collectors. Example: TLS posture on the inter-broker listener is reported by AdminClient (`security.inter.broker.protocol`) AND by the TLS collector's handshake (`tls.handshake_ok` + `tls.protocol`). Controls can `&&` both sides, so config drift between what the broker thinks it's serving and what it actually serves becomes visible.

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

```bash
./install.sh
kafka-security-scanner \
  --bootstrap localhost:9092 \
  --policy enterprise \
  --format terminal,json,sarif,html \
  --out ./reports
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
