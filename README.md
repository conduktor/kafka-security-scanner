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
