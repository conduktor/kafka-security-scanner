---
name: run-kafka-security-scanner
description: Run this project's kafka-security-scanner against a real Kafka cluster or the repo's Docker Compose audit ecosystem, collect non-fabricated evidence, and produce/summarize JSON, HTML, CSV, and SARIF reports. Use when users ask to launch, validate, demo, audit, or troubleshoot scans on their Kafka, Connect, Schema Registry, Prometheus, JMX, cloud-managed Kafka, or local Docker environment.
---

# Run Kafka Security Scanner

## Core Rules

Use real endpoints and real credentials only. Do not invent docs, configs, findings, or governance artifacts to make controls pass.

Treat N/A as missing evidence, not success. Call out unavailable collectors and explain which endpoint, credential, or artifact would reduce the N/A set.

Keep production probes non-mutating by default. Add `--allow-active-probes` only for an isolated lab or when the user explicitly approves active writes against the target.

Prefer `--kafka-client-config` for production auth because it carries real truststores, keystores, OAuth handlers, and custom Kafka client settings. Use simplified SASL flags only for quick local checks.

## Fast Path

Use the bundled wrapper when the user gives a cluster target:

```bash
BOOTSTRAP=broker:9092 \
KAFKA_CLIENT_CONFIG=./client.properties \
CONNECT_URL=https://connect.example.com \
SCHEMA_REGISTRY_URL=https://schema-registry.example.com \
PROMETHEUS_URL=https://prometheus.example.com \
OUT_DIR=reports/prod-audit \
.agents/skills/run-kafka-security-scanner/scripts/run-scan.sh
```

The wrapper builds `installDist`, selects collectors from the supplied endpoints, writes reports, and prints a compact JSON summary. Set `FAIL_ON=high` for CI gates; the wrapper defaults to `FAIL_ON=none` so interactive audit runs still finish and write reports.

## Collector Selection

Start with `adminclient,tls`. Add collectors only when the user provides real access:

- `connect`: `CONNECT_URL` or `--connect-url`
- `schemaregistry`: `SCHEMA_REGISTRY_URL` or `--schema-registry-url`
- `alerts`: `PROMETHEUS_URL` or `--prometheus-url`
- `jmx`: `JMX_HOST_PORT` or `--jmx-host-port`
- `filesystem`: `KAFKA_CONFIG_DIR` pointing to the broker's actual config directory or a copied directory from the running broker
- `docs`: `DOCS_DIR` only when the user supplies real, reviewable governance artifacts
- `restproxy`, `consumerjmx`, `streams`, `siem`, `cis`, cloud collectors: include only with their real endpoints, local access, reports, or credentials

For managed services, do not rely on `--kafka-flavor` alone as evidence. Enable the vendor collector with real API credentials so coverage is verified by the provider API.

## Local Docker Audit Lab

For a reproducible local demo, use `examples/audit-compose/docker-compose.yml`. It runs real Kafka, Schema Registry, Connect, and Prometheus services. It is intentionally not a production-hardening example; its value is proving scanner behavior and report generation against live services.

Run:

```bash
docker compose -f examples/audit-compose/docker-compose.yml -p kss-audit up -d
```

Then seed real resources before scanning: Kafka topics, a Schema Registry subject, and a Connect connector. Use `--allow-active-probes` only in this lab if you want Schema Registry write-auth evidence.

```bash
examples/audit-compose/seed.sh
```

## Reporting

Always give the user the report paths and a short summary:

- score, pass/fail/N/A/error counts
- collectors used and unavailable collectors
- top critical/high findings
- at least one concrete evidence example for ecosystem controls such as Connect topic enumeration or Schema Registry write probing

Use `reports/.../report.html` for human review and `reports/.../report.json` or `report.csv` for auditor filtering. Do not summarize a cluster as compliant when critical controls are N/A or when active evidence was not collected.
