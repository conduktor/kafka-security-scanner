#!/usr/bin/env bash
set -euo pipefail

schema_registry_url="${SCHEMA_REGISTRY_URL:-http://localhost:28081}"
connect_url="${CONNECT_URL:-http://localhost:28083}"
prometheus_url="${PROMETHEUS_URL:-http://localhost:29090}"
kafka_container="${KAFKA_CONTAINER:-kss-audit-kafka}"

wait_for_http() {
  local name="$1"
  local url="$2"
  for _ in $(seq 1 60); do
    local code
    code="$(curl -s -o /dev/null -w '%{http_code}' "${url}" || true)"
    if [[ "${code}" == "200" ]]; then
      printf '%s ready at %s\n' "${name}" "${url}"
      return 0
    fi
    sleep 2
  done
  printf '%s did not become ready at %s\n' "${name}" "${url}" >&2
  return 1
}

wait_for_http "Schema Registry" "${schema_registry_url}/subjects"
wait_for_http "Kafka Connect" "${connect_url}/connectors"
wait_for_http "Prometheus" "${prometheus_url}/-/ready"

docker exec "${kafka_container}" sh -lc '
  set -e
  for topic in audit.orders audit.orders.dlq confluent-audit-log-events; do
    env -u KAFKA_JMX_OPTS -u JMX_PORT /opt/kafka/bin/kafka-topics.sh \
      --bootstrap-server localhost:9092 \
      --create --if-not-exists \
      --topic "${topic}" \
      --partitions 1 \
      --replication-factor 1
  done
'

curl -sS -X PUT "${schema_registry_url}/config" \
  -H 'Content-Type: application/vnd.schemaregistry.v1+json' \
  --data '{"compatibility":"BACKWARD"}' >/dev/null

curl -sS -X POST "${schema_registry_url}/subjects/audit.orders-value/versions" \
  -H 'Content-Type: application/vnd.schemaregistry.v1+json' \
  --data '{"schema":"{\"type\":\"record\",\"name\":\"Order\",\"namespace\":\"audit\",\"fields\":[{\"name\":\"id\",\"type\":\"string\",\"doc\":\"@owner platform-team\"},{\"name\":\"card_token\",\"type\":\"string\",\"doc\":\"@tokenized @encrypt pii\"}]}"}' >/dev/null

curl -sS -X PUT "${connect_url}/connectors/audit-mm2-source/config" \
  -H 'Content-Type: application/json' \
  --data '{
    "connector.class": "org.apache.kafka.connect.mirror.MirrorSourceConnector",
    "tasks.max": "1",
    "source.cluster.alias": "source",
    "target.cluster.alias": "target",
    "source.cluster.bootstrap.servers": "kafka:9092",
    "target.cluster.bootstrap.servers": "kafka:9092",
    "source.cluster.security.protocol": "PLAINTEXT",
    "target.cluster.security.protocol": "PLAINTEXT",
    "topics": "audit.orders",
    "sync.topic.acls.enabled": "false",
    "emit.heartbeats.enabled": "false",
    "emit.checkpoints.enabled": "false",
    "replication.factor": "1",
    "offset-syncs.topic.replication.factor": "1",
    "heartbeats.topic.replication.factor": "1",
    "checkpoints.topic.replication.factor": "1",
    "errors.tolerance": "all",
    "errors.deadletterqueue.topic.name": "audit.orders.dlq"
  }' >/dev/null

for _ in $(seq 1 30); do
  status="$(curl -sS "${connect_url}/connectors/audit-mm2-source/status")"
  if [[ "${status}" == *'"connector":{"state":"RUNNING"'* && "${status}" == *'"tasks":[{"id":0,"state":"RUNNING"'* ]]; then
    printf '%s\n' "${status}"
    exit 0
  fi
  sleep 1
done

printf '%s\n' "${status}"
printf 'Connector did not reach RUNNING state\n' >&2
exit 1
