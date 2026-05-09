#!/usr/bin/env bash
# test-all-variants.sh — run kafka-security-scanner against every Kafka/Redpanda variant
# in docker-compose.test-matrix.yaml and assert expected outcomes per variant.
#
# Usage:
#   scripts/test-all-variants.sh                # run all variants
#   scripts/test-all-variants.sh kafka-42-plaintext  # run a single variant
#
# Exit codes:
#   0 — all targeted variants behaved as expected
#   1 — one or more variants produced unexpected scanner output
#   2 — infrastructure failure (compose or scanner could not run)

set -euo pipefail

cd "$(dirname "$0")/.."

COMPOSE_FILE="docker-compose.test-matrix.yaml"
POLICY="policies/test-minimal-valid.yaml"
OUT_BASE="reports/matrix"
CMD="build/install/kafka-security-scanner/bin/kafka-security-scanner"

declare -A PORTS=(
  [kafka-42-plaintext]=19092
  [kafka-42-sasl]=29092
  [kafka-39-plaintext]=39092
  [kafka-42-acl]=49092
  [redpanda-plaintext]=59092
  [redpanda-sasl]=65093
  [kafka-42-jmx]=14092
  [kafka-42-cluster3]=13092
)

# Containers needed for each variant (handles multi-node like cluster3).
declare -A SERVICES=(
  [kafka-42-plaintext]=kafka-42-plaintext
  [kafka-42-sasl]=kafka-42-sasl
  [kafka-39-plaintext]=kafka-39-plaintext
  [kafka-42-acl]=kafka-42-acl
  [redpanda-plaintext]=redpanda-plaintext
  [redpanda-sasl]=redpanda-sasl
  [kafka-42-jmx]=kafka-42-jmx
  [kafka-42-cluster3]="kafka-42-cluster3-1 kafka-42-cluster3-2 kafka-42-cluster3-3"
)

declare -A AUTH_FLAGS=(
  [kafka-42-plaintext]=""
  [kafka-42-sasl]="--security-protocol SASL_PLAINTEXT --sasl-mechanism PLAIN --sasl-username admin --sasl-password admin-secret"
  [kafka-39-plaintext]=""
  [kafka-42-acl]="--security-protocol SASL_PLAINTEXT --sasl-mechanism PLAIN --sasl-username admin --sasl-password admin-secret"
  [redpanda-plaintext]=""
  [redpanda-sasl]="--security-protocol SASL_PLAINTEXT --sasl-mechanism SCRAM-SHA-256 --sasl-username admin --sasl-password admin-secret"
  [kafka-42-jmx]="--collectors adminclient,jmx --jmx-host-port localhost:9999"
  [kafka-42-cluster3]=""
)

# fail_threshold values: minimum acceptable failCount; exit 1 if scanner reports fewer.
declare -A MIN_FAILS=(
  [kafka-42-plaintext]=3
  [kafka-42-sasl]=1
  [kafka-39-plaintext]=3
  [kafka-42-acl]=2          # SEC-001 + the wildcard ACL we'll create -> SEC-004
  [redpanda-plaintext]=2
  [redpanda-sasl]=0
  [kafka-42-jmx]=3
  [kafka-42-cluster3]=2
)

# Findings the scanner MUST report for the variant. Empty list = no specific assertion.
declare -A MUST_FAIL=(
  [kafka-42-plaintext]="SEC-001 SEC-008"
  [kafka-42-acl]="SEC-004"            # the wildcard ACL we bootstrap below
  [kafka-42-jmx]="SEC-001"
  [kafka-42-cluster3]="SEC-001"
)

ALL_VARIANTS=(
  kafka-42-plaintext kafka-42-sasl kafka-39-plaintext kafka-42-acl
  redpanda-plaintext redpanda-sasl
  kafka-42-jmx kafka-42-cluster3
)
TARGETS=("${@:-${ALL_VARIANTS[@]}}")

if [[ ! -x "$CMD" ]]; then
  echo "→ Building scanner distribution"
  gradle installDist -x test -x check >/dev/null
fi

mkdir -p "$OUT_BASE"

failures=()
results_summary=""

bootstrap_acl_variant() {
  # Create a wildcard ACL so KAFKA-ACL-013 / SEC-004 has something to flag.
  # Run kafka-acls.sh from the broker container but talk to it via the *internal*
  # advertised port (kafka42-acl:9092). The host-mapped port (localhost:49092) is
  # only routable from outside the docker network.
  local container="kafka-security-scanner-java-kafka-42-acl-1"
  echo "→ Bootstrapping ACLs on kafka-42-acl (via INTERNAL listener)"
  for attempt in 1 2 3 4 5; do
    if docker exec "$container" /opt/kafka/bin/kafka-acls.sh \
        --bootstrap-server kafka42-acl:9094 \
        --add --allow-principal "User:*" \
        --operation Read --topic test-public-feed > /dev/null 2>&1; then
      break
    fi
    sleep 2
  done
  docker exec "$container" /opt/kafka/bin/kafka-acls.sh \
    --bootstrap-server kafka42-acl:9094 \
    --add --allow-principal "User:app-team" \
    --operation Write --topic users-events > /dev/null 2>&1 || true
}

for variant in "${TARGETS[@]}"; do
  port="${PORTS[$variant]:-}"
  if [[ -z "$port" ]]; then
    echo "✗ Unknown variant: $variant"
    failures+=("$variant:unknown")
    continue
  fi

  echo "═══ $variant (port $port) ═══"
  out_dir="$OUT_BASE/$variant"
  mkdir -p "$out_dir"

  services="${SERVICES[$variant]}"
  echo "→ Starting container(s): $services"
  # shellcheck disable=SC2086
  if ! docker compose -f "$COMPOSE_FILE" up -d $services >/dev/null 2>&1; then
    echo "✗ compose up failed"
    failures+=("$variant:compose")
    continue
  fi

  echo "→ Waiting for broker on $port"
  ready=0
  for i in {1..60}; do
    if nc -z localhost "$port" 2>/dev/null; then
      ready=1
      break
    fi
    sleep 1
  done

  if [[ $ready -eq 0 ]]; then
    echo "✗ broker never became reachable on $port"
    failures+=("$variant:not-ready")
    # shellcheck disable=SC2086
    docker compose -f "$COMPOSE_FILE" stop $services >/dev/null 2>&1 || true
    continue
  fi

  # Brokers respond on port long before AdminClient is ready; give the cluster time.
  case "$variant" in
    redpanda-*)         sleep 18 ;;
    kafka-42-cluster3)  sleep 18 ;;
    *)                  sleep 10 ;;
  esac

  if [[ "$variant" == "kafka-42-acl" ]]; then
    bootstrap_acl_variant
    sleep 2
  fi

  echo "→ Scanning"
  set +e
  auth_args="${AUTH_FLAGS[$variant]:-}"
  # shellcheck disable=SC2086
  "$CMD" \
    --bootstrap "localhost:$port" \
    --policy "$POLICY" \
    --format json \
    --out "$out_dir" \
    --timeout 60 \
    --fail-on none \
    --cluster-name "$variant" \
    $auth_args \
    > "$out_dir/scanner.log" 2>&1
  scanner_exit=$?
  set -e

  if [[ ! -f "$out_dir/report.json" ]]; then
    echo "✗ scanner produced no report (exit=$scanner_exit)"
    failures+=("$variant:no-report")
    # shellcheck disable=SC2086
    docker compose -f "$COMPOSE_FILE" stop $services >/dev/null 2>&1 || true
    continue
  fi

  fail_count=$(jq '.fail_count' "$out_dir/report.json")
  pass_count=$(jq '.pass_count' "$out_dir/report.json")
  score=$(jq '.score' "$out_dir/report.json")
  brokers=$(jq '.cluster.brokers' "$out_dir/report.json")
  expected_min="${MIN_FAILS[$variant]}"

  status="OK"
  if [[ "$fail_count" -lt "$expected_min" ]]; then
    status="MISMATCH (expected >= $expected_min fails, got $fail_count)"
    failures+=("$variant:fewer-fails")
  fi

  must_fail="${MUST_FAIL[$variant]:-}"
  if [[ -n "$must_fail" ]]; then
    failed_ids=$(jq -r '.findings[] | select(.status=="fail") | .control_id' "$out_dir/report.json")
    for required in $must_fail; do
      if ! grep -qx "$required" <<< "$failed_ids"; then
        status="MISSING-FINDING $required"
        failures+=("$variant:missing-$required")
      fi
    done
  fi

  if [[ "$variant" == "kafka-42-cluster3" && "$brokers" -ne 3 ]]; then
    status="WRONG-BROKER-COUNT (expected 3, got $brokers)"
    failures+=("$variant:broker-count")
  fi

  line=$(printf "%-22s score=%3d  pass=%2d  fail=%2d  brokers=%d  %s\n" \
    "$variant" "$score" "$pass_count" "$fail_count" "$brokers" "$status")
  echo "$line"
  results_summary+="$line"

  # shellcheck disable=SC2086
  docker compose -f "$COMPOSE_FILE" stop $services >/dev/null 2>&1 || true
done

echo
echo "═══ Summary ═══"
printf "%s" "$results_summary"

if (( ${#failures[@]} > 0 )); then
  echo
  echo "✗ Failures:"
  printf '  %s\n' "${failures[@]}"
  exit 1
fi

echo "✓ All targeted variants behaved as expected"
