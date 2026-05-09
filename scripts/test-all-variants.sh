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
)

declare -A AUTH_FLAGS=(
  [kafka-42-plaintext]=""
  [kafka-42-sasl]="--security-protocol SASL_PLAINTEXT --sasl-mechanism PLAIN --sasl-username admin --sasl-password admin-secret"
  [kafka-39-plaintext]=""
  [kafka-42-acl]="--security-protocol SASL_PLAINTEXT --sasl-mechanism PLAIN --sasl-username admin --sasl-password admin-secret"
  [redpanda-plaintext]=""
  [redpanda-sasl]="--security-protocol SASL_PLAINTEXT --sasl-mechanism SCRAM-SHA-256 --sasl-username admin --sasl-password admin-secret"
)

# fail_threshold values: minimum acceptable failCount; exit 1 if scanner reports fewer.
declare -A MIN_FAILS=(
  [kafka-42-plaintext]=3   # plaintext: SEC-001, SEC-008, REL-001 at minimum
  [kafka-42-sasl]=1        # SASL but PLAINTEXT inter-broker -> SEC-001 still fires
  [kafka-39-plaintext]=3   # same baseline
  [kafka-42-acl]=1         # ACLs on but inter-broker plain -> SEC-001
  [redpanda-plaintext]=2   # SEC-001 plus likely REL-004
  [redpanda-sasl]=0        # opportunistic
)

ALL_VARIANTS=(kafka-42-plaintext kafka-42-sasl kafka-39-plaintext kafka-42-acl redpanda-plaintext redpanda-sasl)
TARGETS=("${@:-${ALL_VARIANTS[@]}}")

if [[ ! -x "$CMD" ]]; then
  echo "→ Building scanner distribution"
  gradle installDist -x test -x check >/dev/null
fi

mkdir -p "$OUT_BASE"

failures=()
results_summary=""

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

  echo "→ Starting container"
  docker compose -f "$COMPOSE_FILE" up -d "$variant" >/dev/null 2>&1 || {
    echo "✗ compose up failed"
    failures+=("$variant:compose")
    continue
  }

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
    docker compose -f "$COMPOSE_FILE" stop "$variant" >/dev/null 2>&1 || true
    continue
  fi

  # Brokers respond on port long before AdminClient is ready; give the cluster time
  # to apply bootstrap config (Redpanda especially) before authentication is functional.
  case "$variant" in
    redpanda-*) sleep 18 ;;
    *) sleep 10 ;;
  esac

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
    docker compose -f "$COMPOSE_FILE" stop "$variant" >/dev/null 2>&1 || true
    continue
  fi

  fail_count=$(jq '.fail_count' "$out_dir/report.json")
  pass_count=$(jq '.pass_count' "$out_dir/report.json")
  score=$(jq '.score' "$out_dir/report.json")
  expected_min="${MIN_FAILS[$variant]}"

  status="OK"
  if [[ "$fail_count" -lt "$expected_min" ]]; then
    status="MISMATCH (expected >= $expected_min fails, got $fail_count)"
    failures+=("$variant:fewer-fails")
  fi

  line=$(printf "%-22s score=%3d  pass=%2d  fail=%2d  %s\n" \
    "$variant" "$score" "$pass_count" "$fail_count" "$status")
  echo "$line"
  results_summary+="$line"

  docker compose -f "$COMPOSE_FILE" stop "$variant" >/dev/null 2>&1 || true
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
