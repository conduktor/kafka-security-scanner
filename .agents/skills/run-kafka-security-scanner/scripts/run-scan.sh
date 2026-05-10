#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd -- "${script_dir}/../../../.." && pwd)"

bootstrap="${BOOTSTRAP:-}"
if [[ -z "${bootstrap}" ]]; then
  printf 'BOOTSTRAP is required, for example BOOTSTRAP=broker:9092 %s\n' "$0" >&2
  exit 2
fi

out_dir="${OUT_DIR:-reports/cluster-audit}"
policy="${POLICY:-enterprise}"
format="${FORMAT:-terminal,json,html,csv,sarif}"
timeout="${TIMEOUT:-60}"
fail_on="${FAIL_ON:-none}"

collectors="${COLLECTORS:-adminclient,tls}"
append_collector() {
  local name="$1"
  case ",${collectors}," in
    *",${name},"*) ;;
    *) collectors="${collectors},${name}" ;;
  esac
}

args=(
  --bootstrap "${bootstrap}"
  --policy "${policy}"
  --collectors "${collectors}"
  --format "${format}"
  --out "${out_dir}"
  --timeout "${timeout}"
  --fail-on "${fail_on}"
)

add_value_arg() {
  local env_name="$1"
  local flag="$2"
  local collector="${3:-}"
  local value="${!env_name:-}"
  if [[ -n "${value}" ]]; then
    args+=("${flag}" "${value}")
    if [[ -n "${collector}" ]]; then
      append_collector "${collector}"
    fi
  fi
}

add_value_arg KAFKA_CLIENT_CONFIG --kafka-client-config
add_value_arg SECURITY_PROTOCOL --security-protocol
add_value_arg SASL_MECHANISM --sasl-mechanism
add_value_arg SASL_USERNAME --sasl-username
add_value_arg SASL_PASSWORD --sasl-password
add_value_arg SASL_JAAS_CONFIG --sasl-jaas-config
add_value_arg KAFKA_CONFIG_DIR --kafka-config-dir filesystem
add_value_arg JMX_HOST_PORT --jmx-host-port jmx
add_value_arg CONNECT_URL --connect-url connect
add_value_arg SCHEMA_REGISTRY_URL --schema-registry-url schemaregistry
add_value_arg REST_PROXY_URL --rest-proxy-url restproxy
add_value_arg PROMETHEUS_URL --prometheus-url alerts
add_value_arg DOCS_DIR --docs-dir docs
add_value_arg CIS_REPORT --cis-report cis
add_value_arg CONSUMER_JMX_HOST_PORTS --consumer-jmx-host-ports consumerjmx
add_value_arg STREAMS_JMX_HOST_PORTS --streams-jmx-host-ports streams
add_value_arg STREAMS_STATE_DIR --streams-state-dir streams
add_value_arg KAFKA_FLAVOR --kafka-flavor

if [[ "${ALLOW_ACTIVE_PROBES:-false}" == "true" ]]; then
  args+=(--allow-active-probes)
fi

args[5]="${collectors}"

cd "${repo_root}"
gradle installDist --no-daemon

scanner="build/install/kafka-security-scanner/bin/kafka-security-scanner"
"${scanner}" "${args[@]}" ${EXTRA_ARGS:-}

json_report="${out_dir}/report.json"
if command -v jq >/dev/null 2>&1 && [[ -f "${json_report}" ]]; then
  jq '{cluster, score, pass_count, fail_count, na_count, error_count, collectors_used, collectors_unavailable}' "${json_report}"
fi
