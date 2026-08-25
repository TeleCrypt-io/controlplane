#!/usr/bin/env bash

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

_bounded_capture() {
  local max_bytes="$1" output="$2" timeout_seconds="$3" stderr_file="${2}.stderr" status stderr_bytes
  shift 3
  [[ "$max_bytes" =~ ^[0-9]+$ && "$max_bytes" -gt 0 ]] || return 2
  set +e
  /usr/bin/python3 "$script_dir/bounded-command.py" \
    --stdout-limit "$max_bytes" --stderr-limit "$max_bytes" \
    --stdout-path "$output" --stderr-path "$stderr_file" --timeout "$timeout_seconds" -- "$@"
  status="$?"
  set -e
  stderr_bytes="$(wc -c <"$stderr_file")"
  if (( status != 0 )); then
    cat -- "$stderr_file" >&2
    return "$status"
  fi
  if (( stderr_bytes != 0 )); then
    cat -- "$stderr_file" >&2
    echo 'successful command emitted unexpected diagnostics' >&2
    return 1
  fi
}

bounded_capture() { _bounded_capture "$1" "$2" 120 "${@:3}"; }

# The original helper is retained for callers that already provide a bounded command. This
# adapter supplies the missing hard deadline for network/API commands as well.
bounded_capture_deadline() {
  local max_bytes="$1" output="$2" timeout_seconds="$3"
  shift 3
  [[ "$timeout_seconds" =~ ^[0-9]+$ && "$timeout_seconds" -gt 0 ]] || return 2
  _bounded_capture "$max_bytes" "$output" "$timeout_seconds" "$@"
}

redact_diagnostics() {
  sed -E \
    -e 's/(MAS_OIDC_CLIENT_SECRET|PLAN_SESSION_KEY|PLAN_ASSERTION_PRIVATE_KEY)([=:][[:space:]]*)[^[:space:]]+/\1\2[redacted]/g' \
    -e 's/((secret|token|password|private[[:space:]]+key))([=:][[:space:]]*)[^[:space:]]+/\1\3[redacted]/Ig' \
    "$@"
}

ghcr_version_records() {
  local page_json="$1" release_tag="$2" build_digest="$3"
  jq -e '
    type == "array" and length <= 100 and
    all(.[];
      type == "object" and
      (.id | type == "number" and . > 0 and . == floor) and
      (.name | type == "string" and test("^sha256:[0-9a-f]{64}$")) and
      (.metadata | type == "object" and .package_type == "container") and
      (.metadata.container | type == "object") and
      (.metadata.container.tags | type == "array" and
        all(.[]; type == "string" and test("^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")) and
        (length == (unique | length)))
    )' "$page_json" >/dev/null || return 1
  jq -r --arg tag "$release_tag" --arg digest "$build_digest" '
    .[] |
    [
      (.id | tostring),
      .name,
      ([.metadata.container.tags[] | select(. == $tag)] | length | tostring),
      (if .name == $digest then "1" else "0" end)
    ] | @tsv
  ' "$page_json"
}
