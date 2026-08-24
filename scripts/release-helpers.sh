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
