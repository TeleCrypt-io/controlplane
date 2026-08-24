#!/usr/bin/env bash
set -euo pipefail

: "${IMAGE_REF:?IMAGE_REF is required}"
: "${RELEASE_TAG:?RELEASE_TAG is required}"
: "${RELEASE_SHA:?RELEASE_SHA is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
temporary_root="$(mktemp -d "${TMPDIR:-/tmp}/controlplane-image.XXXXXX")"
cleanup() { rm -rf -- "$temporary_root"; }
trap cleanup EXIT
trap 'cleanup; exit 143' HUP INT TERM
bounded_value() {
  local max_bytes=65536 output stderr_file status bytes stderr_bytes
  output="$(mktemp "$temporary_root/output.XXXXXX")"
  stderr_file="$output.stderr"
  set +e
  /usr/bin/python3 "$script_dir/bounded-command.py" \
    --stdout-limit "$max_bytes" --stderr-limit "$max_bytes" \
    --stdout-path "$output" --stderr-path "$stderr_file" --timeout 120 -- \
    docker "$@"
  status="$?"
  set -e
  bytes="$(wc -c <"$output")"
  stderr_bytes="$(wc -c <"$stderr_file")"
  if (( bytes > max_bytes || stderr_bytes > max_bytes || status != 0 || stderr_bytes != 0 )); then
    cat "$stderr_file" >&2
    rm -f "$output" "$stderr_file"
    return 1
  fi
  cat "$output"
  rm -f "$output" "$stderr_file"
}

expected_source="https://github.com/${GITHUB_REPOSITORY}"
for label_expectation in \
  "org.opencontainers.image.source=$expected_source" \
  "org.opencontainers.image.revision=$RELEASE_SHA" \
  "org.opencontainers.image.version=$RELEASE_TAG" \
  "org.opencontainers.image.licenses=BUSL-1.1" \
  "org.opencontainers.image.title=TeleCrypt Controlplane" \
  "org.opencontainers.image.description=TeleCrypt Registration, Janitor, and Plan services" \
  "org.opencontainers.image.vendor=TeleCrypt.io" \
  "io.telecrypt.config-contract=1" \
  "org.telecrypt.controlplane.release=$RELEASE_TAG" \
  "org.telecrypt.tier-controller.release=$RELEASE_TAG"; do
  label_name="${label_expectation%%=*}"
  expected_value="${label_expectation#*=}"
  actual_value="$(bounded_value image inspect --format "{{index .Config.Labels \"$label_name\"}}" "$IMAGE_REF")"
  [[ "$actual_value" == "$expected_value" ]] || {
    echo "image label $label_name=$actual_value does not match $expected_value" >&2
    exit 1
  }
done

[[ "$(bounded_value image inspect --format '{{.Config.User}}' "$IMAGE_REF")" == "991:991" ]] || {
  echo "image user is not 991:991" >&2
  exit 1
}
[[ "$(bounded_value image inspect --format '{{json .Config.Entrypoint}}' "$IMAGE_REF")" == "null" ]] || {
  echo "image Entrypoint must be unset" >&2
  exit 1
}
[[ "$(bounded_value image inspect --format '{{json .Config.Cmd}}' "$IMAGE_REF")" == '["/registration"]' ]] || {
  echo "image default command must be [\"/registration\"]" >&2
  exit 1
}
