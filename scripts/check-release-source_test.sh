#!/usr/bin/env bash
# shellcheck disable=SC2016
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
helper="$repo_root/scripts/check-release-source.sh"
workflow="$repo_root/.github/workflows/build.yml"

grep -Fqx '#!/usr/bin/env bash' "$helper"
grep -Fq 'actions/checkout@v7.0.1' "$workflow"
grep -Fq 'fetch-depth: 0' "$workflow"
grep -Fq 'persist-credentials: false' "$workflow"
grep -Fq 'GIT_NO_REPLACE_OBJECTS=1' "$helper"
grep -Fq 'GIT_CONFIG_GLOBAL=/dev/null' "$helper"
grep -Fq 'GIT_CONFIG_SYSTEM=/dev/null' "$helper"
grep -Fq 'credential.helper=' "$helper"
grep -Fq 'http.proxy=' "$helper"
grep -Fq 'https://github.com/${GITHUB_REPOSITORY}.git' "$helper"
grep -Fq 'refs/tags/$RELEASE_TAG:$remote_tag_ref' "$helper"
grep -Fq 'refs/heads/main:"$remote_main_ref"' "$helper"
grep -Fq 'merge-base --is-ancestor' "$helper"
grep -Fq 'bounded_capture_deadline' "$repo_root/scripts/release-helpers.sh"
if grep -Eq '2>&1[[:space:]]*\|[[:space:]]*/usr/bin/head' "$repo_root/scripts/check-release-source.sh"; then
  echo 'Git output must be bounded independently on stdout and stderr' >&2
  exit 1
fi
grep -Fq -- '--draft' "$workflow"
grep -Fq -- '--method PATCH' "$workflow"
grep -Fq 'releases?per_page=100&page=' "$workflow"
grep -Fq "select(.draft == true and .tag_name == \$tag)" "$workflow"
grep -Fq "releases/\$RELEASE_DRAFT_ID" "$workflow"
grep -Fq "releases/\$RELEASE_ID" "$workflow"
grep -Fq 'name: controlplane-wheel-${{ github.run_id }}-${{ github.sha }}' "$workflow"
grep -Fq 'github_expression_prefix=' "$workflow"
grep -Fq 'expected_wheel_name=' "$workflow"
legacy_edit="$(printf '%s %s' gh 'release edit')"
tag_release_path="$(printf '%s/%s/' releases tags)"
if grep -Fq "$legacy_edit" "$workflow" || grep -Fq "$tag_release_path" "$workflow"; then
  echo 'draft Release path must use bounded discovery and numeric release IDs' >&2
  exit 1
fi
grep -Fq 'cat-file -t' "$helper"
grep -Fq 'tag_ref^{}' "$helper"
grep -Fq 'checkout_commit" == "$RELEASE_SHA"' "$helper"
grep -Fq 'ANNOTATED_TAG_SHA=' "$helper"
grep -Fq 'bounded-command.py' "$helper"
grep -Fq 'start_new_session=True' "$repo_root/scripts/bounded-command.py"

if grep -Eq 'GIT_CONFIG_KEY_|GIT_INDEX_FILE|config --(local|worktree)|symlink' "$helper"; then
  echo 'source helper contains retired hostile Git machinery' >&2
  exit 1
fi
if grep -Eq 'created_at|published_at|browser_download_url|expected_release_url' "$workflow"; then
  echo 'workflow contains retired derived Release assertions' >&2
  exit 1
fi

temporary="$(mktemp -d)"
trap 'rm -rf -- "$temporary"' EXIT
set +e
(
  cd "$temporary"
  # The child writes a legitimate work file larger than the diagnostic bound.
  source "$repo_root/scripts/release-helpers.sh"
  bounded_capture 65536 "$temporary/stdout" /usr/bin/python3 -c \
    'from pathlib import Path; Path("work.bin").write_bytes(b"x" * 131072); print("ok")'
)
status=$?
set -e
test "$status" -eq 0
test "$(cat "$temporary/stdout")" = ok
test "$(stat -c %s "$temporary/work.bin")" -eq 131072

set +e
(
  cd "$temporary"
  source "$repo_root/scripts/release-helpers.sh"
  bounded_capture 1024 "$temporary/descendant" /usr/bin/python3 -c \
    'import subprocess,sys; subprocess.Popen([sys.executable,"-c","import time; time.sleep(60)"]); print("leader")'
)
status=$?
set -e
test "$status" -eq 0
test "$(cat "$temporary/descendant")" = leader
