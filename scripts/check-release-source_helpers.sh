#!/usr/bin/env bash

normalize_canonical_origin_url() {
  local repository="$1" remote_urls="$2" canonical_origin
  canonical_origin="https://github.com/${repository}"
  case "$remote_urls" in
    "$canonical_origin"|"$canonical_origin.git")
      printf '%s.git\n' "$canonical_origin"
      ;;
    *)
      return 1
      ;;
  esac
}
