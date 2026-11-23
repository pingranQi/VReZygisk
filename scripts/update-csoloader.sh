#!/usr/bin/env sh
set -eu

ROOT=$(git -C "$(dirname "$0")/.." rev-parse --show-toplevel)
SUBMODULE="loader/src/external/csoloader"
UPSTREAM="https://github.com/ThePedroo/CSOLoader"

cd "$ROOT"

case "${1:-status}" in
  status)
    git submodule update --init --recursive "$SUBMODULE"
    printf 'path: %s\n' "$SUBMODULE"
    printf 'upstream: %s\n' "$(git config -f .gitmodules --get submodule.CSOLoader.url)"
    printf 'pinned commit: %s\n' "$(git -C "$SUBMODULE" rev-parse HEAD)"
    ;;
  update)
    if [ "$#" -ne 2 ]; then
      echo "usage: $0 update <tag-or-commit>" >&2
      exit 2
    fi
    git submodule update --init "$SUBMODULE"
    git -C "$SUBMODULE" remote set-url origin "$UPSTREAM"
    git -C "$SUBMODULE" fetch --no-tags origin "$2"
    git -C "$SUBMODULE" checkout --detach FETCH_HEAD
    printf 'CSOLoader now checked out at %s\n' "$(git -C "$SUBMODULE" rev-parse HEAD)"
    echo "Review and commit the updated submodule gitlink in the superproject."
    ;;
  *)
    echo "usage: $0 [status|update <tag-or-commit>]" >&2
    exit 2
    ;;
esac
